package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"os"
	"sync"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/reassembly"

	"github.com/Andoryuuta/Erupe/network"
)

// mhfTCPStream represents a single (bidirectional) TCP stream.
type mhfTCPStream struct {
	net, transport   gopacket.Flow
	isMhfConn        bool
	isNullInitedConn bool
	nullInitComplete bool
	sync.Mutex
}

// Accept is called when a TCP packet is received for a new stream connection.
func (t *mhfTCPStream) Accept(tcp *layers.TCP, ci gopacket.CaptureInfo, dir reassembly.TCPFlowDirection, nextSeq reassembly.Sequence, start *bool, ac reassembly.AssemblerContext) bool {
	*start = true
	return true
}

// ReassembledSG is called whenever the reassembler has enough data from tcp packets.
func (t *mhfTCPStream) ReassembledSG(sg reassembly.ScatterGather, ac reassembly.AssemblerContext) {
	_, _, _, skip := sg.Info()
	length, _ := sg.Lengths()

	if skip == -1 {
		// this is allowed
	} else if skip != 0 {
		// Missing bytes in stream: do not even try to parse it
		fmt.Printf("Skip: %v\n", skip)
		return
	}

	data := sg.Fetch(length)
	if t.isMhfConn {
		// Loop and try to parse as many packets from the currently available data as possible.
		do := 0
		for {
			if len(data[do:]) < 14 {
				if len(data[do:]) > 0 {
					//fmt.Println("Not enough for header")
					sg.KeepFrom(do + 0)
				}
				return
			}

			// Check if we have the 8*null init followed by a start of packet (0x03).
			if !t.nullInitComplete {
				if bytes.Equal(data[do:do+9], []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03}) {
					fmt.Println("Got 8*NULL init.")
					t.nullInitComplete = true
					sg.KeepFrom(do + 8)
					return
				}
			}

			// Try to recover if we got off somewhere
			if data[0] != 3 {
				fmt.Println("Got a non-0x03 starting byte, trying to recover. This may lose some packets unfortunately.")
				sg.KeepFrom(length)
				return
			}

			// Parse the header and see if have enough data for the payload.
			cph, err := network.NewCryptPacketHeader(data[do : do+14])
			if err != nil {
				panic(err)
			}

			// Try to read in the payload
			if len(data[do:]) >= 14+int(cph.DataSize) {
				payload := data[do+14 : do+14+int(cph.DataSize)]

				fmt.Printf("Read full MHF packet, size: %d\n", cph.DataSize)
				t.handleFullMhfPacket(cph, payload, sg, ac)

				do += 14 + int(cph.DataSize)
				continue

			} else {
				//fmt.Printf("Not enough data for header payload: %+v\n", cph)
				sg.KeepFrom(do + 0)
				return
			}
		}
	}

}

// handleFullMhfPacket handles decrypting and outputting a completed(size-wise) MHF packet.
func (t *mhfTCPStream) handleFullMhfPacket(cph *network.CryptPacketHeader, payload []byte, sg reassembly.ScatterGather, ac reassembly.AssemblerContext) {
	dir, _, _, _ := sg.Info()
	outFile := ac.(*Context).LogFile

	// Lock the log file to avoid data-race prints and defer an unlock.
	ac.(*Context).LogFileLock.Lock()
	defer ac.(*Context).LogFileLock.Unlock()

	// Make some indention, and send/recv strings based on the packet direction.
	var ident string
	var gameServerString string // The gameserver IP:PORT (regardless of direction)
	var dirString string

	isSend := (dir == reassembly.TCPDirClientToServer)
	dstString := fmt.Sprintf("%v:%v", t.net.Dst().String(), t.transport.Dst().String())
	srcString := fmt.Sprintf("%v:%v", t.net.Reverse().Dst().String(), t.transport.Reverse().Dst().String())
	if _, ok := knownHosts[srcString]; ok {
		// The stream source is the game server.
		gameServerString = srcString

		// Invert the flow direction.
		isSend = !isSend

	} else {
		gameServerString = dstString
	}

	if isSend {
		ident = fmt.Sprintf("%v %v(%s): ", t.net, t.transport, dir)
		dirString = "Send"
	} else {
		ident = fmt.Sprintf("%v %v(%s): ", t.net.Reverse(), t.transport.Reverse(), dir)
		dirString = "Recv"
	}

	var hostCommentString string
	host, ok := knownHosts[gameServerString]
	if ok {
		hostCommentString = fmt.Sprintf("//%s %s", ident, host)
	} else {
		hostCommentString = fmt.Sprintf("//%s Unknown host %s\n", ident, gameServerString)
	}

	// Now begin actually writing the packets to the file.

	fmt.Fprintln(outFile, "")

	// Print header
	//fmt.Fprintf(outFile, "//%+v\n", cph)

	// Print host
	fmt.Fprintln(outFile, hostCommentString)

	// Print time and direction(send/recv)
	fmt.Fprintln(outFile, ac.GetCaptureInfo().Timestamp)
	fmt.Fprintln(outFile, dirString)

	// Decrypt the packet.
	dec, err := bruteforceDecrypt(cph, payload)
	if err != nil {
		fmt.Fprintln(outFile, "PARSER_ERROR_FAILED_TO_DECRYPT") // Fake pseudo-opcode for failing to decrypt
		fmt.Fprintln(outFile, "")                               // Blank line where the hex would usually be.
		fmt.Println(err)
		return
	}

	// Check if the server uses opcodes and print accordingly.
	if t.isNullInitedConn {
		fmt.Fprintln(outFile, "PARSER_ERROR_SERVER_DOESNT_USE_OPCODES") // Fake pseudo-opcode for servers that don't have an opcode.
	} else {
		fmt.Fprintln(outFile, network.PacketID(binary.BigEndian.Uint16(dec[:2])).String())
	}

	// Print the spaced hex of the decrypted output.
	fmt.Fprintln(outFile, makeSpacedHex(dec))
}

func (t *mhfTCPStream) ReassemblyComplete(ac reassembly.AssemblerContext) bool {
	// do not remove the connection to allow last ACK
	return false
}

// mhfTCPStreamFactory provides a simple factory interface for creating new mhfTCPStream instances.
type mhfTCPStreamFactory struct{}

func (f *mhfTCPStreamFactory) New(net, transport gopacket.Flow, tcp *layers.TCP, ac reassembly.AssemblerContext) reassembly.Stream {
	stream := &mhfTCPStream{
		net:              net,
		transport:        transport,
		isMhfConn:        isMhfServer(uint16(tcp.SrcPort)) || isMhfServer(uint16(tcp.DstPort)),
		isNullInitedConn: isNullInitedServer(uint16(tcp.SrcPort)) || isNullInitedServer(uint16(tcp.DstPort)),
	}

	return stream
}

// Context holds context for packets passed through the reassembler.
type Context struct {
	CaptureInfo gopacket.CaptureInfo
	LogFile     *os.File
	LogFileLock sync.Mutex
}

// GetCaptureInfo gets the capture info
func (c *Context) GetCaptureInfo() gopacket.CaptureInfo {
	return c.CaptureInfo
}

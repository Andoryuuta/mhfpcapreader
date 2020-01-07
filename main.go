package main

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"os"
	"sync"

	"github.com/google/gopacket"

	"github.com/google/gopacket/ip4defrag"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/reassembly"

	"github.com/Andoryuuta/Erupe/network"
)

var filename = flag.String("i", "", "Input pcap filename")

var outFile *os.File
var outFileLock sync.Mutex

type mhfReader struct {
}

/* It's a connection (bidirectional) */
type mhfTCPStream struct {
	net, transport   gopacket.Flow
	isMhfServer      bool
	nullInitComplete bool

	tcpstate   *reassembly.TCPSimpleFSM
	optchecker reassembly.TCPOptionCheck

	sync.Mutex
}

func (t *mhfTCPStream) Accept(tcp *layers.TCP, ci gopacket.CaptureInfo, dir reassembly.TCPFlowDirection, nextSeq reassembly.Sequence, start *bool, ac reassembly.AssemblerContext) bool {
	// FSM
	if !t.tcpstate.CheckState(tcp, dir) {
		fmt.Printf("FSM: Packet rejected by FSM (state:%s)\n", t.tcpstate.String())
	}

	// Options
	err := t.optchecker.Accept(tcp, ci, dir, nextSeq, start)
	if err != nil {
		fmt.Printf("OptChkr: Packet rejected by OptionChecker: %s\n", err)
	}

	c, err := tcp.ComputeChecksum()
	if err != nil {
		fmt.Printf("Got error computing checksum: %s\n", err)
	} else if c != 0x0 {
		fmt.Printf("Invalid checksum: 0x%x\n", c)
	}

	*start = true
	return true
}

func (t *mhfTCPStream) ReassembledSG(sg reassembly.ScatterGather, ac reassembly.AssemblerContext) {
	_, _, _, skip := sg.Info()
	length, _ := sg.Lengths()

	if skip == -1 {
		// this is allowed
	} else if skip != 0 {
		// Missing bytes in stream: do not even try to parse it
		return
	}
	fmt.Printf("Skip: %v\n", skip)

	data := sg.Fetch(length)
	fmt.Printf("Got %v expected %v\n", len(data), length)

	fmt.Printf("%+v\n", sg.Stats())
	if t.isMhfServer {
		if len(data) < 14 {
			if len(data) > 0 {
				sg.KeepFrom(0)
			}
			return
		}

		// Check if we have the 8*null init followed by a start of packet (0x03).
		if !t.nullInitComplete {
			if bytes.Equal(data[:9], []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03}) {
				//fmt.Println("Got 8*NULL init.")
				t.nullInitComplete = true
				sg.KeepFrom(8)
				return
			}
		}

		// Parse the header and see if have enough data for the payload.
		cph, err := network.NewCryptPacketHeader(data[:14])
		if err != nil {
			panic(err)
		}
		fmt.Printf("%s\n", hex.Dump(data[:14]))
		fmt.Printf("%+v\n", cph)

		if len(data) >= 14+int(cph.DataSize) {
			payload := data[14 : 14+cph.DataSize]

			fmt.Printf("Read FULL packet, size: %d\n", cph.DataSize)
			t.handleFullMhfPacket(cph, payload, sg, ac)

			avail, saved := sg.Lengths()
			fmt.Printf("avil:%v, saved:%v\n", avail, saved)

			sg.KeepFrom(14 + int(cph.DataSize))
		} else {
			//fmt.Printf("Not enough data for header payload: %+v\n", cph)
			sg.KeepFrom(0)
		}

		return
	}
}

func (t *mhfTCPStream) handleFullMhfPacket(cph *network.CryptPacketHeader, payload []byte, sg reassembly.ScatterGather, ac reassembly.AssemblerContext) {
	dir, _, _, _ := sg.Info()

	var ident string
	var hostString string
	var dirString string
	if dir == reassembly.TCPDirClientToServer {
		ident = fmt.Sprintf("%v %v(%s): ", t.net, t.transport, dir)
		hostString = fmt.Sprintf("%v:%v", t.net.Dst().String(), t.transport.Dst().String())
		dirString = "Send"
	} else {
		ident = fmt.Sprintf("%v %v(%s): ", t.net.Reverse(), t.transport.Reverse(), dir)
		hostString = fmt.Sprintf("%v:%v", t.net.Dst().String(), t.transport.Dst().String())
		dirString = "Recv"
	}

	fmt.Fprintln(outFile, "")

	fmt.Fprintf(outFile, "%+v\n", cph)

	host, ok := knownHosts[hostString]
	if ok {
		fmt.Fprintf(outFile, "//%s %s\n", ident, host)
	} else {
		fmt.Fprintf(outFile, "//%s Unknown host %s\n", ident, hostString)
	}

	fmt.Fprintln(outFile, ac.GetCaptureInfo().Timestamp)
	fmt.Fprintln(outFile, dirString)

	//fmt.Printf("Packet #%v\n", ac.(*Context).GetPacketID())

	dec, err := bruteforceDecrypt(cph, payload)
	if err != nil {
		fmt.Println(err)
		return
	}

	fmt.Fprintln(outFile, network.PacketID(binary.BigEndian.Uint16(dec[:2])).String())

	//fmt.Fprintf(outFile, "Decrypted:\n%s\n", hex.Dump(dec))
	fmt.Fprintln(outFile, makeSpacedHex(dec))
}

func (t *mhfTCPStream) ReassemblyComplete(ac reassembly.AssemblerContext) bool {
	// do not remove the connection to allow last ACK
	return false
}

// Context for the assembler
type Context struct {
	PacketID    int
	CaptureInfo gopacket.CaptureInfo
}

// GetCaptureInfo gets the capture info
func (c *Context) GetCaptureInfo() gopacket.CaptureInfo {
	return c.CaptureInfo
}

// GetPacketID gets the packet id
func (c *Context) GetPacketID() int {
	return c.PacketID
}

type mhfTCPStreamFactory struct{}

func (f *mhfTCPStreamFactory) New(net, transport gopacket.Flow, tcp *layers.TCP, ac reassembly.AssemblerContext) reassembly.Stream {

	fsmOptions := reassembly.TCPSimpleFSMOptions{
		SupportMissingEstablishment: true,
	}

	stream := &mhfTCPStream{
		net:         net,
		transport:   transport,
		isMhfServer: isMhfServer(uint16(tcp.SrcPort)) || isMhfServer(uint16(tcp.DstPort)),
		tcpstate:    reassembly.NewTCPSimpleFSM(fsmOptions),
		optchecker:  reassembly.NewTCPOptionCheck(),
	}

	return stream
}

func main() {
	flag.Parse()

	var err error
	outFile, err = os.Create(fmt.Sprintf("%s_LOG.txt", *filename))
	if err != nil {
		panic(err)
	}

	handle, err := pcap.OpenOffline(*filename)
	if err != nil {
		panic(err)
	}

	err = handle.SetBPFFilter("(net 106.185.0.0/16) || (net 27.105.81.0/24)")
	if err != nil {
		panic(err)
	}

	dec, ok := gopacket.DecodersByLayerName[fmt.Sprintf("%s", handle.LinkType())]
	if !ok {
		panic("Error getting decoder")
	}

	source := gopacket.NewPacketSource(handle, dec)
	source.Lazy = false
	source.NoCopy = true

	streamFactory := &mhfTCPStreamFactory{}
	streamPool := reassembly.NewStreamPool(streamFactory)
	assembler := reassembly.NewAssembler(streamPool)
	defragger := ip4defrag.NewIPv4Defragmenter()

	idx := 0
	for packet := range source.Packets() {
		idx++

		fmt.Printf("Packet #%d\n", idx)

		// defrag the IPv4 packet if required
		ip4Layer := packet.Layer(layers.LayerTypeIPv4)
		if ip4Layer == nil {
			continue
		}
		ip4 := ip4Layer.(*layers.IPv4)
		l := ip4.Length
		newip4, err := defragger.DefragIPv4(ip4)
		if err != nil {
			log.Fatalln("Error while de-fragmenting", err)
		} else if newip4 == nil {
			fmt.Printf("Fragment...\n")
			continue // packet fragment, we don't have whole packet yet.
		}
		if newip4.Length != l {
			fmt.Printf("Decoding re-assembled packet: %s\n", newip4.NextLayerType())
			pb, ok := packet.(gopacket.PacketBuilder)
			if !ok {
				panic("Not a PacketBuilder")
			}
			nextDecoder := newip4.NextLayerType()
			nextDecoder.Decode(newip4.Payload, pb)
		}

		// Put the packet into the reassembler.
		tcp := packet.Layer(layers.LayerTypeTCP)
		if tcp != nil {
			tcp := tcp.(*layers.TCP)

			err := tcp.SetNetworkLayerForChecksum(packet.NetworkLayer())
			if err != nil {
				log.Fatalf("Failed to set network layer for checksum: %s\n", err)
			}

			c := Context{
				CaptureInfo: packet.Metadata().CaptureInfo,
				PacketID:    idx,
			}

			assembler.AssembleWithContext(packet.NetworkLayer().NetworkFlow(), tcp, &c)
		}
	}

	closed := assembler.FlushAll()
	fmt.Printf("Final flush: %d closed\n", closed)

	//streamPool.Dump()
	//fmt.Printf("%s\n", assembler.Dump())
}

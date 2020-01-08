package main

import (
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/google/gopacket"

	"github.com/google/gopacket/ip4defrag"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/reassembly"
)

func main() {
	var filename = flag.String("i", "", "Input pcap filename")
	var outFilename = flag.String("o", "", "Output log name")
	flag.Parse()

	// Parse the pcap if a single -i input was provided.
	if *filename != "" {
		// Create an output name based on the input if outputLogFilename is not set.
		outName := fmt.Sprintf("%s_LOG.txt", *filename)
		if *outFilename != "" {
			outName = *outFilename
		}

		doParsePcap(*filename, outName)
	}
}

func doParsePcap(pcapFilename string, outName string) {
	// Create the output log file.
	outFile, err := os.Create(outName)
	if err != nil {
		panic(err)
	}
	defer outFile.Close()

	// Open the pcap.
	handle, err := pcap.OpenOffline(pcapFilename)
	if err != nil {
		panic(err)
	}

	// Filter the pcap by our hosts filter.
	err = handle.SetBPFFilter(constBPFFilter)
	if err != nil {
		panic(err)
	}

	// Get the TCP decoder.
	dec, ok := gopacket.DecodersByLayerName[fmt.Sprintf("%s", handle.LinkType())]
	if !ok {
		panic("Error getting decoder")
	}

	// Create a new source from our pcap handle and our TCP decoder.
	source := gopacket.NewPacketSource(handle, dec)
	source.Lazy = false
	source.NoCopy = true

	streamFactory := &mhfTCPStreamFactory{}
	streamPool := reassembly.NewStreamPool(streamFactory)
	assembler := reassembly.NewAssembler(streamPool)
	defragger := ip4defrag.NewIPv4Defragmenter()

	// Loop over all of the packets and pass any TCP to the reassembler.
	for packet := range source.Packets() {
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

		// Put the packet into the reassembler if TCP.
		tcp := packet.Layer(layers.LayerTypeTCP)
		if tcp != nil {
			tcp := tcp.(*layers.TCP)

			err := tcp.SetNetworkLayerForChecksum(packet.NetworkLayer())
			if err != nil {
				log.Fatalf("Failed to set network layer for checksum: %s\n", err)
			}

			c := Context{
				CaptureInfo: packet.Metadata().CaptureInfo,
				LogFile:     outFile,
			}

			assembler.AssembleWithContext(packet.NetworkLayer().NetworkFlow(), tcp, &c)
		}
	}

	// Flush any data in the assembler that was waiting for more packets/data.
	assembler.FlushAll()
}

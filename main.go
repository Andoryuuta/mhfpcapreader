package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"runtime/debug"

	"github.com/google/gopacket"

	"github.com/google/gopacket/ip4defrag"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/reassembly"
)

func main() {
	var filename = flag.String("i", "", "Input pcap filename")
	var outFilename = flag.String("o", "", "Output log name")
	var inputDir = flag.String("idir", "", "Input directory (bulk parsing)")
	var outputDir = flag.String("odir", "output", "Output directory (bulk parsing)")
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

	// Whole directory parsing.
	if *inputDir != "" {
		var filepaths []string
		err := filepath.Walk(*inputDir, func(path string, info os.FileInfo, err error) error {
			if info.IsDir() {
				return nil
			}

			ext := filepath.Ext(path)
			if ext == ".pcap" || ext == ".pcapng" {
				filepaths = append(filepaths, path)
			}

			return nil
		})
		if err != nil {
			panic(err)
		}

		os.MkdirAll(*outputDir, os.ModePerm)
		for _, fp := range filepaths {
			fmt.Println("Now parsing:", fp)

			// Create an output name based on the input name.
			outName := fmt.Sprintf("%s_LOG.txt", filepath.Base(fp))
			wrapDoParsePcap(fp, filepath.Join(*outputDir, outName))

			fmt.Println("Finished parsing:", fp)
		}
	}
}

// There some places in gopacket/reassembly that occasionally cause unhandled panics,
// this function wraps the doParsePcap call in a recover statement and ignores errors for bulk parsing.
func wrapDoParsePcap(pcapFilename string, outName string) {
	defer func() {
		if r := recover(); r != nil {
			fmt.Println("stacktrace from panic: \n" + string(debug.Stack()))
		}
	}()

	err := doParsePcap(pcapFilename, outName)
	if err != nil {
		fmt.Printf("Got error: %v\n", err)
	}
}

func doParsePcap(pcapFilename string, outName string) error {
	// Create the output log file.
	outFile, err := os.Create(outName)
	if err != nil {
		return err
	}
	defer outFile.Close()

	// Open the pcap.
	handle, err := pcap.OpenOffline(pcapFilename)
	if err != nil {
		return err
	}
	defer handle.Close()

	// Filter the pcap by our hosts filter.
	err = handle.SetBPFFilter(constBPFFilter)
	if err != nil {
		return err
	}

	// Get the TCP decoder.
	dec, ok := gopacket.DecodersByLayerName[fmt.Sprintf("%s", handle.LinkType())]
	if !ok {
		return err
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
				//log.Fatalf("Failed to set network layer for checksum: %s\n", err)
				return err
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

	return nil
}

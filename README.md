# mhfpcapreader
mhfpcapreader is a small CLI tool to parse and decrypt archived MHF `.pcap` files to a simple log text file.

This tool reassembles the TCP streams using [gopacket](https://github.com/google/gopacket), then decrypts the packets with existing code from Erupe.

## Usage
```
go get -u github.com/Andoryuuta/mhfpcapreader
```
```
mhfpcapreader -i some_file.pcap -o output_log.txt
```


## Warning
TCP is complex, TCP state reassembly from a one-sided packet capture is also complex. Expect a lot of oddities with the tool and output log, such as, but not limited to: incorrectly ordered packets (especially at the beginning of pcaps without a valid TCP initalization sequence capture), missing packets, and outright crashes. 

## Acknowledgements
This tool was originally based on the gopacket [`reassemblydump`](https://github.com/google/gopacket/blob/master/examples/reassemblydump/main.go) example.

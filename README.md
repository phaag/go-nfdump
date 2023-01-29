# go-nfdump

This Go module allows to read and process files created by [nfdump](https://github.com/phaag/nfdump), the netflow/ipfix/sflow collector and processing tools.

This module is experimental and does not yet decode all available nfdump elements. It reads and processes only nfdump v2 files, which are created by nfdump-1.7.x. Files created with nfdump-1.6.x are recogized but skipped for decoding.

Expample to read and process a flow file:



```go

package main

import (
	"flag"
	"fmt"
	""github.com/phaag/go-nfdump/nffile"
	""github.com/phaag/go-nfdump/nfrecord"
	"os"
)

var (
	fileName = flag.String("r", "", "nfdump file to read")
)

func main() {

	flag.CommandLine.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage of %s [flags]\n", os.Args[0])
		flag.PrintDefaults()
	}
	
	flag.Parse()
	
	if len(*fileName) == 0 {
		fmt.Printf("Filename required\n")
		flag.PrintDefaults()
		os.Exit(255)
	}
	
	nffile := nffile.New()
	err := nffile.Open(*fileName)
	
	if err != nil {
		fmt.Printf("Failed to open nf file: %v\n", err)
		os.Exit(255)
	}
	
	// print nffile stats
	fmt.Printf("nffile:\n%v", nffile)
	
	// Dump flow records
	recordChannel, _ := nfrecord.AllRecords(nffile)
	for record := range recordChannel {
		fmt.Printf("%v\n", record)
		genericFlow := record.GenericFlow()
		if genericFlow != nil {
			fmt.Printf("SrcPort: %d\n", genericFlow.SrcPort)
			fmt.Printf("DstPort: %d\n", genericFlow.DstPort)
		}
		ipAddr := record.IP()
		if ipAddr != nil {
			fmt.Printf("SrcIP: %v\n", ipAddr.SrcIP)
			fmt.Printf("DstIP: %v\n", ipAddr.DstIP)
	
		}
	}
}

```

So far the generic data block as well as IPv4/IPv6 addresses are avilable through the interface.

```go
type EXgenericFlow struct {
	MsecFirst    uint64
	MsecLast     uint64
	MsecReceived uint64
	InPackets    uint64
	InBytes      uint64
	SrcPort      uint16
	DstPort      uint16
	Proto        uint8
	TcpFlags     uint8
	FwdStatus    uint8
	SrcTos       uint8
}

type EXip struct {
	SrcIP net.IP
	DstIP net.IP
}
```

Please note, that the interface may be subject to change, as this module is work in progress.

More element data blocks will follow, including the famous nfdump filter engine.

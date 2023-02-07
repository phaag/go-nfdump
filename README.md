# go-nfdump

[![Go Reference](https://pkg.go.dev/badge/github.com/phaag/go-nfdump.svg)](https://pkg.go.dev/github.com/phaag/go-nfdump)
[![buildtest](https://github.com/phaag/go-nfdump/actions/workflows/go.yml/badge.svg)](https://github.com/phaag/go-nfdump/actions/workflows/go.yml)
[![Go Report Card](https://goreportcard.com/badge/github.com/phaag/go-nfdump)](https://goreportcard.com/report/github.com/phaag/go-nfdump)

This Go module allows to read and process files created by [nfdump](https://github.com/phaag/nfdump), the netflow/ipfix/sflow collector and processing tools.

This module is experimental and does not yet decode all available nfdump record extensions. It reads and processes only nfdump v2 files, which are created by nfdump-1.7.x. Files created with nfdump-1.6.x are recogized but skipped for decoding.

Expample to read and process a flow file:



```go

package main

import (
	"flag"
	"fmt"
	"os"

	nfdump "github.com/phaag/go-nfdump"
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

	nffile := nfdump.New()

	if err := nffile.Open(*fileName); err != nil {
		fmt.Printf("Failed to open nf file: %v\n", err)
		os.Exit(255)
	}

	// print nffile stats
	fmt.Printf("nffile:\n%v", nffile)

	// Dump flow records
	recordChannel, _ := nffile.AllRecords()
	cnt := 0
	for record := range recordChannel {
		cnt++
		fmt.Printf("record: %d\n%v\n", cnt, record)
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
		/*
			other extension
			flowMisc := record.FlowMisc()
			cntFlow := record.CntFlow()
			vLan := record.VLan()
			asRouting := record.AsRouting()
		*/
	}
}
```

The `defs.go` file includes nfdump's `nfxV3.h` header file to convert individual record extensions into appropriate Golang records. So far the generic, misc, flowCount, vlan and asRouting extensions as well as IPv4/IPv6 addresses are available through the interface. See the nfxV3.go file for its definitions.

If you modify the `defs.go` file, generate `nfxV3.go` use the go command

`go generate ./...`

Please note, that the interface may be subject to change, as this module is work in progress.

More element data blocks will follow, including the famous nfdump filter engine.

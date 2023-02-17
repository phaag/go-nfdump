// Copyright © 2023 Peter Haag peter@people.ops-trust.net
// All rights reserved.
//
// Use of this source code is governed by the license that can be
// found in the LICENSE file.

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
			bgpNextHop := record.BgpNextHop()
			ipNextHop := record.IpNextHop()
		*/
	}
}

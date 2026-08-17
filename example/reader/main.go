// Copyright © 2024 Peter Haag peter@people.ops-trust.net
// All rights reserved.
//
// Use of this source code is governed by the license that can be
// found in the LICENSE file.

package main

import (
	"context"
	"encoding/hex"
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
	defer nffile.Close()

	// print nffile stats
	fmt.Printf("nffile:\n%v", nffile)
	fmt.Printf("container layout: V%d\n", nffile.Info().Layout)

	// Walk is the efficient streaming API. One goroutine reads and
	// decompresses upcoming blocks while this callback processes each flow.
	cnt := 0
	err := nffile.Walk(context.Background(), func(record nfdump.FlowRecord) error {
		cnt++

		// check IP addresses in record for IPv4, or IPv6
		if record.IsIPv4() {
			fmt.Printf("Record %d is IPv4\n", cnt)
		} else if record.IsIPv6() {
			fmt.Printf("Record %d is IPv6\n", cnt)
		} else {
			fmt.Printf("Record %d has no IPs\n", cnt)
		}

		// The compact API returns Go values rather than C-layout pointers.
		if genericFlow, ok := record.Generic(); ok {
			fmt.Printf("SrcPort: %d\n", genericFlow.SrcPort)
			fmt.Printf("DstPort: %d\n", genericFlow.DstPort)
		}

		if srcIP, dstIP, ok := record.IP(); ok {
			fmt.Printf("SrcIP: %v\n", srcIP)
			fmt.Printf("DstIP: %v\n", dstIP)
		}

		if payload := record.Extension(nfdump.ExtensionInPayload); payload != nil {
			fmt.Printf("Payload length: %d\n", len(payload))
			fmt.Printf("%s", hex.Dump(payload))
		}
		/*
			// Extension returns the raw payload for less common fields. The payload
			// is valid only until this callback returns; call record.Clone() to keep it.
		*/
		return nil
	})
	if err != nil {
		fmt.Printf("Failed to process flows: %v\n", err)
		return
	}

	// Retrieve exporters only after Walk completes, as they are discovered
	// while records are processed.
	exporterList := nffile.GetExporterList()
	fmt.Printf("Exporter list:\n")
	for id, exporter := range exporterList {
		if exporter.IP != nil && id == int(exporter.SysId) { // valid exporter
			fmt.Printf("  SysID: %d, ID: %d, IP: %v, version: %d", exporter.SysId, exporter.Id, exporter.IP, exporter.Version)
			fmt.Printf(" Sequence failures: %d, packets: %d, flows: %d\n", exporter.SequenceFailures, exporter.Packets, exporter.Flows)
			for _, sampler := range exporter.SamplerList {
				fmt.Printf("  Sampler: id: %d, algorithm: %d, packet interval: %d, space interval: %d\n",
					sampler.Id, sampler.Algorithm, sampler.PacketInterval, sampler.SpaceInterval)
			}
		}
	}
}

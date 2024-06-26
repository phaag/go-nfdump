// Copyright © 2024 Peter Haag peter@people.ops-trust.net
// All rights reserved.
//
// Use of this source code is governed by the license that can be
// found in the LICENSE file.

package main

import (
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

	// print nffile stats
	fmt.Printf("nffile:\n%v", nffile)

	// Dump flow records
	recordChannel, _ := nffile.AllRecords().Get()
	cnt := 0
	for record := range recordChannel {
		cnt++

		// check IP addresses in record for IPv4, or IPv6
		if record.IsIPv4() {
			fmt.Printf("Record %d is IPv4\n", cnt)
		} else if record.IsIPv6() {
			fmt.Printf("Record %d is IPv6\n", cnt)
		} else {
			fmt.Printf("Record %d has no IPs\n", cnt)
		}

		// sampling
		packetInterval, spaceInterval := record.SamplerInfo(nffile)
		fmt.Printf("Record sampler info: packet interval: %d, space interval: %d\n", packetInterval, spaceInterval)

		// print the entire record using %v
		fmt.Printf("%v\n", record)

		// get generic extension and print ports
		// see nfxV3.go for all fields in genericFlow
		if genericFlow := record.GenericFlow(); genericFlow != nil {
			fmt.Printf("SrcPort: %d\n", genericFlow.SrcPort)
			fmt.Printf("DstPort: %d\n", genericFlow.DstPort)
		}

		// get src, dst ip address extension of record
		// can contain IPv4 or IPv6
		ipAddr := record.IP()
		if ipAddr != nil {
			// when printing as %v, Golang takes care about proper formating
			// as IPv4 or IPv6
			// see Golang standard library net.IP for more details to process IPs
			fmt.Printf("SrcIP: %v\n", ipAddr.SrcIP)
			fmt.Printf("DstIP: %v\n", ipAddr.DstIP)
		}

		// get payload extension
		if payload := record.Payload(); payload != nil {
			fmt.Printf("Payload length: %d\n", len(payload))
			fmt.Printf("%s", hex.Dump(payload))
		}
		/*
			// other extension
			// see nfxV3.go for all fields in the respectiv records
			// always check for nil return value as not every extension
			// is available
			flowMisc := record.FlowMisc()
			cntFlow := record.CntFlow()
			vLan := record.VLan()
			asRouting := record.AsRouting()
			bgpNextHop := record.BgpNextHop()
			ipNextHop := record.IpNextHop()

			// please note, sampling contains only references to exporter list
			// use record.SamplerInfo(nffile) to retrieve true sampling values
			sampling := record.Sampling()
		*/
	}

	// retrieve exporter list *after* all records are processed
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

// Copyright © 2024 Peter Haag peter@people.ops-trust.net
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

	// get empty new nffile object
	nffile := nfdump.New()

	// open the flow file
	if err := nffile.Open(*fileName); err != nil {
		fmt.Printf("Failed to open nf file: %v\n", err)
		os.Exit(255)
	}

	// Read all flow records and append the OrderBy() processing
	// finally get the flows and print them
	if recordChannel, err := nffile.AllRecords().OrderBy("bytes", nfdump.DESCENDING).Get(); err != nil {
		fmt.Printf("Failed to process flows: %v\n", err)
	} else {
		for record := range recordChannel {
			record.PrintLine()
		}
	}
}

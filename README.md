# go-nfdump

[![Go Reference](https://pkg.go.dev/badge/github.com/phaag/go-nfdump.svg)](https://pkg.go.dev/github.com/phaag/go-nfdump)
[![buildtest](https://github.com/phaag/go-nfdump/actions/workflows/go.yml/badge.svg)](https://github.com/phaag/go-nfdump/actions/workflows/go.yml)
[![Go Report Card](https://goreportcard.com/badge/github.com/phaag/go-nfdump)](https://goreportcard.com/report/github.com/phaag/go-nfdump)

`go-nfdump` reads and processes flow files written by [nfdump](https://github.com/phaag/nfdump).

## Requirements and installation

- Go 1.24 or later.
- An nfdump V2 flow file written by nfdump 1.7.x.

Add the module to an application with:

```sh
go get github.com/phaag/go-nfdump
```

## Supported files

The module reads nfdump's V2 container and V3 flow records produced by nfdump 1.7.x. It supports uncompressed, LZO, Bzip2, LZ4, and ZSTD blocks.

- nfdump 1.6.x/V1 files are recognized, but flow-record decoding is not supported.
- nfdump 1.8.x files use a new V3 container and V4 flow-record format and are not supported yet.
- Not every nfdump V3 extension has a Go accessor. Unknown extensions are skipped by the public API.

## Read flow records

The record stream is asynchronous. Check the error returned by `Get()` for an immediate failure, consume the channel, then call `Err()` to report a terminal read or decode failure.

```go
package main

import (
	"flag"
	"fmt"
	"os"

	nfdump "github.com/phaag/go-nfdump"
)

func main() {
	fileName := flag.String("r", "", "nfdump file to read")
	flag.Parse()
	if *fileName == "" {
		flag.PrintDefaults()
		os.Exit(2)
	}

	nf := nfdump.New()
	if err := nf.Open(*fileName); err != nil {
		fmt.Fprintf(os.Stderr, "open flow file: %v\n", err)
		os.Exit(1)
	}
	defer nf.Close()

	chain := nf.AllRecords()
	records, err := chain.Get()
	if err != nil {
		fmt.Fprintf(os.Stderr, "start reading flows: %v\n", err)
		os.Exit(1)
	}

	for record := range records {
		if generic := record.GenericFlow(); generic != nil {
			fmt.Printf("%v:%d -> %v:%d proto=%d packets=%d bytes=%d\n",
				record.IP().SrcIP, generic.SrcPort,
				record.IP().DstIP, generic.DstPort,
				generic.Proto, generic.InPackets, generic.InBytes)
		}
	}
	if err := chain.Err(); err != nil {
		fmt.Fprintf(os.Stderr, "read flows: %v\n", err)
		os.Exit(1)
	}

	// Exporters and samplers are discovered while records are read.
	for _, exporter := range nf.GetExporterList() {
		if exporter.IP != nil {
			fmt.Printf("exporter=%v id=%d flows=%d packets=%d\n",
				exporter.IP, exporter.Id, exporter.Flows, exporter.Packets)
		}
	}
}
```

`Open` reads the file metadata. Use `Ident()` for its identifier and `Stat()` for aggregate flow statistics. Always call `Close` when finished.

## Record accessors

Pointer and slice extension accessors return `nil` when the extension is absent. `IP()` returns an `EXip` value whose addresses may be `nil`, and `NokiaNatString()` returns an empty string when absent. The common flow-record accessors are:

- `GenericFlow`, `IP`, `IsIPv4`, and `IsIPv6`
- `FlowMisc`, `CntFlow`, `VLan`, and `AsRouting`
- `BgpNextHop`, `IpNextHop`, and `IpReceived`
- `Sampling` and `SamplerInfo`
- `NatXlateIP`, `NatXlatePort`, `NatCommon`, and `NatPortBlock`
- `Payload`, `FlowId`, `NokiaNat`, `NokiaNatString`, and `IpInfo`

`SamplerInfo` returns the effective packet and space interval for a flow. Exporter and sampler information may appear while the file is streamed, so retrieve `GetExporterList()` only after the record channel is drained.

`String()` provides a verbose representation of a `FlowRecordV3`; `PrintLine()` emits a compact flow line.

## Sorting

`OrderBy` buffers the complete input stream before returning records. It supports `"tstart"`, `"tend"`, `"packets"`, and `"bytes"`, with `nfdump.ASCENDING` or `nfdump.DESCENDING`.

```go
chain := nf.AllRecords().OrderBy("bytes", nfdump.DESCENDING)
records, err := chain.Get()
if err != nil {
	// Handle an immediate error.
}
for record := range records {
	_ = record
}
if err := chain.Err(); err != nil {
	// Handle a terminal read or decode error.
}
```

## Raw data blocks

`ReadDataBlocks()` exposes decompressed Type-3 data blocks. It is intended for callers that need lower-level access than `AllRecords()`.

```go
blocks, err := nf.ReadDataBlocks()
if err != nil {
	// The file is not open.
}
for block := range blocks {
	if block.Err != nil {
		// Terminal I/O, validation, or decompression error.
		break
	}
	// block.Header and block.Data contain the decompressed block.
}
```

For the complete generated extension types, see [nfxV3.go](nfxV3.go). Changes to `defs.go` require regenerating those bindings with `go generate ./...`.

This module is experimental; its API may evolve.

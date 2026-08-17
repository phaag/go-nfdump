# go-nfdump

[![Go Reference](https://pkg.go.dev/badge/github.com/phaag/go-nfdump.svg)](https://pkg.go.dev/github.com/phaag/go-nfdump)
[![buildtest](https://github.com/phaag/go-nfdump/actions/workflows/go.yml/badge.svg)](https://github.com/phaag/go-nfdump/actions/workflows/go.yml)

`go-nfdump` reads and processes flow files written by [nfdump](https://github.com/phaag/nfdump).

## Requirements and installation

- Go 1.24 or later.
- An nfdump V2 (1.7.x) or unencrypted V3 (1.8.x) flow file to read.

The module is pure Go: it does not require cgo, a C compiler, or nfdump C
headers at build time.

Add the module to an application with:

```sh
go get github.com/phaag/go-nfdump
```

## Supported files

The module transparently reads nfdump 1.7.x V2 containers with V3 flow
records and nfdump 1.8.x V3 containers with V4 flow records. Both use the
same `Walk` callback and `FlowRecord` accessors. It supports uncompressed,
LZO, Bzip2, LZ4, and ZSTD blocks.

- nfdump 1.6.x/V1 files are recognized, but flow-record decoding is not supported.
- Encrypted nfdump 1.8.x files are not supported yet.
- The generic `Walk` API provides common V3/V4 extensions: generic flow,
  IPv4/IPv6 addresses, flow misc, counters, VLAN, AS information, input
  payload, and IP information. Other extensions remain accessible through the
  legacy 1.7.x API where available.

## Read flow records

For efficient sequential processing, use `Walk`. One producer goroutine reads
and decompresses blocks while the callback processes the preceding block. The
callback runs in the calling goroutine, flow order is preserved, and at most two
decoded blocks are queued. A record is a view of the current block; call
`record.Clone()` if it must be retained after the callback returns.
Cancellation is observed before each block and at least once every 256 flow
records within a block.

```go
err := nf.Walk(context.Background(), func(record nfdump.FlowRecord) error {
	if generic, ok := record.Generic(); ok {
		fmt.Printf("%d packets\n", generic.InPackets)
	}
	return nil // Return an error to stop processing.
})
if err != nil {
	// Handle I/O, decoding, context, or callback errors.
}
```

`Walk` uses the compact, version-neutral `FlowRecord` API. For 1.7.x files,
`Generic()` returns timestamps, counters, ports, and protocol fields, while
`IP()` returns `netip.Addr` source and destination addresses. `Format()`,
`ExporterID()`, `Flags()`, `NetFlowVersion()`, `Engine()`, `IsIPv4()`, and
`IsIPv6()` provide record metadata. `Extension(id)` exposes a read-only raw
extension payload for fields that do not yet have a native accessor. Prefer
the version-neutral `Extension...` constants, such as
`nfdump.ExtensionInPayload`, over the legacy `EX...ID` names.

`Info()` returns format-neutral file metadata (`Layout`, nfdump version,
creation time, compression, encryption state, block size, and flow-block
count). `Header` is retained only for V1/V2 compatibility and new code should
not depend on it.

`AllRecords`, `OrderBy`, and `ReadDataBlocks` remain legacy V1/V2 APIs. They
produce owned `*FlowRecordV3` values and expose the generated V3 extension
structs; use them where that compatibility is required. Newer layouts return
an error matching `nfdump.ErrUnsupported` instead of being silently coerced.

`Walk` and `Close` coordinate safely. Do not start a second read operation on
the same `NfFile` until `Walk` returns.

The asynchronous channel API below remains available for compatibility. Drain
its channel before calling `Close`.

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

## Benchmarks

The opt-in `Walk` benchmarks compare representative 1.7.x and 1.8.x files
without committing large binary fixtures. Set both paths and run:

```sh
NFDUMP_BENCH_V2=/path/to/1.7.nf \
NFDUMP_BENCH_V3=/path/to/1.8.nf \
go test -run '^$' -bench '^BenchmarkWalkV' -benchtime=3x -count=3
```

`Count` measures streaming delivery; `GenericIP` includes the usual generic
and address extension lookups. File open and close time are excluded.

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

This module is experimental; its API may evolve.

## Sponsorship

Development can be supported through [GitHub Sponsors](https://github.com/sponsors/phaag). Any sponsoring is appreciated.

## License

go-nfdump is distributed under the BSD 2-Clause [License](https://github.com/phaag/go-nfdump/blob/main/LICENSE)

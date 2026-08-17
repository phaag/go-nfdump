// Copyright © 2026 Peter Haag peter@people.ops-trust.net
// All rights reserved.
//
// Use of this source code is governed by the license that can be
// found in the LICENSE file.

package nfdump

import (
	"context"
	"errors"
	"fmt"
)

// FileLayout identifies an nfdump container layout.
type FileLayout uint16

const (
	FileLayoutV1 FileLayout = 1
	FileLayoutV2 FileLayout = 2
	FileLayoutV3 FileLayout = 3
)

// Compression identifies the compression algorithm independently of its
// numeric on-disk encoding. Container layouts may assign different numbers to
// the same algorithm.
type Compression uint8

const (
	CompressionNone Compression = iota
	CompressionLZO
	CompressionBzip2
	CompressionLZ4
	CompressionZSTD
)

// FileInfo is the version-neutral metadata available after Open. Created is
// the nfdump on-disk creation timestamp. Its unit is defined by the container
// layout; V2 uses milliseconds since the Unix epoch.
//
// Header remains available for compatibility with V1/V2 callers. New code
// should prefer Info so it does not depend on a particular container header.
type FileInfo struct {
	Layout        FileLayout
	NfdumpVersion uint32
	Created       uint64
	Compression   Compression
	Encrypted     bool
	BlockSize     uint32
	FlowBlocks    uint32
}

// ErrUnsupported is returned when an operation is not available for the
// opened file layout. For example, the legacy AllRecords and ReadDataBlocks
// APIs are specific to V1/V2 containers.
var ErrUnsupported = errors.New("nfdump: unsupported operation")

type unsupportedError struct {
	operation string
	layout    FileLayout
}

func (err unsupportedError) Error() string {
	return fmt.Sprintf("nfdump: %s is not supported for file layout V%d", err.operation, err.layout)
}

func (err unsupportedError) Unwrap() error { return ErrUnsupported }

// fileReader is the format-specific side of the reader. It deliberately
// delivers FlowRecord values, so the public Walk API has no container-format
// branch in its hot path.
type fileReader interface {
	walk(context.Context, context.CancelFunc, func(FlowRecord) error) error
	close() error
}

// dataBlockReader is implemented only by the legacy V1/V2 backend. DataBlock
// reflects that container's block structure and has no V3-container meaning.
type dataBlockReader interface {
	readDataBlocks(context.Context, chan<- DataBlock) error
}

// legacyRecordReader supplies the V3 records needed by the compatibility
// AllRecords API. It is intentionally separate from fileReader: V4 records
// must not be coerced into FlowRecordV3 values.
type legacyRecordReader interface {
	dataBlockReader
	processDataBlock(DataBlock, func([]byte) error) error
}

// Copyright © 2023 Peter Haag peter@people.ops-trust.net
// All rights reserved.
//
// Use of this source code is governed by the license that can be
// found in the LICENSE file.

package nfdump

import (
	"bytes"
	"compress/bzip2"
	"fmt"
	"io"

	zstd "github.com/klauspost/compress/zstd"
	"github.com/pierrec/lz4/v4"
	lzo "github.com/rasky/go-lzo"
)

// uncompressBlock decodes a single V1/V2 block using the compression semantics
// of the nfdump 1.7.x reader backend.
func (reader *v17Reader) uncompressBlock(blockHeader *DataBlockHeader) ([]byte, error) {
	blockLimit := reader.blockSizeLimit()
	if blockHeader.Size > blockLimit {
		return nil, fmt.Errorf("block size %d exceeds file block size %d", blockHeader.Size, blockLimit)
	}
	if reader.header.Encryption != 0 && blockHeader.Flags&flagBlockUnencrypted == 0 {
		return nil, fmt.Errorf("encrypted data blocks are not supported")
	}

	dataBlock := make([]byte, blockHeader.Size)
	if _, err := io.ReadAtLeast(reader.file, dataBlock, int(blockHeader.Size)); err != nil {
		return nil, fmt.Errorf("nfFile read data block: %w", err)
	}

	compression := reader.header.Compression
	if blockHeader.Flags&flagBlockUncompressed != 0 {
		compression = NOT_COMPRESSED
	}

	switch compression {
	case NOT_COMPRESSED:
	case LZO_COMPRESSED:
		out, err := lzo.Decompress1X(bytes.NewReader(dataBlock), int(blockHeader.Size), int(blockLimit))
		if err != nil {
			return nil, fmt.Errorf("nfFile uncompress lzo1x-1 data block: %w", err)
		}
		dataBlock = out
		blockHeader.Size = uint32(len(out))
	case BZ2_COMPRESSED:
		out, err := io.ReadAll(io.LimitReader(bzip2.NewReader(bytes.NewReader(dataBlock)), int64(blockLimit)+1))
		if err != nil {
			return nil, fmt.Errorf("nfFile uncompress bzip2 data block: %w", err)
		}
		if len(out) > int(blockLimit) {
			return nil, fmt.Errorf("nfFile uncompress bzip2 data block: output exceeds block size")
		}
		dataBlock = out
		blockHeader.Size = uint32(len(out))
	case LZ4_COMPRESSED:
		out := make([]byte, blockLimit)
		n, err := lz4.UncompressBlock(dataBlock, out)
		if err != nil {
			return nil, fmt.Errorf("nfFile uncompress lz4 data block: %w", err)
		}
		out = out[:n]
		dataBlock = out
		blockHeader.Size = uint32(n)
	case ZSTD_COMPRESSED:
		if reader.zstdDecoder == nil {
			decoder, err := zstd.NewReader(nil, zstd.WithDecoderConcurrency(0), zstd.WithDecoderMaxMemory(uint64(blockLimit)))
			if err != nil {
				return nil, fmt.Errorf("nfFile create zstd decoder: %w", err)
			}
			reader.zstdDecoder = decoder
		}
		out, err := reader.zstdDecoder.DecodeAll(dataBlock, nil)
		if err != nil {
			return nil, fmt.Errorf("nfFile uncompress zstd data block: %w", err)
		}
		dataBlock = out
		blockHeader.Size = uint32(len(out))
	default:
		return nil, fmt.Errorf("unknown data block compression: %d", compression)
	}
	if len(dataBlock) > int(blockLimit) {
		return nil, fmt.Errorf("uncompressed block size %d exceeds file block size %d", len(dataBlock), blockLimit)
	}

	return dataBlock, nil
}

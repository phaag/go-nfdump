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

func (nfFile *NfFile) uncompressBlock(blockHeader *DataBlockHeader) ([]byte, error) {
	blockLimit := nfFile.blockSizeLimit()
	if blockHeader.Size > blockLimit {
		return nil, fmt.Errorf("block size %d exceeds file block size %d", blockHeader.Size, blockLimit)
	}
	if nfFile.Header.Encryption != 0 && blockHeader.Flags&flagBlockUnencrypted == 0 {
		return nil, fmt.Errorf("encrypted data blocks are not supported")
	}

	dataBlock := make([]byte, blockHeader.Size)
	if _, err := io.ReadAtLeast(nfFile.file, dataBlock, int(blockHeader.Size)); err != nil {
		return nil, fmt.Errorf("nfFile read appendix data block: %v", err)
	}

	compression := nfFile.Header.Compression
	if blockHeader.Flags&flagBlockUncompressed != 0 {
		compression = NOT_COMPRESSED
	}

	switch compression {
	case NOT_COMPRESSED:
	case LZO_COMPRESSED:
		out, err := lzo.Decompress1X(bytes.NewReader(dataBlock), int(blockHeader.Size), int(blockLimit))
		if err != nil {
			return nil, fmt.Errorf("nfFile uncompress lzo1x-1 data block: %v", err)
		}
		dataBlock = out
		blockHeader.Size = uint32(len(out))
	case BZ2_COMPRESSED:
		out, err := io.ReadAll(io.LimitReader(bzip2.NewReader(bytes.NewReader(dataBlock)), int64(blockLimit)+1))
		if err != nil {
			return nil, fmt.Errorf("nfFile uncompress bzip2 data block: %v", err)
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
			return nil, fmt.Errorf("nfFile uncompress lz4 data block: %v", err)
		}
		out = out[:n]
		dataBlock = out
		blockHeader.Size = uint32(n)
	case ZSTD_COMPRESSED:
		if nfFile.zstdDecoder == nil {
			var err error
			nfFile.zstdDecoder, err = zstd.NewReader(nil, zstd.WithDecoderConcurrency(0), zstd.WithDecoderMaxMemory(uint64(blockLimit)))
			if err != nil {
				return nil, fmt.Errorf("nfFile create zstd decoder: %v", err)
			}
		}
		out, err := nfFile.zstdDecoder.DecodeAll(dataBlock, nil)
		if err != nil {
			return nil, fmt.Errorf("nfFile uncompress zstd data block: %v", err)
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

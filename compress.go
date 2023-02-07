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

	"github.com/pierrec/lz4/v4"
	lzo "github.com/rasky/go-lzo"
)

func (nfFile *NfFile) uncompressBlock(blockHeader *DataBlockHeader) ([]byte, error) {

	dataBlock := make([]byte, blockHeader.Size)
	if _, err := io.ReadAtLeast(nfFile.file, dataBlock, int(blockHeader.Size)); err != nil {
		return nil, fmt.Errorf("nfFile read appendix data block: %v", err)
	}

	switch nfFile.Header.Compression {
	case NOT_COMPRESSED:
	case LZO_COMPRESSED:
		out, err := lzo.Decompress1X(bytes.NewReader(dataBlock), int(blockHeader.Size), 2*int(blockHeader.Size))
		if err != nil {
			return nil, fmt.Errorf("nfFile uncompress lzo1x-1 data block: %v", err)
		}
		dataBlock = out
		blockHeader.Size = uint32(len(out))
	case BZ2_COMPRESSED:
		reader := bzip2.NewReader(bytes.NewReader(dataBlock))
		out := make([]byte, 3*len(dataBlock))
		n, err := reader.Read(out)
		if err != nil {
			return nil, fmt.Errorf("nfFile uncompress bzip2 data block: %v", err)
		}
		out = out[:n]
		dataBlock = out
		blockHeader.Size = uint32(n)
	case LZ4_COMPRESSED:
		out := make([]byte, 3*len(dataBlock))
		n, err := lz4.UncompressBlock(dataBlock, out)
		if err != nil {
			return nil, fmt.Errorf("nfFile uncompress lz4 data block: %v", err)
		}
		out = out[:n]
		dataBlock = out
		blockHeader.Size = uint32(n)
	default:
		return nil, fmt.Errorf("unknown data block compression: %d", nfFile.Header.Compression)
	}

	return dataBlock, nil
}

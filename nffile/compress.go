/*
 *  Copyright (c) 2022, Peter Haag
 *  All rights reserved.
 *
 *  Redistribution and use in source and binary forms, with or without
 *  modification, are permitted provided that the following conditions are met:
 *
 *   * Redistributions of source code must retain the above copyright notice,
 *     this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above copyright notice,
 *     this list of conditions and the following disclaimer in the documentation
 *     and/or other materials provided with the distribution.
 *   * Neither the name of the author nor the names of its contributors may be
 *     used to endorse or promote products derived from this software without
 *     specific prior written permission.
 *
 *  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 *  AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 *  IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 *  ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
 *  LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 *  CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 *  SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 *  INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 *  CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 *  ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 *  POSSIBILITY OF SUCH DAMAGE.
 */

package nffile

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

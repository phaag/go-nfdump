// Copyright © 2026 Peter Haag peter@people.ops-trust.net
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

// uncompressV18 decodes the payload following a V3 data-block header. V3
// compression values intentionally differ from V2 and are kept local here.
func (reader *v18Reader) uncompressV18(data []byte, compression uint16, rawSize int) ([]byte, error) {
	if rawSize < 0 || rawSize > int(reader.header.blockSize)-v18BlockHeader {
		return nil, fmt.Errorf("invalid V3 decompressed payload size %d", rawSize)
	}
	switch compression {
	case 1: // NOT_COMPRESSED
		if len(data) != rawSize {
			return nil, fmt.Errorf("uncompressed V3 payload size %d, want %d", len(data), rawSize)
		}
		return data, nil
	case 2: // LZO_COMPRESSED
		out, err := lzo.Decompress1X(bytes.NewReader(data), len(data), rawSize)
		if err != nil {
			return nil, fmt.Errorf("uncompress V3 lzo block: %w", err)
		}
		return out, nil
	case 3: // BZ2_COMPRESSED
		out, err := io.ReadAll(io.LimitReader(bzip2.NewReader(bytes.NewReader(data)), int64(rawSize)+1))
		if err != nil {
			return nil, fmt.Errorf("uncompress V3 bzip2 block: %w", err)
		}
		if len(out) != rawSize {
			return nil, fmt.Errorf("uncompress V3 bzip2 size %d, want %d", len(out), rawSize)
		}
		return out, nil
	case 4: // LZ4_COMPRESSED
		out := make([]byte, rawSize)
		n, err := lz4.UncompressBlock(data, out)
		if err != nil {
			return nil, fmt.Errorf("uncompress V3 lz4 block: %w", err)
		}
		if n != rawSize {
			return nil, fmt.Errorf("uncompress V3 lz4 size %d, want %d", n, rawSize)
		}
		return out, nil
	case 5: // ZSTD_COMPRESSED
		if reader.zstdDecoder == nil {
			decoder, err := zstd.NewReader(nil, zstd.WithDecoderConcurrency(0), zstd.WithDecoderMaxMemory(uint64(reader.header.blockSize)))
			if err != nil {
				return nil, fmt.Errorf("create V3 zstd decoder: %w", err)
			}
			reader.zstdDecoder = decoder
		}
		out, err := reader.zstdDecoder.DecodeAll(data, nil)
		if err != nil {
			return nil, fmt.Errorf("uncompress V3 zstd block: %w", err)
		}
		if len(out) != rawSize {
			return nil, fmt.Errorf("uncompress V3 zstd size %d, want %d", len(out), rawSize)
		}
		return out, nil
	default:
		return nil, fmt.Errorf("unknown V3 block compression: %d", compression)
	}
}

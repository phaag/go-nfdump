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

// uncompressV18 decodes the payload following a V3 data-block header
// directly into dst, whose length is the exact expected decompressed size
// (the V3 block header carries rawSize, unlike V2). Every codec below either
// decodes straight into dst or, where the underlying library offers no
// destination-buffer API (LZO), decodes into its own buffer and copies once
// into dst - still one allocation and one copy fewer per block than
// decoding into a separate scratch buffer and then assembling a final
// buffer from it. V3 compression values intentionally differ from V2 and
// are kept local here.
func (reader *v18Reader) uncompressV18(data []byte, compression uint16, dst []byte) error {
	rawSize := len(dst)
	if rawSize > int(reader.header.blockSize)-v18BlockHeader {
		return fmt.Errorf("invalid V3 decompressed payload size %d", rawSize)
	}
	switch compression {
	case 1: // NOT_COMPRESSED
		if len(data) != rawSize {
			return fmt.Errorf("uncompressed V3 payload size %d, want %d", len(data), rawSize)
		}
		copy(dst, data)
		return nil
	case 2: // LZO_COMPRESSED
		out, err := lzo.Decompress1X(bytes.NewReader(data), len(data), rawSize)
		if err != nil {
			return fmt.Errorf("uncompress V3 lzo block: %w", err)
		}
		if len(out) != rawSize {
			return fmt.Errorf("uncompress V3 lzo size %d, want %d", len(out), rawSize)
		}
		copy(dst, out)
		return nil
	case 3: // BZ2_COMPRESSED
		zr := bzip2.NewReader(bytes.NewReader(data))
		if _, err := io.ReadFull(zr, dst); err != nil {
			return fmt.Errorf("uncompress V3 bzip2 block: %w", err)
		}
		var probe [1]byte
		n, err := zr.Read(probe[:])
		if n > 0 {
			return fmt.Errorf("uncompress V3 bzip2 block: output exceeds expected size %d", rawSize)
		}
		if err != io.EOF {
			if err == nil {
				return fmt.Errorf("uncompress V3 bzip2 block: decoder made no progress after expected output")
			}
			return fmt.Errorf("uncompress V3 bzip2 block: %w", err)
		}
		return nil
	case 4: // LZ4_COMPRESSED
		n, err := lz4.UncompressBlock(data, dst)
		if err != nil {
			return fmt.Errorf("uncompress V3 lz4 block: %w", err)
		}
		if n != rawSize {
			return fmt.Errorf("uncompress V3 lz4 size %d, want %d", n, rawSize)
		}
		return nil
	case 5: // ZSTD_COMPRESSED
		if reader.zstdDecoder == nil {
			decoder, err := zstd.NewReader(nil, zstd.WithDecoderConcurrency(0), zstd.WithDecoderMaxMemory(uint64(reader.header.blockSize)))
			if err != nil {
				return fmt.Errorf("create V3 zstd decoder: %w", err)
			}
			reader.zstdDecoder = decoder
		}
		// dst[:0] retains dst's full capacity (exactly rawSize), so DecodeAll
		// appends into dst's own backing array rather than allocating a new
		// one - guaranteed by append's semantics since len+n <= cap here.
		out, err := reader.zstdDecoder.DecodeAll(data, dst[:0])
		if err != nil {
			return fmt.Errorf("uncompress V3 zstd block: %w", err)
		}
		if len(out) != rawSize {
			return fmt.Errorf("uncompress V3 zstd size %d, want %d", len(out), rawSize)
		}
		if rawSize > 0 && &out[0] != &dst[0] {
			// Defensive fallback: should be unreachable given the capacity
			// guarantee above, but never silently return data decoded into a
			// detached buffer.
			copy(dst, out)
		}
		return nil
	default:
		return fmt.Errorf("unknown V3 block compression: %d", compression)
	}
}

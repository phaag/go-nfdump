// Copyright © 2026 Peter Haag peter@people.ops-trust.net
// All rights reserved.
//
// Use of this source code is governed by the license that can be
// found in the LICENSE file.

package nfdump

import (
	"context"
	"encoding/binary"
	"fmt"
	"os"

	zstd "github.com/klauspost/compress/zstd"
)

const (
	v18HeaderSize    = 48
	v18FooterSize    = 56
	v18DirectoryHead = 8
	v18DirectoryEnt  = 16
	v18BlockHeader   = 24
	v18FlowBlockHead = 56

	v18DirectoryMagic = 0xB10CB10C
	v18FooterMagic    = 0xA50F
	v18BlockFlow      = 1
	v18MaxBlockSize   = 64 << 20
)

type v18Header struct {
	nfdVersion  uint32
	created     uint64
	compression uint16
	flags       uint32
	blockSize   uint32
	dirSize     uint32
	dirOffset   uint64
}

type v18DirectoryEntry struct {
	typeID uint32
	size   uint32
	offset uint64
}

type v18Reader struct {
	owner       *NfFile
	file        *os.File
	header      v18Header
	entries     []v18DirectoryEntry
	zstdDecoder *zstd.Decoder
	// readBuf is a scratch buffer for the on-disk (possibly compressed) bytes
	// of the block currently being read. readBlock is only ever called
	// sequentially from the single producer goroutine in walk, and readBuf's
	// contents are never referenced once readBlock returns (the decompressed
	// result lives in its own freshly allocated slice), so reusing it across
	// blocks is safe and avoids a fresh multi-megabyte allocation per block.
	readBuf []byte
}

func openV18Reader(owner *NfFile, file *os.File, fileName string) (*v18Reader, error) {
	info, err := file.Stat()
	if err != nil {
		return nil, fmt.Errorf("nfFile stat %s: %w", fileName, err)
	}
	fileSize := info.Size()
	if fileSize < v18HeaderSize+v18FooterSize {
		return nil, fmt.Errorf("nfFile V3 file too short: %d bytes", fileSize)
	}

	headerBytes := make([]byte, v18HeaderSize)
	if _, err := file.ReadAt(headerBytes, 0); err != nil {
		return nil, fmt.Errorf("nfFile read V3 header: %w", err)
	}
	if binary.LittleEndian.Uint16(headerBytes[0:2]) != 0xA50C || binary.LittleEndian.Uint16(headerBytes[2:4]) != 3 {
		return nil, fmt.Errorf("nfFile invalid V3 header")
	}
	header := v18Header{
		nfdVersion:  binary.LittleEndian.Uint32(headerBytes[4:8]),
		created:     binary.LittleEndian.Uint64(headerBytes[8:16]),
		compression: binary.LittleEndian.Uint16(headerBytes[18:20]),
		flags:       binary.LittleEndian.Uint32(headerBytes[20:24]),
		blockSize:   binary.LittleEndian.Uint32(headerBytes[24:28]),
		dirSize:     binary.LittleEndian.Uint32(headerBytes[28:32]),
		dirOffset:   binary.LittleEndian.Uint64(headerBytes[32:40]),
	}
	if header.blockSize == 0 || header.blockSize > v18MaxBlockSize {
		return nil, fmt.Errorf("nfFile invalid V3 block size: %d", header.blockSize)
	}
	if header.compression > 5 {
		return nil, fmt.Errorf("nfFile unknown V3 compression: %d", header.compression)
	}
	if header.flags&1 != 0 {
		return nil, fmt.Errorf("nfFile encrypted V3 files are not supported")
	}

	footerBytes := make([]byte, v18FooterSize)
	if _, err := file.ReadAt(footerBytes, fileSize-v18FooterSize); err != nil {
		return nil, fmt.Errorf("nfFile read V3 footer: %w", err)
	}
	if binary.LittleEndian.Uint32(footerBytes[0:4]) != v18FooterMagic {
		return nil, fmt.Errorf("nfFile invalid V3 footer magic")
	}
	footerDirSize := binary.LittleEndian.Uint32(footerBytes[4:8])
	footerDirOffset := binary.LittleEndian.Uint64(footerBytes[8:16])
	if header.dirSize != footerDirSize || header.dirOffset != footerDirOffset {
		return nil, fmt.Errorf("nfFile V3 header and footer directory disagree")
	}
	if header.dirSize < v18DirectoryHead || header.dirOffset < v18HeaderSize ||
		header.dirOffset > uint64(fileSize-v18FooterSize) || uint64(header.dirSize) > uint64(fileSize-v18FooterSize)-header.dirOffset {
		return nil, fmt.Errorf("nfFile invalid V3 directory range")
	}

	directory := make([]byte, header.dirSize)
	if _, err := file.ReadAt(directory, int64(header.dirOffset)); err != nil {
		return nil, fmt.Errorf("nfFile read V3 directory: %w", err)
	}
	checksum := binary.LittleEndian.Uint64(footerBytes[16:24])
	if checksum != 0 && v3Checksum64(directory) != checksum {
		return nil, fmt.Errorf("nfFile V3 directory checksum mismatch")
	}
	if binary.LittleEndian.Uint32(directory[0:4]) != v18DirectoryMagic {
		return nil, fmt.Errorf("nfFile invalid V3 directory magic")
	}
	numEntries := binary.LittleEndian.Uint32(directory[4:8])
	if uint64(numEntries) > uint64((len(directory)-v18DirectoryHead)/v18DirectoryEnt) ||
		v18DirectoryHead+int(numEntries)*v18DirectoryEnt != len(directory) {
		return nil, fmt.Errorf("nfFile invalid V3 directory entry count")
	}
	entries := make([]v18DirectoryEntry, numEntries)
	flowBlocks := uint32(0)
	for i := range entries {
		offset := v18DirectoryHead + i*v18DirectoryEnt
		entry := v18DirectoryEntry{
			typeID: binary.LittleEndian.Uint32(directory[offset : offset+4]),
			size:   binary.LittleEndian.Uint32(directory[offset+4 : offset+8]),
			offset: binary.LittleEndian.Uint64(directory[offset+8 : offset+16]),
		}
		if entry.size < v18BlockHeader || entry.size > v18MaxBlockSize || entry.offset < v18HeaderSize || entry.offset > uint64(fileSize-v18FooterSize) ||
			uint64(entry.size) > uint64(fileSize-v18FooterSize)-entry.offset {
			return nil, fmt.Errorf("nfFile invalid V3 directory entry %d", i)
		}
		if entry.typeID == v18BlockFlow {
			flowBlocks++
		}
		entries[i] = entry
	}

	reader := &v18Reader{owner: owner, file: file, header: header, entries: entries}
	owner.info = FileInfo{
		Layout:        FileLayoutV3,
		NfdumpVersion: header.nfdVersion,
		Created:       header.created,
		Compression:   v18Compression(header.compression),
		Encrypted:     header.flags&1 != 0,
		BlockSize:     header.blockSize,
		FlowBlocks:    flowBlocks,
	}
	return reader, nil
}

func v18Compression(compression uint16) Compression {
	switch compression {
	case 2:
		return CompressionLZO
	case 3:
		return CompressionBzip2
	case 4:
		return CompressionLZ4
	case 5:
		return CompressionZSTD
	default:
		return CompressionNone
	}
}

func (reader *v18Reader) close() error {
	if reader.zstdDecoder != nil {
		reader.zstdDecoder.Close()
		reader.zstdDecoder = nil
	}
	if reader.file == nil {
		return nil
	}
	err := reader.file.Close()
	reader.file = nil
	return err
}

func (reader *v18Reader) walk(ctx context.Context, cancel context.CancelFunc, fn func(FlowRecord) error) error {
	checkEvery := reader.owner.walkContextCheckEvery
	blocks := make(chan []byte, 2)
	producerDone := make(chan error, 1)
	go func() {
		defer close(blocks)
		producerDone <- reader.readFlowBlocks(ctx, blocks)
	}()

	var walkErr error
	for block := range blocks {
		if err := ctx.Err(); err != nil {
			walkErr = err
			cancel()
			break
		}
		flowCount, nextCheck := uint32(0), uint32(0)
		walkErr = reader.processFlowBlock(block, func(record FlowRecord) error {
			if checkEvery != 0 && flowCount == nextCheck {
				if err := ctx.Err(); err != nil {
					return err
				}
				nextCheck += checkEvery
			}
			flowCount++
			return fn(record)
		})
		if walkErr != nil {
			cancel()
			break
		}
	}
	producerErr := <-producerDone
	if walkErr != nil {
		return walkErr
	}
	return producerErr
}

func (reader *v18Reader) readFlowBlocks(ctx context.Context, blocks chan<- []byte) error {
	for i, entry := range reader.entries {
		if err := ctx.Err(); err != nil {
			return err
		}
		if entry.typeID != v18BlockFlow {
			continue
		}
		block, err := reader.readBlock(entry)
		if err != nil {
			return fmt.Errorf("read V3 flow block %d: %w", i, err)
		}
		select {
		case blocks <- block:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return nil
}

func (reader *v18Reader) readBlock(entry v18DirectoryEntry) ([]byte, error) {
	if cap(reader.readBuf) < int(entry.size) {
		reader.readBuf = make([]byte, entry.size)
	}
	onDisk := reader.readBuf[:entry.size]
	if _, err := reader.file.ReadAt(onDisk, int64(entry.offset)); err != nil {
		return nil, err
	}
	if binary.LittleEndian.Uint32(onDisk[0:4]) != entry.typeID || binary.LittleEndian.Uint32(onDisk[4:8]) != entry.size {
		return nil, fmt.Errorf("block header does not match directory")
	}
	rawSize := binary.LittleEndian.Uint32(onDisk[8:12])
	compression := binary.LittleEndian.Uint16(onDisk[12:14])
	encryption := binary.LittleEndian.Uint16(onDisk[14:16])
	checksum := binary.LittleEndian.Uint64(onDisk[16:24])
	if rawSize < v18BlockHeader || rawSize > reader.header.blockSize {
		return nil, fmt.Errorf("invalid raw block size %d", rawSize)
	}
	if checksum != 0 && v3Checksum64(onDisk[v18BlockHeader:]) != checksum {
		return nil, fmt.Errorf("block checksum mismatch")
	}
	if encryption != 0 {
		return nil, fmt.Errorf("encrypted V3 blocks are not supported")
	}
	if compression == 0 {
		compression = reader.header.compression
	}
	// The V3 block header carries the exact decompressed size (rawSize), so
	// unlike V2/1.7.x we can allocate the final, correctly sized buffer once
	// and have uncompressV18 decode straight into its tail - no separate
	// scratch decompression buffer and no second copy to assemble the result.
	block := make([]byte, rawSize)
	copy(block, onDisk[:v18BlockHeader])
	if err := reader.uncompressV18(onDisk[v18BlockHeader:], compression, block[v18BlockHeader:]); err != nil {
		return nil, err
	}
	return block, nil
}

func (reader *v18Reader) processFlowBlock(block []byte, fn func(FlowRecord) error) error {
	if len(block) < v18FlowBlockHead || binary.LittleEndian.Uint32(block[0:4]) != v18BlockFlow {
		return fmt.Errorf("invalid V3 flow block")
	}
	numRecords := int(binary.LittleEndian.Uint32(block[24:28]))
	offset := v18FlowBlockHead
	for i := 0; i < numRecords; i++ {
		if offset+4 > len(block) {
			return fmt.Errorf("V3 flow record %d header is truncated", i)
		}
		recordSize := int(binary.LittleEndian.Uint16(block[offset+2 : offset+4]))
		if recordSize < v4RecordHeaderSize || offset+recordSize > len(block) {
			return fmt.Errorf("V3 flow record %d has invalid size %d", i, recordSize)
		}
		record, err := newFlowRecordV4(block[offset : offset+recordSize])
		if err != nil {
			return fmt.Errorf("V3 flow record %d: %w", i, err)
		}
		if err := fn(record); err != nil {
			return err
		}
		offset += recordSize
	}
	if offset != len(block) {
		return fmt.Errorf("V3 flow record count does not consume block data")
	}
	return nil
}

var _ fileReader = (*v18Reader)(nil)

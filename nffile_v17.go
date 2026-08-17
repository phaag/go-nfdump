// Copyright © 2026 Peter Haag peter@people.ops-trust.net
// All rights reserved.
//
// Use of this source code is governed by the license that can be
// found in the LICENSE file.

package nfdump

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"os"

	zstd "github.com/klauspost/compress/zstd"
)

// v17Reader handles the V1/V2 containers and V3 flow records emitted by
// nfdump 1.7.x. The name describes the nfdump generation, not an exported
// file-format contract.
type v17Reader struct {
	owner       *NfFile
	file        *os.File
	header      NfFileHeader
	zstdDecoder *zstd.Decoder
}

func openV17ReaderV2(owner *NfFile, file *os.File, fileName string) (*v17Reader, error) {
	var header NfFileHeader
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return nil, fmt.Errorf("nfFile seek header: %w", err)
	}
	if err := binary.Read(file, binary.LittleEndian, &header); err != nil {
		return nil, fmt.Errorf("nfFile read V2 header on %s: %w", fileName, err)
	}
	if header.BlockSize > BUFFSIZE {
		return nil, fmt.Errorf("nfFile invalid block size: %d", header.BlockSize)
	}
	if header.Compression > ZSTD_COMPRESSED {
		return nil, fmt.Errorf("nfFile unknown compression: %d", header.Compression)
	}
	if header.Encryption != 0 {
		return nil, fmt.Errorf("nfFile encrypted files are not supported")
	}
	if header.AppendixBlocks > 0 {
		info, err := file.Stat()
		if err != nil {
			return nil, fmt.Errorf("nfFile stat %s: %w", fileName, err)
		}
		if header.OffAppendix >= uint64(info.Size()) {
			return nil, fmt.Errorf("nfFile invalid appendix offset: %d", header.OffAppendix)
		}
	}

	reader := &v17Reader{owner: owner, file: file, header: header}
	owner.Header = header // Deprecated V1/V2 compatibility field.
	owner.info = FileInfo{
		Layout:        FileLayoutV2,
		NfdumpVersion: header.NfVersion,
		Created:       header.Created,
		Compression:   Compression(header.Compression),
		Encrypted:     header.Encryption != 0,
		BlockSize:     header.BlockSize,
		FlowBlocks:    header.NumBlocks,
	}
	if err := reader.readAppendix(); err != nil {
		reader.close()
		return nil, err
	}
	return reader, nil
}

// blockSizeLimit returns the maximum uncompressed V1/V2 block payload. Early
// 1.7 files may leave BlockSize unset; nfdump reads those using BUFFSIZE.
func (reader *v17Reader) blockSizeLimit() uint32 {
	if reader.header.BlockSize == 0 {
		return BUFFSIZE
	}
	return reader.header.BlockSize
}

func (reader *v17Reader) close() error {
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

// readAppendix reads a V2 appendix and updates the owner metadata.
func (reader *v17Reader) readAppendix() error {
	currentPos, err := reader.file.Seek(0, io.SeekCurrent)
	if err != nil {
		return fmt.Errorf("nfFile seek appendix: %w", err)
	}
	defer reader.file.Seek(currentPos, io.SeekStart)

	if _, err = reader.file.Seek(int64(reader.header.OffAppendix), io.SeekStart); err != nil {
		return fmt.Errorf("nfFile seek appendix: %w", err)
	}

	var blockHeader DataBlockHeader
	for i := 0; i < int(reader.header.AppendixBlocks); i++ {
		if err := binary.Read(reader.file, binary.LittleEndian, &blockHeader); err != nil {
			return fmt.Errorf("nfFile read appendix block: %w", err)
		}
		dataBlock, err := reader.uncompressBlock(&blockHeader)
		if err != nil {
			return fmt.Errorf("nfFile read appendix block: %w", err)
		}
		b := bytes.NewBuffer(dataBlock)
		for j := 0; j < int(blockHeader.NumRecords); j++ {
			var record recordHeader
			if err := binary.Read(b, binary.LittleEndian, &record); err != nil {
				return fmt.Errorf("read appendix record %d: %w", j, err)
			}
			if record.Size < uint16(binary.Size(recordHeader{})) || int(record.Size) > b.Len()+binary.Size(recordHeader{}) {
				return fmt.Errorf("read appendix record %d: invalid size %d", j, record.Size)
			}
			payload := make([]byte, int(record.Size)-binary.Size(recordHeader{}))
			if _, err := io.ReadFull(b, payload); err != nil {
				return fmt.Errorf("read appendix record %d: %w", j, err)
			}
			switch record.Type {
			case TYPE_IDENT:
				reader.owner.ident = string(payload)
			case TYPE_STAT:
				if len(payload) != binary.Size(StatRecord{}) {
					return fmt.Errorf("read appendix record %d: invalid stat size %d", j, record.Size)
				}
				if err := binary.Read(bytes.NewReader(payload), binary.LittleEndian, &reader.owner.StatRecord); err != nil {
					return fmt.Errorf("read appendix record %d: %w", j, err)
				}
			}
		}
	}
	return nil
}

func (reader *v17Reader) readDataBlocks(ctx context.Context, blockChannel chan<- DataBlock) error {
	for i := 0; i < int(reader.header.NumBlocks); i++ {
		if err := ctx.Err(); err != nil {
			return err
		}
		dataBlock := DataBlock{}
		if err := binary.Read(reader.file, binary.LittleEndian, &dataBlock.Header); err != nil {
			return fmt.Errorf("read data block %d header: %w", i, err)
		}
		if dataBlock.Header.Size > reader.blockSizeLimit() {
			return fmt.Errorf("read data block %d: size %d exceeds block size %d", i, dataBlock.Header.Size, reader.blockSizeLimit())
		}
		if dataBlock.Header.Type != 3 {
			if _, err := reader.file.Seek(int64(dataBlock.Header.Size), io.SeekCurrent); err != nil {
				return fmt.Errorf("skip data block %d: %w", i, err)
			}
			continue
		}
		var err error
		dataBlock.Data, err = reader.uncompressBlock(&dataBlock.Header)
		if err != nil {
			return fmt.Errorf("read data block %d: %w", i, err)
		}
		select {
		case blockChannel <- dataBlock:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return nil
}

func (reader *v17Reader) walk(ctx context.Context, cancel context.CancelFunc, fn func(FlowRecord) error) error {
	blockChannel := make(chan DataBlock, 2)
	producerDone := make(chan error, 1)
	go func() {
		defer close(blockChannel)
		producerDone <- reader.readDataBlocks(ctx, blockChannel)
	}()

	var walkErr error
	for dataBlock := range blockChannel {
		if err := ctx.Err(); err != nil {
			walkErr = err
			cancel()
			break
		}
		walkErr = reader.processDataBlock(dataBlock, func(raw []byte) error {
			if err := ctx.Err(); err != nil {
				return err
			}
			record, err := newFlowRecordV3(raw)
			if err != nil {
				return err
			}
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

func (reader *v17Reader) processDataBlock(dataBlock DataBlock, handleFlow func([]byte) error) error {
	if int(dataBlock.Header.Size) != len(dataBlock.Data) {
		return fmt.Errorf("data block size mismatch: header %d, data %d", dataBlock.Header.Size, len(dataBlock.Data))
	}
	offset := 0
	for i := 0; i < int(dataBlock.Header.NumRecords); i++ {
		if len(dataBlock.Data)-offset < binary.Size(recordHeader{}) {
			return fmt.Errorf("data block record %d: truncated record header", i)
		}
		recordType := binary.LittleEndian.Uint16(dataBlock.Data[offset : offset+2])
		recordSize := binary.LittleEndian.Uint16(dataBlock.Data[offset+2 : offset+4])
		if recordSize < uint16(binary.Size(recordHeader{})) || int(recordSize) > len(dataBlock.Data)-offset {
			return fmt.Errorf("data block record %d: invalid size %d", i, recordSize)
		}
		recordData := dataBlock.Data[offset : offset+int(recordSize)]
		switch recordType {
		case V3Record:
			if err := handleFlow(recordData); err != nil {
				return fmt.Errorf("data block record %d: %w", i, err)
			}
		case ExporterInfoRecordType:
			if err := reader.owner.addExporterInfo(recordData); err != nil {
				return fmt.Errorf("data block record %d: %w", i, err)
			}
		case ExporterStatRecordType:
			if err := reader.owner.addExporterStat(recordData); err != nil {
				return fmt.Errorf("data block record %d: %w", i, err)
			}
		case SamplerRecordType:
			if err := reader.owner.addSampler(recordData); err != nil {
				return fmt.Errorf("data block record %d: %w", i, err)
			}
		}
		offset += int(recordSize)
	}
	if offset != len(dataBlock.Data) {
		return fmt.Errorf("data block record count %d does not consume block data", dataBlock.Header.NumRecords)
	}
	return nil
}

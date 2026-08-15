// Copyright © 2024-2026 Peter Haag peter@people.ops-trust.net
// All rights reserved.
//
// Use of this source code is governed by the license that can be
// found in the LICENSE file.

// Package nfdump provides an API for nfdump files
package nfdump

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"sync"

	zstd "github.com/klauspost/compress/zstd"
)

type NfFile struct {
	readMu       sync.Mutex
	stateMu      sync.Mutex
	readCancel   context.CancelFunc
	file         *os.File
	Header       NfFileHeader
	ident        string
	StatRecord   StatRecord
	ExporterList []Exporter
	zstdDecoder  *zstd.Decoder
}

const NOT_COMPRESSED = 0
const LZO_COMPRESSED = 1
const BZ2_COMPRESSED = 2
const LZ4_COMPRESSED = 3
const ZSTD_COMPRESSED = 4

const BUFFSIZE = 5 * 1048576

const (
	flagBlockUncompressed = 0x1
	flagBlockUnencrypted  = 0x2
)

type NfFileHeader struct {
	Magic       uint16 // magic 0xA50C to recognize nfdump file type and endian type
	Version     uint16 // version of binary file layout. Valid: version 2
	NfVersion   uint32 // version of nfdump created this file
	Created     uint64 // file creat time
	Compression uint8  // type of compression
	// NOT_COMPRESSED 0
	// LZO_COMPRESSED 1
	// BZ2_COMPRESSED 2
	// LZ4_COMPRESSED 3
	// ZSTD_COMPRESSED 4
	Encryption uint8 // type of encryption
	// NOT_ENCRYPTED 0
	AppendixBlocks uint16 // number of blocks to read from appendix
	Unused         uint32 // unused. must be 0
	OffAppendix    uint64 // // offset in file for appendix blocks with additional data
	BlockSize      uint32 // max block size of a data block
	NumBlocks      uint32 // number of data blocks in file
}

type DataBlockHeader struct {
	NumRecords uint32 // size of this block in bytes without this header
	Size       uint32 // size of this block in bytes without this header
	Type       uint16 // Block type
	// DATA_BLOCK_TYPE_3   3
	// DATA_BLOCK_TYPE_4   4
	Flags uint16
	// Bit 0: 0: file block compression, 1: block uncompressed
	// Bit 1: 0: file block encryption, 1: block unencrypted
	// Bit 2: 0: no autoread, 1: autoread - internal structure
}

type DataBlock struct {
	Header DataBlockHeader
	Data   []byte
	// Err is set when the reader encounters a terminal stream error. Consumers
	// must stop reading when it is non-nil.
	Err error
}

/*
 * Generic data record
 * Contains any type of data, specified by type
 */
type recordHeader struct {
	// record header
	Type uint16 // type of data
	Size uint16 // size of record including this header
}

type StatRecord struct {
	// overall stat
	Numflows   uint64
	Numbytes   uint64
	Numpackets uint64
	// flow stat
	NumflowsTcp   uint64
	NumflowsUdp   uint64
	NumflowsIcmp  uint64
	NumflowsOther uint64
	// bytes stat
	NumbytesTcp   uint64
	NumbytesUdp   uint64
	NumbytesIcmp  uint64
	NumbytesOther uint64
	// packet stat
	NumpacketsTcp   uint64
	NumpacketsUdp   uint64
	NumpacketsIcmp  uint64
	NumpacketsOther uint64
	// time window
	FirstSeen uint64
	LastSeen  uint64
	// other
	SequenceFailure uint64
}

const TYPE_IDENT = 0x8001
const TYPE_STAT = 0x8002

// New returns a new empty NfFile object
func New() *NfFile {
	return new(NfFile)
}

// blockSizeLimit returns the maximum block payload size. Early 1.7 files may
// leave BlockSize unset; nfdump reads those with its historical BUFFSIZE cap.
func (nfFile *NfFile) blockSizeLimit() uint32 {
	if nfFile.Header.BlockSize == 0 {
		return BUFFSIZE
	}
	return nfFile.Header.BlockSize
}

// print %v string function
// if an NfFile object is printed String() is called
func (nfFile *NfFile) String() string {
	s := fmt.Sprintf("Magic          :  0x%x\n", nfFile.Header.Magic) +
		fmt.Sprintf("Version        :  %d\n", nfFile.Header.Version) +
		fmt.Sprintf("NfVersion      :  0x%x\n", nfFile.Header.NfVersion) +
		fmt.Sprintf("Created        :  %d\n", nfFile.Header.Created) +
		fmt.Sprintf("Compression    :  %d\n", nfFile.Header.Compression) +
		fmt.Sprintf("Encryption     :  %d\n", nfFile.Header.Encryption) +
		fmt.Sprintf("appendixBlocks :  %d\n", nfFile.Header.AppendixBlocks) +
		fmt.Sprintf("unused         :  %d\n", nfFile.Header.Unused) +
		fmt.Sprintf("offAppendix    :  %d\n", nfFile.Header.OffAppendix) +
		fmt.Sprintf("BlockSize      :  %d\n", nfFile.Header.BlockSize) +
		fmt.Sprintf("NumBlocks      :  %d\n", nfFile.Header.NumBlocks) +
		fmt.Sprintf("Ident          : %s\n", nfFile.ident) +
		fmt.Sprintf("Stat           : %v\n", nfFile.StatRecord)
	return s
}

// readAppendix reads the NfFile appendix if available and updates
// the NfFile object
func (nfFile *NfFile) readAppendix() error {

	currentPos, err := nfFile.file.Seek(0, io.SeekCurrent)
	if err != nil {
		return fmt.Errorf("nfFile Seek(): %v", err)
	}

	if _, err = nfFile.file.Seek(int64(nfFile.Header.OffAppendix), io.SeekStart); err != nil {
		return fmt.Errorf("nfFile Seek(): %v", err)
	}

	var blockHeader DataBlockHeader
	for i := 0; i < int(nfFile.Header.AppendixBlocks); i++ {
		if err := binary.Read(nfFile.file, binary.LittleEndian, &blockHeader); err != nil {
			nfFile.file.Seek(currentPos, io.SeekStart)
			return fmt.Errorf("nfFile read appendix block: %v", err)
		}

		dataBlock, err := nfFile.uncompressBlock(&blockHeader)
		if err != nil {
			nfFile.file.Seek(currentPos, io.SeekStart)
			return fmt.Errorf("nfFile read appendix block: %v", err)
		}

		b := bytes.NewBuffer(dataBlock)

		for j := 0; j < int(blockHeader.NumRecords); j++ {
			var record recordHeader
			if err := binary.Read(b, binary.LittleEndian, &record); err != nil {
				return fmt.Errorf("read appendix record %d: %w", j, err)
			}
			if record.Size < uint16(binary.Size(recordHeader{})) {
				return fmt.Errorf("read appendix record %d: invalid size %d", j, record.Size)
			}
			if int(record.Size) > b.Len()+binary.Size(recordHeader{}) {
				return fmt.Errorf("read appendix record %d: size %d exceeds block", j, record.Size)
			}
			var readErr error
			switch record.Type {
			case TYPE_IDENT:
				ident := make([]byte, record.Size-4) // 4 header
				readErr = binary.Read(b, binary.LittleEndian, &ident)
				if readErr == nil {
					nfFile.ident = string(ident)
				}
			case TYPE_STAT:
				if record.Size != uint16(binary.Size(StatRecord{})+binary.Size(recordHeader{})) {
					return fmt.Errorf("read appendix record %d: invalid stat size %d", j, record.Size)
				}
				readErr = binary.Read(b, binary.LittleEndian, &nfFile.StatRecord)
			default:
				// skip
				if record.Size > 4 {
					recordData := make([]byte, record.Size-4)
					readErr = binary.Read(b, binary.LittleEndian, &recordData)
				}
			}
			if readErr != nil {
				return fmt.Errorf("read appendix record %d: %w", j, readErr)
			}
		}
	}

	if _, err = nfFile.file.Seek(currentPos, io.SeekStart); err != nil {
		return fmt.Errorf("nfFile Seek(): %v", err)
	}
	return nil
}

// Open opens an nffile given as string argument
func (nfFile *NfFile) Open(fileName string) error {
	nfFile.cancelRead()
	nfFile.readMu.Lock()
	defer nfFile.readMu.Unlock()

	if nfFile.file != nil {
		if err := nfFile.close(); err != nil {
			return fmt.Errorf("nfFile close previous file: %w", err)
		}
	}

	file, err := os.Open(fileName)
	if err != nil {
		return fmt.Errorf("nfFile Open() on %s: %v", fileName, err)
	}

	if err = binary.Read(file, binary.LittleEndian, &nfFile.Header); err != nil {
		file.Close()
		return fmt.Errorf("nfFile read header on %s: %v", fileName, err)
	}

	if nfFile.Header.Magic != 0xA50C {
		file.Close()
		return fmt.Errorf("nfFile read header, bad magic : 0x%x", nfFile.Header.Magic)
	}

	if nfFile.Header.Version == 2 {
		if nfFile.Header.BlockSize > BUFFSIZE {
			file.Close()
			return fmt.Errorf("nfFile invalid block size: %d", nfFile.Header.BlockSize)
		}
		if nfFile.Header.Compression > ZSTD_COMPRESSED {
			file.Close()
			return fmt.Errorf("nfFile unknown compression: %d", nfFile.Header.Compression)
		}
		if nfFile.Header.Encryption != 0 {
			file.Close()
			return fmt.Errorf("nfFile encrypted files are not supported")
		}
		if nfFile.Header.AppendixBlocks > 0 {
			info, statErr := file.Stat()
			if statErr != nil || nfFile.Header.OffAppendix >= uint64(info.Size()) {
				file.Close()
				if statErr != nil {
					return fmt.Errorf("nfFile stat %s: %w", fileName, statErr)
				}
				return fmt.Errorf("nfFile invalid appendix offset: %d", nfFile.Header.OffAppendix)
			}
		}
	}

	nfFile.ExporterList = make([]Exporter, 8)
	nfFile.file = file
	switch nfFile.Header.Version {
	case 1:
		return nfFile.openV1()
	case 2:
		if err := nfFile.readAppendix(); err != nil {
			nfFile.close()
			return err
		}
		return nil
	default:
		file.Close()
		nfFile.file = nil
		return fmt.Errorf("nfFile unknown version: %d", nfFile.Header.Version)
	}
	// unreached
}

// Closes the current underlaying file
func (nfFile *NfFile) Close() error {
	nfFile.cancelRead()
	nfFile.readMu.Lock()
	defer nfFile.readMu.Unlock()
	return nfFile.close()
}

func (nfFile *NfFile) close() error {
	if nfFile.zstdDecoder != nil {
		nfFile.zstdDecoder.Close()
		nfFile.zstdDecoder = nil
	}
	if nfFile.file == nil {
		return nil
	}
	err := nfFile.file.Close()
	nfFile.file = nil
	return err
}

func (nfFile *NfFile) setReadCancel(cancel context.CancelFunc) {
	nfFile.stateMu.Lock()
	nfFile.readCancel = cancel
	nfFile.stateMu.Unlock()
}

func (nfFile *NfFile) clearReadCancel() {
	nfFile.stateMu.Lock()
	nfFile.readCancel = nil
	nfFile.stateMu.Unlock()
}

func (nfFile *NfFile) cancelRead() {
	nfFile.stateMu.Lock()
	cancel := nfFile.readCancel
	nfFile.stateMu.Unlock()
	if cancel != nil {
		cancel()
	}
}

// Ident returns the identifier of the current NfFile object
func (nfFile *NfFile) Ident() string {
	return nfFile.ident
}

// Stat returns the stat record of the current NfFile object
func (nfFile *NfFile) Stat() StatRecord {
	return nfFile.StatRecord
}

// ReadDataBlocks iterates over the underlaying file and decompresses the data blocks
// A channel with all uncompressed data blocks is returned.
func (nfFile *NfFile) ReadDataBlocks() (chan DataBlock, error) {
	blockChannel := make(chan DataBlock, 16)
	nfFile.readMu.Lock()
	if nfFile.file == nil {
		nfFile.readMu.Unlock()
		close(blockChannel)
		return blockChannel, fmt.Errorf("nfFile read data blocks: no open file")
	}
	ctx, cancel := context.WithCancel(context.Background())
	nfFile.setReadCancel(cancel)
	go func() {
		defer cancel()
		defer nfFile.clearReadCancel()
		defer nfFile.readMu.Unlock()
		defer close(blockChannel)
		if err := nfFile.readDataBlocks(ctx, blockChannel); err != nil && ctx.Err() == nil {
			select {
			case blockChannel <- DataBlock{Err: err}:
			case <-ctx.Done():
			}
		}
	}()
	return blockChannel, nil
}

// readDataBlocks reads and decompresses Type-3 blocks into blockChannel. The
// caller owns the file-read lock and is responsible for closing blockChannel.
func (nfFile *NfFile) readDataBlocks(ctx context.Context, blockChannel chan<- DataBlock) error {
	for i := 0; i < int(nfFile.Header.NumBlocks); i++ {
		if err := ctx.Err(); err != nil {
			return err
		}

		dataBlock := DataBlock{}
		if err := binary.Read(nfFile.file, binary.LittleEndian, &dataBlock.Header); err != nil {
			return fmt.Errorf("read data block %d header: %w", i, err)
		}
		if dataBlock.Header.Size > nfFile.blockSizeLimit() {
			return fmt.Errorf("read data block %d: size %d exceeds block size %d", i, dataBlock.Header.Size, nfFile.blockSizeLimit())
		}
		if dataBlock.Header.Type != 3 {
			if _, err := nfFile.file.Seek(int64(dataBlock.Header.Size), io.SeekCurrent); err != nil {
				return fmt.Errorf("skip data block %d: %w", i, err)
			}
			continue
		}

		var err error
		dataBlock.Data, err = nfFile.uncompressBlock(&dataBlock.Header)
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

// function to retrieve all records from nfFile handle.
// it reads and uncompresses the data blocks with ReadDataBlocks
// it converts the raw byte stream into a *FlowRecordV3
// - does not take any options
//
// returns a record chain object
func (nfFile *NfFile) AllRecords() *RecordChain {
	recordChannel := make(chan *FlowRecordV3, 32)
	chain := &RecordChain{recordChan: recordChannel}
	go func() {
		defer close(recordChannel)
		blockChannel, err := nfFile.ReadDataBlocks()
		if err != nil {
			chain.setErr(err)
			return
		}
		for dataBlock := range blockChannel {
			if dataBlock.Err != nil {
				chain.setErr(dataBlock.Err)
				return
			}
			if err := nfFile.processDataBlock(dataBlock, func(raw []byte) error {
				record, err := NewRecord(raw)
				if err != nil {
					return err
				}
				record.GetSamplerInfo(nfFile)
				recordChannel <- record
				return nil
			}); err != nil {
				chain.setErr(err)
				return
			}
		}
	}()
	return chain
}

// Walk reads flow records while a single producer goroutine prefetches and
// decompresses upcoming blocks. fn runs in the caller's goroutine. Records are
// compact views of the current block and must be copied with Clone before retaining
// them after fn returns.
func (nfFile *NfFile) Walk(ctx context.Context, fn func(FlowRecord) error) error {
	if ctx == nil {
		return fmt.Errorf("nfFile walk: nil context")
	}
	if fn == nil {
		return fmt.Errorf("nfFile walk: nil callback")
	}

	nfFile.readMu.Lock()
	if nfFile.file == nil {
		nfFile.readMu.Unlock()
		return fmt.Errorf("nfFile walk: no open file")
	}

	walkCtx, cancel := context.WithCancel(ctx)
	nfFile.setReadCancel(cancel)
	blockChannel := make(chan DataBlock, 2)
	producerDone := make(chan error, 1)
	go func() {
		defer close(blockChannel)
		producerDone <- nfFile.readDataBlocks(walkCtx, blockChannel)
	}()

	var walkErr error
	for dataBlock := range blockChannel {
		if err := ctx.Err(); err != nil {
			walkErr = err
			cancel()
			break
		}
		walkErr = nfFile.processDataBlock(dataBlock, func(raw []byte) error {
			if err := walkCtx.Err(); err != nil {
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
	cancel()
	producerErr := <-producerDone
	nfFile.clearReadCancel()
	nfFile.readMu.Unlock()

	if walkErr != nil {
		return walkErr
	}
	if producerErr != nil {
		return producerErr
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	return nil
}

func (nfFile *NfFile) processDataBlock(dataBlock DataBlock, handleFlow func([]byte) error) error {
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
			if err := nfFile.addExporterInfo(recordData); err != nil {
				return fmt.Errorf("data block record %d: %w", i, err)
			}
		case ExporterStatRecordType:
			if err := nfFile.addExporterStat(recordData); err != nil {
				return fmt.Errorf("data block record %d: %w", i, err)
			}
		case SamplerLegacyRecordType:
			// Not processed for now.
		case SamplerRecordType:
			if err := nfFile.addSampler(recordData); err != nil {
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

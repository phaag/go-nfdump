// Copyright © 2024-2026 Peter Haag peter@people.ops-trust.net
// All rights reserved.
//
// Use of this source code is governed by the license that can be
// found in the LICENSE file.

// Package nfdump provides an API for nfdump files
package nfdump

import (
	"context"
	"encoding/binary"
	"fmt"
	"os"
	"sync"
)

type NfFile struct {
	readMu                sync.Mutex
	stateMu               sync.Mutex
	readCancel            context.CancelFunc
	reader                fileReader
	walkContextCheckEvery uint32
	// Header is the V1/V2 container header retained for compatibility. It is
	// not populated for newer container layouts; use Info for new code.
	Header       NfFileHeader
	info         FileInfo
	ident        string
	StatRecord   StatRecord
	ExporterList []Exporter
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
	return &NfFile{walkContextCheckEvery: 256}
}

// print %v string function
// if an NfFile object is printed String() is called
func (nfFile *NfFile) String() string {
	info := nfFile.Info()
	s := fmt.Sprintf("Layout         :  V%d\n", info.Layout) +
		fmt.Sprintf("NfVersion      :  0x%x\n", info.NfdumpVersion) +
		fmt.Sprintf("Created        :  %d\n", info.Created) +
		fmt.Sprintf("Compression    :  %d\n", info.Compression) +
		fmt.Sprintf("Encryption     :  %t\n", info.Encrypted) +
		fmt.Sprintf("BlockSize      :  %d\n", info.BlockSize) +
		fmt.Sprintf("FlowBlocks     :  %d\n", info.FlowBlocks) +
		fmt.Sprintf("Ident          : %s\n", nfFile.ident) +
		fmt.Sprintf("Stat           : %v\n", nfFile.StatRecord)
	return s
}

// Open opens an nffile given as string argument
func (nfFile *NfFile) Open(fileName string) error {
	nfFile.cancelRead()
	nfFile.readMu.Lock()
	defer nfFile.readMu.Unlock()

	if nfFile.reader != nil {
		if err := nfFile.close(); err != nil {
			return fmt.Errorf("nfFile close previous file: %w", err)
		}
	}

	file, err := os.Open(fileName)
	if err != nil {
		return fmt.Errorf("nfFile Open() on %s: %v", fileName, err)
	}

	var prefix struct {
		Magic   uint16
		Version uint16
	}
	if err = binary.Read(file, binary.LittleEndian, &prefix); err != nil {
		file.Close()
		return fmt.Errorf("nfFile read header on %s: %v", fileName, err)
	}

	if prefix.Magic != 0xA50C {
		file.Close()
		return fmt.Errorf("nfFile read header, bad magic : 0x%x", prefix.Magic)
	}

	nfFile.ExporterList = make([]Exporter, 8)
	nfFile.Header = NfFileHeader{}
	nfFile.info = FileInfo{}
	nfFile.ident = ""
	nfFile.StatRecord = StatRecord{}

	switch prefix.Version {
	case 1:
		reader, err := openV17ReaderV1(nfFile, file)
		if err != nil {
			file.Close()
			return err
		}
		nfFile.reader = reader
		return nil
	case 2:
		reader, err := openV17ReaderV2(nfFile, file, fileName)
		if err != nil {
			file.Close()
			return err
		}
		nfFile.reader = reader
		return nil
	case 3:
		reader, err := openV18Reader(nfFile, file, fileName)
		if err != nil {
			file.Close()
			return err
		}
		nfFile.reader = reader
		return nil
	default:
		file.Close()
		return unsupportedError{operation: "open", layout: FileLayout(prefix.Version)}
	}
}

// Closes the current underlaying file
func (nfFile *NfFile) Close() error {
	nfFile.cancelRead()
	nfFile.readMu.Lock()
	defer nfFile.readMu.Unlock()
	return nfFile.close()
}

func (nfFile *NfFile) close() error {
	if nfFile.reader == nil {
		return nil
	}
	err := nfFile.reader.close()
	nfFile.reader = nil
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

// Info returns format-neutral metadata for the currently open file.
func (nfFile *NfFile) Info() FileInfo {
	return nfFile.info
}

// Stat returns the stat record of the current NfFile object
func (nfFile *NfFile) Stat() StatRecord {
	return nfFile.StatRecord
}

// ReadDataBlocks iterates over a V1/V2 file and decompresses its Type-3 data
// blocks. It is a legacy, container-specific API; use Walk for new code.
func (nfFile *NfFile) ReadDataBlocks() (chan DataBlock, error) {
	blockChannel := make(chan DataBlock, 16)
	nfFile.readMu.Lock()
	reader, ok := nfFile.reader.(dataBlockReader)
	if !ok {
		nfFile.readMu.Unlock()
		close(blockChannel)
		if nfFile.reader == nil {
			return blockChannel, fmt.Errorf("nfFile read data blocks: no open file")
		}
		return blockChannel, unsupportedError{operation: "ReadDataBlocks", layout: nfFile.info.Layout}
	}
	ctx, cancel := context.WithCancel(context.Background())
	nfFile.setReadCancel(cancel)
	go func() {
		defer cancel()
		defer nfFile.clearReadCancel()
		defer nfFile.readMu.Unlock()
		defer close(blockChannel)
		if err := reader.readDataBlocks(ctx, blockChannel); err != nil && ctx.Err() == nil {
			select {
			case blockChannel <- DataBlock{Err: err}:
			case <-ctx.Done():
			}
		}
	}()
	return blockChannel, nil
}

// AllRecords is the legacy V1/V2 API. It reads Type-3 data blocks and converts
// their V3 flow records into owned *FlowRecordV3 values. Use Walk for the
// format-neutral streaming API.
func (nfFile *NfFile) AllRecords() *RecordChain {
	recordChannel := make(chan *FlowRecordV3, 32)
	chain := &RecordChain{recordChan: recordChannel}
	go func() {
		defer close(recordChannel)
		reader, ok := nfFile.reader.(legacyRecordReader)
		if !ok {
			if nfFile.reader == nil {
				chain.setErr(fmt.Errorf("nfFile all records: no open file"))
			} else {
				chain.setErr(unsupportedError{operation: "AllRecords", layout: nfFile.info.Layout})
			}
			return
		}
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
			if err := reader.processDataBlock(dataBlock, func(raw []byte) error {
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
// them after fn returns. Context cancellation is checked before each block and
// at least once every 256 flow records within a block.
func (nfFile *NfFile) Walk(ctx context.Context, fn func(FlowRecord) error) error {
	if ctx == nil {
		return fmt.Errorf("nfFile walk: nil context")
	}
	if fn == nil {
		return fmt.Errorf("nfFile walk: nil callback")
	}

	nfFile.readMu.Lock()
	if nfFile.reader == nil {
		nfFile.readMu.Unlock()
		return fmt.Errorf("nfFile walk: no open file")
	}

	walkCtx, cancel := context.WithCancel(ctx)
	nfFile.setReadCancel(cancel)
	reader := nfFile.reader
	walkErr := reader.walk(walkCtx, cancel, fn)
	cancel()
	nfFile.clearReadCancel()
	nfFile.readMu.Unlock()

	if walkErr != nil {
		return walkErr
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	return nil
}

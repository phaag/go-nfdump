/*
 *  Copyright (c) 2023, Peter Haag
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
	"encoding/binary"
	"fmt"
	"io"
	"os"
)

type NfFile struct {
	file       *os.File
	Header     NfFileHeader
	ident      string
	StatRecord StatRecord
}

const NOT_COMPRESSED = 0
const LZO_COMPRESSED = 1
const BZ2_COMPRESSED = 2
const LZ4_COMPRESSED = 3

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
			binary.Read(b, binary.LittleEndian, &record)
			/*
				fmt.Printf("Record type: %d\n", record.Type)
				fmt.Printf("Record size: %d\n", record.Size)
			*/
			switch record.Type {
			case TYPE_IDENT:
				ident := make([]byte, record.Size-5) // 5: 4 header + 0 byte
				binary.Read(b, binary.LittleEndian, &ident)
				nfFile.ident = string(ident)
			case TYPE_STAT:
				// fmt.Printf("Read stat: %d\n", unsafe.Sizeof(nfFile.StatRecord))
				binary.Read(b, binary.LittleEndian, &nfFile.StatRecord)
			default:
				// skip
				recordData := make([]byte, record.Size-4)
				binary.Read(b, binary.LittleEndian, &recordData)
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

	nfFile.file = file
	switch nfFile.Header.Version {
	case 1:
		return nfFile.openV1()
	case 2:
		return nfFile.readAppendix()
	default:
		file.Close()
		nfFile.file = nil
		return fmt.Errorf("nfFile unknown version: %d", nfFile.Header.Version)
	}
	// unreached
}

// Closes the current underlaying file
func (nfFile *NfFile) Close() error {
	nfFile.file.Close()
	return nil
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
	go func() {
		for i := 0; i < int(nfFile.Header.NumBlocks); i++ {
			dataBlock := DataBlock{}
			if err := binary.Read(nfFile.file, binary.LittleEndian, &dataBlock.Header); err != nil {
				close(blockChannel)
				// fmt.Printf("nfFile read block header: %v", err)
				return
			}
			var err error
			dataBlock.Data, err = nfFile.uncompressBlock(&dataBlock.Header)
			// fmt.Printf("nfFile uncompress block: %v", err)
			if err == nil {
				blockChannel <- dataBlock
			}
		}
		close(blockChannel)
	}()
	return blockChannel, nil
}

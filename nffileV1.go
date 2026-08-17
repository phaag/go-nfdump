// Copyright © 2023 Peter Haag peter@people.ops-trust.net
// All rights reserved.
//
// Use of this source code is governed by the license that can be
// found in the LICENSE file.

package nfdump

import (
	"encoding/binary"
	"fmt"
	"io"
	"os"
)

const (
	NUM_FLAGS           = 4
	FLAG_NOT_COMPRESSED = 0x0  // records are not compressed
	FLAG_LZO_COMPRESSED = 0x1  // records are LZO compressed
	FLAG_ANONYMIZED     = 0x2  // flow data are anonimized
	FLAG_UNUSED         = 0x4  // unused
	FLAG_BZ2_COMPRESSED = 0x8  // records are BZ2 compressed
	FLAG_LZ4_COMPRESSED = 0x10 // records are LZ4 compressed
	COMPRESSION_MASK    = 0x19 // all compression bits
)

/*
	// shortcuts

	#define FILE_IS_NOT_COMPRESSED(n) (((n)->flags & COMPRESSION_MASK) == 0)
	#define FILE_IS_LZO_COMPRESSED(n) ((n)->flags & FLAG_LZO_COMPRESSED)
	#define FILE_IS_BZ2_COMPRESSED(n) ((n)->flags & FLAG_BZ2_COMPRESSED)
	#define FILE_IS_LZ4_COMPRESSED(n) ((n)->flags & FLAG_LZ4_COMPRESSED)
	#define FILEV1_COMPRESSION(n) (FILE_IS_LZO_COMPRESSED(n) ? LZO_COMPRESSED : (FILE_IS_BZ2_COMPRESSED(n) ? BZ2_COMPRESSED : (FILE_IS_LZ4_COMPRESSED(n) ? LZ4_COMPR
	ESSED : NOT_COMPRESSED)))

	#define BLOCK_IS_COMPRESSED(n) ((n)->flags == 2 )
	#define IP_ANONYMIZED(n) ((n)->file_header->flags & FLAG_ANONYMIZED)
*/

type NfFileHeaderV1 struct {
	Magic     uint16 // magic 0xA50C to recognize nfdump file type and endian type
	Version   uint16 // version of binary file layout. Valid: version 2
	Flags     uint32
	NumBlocks uint32    // number of data blocks in file
	Ident     [128]byte // string identifier for this file
}

type statRecordV1 struct {
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
	FirstSeen uint32
	LastSeen  uint32
	MsecFirst uint16
	MsecLast  uint16
	// other
	SequenceFailure uint32
}

func openV17ReaderV1(owner *NfFile, file *os.File) (*v17Reader, error) {

	var nfFileV1Header NfFileHeaderV1
	var statRecordV1 statRecordV1

	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return nil, fmt.Errorf("nfFile seek V1 header: %w", err)
	}
	if err := binary.Read(file, binary.LittleEndian, &nfFileV1Header); err != nil {
		return nil, fmt.Errorf("nfFile read V1 header: %w", err)
	}
	if err := binary.Read(file, binary.LittleEndian, &statRecordV1); err != nil {
		return nil, fmt.Errorf("nfFile read V1 stats: %w", err)
	}

	owner.StatRecord.Numflows = statRecordV1.Numflows
	owner.StatRecord.Numpackets = statRecordV1.Numpackets
	owner.StatRecord.Numbytes = statRecordV1.Numbytes

	owner.StatRecord.NumflowsTcp = statRecordV1.NumflowsTcp
	owner.StatRecord.NumflowsUdp = statRecordV1.NumflowsUdp
	owner.StatRecord.NumflowsIcmp = statRecordV1.NumflowsIcmp
	owner.StatRecord.NumflowsOther = statRecordV1.NumflowsOther

	owner.StatRecord.NumpacketsTcp = statRecordV1.NumpacketsTcp
	owner.StatRecord.NumpacketsUdp = statRecordV1.NumpacketsUdp
	owner.StatRecord.NumpacketsIcmp = statRecordV1.NumpacketsIcmp
	owner.StatRecord.NumpacketsOther = statRecordV1.NumpacketsOther

	owner.StatRecord.NumbytesTcp = statRecordV1.NumbytesTcp
	owner.StatRecord.NumbytesUdp = statRecordV1.NumbytesUdp
	owner.StatRecord.NumbytesIcmp = statRecordV1.NumbytesIcmp
	owner.StatRecord.NumbytesOther = statRecordV1.NumbytesOther

	owner.StatRecord.FirstSeen = uint64(statRecordV1.FirstSeen*1000 + uint32(statRecordV1.MsecFirst))
	owner.StatRecord.LastSeen = uint64(statRecordV1.LastSeen*1000 + uint32(statRecordV1.MsecLast))

	owner.StatRecord.SequenceFailure = uint64(statRecordV1.SequenceFailure)
	owner.ident = string(nfFileV1Header.Ident[:])

	header := NfFileHeader{}
	header.Magic = nfFileV1Header.Magic
	header.Version = nfFileV1Header.Version
	header.NfVersion = 0x106
	header.Created = 0
	compression := 0
	if nfFileV1Header.Flags&0x1 == 1 {
		compression = 1 // LO0
	} else if nfFileV1Header.Flags&0x8 == 0x8 {
		compression = 2 // BZIP2
	} else if nfFileV1Header.Flags&0x10 == 0x10 {
		compression = 3 // LZ4
	}
	header.Compression = uint8(compression)
	header.Encryption = 0
	header.AppendixBlocks = 0
	header.Unused = 0
	header.OffAppendix = 0
	header.BlockSize = 0
	header.NumBlocks = nfFileV1Header.NumBlocks
	owner.Header = header // Deprecated V1/V2 compatibility field.
	owner.info = FileInfo{
		Layout:        FileLayoutV1,
		NfdumpVersion: header.NfVersion,
		Compression:   Compression(header.Compression),
		FlowBlocks:    header.NumBlocks,
	}

	return &v17Reader{owner: owner, file: file, header: header}, nil
}

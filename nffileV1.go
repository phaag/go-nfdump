// Copyright © 2023 Peter Haag peter@people.ops-trust.net
// All rights reserved.
//
// Use of this source code is governed by the license that can be
// found in the LICENSE file.

package nfdump

import (
	"encoding/binary"
	"fmt"
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

func (nfFile *NfFile) openV1() error {

	var nfFileV1Header NfFileHeaderV1
	var statRecordV1 statRecordV1

	nfFile.file.Seek(0, os.SEEK_SET)
	if err := binary.Read(nfFile.file, binary.LittleEndian, &nfFileV1Header); err != nil {
		nfFile.file.Close()
		return fmt.Errorf("nfFile read V1 header: %v", err)
	}

	if err := binary.Read(nfFile.file, binary.LittleEndian, &statRecordV1); err != nil {
		nfFile.file.Close()
		return fmt.Errorf("nfFile read header: %v", err)
	}

	nfFile.StatRecord.Numflows = statRecordV1.Numflows
	nfFile.StatRecord.Numpackets = statRecordV1.Numpackets
	nfFile.StatRecord.Numbytes = statRecordV1.Numbytes

	nfFile.StatRecord.NumflowsTcp = statRecordV1.NumflowsTcp
	nfFile.StatRecord.NumflowsUdp = statRecordV1.NumflowsUdp
	nfFile.StatRecord.NumflowsIcmp = statRecordV1.NumflowsIcmp
	nfFile.StatRecord.NumflowsOther = statRecordV1.NumflowsOther

	nfFile.StatRecord.NumpacketsTcp = statRecordV1.NumpacketsTcp
	nfFile.StatRecord.NumpacketsUdp = statRecordV1.NumpacketsUdp
	nfFile.StatRecord.NumpacketsIcmp = statRecordV1.NumpacketsIcmp
	nfFile.StatRecord.NumpacketsOther = statRecordV1.NumpacketsOther

	nfFile.StatRecord.NumbytesTcp = statRecordV1.NumbytesTcp
	nfFile.StatRecord.NumbytesUdp = statRecordV1.NumbytesUdp
	nfFile.StatRecord.NumbytesIcmp = statRecordV1.NumbytesIcmp
	nfFile.StatRecord.NumbytesOther = statRecordV1.NumbytesOther

	nfFile.StatRecord.FirstSeen = uint64(statRecordV1.FirstSeen*1000 + uint32(statRecordV1.MsecFirst))
	nfFile.StatRecord.LastSeen = uint64(statRecordV1.LastSeen*1000 + uint32(statRecordV1.MsecLast))

	nfFile.StatRecord.SequenceFailure = uint64(statRecordV1.SequenceFailure)
	nfFile.ident = string(nfFileV1Header.Ident[:])

	nfFile.Header.Magic = nfFileV1Header.Magic
	nfFile.Header.Version = nfFileV1Header.Version
	nfFile.Header.NfVersion = 0x106
	nfFile.Header.Created = 0
	nfFile.Header.Compression = 0
	nfFile.Header.Encryption = 0
	nfFile.Header.AppendixBlocks = 0
	nfFile.Header.Unused = 0
	nfFile.Header.OffAppendix = 0
	nfFile.Header.BlockSize = 0
	nfFile.Header.NumBlocks = nfFileV1Header.NumBlocks

	return nil
}

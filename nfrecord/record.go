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

package nfrecord

import (
	"encoding/binary"
	"fmt"
	"go-nfdump/nffile"
	"net"
	"time"
	"unsafe"
)

const EXgenericFlowID = 1
const EXipv4FlowID = 2
const EXipv6FlowID = 3

const V3_FLAG_EVENT = 1
const V3_FLAG_SAMPLED = 2
const V3_FLAG_ANON = 4

const V3RecordID = 11

const MAXEXTENSIONS = 38

type recordHeaderV3 struct {
	Type        uint16
	Size        uint16
	NumElements uint16
	EngineType  uint8
	EngineID    uint8
	ExporterID  uint16
	Flags       uint8
	Nfversion   uint8
}

type EXgenericFlow struct {
	MsecFirst    uint64
	MsecLast     uint64
	MsecReceived uint64
	InPackets    uint64
	InBytes      uint64
	SrcPort      uint16
	DstPort      uint16
	Proto        uint8
	TcpFlags     uint8
	FwdStatus    uint8
	SrcTos       uint8
}

type EXip struct {
	SrcIP net.IP
	DstIP net.IP
}

type FlowRecordV3 struct {
	rawRecord    []byte
	recordHeader *recordHeaderV3
	genericFlow  *EXgenericFlow
	srcIP        net.IP
	dstIP        net.IP
	extOffset    [MAXEXTENSIONS]int
}

func flagsString(flags uint16) string {
	var flagChars = []byte{'.', '.', '.', '.', '.', '.', '.', '.'}

	// Congestion window reduced -  CWR
	if flags&128 != 0 {
		flagChars[0] = 'C'
	}
	// ECN-Echo
	if flags&64 != 0 {
		flagChars[1] = 'E'
	}
	// Urgent
	if flags&32 != 0 {
		flagChars[2] = 'U'
	}
	// Ack
	if flags&16 != 0 {
		flagChars[3] = 'A'
	}
	// Push
	if flags&8 != 0 {
		flagChars[4] = 'P'
	}
	// Reset
	if flags&4 != 0 {
		flagChars[5] = 'R'
	}
	// Syn
	if flags&2 != 0 {
		flagChars[6] = 'S'
	}
	// Fin
	if flags&1 != 0 {
		flagChars[7] = 'F'
	}

	return string(flagChars)

} // End of FlagsString

// Extract next flow record
func New(record []byte) *FlowRecordV3 {

	offset := 0
	recordType := binary.LittleEndian.Uint16(record[offset : offset+2])
	recordSize := binary.LittleEndian.Uint16(record[offset+2 : offset+4])
	numElements := binary.LittleEndian.Uint16(record[offset+4 : offset+6])

	if recordType != V3RecordID {
		return nil
	}

	flowRecord := new(FlowRecordV3)
	flowRecord.rawRecord = make([]byte, recordSize)
	copy(flowRecord.rawRecord, record)
	raw := flowRecord.rawRecord

	flowRecord.recordHeader = (*recordHeaderV3)(unsafe.Pointer(&raw[0]))
	offset = 12
	for i := 0; i < int(numElements); i++ {
		elementType := binary.LittleEndian.Uint16(raw[offset : offset+2])
		elementSize := binary.LittleEndian.Uint16(raw[offset+2 : offset+4])
		// fmt.Printf(" . Element type: %d, length: %d\n", elementType, elementSize)
		exOffset := offset + 4
		if elementType < MAXEXTENSIONS {
			flowRecord.extOffset[elementType] = exOffset
		}
		switch elementType {
		case EXgenericFlowID:
			flowRecord.genericFlow = (*EXgenericFlow)(unsafe.Pointer(&raw[exOffset]))
		case EXipv4FlowID:
			flowRecord.srcIP = net.IPv4(raw[exOffset+3], raw[exOffset+2], raw[exOffset+1], raw[exOffset])
			flowRecord.dstIP = net.IPv4(raw[exOffset+7], raw[exOffset+6], raw[exOffset+5], raw[exOffset+4])
		case EXipv6FlowID:
			flowRecord.srcIP = net.IP{raw[exOffset+7], raw[exOffset+6], raw[exOffset+5], raw[exOffset+4], raw[exOffset+3], raw[exOffset+2], raw[exOffset+1], raw[exOffset+0], raw[exOffset+15], raw[exOffset+14], raw[exOffset+13], raw[exOffset+12], raw[exOffset+11], raw[exOffset+10], raw[exOffset+9], raw[exOffset+8]}
			flowRecord.dstIP = net.IP{raw[exOffset+23], raw[exOffset+22], raw[exOffset+21], raw[exOffset+20], raw[exOffset+19], raw[exOffset+18], raw[exOffset+17], raw[exOffset+16], raw[exOffset+31], raw[exOffset+30], raw[exOffset+29], raw[exOffset+28], raw[exOffset+27], raw[exOffset+26], raw[exOffset+25], raw[exOffset+24]}
		}
		offset += int(elementSize)
	}

	return flowRecord
}

// Return string for %v Printf()
func (flowRecord *FlowRecordV3) String() string {
	var flowType string
	if flowRecord.recordHeader.Nfversion != 0 {
		if flowRecord.recordHeader.Nfversion&0x80 != 0 {
			flowType = "SFLOW"
		} else if flowRecord.recordHeader.Nfversion&0x40 != 0 {
			flowType = "PCAP"
		} else {
			flowType = "NETFLOW"
		}
	} else {
		flowType = "FLOW"
	}

	var s string = "" +
		fmt.Sprintf("Flow Record:\n") +
		fmt.Sprintf("  Flags      : %v %s\n", flowRecord.recordHeader.Flags, flowType) +
		fmt.Sprintf("  Elements   : %v\n", flowRecord.recordHeader.NumElements) +
		fmt.Sprintf("  Size       : %v\n", flowRecord.recordHeader.Size) +
		fmt.Sprintf("  EngineType : %v\n", flowRecord.recordHeader.EngineType) +
		fmt.Sprintf("  EngineID   : %v\n", flowRecord.recordHeader.EngineID) +
		fmt.Sprintf("  ExporterID : %v\n", flowRecord.recordHeader.ExporterID) +
		fmt.Sprintf("  Netflow    : %v\n", flowRecord.recordHeader.Nfversion)
	if flowRecord.genericFlow != nil {
		s = flowRecord.DumpEXgenericFlow(s)
	}
	return s + fmt.Sprintf("  SrcIP      : %v\n  DstIP      : %v\n", flowRecord.srcIP, flowRecord.dstIP)
}

// Return generic extension
func (flowRecord *FlowRecordV3) GenericFlow() *EXgenericFlow {
	return flowRecord.genericFlow
}

// Return IP record
func (flowRecord *FlowRecordV3) IP() *EXip {
	return &EXip{flowRecord.srcIP, flowRecord.dstIP}
}

func (flowRecord *FlowRecordV3) DumpEXgenericFlow(s string) string {

	tTime := time.UnixMilli(int64(flowRecord.genericFlow.MsecFirst))
	s += fmt.Sprintf("  First      : %d %v\n", flowRecord.genericFlow.MsecFirst, tTime)

	tTime = time.UnixMilli(int64(flowRecord.genericFlow.MsecLast))
	s += fmt.Sprintf("  Last       : %d %v\n", flowRecord.genericFlow.MsecLast, tTime)

	tTime = time.UnixMilli(int64(flowRecord.genericFlow.MsecReceived))
	s += fmt.Sprintf("  Received   : %d %v\n", flowRecord.genericFlow.MsecReceived, tTime) +

		fmt.Sprintf("  In Packets : %d\n", flowRecord.genericFlow.InPackets) +
		fmt.Sprintf("  In Bytes   : %d\n", flowRecord.genericFlow.InBytes) +
		fmt.Sprintf("  Proto      : %d\n", flowRecord.genericFlow.Proto) +
		fmt.Sprintf("  SrcPort    : %d\n", flowRecord.genericFlow.SrcPort) +
		fmt.Sprintf("  DstPort    : %d\n", flowRecord.genericFlow.DstPort) +
		fmt.Sprintf("  TcpFlags   : 0x%x %s\n", flowRecord.genericFlow.TcpFlags, flagsString(uint16(flowRecord.genericFlow.TcpFlags))) +
		fmt.Sprintf("  FwdStatus  : %d\n", flowRecord.genericFlow.FwdStatus) +
		fmt.Sprintf("  SrcTos     : %d\n", flowRecord.genericFlow.SrcTos)
	return s
}

func AllRecords(nfFile *nffile.NfFile) (chan *FlowRecordV3, error) {
	recordChannel := make(chan *FlowRecordV3, 32)
	go func() {
		blockChannel, _ := nfFile.ReadDataBlocks()
		for dataBlock := range blockChannel {
			fmt.Printf("Next block - type: %d, records: %d\n", dataBlock.Header.Type, dataBlock.Header.NumRecords)
			offset := 0
			for i := 0; i < int(dataBlock.Header.NumRecords); i++ {
				//recordType := binary.LittleEndian.Uint16(dataBlock.Data[offset : offset+2])
				recordSize := binary.LittleEndian.Uint16(dataBlock.Data[offset+2 : offset+4])
				//numElements := binary.LittleEndian.Uint16(dataBlock.Data[offset+4 : offset+6])
				// fmt.Printf("Record %d type: %d, length: %d, numElements: %d\n", i, recordType, recordSize, numElements)
				recordChannel <- New(dataBlock.Data[offset : offset+int(recordSize)])
				offset += int(recordSize)
			}
		}
		close(recordChannel)
	}()
	return recordChannel, nil
}

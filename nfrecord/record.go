//go:generate sh -c "go tool cgo -godefs defs.go >nfxV3.go"

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
	"net"
	"unsafe"

	"github.com/phaag/go-nfdump/nffile"
)

type EXip struct {
	SrcIP net.IP
	DstIP net.IP
}

type FlowRecordV3 struct {
	rawRecord    []byte
	recordHeader *recordHeaderV3
	srcIP        net.IP
	dstIP        net.IP
	extOffset    [MAXEXTENSIONS]int
}

// Extract next flow record from []byte stream
func New(record []byte) *FlowRecordV3 {

	offset := 0
	recordType := binary.LittleEndian.Uint16(record[offset : offset+2])
	recordSize := binary.LittleEndian.Uint16(record[offset+2 : offset+4])
	numElements := binary.LittleEndian.Uint16(record[offset+4 : offset+6])

	if recordType != V3Record {
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

// Return generic extension
func (flowRecord *FlowRecordV3) GenericFlow() *EXgenericFlow {
	offset := flowRecord.extOffset[EXgenericFlowID]
	if offset == 0 {
		return nil
	}
	genericFlow := (*EXgenericFlow)(unsafe.Pointer(&flowRecord.rawRecord[offset]))
	return genericFlow
}

// Return IP extension IPv4 or IPv6
func (flowRecord *FlowRecordV3) IP() *EXip {
	return &EXip{flowRecord.srcIP, flowRecord.dstIP}
}

// Return misc extension
func (flowRecord *FlowRecordV3) FlowMisc() *EXflowMisc {
	offset := flowRecord.extOffset[EXflowMiscID]
	if offset == 0 {
		return nil
	}
	flowMisc := (*EXflowMisc)(unsafe.Pointer(&flowRecord.rawRecord[offset]))
	return flowMisc
}

// Return out counter extension
func (flowRecord *FlowRecordV3) CntFlow() *EXcntFlow {
	offset := flowRecord.extOffset[EXcntFlowID]
	if offset == 0 {
		return nil
	}
	cntFlow := (*EXcntFlow)(unsafe.Pointer(&flowRecord.rawRecord[offset]))
	return cntFlow
}

// Return vlan extension
func (flowRecord *FlowRecordV3) VLan() *EXvLan {
	offset := flowRecord.extOffset[EXvLanID]
	if offset == 0 {
		return nil
	}
	vlan := (*EXvLan)(unsafe.Pointer(&flowRecord.rawRecord[offset]))
	return vlan
}

// Return asRouting extension
func (flowRecord *FlowRecordV3) AsRouting() *EXasRouting {
	offset := flowRecord.extOffset[EXasRoutingID]
	if offset == 0 {
		return nil
	}
	asRouting := (*EXasRouting)(unsafe.Pointer(&flowRecord.rawRecord[offset]))
	return asRouting
}

// AllRecord takes an NfFile object and returns a channel of FlowRecordV3
// it reads and uncompresses the data blocks with ReadDataBlocks
// Iterating over the channel reads all flow records
func AllRecords(nfFile *nffile.NfFile) (chan *FlowRecordV3, error) {
	recordChannel := make(chan *FlowRecordV3, 32)
	go func() {
		blockChannel, _ := nfFile.ReadDataBlocks()
		for dataBlock := range blockChannel {
			// fmt.Printf("Next block - type: %d, records: %d\n", dataBlock.Header.Type, dataBlock.Header.NumRecords)
			offset := 0
			for i := 0; i < int(dataBlock.Header.NumRecords); i++ {
				//recordType := binary.LittleEndian.Uint16(dataBlock.Data[offset : offset+2])
				recordSize := binary.LittleEndian.Uint16(dataBlock.Data[offset+2 : offset+4])
				//numElementS := binary.LittleEndian.Uint16(dataBlock.Data[offset+4 : offset+6])
				// fmt.Printf("Record %d type: %d, length: %d, numElementS: %d\n", i, recordType, recordSize, numElementS)
				recordChannel <- New(dataBlock.Data[offset : offset+int(recordSize)])
				offset += int(recordSize)
			}
		}
		close(recordChannel)
	}()
	return recordChannel, nil
}

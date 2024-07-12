//go:generate sh -c "go tool cgo -godefs defs.go >nfxV3.go"

// Copyright © 2024 Peter Haag peter@people.ops-trust.net
// All rights reserved.
//
// Use of this source code is governed by the license that can be
// found in the LICENSE file.

package nfdump

import (
	"encoding/binary"
	"fmt"
	"net"
	"unsafe"
)

type EXip struct {
	SrcIP net.IP
	DstIP net.IP
}

type elementParam struct {
	offset int
	size   int
}

type FlowRecordV3 struct {
	rawRecord      []byte
	recordHeader   *recordHeaderV3
	srcIP          net.IP
	dstIP          net.IP
	isV4           bool
	isV6           bool
	srcXlateIP     net.IP
	dstXlateIP     net.IP
	hasXlateIP     bool
	packetInterval int
	spaceInterval  int
	extOffset      [MAXEXTENSIONS]elementParam
}

// type to return/accept in the flow processing record chain
type RecordChain struct {
	recordChan chan *FlowRecordV3
	err        error
}

// function to terminate processing chain
// - takes the record chain object as input
//
// returns a flow record chanel
func (recordChain *RecordChain) Get() (chan *FlowRecordV3, error) {
	return recordChain.recordChan, recordChain.err
}

// function to convert a byte stream from file into a *FlowRecordV3
// - take a byte stream as input
// returns a *FlowRecordV3 or an error
func NewRecord(record []byte) (*FlowRecordV3, error) {

	offset := 0
	recordType := binary.LittleEndian.Uint16(record[offset : offset+2])
	recordSize := binary.LittleEndian.Uint16(record[offset+2 : offset+4])
	numElements := binary.LittleEndian.Uint16(record[offset+4 : offset+6])

	if recordType != V3Record {
		return nil, fmt.Errorf("Not a v3 record")
	}

	flowRecord := new(FlowRecordV3)
	flowRecord.rawRecord = make([]byte, recordSize)
	copy(flowRecord.rawRecord, record)
	raw := flowRecord.rawRecord

	flowRecord.recordHeader = (*recordHeaderV3)(unsafe.Pointer(&raw[0]))
	offset = 12
	for i := 0; i < int(numElements); i++ {
		// fmt.Printf(" . next Element at offset: %d\n", offset)
		if (offset + 4) > int(recordSize) {
			return nil, fmt.Errorf("Record header boundary check error")
		}
		elementType := binary.LittleEndian.Uint16(raw[offset : offset+2])
		elementSize := binary.LittleEndian.Uint16(raw[offset+2 : offset+4])
		if (offset + int(elementSize)) > int(recordSize) {
			return nil, fmt.Errorf("Record body boundary check error")
		}
		// fmt.Printf(" . Element type: %d, length: %d\n", elementType, elementSize)
		exOffset := offset + 4
		if elementType < MAXEXTENSIONS {
			flowRecord.extOffset[elementType].offset = exOffset
			flowRecord.extOffset[elementType].size = int(elementSize) - 4
		}
		switch elementType {
		case EXipv4FlowID:
			flowRecord.srcIP = net.IPv4(raw[exOffset+3], raw[exOffset+2], raw[exOffset+1], raw[exOffset])
			flowRecord.dstIP = net.IPv4(raw[exOffset+7], raw[exOffset+6], raw[exOffset+5], raw[exOffset+4])
			flowRecord.isV4 = true
		case EXipv6FlowID:
			flowRecord.srcIP = net.IP{raw[exOffset+7], raw[exOffset+6], raw[exOffset+5], raw[exOffset+4], raw[exOffset+3], raw[exOffset+2], raw[exOffset+1], raw[exOffset+0], raw[exOffset+15], raw[exOffset+14], raw[exOffset+13], raw[exOffset+12], raw[exOffset+11], raw[exOffset+10], raw[exOffset+9], raw[exOffset+8]}
			flowRecord.dstIP = net.IP{raw[exOffset+23], raw[exOffset+22], raw[exOffset+21], raw[exOffset+20], raw[exOffset+19], raw[exOffset+18], raw[exOffset+17], raw[exOffset+16], raw[exOffset+31], raw[exOffset+30], raw[exOffset+29], raw[exOffset+28], raw[exOffset+27], raw[exOffset+26], raw[exOffset+25], raw[exOffset+24]}
			flowRecord.isV6 = true
		case EXnatXlateIPv4ID:
			flowRecord.srcXlateIP = net.IPv4(raw[exOffset+3], raw[exOffset+2], raw[exOffset+1], raw[exOffset])
			flowRecord.dstXlateIP = net.IPv4(raw[exOffset+7], raw[exOffset+6], raw[exOffset+5], raw[exOffset+4])
			flowRecord.hasXlateIP = true
		case EXnatXlateIPv6ID:
			flowRecord.srcXlateIP = net.IP{raw[exOffset+7], raw[exOffset+6], raw[exOffset+5], raw[exOffset+4], raw[exOffset+3], raw[exOffset+2], raw[exOffset+1], raw[exOffset+0], raw[exOffset+15], raw[exOffset+14], raw[exOffset+13], raw[exOffset+12], raw[exOffset+11], raw[exOffset+10], raw[exOffset+9], raw[exOffset+8]}
			flowRecord.dstXlateIP = net.IP{raw[exOffset+23], raw[exOffset+22], raw[exOffset+21], raw[exOffset+20], raw[exOffset+19], raw[exOffset+18], raw[exOffset+17], raw[exOffset+16], raw[exOffset+31], raw[exOffset+30], raw[exOffset+29], raw[exOffset+28], raw[exOffset+27], raw[exOffset+26], raw[exOffset+25], raw[exOffset+24]}
			flowRecord.hasXlateIP = true
		}
		offset += int(elementSize)
	}

	flowRecord.packetInterval = 1
	flowRecord.spaceInterval = 0

	return flowRecord, nil
}

// Returns the generic extension from the *FlowRecordV3 object
func (flowRecord *FlowRecordV3) GenericFlow() *EXgenericFlow {
	offset := flowRecord.extOffset[EXgenericFlowID].offset
	if offset == 0 {
		return nil
	}
	genericFlow := (*EXgenericFlow)(unsafe.Pointer(&flowRecord.rawRecord[offset]))
	return genericFlow
}

// Returns the IP extension IPv4 or IPv6 from the *FlowRecordV3 object
func (flowRecord *FlowRecordV3) IP() *EXip {
	return &EXip{flowRecord.srcIP, flowRecord.dstIP}
}

// Returns true, if record is a IPv4 flow
func (flowRecord *FlowRecordV3) IsIPv4() bool {
	return flowRecord.isV4
}

// Returns true, if record is a IPv4 flow
func (flowRecord *FlowRecordV3) IsIPv6() bool {
	return flowRecord.isV6
}

// Returns the misc extension from the *FlowRecordV3 object
func (flowRecord *FlowRecordV3) FlowMisc() *EXflowMisc {
	offset := flowRecord.extOffset[EXflowMiscID].offset
	if offset == 0 {
		return nil
	}
	flowMisc := (*EXflowMisc)(unsafe.Pointer(&flowRecord.rawRecord[offset]))
	return flowMisc
}

// Returns the counter extension from the *FlowRecordV3 object
func (flowRecord *FlowRecordV3) CntFlow() *EXcntFlow {
	offset := flowRecord.extOffset[EXcntFlowID].offset
	if offset == 0 {
		return nil
	}
	cntFlow := (*EXcntFlow)(unsafe.Pointer(&flowRecord.rawRecord[offset]))
	return cntFlow
}

// Returns the vlan extension from the *FlowRecordV3 object
func (flowRecord *FlowRecordV3) VLan() *EXvLan {
	offset := flowRecord.extOffset[EXvLanID].offset
	if offset == 0 {
		return nil
	}
	vlan := (*EXvLan)(unsafe.Pointer(&flowRecord.rawRecord[offset]))
	return vlan
}

// Returns the asRouting extension from the *FlowRecordV3 object
func (flowRecord *FlowRecordV3) AsRouting() *EXasRouting {
	offset := flowRecord.extOffset[EXasRoutingID].offset
	if offset == 0 {
		return nil
	}
	asRouting := (*EXasRouting)(unsafe.Pointer(&flowRecord.rawRecord[offset]))
	return asRouting
}

// Returns the bgp next hop IPv4 or IPv6 from the *FlowRecordV3 object
func (flowRecord *FlowRecordV3) BgpNextHop() *EXbgpNextHop {
	// IPv4
	offset := flowRecord.extOffset[EXbgpNextHopV4ID].offset
	if offset != 0 {
		raw := flowRecord.rawRecord
		nextHop := new(EXbgpNextHop)
		nextHop.IP = net.IPv4(raw[offset+3], raw[offset+2], raw[offset+1], raw[offset])
		return nextHop
	}

	// IPv6
	offset = flowRecord.extOffset[EXbgpNextHopV6ID].offset
	if offset != 0 {
		raw := flowRecord.rawRecord
		nextHop := new(EXbgpNextHop)
		nextHop.IP = net.IP{raw[offset+7], raw[offset+6], raw[offset+5], raw[offset+4], raw[offset+3], raw[offset+2], raw[offset+1], raw[offset+0], raw[offset+15], raw[offset+14], raw[offset+13], raw[offset+12], raw[offset+11], raw[offset+10], raw[offset+9], raw[offset+8]}
		return nextHop
	}

	// no next hop IP
	return nil
}

// Returns the IP next hop IPv4 or IPv6 from the *FlowRecordV3 object
func (flowRecord *FlowRecordV3) IpNextHop() *EXipNextHop {
	// IPv4
	offset := flowRecord.extOffset[EXipNextHopV4ID].offset
	if offset != 0 {
		raw := flowRecord.rawRecord
		nextHop := new(EXipNextHop)
		nextHop.IP = net.IPv4(raw[offset+3], raw[offset+2], raw[offset+1], raw[offset])
		return nextHop
	}

	// IPv6
	offset = flowRecord.extOffset[EXipNextHopV6ID].offset
	if offset != 0 {
		raw := flowRecord.rawRecord
		nextHop := new(EXipNextHop)
		nextHop.IP = net.IP{raw[offset+7], raw[offset+6], raw[offset+5], raw[offset+4], raw[offset+3], raw[offset+2], raw[offset+1], raw[offset+0], raw[offset+15], raw[offset+14], raw[offset+13], raw[offset+12], raw[offset+11], raw[offset+10], raw[offset+9], raw[offset+8]}
		return nextHop
	}

	// no next hop IP
	return nil
}

// Returns the IP received IPv4 or IPv6 from the *FlowRecordV3 object
func (flowRecord *FlowRecordV3) IpReceived() *EXipReceived {
	// IPv4
	offset := flowRecord.extOffset[EXipReceivedV4ID].offset
	if offset != 0 {
		raw := flowRecord.rawRecord
		ipReceived := new(EXipReceived)
		ipReceived.IP = net.IPv4(raw[offset+3], raw[offset+2], raw[offset+1], raw[offset])
		return ipReceived
	}

	// IPv6
	offset = flowRecord.extOffset[EXipReceivedV6ID].offset
	if offset != 0 {
		raw := flowRecord.rawRecord
		ipReceived := new(EXipReceived)
		ipReceived.IP = net.IP{raw[offset+7], raw[offset+6], raw[offset+5], raw[offset+4], raw[offset+3], raw[offset+2], raw[offset+1], raw[offset+0], raw[offset+15], raw[offset+14], raw[offset+13], raw[offset+12], raw[offset+11], raw[offset+10], raw[offset+9], raw[offset+8]}
		return ipReceived
	}

	// no IP received
	return nil
}

// Returns the bgp next hop IPv4 or IPv6 from the *FlowRecordV3 object
func (flowRecord *FlowRecordV3) Sampling() *EXsamplerInfo {

	offset := flowRecord.extOffset[EXsamplerInfoID].offset
	if offset == 0 {
		return nil
	}
	samplerInfo := (*EXsamplerInfo)(unsafe.Pointer(&flowRecord.rawRecord[offset]))
	return samplerInfo
}

// Returns the nat xlate IP extension from the *FlowRecordV3 object
func (flowRecord *FlowRecordV3) NatXlateIP() *EXnatXlateIP {
	if flowRecord.hasXlateIP {
		return &EXnatXlateIP{flowRecord.srcXlateIP, flowRecord.dstXlateIP}
	} else {
		return nil
	}
}

// Returns the nat xlate port extension from the *FlowRecordV3 object
func (flowRecord *FlowRecordV3) NatXlatePort() *EXnatXlatePort {
	offset := flowRecord.extOffset[EXnatXlatePortID].offset
	if offset == 0 {
		return nil
	}
	xlatePort := (*EXnatXlatePort)(unsafe.Pointer(&flowRecord.rawRecord[offset]))
	return xlatePort
}

// Returns the natCommon extension from the *FlowRecordV3 object
func (flowRecord *FlowRecordV3) NatCommon() *EXnatCommon {
	offset := flowRecord.extOffset[EXnatCommonID].offset
	if offset == 0 {
		return nil
	}
	natCommon := (*EXnatCommon)(unsafe.Pointer(&flowRecord.rawRecord[offset]))
	return natCommon
}

// Returns the natPortBlock extension from the *FlowRecordV3 object
func (flowRecord *FlowRecordV3) NatPortBlock() *EXnatPortBlock {
	offset := flowRecord.extOffset[EXnatPortBlockID].offset
	if offset == 0 {
		return nil
	}
	natPortBlock := (*EXnatPortBlock)(unsafe.Pointer(&flowRecord.rawRecord[offset]))
	return natPortBlock
}

// Returns the payload from the *FlowRecordV3 object
func (flowRecord *FlowRecordV3) Payload() EXinPayload {
	offset := flowRecord.extOffset[EXinPayloadID].offset
	if offset == 0 {
		return nil
	}
	size := flowRecord.extOffset[EXinPayloadID].size
	return flowRecord.rawRecord[offset : offset+size]
}

// returns the sampler info from the *FlowRecordV3 object
func (flowRecord *FlowRecordV3) SamplerInfo(nfFile *NfFile) (int, int) {
	return flowRecord.packetInterval, flowRecord.spaceInterval
}

func (flowRecord *FlowRecordV3) GetSamplerInfo(nfFile *NfFile) {

	var sampling *EXsamplerInfo
	var exporterID uint16
	if sampling = flowRecord.Sampling(); sampling != nil {
		exporterID = sampling.Sysid
	} else {
		exporterID = flowRecord.recordHeader.ExporterID
	}

	maxExporterID := len(nfFile.ExporterList)
	if exporterID >= uint16(maxExporterID) || nfFile.ExporterList[exporterID].IP == nil {
		return
	}

	exporter := nfFile.ExporterList[exporterID]

	// samplers are added in sequence and may overwrite previous samplers
	// the last in chain is currently valid
	for _, sampler := range exporter.SamplerList {
		if sampling != nil {
			if sampling.SelectorID == uint64(sampler.Id) {
				flowRecord.packetInterval = int(sampler.PacketInterval)
				flowRecord.spaceInterval = int(sampler.SpaceInterval)
			}
		} else {
			flowRecord.packetInterval = int(sampler.PacketInterval)
			flowRecord.spaceInterval = int(sampler.SpaceInterval)
		}
	}

}

// Returns the flowID extension from the *FlowRecordV3 object
func (flowRecord *FlowRecordV3) FlowId() *EXflowId {
	offset := flowRecord.extOffset[EXflowIdID].offset
	if offset == 0 {
		return nil
	}
	flowId := (*EXflowId)(unsafe.Pointer(&flowRecord.rawRecord[offset]))
	return flowId
}

// Returns the flowID extension from the *FlowRecordV3 object
func (flowRecord *FlowRecordV3) NokiaNat() *EXnokiaNat {
	offset := flowRecord.extOffset[EXnokiaNatID].offset
	if offset == 0 {
		return nil
	}
	nokiaNat := (*EXnokiaNat)(unsafe.Pointer(&flowRecord.rawRecord[offset]))
	return nokiaNat
}

// Returns the payload from the *FlowRecordV3 object
func (flowRecord *FlowRecordV3) NokiaNatString() EXnokiaNatString {
	offset := flowRecord.extOffset[EXnokiaNatStringID].offset
	if offset == 0 {
		return ""
	}
	size := flowRecord.extOffset[EXnokiaNatStringID].size
	bytes := flowRecord.rawRecord[offset : offset+size]
	return (EXnokiaNatString)(string(bytes[:]))
}

// Returns the ipInfo extension from the *FlowRecordV3 object
func (flowRecord *FlowRecordV3) IpInfo() *EXipInfo {
	offset := flowRecord.extOffset[EXipInfoID].offset
	if offset == 0 {
		return nil
	}
	ipInfo := (*EXipInfo)(unsafe.Pointer(&flowRecord.rawRecord[offset]))
	return ipInfo
}

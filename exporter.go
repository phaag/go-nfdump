// Copyright © 2023 Peter Haag peter@people.ops-trust.net
// All rights reserved.
//
// Use of this source code is governed by the license that can be
// found in the LICENSE file.

// Package nfdump provides an API for nfdump files
package nfdump

import (
	"encoding/binary"
	"fmt"
	"net"
	"syscall"
	"unsafe"
)

type Exporter struct {
	IP               net.IP // IP address
	isV4             bool
	isV6             bool
	SysId            uint16 // internal assigned ID
	Version          uint16 // netflow version
	Id               uint32 // exporter ID/Domain ID/Observation Domain ID assigned by the device
	Packets          uint64 // number of packets sent by this exporter
	Flows            uint64 // number of flow records sent by this exporter
	SequenceFailures uint32 // number of sequence failures
}

const MaxExporters = 256

// Extract next flow record from []byte stream
func (nfFile *NfFile) addExporterInfo(record []byte) {
	exporterInfo := (*ExporterInfoRecord)(unsafe.Pointer(&record[0]))
	var exporter Exporter
	exporter.Id = exporterInfo.Id
	exporter.SysId = exporterInfo.Sysid
	exporter.Version = uint16(exporterInfo.Version)

	if int(exporter.SysId) >= MaxExporters {
		fmt.Printf("Exporter SysID: %d out of range\n", exporter.SysId)
	}

	for int(exporter.SysId) >= len(nfFile.ExporterList) {
		newSlice := make([]Exporter, 8)
		nfFile.ExporterList = append(nfFile.ExporterList, newSlice...)
	}

	if exporterInfo.Family == syscall.AF_INET {
		exporter.isV4 = true
		exOffset := 16
		exporter.IP = net.IPv4(record[exOffset+3], record[exOffset+2], record[exOffset+1], record[exOffset])
	}
	if exporterInfo.Family == syscall.AF_INET6 {
		exporter.isV6 = true
		exOffset := 8
		exporter.IP = net.IP{record[exOffset+7], record[exOffset+6], record[exOffset+5], record[exOffset+4], record[exOffset+3], record[exOffset+2], record[exOffset+1], record[exOffset+0], record[exOffset+15], record[exOffset+14], record[exOffset+13], record[exOffset+12], record[exOffset+11], record[exOffset+10], record[exOffset+9], record[exOffset+8]}
	}
	nfFile.ExporterList[exporter.SysId] = exporter
}

func (nfFile *NfFile) addExporterStat(record []byte) {
	offset := 0
	recordType := binary.LittleEndian.Uint16(record[offset : offset+2])
	recordSize := binary.LittleEndian.Uint16(record[offset+2 : offset+4])
	numStat := binary.LittleEndian.Uint16(record[offset+4 : offset+8])
	fmt.Printf("ExporterStat: type: %d, size: %d, numStats: %d\n", recordType, recordSize, numStat)

	offset = 8
	for i := 0; i < int(numStat); i++ {
		sysId := binary.LittleEndian.Uint32(record[offset : offset+4])              // identifies the exporter
		sequenceFailures := binary.LittleEndian.Uint32(record[offset+4 : offset+8]) // number of sequence failures
		packets := binary.LittleEndian.Uint64(record[offset+8 : offset+16])         // number of packets sent by this exporter
		flows := binary.LittleEndian.Uint64(record[offset+16 : offset+24])          // number of flows sent by this exporter
		offset += 24
		if nfFile.ExporterList[sysId].SysId == uint16(sysId) {
			nfFile.ExporterList[sysId].SequenceFailures += sequenceFailures
			nfFile.ExporterList[sysId].Packets += packets
			nfFile.ExporterList[sysId].Flows += flows
		} else {
			fmt.Printf("Unknown Exporter id: %d\n", sysId)
		}
	}

}

// Get exporter list
func (nfFile *NfFile) GetExporterList() []Exporter {
	return nfFile.ExporterList
}

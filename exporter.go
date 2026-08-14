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

type Sampler struct {
	Id             int64
	Algorithm      uint16
	PacketInterval uint32
	SpaceInterval  uint32
}

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
	SamplerList      []Sampler
}

const MaxExporters = 256

// Extract next flow record from []byte stream
func (nfFile *NfFile) addExporterInfo(record []byte) error {
	if len(record) < int(unsafe.Sizeof(ExporterInfoRecord{})) {
		return fmt.Errorf("exporter info record too short: %d bytes", len(record))
	}
	exporterInfo := (*ExporterInfoRecord)(unsafe.Pointer(&record[0]))
	var exporter Exporter
	exporter.Id = exporterInfo.Id
	exporter.SysId = exporterInfo.Sysid
	exporter.Version = uint16(exporterInfo.Version)

	if int(exporter.SysId) >= MaxExporters {
		return fmt.Errorf("exporter SysID %d out of range", exporter.SysId)
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
	return nil
}

func (nfFile *NfFile) addExporterStat(record []byte) error {
	const statsHeaderSize = 8
	const statSize = 24
	if len(record) < statsHeaderSize {
		return fmt.Errorf("exporter stat record too short: %d bytes", len(record))
	}
	numStat := binary.LittleEndian.Uint32(record[4:8])
	if numStat == 0 || int(numStat) > (len(record)-statsHeaderSize)/statSize || len(record) != statsHeaderSize+int(numStat)*statSize {
		return fmt.Errorf("invalid exporter stat count %d for %d bytes", numStat, len(record))
	}

	offset := statsHeaderSize
	for i := 0; i < int(numStat); i++ {
		sysId := binary.LittleEndian.Uint32(record[offset : offset+4])              // identifies the exporter
		sequenceFailures := binary.LittleEndian.Uint32(record[offset+4 : offset+8]) // number of sequence failures
		packets := binary.LittleEndian.Uint64(record[offset+8 : offset+16])         // number of packets sent by this exporter
		flows := binary.LittleEndian.Uint64(record[offset+16 : offset+24])          // number of flows sent by this exporter
		offset += 24
		if int(sysId) >= len(nfFile.ExporterList) {
			return fmt.Errorf("invalid exporter ID: %d", sysId)
		}
		if nfFile.ExporterList[sysId].SysId == uint16(sysId) {
			nfFile.ExporterList[sysId].SequenceFailures += sequenceFailures
			nfFile.ExporterList[sysId].Packets += packets
			nfFile.ExporterList[sysId].Flows += flows
		} else {
			return fmt.Errorf("unknown exporter ID: %d", sysId)
		}
	}
	return nil
}

func (nfFile *NfFile) addSampler(record []byte) error {
	if len(record) < int(unsafe.Sizeof(SamplerRecord{})) {
		return fmt.Errorf("sampler record too short: %d bytes", len(record))
	}
	samplerInfo := (*SamplerRecord)(unsafe.Pointer(&record[0]))

	maxExporterID := len(nfFile.ExporterList)
	if samplerInfo.Sysid >= uint16(maxExporterID) || nfFile.ExporterList[samplerInfo.Sysid].IP == nil {
		return fmt.Errorf("no valid exporter for sampler")
	}

	nfFile.ExporterList[samplerInfo.Sysid].SamplerList = append(nfFile.ExporterList[samplerInfo.Sysid].SamplerList, Sampler{
		Id:             samplerInfo.Id,
		Algorithm:      samplerInfo.Algorithm,
		PacketInterval: samplerInfo.PacketInterval,
		SpaceInterval:  samplerInfo.SpaceInterval,
	})

	return nil
}

// Get exporter list
func (nfFile *NfFile) GetExporterList() []Exporter {
	return nfFile.ExporterList
}

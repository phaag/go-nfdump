// Copyright © 2026 Peter Haag peter@people.ops-trust.net
// All rights reserved.
//
// Use of this source code is governed by the license that can be
// found in the LICENSE file.

package nfdump

import (
	"encoding/binary"
	"fmt"
	"net/netip"
)

const v3RecordHeaderSize = 12

// RecordFormat identifies the on-disk flow-record layout.
type RecordFormat uint8

const (
	// RecordFormatV3 is the flow-record layout used by nfdump 1.7.x files.
	RecordFormatV3 RecordFormat = 3
	// RecordFormatV4 is reserved for the flow-record layout used by nfdump
	// 1.8.x files. It is exposed now so users can write format-neutral code
	// without a later API change.
	RecordFormatV4 RecordFormat = 4
)

// ExtensionID identifies a logical nfdump extension. The current V3 record
// layout uses these values directly. Future record layouts translate their
// on-disk extension representation to the same identifiers before returning a
// payload from Extension.
//
// It is an alias rather than a new defined type to keep calls that use the
// historical EX...ID constants source-compatible.
type ExtensionID = uint16

// Version-neutral extension identifiers for the common extensions. The
// historical EX...ID constants remain available for compatibility with the
// legacy FlowRecordV3 API.
const (
	ExtensionGenericFlow ExtensionID = EXgenericFlowID
	ExtensionIPv4Flow    ExtensionID = EXipv4FlowID
	ExtensionIPv6Flow    ExtensionID = EXipv6FlowID
	ExtensionFlowMisc    ExtensionID = EXflowMiscID
	ExtensionCounters    ExtensionID = EXcntFlowID
	ExtensionVLAN        ExtensionID = EXvLanID
	ExtensionASRouting   ExtensionID = EXasRoutingID
	ExtensionInPayload   ExtensionID = EXinPayloadID
	ExtensionIPInfo      ExtensionID = EXipInfoID
)

// GenericFlow contains the fields common to every flow record that has a
// generic-flow extension. Timestamps are milliseconds since the Unix epoch.
type GenericFlow struct {
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

// FlowRecord is a compact, read-only view of a flow record. It is passed to a
// Walk callback by value and is valid only for the duration of that callback.
// Call Clone to retain a record after the callback returns.
//
// The type intentionally exposes format-neutral Go values rather than C-layout
// structures. Further record formats can therefore use the same API.
type FlowRecord struct {
	raw    []byte
	format RecordFormat
}

// Format returns the on-disk record layout.
func (record FlowRecord) Format() RecordFormat {
	return record.format
}

// Clone returns an independent, owned copy of the record.
func (record FlowRecord) Clone() FlowRecord {
	raw := make([]byte, len(record.raw))
	copy(raw, record.raw)
	return FlowRecord{raw: raw, format: record.format}
}

// Extension returns the raw payload of the logical extension id. The returned
// bytes are read-only and are valid only for the duration of the Walk callback
// unless the FlowRecord has been cloned.
func (record FlowRecord) Extension(id ExtensionID) []byte {
	if record.format != RecordFormatV3 || len(record.raw) < v3RecordHeaderSize {
		return nil
	}

	numElements := binary.LittleEndian.Uint16(record.raw[4:6])
	offset := v3RecordHeaderSize
	for i := 0; i < int(numElements); i++ {
		if offset+4 > len(record.raw) {
			return nil
		}
		elementID := binary.LittleEndian.Uint16(record.raw[offset : offset+2])
		elementSize := int(binary.LittleEndian.Uint16(record.raw[offset+2 : offset+4]))
		if elementSize < 4 || offset+elementSize > len(record.raw) {
			return nil
		}
		if elementID == id {
			return record.raw[offset+4 : offset+elementSize]
		}
		offset += elementSize
	}
	return nil
}

// Generic returns generic flow counters, timestamps, and transport fields.
func (record FlowRecord) Generic() (GenericFlow, bool) {
	data := record.Extension(ExtensionGenericFlow)
	if len(data) < 48 {
		return GenericFlow{}, false
	}
	return GenericFlow{
		MsecFirst:    binary.LittleEndian.Uint64(data[0:8]),
		MsecLast:     binary.LittleEndian.Uint64(data[8:16]),
		MsecReceived: binary.LittleEndian.Uint64(data[16:24]),
		InPackets:    binary.LittleEndian.Uint64(data[24:32]),
		InBytes:      binary.LittleEndian.Uint64(data[32:40]),
		SrcPort:      binary.LittleEndian.Uint16(data[40:42]),
		DstPort:      binary.LittleEndian.Uint16(data[42:44]),
		Proto:        data[44],
		TcpFlags:     data[45],
		FwdStatus:    data[46],
		SrcTos:       data[47],
	}, true
}

// IP returns the source and destination address. ok is false when neither an
// IPv4 nor IPv6 address extension is present.
func (record FlowRecord) IP() (src, dst netip.Addr, ok bool) {
	if data := record.Extension(ExtensionIPv4Flow); len(data) >= 8 {
		return netip.AddrFrom4([4]byte{data[3], data[2], data[1], data[0]}),
			netip.AddrFrom4([4]byte{data[7], data[6], data[5], data[4]}), true
	}
	if data := record.Extension(ExtensionIPv6Flow); len(data) >= 32 {
		return netip.AddrFrom16(v3IPv6(data[0:16])), netip.AddrFrom16(v3IPv6(data[16:32])), true
	}
	return netip.Addr{}, netip.Addr{}, false
}

// IsIPv4 reports whether the record contains an IPv4 address extension.
func (record FlowRecord) IsIPv4() bool {
	return len(record.Extension(ExtensionIPv4Flow)) >= 8
}

// IsIPv6 reports whether the record contains an IPv6 address extension.
func (record FlowRecord) IsIPv6() bool {
	return len(record.Extension(ExtensionIPv6Flow)) >= 32
}

// ExporterID returns nfdump's exporter identifier.
func (record FlowRecord) ExporterID() uint32 {
	if record.format != RecordFormatV3 || len(record.raw) < v3RecordHeaderSize {
		return 0
	}
	return uint32(binary.LittleEndian.Uint16(record.raw[8:10]))
}

// Flags returns the record flags.
func (record FlowRecord) Flags() uint16 {
	if record.format != RecordFormatV3 || len(record.raw) < v3RecordHeaderSize {
		return 0
	}
	return uint16(record.raw[10])
}

// NetFlowVersion returns the exporting protocol version.
func (record FlowRecord) NetFlowVersion() uint8 {
	if record.format != RecordFormatV3 || len(record.raw) < v3RecordHeaderSize {
		return 0
	}
	return record.raw[11]
}

// Engine returns the exporter's engine type and engine ID.
func (record FlowRecord) Engine() (engineType, engineID uint8) {
	if record.format != RecordFormatV3 || len(record.raw) < v3RecordHeaderSize {
		return 0, 0
	}
	return record.raw[6], record.raw[7]
}

func newFlowRecordV3(raw []byte) (FlowRecord, error) {
	if err := validateV3Record(raw); err != nil {
		return FlowRecord{}, err
	}
	return FlowRecord{raw: raw, format: RecordFormatV3}, nil
}

func v3IPv6(data []byte) [16]byte {
	return [16]byte{
		data[7], data[6], data[5], data[4], data[3], data[2], data[1], data[0],
		data[15], data[14], data[13], data[12], data[11], data[10], data[9], data[8],
	}
}

func validateV3Record(record []byte) error {
	if len(record) < v3RecordHeaderSize {
		return fmt.Errorf("record too short: %d bytes", len(record))
	}
	if binary.LittleEndian.Uint16(record[0:2]) != V3Record {
		return fmt.Errorf("not a v3 record")
	}
	recordSize := binary.LittleEndian.Uint16(record[2:4])
	if recordSize < v3RecordHeaderSize || int(recordSize) != len(record) {
		return fmt.Errorf("invalid record size %d for %d bytes", recordSize, len(record))
	}

	numElements := binary.LittleEndian.Uint16(record[4:6])
	offset := v3RecordHeaderSize
	for i := 0; i < int(numElements); i++ {
		if offset+4 > int(recordSize) {
			return fmt.Errorf("record header boundary check error")
		}
		elementType := binary.LittleEndian.Uint16(record[offset : offset+2])
		elementSize := binary.LittleEndian.Uint16(record[offset+2 : offset+4])
		if elementSize < 4 || offset+int(elementSize) > int(recordSize) {
			return fmt.Errorf("record body boundary check error")
		}
		if err := validateV3AddressExtension(elementType, elementSize); err != nil {
			return err
		}
		offset += int(elementSize)
	}
	if offset != int(recordSize) {
		return fmt.Errorf("record contains %d trailing bytes", int(recordSize)-offset)
	}
	return nil
}

func validateV3AddressExtension(elementType, elementSize uint16) error {
	switch elementType {
	case EXipv4FlowID:
		if elementSize < 12 {
			return fmt.Errorf("IPv4 extension too short: %d", elementSize)
		}
	case EXipv6FlowID:
		if elementSize < 36 {
			return fmt.Errorf("IPv6 extension too short: %d", elementSize)
		}
	case EXnatXlateIPv4ID:
		if elementSize < 12 {
			return fmt.Errorf("NAT IPv4 extension too short: %d", elementSize)
		}
	case EXnatXlateIPv6ID:
		if elementSize < 36 {
			return fmt.Errorf("NAT IPv6 extension too short: %d", elementSize)
		}
	}
	return nil
}

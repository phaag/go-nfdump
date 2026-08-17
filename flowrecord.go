// Copyright © 2026 Peter Haag peter@people.ops-trust.net
// All rights reserved.
//
// Use of this source code is governed by the license that can be
// found in the LICENSE file.

package nfdump

import (
	"encoding/binary"
	"fmt"
	"math/bits"
	"net/netip"
)

const v3RecordHeaderSize = 12

const (
	v4RecordType       = 16
	v4RecordHeaderSize = 24
	v4VariableLength   = 0xffff
)

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
	switch record.format {
	case RecordFormatV3:
		return record.v3Extension(id)
	case RecordFormatV4:
		return record.v4Extension(id)
	default:
		return nil
	}
}

func (record FlowRecord) v3Extension(id ExtensionID) []byte {
	if len(record.raw) < v3RecordHeaderSize {
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

// v4ExtensionID maps a stable public identifier to its V4 bitmap bit. The V4
// layout split several old extensions and assigned new bitmap positions.
func v4ExtensionID(id ExtensionID) (uint, bool) {
	switch id {
	case ExtensionGenericFlow:
		return 1, true
	case ExtensionIPv4Flow:
		return 2, true
	case ExtensionIPv6Flow:
		return 3, true
	case ExtensionFlowMisc:
		return 5, true
	case ExtensionCounters:
		return 6, true
	case ExtensionVLAN:
		return 7, true
	case ExtensionASRouting:
		return 8, true // V4 EXasInfo carries source and destination AS.
	case ExtensionInPayload:
		return 26, true
	case ExtensionIPInfo:
		return 39, true
	default:
		return 0, false
	}
}

func (record FlowRecord) v4Extension(id ExtensionID) []byte {
	extID, ok := v4ExtensionID(id)
	if !ok || len(record.raw) < v4RecordHeaderSize {
		return nil
	}
	bitmap := binary.LittleEndian.Uint64(record.raw[16:24])
	bit := uint64(1) << extID
	if bitmap&bit == 0 {
		return nil
	}
	rank := bits.OnesCount64(bitmap & (bit - 1))
	offsetTable := v4OffsetTableSize(bitmap)
	offset := int(binary.LittleEndian.Uint16(record.raw[v4RecordHeaderSize+rank*2:]))
	size, ok := v4ExtensionSize(extID, record.raw[offset:])
	if !ok || offset < offsetTable || offset+size > len(record.raw) {
		return nil
	}
	data := record.raw[offset : offset+size]
	if extID == 26 { // EXPayload_t: expose its byte payload, not the length word.
		return data[4:]
	}
	return data
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
	switch record.format {
	case RecordFormatV3:
		if len(record.raw) >= v3RecordHeaderSize {
			return uint32(binary.LittleEndian.Uint16(record.raw[8:10]))
		}
	case RecordFormatV4:
		if len(record.raw) >= v4RecordHeaderSize {
			return binary.LittleEndian.Uint32(record.raw[8:12])
		}
	}
	return 0
}

// Flags returns the record flags.
func (record FlowRecord) Flags() uint16 {
	switch record.format {
	case RecordFormatV3:
		if len(record.raw) >= v3RecordHeaderSize {
			return uint16(record.raw[10])
		}
	case RecordFormatV4:
		if len(record.raw) >= v4RecordHeaderSize {
			return binary.LittleEndian.Uint16(record.raw[6:8])
		}
	}
	return 0
}

// NetFlowVersion returns the exporting protocol version.
func (record FlowRecord) NetFlowVersion() uint8 {
	switch record.format {
	case RecordFormatV3:
		if len(record.raw) >= v3RecordHeaderSize {
			return record.raw[11]
		}
	case RecordFormatV4:
		if len(record.raw) >= v4RecordHeaderSize {
			return record.raw[14]
		}
	}
	return 0
}

// Engine returns the exporter's engine type and engine ID.
func (record FlowRecord) Engine() (engineType, engineID uint8) {
	switch record.format {
	case RecordFormatV3:
		if len(record.raw) >= v3RecordHeaderSize {
			return record.raw[6], record.raw[7]
		}
	case RecordFormatV4:
		if len(record.raw) >= v4RecordHeaderSize {
			return record.raw[12], record.raw[13]
		}
	}
	return 0, 0
}

func newFlowRecordV3(raw []byte) (FlowRecord, error) {
	if err := validateV3Record(raw); err != nil {
		return FlowRecord{}, err
	}
	return FlowRecord{raw: raw, format: RecordFormatV3}, nil
}

func newFlowRecordV4(raw []byte) (FlowRecord, error) {
	if err := validateV4Record(raw); err != nil {
		return FlowRecord{}, err
	}
	return FlowRecord{raw: raw, format: RecordFormatV4}, nil
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

func v4OffsetTableSize(bitmap uint64) int {
	return (v4RecordHeaderSize + bits.OnesCount64(bitmap)*2 + 7) &^ 7
}

// v4ExtensionSize returns the fixed on-disk extension size, or reads the
// length prefix used by V4 variable-length extensions.
func v4ExtensionSize(id uint, data []byte) (int, bool) {
	var size int
	switch id {
	case 1:
		size = 48 // EXgenericFlow
	case 2:
		size = 8 // EXipv4Flow
	case 3:
		size = 32 // EXipv6Flow
	case 4, 7, 8, 9, 16, 18, 24, 33:
		size = 8
	case 5, 11, 20, 31, 36, 37, 39:
		size = 8
	case 6, 17, 21, 22, 34:
		size = 24
	case 10, 19:
		size = 32
	case 12, 14, 15, 30:
		size = 16
	case 13:
		size = 40
	case 23:
		size = 72
	case 28:
		size = 16
	case 29:
		size = 40
	case 35:
		size = 32
	case 38:
		size = 4
	case 25, 26, 27, 32:
		if len(data) < 4 {
			return 0, false
		}
		length := binary.LittleEndian.Uint32(data[:4])
		if length > uint32(len(data)-4) {
			return 0, false
		}
		size = 4 + int(length)
	default:
		return 0, false
	}
	return size, size <= len(data)
}

func validateV4Record(record []byte) error {
	if len(record) < v4RecordHeaderSize {
		return fmt.Errorf("V4 record too short: %d bytes", len(record))
	}
	if binary.LittleEndian.Uint16(record[0:2]) != v4RecordType {
		return fmt.Errorf("not a V4 record")
	}
	recordSize := int(binary.LittleEndian.Uint16(record[2:4]))
	if recordSize != len(record) || recordSize < v4RecordHeaderSize || recordSize&7 != 0 {
		return fmt.Errorf("invalid V4 record size %d for %d bytes", recordSize, len(record))
	}
	numExtensions := int(binary.LittleEndian.Uint16(record[4:6]))
	bitmap := binary.LittleEndian.Uint64(record[16:24])
	if bits.OnesCount64(bitmap) != numExtensions {
		return fmt.Errorf("V4 record extension count does not match bitmap")
	}
	offsetTableEnd := v4OffsetTableSize(bitmap)
	if offsetTableEnd > recordSize {
		return fmt.Errorf("V4 record offset table exceeds record")
	}

	// Keep extension ranges ordered by offset. Only the immediate neighbours
	// can overlap a newly inserted range, avoiding an O(n²) all-pairs scan on
	// every flow while retaining the V4 any-order extension guarantee.
	var starts, ends [40]uint16 // MAXEXTENSIONS in nfxV4.h is 40.
	intervalCount := 0
	for remaining, rank := bitmap, 0; remaining != 0; rank++ {
		id := uint(bits.TrailingZeros64(remaining))
		remaining &= remaining - 1
		offset := int(binary.LittleEndian.Uint16(record[v4RecordHeaderSize+rank*2:]))
		if offset < offsetTableEnd || offset&7 != 0 || offset >= recordSize {
			return fmt.Errorf("V4 extension %d has invalid offset %d", id, offset)
		}
		size, ok := v4ExtensionSize(id, record[offset:])
		if !ok || offset+size > recordSize {
			return fmt.Errorf("V4 extension %d exceeds record", id)
		}
		if intervalCount == len(starts) {
			return fmt.Errorf("V4 record has too many extensions")
		}
		position := intervalCount
		for position > 0 && starts[position-1] > uint16(offset) {
			starts[position] = starts[position-1]
			ends[position] = ends[position-1]
			position--
		}
		if (position > 0 && int(ends[position-1]) > offset) ||
			(position < intervalCount && offset+size > int(starts[position])) {
			return fmt.Errorf("V4 extension data overlaps")
		}
		starts[position] = uint16(offset)
		ends[position] = uint16(offset + size)
		intervalCount++
	}
	return nil
}

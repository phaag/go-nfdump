// Code generated by cmd/cgo -godefs; DO NOT EDIT.
// cgo -godefs defs.go

package nfdump

import (
	"net"
)

const (
	EXnull			= uint(0x0)
	EXgenericFlowID		= uint16(0x1)
	EXipv4FlowID		= uint16(0x2)
	EXipv6FlowID		= uint16(0x3)
	EXflowMiscID		= uint16(0x4)
	EXcntFlowID		= uint16(0x5)
	EXvLanID		= uint16(0x6)
	EXasRoutingID		= uint16(0x7)
	EXbgpNextHopV4ID	= uint16(0x8)
	EXbgpNextHopV6ID	= uint16(0x9)
	EXipNextHopV4ID		= uint16(0xa)
	EXipNextHopV6ID		= uint16(0xb)
	EXipReceivedV4ID	= uint16(0xc)
	EXipReceivedV6ID	= uint16(0xd)
)

const (
	V3_FLAG_EVENT	= uint(0x1)
	V3_FLAG_SAMPLED	= uint(0x2)
	V3_FLAG_ANON	= uint(0x4)
)

const (
	V3Record		= uint16(0xb)
	ExporterInfoRecordType	= uint16(0x7)
	ExporterStatRecordType	= uint16(0x8)
	SamplerLegacyRecordType	= uint16(0x9)
	SamplerRecordType	= uint16(0xf)
)

const MAXEXTENSIONS = uint16(0x26)

type recordHeaderV3 struct {
	Type		uint16
	Size		uint16
	NumElements	uint16
	EngineType	uint8
	EngineID	uint8
	ExporterID	uint16
	Flags		uint8
	Nfversion	uint8
}

type EXgenericFlow struct {
	MsecFirst	uint64
	MsecLast	uint64
	MsecReceived	uint64
	InPackets	uint64
	InBytes		uint64
	SrcPort		uint16
	DstPort		uint16
	Proto		uint8
	TcpFlags	uint8
	FwdStatus	uint8
	SrcTos		uint8
}
type EXflowMisc struct {
	Input		uint32
	Output		uint32
	SrcMask		uint8
	DstMask		uint8
	Dir		uint8
	DstTos		uint8
	BiFlowDir	uint8
	FlowEndReason	uint8
	RevTcpFlags	uint8
	Fill		uint8
}
type EXcntFlow struct {
	Flows		uint64
	OutPackets	uint64
	OutBytes	uint64
}
type EXvLan struct {
	SrcVlan	uint32
	DstVlan	uint32
}
type EXasRouting struct {
	SrcAS	uint32
	DstAS	uint32
}

type EXbgpNextHop struct {
	IP net.IP
}

type EXipNextHop struct {
	IP net.IP
}

type EXipReceived struct {
	IP net.IP
}

type ExporterInfoRecord struct {
	Type	uint16
	Size	uint16
	Version	uint32
	Ip	[2]uint64
	Family	uint16
	Sysid	uint16
	Id	uint32
}
type SamplerRecord struct {
	Type		uint16
	Size		uint16
	Sysid		uint16
	Algorithm	uint16
	Id		int64
	PacketInterval	uint32
	SpaceInterval	uint32
}

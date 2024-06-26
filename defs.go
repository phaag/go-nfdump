//go:build ignore

// Copyright © 2023 Peter Haag peter@people.ops-trust.net
// All rights reserved.
//
// Use of this source code is governed by the license that can be
// found in the LICENSE file.

package nfdump

//#define GOLANG 1
//#include <stdint.h>
//#include "nfxV3.h"
//#include "id.h"
//#include "exporter.h"
//
import "C"

import (
	"net"
)

const (
	EXnull             = uint(C.EXnull)
	EXgenericFlowID    = uint16(C.EXgenericFlowID)
	EXipv4FlowID       = uint16(C.EXipv4FlowID)
	EXipv6FlowID       = uint16(C.EXipv6FlowID)
	EXflowMiscID       = uint16(C.EXflowMiscID)
	EXcntFlowID        = uint16(C.EXcntFlowID)
	EXvLanID           = uint16(C.EXvLanID)
	EXasRoutingID      = uint16(C.EXasRoutingID)
	EXbgpNextHopV4ID   = uint16(C.EXbgpNextHopV4ID)
	EXbgpNextHopV6ID   = uint16(C.EXbgpNextHopV6ID)
	EXipNextHopV4ID    = uint16(C.EXipNextHopV4ID)
	EXipNextHopV6ID    = uint16(C.EXipNextHopV6ID)
	EXipReceivedV4ID   = uint16(C.EXipReceivedV4ID)
	EXipReceivedV6ID   = uint16(C.EXipReceivedV6ID)
	EXmplsLabelID      = uint16(C.EXmplsLabelID)
	EXsamplerInfoID    = uint16(C.EXsamplerInfoID)
	EXinPayloadID      = uint16(C.EXinPayloadID)
	EXnatXlateIPv4ID   = uint16(C.EXnatXlateIPv4ID)
	EXnatXlateIPv6ID   = uint16(C.EXnatXlateIPv6ID)
	EXnatXlatePortID   = uint16(C.EXnatXlatePortID)
	EXnatCommonID      = uint16(C.EXnatCommonID)
	EXnatPortBlockID   = uint16(C.EXnatPortBlockID)
	EXflowIdID         = uint16(C.EXflowIdID)
	EXnokiaNatID       = uint16(C.EXnokiaNatID)
	EXnokiaNatStringID = uint16(C.EXnokiaNatStringID)
)

const (
	V3_FLAG_EVENT   = uint(C.V3_FLAG_EVENT)
	V3_FLAG_SAMPLED = uint(C.V3_FLAG_SAMPLED)
	V3_FLAG_ANON    = uint(C.V3_FLAG_ANON)
)

const (
	ExtensionMapType        = uint16(C.ExtensionMapType)
	V3Record                = uint16(C.V3Record)
	ExporterInfoRecordType  = uint16(C.ExporterInfoRecordType)
	ExporterStatRecordType  = uint16(C.ExporterStatRecordType)
	SamplerLegacyRecordType = uint16(C.SamplerLegacyRecordType)
	SamplerRecordType       = uint16(C.SamplerRecordType)
	CommonRecordType        = uint16(C.CommonRecordType)
)

const MAXEXTENSIONS = uint16(C.MAXEXTENSIONS)

type recordHeaderV3 C.struct_recordHeaderV3_s

type EXgenericFlow C.struct_EXgenericFlow_s
type EXflowMisc C.struct_EXflowMisc_s
type EXcntFlow C.struct_EXcntFlow_s
type EXvLan C.struct_EXvLan_s
type EXmplsLabel C.struct_EXmplsLabel_s
type EXasRouting C.struct_EXasRouting_s
type EXipReceivedV4 C.struct_EXipReceivedV4_s
type EXsamplerInfo C.struct_EXsamplerInfo_s
type EXnatXlatePort C.struct_EXnatXlatePort_s
type EXnatCommon C.struct_EXnatCommon_s
type EXnatPortBlock C.struct_EXnatPortBlock_s
type EXflowId C.struct_EXflowId_s
type EXnokiaNat C.struct_EXnokiaNat_s
type EXnokiaNatString string

type EXbgpNextHop struct {
	IP net.IP
}

type EXipNextHop struct {
	IP net.IP
}

type EXipReceived struct {
	IP net.IP
}

type EXnatXlateIP struct {
	SrcXIP net.IP
	DstXIP net.IP
}

type EXinPayload []byte

type ExporterInfoRecord C.struct_exporter_info_record_s
type SamplerRecord C.struct_sampler_record_s

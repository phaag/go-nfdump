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
//
import "C"

import (
	"net"
)

const (
	EXnull           = uint(C.EXnull)
	EXgenericFlowID  = uint16(C.EXgenericFlowID)
	EXipv4FlowID     = uint16(C.EXipv4FlowID)
	EXipv6FlowID     = uint16(C.EXipv6FlowID)
	EXflowMiscID     = uint16(C.EXflowMiscID)
	EXcntFlowID      = uint16(C.EXcntFlowID)
	EXvLanID         = uint16(C.EXvLanID)
	EXasRoutingID    = uint16(C.EXasRoutingID)
	EXbgpNextHopV4ID = uint16(C.EXbgpNextHopV4ID)
	EXbgpNextHopV6ID = uint16(C.EXbgpNextHopV6ID)
	EXipNextHopV4ID  = uint16(C.EXipNextHopV4ID)
	EXipNextHopV6ID  = uint16(C.EXipNextHopV6ID)
)

const (
	V3_FLAG_EVENT   = uint(C.V3_FLAG_EVENT)
	V3_FLAG_SAMPLED = uint(C.V3_FLAG_SAMPLED)
	V3_FLAG_ANON    = uint(C.V3_FLAG_ANON)
)

const V3Record = uint16(C.V3Record)

const MAXEXTENSIONS = uint16(C.MAXEXTENSIONS)

type recordHeaderV3 C.struct_recordHeaderV3_s

type EXgenericFlow C.struct_EXgenericFlow_s
type EXflowMisc C.struct_EXflowMisc_s
type EXcntFlow C.struct_EXcntFlow_s
type EXvLan C.struct_EXvLan_s
type EXasRouting C.struct_EXasRouting_s

type EXbgpNextHop struct {
	IP net.IP
}

type EXipNextHop struct {
	IP net.IP
}

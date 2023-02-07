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

const EXnull = uint(C.EXnull)
const EXgenericFlowID = uint16(C.EXgenericFlowID)
const EXipv4FlowID = uint16(C.EXipv4FlowID)
const EXipv6FlowID = uint16(C.EXipv6FlowID)
const EXflowMiscID = uint16(C.EXflowMiscID)
const EXcntFlowID = uint16(C.EXcntFlowID)
const EXvLanID = uint16(C.EXvLanID)
const EXasRoutingID = uint16(C.EXasRoutingID)

const V3_FLAG_EVENT = uint(C.V3_FLAG_EVENT)
const V3_FLAG_SAMPLED = uint(C.V3_FLAG_SAMPLED)
const V3_FLAG_ANON = uint(C.V3_FLAG_ANON)

const V3Record = uint16(C.V3Record)

const MAXEXTENSIONS = uint16(C.MAXEXTENSIONS)

type recordHeaderV3 C.struct_recordHeaderV3_s

type EXgenericFlow C.struct_EXgenericFlow_s
type EXflowMisc C.struct_EXflowMisc_s
type EXcntFlow C.struct_EXcntFlow_s
type EXvLan C.struct_EXvLan_s
type EXasRouting C.struct_EXasRouting_s
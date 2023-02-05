//go:build ignore

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

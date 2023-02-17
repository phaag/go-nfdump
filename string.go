// Copyright © 2023 Peter Haag peter@people.ops-trust.net
// All rights reserved.
//
// Use of this source code is governed by the license that can be
// found in the LICENSE file.

package nfdump

import (
	"fmt"
	"time"
)

func flagsString(flags uint16) string {
	var flagChars = []byte{'.', '.', '.', '.', '.', '.', '.', '.'}

	// Congestion window reduced -  CWR
	if flags&128 != 0 {
		flagChars[0] = 'C'
	}
	// ECN-Echo
	if flags&64 != 0 {
		flagChars[1] = 'E'
	}
	// Urgent
	if flags&32 != 0 {
		flagChars[2] = 'U'
	}
	// Ack
	if flags&16 != 0 {
		flagChars[3] = 'A'
	}
	// Push
	if flags&8 != 0 {
		flagChars[4] = 'P'
	}
	// Reset
	if flags&4 != 0 {
		flagChars[5] = 'R'
	}
	// Syn
	if flags&2 != 0 {
		flagChars[6] = 'S'
	}
	// Fin
	if flags&1 != 0 {
		flagChars[7] = 'F'
	}

	return string(flagChars)

} // End of FlagsString

// Return string for %v Printf()
func (flowRecord *FlowRecordV3) String() string {
	var flowType string
	if flowRecord.recordHeader.Nfversion != 0 {
		if flowRecord.recordHeader.Nfversion&0x80 != 0 {
			flowType = "SFLOW"
		} else if flowRecord.recordHeader.Nfversion&0x40 != 0 {
			flowType = "PCAP"
		} else {
			flowType = "NETFLOW"
		}
	} else {
		flowType = "FLOW"
	}

	var recordFlags string
	recordFlags = ""
	if flowRecord.recordHeader.Flags&uint8(V3_FLAG_EVENT) != 0 {
		recordFlags += " Event"
	}
	if flowRecord.recordHeader.Flags&uint8(V3_FLAG_SAMPLED) != 0 {
		recordFlags += " Sampled"
	}
	if flowRecord.recordHeader.Flags&uint8(V3_FLAG_ANON) != 0 {
		recordFlags += " Anon"
	}
	var s string = "Flow Record:\n" +
		fmt.Sprintf("  Flags       : %v %s%s\n", flowRecord.recordHeader.Flags, flowType, recordFlags) +
		fmt.Sprintf("  Elements    : %v\n", flowRecord.recordHeader.NumElements) +
		fmt.Sprintf("  Size        : %v\n", flowRecord.recordHeader.Size) +
		fmt.Sprintf("  EngineType  : %v\n", flowRecord.recordHeader.EngineType) +
		fmt.Sprintf("  EngineID    : %v\n", flowRecord.recordHeader.EngineID) +
		fmt.Sprintf("  ExporterID  : %v\n", flowRecord.recordHeader.ExporterID) +
		fmt.Sprintf("  Netflow     : %v\n", flowRecord.recordHeader.Nfversion)

	s += flowRecord.dumpEXgenericFlow()
	s += fmt.Sprintf("  SrcIP       : %v\n  DstIP       : %v\n", flowRecord.srcIP, flowRecord.dstIP)
	s += flowRecord.dumpEXflowMisc()
	s += flowRecord.dumpEXcntFlow()
	s += flowRecord.dumpEXvLan()
	s += flowRecord.dumpEXasRouting()
	s += flowRecord.dumpEXbgpNextHop()
	s += flowRecord.dumpEXipNextHop()
	s += flowRecord.dumpEXipReceived()

	return s
}

func (flowRecord *FlowRecordV3) dumpEXgenericFlow() string {

	var genericFlow *EXgenericFlow
	if genericFlow = flowRecord.GenericFlow(); genericFlow == nil {
		return ""
	}

	var s string = ""
	tTime := time.UnixMilli(int64(genericFlow.MsecFirst))
	s += fmt.Sprintf("  First       : %d %v\n", genericFlow.MsecFirst, tTime)

	tTime = time.UnixMilli(int64(genericFlow.MsecLast))
	s += fmt.Sprintf("  Last        : %d %v\n", genericFlow.MsecLast, tTime)

	tTime = time.UnixMilli(int64(genericFlow.MsecReceived))
	tcpFlags := genericFlow.TcpFlags
	if genericFlow.Proto != 6 {
		tcpFlags = 0
	}
	s += fmt.Sprintf("  Received    : %d %v\n", genericFlow.MsecReceived, tTime) +

		fmt.Sprintf("  In Packets  : %d\n", genericFlow.InPackets) +
		fmt.Sprintf("  In Bytes    : %d\n", genericFlow.InBytes) +
		fmt.Sprintf("  Proto       : %d\n", genericFlow.Proto) +
		fmt.Sprintf("  SrcPort     : %d\n", genericFlow.SrcPort) +
		fmt.Sprintf("  DstPort     : %d\n", genericFlow.DstPort) +
		fmt.Sprintf("  TcpFlags    : 0x%x %s\n", tcpFlags, flagsString(uint16(tcpFlags))) +
		fmt.Sprintf("  FwdStatus   : %d\n", genericFlow.FwdStatus) +
		fmt.Sprintf("  SrcTos      : %d\n", genericFlow.SrcTos)
	return s
}

func (flowRecord *FlowRecordV3) dumpEXflowMisc() string {

	var flowMisc *EXflowMisc
	if flowMisc = flowRecord.FlowMisc(); flowMisc == nil {
		return ""
	}

	var s string = "" +
		fmt.Sprintf("  Input       : %v\n", flowMisc.Input) +
		fmt.Sprintf("  Output      : %v\n", flowMisc.Output) +
		fmt.Sprintf("  SrcMask     : %v\n", flowMisc.SrcMask) +
		fmt.Sprintf("  DstMask     : %v\n", flowMisc.DstMask) +
		fmt.Sprintf("  Direction   : %v\n", flowMisc.Dir) +
		fmt.Sprintf("  DstTos      : %v\n", flowMisc.DstTos) +
		fmt.Sprintf("  BiFlowDir   : %v\n", flowMisc.BiFlowDir) +
		fmt.Sprintf("  EndReason   : %v\n", flowMisc.FlowEndReason)

	return s
}

func (flowRecord *FlowRecordV3) dumpEXcntFlow() string {
	var cntFlow *EXcntFlow
	if cntFlow = flowRecord.CntFlow(); cntFlow == nil {
		return ""
	}

	var s string = "" +
		fmt.Sprintf("  Out Packets : %d\n", cntFlow.OutPackets) +
		fmt.Sprintf("  Out Bytes   : %d\n", cntFlow.OutBytes) +
		fmt.Sprintf("  Aggr Flows  : %d\n", cntFlow.Flows)

	return s
}

func (flowRecord *FlowRecordV3) dumpEXvLan() string {
	var vLan *EXvLan
	if vLan = flowRecord.VLan(); vLan == nil {
		return ""
	}

	var s string = "" +
		fmt.Sprintf("  Src Vlan    : %d\n", vLan.SrcVlan) +
		fmt.Sprintf("  Dst Vlan    : %d\n", vLan.DstVlan)

	return s
}

func (flowRecord *FlowRecordV3) dumpEXasRouting() string {
	var asRouting *EXasRouting
	if asRouting = flowRecord.AsRouting(); asRouting == nil {
		return ""
	}

	var s string = "" +
		fmt.Sprintf("  Src AS      : %d\n", asRouting.SrcAS) +
		fmt.Sprintf("  Dst AS      : %d\n", asRouting.DstAS)

	return s
}

func (flowRecord *FlowRecordV3) dumpEXbgpNextHop() string {
	var nextHop *EXbgpNextHop
	if nextHop = flowRecord.BgpNextHop(); nextHop == nil {
		return ""
	}
	return fmt.Sprintf("  Bgp next hop: %v\n", nextHop.IP)
}

func (flowRecord *FlowRecordV3) dumpEXipNextHop() string {
	var nextHop *EXipNextHop
	if nextHop = flowRecord.IpNextHop(); nextHop == nil {
		return ""
	}
	return fmt.Sprintf("  IP next hop : %v\n", nextHop.IP)
}

func (flowRecord *FlowRecordV3) dumpEXipReceived() string {
	var ipReceived *EXipReceived
	if ipReceived = flowRecord.IpReceived(); ipReceived == nil {
		return ""
	}
	return fmt.Sprintf("  IP received : %v\n", ipReceived.IP)
}

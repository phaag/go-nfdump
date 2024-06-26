// Copyright © 2024 Peter Haag peter@people.ops-trust.net
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

	s += flowRecord.dumpEXsampling()
	s += flowRecord.dumpEXflowMisc()
	s += flowRecord.dumpEXcntFlow()
	s += flowRecord.dumpEXvLan()
	s += flowRecord.dumpEXmpls()
	s += flowRecord.dumpEXasRouting()
	s += flowRecord.dumpEXbgpNextHop()
	s += flowRecord.dumpEXipNextHop()
	s += flowRecord.dumpEXnatCommon()
	s += flowRecord.dumpEXnatXlateIP()
	s += flowRecord.dumpEXnatXlatePort()
	s += flowRecord.dumpEXnatPortBlock()
	s += flowRecord.dumpEXipReceived()
	s += flowRecord.dumpEXflowId()
	s += flowRecord.dumpEXnokiaNAT()
	s += flowRecord.dumpEXnokiaNatString()

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

func (flowRecord *FlowRecordV3) dumpEXsampling() string {

	var sampling *EXsamplerInfo
	if sampling = flowRecord.Sampling(); sampling != nil {

		var s string = fmt.Sprintf("  SamplingID  : %d\n", sampling.SelectorID) +
			fmt.Sprintf("  ExporterID  : %d\n", sampling.Sysid)
		return s
	} else {
		return ""
	}
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

func (flowRecord *FlowRecordV3) dumpEXmpls() string {
	var mplsLabels *EXmplsLabel
	if mplsLabels = flowRecord.MplsLabels(); mplsLabels == nil {
		return ""
	}

	var s string
	for i, label := range mplsLabels.MplsLabel {
		formattedLabel := fmt.Sprintf("%d-%1d-%1d", label>>4, (label&0xF)>>1, label&1)
		s += fmt.Sprintf("  MPLS Label%d : %s\n", i, formattedLabel)
	}
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

func (flowRecord *FlowRecordV3) dumpEXnatXlateIP() string {
	var natXlateIP = flowRecord.NatXlateIP()
	if !flowRecord.hasXlateIP {
		return ""
	}

	var s string = "" +
		// when printing as %v, Golang takes care about proper formating
		// as IPv4 or IPv6
		// see Golang standard library net.IP for more details to process IPs
		fmt.Sprintf("  NAT Src X-IP: %v\n", natXlateIP.SrcXIP) +
		fmt.Sprintf("  NAT Dst X-IP: %v\n", natXlateIP.DstXIP)

	return s
}

func (flowRecord *FlowRecordV3) dumpEXnatXlatePort() string {
	var xlatePort *EXnatXlatePort
	if xlatePort = flowRecord.NatXlatePort(); xlatePort == nil {
		return ""
	}
	var s string = "" +
		fmt.Sprintf("  NAT SrcXPort: %d\n", xlatePort.XlateSrcPort) +
		fmt.Sprintf("  NAT DstXPort: %d\n", xlatePort.XlateDstPort)

	return s
}

func (flowRecord *FlowRecordV3) dumpEXnatCommon() string {
	var natCommon *EXnatCommon
	if natCommon = flowRecord.NatCommon(); natCommon == nil {
		return ""
	}

	var s string = "" +
		fmt.Sprintf("  NAT Event   : %d\n", natCommon.NatEvent) +
		fmt.Sprintf("  NAT PoolID  : %d\n", natCommon.NatPoolID)

	return s
}

func (flowRecord *FlowRecordV3) dumpEXnatPortBlock() string {
	var natPortBlock *EXnatPortBlock
	if natPortBlock = flowRecord.NatPortBlock(); natPortBlock == nil {
		return ""
	}

	fmt.Printf("Dump NAT PORT\n")
	var s string = "" +
		fmt.Sprintf("  NAT pstart  : %d\n", natPortBlock.BlockStart) +
		fmt.Sprintf("  NAT pend    : %d\n", natPortBlock.BlockEnd) +
		fmt.Sprintf("  NAT pstep   : %d\n", natPortBlock.BlockStep) +
		fmt.Sprintf("  NAT psize   : %d\n", natPortBlock.BlockSize)

	return s
}

func (flowRecord *FlowRecordV3) dumpEXipReceived() string {
	var ipReceived *EXipReceived
	if ipReceived = flowRecord.IpReceived(); ipReceived == nil {
		return ""
	}
	return fmt.Sprintf("  IP received : %v\n", ipReceived.IP)
}

func (flowRecord *FlowRecordV3) dumpEXflowId() string {
	var flowId *EXflowId
	if flowId = flowRecord.FlowId(); flowId == nil {
		return ""
	}
	return fmt.Sprintf("  Flow ID     : 0x%x\n", flowId.FlowId)
}

func (flowRecord *FlowRecordV3) dumpEXnokiaNAT() string {
	var nokiaNat *EXnokiaNat
	if nokiaNat = flowRecord.NokiaNat(); nokiaNat == nil {
		return ""
	}

	var s string = "" +
		fmt.Sprintf("  In Srv ID   : %d\n", nokiaNat.InServiceID) +
		fmt.Sprintf("  Out Srv ID  : %d\n", nokiaNat.OutServiceID)

	return s
}

func (flowRecord *FlowRecordV3) dumpEXnokiaNatString() string {
	var natString EXnokiaNatString
	if natString = flowRecord.NokiaNatString(); natString == "" {
		return ""
	}
	return fmt.Sprintf("  Flow ID     : %v\n", natString)
}

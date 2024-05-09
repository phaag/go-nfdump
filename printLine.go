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

func fmtDuration(d uint64) string {
	msec := d % 1000
	d = (d - msec) / 1000
	sec := d % 60
	d = (d - sec) / 60
	min := d % 60
	d = (d - min) / 60
	hour := d % 24
	days := (d - hour) / 24
	if days == 0 {
		return fmt.Sprintf("   %02d:%02d:%02d.%03d", hour, min, sec, msec)
	} else {
		return fmt.Sprintf("%02dd %02d:%02d:%02d.%03d", days, hour, min, sec, msec)
	}
}

// Return generic extension
func (flowRecord *FlowRecordV3) PrintLine() {
	if genericFlow := flowRecord.GenericFlow(); genericFlow != nil {
		tTime := time.UnixMilli(int64(genericFlow.MsecFirst))
		duration := genericFlow.MsecLast - genericFlow.MsecFirst
		ipAddr := flowRecord.IP()
		if ipAddr != nil {
			fmt.Printf("%s %s %3d %15v:%-5v -> %15v:%-5v %5d %7d\n", tTime.Format("2006-01-02 15:04:05.000"), fmtDuration(duration), genericFlow.Proto,
				ipAddr.SrcIP, genericFlow.SrcPort, ipAddr.DstIP, genericFlow.DstPort, genericFlow.InPackets, genericFlow.InBytes)
		}
	}
}

// Copyright © 2024 Peter Haag peter@people.ops-trust.net
// All rights reserved.
//
// Use of this source code is governed by the license that can be
// found in the LICENSE file.

package nfdump

import (
	"fmt"

	"github.com/twotwotwo/sorts"
)

type sortRecord struct {
	index uint32
	value uint64
}

type sortType []sortRecord

var sortArray []sortRecord
var recordArray []*FlowRecordV3

// sort direction ASCENDING
const ASCENDING = 1

// sort direction DESCENDING
const DESCENDING = 2

// implement sorts interface
// return len of sorting array
func (a sortType) Len() int { return len(a) }

// swap 2 elements
func (a sortType) Swap(i, j int) { a[i], a[j] = a[j], a[i] }

// return key of element i
func (a sortType) Key(i int) uint64 {
	return a[i].value
}

// compare tw values for less
func (a sortType) Less(i, j int) bool {
	return a[i].value < a[j].value
}

// value functions
// return appropriate values
type valueFuncType func(record *FlowRecordV3) uint64

// tstart in msec
func getTstart(record *FlowRecordV3) uint64 {
	var value uint64
	if genericFlow := record.GenericFlow(); genericFlow != nil {
		value = genericFlow.MsecFirst
	}
	return value
}

// tend in msec
func getTend(record *FlowRecordV3) uint64 {
	var value uint64
	if genericFlow := record.GenericFlow(); genericFlow != nil {
		value = genericFlow.MsecFirst
	}
	return value
}

// packets
func getPackets(record *FlowRecordV3) uint64 {
	var value uint64
	if genericFlow := record.GenericFlow(); genericFlow != nil {
		value = genericFlow.InPackets
	}
	return value
}

// bytes
func getBytes(record *FlowRecordV3) uint64 {
	var value uint64
	if genericFlow := record.GenericFlow(); genericFlow != nil {
		value = genericFlow.InBytes
	}
	return value
}

// order option - name and function
type orderOption struct {
	name      string
	orderFunc valueFuncType
}

// list all possible orderBy options
var orderTable = []orderOption{
	orderOption{"tstart", getTstart},
	orderOption{"tend", getTend},
	orderOption{"packets", getPackets},
	orderOption{"bytes", getBytes},
}

// function used recordChain as input, sort the records by orderBy
// accepts and orderBy, defined in the order table as name
// direction is einer ASCENDING or DESCENDING
// returns chain element with channel of sorted records
func (recordChain *RecordChain) OrderBy(orderBy string, direction int) *RecordChain {
	// propagate error
	if recordChain.err != nil {
		return &RecordChain{recordChan: nil, err: recordChain.err}
	}

	var valueFunc valueFuncType
	for i := 0; i < len(orderTable); i++ {
		if orderBy == orderTable[i].name {
			valueFunc = orderTable[i].orderFunc
		}
	}

	if valueFunc == nil {
		return &RecordChain{recordChan: nil, err: fmt.Errorf("Unknown orderBy: %s", orderBy)}
	}

	writeChan := make(chan *FlowRecordV3, 64)

	// store all flow records into an array for later printing
	recordArray = make([]*FlowRecordV3, 1024*1024)

	// store value to be sorted and index of appropriate flow record of
	// recordArray. Keeps sortArray smaller - cache friendly
	sortArray = make([]sortRecord, 1024*1024)

	go func(readChan chan *FlowRecordV3) {

		var arrayLen = len(sortArray)
		// use direct access [cnt] to slice to speed up instead of append()
		// increase array if needed
		var cnt uint32 = 0
		for record := range readChan {
			if uint32(arrayLen)-cnt == 0 {
				// double array, if exhausted
				sortArray = append(make([]sortRecord, 2*arrayLen), sortArray...)
				recordArray = append(make([]*FlowRecordV3, 2*arrayLen), recordArray...)

				// use new len of array. Go may assign more memory than requested
				// so use actual len
				arrayLen = len(sortArray)
			}
			recordArray[cnt] = record
			value := valueFunc(record)
			sortArray[cnt] = sortRecord{cnt, value}
			cnt++
		}

		// sort array
		// the interface makes use of len() - therefore cut slice pointer to real size
		sorts.ByUint64(sortType(sortArray[0:cnt]))

		if direction == ASCENDING {
			for i := 0; i < int(cnt); i++ {
				index := sortArray[i].index
				record := recordArray[index]
				writeChan <- record
			}
		} else {
			for i := int(cnt) - 1; i >= 0; i-- {
				index := sortArray[i].index
				record := recordArray[index]
				writeChan <- record
			}
		}
		close(writeChan)

	}(recordChain.recordChan)

	return &RecordChain{recordChan: writeChan, err: nil}
} // End of OrderBy

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

// sort record
// contains value to be sorted and index into the record array with the flow record.
// keeping the flow record separate, is more CPU cache friendly, as only a sortRecord
// needs to be moved in memory
type sortRecord struct {
	index uint32
	value uint64
}

// the sort slice type for sorting
type sortType []sortRecord

// the slice for all sort record, to be sorted
var sortArray []sortRecord

// the static record array is just filled and never moved
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

// compare two values for less
func (a sortType) Less(i, j int) bool {
	return a[i].value < a[j].value
}

// value functions
// return appropriate values to be sorted
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

// table with all possible orderBy options currently implemented
var orderTable = []orderOption{
	orderOption{"tstart", getTstart},
	orderOption{"tend", getTend},
	orderOption{"packets", getPackets},
	orderOption{"bytes", getBytes},
}

// function, which uses recordChain as input
//   - sorts the records by orderBy
//   - accepts orderBy as defined in the order table
//   - accpets direction as either ASCENDING or DESCENDING
//
// returns chain element with channel of sorted records
func (recordChain *RecordChain) OrderBy(orderBy string, direction int) *RecordChain {
	// propagate error, if input void
	if recordChain.err != nil {
		return &RecordChain{recordChan: nil, err: recordChain.err}
	}

	// get appropriate value function
	var valueFunc valueFuncType
	for i := 0; i < len(orderTable); i++ {
		if orderBy == orderTable[i].name {
			valueFunc = orderTable[i].orderFunc
			break
		}
	}

	if valueFunc == nil {
		return &RecordChain{recordChan: nil, err: fmt.Errorf("Unknown orderBy: %s", orderBy)}
	}

	// write the sorted records to this channel
	writeChan := make(chan *FlowRecordV3, 128)

	// store all flow records into an array for later printing
	// initial len - 1 meg
	recordArray = make([]*FlowRecordV3, 1024*1024)

	// store value to be sorted and index of appropriate flow record of
	// recordArray. initial len - 1 meg
	sortArray = make([]sortRecord, 1024*1024)

	// fire off goroutine
	go func(readChan chan *FlowRecordV3) {

		var arrayLen = len(sortArray)
		// use direct access ..[cnt] to slice to speed up instead of append()
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

			// calculate sort value and assign values
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

	// return chain element
	return &RecordChain{recordChan: writeChan, err: nil}

} // End of OrderBy

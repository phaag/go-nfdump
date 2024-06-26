// convert.go handles DataBlock type 2 conversion to type 3 and CommonRecord conversion to RecordV3. Inspired by nfdump C implementation
package nfdump

import (
	"encoding/binary"
	"fmt"
	"log"
	"os"
	"unsafe"
)

var extensionMapList *ExtensionMapList

// Define the flag constants
const (
	FlagIPv6Addr = 1 << iota // 1 << 0 == 1
	FlagPkg64                // 1 << 1 == 2
	FlagBytes64              // 1 << 2 == 4
	FlagIPv6NH               // 1 << 3 == 8
	FlagIPv6NHB              // 1 << 4 == 16
	FlagIPv6Exp              // 1 << 5 == 32
	FlagEvent                // 1 << 6 == 64
	FlagSampled              // 1 << 7 == 128
)

type CommonRecordFixed struct {
	Type          uint16
	Size          uint16
	Flags         uint16
	ExtMap        uint16
	MsecFirst     uint16
	MsecLast      uint16
	First         uint32
	Last          uint32
	FwdStatus     uint8
	TcpFlags      uint8
	Prot          uint8
	Tos           uint8
	SrcPort       uint16
	DstPort       uint16
	ExporterSysID uint16
	BiFlowDir     uint8
	FlowEndReason uint8
}

// CommonRecord represents a NetFlow common record.
type CommonRecord struct {
	CommonRecordFixed
	Data []byte
}

type elementHeader struct {
	Type uint16
	Size uint16
}

func TestFlag(varFlags uint16, flag uint16) bool {
	return varFlags&flag != 0
}

func ConvertBlockType2(v2DataBlock *DataBlock, v3DataBlock *DataBlock) {
	log.SetOutput(os.Stdout)
	log.SetFlags(log.Lshortfile)
	offset := 0
	var sumSize uint32 = 0
	for i := 0; i < int(v2DataBlock.Header.NumRecords); i++ {
		if uint32(offset) >= v2DataBlock.Header.Size {
			fmt.Fprintf(os.Stderr, "DataBlock error: numRecords: %d, size: %d. Current record index: %d, size: %d\n", v2DataBlock.Header.NumRecords, v2DataBlock.Header.Size, i, offset)
			break
		}

		recordType := binary.LittleEndian.Uint16(v2DataBlock.Data[offset : offset+2])
		recordSize := binary.LittleEndian.Uint16(v2DataBlock.Data[offset+2 : offset+4])

		if sumSize+uint32(recordSize) > v2DataBlock.Header.Size {
			log.Println("Corrupt data file. Inconsistent block size")
			sumSize = 0
			break
		}

		switch recordType {
		case CommonRecordType:
			fixedSize := 32
			tmpOffset := 0
			if offset+fixedSize > len(v2DataBlock.Data) {
				log.Printf("Data block is too small to contain the CommonRecord")
				return
			}
			common_record := CommonRecord{}
			commonRecordFixedPart := (*CommonRecordFixed)(unsafe.Pointer(&v2DataBlock.Data[offset]))
			tmpOffset = offset + fixedSize
			dataSize := int(commonRecordFixedPart.Size) - fixedSize
			common_record.CommonRecordFixed = *commonRecordFixedPart

			// Ensure that the remaining data can accommodate the Data slice
			if tmpOffset+dataSize > len(v2DataBlock.Data) {
				log.Printf("Data block is too small to contain the variable part of CommonRecord")
				return
			}
			common_record.Data = make([]byte, dataSize)
			copy(common_record.Data[:], v2DataBlock.Data[tmpOffset:tmpOffset+dataSize])
			ConvertRecordV2(&common_record, v3DataBlock) // Populates v3DataBlock with V3 records
		case ExtensionMapType:
			InitCompat16()

			err := AddExtensionInfo(v2DataBlock.Data[offset:offset+int(recordSize)], extensionMapList)
			if err != nil {
				log.Println("Failed to parse extensions")
				continue
			}
		// Just copy over other types of records
		case ExporterInfoRecordType, ExporterStatRecordType, SamplerLegacyRecordType:
			copy(v3DataBlock.Data[v3DataBlock.Header.Size:offset+int(recordSize)], v2DataBlock.Data[offset:offset+int(recordSize)])
			v3DataBlock.Header.NumRecords++
			v3DataBlock.Header.Size += uint32(recordSize)
		}

		offset += int(recordSize)
	}

}

func IsAvailable(block *DataBlock, required uint32) bool {
	return (block.Header.Size + required) < BUFFSIZE
}

func InitCompat16() {
	if extensionMapList != nil {
		return
	}
	extensionMapList = InitExtensionMaps()
}

// GetCurrentCursor returns the current cursor based on the block's size
func GetCurrentCursor(block *DataBlock) unsafe.Pointer {
	// Start with the base pointer of the block
	basePtr := unsafe.Pointer(&block.Data[0])

	// Add the header size to the base pointer
	cursor := unsafe.Add(basePtr, uintptr(block.Header.Size))

	// Convert the cursor back to an unsafe.Pointer
	return cursor
}

func ConvertRecordV2(common_record *CommonRecord, v3DataBlock *DataBlock) error {
	// These constants are used in place of unsafe.Sizeof() for offsets
	const (
		v3RecordHeaderSize     = 12
		genericFlowSize        = 48
		EX_IO_SNMP_2_Size      = 4
		EX_IO_SNMP_4_Size      = 8
		EXVlanCommonRecordSize = 4  // CommonRecord VLAN ext size is 2 * 2(uint16)
		EXVlanV3RecordSize     = 8  // V3Record VLAN ext size is 2 * 4(uint32)
		EXMplsLblSize          = 40 // 10x mpls labels of uint32 = 40 bytes
		EXipReceivedV4Size     = 4
		EXipReceivedTimeSize   = 8
	)
	// Calculate the required size
	required := uint32(2 * common_record.Size)

	// Check if we our DataBlock size does not exceed pre-allocated BUFFERSIZE
	if !IsAvailable(v3DataBlock, required) {
		return fmt.Errorf("assertion failed: block size %d + required %d >= %d", v3DataBlock.Header.Size, required, BUFFSIZE)
	}
	mapId := uint32(common_record.ExtMap)
	if mapId >= 65536 {
		return fmt.Errorf("corrupt data file. Extension map id %d too big", common_record.ExtMap)
	}
	if extensionMapList == nil {
		log.Printf("extension map list with ID %d not found. Extensions not initialized for current block. Something is wrong", common_record.ExtMap)
		return fmt.Errorf("extension map list not found %d", common_record.ExtMap)
	}
	if _, exists := extensionMapList.Slots[common_record.ExtMap]; !exists {
		return fmt.Errorf("corrupt data file. Missing extension map %v. Skip record", common_record.ExtMap)
	}
	if common_record.Size > 2048 {
		return fmt.Errorf("corrupt data file. Record size %d. Skip record", common_record.Size)
	}

	extensionInfo := extensionMapList.Slots[common_record.ExtMap]
	extensionMap := extensionInfo.Map
	extensionCount := len(extensionMap.ExtensionIDs)

	// Pointer to the new v3record in V3 data block
	v3RecordPtr := GetCurrentCursor(v3DataBlock)

	// ptr points to the start of new record. Create the header
	recordHeader := (*recordHeaderV3)(v3RecordPtr)
	recordHeader.Type = V3Record
	recordHeader.Size = 12
	recordHeader.ExporterID = common_record.ExporterSysID
	recordHeader.NumElements = 0

	// move ptr to the end of record header, start of element data
	v3RecordPtr = unsafe.Add(v3RecordPtr, v3RecordHeaderSize)

	// Allocate element header and move ptr to the end of element header, start of element data
	v3RecordPtr = AddExtensionElement(recordHeader, v3RecordPtr, EXgenericFlowID, genericFlowSize)

	genericFlow := (*EXgenericFlow)(v3RecordPtr)
	genericFlow.MsecFirst = uint64(common_record.First)*1000 + uint64(common_record.MsecFirst)
	genericFlow.MsecLast = uint64(common_record.Last)*1000 + uint64(common_record.MsecLast)
	genericFlow.Proto = common_record.Prot
	genericFlow.TcpFlags = common_record.TcpFlags
	genericFlow.SrcPort = common_record.SrcPort
	genericFlow.DstPort = common_record.DstPort
	genericFlow.FwdStatus = common_record.FwdStatus
	genericFlow.SrcTos = common_record.Tos

	v3RecordPtr = unsafe.Add(v3RecordPtr, genericFlowSize)

	crOffset := 0

	if TestFlag(common_record.Flags, FlagIPv6Addr) {
		v3RecordPtr = AddExtensionElement(recordHeader, v3RecordPtr, EXipv6FlowID, 2*16)
		srcDstIP := (*[32]byte)(v3RecordPtr)
		copy(srcDstIP[:], common_record.Data[crOffset:crOffset+32])
		crOffset += 2 * 16 // 32 bytes
		v3RecordPtr = unsafe.Add(v3RecordPtr, crOffset)
	} else {
		v3RecordPtr = AddExtensionElement(recordHeader, v3RecordPtr, EXipv4FlowID, 2*4)
		srcDstIP := (*[8]byte)(v3RecordPtr)
		copy(srcDstIP[:], common_record.Data[crOffset:crOffset+8])
		crOffset += 2 * 4 // 8 bytes
		v3RecordPtr = unsafe.Add(v3RecordPtr, crOffset)
	}
	if TestFlag(common_record.Flags, FlagPkg64) {
		genericFlow.InPackets = uint64(binary.LittleEndian.Uint32(common_record.Data[crOffset : crOffset+8]))
		crOffset += 8
	} else {
		genericFlow.InPackets = uint64(binary.LittleEndian.Uint32(common_record.Data[crOffset : crOffset+4]))
		crOffset += 4
	}

	if TestFlag(common_record.Flags, FlagBytes64) {
		genericFlow.InBytes = binary.LittleEndian.Uint64(common_record.Data[crOffset : crOffset+8])
		crOffset += 8
	} else {
		genericFlow.InBytes = uint64(binary.LittleEndian.Uint32(common_record.Data[crOffset : crOffset+4]))
		crOffset += 4
	}

	i := 0

	for i < extensionCount {
		switch extensionMap.ExtensionIDs[uint16(i)] {
		case 0, 1, 2, 3:
			// 0 - 3 should never be in an extension table so - ignore it
			// No action needed
		case EX_IO_SNMP_2:
			// Placeholder
			crOffset += EX_IO_SNMP_2_Size
		case EX_IO_SNMP_4:
			// Placeholder
			crOffset += EX_IO_SNMP_4_Size
		case EX_VLAN:
			v3RecordPtr = AddExtensionElement(recordHeader, v3RecordPtr, EXvLanID, EXVlanV3RecordSize)
			srcDstVlan := (*[EXVlanV3RecordSize]byte)(v3RecordPtr)
			copy(srcDstVlan[:2], common_record.Data[crOffset:crOffset+2])
			copy(srcDstVlan[4:6], common_record.Data[crOffset+2:crOffset+4])
			crOffset += EXVlanCommonRecordSize
			v3RecordPtr = unsafe.Add(v3RecordPtr, EXVlanV3RecordSize)
		case EX_MPLS:
			v3RecordPtr = AddExtensionElement(recordHeader, v3RecordPtr, EXmplsLabelID, EXMplsLblSize)
			mplsLabels := (*[EXMplsLblSize]byte)(v3RecordPtr)
			copy(mplsLabels[:], common_record.Data[crOffset:crOffset+EXMplsLblSize])
			crOffset += EXMplsLblSize
			v3RecordPtr = unsafe.Add(v3RecordPtr, EXMplsLblSize)
		case EX_ROUTER_IP_v4:
			v3RecordPtr = AddExtensionElement(recordHeader, v3RecordPtr, EXipReceivedV4ID, EXipReceivedV4Size)
			routerIp := (*[EXipReceivedV4Size]byte)(v3RecordPtr)
			copy(routerIp[:], common_record.Data[crOffset:crOffset+4])
			crOffset += EXipReceivedV4Size
			v3RecordPtr = unsafe.Add(v3RecordPtr, EXipReceivedV4Size)
		case EX_RECEIVED:
			genericFlow.MsecReceived = binary.LittleEndian.Uint64(common_record.Data[crOffset : crOffset+EXipReceivedTimeSize])
			crOffset += EXipReceivedTimeSize
		// Partial implementation of few select extensions. Add the rest of extensions if needed
		default:
			fmt.Printf("Got unexpected extension: %d\n", extensionMap.ExtensionIDs[uint16(i)])
		}
		i++
	}

	v3DataBlock.Header.NumRecords++
	v3DataBlock.Header.Size += uint32(recordHeader.Size)
	return nil
}

func AddExtensionElement(recordHeader *recordHeaderV3, v3RecordPtr unsafe.Pointer, elementType uint16, elementSize uint16) unsafe.Pointer {
	const elementHeaderSize = 4
	recordElement := (*elementHeader)(v3RecordPtr)
	recordElement.Type = elementType
	recordElement.Size = elementHeaderSize + elementSize // Header + data
	recordHeader.Size += recordElement.Size
	recordHeader.NumElements++
	// advance the pointer to element data
	v3RecordPtr = unsafe.Add(v3RecordPtr, elementHeaderSize)
	return v3RecordPtr
}

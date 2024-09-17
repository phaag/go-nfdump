package nfdump

import (
	"encoding/binary"
	"fmt"
	"log"
)

func AddExtensionInfo(recordData []byte, extensionMapList *ExtensionMapList) error {
	// Process Extensions
	if len(recordData) < 8 {
		return fmt.Errorf("recordData too short, expected at least 8 bytes")
	}

	recordType := binary.LittleEndian.Uint16(recordData[0:2]) // type 2 = ext map
	recordSize := binary.LittleEndian.Uint16(recordData[2:4])
	extMapID := binary.LittleEndian.Uint16(recordData[4:6])
	extSize := binary.LittleEndian.Uint16(recordData[6:8])

	// Verify that the length of recordData matches the recordSize
	if len(recordData) != int(recordSize) {
		return fmt.Errorf("recordData length (%d) does not match recordSize (%d)", len(recordData), recordSize)
	}

	// Calculate the number of extension IDs
	fixedPart := 8
	uint16Size := 2
	numIDs := (len(recordData) - fixedPart) / uint16Size

	// Read the extension IDs
	extensionIDs := make([]uint16, numIDs)
	offset := fixedPart
	for i := 0; i < numIDs; i++ {
		extensionIDs[i] = binary.LittleEndian.Uint16(recordData[offset : offset+2])
		offset += 2
	}

	extMap := &ExtensionMap{
		Type:          recordType,
		Size:          recordSize,
		MapID:         extMapID,
		ExtensionSize: extSize,
		ExtensionIDs:  extensionIDs,
	}

	// Attempt to insert the decoded extension map into the list
	err := InsertExtensionMap(extensionMapList, extMap)
	if err != nil {
		log.Printf("Corrupt data file. Unable to insert extension map: %v", err)
		return fmt.Errorf("corrupt data file. Unable to insert extension map: %v", err)
	}

	return nil
}

func PrintExtensionMap(extMap *ExtensionMap) {
	if extMap == nil {
		fmt.Println("Received nil ExtensionMap")
		return
	}

	fmt.Println("Extension Map:")
	fmt.Printf("  Map ID   = %d\n", extMap.MapID)
	fmt.Printf("  Map Type = %d\n", extMap.Type)
	fmt.Printf("  Map Size = %d\n", extMap.Size)
	fmt.Printf("  Ext Size = %d\n", extMap.ExtensionSize)

	for _, id := range extMap.ExtensionIDs {
		if id == 0 { // Assuming 0 is used as a termination or not valid in this context
			break
		}
		// Assuming IDs are valid and within the range of ExtensionDescriptors
		if int(id) < len(ExtensionDescriptors) {
			descriptor := ExtensionDescriptors[id]
			fmt.Printf("  ID %3d, ext %3d = %s, size = %3d\n", descriptor.UserIndex, id, descriptor.Description, descriptor.Size)
		} else {
			fmt.Printf("  ID %3d not found in descriptors\n", id)
		}
	}
	fmt.Println()
}

var MaxNumExtensions uint16

func InitExtensionMaps() *ExtensionMapList {
	list := &ExtensionMapList{
		Slots: make(map[uint16]*ExtensionInfo),
	}

	// In our specific use case, we can hardcode MaxNumExtensions = 49
	MaxNumExtensions = 0
	for _, descriptor := range ExtensionDescriptors {
		if descriptor.ID != 0 {
			MaxNumExtensions++
		}
	}

	return list
}

func InsertExtensionMap(list *ExtensionMapList, extMap *ExtensionMap) error {
	if err := VerifyExtensionMap(extMap); err != nil {
		return fmt.Errorf("corrupt extension map: verification failed")
	}

	// fmt.Println("Debug: insert extension map")
	// PrintExtensionMap(extMap)
	if existingInfo, exists := list.Slots[extMap.MapID]; exists {
		// Check if same map already in slot
		if existingInfo.Map.Size == extMap.Size {
			if compareExtensionIDs(existingInfo.Map.ExtensionIDs, extMap.ExtensionIDs) {
				fmt.Println("Same map => nothing to do")
				return nil // Same map, nothing to do
			}
		}
	}

	// No existing map found, or existing map is different, create a new one
	newInfo := &ExtensionInfo{
		Map: extMap,
	}

	// Insert new extension into slot
	list.Slots[extMap.MapID] = newInfo
	if extMap.MapID > list.MaxUsed {
		list.MaxUsed = extMap.MapID
	}

	return nil
}

// VerifyExtensionMap checks the integrity and correctness of an extension map
func VerifyExtensionMap(extMap *ExtensionMap) error {
	if (extMap.Size & 0x3) != 0 {
		return fmt.Errorf("verify map id %d: WARNING: map size %d not aligned", extMap.MapID, extMap.Size)
	}

	var extensionSize uint16 = 0
	i := 0
	for i <= len(extMap.ExtensionIDs) {
		id := extMap.ExtensionIDs[i]
		if id == 0 {
			break
		}
		if id > MaxNumExtensions {
			return fmt.Errorf("verify map id %d: ERROR: element id %d out of range [%d]", extMap.MapID, id, len(ExtensionDescriptors))
		}
		extensionSize += ExtensionDescriptors[id].Size
		i++ // Increment i at the end of the loop
	}

	if i != len(extMap.ExtensionIDs) && (i+1) != len(extMap.ExtensionIDs) {
		return fmt.Errorf("verify map id %d: map has a zero element", extMap.MapID)
	}

	if extMap.ExtensionIDs[i] != 0 {
		return fmt.Errorf("verify map id %d: ERROR: no zero element at the end", extMap.MapID)
	}

	if uint16(extensionSize) != extMap.ExtensionSize {
		return fmt.Errorf("verify map id %d: ERROR: extension size: Expected %d, Map reports: %d", extMap.MapID, extensionSize, extMap.ExtensionSize)
	}

	return nil
}

func compareExtensionIDs(existingIDs, newIDs []uint16) bool {
	// Compare each ID in the slices up to the length of the shortest slice
	minLength := len(existingIDs)
	if len(newIDs) < minLength {
		minLength = len(newIDs)
	}

	for i := 0; i < minLength; i++ {
		if existingIDs[i] != newIDs[i] {
			// Found a discrepancy
			return false
		}
		if existingIDs[i] == 0 {
			// We reached the end of valid data
			return true
		}
	}

	// If we reach here, check if the next ID in either slice is zero,
	// indicating the end of the list if slices are not the same length.
	if minLength < len(existingIDs) && existingIDs[minLength] == 0 {
		return true
	}
	if minLength < len(newIDs) && newIDs[minLength] == 0 {
		return true
	}

	// If both are the same length and we did not find a difference
	return minLength == len(existingIDs) && minLength == len(newIDs)
}

type ExtensionDescriptor struct {
	ID          uint16
	Size        uint16
	UserIndex   uint32
	Enabled     uint32
	Description string
}

type ExtensionMap struct {
	Type          uint16   // type 2 is ExtensionMapType
	Size          uint16   // size of full map incl. header
	MapID         uint16   // identifies this map
	ExtensionSize uint16   // size of all extensions
	ExtensionIDs  []uint16 // extension id array
}

type ExtensionInfo struct {
	Map       *ExtensionMap
	ExportMap *ExtensionMap
	// RefCount  uint32
}

type ExtensionMapList struct {
	Slots   map[uint16]*ExtensionInfo // Map for fast lookup by mapID
	MaxUsed uint16                    // Track the highest mapID used
}

type EX_IO_SNMP_4_5 struct {
	input  uint32
	output uint32
}

type EXMPLS struct {
	SrcVlan uint32
	DstVlan uint32
}

// ICMPDetails splits out ICMP type and code from DstPort if needed.
type ICMPDetails struct {
	IcmpType uint8
	IcmpCode uint8
}

// Depending on the protocol, you might need to interpret the dstPort as ICMP type and code.
func (gf *EXgenericFlow) ICMPDetails() ICMPDetails {
	return ICMPDetails{
		IcmpType: uint8(gf.DstPort >> 8),
		IcmpCode: uint8(gf.DstPort & 0xFF),
	}
}

const (
	COMMON_BLOCK_ID     = 0
	EX_IPv4v6           = 1
	EX_PACKET_4_8       = 2
	EX_BYTE_4_8         = 3
	EX_IO_SNMP_2        = 4
	EX_IO_SNMP_4        = 5
	EX_AS_2             = 6
	EX_AS_4             = 7
	EX_MULIPLE          = 8
	EX_NEXT_HOP_v4      = 9
	EX_NEXT_HOP_v6      = 10
	EX_NEXT_HOP_BGP_v4  = 11
	EX_NEXT_HOP_BGP_v6  = 12
	EX_VLAN             = 13
	EX_OUT_PKG_4        = 14
	EX_OUT_PKG_8        = 15
	EX_OUT_BYTES_4      = 16
	EX_OUT_BYTES_8      = 17
	EX_AGGR_FLOWS_4     = 18
	EX_AGGR_FLOWS_8     = 19
	EX_MAC_1            = 20
	EX_MAC_2            = 21
	EX_MPLS             = 22
	EX_ROUTER_IP_v4     = 23
	EX_ROUTER_IP_v6     = 24
	EX_ROUTER_ID        = 25
	EX_BGPADJ           = 26
	EX_RECEIVED         = 27
	EX_RESERVED_1       = 28
	EX_RESERVED_2       = 29
	EX_RESERVED_3       = 30
	EX_RESERVED_4       = 31
	EX_RESERVED_5       = 32
	EX_RESERVED_6       = 33
	EX_RESERVED_7       = 34
	EX_RESERVED_8       = 35
	EX_RESERVED_9       = 36
	EX_NSEL_COMMON      = 37
	EX_NSEL_XLATE_PORTS = 38
	EX_NSEL_XLATE_IP_v4 = 39
	EX_NSEL_XLATE_IP_v6 = 40
	EX_NSEL_ACL         = 41
	EX_NSEL_USER        = 42
	EX_NSEL_USER_MAX    = 43
	EX_NSEL_RESERVED    = 44
	EX_LATENCY          = 45
	EX_NEL_COMMON       = 46
	EX_NEL_GLOBAL_IP_v4 = 47
	EX_PORT_BLOCK_ALLOC = 48
	EX_NEL_RESERVED_1   = 49
)

var ExtensionDescriptors = []ExtensionDescriptor{
	{ID: COMMON_BLOCK_ID, Size: 0, UserIndex: 0, Enabled: 1, Description: "Required extension: Common record"},
	{ID: EX_IPv4v6, Size: 0, UserIndex: 0, Enabled: 1, Description: "Required extension: IPv4/IPv6 src/dst address"},
	{ID: EX_PACKET_4_8, Size: 0, UserIndex: 0, Enabled: 1, Description: "Required extension: 4/8 byte input packets"},
	{ID: EX_BYTE_4_8, Size: 0, UserIndex: 0, Enabled: 1, Description: "Required extension: 4/8 byte input bytes"},
	{ID: EX_IO_SNMP_2, Size: 4, UserIndex: 1, Enabled: 1, Description: "2 byte input/output interface index"},
	{ID: EX_IO_SNMP_4, Size: 8, UserIndex: 1, Enabled: 1, Description: "4 byte input/output interface index"},
	{ID: EX_AS_2, Size: 4, UserIndex: 2, Enabled: 1, Description: "2 byte src/dst AS number"},
	{ID: EX_AS_4, Size: 8, UserIndex: 2, Enabled: 1, Description: "4 byte src/dst AS number"},
	{ID: EX_MULIPLE, Size: 4, UserIndex: 3, Enabled: 0, Description: "dst tos, direction, src/dst mask"},
	{ID: EX_NEXT_HOP_v4, Size: 4, UserIndex: 4, Enabled: 0, Description: "IPv4 next hop"},
	{ID: EX_NEXT_HOP_v6, Size: 16, UserIndex: 4, Enabled: 0, Description: "IPv6 next hop"},
	{ID: EX_NEXT_HOP_BGP_v4, Size: 4, UserIndex: 5, Enabled: 0, Description: "IPv4 BGP next IP"},
	{ID: EX_NEXT_HOP_BGP_v6, Size: 16, UserIndex: 5, Enabled: 0, Description: "IPv6 BGP next IP"},
	{ID: EX_VLAN, Size: 4, UserIndex: 6, Enabled: 0, Description: "src/dst vlan id"},
	{ID: EX_OUT_PKG_4, Size: 4, UserIndex: 7, Enabled: 0, Description: "4 byte output packets"},
	{ID: EX_OUT_PKG_8, Size: 8, UserIndex: 7, Enabled: 0, Description: "8 byte output packets"},
	{ID: EX_OUT_BYTES_4, Size: 4, UserIndex: 8, Enabled: 0, Description: "4 byte output bytes"},
	{ID: EX_OUT_BYTES_8, Size: 8, UserIndex: 8, Enabled: 0, Description: "8 byte output bytes"},
	{ID: EX_AGGR_FLOWS_4, Size: 4, UserIndex: 9, Enabled: 0, Description: "4 byte aggregated flows"},
	{ID: EX_AGGR_FLOWS_8, Size: 8, UserIndex: 9, Enabled: 0, Description: "8 byte aggregated flows"},
	{ID: EX_MAC_1, Size: 16, UserIndex: 10, Enabled: 0, Description: "in src/out dst mac address"},
	{ID: EX_MAC_2, Size: 16, UserIndex: 11, Enabled: 0, Description: "in dst/out src mac address"},
	{ID: EX_MPLS, Size: 40, UserIndex: 12, Enabled: 0, Description: "MPLS Labels"},
	{ID: EX_ROUTER_IP_v4, Size: 4, UserIndex: 13, Enabled: 0, Description: "IPv4 router IP addr"},
	{ID: EX_ROUTER_IP_v6, Size: 16, UserIndex: 13, Enabled: 0, Description: "IPv6 router IP addr"},
	{ID: EX_ROUTER_ID, Size: 4, UserIndex: 14, Enabled: 0, Description: "router ID"},
	{ID: EX_BGPADJ, Size: 8, UserIndex: 15, Enabled: 0, Description: "BGP adjacent prev/next AS"},
	{ID: EX_RECEIVED, Size: 8, UserIndex: 16, Enabled: 0, Description: "time packet received"},
	// reserved for more v9/IPFIX
	{ID: EX_RESERVED_1, Size: 0, UserIndex: 0, Enabled: 0, Description: ""},
	{ID: EX_RESERVED_2, Size: 0, UserIndex: 0, Enabled: 0, Description: ""},
	{ID: EX_RESERVED_3, Size: 0, UserIndex: 0, Enabled: 0, Description: ""},
	{ID: EX_RESERVED_4, Size: 0, UserIndex: 0, Enabled: 0, Description: ""},
	{ID: EX_RESERVED_5, Size: 0, UserIndex: 0, Enabled: 0, Description: ""},
	{ID: EX_RESERVED_6, Size: 0, UserIndex: 0, Enabled: 0, Description: ""},
	{ID: EX_RESERVED_7, Size: 0, UserIndex: 0, Enabled: 0, Description: ""},
	{ID: EX_RESERVED_8, Size: 0, UserIndex: 0, Enabled: 0, Description: ""},
	{ID: EX_RESERVED_9, Size: 0, UserIndex: 0, Enabled: 0, Description: ""},
	// ASA - Network Security Event Logging NSEL extensions
	{ID: EX_NSEL_COMMON, Size: 20, UserIndex: 26, Enabled: 0, Description: "NSEL Common block"},
	{ID: EX_NSEL_XLATE_PORTS, Size: 4, UserIndex: 27, Enabled: 0, Description: "NSEL xlate ports"},
	{ID: EX_NSEL_XLATE_IP_v4, Size: 8, UserIndex: 28, Enabled: 0, Description: "NSEL xlate IPv4 addr"},
	{ID: EX_NSEL_XLATE_IP_v6, Size: 32, UserIndex: 28, Enabled: 0, Description: "NSEL xlate IPv6 addr"},
	{ID: EX_NSEL_ACL, Size: 24, UserIndex: 29, Enabled: 0, Description: "NSEL ACL ingress/egress acl ID"},
	{ID: EX_NSEL_USER, Size: 24, UserIndex: 30, Enabled: 0, Description: "NSEL username"},
	{ID: EX_NSEL_USER_MAX, Size: 72, UserIndex: 30, Enabled: 0, Description: "NSEL max username"},
	{ID: EX_NSEL_RESERVED, Size: 0, UserIndex: 0, Enabled: 0, Description: ""},
	// latency extension for nfpcapd and nprobe
	{ID: EX_LATENCY, Size: 24, UserIndex: 64, Enabled: 0, Description: "nprobe/nfpcapd latency"},
	// NAT - Network Event Logging
	{ID: EX_NEL_COMMON, Size: 12, UserIndex: 31, Enabled: 0, Description: "NEL Common block"},
	{ID: EX_NEL_GLOBAL_IP_v4, Size: 0, UserIndex: 0, Enabled: 0, Description: "Compat NEL IPv4"},
	{ID: EX_PORT_BLOCK_ALLOC, Size: 8, UserIndex: 32, Enabled: 0, Description: "NAT Port Block Allocation"},
	{ID: EX_NEL_RESERVED_1, Size: 0, UserIndex: 0, Enabled: 0, Description: ""},
	{ID: 0, Size: 0, UserIndex: 0, Enabled: 0, Description: ""}, // Simulate end of list as in C
}

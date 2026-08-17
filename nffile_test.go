package nfdump

import (
	"context"
	"encoding/binary"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
	"unsafe"
)

func writeV2File(t *testing.T, header NfFileHeader, blocks ...[]byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "flows.nf")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if err := binary.Write(f, binary.LittleEndian, &header); err != nil {
		t.Fatal(err)
	}
	for _, block := range blocks {
		if _, err := f.Write(block); err != nil {
			t.Fatal(err)
		}
	}
	return path
}

func v2Header(compression uint8, numBlocks uint32) NfFileHeader {
	return NfFileHeader{
		Magic:       0xA50C,
		Version:     2,
		Compression: compression,
		BlockSize:   1024,
		NumBlocks:   numBlocks,
	}
}

func flowBlock(t *testing.T, flags uint16, records ...[]byte) []byte {
	t.Helper()
	payload := make([]byte, 0)
	for _, record := range records {
		payload = append(payload, record...)
	}
	header := DataBlockHeader{NumRecords: uint32(len(records)), Size: uint32(len(payload)), Type: 3, Flags: flags}
	block := make([]byte, binary.Size(header)+len(payload))
	writer := sliceWriter(block)
	if err := binary.Write(&writer, binary.LittleEndian, &header); err != nil {
		t.Fatal(err)
	}
	copy(block[binary.Size(header):], payload)
	return block
}

// sliceWriter lets binary.Write use a byte slice without an intermediate file.
type sliceWriter []byte

func (w *sliceWriter) Write(p []byte) (int, error) {
	copy(*w, p)
	*w = (*w)[len(p):]
	return len(p), nil
}

func v3Record(size uint16) []byte {
	record := make([]byte, size)
	if len(record) >= 2 {
		binary.LittleEndian.PutUint16(record[0:2], V3Record)
	}
	if len(record) >= 4 {
		binary.LittleEndian.PutUint16(record[2:4], size)
	}
	return record
}

type v3Element struct {
	id   uint16
	data []byte
}

func v3RecordWithElements(elements ...v3Element) []byte {
	size := 12
	for _, element := range elements {
		size += 4 + len(element.data)
	}
	record := make([]byte, size)
	binary.LittleEndian.PutUint16(record[0:2], V3Record)
	binary.LittleEndian.PutUint16(record[2:4], uint16(size))
	binary.LittleEndian.PutUint16(record[4:6], uint16(len(elements)))
	offset := 12
	for _, element := range elements {
		binary.LittleEndian.PutUint16(record[offset:offset+2], element.id)
		binary.LittleEndian.PutUint16(record[offset+2:offset+4], uint16(4+len(element.data)))
		copy(record[offset+4:], element.data)
		offset += 4 + len(element.data)
	}
	return record
}

type v4Element struct {
	id   uint
	data []byte
}

func align8(value int) int { return (value + 7) &^ 7 }

func v4RecordWithElements(t *testing.T, flags uint16, exporterID uint32, elements ...v4Element) []byte {
	t.Helper()
	bitmap := uint64(0)
	for _, element := range elements {
		bitmap |= uint64(1) << element.id
	}
	offset := align8(v4RecordHeaderSize + len(elements)*2)
	record := make([]byte, offset)
	binary.LittleEndian.PutUint16(record[0:2], v4RecordType)
	binary.LittleEndian.PutUint16(record[4:6], uint16(len(elements)))
	binary.LittleEndian.PutUint16(record[6:8], flags)
	binary.LittleEndian.PutUint32(record[8:12], exporterID)
	record[12] = 9
	record[13] = 3
	record[14] = 10
	binary.LittleEndian.PutUint64(record[16:24], bitmap)

	for rank, id := 0, uint(0); id < 64; id++ {
		if bitmap&(uint64(1)<<id) == 0 {
			continue
		}
		var data []byte
		for _, element := range elements {
			if element.id == id {
				data = element.data
				break
			}
		}
		if len(data) == 0 {
			t.Fatalf("missing V4 extension %d", id)
		}
		binary.LittleEndian.PutUint16(record[v4RecordHeaderSize+rank*2:], uint16(offset))
		record = append(record, data...)
		offset += len(data)
		padding := align8(offset) - offset
		record = append(record, make([]byte, padding)...)
		offset += padding
		rank++
	}
	binary.LittleEndian.PutUint16(record[2:4], uint16(len(record)))
	return record
}

func v18FlowBlock(record []byte) []byte {
	block := make([]byte, v18FlowBlockHead+len(record))
	binary.LittleEndian.PutUint32(block[0:4], v18BlockFlow)
	binary.LittleEndian.PutUint32(block[4:8], uint32(len(block)))
	binary.LittleEndian.PutUint32(block[8:12], uint32(len(block)))
	binary.LittleEndian.PutUint16(block[12:14], 1) // NOT_COMPRESSED
	binary.LittleEndian.PutUint32(block[24:28], 1)
	copy(block[v18FlowBlockHead:], record)
	binary.LittleEndian.PutUint64(block[16:24], xxHash64(block[v18BlockHeader:]))
	return block
}

func writeV3File(t *testing.T, block []byte) string {
	t.Helper()
	directoryOffset := uint64(v18HeaderSize + len(block))
	directory := make([]byte, v18DirectoryHead+v18DirectoryEnt)
	binary.LittleEndian.PutUint32(directory[0:4], v18DirectoryMagic)
	binary.LittleEndian.PutUint32(directory[4:8], 1)
	binary.LittleEndian.PutUint32(directory[8:12], v18BlockFlow)
	binary.LittleEndian.PutUint32(directory[12:16], uint32(len(block)))
	binary.LittleEndian.PutUint64(directory[16:24], v18HeaderSize)

	fileData := make([]byte, v18HeaderSize+len(block)+len(directory)+v18FooterSize)
	binary.LittleEndian.PutUint16(fileData[0:2], 0xA50C)
	binary.LittleEndian.PutUint16(fileData[2:4], 3)
	binary.LittleEndian.PutUint32(fileData[4:8], 0x10800)
	binary.LittleEndian.PutUint64(fileData[8:16], 123456789)
	binary.LittleEndian.PutUint16(fileData[18:20], 1) // NOT_COMPRESSED
	binary.LittleEndian.PutUint32(fileData[24:28], 1024)
	binary.LittleEndian.PutUint32(fileData[28:32], uint32(len(directory)))
	binary.LittleEndian.PutUint64(fileData[32:40], directoryOffset)
	copy(fileData[v18HeaderSize:], block)
	copy(fileData[directoryOffset:], directory)
	footerOffset := len(fileData) - v18FooterSize
	binary.LittleEndian.PutUint32(fileData[footerOffset:footerOffset+4], v18FooterMagic)
	binary.LittleEndian.PutUint32(fileData[footerOffset+4:footerOffset+8], uint32(len(directory)))
	binary.LittleEndian.PutUint64(fileData[footerOffset+8:footerOffset+16], directoryOffset)
	binary.LittleEndian.PutUint64(fileData[footerOffset+16:footerOffset+24], xxHash64(directory))

	path := filepath.Join(t.TempDir(), "flows-v3.nf")
	if err := os.WriteFile(path, fileData, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestAllRecordsHonorsUncompressedBlockFlag(t *testing.T) {
	path := writeV2File(t, v2Header(LZ4_COMPRESSED, 1), flowBlock(t, flagBlockUncompressed, v3Record(12)))
	nf := New()
	if err := nf.Open(path); err != nil {
		t.Fatal(err)
	}
	defer nf.Close()

	chain := nf.AllRecords()
	records, err := chain.Get()
	if err != nil {
		t.Fatal(err)
	}
	count := 0
	for range records {
		count++
	}
	if count != 1 {
		t.Fatalf("got %d records, want 1", count)
	}
	if err := chain.Err(); err != nil {
		t.Fatal(err)
	}
}

func TestWalkReadsRecordsAndAllowsClone(t *testing.T) {
	path := writeV2File(t, v2Header(NOT_COMPRESSED, 2),
		flowBlock(t, 0, v3Record(12)),
		flowBlock(t, 0, v3Record(12), v3Record(12)))
	nf := New()
	if err := nf.Open(path); err != nil {
		t.Fatal(err)
	}
	defer nf.Close()

	var records []FlowRecord
	err := nf.Walk(context.Background(), func(record FlowRecord) error {
		records = append(records, record.Clone())
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 3 {
		t.Fatalf("got %d records, want 3", len(records))
	}
}

func TestWalkFlowRecordAccessors(t *testing.T) {
	generic := make([]byte, 48)
	binary.LittleEndian.PutUint64(generic[0:8], 1000)
	binary.LittleEndian.PutUint64(generic[8:16], 2000)
	binary.LittleEndian.PutUint64(generic[16:24], 1500)
	binary.LittleEndian.PutUint64(generic[24:32], 42)
	binary.LittleEndian.PutUint64(generic[32:40], 4096)
	binary.LittleEndian.PutUint16(generic[40:42], 12345)
	binary.LittleEndian.PutUint16(generic[42:44], 443)
	generic[44] = 6
	generic[45] = 0x12

	record := v3RecordWithElements(
		v3Element{id: EXgenericFlowID, data: generic},
		v3Element{id: EXipv4FlowID, data: []byte{1, 2, 0, 192, 8, 8, 8, 8}},
	)
	record[6] = 9
	record[7] = 3
	binary.LittleEndian.PutUint16(record[8:10], 77)
	record[10] = byte(V3_FLAG_SAMPLED)
	record[11] = 10

	path := writeV2File(t, v2Header(NOT_COMPRESSED, 1), flowBlock(t, 0, record))
	nf := New()
	if err := nf.Open(path); err != nil {
		t.Fatal(err)
	}
	defer nf.Close()

	var retained FlowRecord
	err := nf.Walk(context.Background(), func(flow FlowRecord) error {
		if got := unsafe.Sizeof(flow); got > 32 {
			t.Fatalf("FlowRecord size %d, want at most 32", got)
		}
		if flow.Format() != RecordFormatV3 || !flow.IsIPv4() || flow.IsIPv6() {
			t.Fatalf("unexpected format or IP flags: %#v", flow)
		}
		if flow.ExporterID() != 77 || flow.Flags() != uint16(V3_FLAG_SAMPLED) || flow.NetFlowVersion() != 10 {
			t.Fatalf("unexpected header fields")
		}
		if engineType, engineID := flow.Engine(); engineType != 9 || engineID != 3 {
			t.Fatalf("got engine %d/%d, want 9/3", engineType, engineID)
		}
		if got, ok := flow.Generic(); !ok || got.InPackets != 42 || got.InBytes != 4096 || got.SrcPort != 12345 || got.DstPort != 443 || got.Proto != 6 {
			t.Fatalf("unexpected generic flow: %#v, ok=%t", got, ok)
		}
		src, dst, ok := flow.IP()
		if !ok || src != netip.MustParseAddr("192.0.2.1") || dst != netip.MustParseAddr("8.8.8.8") {
			t.Fatalf("unexpected IPs: %v, %v, ok=%t", src, dst, ok)
		}
		if got := flow.Extension(ExtensionGenericFlow); len(got) != len(generic) {
			t.Fatalf("got generic extension length %d, want %d", len(got), len(generic))
		}
		retained = flow.Clone()
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if got, ok := retained.Generic(); !ok || got.InPackets != 42 {
		t.Fatalf("cloned record is invalid: %#v, ok=%t", got, ok)
	}
}

func TestInfoIsContainerNeutral(t *testing.T) {
	header := v2Header(LZ4_COMPRESSED, 3)
	header.NfVersion = 0x10705
	header.Created = 123456789
	nf := New()
	if err := nf.Open(writeV2File(t, header)); err != nil {
		t.Fatal(err)
	}
	defer nf.Close()

	info := nf.Info()
	if info.Layout != FileLayoutV2 || info.NfdumpVersion != header.NfVersion ||
		info.Created != header.Created || info.Compression != LZ4_COMPRESSED ||
		info.BlockSize != header.BlockSize || info.FlowBlocks != header.NumBlocks || info.Encrypted {
		t.Fatalf("unexpected file info: %#v", info)
	}
}

func TestWalkReadsV3ContainerV4Records(t *testing.T) {
	generic := make([]byte, 48)
	binary.LittleEndian.PutUint64(generic[24:32], 42)
	binary.LittleEndian.PutUint64(generic[32:40], 4096)
	binary.LittleEndian.PutUint16(generic[40:42], 12345)
	binary.LittleEndian.PutUint16(generic[42:44], 443)
	generic[44] = 6
	record := v4RecordWithElements(t, 0x2, 77,
		v4Element{id: 1, data: generic},
		v4Element{id: 2, data: []byte{1, 2, 0, 192, 8, 8, 8, 8}},
		v4Element{id: 26, data: []byte{3, 0, 0, 0, 'a', 'b', 'c'}},
	)
	nf := New()
	if err := nf.Open(writeV3File(t, v18FlowBlock(record))); err != nil {
		t.Fatal(err)
	}
	defer nf.Close()

	if info := nf.Info(); info.Layout != FileLayoutV3 || info.Compression != CompressionNone || info.FlowBlocks != 1 {
		t.Fatalf("unexpected V3 info: %#v", info)
	}
	count := 0
	err := nf.Walk(context.Background(), func(flow FlowRecord) error {
		count++
		if flow.Format() != RecordFormatV4 || flow.ExporterID() != 77 || flow.Flags() != 0x2 || flow.NetFlowVersion() != 10 {
			t.Fatalf("unexpected V4 header fields")
		}
		if engineType, engineID := flow.Engine(); engineType != 9 || engineID != 3 {
			t.Fatalf("got engine %d/%d, want 9/3", engineType, engineID)
		}
		if generic, ok := flow.Generic(); !ok || generic.InPackets != 42 || generic.InBytes != 4096 || generic.SrcPort != 12345 {
			t.Fatalf("unexpected V4 generic extension: %#v, %t", generic, ok)
		}
		src, dst, ok := flow.IP()
		if !ok || src != netip.MustParseAddr("192.0.2.1") || dst != netip.MustParseAddr("8.8.8.8") {
			t.Fatalf("unexpected V4 addresses: %v %v %t", src, dst, ok)
		}
		if payload := flow.Extension(ExtensionInPayload); string(payload) != "abc" {
			t.Fatalf("got V4 input payload %q, want abc", payload)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("got %d records, want 1", count)
	}
}

func TestV4RecordRejectsInvalidExtensionOffset(t *testing.T) {
	record := v4RecordWithElements(t, 0, 1, v4Element{id: 1, data: make([]byte, 48)})
	binary.LittleEndian.PutUint16(record[v4RecordHeaderSize:], 24)
	if _, err := newFlowRecordV4(record); err == nil {
		t.Fatal("newFlowRecordV4 succeeded with extension in offset table")
	}
}

// TestWalkExternalV3 validates a real nfdump 1.8.x file when provided by the
// test environment. It is intentionally opt-in so the repository remains
// self-contained while release and local CI can exercise generated fixtures.
func TestWalkExternalV3(t *testing.T) {
	path := os.Getenv("NFDUMP_V3_FIXTURE")
	if path == "" {
		t.Skip("set NFDUMP_V3_FIXTURE to a real nfdump 1.8.x file")
	}
	nf := New()
	if err := nf.Open(path); err != nil {
		t.Fatal(err)
	}
	defer nf.Close()
	if nf.Info().Layout != FileLayoutV3 {
		t.Fatalf("got layout V%d, want V3", nf.Info().Layout)
	}
	count := 0
	if err := nf.Walk(context.Background(), func(FlowRecord) error {
		count++
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if count == 0 {
		t.Fatal("V3 fixture contains no flow records")
	}
}

func TestOpenRejectsTruncatedV3Container(t *testing.T) {
	path := filepath.Join(t.TempDir(), "flows-v3.nf")
	if err := os.WriteFile(path, []byte{0x0c, 0xa5, 0x03, 0x00}, 0o600); err != nil {
		t.Fatal(err)
	}
	nf := New()
	err := nf.Open(path)
	if err == nil || !strings.Contains(err.Error(), "V3 file too short") {
		t.Fatalf("got error %v, want truncated V3 container error", err)
	}
}

func TestWalkStopsOnCallbackError(t *testing.T) {
	path := writeV2File(t, v2Header(NOT_COMPRESSED, 5),
		flowBlock(t, 0, v3Record(12)),
		flowBlock(t, 0, v3Record(12)),
		flowBlock(t, 0, v3Record(12)),
		flowBlock(t, 0, v3Record(12)),
		flowBlock(t, 0, v3Record(12)))
	nf := New()
	if err := nf.Open(path); err != nil {
		t.Fatal(err)
	}
	defer nf.Close()

	want := errors.New("stop walking")
	done := make(chan error, 1)
	go func() {
		done <- nf.Walk(context.Background(), func(FlowRecord) error {
			return want
		})
	}()
	select {
	case err := <-done:
		if !errors.Is(err, want) {
			t.Fatalf("got error %v, want %v", err, want)
		}
	case <-time.After(time.Second):
		t.Fatal("Walk did not stop after callback error")
	}
}

func TestWalkHonorsCanceledContext(t *testing.T) {
	path := writeV2File(t, v2Header(NOT_COMPRESSED, 1), flowBlock(t, 0, v3Record(12)))
	nf := New()
	if err := nf.Open(path); err != nil {
		t.Fatal(err)
	}
	defer nf.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err := nf.Walk(ctx, func(FlowRecord) error {
		t.Fatal("callback called for canceled context")
		return nil
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("got error %v, want context cancellation", err)
	}
}

func TestAllRecordsReportsMalformedRecord(t *testing.T) {
	badRecord := make([]byte, 4)
	binary.LittleEndian.PutUint16(badRecord[0:2], V3Record)
	binary.LittleEndian.PutUint16(badRecord[2:4], 3)
	path := writeV2File(t, v2Header(NOT_COMPRESSED, 1), flowBlock(t, 0, badRecord))
	nf := New()
	if err := nf.Open(path); err != nil {
		t.Fatal(err)
	}
	defer nf.Close()

	chain := nf.AllRecords()
	records, _ := chain.Get()
	for range records {
		t.Fatal("unexpected record")
	}
	if err := chain.Err(); err == nil || !strings.Contains(err.Error(), "invalid size") {
		t.Fatalf("got error %v, want invalid-size error", err)
	}
}

func TestOrderByPropagatesReadError(t *testing.T) {
	badRecord := make([]byte, 4)
	binary.LittleEndian.PutUint16(badRecord[0:2], V3Record)
	binary.LittleEndian.PutUint16(badRecord[2:4], 3)
	path := writeV2File(t, v2Header(NOT_COMPRESSED, 1), flowBlock(t, 0, badRecord))
	nf := New()
	if err := nf.Open(path); err != nil {
		t.Fatal(err)
	}
	defer nf.Close()

	chain := nf.AllRecords().OrderBy("bytes", ASCENDING)
	records, err := chain.Get()
	if err != nil {
		t.Fatal(err)
	}
	for range records {
		t.Fatal("unexpected record")
	}
	if err := chain.Err(); err == nil || !strings.Contains(err.Error(), "invalid size") {
		t.Fatalf("got error %v, want invalid-size error", err)
	}
}

func TestReadDataBlocksReportsTruncatedBlockHeader(t *testing.T) {
	path := writeV2File(t, v2Header(NOT_COMPRESSED, 1))
	nf := New()
	if err := nf.Open(path); err != nil {
		t.Fatal(err)
	}
	defer nf.Close()

	blocks, err := nf.ReadDataBlocks()
	if err != nil {
		t.Fatal(err)
	}
	block, ok := <-blocks
	if !ok || block.Err == nil {
		t.Fatalf("got block %#v, want terminal error", block)
	}
}

func TestReadDataBlocksRejectsOversizedBlockBeforeAllocation(t *testing.T) {
	header := DataBlockHeader{Size: 1025, Type: 3}
	block := make([]byte, binary.Size(header))
	writer := sliceWriter(block)
	if err := binary.Write(&writer, binary.LittleEndian, &header); err != nil {
		t.Fatal(err)
	}

	path := writeV2File(t, v2Header(NOT_COMPRESSED, 1), block)
	nf := New()
	if err := nf.Open(path); err != nil {
		t.Fatal(err)
	}
	defer nf.Close()

	blocks, err := nf.ReadDataBlocks()
	if err != nil {
		t.Fatal(err)
	}
	dataBlock, ok := <-blocks
	if !ok || dataBlock.Err == nil || !strings.Contains(dataBlock.Err.Error(), "exceeds block size") {
		t.Fatalf("got block %#v, want oversized-block error", dataBlock)
	}
}

func TestNewRecordRejectsMalformedInput(t *testing.T) {
	for _, record := range [][]byte{
		nil,
		v3Record(4),
		append(v3Record(12), 0),
		{byte(V3Record), 0, 12, 0, 1, 0, 0, 0, 0, 0, 0, 0},
	} {
		if _, err := NewRecord(record); err == nil {
			t.Fatalf("NewRecord(%v) succeeded", record)
		}
	}
}

func TestOpenRejectsEncryptedV2File(t *testing.T) {
	header := v2Header(NOT_COMPRESSED, 0)
	header.Encryption = 1
	nf := New()
	if err := nf.Open(writeV2File(t, header)); err == nil {
		t.Fatal("Open succeeded for encrypted file")
	}
}

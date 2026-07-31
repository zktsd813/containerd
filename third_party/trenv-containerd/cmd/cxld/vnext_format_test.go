package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"hash/crc32"
	"math"
	"testing"
)

func TestVNextCRC32CastagnoliKnownAnswer(t *testing.T) {
	const expected uint32 = 0xe3069283
	if got := crc32.Checksum([]byte("123456789"), vnextCRCTable); got != expected {
		t.Fatalf("CRC-32C known answer = %#08x, want %#08x", got, expected)
	}
}

func TestVNextDeviceGeometryHasOneDescriptorPerContentPage(t *testing.T) {
	const (
		deviceBytes = uint64(2 << 30)
		slotBytes   = uint64(2 << 20)
	)
	geometry, err := calculateVNextDeviceGeometry(deviceBytes, slotBytes)
	if err != nil {
		t.Fatalf("calculate geometry: %v", err)
	}
	if geometry.SuperblockAOffset != 0 ||
		geometry.SuperblockBOffset != 4096 ||
		geometry.AllocatorSlotAOffset != 8192 ||
		geometry.AllocatorSlotBOffset != 8192+slotBytes {
		t.Fatalf("unexpected control offsets: %#v", geometry)
	}
	if geometry.DescriptorRegionBytes != geometry.DataPageCount*vnextPageDescriptorSize {
		t.Fatalf("descriptor capacity is not one-to-one: %#v", geometry)
	}
	if geometry.ContentRegionBytes != geometry.DataPageCount*vnextContentPageSize {
		t.Fatalf("content capacity is not one-to-one: %#v", geometry)
	}
	if geometry.ContentRegionBase%vnextContentPageSize != 0 {
		t.Fatalf("content base is not 4 KiB aligned: %d", geometry.ContentRegionBase)
	}
	descriptorEnd := geometry.DescriptorRegionBase + geometry.DescriptorRegionBytes
	if descriptorEnd > geometry.ContentRegionBase {
		t.Fatalf("descriptor and content regions overlap: %#v", geometry)
	}
	last := geometry.DataPageCount - 1
	lastDescriptor, err := geometry.descriptorOffset(last)
	if err != nil {
		t.Fatalf("last descriptor offset: %v", err)
	}
	lastContent, err := geometry.contentOffset(last)
	if err != nil {
		t.Fatalf("last content offset: %v", err)
	}
	if lastDescriptor+vnextPageDescriptorSize > geometry.ContentRegionBase {
		t.Fatalf("last descriptor exceeds descriptor region")
	}
	if lastContent+vnextContentPageSize > geometry.DeviceBytes {
		t.Fatalf("last content page exceeds device")
	}
	if _, err := geometry.descriptorOffset(geometry.DataPageCount); err == nil {
		t.Fatal("out-of-range descriptor index was accepted")
	}
	if _, err := geometry.contentOffset(geometry.DataPageCount); err == nil {
		t.Fatal("out-of-range content index was accepted")
	}
	for _, index := range []uint64{0, 1, geometry.DataPageCount / 2, last} {
		offset, err := geometry.contentOffset(index)
		if err != nil {
			t.Fatalf("content offset %d: %v", index, err)
		}
		got, err := geometry.dataPageIndex(offset)
		if err != nil {
			t.Fatalf("reverse mapping %d: %v", index, err)
		}
		if got != index {
			t.Fatalf("reverse mapping got %d, want %d", got, index)
		}
	}
	_, _, oneMoreEnd, ok := vnextGeometryEnd(
		geometry.ControlRegionBytes,
		geometry.DataPageCount+1)
	if ok && oneMoreEnd <= geometry.DeviceBytes {
		t.Fatalf("geometry did not choose maximal page capacity")
	}
}

func TestVNextDeviceGeometryRejectsInvalidAndOverflowingInputs(t *testing.T) {
	cases := []struct {
		name   string
		device uint64
		slot   uint64
	}{
		{name: "slot too small", device: 1 << 20, slot: 2048},
		{name: "slot unaligned", device: 1 << 20, slot: 4097},
		{name: "slot over format max", device: math.MaxUint64, slot: math.MaxUint64},
		{name: "device only control", device: 8192 + 2*4096, slot: 4096},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			if _, err := calculateVNextDeviceGeometry(test.device, test.slot); err == nil {
				t.Fatal("invalid geometry was accepted")
			}
		})
	}
	if _, ok := vnextAdd(math.MaxUint64, 1); ok {
		t.Fatal("addition overflow was not detected")
	}
	if _, ok := vnextMul(math.MaxUint64, 2); ok {
		t.Fatal("multiplication overflow was not detected")
	}
	if _, ok := vnextAlignUp(math.MaxUint64, 4096); ok {
		t.Fatal("alignment overflow was not detected")
	}
}

func TestVNextPublicationEnvelopeStrictlyRejectsV5AndCorruption(t *testing.T) {
	payload := []byte("root-set-vnext")
	encoded, err := marshalVNextPublicationEnvelope(payload)
	if err != nil {
		t.Fatalf("marshal VNext envelope: %v", err)
	}
	if !bytes.Equal(encoded[:8], []byte("TRPUB006")) {
		t.Fatalf("unexpected magic %q", encoded[:8])
	}
	decoded, err := parseVNextPublicationEnvelope(encoded)
	if err != nil {
		t.Fatalf("parse VNext envelope: %v", err)
	}
	if !bytes.Equal(decoded, payload) {
		t.Fatalf("payload changed: got %q want %q", decoded, payload)
	}

	legacy := append([]byte(nil), encoded...)
	copy(legacy[:8], []byte("TRPUB005"))
	if _, err := parseVNextPublicationEnvelope(legacy); !errors.Is(err, errVNextWrongFormat) {
		t.Fatalf("V5 magic returned %v, want wrong-format rejection", err)
	}
	wrongVersion := append([]byte(nil), encoded...)
	binary.LittleEndian.PutUint32(wrongVersion[8:12], 5)
	if _, err := parseVNextPublicationEnvelope(wrongVersion); !errors.Is(err, errVNextWrongFormat) {
		t.Fatalf("V5 version returned %v, want wrong-format rejection", err)
	}
	unknownMandatory := append([]byte(nil), encoded...)
	binary.LittleEndian.PutUint32(unknownMandatory[28:32], 1)
	if _, err := parseVNextPublicationEnvelope(unknownMandatory); !errors.Is(err, errVNextWrongFormat) {
		t.Fatalf("unknown flags returned %v, want wrong-format rejection", err)
	}
	corrupt := append([]byte(nil), encoded...)
	corrupt[len(corrupt)-1] ^= 0xff
	if _, err := parseVNextPublicationEnvelope(corrupt); !errors.Is(err, errVNextCorrupt) {
		t.Fatalf("payload corruption returned %v, want corrupt rejection", err)
	}
	withTrailingByte := append(append([]byte(nil), encoded...), 0)
	if _, err := parseVNextPublicationEnvelope(withTrailingByte); !errors.Is(err, errVNextCorrupt) {
		t.Fatalf("trailing byte returned %v, want corrupt rejection", err)
	}
	for length := 0; length < int(vnextFormatHeaderSize); length++ {
		if _, err := parseVNextPublicationEnvelope(encoded[:length]); !errors.Is(err, errVNextCorrupt) {
			t.Fatalf("truncation at %d returned %v", length, err)
		}
	}
}

func TestVNextSuperblockRoundTrip(t *testing.T) {
	geometry, err := calculateVNextDeviceGeometry(16<<20, 64<<10)
	if err != nil {
		t.Fatalf("calculate geometry: %v", err)
	}
	want := vnextDeviceSuperblock{
		DeviceUUID: "device-8d73",
		OwnerID:    "owner-2",
		OwnerEpoch: 19,
		Sequence:   7,
		Geometry:   geometry,
	}
	data, err := want.marshalBinary()
	if err != nil {
		t.Fatalf("marshal superblock: %v", err)
	}
	got, err := parseVNextDeviceSuperblock(data)
	if err != nil {
		t.Fatalf("parse superblock: %v", err)
	}
	if got != want {
		t.Fatalf("superblock changed:\n got: %#v\nwant: %#v", got, want)
	}
	crossType := append([]byte(nil), data...)
	copy(crossType[:8], vnextAllocatorMagic[:])
	if _, err := parseVNextDeviceSuperblock(crossType); !errors.Is(err, errVNextWrongFormat) {
		t.Fatalf("allocator magic returned %v, want wrong-format rejection", err)
	}
}

func TestVNextSuperblockRejectsOwnerEpochOutsideSignedSchedulerABI(t *testing.T) {
	geometry, err := calculateVNextDeviceGeometry(4<<20, 64<<10)
	if err != nil {
		t.Fatalf("calculate geometry: %v", err)
	}
	superblock := vnextDeviceSuperblock{
		DeviceUUID: "device",
		OwnerID:    "owner",
		OwnerEpoch: uint64(math.MaxInt64) + 1,
		Sequence:   1,
		Geometry:   geometry,
	}
	if _, err := superblock.marshalBinary(); !errors.Is(err, errVNextWrongFormat) {
		t.Fatalf("out-of-ABI owner epoch returned %v", err)
	}
}

func TestVNextPageDescriptorCanonicalFreeAndArtifactPadding(t *testing.T) {
	freeData, err := (vnextPageDescriptor{}).marshalBinary()
	if err != nil {
		t.Fatalf("marshal FREE descriptor: %v", err)
	}
	if len(freeData) != int(vnextPageDescriptorSize) || !vnextAllZero(freeData) {
		t.Fatalf("FREE descriptor is not exactly 64 zero bytes: %x", freeData)
	}
	free, err := parseVNextPageDescriptor(freeData)
	if err != nil {
		t.Fatalf("parse FREE descriptor: %v", err)
	}
	if free.State != vnextDescriptorFree {
		t.Fatalf("FREE descriptor parsed as state %d", free.State)
	}

	content := []byte("artifact tail")
	page, descriptor, err := buildVNextContentPage(
		vnextContentArtifact, content, 9, 11, 14)
	if err != nil {
		t.Fatalf("build artifact page: %v", err)
	}
	if descriptor.PayloadLength != uint32(len(content)) ||
		descriptor.ContentKind != vnextContentArtifact ||
		descriptor.ContentReferenceCount != 1 {
		t.Fatalf("unexpected artifact descriptor: %#v", descriptor)
	}
	if !bytes.Equal(page[:len(content)], content) || !vnextAllZero(page[len(content):]) {
		t.Fatal("artifact page was not zero-padded")
	}
	if descriptor.ContentCRC32 != crc32.Checksum(page[:], vnextCRCTable) {
		t.Fatal("artifact CRC was not calculated over all 4096 padded bytes")
	}
	raw, err := descriptor.marshalBinary()
	if err != nil {
		t.Fatalf("marshal descriptor: %v", err)
	}
	if len(raw) != int(vnextPageDescriptorSize) {
		t.Fatalf("descriptor encoded to %d bytes", len(raw))
	}
	roundTrip, err := parseVNextPageDescriptor(raw)
	if err != nil {
		t.Fatalf("parse descriptor: %v", err)
	}
	if roundTrip != descriptor {
		t.Fatalf("descriptor changed: got %#v want %#v", roundTrip, descriptor)
	}
	if err := roundTrip.validateContent(page[:]); err != nil {
		t.Fatalf("validate artifact page: %v", err)
	}
	page[0] ^= 0xff
	if err := roundTrip.validateContent(page[:]); !errors.Is(err, errVNextCorrupt) {
		t.Fatalf("content corruption returned %v", err)
	}

	if _, _, err := buildVNextContentPage(vnextContentMemory, content, 9, 11, 14); err == nil {
		t.Fatal("short process-memory page was accepted")
	}
	corruptDescriptor := append([]byte(nil), raw...)
	corruptDescriptor[16] ^= 0x80
	if _, err := parseVNextPageDescriptor(corruptDescriptor); !errors.Is(err, errVNextCorrupt) {
		t.Fatalf("descriptor corruption returned %v", err)
	}
	nonCanonicalFree := make([]byte, vnextPageDescriptorSize)
	binary.LittleEndian.PutUint64(nonCanonicalFree[8:16], 1)
	binary.LittleEndian.PutUint32(nonCanonicalFree[4:8], crc32.Checksum(nonCanonicalFree, vnextCRCTable))
	if _, err := parseVNextPageDescriptor(nonCanonicalFree); err == nil {
		t.Fatal("non-canonical FREE descriptor was accepted")
	}
}

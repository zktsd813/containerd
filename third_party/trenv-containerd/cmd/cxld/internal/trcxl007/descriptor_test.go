package trcxl007

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"hash/crc32"
	"reflect"
	"strings"
	"testing"

	"github.com/containerd/containerd/third_party/trenv-containerd/pkg/cxlcheckpoint"
)

func TestDescriptorKnownAnswerAndExactLayout(t *testing.T) {
	content := []byte("TRCXL007-known-page")
	descriptor := mustImmutableDescriptor(
		t,
		0x0102030405060708,
		0x1112131415161718,
		0x2122232425262728,
		0x3132333435363738,
		cxlcheckpoint.ContentRestoreBlobPayloadV7,
		content)
	wire := mustMarshalDescriptor(t, descriptor)

	const expectedHex = "9b2dfa1a990b98be0807060504030201181716151413121128272625242322213837363534333231130000000203000000000000000000000000000000000000"
	const expectedSHA256 = "89270f4359d65359fce7fa62101be0ae858e2cb48840f778a5ae0f01f9e17243"
	if got := hex.EncodeToString(wire); got != expectedHex {
		t.Fatalf("descriptor known-answer hex = %s", got)
	}
	wireSHA256 := sha256.Sum256(wire)
	if got := hex.EncodeToString(wireSHA256[:]); got != expectedSHA256 {
		t.Fatalf("descriptor known-answer SHA-256 = %s", got)
	}
	if len(wire) != 64 || PageDescriptorBytes != 64 || ContentPageBytes != 4096 {
		t.Fatalf("wire/page geometry = %d/%d/%d", len(wire), PageDescriptorBytes, ContentPageBytes)
	}
	if binary.LittleEndian.Uint32(wire[0:4]) != descriptor.PaddedPageCRC32C ||
		binary.LittleEndian.Uint32(wire[4:8]) != descriptorCRC32C(wire) ||
		binary.LittleEndian.Uint64(wire[8:16]) != descriptor.AllocationRecordID ||
		binary.LittleEndian.Uint64(wire[16:24]) != descriptor.OriginObjectID ||
		binary.LittleEndian.Uint64(wire[24:32]) != descriptor.ContentReferenceCount ||
		binary.LittleEndian.Uint64(wire[32:40]) != descriptor.OwnerTransactionSeq ||
		binary.LittleEndian.Uint32(wire[40:44]) != descriptor.PayloadLength ||
		wire[44] != byte(DescriptorImmutableSealed) ||
		wire[45] != byte(cxlcheckpoint.ContentRestoreBlobPayloadV7) ||
		binary.LittleEndian.Uint16(wire[46:48]) != 0 ||
		!allZero(wire[48:64]) {
		t.Fatalf("known answer does not obey the exact 0..63 descriptor layout: %x", wire)
	}
	checksumInput := append([]byte(nil), wire...)
	for index := 4; index < 8; index++ {
		checksumInput[index] = 0
	}
	if got := crc32.Checksum(checksumInput, crc32.MakeTable(crc32.Castagnoli)); got != binary.LittleEndian.Uint32(wire[4:8]) {
		t.Fatalf("descriptor CRC32C = %#08x, independent calculation = %#08x", wire[4:8], got)
	}
	parsed, err := ParseDescriptor(wire)
	if err != nil {
		t.Fatalf("ParseDescriptor: %v", err)
	}
	if parsed != descriptor {
		t.Fatalf("parsed descriptor = %#v, want %#v", parsed, descriptor)
	}
	if err := parsed.ValidateContentPage(content); err != nil {
		t.Fatalf("ValidateContentPage: %v", err)
	}
	if roundTrip := mustMarshalDescriptor(t, parsed); !bytes.Equal(roundTrip, wire) {
		t.Fatalf("canonical round trip changed bytes\n got %x\nwant %x", roundTrip, wire)
	}
}

func TestFreeDescriptorIsCanonicalAllZero(t *testing.T) {
	free := Descriptor{}
	if err := free.Validate(); err != nil {
		t.Fatalf("Validate FREE: %v", err)
	}
	wire := mustMarshalDescriptor(t, free)
	if len(wire) != PageDescriptorBytes || !allZero(wire) {
		t.Fatalf("FREE descriptor is not exactly %d zero bytes: %x", PageDescriptorBytes, wire)
	}
	parsed, err := ParseDescriptor(wire)
	if err != nil || parsed != free {
		t.Fatalf("ParseDescriptor(FREE) = %#v, %v", parsed, err)
	}

	noncanonical := []Descriptor{
		{PaddedPageCRC32C: 1},
		{AllocationRecordID: 1},
		{OriginObjectID: 1},
		{ContentReferenceCount: 1},
		{OwnerTransactionSeq: 1},
		{PayloadLength: 1},
		{ContentKind: cxlcheckpoint.ContentMemoryPayloadV7},
		{Flags: 1},
	}
	for index, candidate := range noncanonical {
		if err := candidate.Validate(); !errors.Is(err, ErrInvalidDescriptor) {
			t.Fatalf("noncanonical FREE case %d error = %v", index, err)
		}
	}
	raw := make([]byte, PageDescriptorBytes)
	binary.LittleEndian.PutUint64(raw[allocationRecordIDOffset:], 1)
	rewriteDescriptorCRC32C(raw)
	if _, err := ParseDescriptor(raw); !errors.Is(err, ErrInvalidDescriptor) {
		t.Fatalf("noncanonical FREE wire error = %v", err)
	}
	checksumOnly := make([]byte, PageDescriptorBytes)
	rewriteDescriptorCRC32C(checksumOnly)
	if _, err := ParseDescriptor(checksumOnly); !errors.Is(err, ErrInvalidDescriptor) {
		t.Fatalf("checksum-bearing FREE wire error = %v", err)
	}
}

func TestPaddedPageCRC32CKnownAnswers(t *testing.T) {
	fullPattern := bytes.Repeat([]byte{0xa5}, ContentPageBytes)
	tests := []struct {
		name    string
		content []byte
		want    uint32
	}{
		{name: "zero-page", content: nil, want: 0x98f94189},
		{name: "abc-tail", content: []byte("abc"), want: 0x8c1b7305},
		{name: "full-a5", content: fullPattern, want: 0x8ac933d3},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := paddedContentPageCRC32C(test.content)
			if err != nil {
				t.Fatalf("paddedContentPageCRC32C: %v", err)
			}
			if got != test.want {
				t.Fatalf("zero-padded CRC32C = %#08x, want %#08x", got, test.want)
			}
			independent := make([]byte, ContentPageBytes)
			copy(independent, test.content)
			if want := crc32.Checksum(independent, crc32.MakeTable(crc32.Castagnoli)); got != want {
				t.Fatalf("streamed CRC32C %#08x != independent page CRC32C %#08x", got, want)
			}
		})
	}
	if _, err := paddedContentPageCRC32C(make([]byte, ContentPageBytes+1)); !errors.Is(err, ErrInvalidContentPage) {
		t.Fatalf("oversized CRC error = %v", err)
	}
}

func TestParseRejectsLengthTornIntegrityReservedAndStructuralInput(t *testing.T) {
	descriptor := mustImmutableDescriptor(
		t, 1, 2, 3, 4, cxlcheckpoint.ContentArtifactPayloadV7, []byte("artifact"))
	wire := mustMarshalDescriptor(t, descriptor)

	for _, length := range []int{0, 1, PageDescriptorBytes - 1, PageDescriptorBytes + 1} {
		candidate := make([]byte, length)
		copy(candidate, wire)
		if _, err := ParseDescriptor(candidate); !errors.Is(err, ErrCorruptDescriptor) {
			t.Fatalf("length %d error = %v", length, err)
		}
	}
	for _, offset := range []int{0, 3, 4, 7, 8, 44, 63} {
		candidate := append([]byte(nil), wire...)
		candidate[offset] ^= 0x80
		if _, err := ParseDescriptor(candidate); !errors.Is(err, ErrCorruptDescriptor) {
			t.Fatalf("torn offset %d error = %v", offset, err)
		}
	}

	reserved := append([]byte(nil), wire...)
	reserved[48] = 1
	rewriteDescriptorCRC32C(reserved)
	if _, err := ParseDescriptor(reserved); !errors.Is(err, ErrCorruptDescriptor) {
		t.Fatalf("nonzero reserved error = %v", err)
	}
	flags := append([]byte(nil), wire...)
	binary.LittleEndian.PutUint16(flags[flagsOffset:], 1)
	rewriteDescriptorCRC32C(flags)
	if _, err := ParseDescriptor(flags); !errors.Is(err, ErrInvalidDescriptor) {
		t.Fatalf("nonzero flags error = %v", err)
	}
	unknownState := append([]byte(nil), wire...)
	unknownState[stateOffset] = byte(DescriptorZeroPadding + 1)
	rewriteDescriptorCRC32C(unknownState)
	if _, err := ParseDescriptor(unknownState); !errors.Is(err, ErrInvalidDescriptor) {
		t.Fatalf("unknown state error = %v", err)
	}
	unknownKind := append([]byte(nil), wire...)
	unknownKind[contentKindOffset] = 10
	rewriteDescriptorCRC32C(unknownKind)
	if _, err := ParseDescriptor(unknownKind); !errors.Is(err, ErrInvalidDescriptor) {
		t.Fatalf("unknown kind error = %v", err)
	}
}

func TestPersistedUnsignedValuesRejectSignedHighBitAndAcceptMaximum(t *testing.T) {
	base := mustImmutableDescriptor(
		t, 1, 2, 3, 4, cxlcheckpoint.ContentArtifactPayloadV7, []byte("signed-bound"))
	base.AllocationRecordID = cxlcheckpoint.MaxSignedLong
	base.OriginObjectID = cxlcheckpoint.MaxSignedLong
	base.ContentReferenceCount = cxlcheckpoint.MaxSignedLong
	base.OwnerTransactionSeq = cxlcheckpoint.MaxSignedLong
	wire := mustMarshalDescriptor(t, base)
	if parsed, err := ParseDescriptor(wire); err != nil || parsed != base {
		t.Fatalf("maximum signed descriptor = %#v, %v", parsed, err)
	}

	for _, offset := range []int{
		allocationRecordIDOffset,
		originObjectIDOffset,
		contentReferenceCountOffset,
		ownerTransactionSeqOffset,
	} {
		candidate := append([]byte(nil), wire...)
		binary.LittleEndian.PutUint64(candidate[offset:], cxlcheckpoint.MaxSignedLong+1)
		rewriteDescriptorCRC32C(candidate)
		if _, err := ParseDescriptor(candidate); !errors.Is(err, ErrInvalidDescriptor) {
			t.Fatalf("high-bit field at %d error = %v", offset, err)
		}
	}
}

func TestAllNineV7ContentKindsAndV6ShiftRegression(t *testing.T) {
	kinds := []cxlcheckpoint.ContentKindV7{
		cxlcheckpoint.ContentMemoryPayloadV7,
		cxlcheckpoint.ContentArtifactPayloadV7,
		cxlcheckpoint.ContentRestoreBlobPayloadV7,
		cxlcheckpoint.ContentMMTemplateMetadataV7,
		cxlcheckpoint.ContentVirtualPageMapMetadataV7,
		cxlcheckpoint.ContentArtifactManifestMetadataV7,
		cxlcheckpoint.ContentPlacementSlotAV7,
		cxlcheckpoint.ContentPlacementSlotBV7,
		cxlcheckpoint.ContentPublicationV7,
	}
	for index, kind := range kinds {
		want := uint8(index + 1)
		if uint8(kind) != want || !validContentKind(kind) {
			t.Fatalf("V7 kind[%d] = %d, want %d", index, kind, want)
		}
		assertDescriptorRoundTrip(t, reservedDescriptor(kind))
		var descriptor Descriptor
		if placementSlotKind(kind) {
			descriptor = mustEmptySlotDescriptor(t, kind)
		} else {
			content := []byte{byte(index + 1)}
			if kind == cxlcheckpoint.ContentMemoryPayloadV7 {
				content = bytes.Repeat([]byte{byte(index + 1)}, ContentPageBytes)
			}
			descriptor = mustImmutableDescriptor(t, 1, 2, 3, 4, kind, content)
		}
		wire := mustMarshalDescriptor(t, descriptor)
		if wire[contentKindOffset] != want {
			t.Fatalf("kind %d wire byte = %d, want %d", kind, wire[contentKindOffset], want)
		}
		if _, err := ParseDescriptor(wire); err != nil {
			t.Fatalf("kind %d ParseDescriptor: %v", kind, err)
		}
	}

	if uint8(cxlcheckpoint.ContentRestoreBlobPayloadV7) != 3 ||
		uint8(cxlcheckpoint.ContentMMTemplateMetadataV7) != 4 ||
		uint8(cxlcheckpoint.ContentVirtualPageMapMetadataV7) != 5 ||
		uint8(cxlcheckpoint.ContentArtifactManifestMetadataV7) != 6 ||
		uint8(cxlcheckpoint.ContentPlacementSlotAV7) != 7 ||
		uint8(cxlcheckpoint.ContentPlacementSlotBV7) != 8 ||
		uint8(cxlcheckpoint.ContentPublicationV7) != 9 {
		t.Fatal("V7 content-kind values regressed to a V6 ordering")
	}
	if uint8(cxlcheckpoint.ContentMMTemplate) != 3 || uint8(cxlcheckpoint.ContentRestoreBlob) != 5 ||
		uint8(cxlcheckpoint.ContentRestoreBlobPayloadV7) == uint8(cxlcheckpoint.ContentRestoreBlob) ||
		uint8(cxlcheckpoint.ContentMMTemplateMetadataV7) == uint8(cxlcheckpoint.ContentMMTemplate) {
		t.Fatal("test no longer proves that V7 kinds are independent of shifted V6 kinds")
	}
}

func TestDescriptorStateValuesAndCompiledContractAreStable(t *testing.T) {
	states := []DescriptorState{
		DescriptorFree,
		DescriptorReserved,
		DescriptorImmutableSealed,
		DescriptorEmptySlot,
		DescriptorPublishedSlot,
		DescriptorRetiring,
		DescriptorQuarantined,
		DescriptorZeroPadding,
	}
	for want, state := range states {
		if int(state) != want || !state.valid() {
			t.Fatalf("descriptor state[%d] = %d", want, state)
		}
	}
	if err := validateCompiledDescriptorContract(); err != nil {
		t.Fatalf("compiled descriptor contract: %v", err)
	}
	if _, err := ParseDescriptor(make([]byte, PageDescriptorBytes)); err != nil {
		t.Fatalf("ParseDescriptor canonical FREE under compiled contract: %v", err)
	}
}

func TestZeroPaddingKnownAnswerBuilderAndStateRules(t *testing.T) {
	descriptor, err := BuildZeroPaddingPageDescriptor(
		0x0102030405060708,
		0x1112131415161718,
		0x3132333435363738)
	if err != nil {
		t.Fatalf("BuildZeroPaddingPageDescriptor: %v", err)
	}
	wire := mustMarshalDescriptor(t, descriptor)
	digest := sha256.Sum256(wire)
	const expectedHex = "8941f9989e04031e0807060504030201181716151413121100000000000000003837363534333231000000000709000000000000000000000000000000000000"
	const expectedSHA256 = "4890ee0279aeb101a7e18bcbd5348c8336819029fe06f6c9e0ef9273115f5208"
	gotHex := hex.EncodeToString(wire)
	gotSHA256 := hex.EncodeToString(digest[:])
	if gotHex != expectedHex || gotSHA256 != expectedSHA256 {
		t.Fatalf("ZERO_PADDING known answer changed:\nhex=%s\nsha256=%s", gotHex, gotSHA256)
	}
	if descriptor.State != DescriptorZeroPadding ||
		descriptor.ContentKind != cxlcheckpoint.ContentPublicationV7 ||
		descriptor.PaddedPageCRC32C != zeroContentPageCRC32C ||
		descriptor.PayloadLength != 0 || descriptor.ContentReferenceCount != 0 ||
		wire[stateOffset] != 7 || wire[contentKindOffset] != 9 {
		t.Fatalf("ZERO_PADDING descriptor/wire = %#v/%x", descriptor, wire)
	}
	parsed, err := ParseDescriptor(wire)
	if err != nil || parsed != descriptor {
		t.Fatalf("ParseDescriptor(ZERO_PADDING) = %#v, %v", parsed, err)
	}
	if err := descriptor.ValidateContentPage(nil); err != nil {
		t.Fatalf("ZERO_PADDING nil meaningful content: %v", err)
	}
	if err := descriptor.ValidateContentPage([]byte{0}); !errors.Is(err, ErrInvalidContentPage) {
		t.Fatalf("ZERO_PADDING nonempty meaningful content error = %v", err)
	}

	mutations := []func(*Descriptor){
		func(value *Descriptor) { value.ContentKind = cxlcheckpoint.ContentPlacementSlotAV7 },
		func(value *Descriptor) { value.PaddedPageCRC32C ^= 1 },
		func(value *Descriptor) { value.PayloadLength = 1 },
		func(value *Descriptor) { value.ContentReferenceCount = 1 },
		func(value *Descriptor) { value.Flags = 1 },
	}
	for index, mutate := range mutations {
		candidate := descriptor
		mutate(&candidate)
		assertInvalidDescriptor(t, "ZERO_PADDING mutation "+string(rune('a'+index)), candidate)
	}
	for _, input := range []struct {
		allocation  uint64
		object      uint64
		transaction uint64
	}{
		{object: 2, transaction: 3},
		{allocation: 1, transaction: 3},
		{allocation: 1, object: 2},
	} {
		if _, err := BuildZeroPaddingPageDescriptor(
			input.allocation, input.object, input.transaction); !errors.Is(err, ErrInvalidDescriptor) {
			t.Fatalf("ZERO_PADDING zero identity %#v error = %v", input, err)
		}
	}
}

func TestReservedStateRules(t *testing.T) {
	valid := reservedDescriptor(cxlcheckpoint.ContentMemoryPayloadV7)
	assertDescriptorRoundTrip(t, valid)

	mutations := []func(*Descriptor){
		func(value *Descriptor) { value.AllocationRecordID = 0 },
		func(value *Descriptor) { value.OriginObjectID = 0 },
		func(value *Descriptor) { value.OwnerTransactionSeq = 0 },
		func(value *Descriptor) { value.ContentKind = 0 },
		func(value *Descriptor) { value.PaddedPageCRC32C = 1 },
		func(value *Descriptor) { value.ContentReferenceCount = 1 },
		func(value *Descriptor) { value.PayloadLength = 1 },
		func(value *Descriptor) { value.Flags = 1 },
	}
	for index, mutate := range mutations {
		candidate := valid
		mutate(&candidate)
		assertInvalidDescriptor(t, "RESERVED mutation "+string(rune('a'+index)), candidate)
	}
}

func TestImmutableSealedStateAndBuilderRules(t *testing.T) {
	memory := bytes.Repeat([]byte{0x5a}, ContentPageBytes)
	memoryDescriptor := mustImmutableDescriptor(
		t, 1, 2, 1, 3, cxlcheckpoint.ContentMemoryPayloadV7, memory)
	assertDescriptorRoundTrip(t, memoryDescriptor)
	if _, err := BuildImmutableContentPageDescriptor(
		1, 2, 1, 3, cxlcheckpoint.ContentMemoryPayloadV7, memory[:ContentPageBytes-1]); !errors.Is(err, ErrInvalidDescriptor) {
		t.Fatalf("short memory builder error = %v", err)
	}

	shortKinds := []cxlcheckpoint.ContentKindV7{
		cxlcheckpoint.ContentArtifactPayloadV7,
		cxlcheckpoint.ContentRestoreBlobPayloadV7,
		cxlcheckpoint.ContentMMTemplateMetadataV7,
		cxlcheckpoint.ContentVirtualPageMapMetadataV7,
		cxlcheckpoint.ContentArtifactManifestMetadataV7,
		cxlcheckpoint.ContentPublicationV7,
	}
	for _, kind := range shortKinds {
		descriptor := mustImmutableDescriptor(t, 1, 2, 1, 3, kind, []byte{byte(kind)})
		assertDescriptorRoundTrip(t, descriptor)
	}
	for _, kind := range []cxlcheckpoint.ContentKindV7{
		cxlcheckpoint.ContentPlacementSlotAV7,
		cxlcheckpoint.ContentPlacementSlotBV7,
	} {
		if _, err := BuildImmutableContentPageDescriptor(1, 2, 1, 3, kind, []byte("slot")); !errors.Is(err, ErrInvalidDescriptor) {
			t.Fatalf("immutable slot kind %d error = %v", kind, err)
		}
	}
	for _, content := range [][]byte{nil, make([]byte, ContentPageBytes+1)} {
		if _, err := BuildImmutableContentPageDescriptor(
			1, 2, 1, 3, cxlcheckpoint.ContentArtifactPayloadV7, content); !errors.Is(err, ErrInvalidDescriptor) {
			t.Fatalf("immutable length %d error = %v", len(content), err)
		}
	}
	zeroReference := memoryDescriptor
	zeroReference.ContentReferenceCount = 0
	assertInvalidDescriptor(t, "zero immutable reference", zeroReference)
}

func TestEmptySlotStateRules(t *testing.T) {
	for _, kind := range []cxlcheckpoint.ContentKindV7{
		cxlcheckpoint.ContentPlacementSlotAV7,
		cxlcheckpoint.ContentPlacementSlotBV7,
	} {
		descriptor := mustEmptySlotDescriptor(t, kind)
		assertDescriptorRoundTrip(t, descriptor)
		if err := descriptor.ValidateContentPage(nil); err != nil {
			t.Fatalf("EMPTY_SLOT kind %d content: %v", kind, err)
		}
		if err := descriptor.ValidateContentPage([]byte{0}); !errors.Is(err, ErrInvalidContentPage) {
			t.Fatalf("EMPTY_SLOT kind %d nonempty error = %v", kind, err)
		}
	}
	if _, err := BuildEmptySlotPageDescriptor(1, 2, 3, cxlcheckpoint.ContentPublicationV7); !errors.Is(err, ErrInvalidDescriptor) {
		t.Fatalf("non-slot EMPTY_SLOT error = %v", err)
	}
	valid := mustEmptySlotDescriptor(t, cxlcheckpoint.ContentPlacementSlotAV7)
	mutations := []func(*Descriptor){
		func(value *Descriptor) { value.PaddedPageCRC32C ^= 1 },
		func(value *Descriptor) { value.PayloadLength = 1 },
		func(value *Descriptor) { value.ContentReferenceCount = 1 },
	}
	for index, mutate := range mutations {
		candidate := valid
		mutate(&candidate)
		assertInvalidDescriptor(t, "EMPTY_SLOT mutation "+string(rune('a'+index)), candidate)
	}
}

func TestPublishedSlotStateAndBuilderRules(t *testing.T) {
	for _, kind := range []cxlcheckpoint.ContentKindV7{
		cxlcheckpoint.ContentPlacementSlotAV7,
		cxlcheckpoint.ContentPlacementSlotBV7,
	} {
		for _, content := range [][]byte{[]byte("map"), bytes.Repeat([]byte{0x7b}, ContentPageBytes)} {
			descriptor, err := BuildPublishedSlotPageDescriptor(1, 2, 3, 4, kind, content)
			if err != nil {
				t.Fatalf("BuildPublishedSlotPageDescriptor kind %d length %d: %v", kind, len(content), err)
			}
			assertDescriptorRoundTrip(t, descriptor)
			if err := descriptor.ValidateContentPage(content); err != nil {
				t.Fatalf("ValidateContentPage kind %d length %d: %v", kind, len(content), err)
			}
		}
	}
	for _, test := range []struct {
		name      string
		kind      cxlcheckpoint.ContentKindV7
		reference uint64
		content   []byte
	}{
		{name: "non-slot", kind: cxlcheckpoint.ContentPublicationV7, reference: 1, content: []byte("x")},
		{name: "zero-reference", kind: cxlcheckpoint.ContentPlacementSlotAV7, content: []byte("x")},
		{name: "empty", kind: cxlcheckpoint.ContentPlacementSlotAV7, reference: 1},
		{name: "oversized", kind: cxlcheckpoint.ContentPlacementSlotAV7, reference: 1, content: make([]byte, ContentPageBytes+1)},
	} {
		if _, err := BuildPublishedSlotPageDescriptor(1, 2, test.reference, 3, test.kind, test.content); !errors.Is(err, ErrInvalidDescriptor) {
			t.Fatalf("%s error = %v", test.name, err)
		}
	}
}

func TestRetiringAndQuarantinedRetainBoundedMetadata(t *testing.T) {
	states := []DescriptorState{DescriptorRetiring, DescriptorQuarantined}
	kinds := []cxlcheckpoint.ContentKindV7{
		cxlcheckpoint.ContentMemoryPayloadV7,
		cxlcheckpoint.ContentArtifactPayloadV7,
		cxlcheckpoint.ContentRestoreBlobPayloadV7,
		cxlcheckpoint.ContentMMTemplateMetadataV7,
		cxlcheckpoint.ContentVirtualPageMapMetadataV7,
		cxlcheckpoint.ContentArtifactManifestMetadataV7,
		cxlcheckpoint.ContentPlacementSlotAV7,
		cxlcheckpoint.ContentPlacementSlotBV7,
		cxlcheckpoint.ContentPublicationV7,
	}
	for _, state := range states {
		for _, kind := range kinds {
			minimal := Descriptor{
				AllocationRecordID:  1,
				OriginObjectID:      2,
				OwnerTransactionSeq: 3,
				State:               state,
				ContentKind:         kind,
			}
			assertDescriptorRoundTrip(t, minimal)
			bounded := minimal
			bounded.PaddedPageCRC32C = 0xffffffff
			bounded.ContentReferenceCount = cxlcheckpoint.MaxSignedLong
			bounded.PayloadLength = uint32(ContentPageBytes)
			assertDescriptorRoundTrip(t, bounded)
		}
		valid := Descriptor{
			AllocationRecordID:  1,
			OriginObjectID:      2,
			OwnerTransactionSeq: 3,
			State:               state,
			ContentKind:         cxlcheckpoint.ContentArtifactPayloadV7,
		}
		mutations := []func(*Descriptor){
			func(value *Descriptor) { value.AllocationRecordID = 0 },
			func(value *Descriptor) { value.OriginObjectID = 0 },
			func(value *Descriptor) { value.OwnerTransactionSeq = 0 },
			func(value *Descriptor) { value.ContentKind = 0 },
			func(value *Descriptor) { value.PayloadLength = uint32(ContentPageBytes + 1) },
			func(value *Descriptor) { value.ContentReferenceCount = cxlcheckpoint.MaxSignedLong + 1 },
		}
		for index, mutate := range mutations {
			candidate := valid
			mutate(&candidate)
			assertInvalidDescriptor(t, "retained mutation "+string(rune('a'+index)), candidate)
		}
	}
}

func TestValidateContentPageRejectsSubstitutionAndUnsealedStates(t *testing.T) {
	content := []byte("same-length-content")
	descriptor := mustImmutableDescriptor(
		t, 1, 2, 3, 4, cxlcheckpoint.ContentArtifactPayloadV7, content)
	if err := descriptor.ValidateContentPage(content); err != nil {
		t.Fatalf("exact content: %v", err)
	}
	substitution := append([]byte(nil), content...)
	substitution[len(substitution)-1] ^= 1
	for name, candidate := range map[string][]byte{
		"substitution": substitution,
		"short":        content[:len(content)-1],
		"long":         append(append([]byte(nil), content...), 0),
	} {
		if err := descriptor.ValidateContentPage(candidate); !errors.Is(err, ErrInvalidContentPage) {
			t.Fatalf("%s error = %v", name, err)
		}
	}
	wrongCRC := descriptor
	wrongCRC.PaddedPageCRC32C ^= 1
	if err := wrongCRC.ValidateContentPage(content); !errors.Is(err, ErrInvalidContentPage) {
		t.Fatalf("wrong CRC error = %v", err)
	}
	quarantined := descriptor
	quarantined.State = DescriptorQuarantined
	for _, candidate := range []Descriptor{Descriptor{}, reservedDescriptor(cxlcheckpoint.ContentArtifactPayloadV7)} {
		if err := candidate.ValidateContentPage(nil); !errors.Is(err, ErrInvalidContentPage) {
			t.Fatalf("unsealed state %d error = %v", candidate.State, err)
		}
	}
	if err := quarantined.ValidateContentPage(content); !errors.Is(err, ErrInvalidContentPage) {
		t.Fatalf("QUARANTINED matching content error = %v", err)
	}
	retiring := descriptor
	retiring.State = DescriptorRetiring
	if err := retiring.ValidateContentPage(content); err != nil {
		t.Fatalf("RETIRING retained content: %v", err)
	}
}

func TestDescriptorHasNoGenerationOrHiddenWireField(t *testing.T) {
	descriptorType := reflect.TypeOf(Descriptor{})
	wantFields := []string{
		"PaddedPageCRC32C",
		"AllocationRecordID",
		"OriginObjectID",
		"ContentReferenceCount",
		"OwnerTransactionSeq",
		"PayloadLength",
		"State",
		"ContentKind",
		"Flags",
	}
	if descriptorType.NumField() != len(wantFields) {
		t.Fatalf("Descriptor has %d fields, want exactly %d", descriptorType.NumField(), len(wantFields))
	}
	for index, want := range wantFields {
		field := descriptorType.Field(index)
		if field.Name != want || strings.Contains(strings.ToLower(field.Name), "generation") {
			t.Fatalf("Descriptor field[%d] = %q, want %q and no generation", index, field.Name, want)
		}
	}
	if _, exists := descriptorType.FieldByName("Generation"); exists {
		t.Fatal("Descriptor unexpectedly contains per-page Generation")
	}
	descriptor := mustImmutableDescriptor(
		t, 1, 2, 3, 4, cxlcheckpoint.ContentArtifactPayloadV7, []byte("layout"))
	wire := mustMarshalDescriptor(t, descriptor)
	if len(wire) != 64 || !allZero(wire[48:64]) {
		t.Fatalf("wire has a hidden tail field: %x", wire[48:64])
	}
}

func mustImmutableDescriptor(
	t *testing.T,
	allocationRecordID uint64,
	originObjectID uint64,
	contentReferenceCount uint64,
	ownerTransactionSeq uint64,
	kind cxlcheckpoint.ContentKindV7,
	content []byte,
) Descriptor {
	t.Helper()
	descriptor, err := BuildImmutableContentPageDescriptor(
		allocationRecordID,
		originObjectID,
		contentReferenceCount,
		ownerTransactionSeq,
		kind,
		content)
	if err != nil {
		t.Fatalf("BuildImmutableContentPageDescriptor: %v", err)
	}
	return descriptor
}

func mustEmptySlotDescriptor(t *testing.T, kind cxlcheckpoint.ContentKindV7) Descriptor {
	t.Helper()
	descriptor, err := BuildEmptySlotPageDescriptor(1, 2, 3, kind)
	if err != nil {
		t.Fatalf("BuildEmptySlotPageDescriptor: %v", err)
	}
	return descriptor
}

func reservedDescriptor(kind cxlcheckpoint.ContentKindV7) Descriptor {
	return Descriptor{
		AllocationRecordID:  1,
		OriginObjectID:      2,
		OwnerTransactionSeq: 3,
		State:               DescriptorReserved,
		ContentKind:         kind,
	}
}

func mustMarshalDescriptor(t *testing.T, descriptor Descriptor) []byte {
	t.Helper()
	wire, err := descriptor.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary: %v", err)
	}
	return wire
}

func assertDescriptorRoundTrip(t *testing.T, descriptor Descriptor) {
	t.Helper()
	wire := mustMarshalDescriptor(t, descriptor)
	parsed, err := ParseDescriptor(wire)
	if err != nil {
		t.Fatalf("ParseDescriptor(%#v): %v", descriptor, err)
	}
	if parsed != descriptor {
		t.Fatalf("ParseDescriptor = %#v, want %#v", parsed, descriptor)
	}
}

func assertInvalidDescriptor(t *testing.T, name string, descriptor Descriptor) {
	t.Helper()
	if err := descriptor.Validate(); !errors.Is(err, ErrInvalidDescriptor) {
		t.Fatalf("%s Validate error = %v", name, err)
	}
	if _, err := descriptor.MarshalBinary(); !errors.Is(err, ErrInvalidDescriptor) {
		t.Fatalf("%s MarshalBinary error = %v", name, err)
	}
}

func rewriteDescriptorCRC32C(wire []byte) {
	binary.LittleEndian.PutUint32(wire[descriptorCRC32COffset:], 0)
	binary.LittleEndian.PutUint32(
		wire[descriptorCRC32COffset:],
		crc32.Checksum(wire, crc32.MakeTable(crc32.Castagnoli)))
}

package trcxl007

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/containerd/containerd/third_party/trenv-containerd/pkg/cxlcheckpoint"
)

const (
	allocatorSnapshotKnownHeaderHex   = "5452414c433030370700000040000000616c6c6f636174696f6e2d6269746d61702d7631000000009f000000000000008516be3300000000e1d5a35200000000"
	allocatorSnapshotKnownEnvelopeHex = "5452414c433030370700000040000000616c6c6f636174696f6e2d6269746d61702d7631000000009f000000000000008516be3300000000e1d5a352000000000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf0b000000000000000c000000000000000d000000000000000e000000000000000f00000000000000f80000000000000006000000000000001f0000000000000083010000000000800000000000000000000000000000000000000000000080"
	allocatorSnapshotKnownSHA256      = "a144c14f7e5c15a7ef75931dc6956a8af21e72f2880570fcb7153f0a5377f0f9"
)

func TestAllocatorSnapshotKnownAnswerAndRoundTrip(t *testing.T) {
	geometry, snapshot, _, _ := allocatorSnapshotKnownFixture(t)
	wire, err := CanonicalAllocatorSnapshotBytes(snapshot, geometry)
	if err != nil {
		t.Fatalf("canonical bytes: %v", err)
	}
	if len(wire) != 223 {
		t.Fatalf("known envelope length = %d, expected 223", len(wire))
	}
	if got := hex.EncodeToString(wire[:AllocatorSnapshotEnvelopeHeaderBytes]); got != allocatorSnapshotKnownHeaderHex {
		t.Fatalf("known header hex = %s", got)
	}
	if got := hex.EncodeToString(wire); got != allocatorSnapshotKnownEnvelopeHex {
		t.Fatalf("known envelope hex = %s", got)
	}
	wireSHA256 := sha256.Sum256(wire)
	if got := hex.EncodeToString(wireSHA256[:]); got != allocatorSnapshotKnownSHA256 {
		t.Fatalf("known envelope SHA-256 = %s", got)
	}
	if string(wire[0:8]) != AllocatorSnapshotMagicString ||
		binary.LittleEndian.Uint32(wire[8:12]) != AllocatorSnapshotVersion ||
		binary.LittleEndian.Uint32(wire[12:16]) != uint32(AllocatorSnapshotEnvelopeHeaderBytes) {
		t.Fatalf("known header prefix = %x", wire[:16])
	}
	var wantDomain [allocatorSnapshotDomainFieldBytes]byte
	copy(wantDomain[:], AllocatorSnapshotDomain)
	if !bytes.Equal(wire[16:40], wantDomain[:]) {
		t.Fatalf("known domain field = %x", wire[16:40])
	}
	if binary.LittleEndian.Uint64(wire[40:48]) != 159 ||
		binary.LittleEndian.Uint32(wire[52:56]) != 0 ||
		!allocatorSnapshotAllZero(wire[60:64]) {
		t.Fatalf("known header length/flags/reserved = %x", wire[40:64])
	}
	if got, want := binary.LittleEndian.Uint32(wire[48:52]),
		allocatorSnapshotCRC32C(wire[64:]); got != want {
		t.Fatalf("known payload CRC = %#08x, expected %#08x", got, want)
	}
	if got, want := binary.LittleEndian.Uint32(wire[56:60]),
		allocatorSnapshotHeaderCRC32C(wire[:64]); got != want {
		t.Fatalf("known header CRC = %#08x, expected %#08x", got, want)
	}

	parsed, err := ParseAllocatorSnapshot(wire, geometry)
	if err != nil {
		t.Fatalf("parse known answer: %v", err)
	}
	if err := parsed.CrossCheck(
		geometry,
		snapshot.DeviceBindingSHA256,
		snapshot.OwnerIdentitySHA256,
		snapshot.OwnerEpoch); err != nil {
		t.Fatalf("cross-check known answer: %v", err)
	}
	allocatorSnapshotRequireEqual(t, parsed, snapshot)
	for _, index := range []uint64{0, 1, 7, 8, 63, 247} {
		unavailable, err := parsed.PageUnavailable(index)
		if err != nil || !unavailable {
			t.Fatalf("known allocated page %d = %v, %v", index, unavailable, err)
		}
	}
	if unavailable, err := parsed.PageUnavailable(2); err != nil || unavailable {
		t.Fatalf("known free page 2 = %v, %v", unavailable, err)
	}
	if _, err := parsed.PageUnavailable(parsed.DataPageCount); !errors.Is(err, ErrAllocatorSnapshotBounds) {
		t.Fatalf("out-of-bounds query error = %v", err)
	}
}

func TestAllocatorSnapshotEmptyAndTwoGiBFixture(t *testing.T) {
	geometry, err := CalculateDeviceGeometry(2<<30, 128<<10)
	if err != nil {
		t.Fatalf("2 GiB geometry: %v", err)
	}
	bitmapBytes, err := geometry.AllocationBitmapBytes()
	if err != nil {
		t.Fatalf("2 GiB bitmap length: %v", err)
	}
	if bitmapBytes != 64520 {
		t.Fatalf("2 GiB bitmap length = %d, expected 64520", bitmapBytes)
	}
	config := allocatorSnapshotTestConfig(geometry.DataPageCount)
	snapshot, err := NewAllocatorSnapshot(config, make([]byte, int(bitmapBytes)))
	if err != nil {
		t.Fatalf("empty snapshot: %v", err)
	}
	if snapshot.AllocatedPageCount != 0 {
		t.Fatalf("empty allocated count = %d", snapshot.AllocatedPageCount)
	}
	wire, err := CanonicalAllocatorSnapshotBytes(snapshot, geometry)
	if err != nil {
		t.Fatalf("encode 2 GiB snapshot: %v", err)
	}
	if len(wire) != int(AllocatorSnapshotFixedBytes+bitmapBytes) {
		t.Fatalf("2 GiB exact length = %d", len(wire))
	}
	parsed, err := ParseAllocatorSnapshot(wire, geometry)
	if err != nil {
		t.Fatalf("parse 2 GiB snapshot: %v", err)
	}
	allocatorSnapshotRequireEqual(t, parsed, snapshot)
}

func TestAllocatorSnapshotRejectsUnusedHighBitsAndPopcountMismatch(t *testing.T) {
	geometry, err := CalculateDeviceGeometry(2<<20, 4096)
	if err != nil {
		t.Fatalf("geometry: %v", err)
	}
	if geometry.DataPageCount != 500 || geometry.DataPageCount%8 != 4 {
		t.Fatalf("test geometry page count = %d", geometry.DataPageCount)
	}
	bitmapBytes, err := geometry.AllocationBitmapBytes()
	if err != nil {
		t.Fatalf("bitmap length: %v", err)
	}
	snapshot, err := NewAllocatorSnapshot(
		allocatorSnapshotTestConfig(geometry.DataPageCount),
		make([]byte, int(bitmapBytes)))
	if err != nil {
		t.Fatalf("new snapshot: %v", err)
	}
	wire, err := CanonicalAllocatorSnapshotBytes(snapshot, geometry)
	if err != nil {
		t.Fatalf("encode snapshot: %v", err)
	}

	highBits := append([]byte(nil), wire...)
	highBits[len(highBits)-1] |= 0x80
	allocatorSnapshotTestRechecksum(highBits)
	if _, err := ParseAllocatorSnapshot(highBits, geometry); !errors.Is(err, ErrCorruptAllocatorSnapshot) {
		t.Fatalf("unused high-bit error = %v", err)
	}

	wrongPopcount := append([]byte(nil), wire...)
	binary.LittleEndian.PutUint64(wrongPopcount[allocatorSnapshotAllocatedCountOffset:], 1)
	allocatorSnapshotTestRechecksum(wrongPopcount)
	if _, err := ParseAllocatorSnapshot(wrongPopcount, geometry); !errors.Is(err, ErrCorruptAllocatorSnapshot) {
		t.Fatalf("popcount mismatch error = %v", err)
	}
}

func TestAllocatorSnapshotCrossCheckRejectsSubstitution(t *testing.T) {
	geometry, snapshot, _, _ := allocatorSnapshotKnownFixture(t)
	if err := snapshot.CrossCheck(
		geometry,
		snapshot.DeviceBindingSHA256,
		snapshot.OwnerIdentitySHA256,
		snapshot.OwnerEpoch); err != nil {
		t.Fatalf("baseline cross-check: %v", err)
	}

	wrongDevice := snapshot.DeviceBindingSHA256
	wrongDevice[0] ^= 0xff
	if err := snapshot.CrossCheck(
		geometry,
		wrongDevice,
		snapshot.OwnerIdentitySHA256,
		snapshot.OwnerEpoch); !errors.Is(err, ErrAllocatorSnapshotMismatch) {
		t.Fatalf("device substitution error = %v", err)
	}
	wrongOwner := snapshot.OwnerIdentitySHA256
	wrongOwner[0] ^= 0xff
	if err := snapshot.CrossCheck(
		geometry,
		snapshot.DeviceBindingSHA256,
		wrongOwner,
		snapshot.OwnerEpoch); !errors.Is(err, ErrAllocatorSnapshotMismatch) {
		t.Fatalf("Owner substitution error = %v", err)
	}
	if err := snapshot.CrossCheck(
		geometry,
		snapshot.DeviceBindingSHA256,
		snapshot.OwnerIdentitySHA256,
		snapshot.OwnerEpoch+1); !errors.Is(err, ErrAllocatorSnapshotMismatch) {
		t.Fatalf("epoch substitution error = %v", err)
	}
	otherGeometry, err := CalculateDeviceGeometry(2<<20, 4096)
	if err != nil {
		t.Fatalf("other geometry: %v", err)
	}
	if err := snapshot.CrossCheck(
		otherGeometry,
		snapshot.DeviceBindingSHA256,
		snapshot.OwnerIdentitySHA256,
		snapshot.OwnerEpoch); !errors.Is(err, ErrAllocatorSnapshotMismatch) {
		t.Fatalf("geometry substitution error = %v", err)
	}
}

func TestAllocatorSnapshotEnvelopeCorruptionAndCompleteness(t *testing.T) {
	geometry, snapshot, _, _ := allocatorSnapshotKnownFixture(t)
	wire, err := CanonicalAllocatorSnapshotBytes(snapshot, geometry)
	if err != nil {
		t.Fatalf("encode snapshot: %v", err)
	}

	wrongMagic := append([]byte(nil), wire...)
	wrongMagic[0] ^= 0xff
	if _, err := ParseAllocatorSnapshot(wrongMagic, geometry); !errors.Is(err, ErrWrongAllocatorSnapshotFormat) {
		t.Fatalf("wrong magic error = %v", err)
	}
	wrongVersion := append([]byte(nil), wire...)
	binary.LittleEndian.PutUint32(wrongVersion[allocatorSnapshotVersionOffset:], 6)
	if _, err := ParseAllocatorSnapshot(wrongVersion, geometry); !errors.Is(err, ErrWrongAllocatorSnapshotFormat) {
		t.Fatalf("wrong version error = %v", err)
	}
	wrongHeaderSize := append([]byte(nil), wire...)
	binary.LittleEndian.PutUint32(wrongHeaderSize[allocatorSnapshotHeaderSizeOffset:], 63)
	if _, err := ParseAllocatorSnapshot(wrongHeaderSize, geometry); !errors.Is(err, ErrWrongAllocatorSnapshotFormat) {
		t.Fatalf("wrong header-size error = %v", err)
	}
	wrongDomain := append([]byte(nil), wire...)
	wrongDomain[allocatorSnapshotDomainOffset] ^= 1
	if _, err := ParseAllocatorSnapshot(wrongDomain, geometry); !errors.Is(err, ErrWrongAllocatorSnapshotFormat) {
		t.Fatalf("wrong domain error = %v", err)
	}
	wrongFlags := append([]byte(nil), wire...)
	binary.LittleEndian.PutUint32(wrongFlags[allocatorSnapshotFlagsOffset:], 1)
	allocatorSnapshotTestRechecksum(wrongFlags)
	if _, err := ParseAllocatorSnapshot(wrongFlags, geometry); !errors.Is(err, ErrWrongAllocatorSnapshotFormat) {
		t.Fatalf("unknown flags error = %v", err)
	}
	wrongReserved := append([]byte(nil), wire...)
	wrongReserved[allocatorSnapshotReservedOffset] = 1
	allocatorSnapshotTestRechecksum(wrongReserved)
	if _, err := ParseAllocatorSnapshot(wrongReserved, geometry); !errors.Is(err, ErrWrongAllocatorSnapshotFormat) {
		t.Fatalf("reserved-byte error = %v", err)
	}
	badHeaderCRC := append([]byte(nil), wire...)
	badHeaderCRC[allocatorSnapshotHeaderCRCOffset] ^= 1
	if _, err := ParseAllocatorSnapshot(badHeaderCRC, geometry); !errors.Is(err, ErrCorruptAllocatorSnapshot) {
		t.Fatalf("header corruption error = %v", err)
	}
	badPayloadCRC := append([]byte(nil), wire...)
	badPayloadCRC[allocatorSnapshotBitmapOffset] ^= 1
	if _, err := ParseAllocatorSnapshot(badPayloadCRC, geometry); !errors.Is(err, ErrCorruptAllocatorSnapshot) {
		t.Fatalf("payload corruption error = %v", err)
	}
	wrongBitmapLength := append([]byte(nil), wire...)
	binary.LittleEndian.PutUint64(
		wrongBitmapLength[allocatorSnapshotBitmapLengthOffset:],
		snapshot.BitmapByteLength+1)
	allocatorSnapshotTestRechecksum(wrongBitmapLength)
	if _, err := ParseAllocatorSnapshot(wrongBitmapLength, geometry); !errors.Is(err, ErrCorruptAllocatorSnapshot) {
		t.Fatalf("bitmap-length error = %v", err)
	}
	for _, test := range []struct {
		name   string
		offset int
	}{
		{"Owner epoch", allocatorSnapshotOwnerEpochOffset},
		{"snapshot sequence", allocatorSnapshotSequenceOffset},
		{"next allocation ID", allocatorSnapshotNextAllocationOffset},
		{"next transaction seq", allocatorSnapshotNextTransactionOffset},
		{"Owner journal sequence", allocatorSnapshotOwnerJournalOffset},
	} {
		t.Run(test.name+" signed overflow", func(t *testing.T) {
			overflow := append([]byte(nil), wire...)
			binary.LittleEndian.PutUint64(overflow[test.offset:], cxlcheckpoint.MaxSignedLong+1)
			allocatorSnapshotTestRechecksum(overflow)
			if _, err := ParseAllocatorSnapshot(overflow, geometry); !errors.Is(err, ErrCorruptAllocatorSnapshot) {
				t.Fatalf("signed-overflow error = %v", err)
			}
		})
	}

	trailing := append(append([]byte(nil), wire...), 0)
	if _, err := ParseAllocatorSnapshot(trailing, geometry); !errors.Is(err, ErrCorruptAllocatorSnapshot) {
		t.Fatalf("trailing-byte error = %v", err)
	}
	for _, length := range []int{0, 63, 64, len(wire) - 1} {
		if _, err := ParseAllocatorSnapshot(wire[:length], geometry); !errors.Is(err, ErrCorruptAllocatorSnapshot) {
			t.Fatalf("truncation at %d error = %v", length, err)
		}
	}
}

func TestAllocatorSnapshotSignedBoundsAndLogicalMutations(t *testing.T) {
	geometry, snapshot, config, bitmap := allocatorSnapshotKnownFixture(t)
	tests := []struct {
		name   string
		mutate func(*AllocatorSnapshotConfig)
	}{
		{"zero-device-digest", func(c *AllocatorSnapshotConfig) { c.DeviceBindingSHA256 = [sha256.Size]byte{} }},
		{"zero-owner-digest", func(c *AllocatorSnapshotConfig) { c.OwnerIdentitySHA256 = [sha256.Size]byte{} }},
		{"zero-owner-epoch", func(c *AllocatorSnapshotConfig) { c.OwnerEpoch = 0 }},
		{"large-owner-epoch", func(c *AllocatorSnapshotConfig) { c.OwnerEpoch = cxlcheckpoint.MaxSignedLong + 1 }},
		{"zero-snapshot-sequence", func(c *AllocatorSnapshotConfig) { c.SnapshotSequence = 0 }},
		{"large-snapshot-sequence", func(c *AllocatorSnapshotConfig) { c.SnapshotSequence = cxlcheckpoint.MaxSignedLong + 1 }},
		{"zero-next-allocation", func(c *AllocatorSnapshotConfig) { c.NextAllocationRecordID = 0 }},
		{"large-next-allocation", func(c *AllocatorSnapshotConfig) { c.NextAllocationRecordID = cxlcheckpoint.MaxSignedLong + 1 }},
		{"zero-next-transaction", func(c *AllocatorSnapshotConfig) { c.NextOwnerTransactionSeq = 0 }},
		{"large-next-transaction", func(c *AllocatorSnapshotConfig) { c.NextOwnerTransactionSeq = cxlcheckpoint.MaxSignedLong + 1 }},
		{"large-journal-sequence", func(c *AllocatorSnapshotConfig) { c.OwnerJournalSequence = cxlcheckpoint.MaxSignedLong + 1 }},
		{"zero-data-pages", func(c *AllocatorSnapshotConfig) { c.DataPageCount = 0 }},
		{"large-data-pages", func(c *AllocatorSnapshotConfig) { c.DataPageCount = cxlcheckpoint.MaxSignedLong + 1 }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			candidate := config
			test.mutate(&candidate)
			if _, err := NewAllocatorSnapshot(candidate, bitmap); !errors.Is(err, ErrInvalidAllocatorSnapshot) {
				t.Fatalf("invalid config error = %v", err)
			}
		})
	}

	maxConfig := config
	maxConfig.OwnerEpoch = cxlcheckpoint.MaxSignedLong
	maxConfig.SnapshotSequence = cxlcheckpoint.MaxSignedLong
	maxConfig.NextAllocationRecordID = cxlcheckpoint.MaxSignedLong
	maxConfig.NextOwnerTransactionSeq = cxlcheckpoint.MaxSignedLong
	maxConfig.OwnerJournalSequence = cxlcheckpoint.MaxSignedLong
	if _, err := NewAllocatorSnapshot(maxConfig, bitmap); err != nil {
		t.Fatalf("inclusive signed maximum rejected: %v", err)
	}
	zeroJournal := config
	zeroJournal.OwnerJournalSequence = 0
	if _, err := NewAllocatorSnapshot(zeroJournal, bitmap); err != nil {
		t.Fatalf("zero journal sequence rejected: %v", err)
	}

	badAllocated := snapshot.Clone()
	badAllocated.AllocatedPageCount = badAllocated.DataPageCount + 1
	if _, err := CanonicalAllocatorSnapshotBytes(badAllocated, geometry); !errors.Is(err, ErrInvalidAllocatorSnapshot) {
		t.Fatalf("allocated>data error = %v", err)
	}
	badPopcount := snapshot.Clone()
	badPopcount.AllocatedPageCount--
	if _, err := CanonicalAllocatorSnapshotBytes(badPopcount, geometry); !errors.Is(err, ErrInvalidAllocatorSnapshot) {
		t.Fatalf("logical popcount error = %v", err)
	}
	badLength := snapshot.Clone()
	badLength.BitmapByteLength++
	if _, err := CanonicalAllocatorSnapshotBytes(badLength, geometry); !errors.Is(err, ErrInvalidAllocatorSnapshot) {
		t.Fatalf("logical bitmap-length error = %v", err)
	}
}

func TestAllocatorSnapshotStoragePaddingBoundsAndDigest(t *testing.T) {
	geometry, snapshot, _, _ := allocatorSnapshotKnownFixture(t)
	storage, err := EncodeAllocatorSnapshotForStorage(snapshot, geometry)
	if err != nil {
		t.Fatalf("encode storage: %v", err)
	}
	exact := storage.ExactBytes()
	padded := storage.PaddedBytes()
	if storage.ExactLength() != uint64(len(exact)) || storage.SlotLength() != uint64(len(padded)) {
		t.Fatalf("storage lengths = %d/%d, slices = %d/%d",
			storage.ExactLength(), storage.SlotLength(), len(exact), len(padded))
	}
	if uint64(len(padded)) != geometry.AllocatorSnapshotSlotBytes {
		t.Fatalf("padded length = %d, expected %d", len(padded), geometry.AllocatorSnapshotSlotBytes)
	}
	if !bytes.Equal(padded[:len(exact)], exact) || !allocatorSnapshotAllZero(padded[len(exact):]) {
		t.Fatal("storage image is not exact bytes followed by all-zero padding")
	}
	if got, want := storage.SHA256(), sha256.Sum256(exact); got != want {
		t.Fatalf("storage SHA-256 = %x, expected %x", got, want)
	}

	exact[0] ^= 0xff
	if storage.ExactBytes()[0] == exact[0] {
		t.Fatal("ExactBytes exposes storage's mutable slice")
	}
	padded[0] ^= 0xff
	if storage.PaddedBytes()[0] == padded[0] {
		t.Fatal("PaddedBytes exposes storage's mutable slice")
	}

	oversized := make([]byte, geometry.AllocatorSnapshotSlotBytes+1)
	if _, err := ParseAllocatorSnapshot(oversized, geometry); !errors.Is(err, ErrCorruptAllocatorSnapshot) {
		t.Fatalf("oversized envelope error = %v", err)
	}
	tooSmall := geometry
	tooSmall.AllocatorSnapshotSlotBytes = AllocatorSnapshotFixedBytes - 1
	if _, err := CanonicalAllocatorSnapshotBytes(snapshot, tooSmall); err == nil {
		t.Fatal("too-small configured slot succeeded")
	}
	tooLarge := geometry
	tooLarge.AllocatorSnapshotSlotBytes = MaxAllocatorSnapshotSlotBytes + uint64(ContentPageBytes)
	if _, err := CanonicalAllocatorSnapshotBytes(snapshot, tooLarge); err == nil {
		t.Fatal("oversized configured slot succeeded")
	}
}

func TestAllocatorSnapshotCallerMutationDoesNotAlias(t *testing.T) {
	geometry, _, config, bitmap := allocatorSnapshotKnownFixture(t)
	snapshot, err := NewAllocatorSnapshot(config, bitmap)
	if err != nil {
		t.Fatalf("new snapshot: %v", err)
	}
	bitmap[0] ^= 0xff
	if snapshot.BitmapBytes()[0] == bitmap[0] {
		t.Fatal("constructor retained caller bitmap alias")
	}
	returned := snapshot.BitmapBytes()
	returned[0] ^= 0xff
	if snapshot.BitmapBytes()[0] == returned[0] {
		t.Fatal("BitmapBytes exposed internal bitmap alias")
	}
	clone := snapshot.Clone()
	snapshot.allocationBitmap[0] ^= 0xff
	if clone.BitmapBytes()[0] == snapshot.BitmapBytes()[0] {
		t.Fatal("Clone retained source bitmap alias")
	}

	wire, err := CanonicalAllocatorSnapshotBytes(clone, geometry)
	if err != nil {
		t.Fatalf("encode clone: %v", err)
	}
	parsed, err := ParseAllocatorSnapshot(wire, geometry)
	if err != nil {
		t.Fatalf("parse clone: %v", err)
	}
	before := parsed.BitmapBytes()
	wire[allocatorSnapshotBitmapOffset] ^= 0xff
	if !bytes.Equal(parsed.BitmapBytes(), before) {
		t.Fatal("parsed snapshot retained input envelope alias")
	}
}

func TestAllocatorSnapshotHasNoGenerationCheckpointRecordPathOrRuntimeState(t *testing.T) {
	wantSnapshotFields := []string{
		"DeviceBindingSHA256",
		"OwnerIdentitySHA256",
		"OwnerEpoch",
		"SnapshotSequence",
		"NextAllocationRecordID",
		"NextOwnerTransactionSeq",
		"OwnerJournalSequence",
		"DataPageCount",
		"AllocatedPageCount",
		"BitmapByteLength",
		"allocationBitmap",
	}
	allocatorSnapshotRequireExactFields(t, reflect.TypeOf(AllocatorSnapshot{}), wantSnapshotFields)
	wantConfigFields := wantSnapshotFields[:8]
	allocatorSnapshotRequireExactFields(t, reflect.TypeOf(AllocatorSnapshotConfig{}), wantConfigFields)
	for _, target := range []reflect.Type{
		reflect.TypeOf(AllocatorSnapshot{}),
		reflect.TypeOf(AllocatorSnapshotConfig{}),
		reflect.TypeOf(AllocatorSnapshotStorage{}),
	} {
		for index := 0; index < target.NumField(); index++ {
			name := strings.ToLower(target.Field(index).Name)
			for _, forbidden := range []string{
				"generation", "checkpointid", "checkpointrecords", "path", "route", "runtime", "slotselection",
			} {
				if strings.Contains(name, forbidden) {
					t.Fatalf("%s contains forbidden field %q", target.Name(), target.Field(index).Name)
				}
			}
		}
	}
	if _, err := (AllocatorSnapshot{}).PageUnavailable(0); !errors.Is(err, ErrAllocatorSnapshotBounds) {
		t.Fatalf("zero-value page query error = %v", err)
	}
}

func allocatorSnapshotKnownFixture(
	t *testing.T,
) (DeviceGeometry, AllocatorSnapshot, AllocatorSnapshotConfig, []byte) {
	t.Helper()
	geometry, err := CalculateDeviceGeometry(1<<20, 4096)
	if err != nil {
		t.Fatalf("known geometry: %v", err)
	}
	if geometry.DataPageCount != 248 {
		t.Fatalf("known page count = %d, expected 248", geometry.DataPageCount)
	}
	config := allocatorSnapshotTestConfig(geometry.DataPageCount)
	bitmapBytes, err := geometry.AllocationBitmapBytes()
	if err != nil {
		t.Fatalf("known bitmap length: %v", err)
	}
	bitmap := make([]byte, int(bitmapBytes))
	for _, page := range []uint64{0, 1, 7, 8, 63, 247} {
		allocatorSnapshotTestSetBit(bitmap, page)
	}
	snapshot, err := NewAllocatorSnapshot(config, bitmap)
	if err != nil {
		t.Fatalf("known snapshot: %v", err)
	}
	return geometry, snapshot, config, append([]byte(nil), bitmap...)
}

func allocatorSnapshotTestConfig(dataPageCount uint64) AllocatorSnapshotConfig {
	var deviceDigest [sha256.Size]byte
	var ownerDigest [sha256.Size]byte
	for index := 0; index < sha256.Size; index++ {
		deviceDigest[index] = byte(index + 1)
		ownerDigest[index] = byte(0xa0 + index)
	}
	return AllocatorSnapshotConfig{
		DeviceBindingSHA256:     deviceDigest,
		OwnerIdentitySHA256:     ownerDigest,
		OwnerEpoch:              11,
		SnapshotSequence:        12,
		NextAllocationRecordID:  13,
		NextOwnerTransactionSeq: 14,
		OwnerJournalSequence:    15,
		DataPageCount:           dataPageCount,
	}
}

func allocatorSnapshotTestSetBit(bitmap []byte, dataPageIndex uint64) {
	bitmap[dataPageIndex/8] |= byte(1) << uint(dataPageIndex%8)
}

func allocatorSnapshotTestRechecksum(wire []byte) {
	binary.LittleEndian.PutUint32(
		wire[allocatorSnapshotPayloadCRCOffset:],
		allocatorSnapshotCRC32C(wire[AllocatorSnapshotEnvelopeHeaderBytes:]))
	binary.LittleEndian.PutUint32(
		wire[allocatorSnapshotHeaderCRCOffset:],
		allocatorSnapshotHeaderCRC32C(wire[:AllocatorSnapshotEnvelopeHeaderBytes]))
}

func allocatorSnapshotRequireEqual(t *testing.T, got, want AllocatorSnapshot) {
	t.Helper()
	gotBitmap := got.BitmapBytes()
	wantBitmap := want.BitmapBytes()
	got.allocationBitmap = nil
	want.allocationBitmap = nil
	if !reflect.DeepEqual(got, want) || !bytes.Equal(gotBitmap, wantBitmap) {
		t.Fatalf("snapshot = %#v/%x, expected %#v/%x", got, gotBitmap, want, wantBitmap)
	}
}

func allocatorSnapshotRequireExactFields(t *testing.T, target reflect.Type, names []string) {
	t.Helper()
	if target.NumField() != len(names) {
		t.Fatalf("%s has %d fields, expected %d", target.Name(), target.NumField(), len(names))
	}
	for index, name := range names {
		if target.Field(index).Name != name {
			t.Fatalf("%s field[%d] = %q, expected %q",
				target.Name(), index, target.Field(index).Name, name)
		}
	}
}

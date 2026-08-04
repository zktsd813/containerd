package cxlcheckpoint

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"reflect"
	"runtime"
	"strings"
	"testing"
)

const maxStaticPublicationRootV7CrossCheckHeapBytes uint64 = 4 << 20

func TestV7StorageCompatibilityContract(t *testing.T) {
	const want = "publication=TRPUB007/v7/little-endian/immutable-publication-v1;" +
		"envelope-header=64;max-envelope=8388608;" +
		"page=4096;fingerprint=crc32c-castagnoli/0x11edc6f41;" +
		"descriptor=TRCXL007/64/trcxl007-page-descriptor-little-endian-v2;" +
		"owner-state=TROWN007/v3"
	if V7StorageCompatibilityID != want {
		t.Fatalf("V7 storage compatibility ID = %q", V7StorageCompatibilityID)
	}
	if got := len(V7StorageCompatibilityID); got != 243 || got > 256 {
		t.Fatalf("V7 storage compatibility ID length = %d, want 243 within 256-byte device/Owner bound", got)
	}
	if V7StorageDeviceFormatMagicString != "TRCXL007" ||
		V7StorageDeviceFormatVersion != 7 || V7StoragePageSize != 4096 ||
		V7StoragePageDescriptorBytes != 64 ||
		V7StoragePublicationByteOrder != "little-endian" ||
		V7StoragePublicationABI != PublicationV7Domain ||
		V7StoragePageDescriptorABI != "trcxl007-page-descriptor-little-endian-v2" ||
		V7StorageFingerprintAlgorithm != "crc32c-castagnoli" ||
		V7StorageFingerprintPolynomial != "0x11edc6f41" {
		t.Fatal("compiled V7 target storage constants changed")
	}
	if V7StorageFirstContentKind != ContentMemoryPayloadV7 ||
		V7StorageLastContentKind != ContentPublicationV7 ||
		V7StorageContentKindCount != 9 {
		t.Fatal("V7 target descriptor content-kind coverage changed")
	}
	for value := V7StorageFirstContentKind; value <= V7StorageLastContentKind; value++ {
		if !value.valid() {
			t.Fatalf("target content kind %d is not a valid V7 content kind", value)
		}
	}
}

func TestStaticPublicationRootV7BuildRoundTripAndCrossCheck(t *testing.T) {
	publication, storage, root := validStaticPublicationRootV7Fixture(t)
	if len(storage.PageRuns) != 2 ||
		storage.PageRuns[0].FirstPage.DeviceUUID != "device-b" ||
		storage.PageRuns[1].FirstPage.DeviceUUID != "device-a" {
		t.Fatalf("fixture does not cross devices: %#v", storage.PageRuns)
	}
	if got, want := root.Devices, []StaticPublicationRootV7Device{
		{DeviceUUID: "device-a", DataPageCount: 128},
		{DeviceUUID: "device-b", DataPageCount: 128},
	}; !reflect.DeepEqual(got, want) {
		t.Fatalf("compact devices = %#v, want %#v", got, want)
	}
	if root.Runs[0].DeviceIndex != 1 || root.Runs[1].DeviceIndex != 0 {
		t.Fatalf("compact run indexes = %#v", root.Runs)
	}
	expanded, err := root.ExpandedPageRuns()
	if err != nil {
		t.Fatalf("ExpandedPageRuns(): %v", err)
	}
	if !reflect.DeepEqual(expanded, storage.PageRuns) {
		t.Fatalf("expanded runs = %#v, want %#v", expanded, storage.PageRuns)
	}
	if err := root.CrossCheckPublication(storage.ExactBytes); err != nil {
		t.Fatalf("CrossCheckPublication(): %v", err)
	}

	first, err := CanonicalStaticPublicationRootV7Bytes(root)
	if err != nil {
		t.Fatalf("CanonicalStaticPublicationRootV7Bytes(first): %v", err)
	}
	second, err := CanonicalStaticPublicationRootV7Bytes(root)
	if err != nil {
		t.Fatalf("CanonicalStaticPublicationRootV7Bytes(second): %v", err)
	}
	if !bytes.Equal(first, second) {
		t.Fatal("TRPSR007 encoding is not deterministic")
	}
	if got := string(first[:8]); got != StaticPublicationRootV7MagicString {
		t.Fatalf("magic = %q", got)
	}
	if got := string(bytes.TrimRight(first[16:40], "\x00")); got != StaticPublicationRootV7Domain {
		t.Fatalf("domain = %q", got)
	}
	if binary.LittleEndian.Uint32(first[12:16]) != staticPublicationRootV7HeaderSize {
		t.Fatalf("header size = %d", binary.LittleEndian.Uint32(first[12:16]))
	}
	if uint64(len(first)) > MaxStaticPublicationRootV7Bytes {
		t.Fatalf("root envelope is %d bytes", len(first))
	}
	size, err := CanonicalStaticPublicationRootV7Size(root)
	if err != nil || size != uint64(len(first)) {
		t.Fatalf("CanonicalStaticPublicationRootV7Size() = %d, %v", size, err)
	}
	decoded, err := DecodeStaticPublicationRootV7(first)
	if err != nil {
		t.Fatalf("DecodeStaticPublicationRootV7(): %v", err)
	}
	if !reflect.DeepEqual(decoded, root) {
		t.Fatalf("round trip differs:\n got %#v\nwant %#v", decoded, root)
	}
	if decoded.CheckpointID != publication.CheckpointID {
		t.Fatalf("decoded checkpoint = %q", decoded.CheckpointID)
	}
}

func TestStaticPublicationRootV7BuildRejectsInconsistentStorage(t *testing.T) {
	publication, storage, _ := validStaticPublicationRootV7Fixture(t)
	tests := []struct {
		name   string
		mutate func(*PublicationStorageV7)
	}{
		{"object-id", func(value *PublicationStorageV7) { value.ContentObjectID++ }},
		{"logical-page-start", func(value *PublicationStorageV7) { value.LogicalPageStart++ }},
		{"capacity-pages", func(value *PublicationStorageV7) { value.CapacityPages-- }},
		{"exact-bytes", func(value *PublicationStorageV7) { value.ExactBytes[0] ^= 0x80 }},
		{"exact-length", func(value *PublicationStorageV7) {
			value.ExactBytes = value.ExactBytes[:len(value.ExactBytes)-1]
		}},
		{"padded-byte", func(value *PublicationStorageV7) {
			value.PaddedBytes[len(value.PaddedBytes)-1] = 1
		}},
		{"padded-length", func(value *PublicationStorageV7) {
			value.PaddedBytes = value.PaddedBytes[:len(value.PaddedBytes)-1]
		}},
		{"sha", func(value *PublicationStorageV7) { value.SHA256[0] ^= 0x80 }},
		{"exact-run", func(value *PublicationStorageV7) { value.PageRuns[0].PageCount++ }},
		{"padded-run", func(value *PublicationStorageV7) {
			value.PaddedWriteRuns[0].FirstPage.DataPageIndex++
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			candidate := clonePublicationStorageV7(storage)
			test.mutate(&candidate)
			if _, err := BuildStaticPublicationRootV7(publication, candidate); !errors.Is(err, ErrInvalidStaticPublicationRootV7) {
				t.Fatalf("BuildStaticPublicationRootV7() error = %v", err)
			}
		})
	}
}

func TestStaticPublicationRootV7CrossCheckRejectsSubstitution(t *testing.T) {
	_, storage, base := validStaticPublicationRootV7Fixture(t)
	tests := []struct {
		name   string
		mutate func(*StaticPublicationRootV7)
	}{
		{"checkpoint", func(value *StaticPublicationRootV7) { value.CheckpointID += "-other" }},
		{"compatibility", func(value *StaticPublicationRootV7) { value.StorageCompatibilityID += "-other" }},
		{"owner-state-v2", func(value *StaticPublicationRootV7) {
			value.StorageCompatibilityID = strings.Replace(
				value.StorageCompatibilityID,
				"owner-state=TROWN007/v3",
				"owner-state=TROWN007/v2",
				1)
		}},
		{"object", func(value *StaticPublicationRootV7) { value.PublicationObjectID++ }},
		{"Owner", func(value *StaticPublicationRootV7) { value.OwnerID += "-other" }},
		{"epoch", func(value *StaticPublicationRootV7) { value.OwnerEpoch++ }},
		{"allocation", func(value *StaticPublicationRootV7) { value.AllocationRecordID++ }},
		{"length", func(value *StaticPublicationRootV7) { value.PublicationLength++ }},
		{"sha", func(value *StaticPublicationRootV7) { value.PublicationSHA256[0] ^= 0x80 }},
		{"device-capacity", func(value *StaticPublicationRootV7) { value.Devices[0].DataPageCount++ }},
		{"locator", func(value *StaticPublicationRootV7) { value.Runs[0].DataPageIndex++ }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			candidate := cloneStaticPublicationRootV7(base)
			test.mutate(&candidate)
			if err := candidate.CrossCheckPublication(storage.ExactBytes); !errors.Is(err, ErrInvalidStaticPublicationRootV7) {
				t.Fatalf("CrossCheckPublication() error = %v", err)
			}
		})
	}
	corruptPublication := append([]byte(nil), storage.ExactBytes...)
	corruptPublication[len(corruptPublication)-1] ^= 1
	if err := base.CrossCheckPublication(corruptPublication); err == nil {
		t.Fatal("CrossCheckPublication accepted corrupt exact publication bytes")
	}
}

func TestStaticPublicationRootV7CrossCheckUsesExactSourceForLargeSlot(t *testing.T) {
	publication := clonePublicationV7Fixture(validPublicationV7Fixture(t)).publication
	publicationObjectIndex := len(publication.Objects) - 1
	oldCapacity := publication.Objects[publicationObjectIndex].CapacityPages
	publication.Objects[publicationObjectIndex].CapacityPages = MaxPublicationV7SlotPages
	delta := MaxPublicationV7SlotPages - oldCapacity
	publication.InitialAllocation.TotalPages += delta
	lastExtent := len(publication.InitialAllocation.Extents) - 1
	publication.InitialAllocation.Extents[lastExtent].PageCount += delta
	publication.InitialAllocation.Devices[1].DataPageCount =
		publication.InitialAllocation.Extents[lastExtent].StartDataPageIndex +
			publication.InitialAllocation.Extents[lastExtent].PageCount + 1
	if err := publication.Validate(); err != nil {
		t.Fatalf("large-slot PublicationV7.Validate(): %v", err)
	}
	canonical, err := CanonicalPublicationV7Bytes(publication)
	if err != nil {
		t.Fatalf("CanonicalPublicationV7Bytes(): %v", err)
	}
	if len(canonical) >= int(PublicationV7PageSize) {
		t.Fatalf("fixture exact publication is %d bytes, want less than one page", len(canonical))
	}
	source, err := deriveStaticPublicationRootV7ExactSource(publication, canonical)
	if err != nil {
		t.Fatalf("deriveStaticPublicationRootV7ExactSource(): %v", err)
	}
	if source.exactLength != uint64(len(canonical)) ||
		source.sha256 != sha256.Sum256(canonical) || len(source.pageRuns) != 1 ||
		source.pageRuns[0].PageCount != 1 {
		t.Fatalf("lightweight exact source = %#v", source)
	}
	for index := 0; index < reflect.TypeOf(source).NumField(); index++ {
		name := strings.ToLower(reflect.TypeOf(source).Field(index).Name)
		if strings.Contains(name, "padded") {
			t.Fatalf("restore-side exact source contains padded storage field %q", name)
		}
	}
	root, err := buildStaticPublicationRootV7Validated(publication, source)
	if err != nil {
		t.Fatalf("buildStaticPublicationRootV7Validated(): %v", err)
	}
	// The exact decode/re-encode path normally allocates far below 4 MiB. This
	// deliberately generous ceiling remains below the 8 MiB PaddedBytes buffer
	// that EncodePublicationV7ForStorage would allocate for this maximum slot.
	runtime.GC()
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	if err := root.CrossCheckPublication(canonical); err != nil {
		t.Fatalf("CrossCheckPublication() with maximum reserved slot: %v", err)
	}
	runtime.ReadMemStats(&after)
	allocated := after.TotalAlloc - before.TotalAlloc
	if allocated > maxStaticPublicationRootV7CrossCheckHeapBytes {
		t.Fatalf(
			"CrossCheckPublication allocated %d heap bytes, limit %d; restore must not materialize the 8 MiB publication slot padding",
			allocated, maxStaticPublicationRootV7CrossCheckHeapBytes)
	}
}

func TestStaticPublicationRootV7ValidationRejectsNoncanonicalValues(t *testing.T) {
	_, _, base := validStaticPublicationRootV7Fixture(t)
	tests := []struct {
		name   string
		mutate func(*StaticPublicationRootV7)
	}{
		{"state", func(value *StaticPublicationRootV7) { value.State = 0 }},
		{"checkpoint-empty", func(value *StaticPublicationRootV7) { value.CheckpointID = "" }},
		{"checkpoint-long", func(value *StaticPublicationRootV7) {
			value.CheckpointID = strings.Repeat("x", MaxStaticPublicationRootV7IdentityBytes+1)
		}},
		{"checkpoint-space", func(value *StaticPublicationRootV7) { value.CheckpointID = " x" }},
		{"checkpoint-control", func(value *StaticPublicationRootV7) { value.CheckpointID = "x\n" }},
		{"compatibility", func(value *StaticPublicationRootV7) { value.StorageCompatibilityID = "other" }},
		{"object-zero", func(value *StaticPublicationRootV7) { value.PublicationObjectID = 0 }},
		{"object-signed-overflow", func(value *StaticPublicationRootV7) {
			value.PublicationObjectID = MaxSignedLong + 1
		}},
		{"Owner-empty", func(value *StaticPublicationRootV7) { value.OwnerID = "" }},
		{"epoch-zero", func(value *StaticPublicationRootV7) { value.OwnerEpoch = 0 }},
		{"epoch-signed-overflow", func(value *StaticPublicationRootV7) { value.OwnerEpoch = MaxSignedLong + 1 }},
		{"allocation-zero", func(value *StaticPublicationRootV7) { value.AllocationRecordID = 0 }},
		{"allocation-signed-overflow", func(value *StaticPublicationRootV7) {
			value.AllocationRecordID = MaxSignedLong + 1
		}},
		{"publication-too-short", func(value *StaticPublicationRootV7) {
			value.PublicationLength = PublicationV7EnvelopeHeaderBytes
		}},
		{"publication-too-long", func(value *StaticPublicationRootV7) {
			value.PublicationLength = MaxPublicationV7Bytes + 1
		}},
		{"sha-zero", func(value *StaticPublicationRootV7) { value.PublicationSHA256 = [sha256.Size]byte{} }},
		{"devices-empty", func(value *StaticPublicationRootV7) { value.Devices = nil }},
		{"devices-too-many", func(value *StaticPublicationRootV7) {
			value.Devices = make([]StaticPublicationRootV7Device, MaxStaticPublicationRootV7Devices+1)
		}},
		{"device-order", func(value *StaticPublicationRootV7) {
			value.Devices[0], value.Devices[1] = value.Devices[1], value.Devices[0]
		}},
		{"device-duplicate", func(value *StaticPublicationRootV7) {
			value.Devices[1].DeviceUUID = value.Devices[0].DeviceUUID
		}},
		{"device-path", func(value *StaticPublicationRootV7) { value.Devices[0].DeviceUUID = "/dev/dax0.0" }},
		{"device-capacity-zero", func(value *StaticPublicationRootV7) { value.Devices[0].DataPageCount = 0 }},
		{"device-capacity-signed-overflow", func(value *StaticPublicationRootV7) {
			value.Devices[0].DataPageCount = MaxSignedLong + 1
		}},
		{"device-unused", func(value *StaticPublicationRootV7) {
			value.Devices = append(value.Devices,
				StaticPublicationRootV7Device{DeviceUUID: "device-z", DataPageCount: 1})
		}},
		{"runs-empty", func(value *StaticPublicationRootV7) { value.Runs = nil }},
		{"runs-too-many", func(value *StaticPublicationRootV7) {
			value.Runs = make([]StaticPublicationRootV7Run, MaxStaticPublicationRootV7Runs+1)
		}},
		{"run-gap", func(value *StaticPublicationRootV7) { value.Runs[0].ObjectPageStart = 1 }},
		{"run-object-page-signed-overflow", func(value *StaticPublicationRootV7) {
			value.Runs[0].ObjectPageStart = MaxSignedLong + 1
		}},
		{"run-device-index", func(value *StaticPublicationRootV7) { value.Runs[0].DeviceIndex = 2 }},
		{"run-data-page-signed-overflow", func(value *StaticPublicationRootV7) {
			value.Runs[0].DataPageIndex = MaxSignedLong + 1
		}},
		{"run-page-count-zero", func(value *StaticPublicationRootV7) { value.Runs[0].PageCount = 0 }},
		{"run-page-count-signed-overflow", func(value *StaticPublicationRootV7) {
			value.Runs[0].PageCount = MaxSignedLong + 1
		}},
		{"run-device-capacity", func(value *StaticPublicationRootV7) {
			value.Runs[0].DataPageIndex = value.Devices[value.Runs[0].DeviceIndex].DataPageCount
		}},
		{"run-coverage", func(value *StaticPublicationRootV7) { value.PublicationLength += PublicationV7PageSize }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			candidate := cloneStaticPublicationRootV7(base)
			test.mutate(&candidate)
			if err := candidate.Validate(); !errors.Is(err, ErrInvalidStaticPublicationRootV7) {
				t.Fatalf("Validate() error = %v", err)
			}
			if _, err := CanonicalStaticPublicationRootV7Bytes(candidate); !errors.Is(err, ErrInvalidStaticPublicationRootV7) {
				t.Fatalf("encoder error = %v", err)
			}
		})
	}

	coalescible := knownStaticPublicationRootV7()
	coalescible.Devices = coalescible.Devices[:1]
	coalescible.Runs = []StaticPublicationRootV7Run{
		{ObjectPageStart: 0, DeviceIndex: 0, DataPageIndex: 20, PageCount: 1},
		{ObjectPageStart: 1, DeviceIndex: 0, DataPageIndex: 21, PageCount: 1},
	}
	if err := coalescible.Validate(); !errors.Is(err, ErrInvalidStaticPublicationRootV7) ||
		!strings.Contains(err.Error(), "coalescible") {
		t.Fatalf("coalescible run error = %v", err)
	}

	overlap := knownStaticPublicationRootV7()
	overlap.PublicationLength = 3 * PublicationV7PageSize
	overlap.Runs = []StaticPublicationRootV7Run{
		{ObjectPageStart: 0, DeviceIndex: 0, DataPageIndex: 20, PageCount: 1},
		{ObjectPageStart: 1, DeviceIndex: 1, DataPageIndex: 30, PageCount: 1},
		{ObjectPageStart: 2, DeviceIndex: 0, DataPageIndex: 20, PageCount: 1},
	}
	if err := overlap.Validate(); !errors.Is(err, ErrInvalidStaticPublicationRootV7) ||
		!strings.Contains(err.Error(), "overlap physically") {
		t.Fatalf("physical overlap error = %v", err)
	}
}

func TestStaticPublicationRootV7DeviceOrderIsUnsignedUTF8(t *testing.T) {
	bmp := "device-\ue000"
	nonBMP := "device-\U00010000"
	if !staticPublicationRootV7DeviceUUIDLess(bmp, nonBMP) {
		t.Fatal("device order is not unsigned lexicographic UTF-8 byte order")
	}
	root := knownStaticPublicationRootV7()
	if root.Devices[0].DeviceUUID != bmp || root.Devices[1].DeviceUUID != nonBMP {
		t.Fatal("known root does not pin the UTF-8/UTF-16 ordering difference")
	}
	if err := root.Validate(); err != nil {
		t.Fatalf("UTF-8 ordered root: %v", err)
	}
	reversed := cloneStaticPublicationRootV7(root)
	reversed.Devices[0], reversed.Devices[1] = reversed.Devices[1], reversed.Devices[0]
	if err := reversed.Validate(); !errors.Is(err, ErrInvalidStaticPublicationRootV7) {
		t.Fatalf("reversed UTF-8 device table error = %v", err)
	}
}

func TestStaticPublicationRootV7DecoderFailsClosed(t *testing.T) {
	encoded, err := CanonicalStaticPublicationRootV7Bytes(knownStaticPublicationRootV7())
	if err != nil {
		t.Fatalf("encode fixture: %v", err)
	}
	tests := []struct {
		name string
		data func() []byte
		want error
	}{
		{"truncated", func() []byte { return append([]byte(nil), encoded[:63]...) }, ErrCorruptStaticPublicationRootV7},
		{"trailing-envelope", func() []byte { return append(append([]byte(nil), encoded...), 0) }, ErrCorruptStaticPublicationRootV7},
		{"magic", func() []byte { value := cloneBytes(encoded); value[0] ^= 1; return value }, ErrWrongStaticPublicationRootV7Format},
		{"version", func() []byte {
			value := cloneBytes(encoded)
			binary.LittleEndian.PutUint32(value[8:12], 8)
			return value
		}, ErrWrongStaticPublicationRootV7Format},
		{"header-size", func() []byte {
			value := cloneBytes(encoded)
			binary.LittleEndian.PutUint32(value[12:16], 63)
			return value
		}, ErrWrongStaticPublicationRootV7Format},
		{"domain", func() []byte { value := cloneBytes(encoded); value[16] ^= 1; return value }, ErrWrongStaticPublicationRootV7Format},
		{"flags", func() []byte { value := cloneBytes(encoded); value[52] = 1; return value }, ErrWrongStaticPublicationRootV7Format},
		{"reserved", func() []byte { value := cloneBytes(encoded); value[60] = 1; return value }, ErrWrongStaticPublicationRootV7Format},
		{"header-crc", func() []byte { value := cloneBytes(encoded); value[56] ^= 1; return value }, ErrCorruptStaticPublicationRootV7},
		{"payload-crc", func() []byte { value := cloneBytes(encoded); value[48] ^= 1; return value }, ErrCorruptStaticPublicationRootV7},
		{"declared-payload-too-large", func() []byte {
			value := cloneBytes(encoded)
			binary.LittleEndian.PutUint64(value[40:48], maxStaticPublicationRootV7PayloadBytes+1)
			refreshStaticPublicationRootV7HeaderCRC(value)
			return value
		}, ErrCorruptStaticPublicationRootV7},
		{"invalid-utf8", func() []byte {
			return mutateStaticPublicationRootV7Payload(encoded, func(payload []byte) { payload[5] = 0xff })
		}, ErrCorruptStaticPublicationRootV7},
		{"text-limit-before-allocation", func() []byte {
			return mutateStaticPublicationRootV7Payload(encoded, func(payload []byte) {
				binary.LittleEndian.PutUint32(payload[1:5], MaxStaticPublicationRootV7IdentityBytes+1)
			})
		}, ErrCorruptStaticPublicationRootV7},
		{"device-count-limit-before-allocation", func() []byte {
			return mutateStaticPublicationRootV7Payload(encoded, func(payload []byte) {
				deviceCount, _ := staticPublicationRootV7CollectionOffsets(payload)
				binary.LittleEndian.PutUint32(payload[deviceCount:deviceCount+4],
					MaxStaticPublicationRootV7Devices+1)
			})
		}, ErrCorruptStaticPublicationRootV7},
		{"device-count-fit-before-allocation", func() []byte {
			return mutateStaticPublicationRootV7Payload(encoded, func(payload []byte) {
				deviceCount, _ := staticPublicationRootV7CollectionOffsets(payload)
				binary.LittleEndian.PutUint32(payload[deviceCount:deviceCount+4],
					MaxStaticPublicationRootV7Devices)
			})
		}, ErrCorruptStaticPublicationRootV7},
		{"run-count-limit-before-allocation", func() []byte {
			return mutateStaticPublicationRootV7Payload(encoded, func(payload []byte) {
				_, runCount := staticPublicationRootV7CollectionOffsets(payload)
				binary.LittleEndian.PutUint32(payload[runCount:runCount+4],
					MaxStaticPublicationRootV7Runs+1)
			})
		}, ErrCorruptStaticPublicationRootV7},
		{"semantic-state", func() []byte {
			return mutateStaticPublicationRootV7Payload(encoded, func(payload []byte) { payload[0] = 2 })
		}, ErrInvalidStaticPublicationRootV7},
		{"payload-trailing", func() []byte {
			value := append(cloneBytes(encoded), 0)
			binary.LittleEndian.PutUint64(value[40:48], uint64(len(value))-StaticPublicationRootV7EnvelopeHeaderBytes)
			refreshStaticPublicationRootV7Checksums(value)
			return value
		}, ErrCorruptStaticPublicationRootV7},
		{"complete-envelope-limit", func() []byte {
			return make([]byte, MaxStaticPublicationRootV7Bytes+1)
		}, ErrCorruptStaticPublicationRootV7},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := DecodeStaticPublicationRootV7(test.data()); !errors.Is(err, test.want) {
				t.Fatalf("DecodeStaticPublicationRootV7() error = %v, want %v", err, test.want)
			}
		})
	}
}

func TestStaticPublicationRootV7WorstCaseBound(t *testing.T) {
	root := StaticPublicationRootV7{
		State:                  StaticPublicationRootV7Committed,
		CheckpointID:           strings.Repeat("c", MaxStaticPublicationRootV7IdentityBytes),
		StorageCompatibilityID: V7StorageCompatibilityID,
		PublicationObjectID:    1,
		OwnerID:                strings.Repeat("o", MaxStaticPublicationRootV7IdentityBytes),
		OwnerEpoch:             1,
		AllocationRecordID:     1,
		PublicationLength:      MaxStaticPublicationRootV7Runs * PublicationV7PageSize,
		PublicationSHA256:      sha256.Sum256([]byte("worst-case-static-root-v7")),
		Devices:                make([]StaticPublicationRootV7Device, MaxStaticPublicationRootV7Devices),
		Runs:                   make([]StaticPublicationRootV7Run, MaxStaticPublicationRootV7Runs),
	}
	for index := range root.Devices {
		prefix := "device-" + leftPadDecimal(index, 3) + "-"
		root.Devices[index] = StaticPublicationRootV7Device{
			DeviceUUID:    prefix + strings.Repeat("x", MaxStaticPublicationRootV7IdentityBytes-len(prefix)),
			DataPageCount: 1,
		}
		root.Runs[index] = StaticPublicationRootV7Run{
			ObjectPageStart: uint64(index),
			DeviceIndex:     uint32(index),
			DataPageIndex:   0,
			PageCount:       1,
		}
	}
	encoded, err := CanonicalStaticPublicationRootV7Bytes(root)
	if err != nil {
		t.Fatalf("encode worst case: %v", err)
	}
	if uint64(len(encoded)) > maxStaticPublicationRootV7WorstCaseBytes ||
		uint64(len(encoded)) > MaxStaticPublicationRootV7Bytes {
		t.Fatalf("worst case is %d bytes; proof %d, ceiling %d",
			len(encoded), maxStaticPublicationRootV7WorstCaseBytes,
			MaxStaticPublicationRootV7Bytes)
	}
	if _, err := DecodeStaticPublicationRootV7(encoded); err != nil {
		t.Fatalf("decode worst case: %v", err)
	}
}

func TestStaticPublicationRootV7KnownAnswer(t *testing.T) {
	const wantBase64 = "VFJQU1IwMDcHAAAAQAAAAHB1YmxpY2F0aW9uLWJvb3RzdHJhcC12McgBAAAAAAAAO5udVgAAAADjU1n9AAAAAAETAAAAY2hlY2twb2ludC1rbm93bi12N/MAAABwdWJsaWNhdGlvbj1UUlBVQjAwNy92Ny9saXR0bGUtZW5kaWFuL2ltbXV0YWJsZS1wdWJsaWNhdGlvbi12MTtlbnZlbG9wZS1oZWFkZXI9NjQ7bWF4LWVudmVsb3BlPTgzODg2MDg7cGFnZT00MDk2O2ZpbmdlcnByaW50PWNyYzMyYy1jYXN0YWdub2xpLzB4MTFlZGM2ZjQxO2Rlc2NyaXB0b3I9VFJDWEwwMDcvNjQvdHJjeGwwMDctcGFnZS1kZXNjcmlwdG9yLWxpdHRsZS1lbmRpYW4tdjI7b3duZXItc3RhdGU9VFJPV04wMDcvdjMJAAAAAAAAAAgAAABvd25lci3OsQsAAAAAAAAAHQAAAAAAAACIEwAAAAAAAETkM582rZ8PS/4pMW9pU5qynn+XkIooUtZ5NcAWiWYYAgAAAAoAAABkZXZpY2Ut7oCAZAAAAAAAAAALAAAAZGV2aWNlLfCQgIDIAAAAAAAAAAIAAAAAAAAAAAAAAAEAAAAeAAAAAAAAAAEAAAAAAAAAAQAAAAAAAAAAAAAAFAAAAAAAAAABAAAAAAAAAA=="
	const wantSHA256 = "2a9d4ef45757fb5b9a8cab0a9502bd993415cbd09ab899320735adfb1f0b148b"
	encoded, err := CanonicalStaticPublicationRootV7Bytes(knownStaticPublicationRootV7())
	if err != nil {
		t.Fatalf("encode known answer: %v", err)
	}
	gotBase64 := base64.StdEncoding.EncodeToString(encoded)
	gotDigest := sha256.Sum256(encoded)
	gotSHA256 := hex.EncodeToString(gotDigest[:])
	if gotBase64 != wantBase64 || gotSHA256 != wantSHA256 {
		t.Fatalf("known answer changed:\nbase64=%s\nsha256=%s", gotBase64, gotSHA256)
	}
}

func validStaticPublicationRootV7Fixture(
	t *testing.T,
) (PublicationV7, PublicationStorageV7, StaticPublicationRootV7) {
	t.Helper()
	publication := clonePublicationV7Fixture(validPublicationV7Fixture(t)).publication
	publication.ImmutableGraphID = strings.Repeat("g", 1400)
	publication.DedupDomainID = strings.Repeat("d", 1400)
	publication.SharingPolicyID = strings.Repeat("s", 1400)
	publication.InitialAllocation.Extents = append(
		[]AllocationExtentV7(nil), publication.InitialAllocation.Extents[:5]...)
	publication.InitialAllocation.Extents = append(
		publication.InitialAllocation.Extents,
		AllocationExtentV7{
			DeviceIndex: 1, StartDataPageIndex: 50,
			PageCount: 1, LogicalPageStart: 13,
		},
		AllocationExtentV7{
			DeviceIndex: 0, StartDataPageIndex: 60,
			PageCount: 3, LogicalPageStart: 14,
		},
	)
	if err := publication.Validate(); err != nil {
		t.Fatalf("multi-device PublicationV7.Validate(): %v", err)
	}
	storage, err := EncodePublicationV7ForStorage(publication)
	if err != nil {
		t.Fatalf("EncodePublicationV7ForStorage(): %v", err)
	}
	if len(storage.ExactBytes) <= int(PublicationV7PageSize) ||
		len(storage.ExactBytes) > 2*int(PublicationV7PageSize) {
		t.Fatalf("fixture publication size = %d, want two pages", len(storage.ExactBytes))
	}
	root, err := BuildStaticPublicationRootV7(publication, storage)
	if err != nil {
		t.Fatalf("BuildStaticPublicationRootV7(): %v", err)
	}
	return publication, storage, root
}

func knownStaticPublicationRootV7() StaticPublicationRootV7 {
	return StaticPublicationRootV7{
		State:                  StaticPublicationRootV7Committed,
		CheckpointID:           "checkpoint-known-v7",
		StorageCompatibilityID: V7StorageCompatibilityID,
		PublicationObjectID:    9,
		OwnerID:                "owner-\u03b1",
		OwnerEpoch:             11,
		AllocationRecordID:     29,
		PublicationLength:      5000,
		PublicationSHA256: sha256.Sum256(
			[]byte("TRPUB007-known-answer-exact-bytes")),
		Devices: []StaticPublicationRootV7Device{
			{DeviceUUID: "device-\ue000", DataPageCount: 100},
			{DeviceUUID: "device-\U00010000", DataPageCount: 200},
		},
		Runs: []StaticPublicationRootV7Run{
			{ObjectPageStart: 0, DeviceIndex: 1, DataPageIndex: 30, PageCount: 1},
			{ObjectPageStart: 1, DeviceIndex: 0, DataPageIndex: 20, PageCount: 1},
		},
	}
}

func clonePublicationStorageV7(source PublicationStorageV7) PublicationStorageV7 {
	clone := source
	clone.ExactBytes = cloneBytes(source.ExactBytes)
	clone.PaddedBytes = cloneBytes(source.PaddedBytes)
	clone.PageRuns = append([]AllocationPageRunV7(nil), source.PageRuns...)
	clone.PaddedWriteRuns = append([]AllocationPageRunV7(nil), source.PaddedWriteRuns...)
	return clone
}

func cloneStaticPublicationRootV7(source StaticPublicationRootV7) StaticPublicationRootV7 {
	clone := source
	clone.Devices = append([]StaticPublicationRootV7Device(nil), source.Devices...)
	clone.Runs = append([]StaticPublicationRootV7Run(nil), source.Runs...)
	return clone
}

func cloneBytes(source []byte) []byte {
	return append([]byte(nil), source...)
}

func mutateStaticPublicationRootV7Payload(
	encoded []byte,
	mutate func([]byte),
) []byte {
	value := cloneBytes(encoded)
	mutate(value[StaticPublicationRootV7EnvelopeHeaderBytes:])
	refreshStaticPublicationRootV7Checksums(value)
	return value
}

func refreshStaticPublicationRootV7Checksums(value []byte) {
	binary.LittleEndian.PutUint32(
		value[48:52], checksumCRC32C(value[StaticPublicationRootV7EnvelopeHeaderBytes:]))
	refreshStaticPublicationRootV7HeaderCRC(value)
}

func refreshStaticPublicationRootV7HeaderCRC(value []byte) {
	binary.LittleEndian.PutUint32(
		value[56:60], staticPublicationRootV7HeaderCRC(value[:staticPublicationRootV7HeaderSize]))
}

func staticPublicationRootV7CollectionOffsets(payload []byte) (int, int) {
	offset := 1
	skipText := func() {
		length := int(binary.LittleEndian.Uint32(payload[offset : offset+4]))
		offset += 4 + length
	}
	skipText() // checkpoint
	skipText() // compatibility
	offset += 8
	skipText() // Owner
	offset += 8 + 8 + 8 + sha256.Size
	deviceCountOffset := offset
	deviceCount := int(binary.LittleEndian.Uint32(payload[offset : offset+4]))
	offset += 4
	for index := 0; index < deviceCount; index++ {
		skipText()
		offset += 8
	}
	return deviceCountOffset, offset
}

func leftPadDecimal(value, width int) string {
	digits := []byte{'0' + byte(value/100%10), '0' + byte(value/10%10), '0' + byte(value%10)}
	return string(digits[3-width:])
}

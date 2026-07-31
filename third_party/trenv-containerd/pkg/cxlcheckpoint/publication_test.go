package cxlcheckpoint

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

func validPublication(t testing.TB) Publication {
	t.Helper()
	publication := Publication{
		CheckpointID: "checkpoint-a",
		Devices: []Device{
			{DeviceUUID: "device-a", OwnerID: "owner-a", OwnerEpoch: 7, DataPageCount: 1024},
			{DeviceUUID: "device-b", OwnerID: "owner-a", OwnerEpoch: 7, DataPageCount: 1024},
			{DeviceUUID: "device-c", OwnerID: "owner-b", OwnerEpoch: 9, DataPageCount: 1024},
		},
		ContentObjects: []ContentObject{
			{ObjectID: 1, Kind: ContentMemory, ByteLength: 2 * PageSize, LogicalPageStart: 0, PageCount: 2},
			{ObjectID: 2, Kind: ContentArtifact, ByteLength: 5, LogicalPageStart: 2, PageCount: 1},
			{ObjectID: 3, Kind: ContentMMTemplate, ByteLength: 256, LogicalPageStart: 3, PageCount: 1},
			{ObjectID: 4, Kind: ContentPageMap, ByteLength: 256, LogicalPageStart: 4, PageCount: 1},
			{ObjectID: 5, Kind: ContentPageMap, ByteLength: 0, LogicalPageStart: 5, PageCount: 1},
			{ObjectID: 6, Kind: ContentRestoreBlob, ByteLength: 50, LogicalPageStart: 6, PageCount: 1},
		},
		Allocation: InitialAllocation{
			OwnerID:            "owner-a",
			OwnerEpoch:         7,
			AllocationRecordID: 42,
			TotalPages:         7,
			Extents: []AllocationExtent{
				{DeviceUUID: "device-a", StartDataPageIndex: 100, PageCount: 4, LogicalPageStart: 0},
				{DeviceUUID: "device-b", StartDataPageIndex: 200, PageCount: 3, LogicalPageStart: 4},
			},
		},
		MMTemplate: MMTemplate{
			TemplateID:             "template-a",
			ContentObjectID:        3,
			RuntimeCompatibilityID: "runtime-kernel-criu-a",
			PageSize:               PageSize,
			VMAs: []VMA{
				{
					StartVAddr:      0x1000,
					EndVAddr:        0x3000,
					ProtectionFlags: ProtectionRead | ProtectionWrite,
					MappingFlags:    MappingPrivate | MappingAnonymous,
					BackingKind:     BackingAnonymous,
					PageMapRunStart: 0,
					PageMapRunCount: 1,
				},
				{
					StartVAddr:      0x4000,
					EndVAddr:        0x5000,
					ProtectionFlags: ProtectionRead,
					MappingFlags:    MappingShared,
					BackingKind:     BackingArtifact,
					PageMapRunStart: 1,
					PageMapRunCount: 1,
				},
			},
		},
		PageMap: PageMap{
			PageMapID:       "page-map-a",
			Version:         1,
			ContentObjectID: 4,
			PageSize:        PageSize,
			Runs: []PageMapRun{
				{
					StartVAddr: 0x1000,
					PageCount:  2,
					FirstPage: PageID{
						OwnerID:            "owner-a",
						DeviceUUID:         "device-a",
						AllocationRecordID: 42,
						DataPageIndex:      100,
					},
				},
				{
					StartVAddr: 0x4000,
					PageCount:  1,
					FirstPage: PageID{
						OwnerID:            "owner-b",
						DeviceUUID:         "device-c",
						AllocationRecordID: 99,
						DataPageIndex:      50,
					},
				},
			},
		},
		Artifacts: ArtifactManifest{
			ManifestID: "artifacts-a",
			Entries: []ArtifactEntry{
				{Path: "bin", Type: ArtifactDirectory, Mode: 0755},
				{
					Path:            "bin/action",
					Type:            ArtifactRegular,
					Mode:            0755,
					UID:             1000,
					GID:             1000,
					ByteLength:      5,
					ContentObjectID: 2,
				},
				{Path: "link", Type: ArtifactSymlink, Mode: 0777, LinkTarget: "bin/action"},
			},
		},
		MappingSlots: MappingSlots{
			A: MappingSlot{Name: MappingSlotA, ContentObjectID: 4, CapacityPages: 1},
			B: MappingSlot{Name: MappingSlotB, ContentObjectID: 5, CapacityPages: 1},
		},
		Root: CommittedRoot{
			State:               RootCommitted,
			RootID:              "root-a",
			CheckpointID:        "checkpoint-a",
			OwnerID:             "owner-a",
			AllocationRecordID:  42,
			MMTemplateID:        "template-a",
			PageMapID:           "page-map-a",
			PageMapVersion:      1,
			ArtifactManifestID:  "artifacts-a",
			ActiveMappingSlot:   MappingSlotA,
			PublicationSequence: 1,
		},
	}
	mmTemplateSize, err := canonicalMMTemplateSize(publication.MMTemplate)
	if err != nil {
		t.Fatalf("canonical MM template size: %v", err)
	}
	pageMapSize, err := canonicalPageMapSize(publication.PageMap)
	if err != nil {
		t.Fatalf("canonical PageMap size: %v", err)
	}
	publication.ContentObjects[2].ByteLength = mmTemplateSize
	publication.ContentObjects[3].ByteLength = pageMapSize
	refreshDeviceDigest(t, &publication)
	if err := publication.Validate(); err != nil {
		t.Fatalf("test publication is invalid: %v", err)
	}
	return publication
}

func refreshDeviceDigest(t testing.TB, publication *Publication) {
	t.Helper()
	digest, err := DeviceTableDigest(publication.Devices)
	if err != nil {
		t.Fatalf("device-table digest: %v", err)
	}
	publication.Root.DeviceTableDigest = digest
}

func requireInvalid(t *testing.T, publication Publication) {
	t.Helper()
	if err := publication.Validate(); !errors.Is(err, ErrInvalid) {
		t.Fatalf("Validate() error = %v, want ErrInvalid", err)
	}
	if _, err := Encode(publication); !errors.Is(err, ErrInvalid) {
		t.Fatalf("Encode() error = %v, want ErrInvalid", err)
	}
}

func requireDecodeError(t *testing.T, encoded []byte, target error) {
	t.Helper()
	if _, err := Decode(encoded); !errors.Is(err, target) {
		t.Fatalf("Decode() error = %v, want %v", err, target)
	}
}

func TestCRC32CKnownAnswer(t *testing.T) {
	const want uint32 = 0xe3069283
	if got := checksumCRC32C([]byte("123456789")); got != want {
		t.Fatalf("CRC-32C(123456789) = %#08x, want %#08x", got, want)
	}
}

func TestPublicationRoundTripIsDeterministicAndLittleEndian(t *testing.T) {
	publication := validPublication(t)
	first, err := Encode(publication)
	if err != nil {
		t.Fatalf("Encode(): %v", err)
	}
	second, err := Encode(publication)
	if err != nil {
		t.Fatalf("second Encode(): %v", err)
	}
	if !bytes.Equal(first, second) {
		t.Fatal("identical publications encoded differently")
	}
	if got := string(first[:8]); got != MagicString {
		t.Fatalf("magic = %q, want %q", got, MagicString)
	}
	if got := binary.LittleEndian.Uint32(first[8:12]); got != Version {
		t.Fatalf("version = %d, want %d", got, Version)
	}
	if got := binary.LittleEndian.Uint32(first[12:16]); got != envelopeHeaderSize {
		t.Fatalf("header size = %d, want %d", got, envelopeHeaderSize)
	}
	if got := binary.LittleEndian.Uint64(first[16:24]); got != uint64(len(first))-uint64(envelopeHeaderSize) {
		t.Fatalf("payload length = %d, envelope length = %d", got, len(first))
	}
	if got, want := binary.LittleEndian.Uint32(first[24:28]), checksumCRC32C(first[envelopeHeaderSize:]); got != want {
		t.Fatalf("payload CRC-32C = %#08x, want %#08x", got, want)
	}
	if got, want := binary.LittleEndian.Uint32(first[32:36]), headerCRC(first[:envelopeHeaderSize]); got != want {
		t.Fatalf("header CRC-32C = %#08x, want %#08x", got, want)
	}
	decoded, err := Decode(first)
	if err != nil {
		t.Fatalf("Decode(): %v", err)
	}
	if !reflect.DeepEqual(decoded, publication) {
		t.Fatalf("round trip differs:\n got: %#v\nwant: %#v", decoded, publication)
	}
	reencoded, err := Encode(decoded)
	if err != nil {
		t.Fatalf("re-Encode(): %v", err)
	}
	if !bytes.Equal(first, reencoded) {
		t.Fatal("decode followed by encode was not byte deterministic")
	}

	kinds := make(map[ContentKind]bool)
	for _, object := range decoded.ContentObjects {
		kinds[object.Kind] = true
	}
	for kind := ContentMemory; kind <= ContentRestoreBlob; kind++ {
		if !kinds[kind] {
			t.Fatalf("content kind %d is absent from round-trip fixture", kind)
		}
	}
	if decoded.Artifacts.Entries[1].ByteLength != 5 {
		t.Fatal("artifact exact byte length was not preserved")
	}
}

func TestDeviceTableDigestIsCanonicalAndHasNoLocalPathContract(t *testing.T) {
	publication := validPublication(t)
	want := publication.Root.DeviceTableDigest
	reversed := append([]Device(nil), publication.Devices...)
	for left, right := 0, len(reversed)-1; left < right; left, right = left+1, right-1 {
		reversed[left], reversed[right] = reversed[right], reversed[left]
	}
	got, err := DeviceTableDigest(reversed)
	if err != nil {
		t.Fatalf("digest reversed table: %v", err)
	}
	if got != want {
		t.Fatalf("device digest depends on input order: got %x want %x", got, want)
	}

	deviceType := reflect.TypeOf(Device{})
	wantFields := []string{"DeviceUUID", "OwnerID", "OwnerEpoch", "DataPageCount"}
	if deviceType.NumField() != len(wantFields) {
		t.Fatalf("Device has %d fields, want portable fields %v", deviceType.NumField(), wantFields)
	}
	for index, wantName := range wantFields {
		if gotName := deviceType.Field(index).Name; gotName != wantName {
			t.Fatalf("Device field %d = %q, want %q", index, gotName, wantName)
		}
	}
	encoded, err := Encode(publication)
	if err != nil {
		t.Fatalf("Encode(): %v", err)
	}
	if bytes.Contains(encoded, []byte("/dev/")) {
		t.Fatal("portable publication contains a host-local /dev path")
	}

	publication.Devices[0].DeviceUUID = "/dev/dax0.0"
	requireInvalid(t, publication)
}

func TestInitialAllocationCanSpanDevicesButNotOwners(t *testing.T) {
	publication := validPublication(t)
	if len(publication.Allocation.Extents) != 2 ||
		publication.Allocation.Extents[0].DeviceUUID == publication.Allocation.Extents[1].DeviceUUID {
		t.Fatal("fixture does not exercise a multiple-device allocation")
	}
	if err := publication.Validate(); err != nil {
		t.Fatalf("multiple-device allocation rejected: %v", err)
	}
	for _, extent := range publication.Allocation.Extents {
		for _, device := range publication.Devices {
			if device.DeviceUUID == extent.DeviceUUID &&
				(device.OwnerID != publication.Allocation.OwnerID || device.OwnerEpoch != publication.Allocation.OwnerEpoch) {
				t.Fatalf("initial extent device %q does not match allocation Owner+epoch", extent.DeviceUUID)
			}
		}
	}

	publication.Allocation.Extents[1].DeviceUUID = "device-c"
	requireInvalid(t, publication)

	publication = validPublication(t)
	publication.Allocation.OwnerEpoch++
	requireInvalid(t, publication)
}

func TestPageMapAllowsCrossOwnerCanonicalPage(t *testing.T) {
	publication := validPublication(t)
	remote := publication.PageMap.Runs[1].FirstPage
	if remote.OwnerID == publication.Allocation.OwnerID {
		t.Fatal("fixture remote PageID unexpectedly belongs to initial Owner")
	}
	deviceByUUID := make(map[string]Device)
	for _, device := range publication.Devices {
		deviceByUUID[device.DeviceUUID] = device
	}
	if deviceByUUID[remote.DeviceUUID].OwnerID != remote.OwnerID {
		t.Fatal("fixture remote PageID does not match its canonical Owner")
	}
	if deviceByUUID[remote.DeviceUUID].OwnerEpoch == publication.Allocation.OwnerEpoch {
		t.Fatal("fixture does not exercise a different canonical Owner epoch")
	}
	if err := publication.Validate(); err != nil {
		t.Fatalf("cross-Owner canonical PageID rejected: %v", err)
	}

	publication.PageMap.Runs[1].FirstPage.OwnerID = "owner-a"
	requireInvalid(t, publication)
}

func TestPageMapRunCannotCrossKnownAllocationExtent(t *testing.T) {
	publication := validPublication(t)
	// device-a's initial extent is [100,104). A two-page run beginning at
	// 103 would silently enter a different allocation record at page 104.
	publication.PageMap.Runs[0].FirstPage.DataPageIndex = 103
	requireInvalid(t, publication)

	// A different AllocationRecordID is one explicit run identity. Its
	// physical membership must be resolved against that Owner's descriptor
	// table, so it remains a valid canonical reference in this codec.
	publication = validPublication(t)
	publication.PageMap.Runs[0].FirstPage.AllocationRecordID = 43
	if err := publication.Validate(); err != nil {
		t.Fatalf("explicit canonical allocation identity rejected: %v", err)
	}

	// Device and allocation identity are fields of the run base, rather than
	// values inferred from a local shard number. A boundary is represented by
	// a second run and survives the binary round trip.
	publication = validPublication(t)
	encoded, err := Encode(publication)
	if err != nil {
		t.Fatalf("Encode(): %v", err)
	}
	decoded, err := Decode(encoded)
	if err != nil {
		t.Fatalf("Decode(): %v", err)
	}
	if decoded.PageMap.Runs[0].FirstPage.DeviceUUID == decoded.PageMap.Runs[1].FirstPage.DeviceUUID ||
		decoded.PageMap.Runs[0].FirstPage.AllocationRecordID == decoded.PageMap.Runs[1].FirstPage.AllocationRecordID {
		t.Fatal("run boundary lost distinct device/allocation identity")
	}
}

func TestMappingSlotsAreBothReservedAndRootSelectsExactObject(t *testing.T) {
	publication := validPublication(t)
	if publication.MappingSlots.A.CapacityPages == 0 || publication.MappingSlots.B.CapacityPages == 0 {
		t.Fatal("fixture does not pre-reserve both mapping slots")
	}
	if publication.MappingSlots.A.ContentObjectID == publication.MappingSlots.B.ContentObjectID {
		t.Fatal("fixture mapping slots are not distinct")
	}
	if err := publication.Validate(); err != nil {
		t.Fatalf("valid slots rejected: %v", err)
	}

	tests := []struct {
		name   string
		mutate func(*Publication)
	}{
		{
			name: "same content object",
			mutate: func(p *Publication) {
				p.MappingSlots.B.ContentObjectID = p.MappingSlots.A.ContentObjectID
			},
		},
		{
			name: "unreserved B capacity",
			mutate: func(p *Publication) {
				p.MappingSlots.B.CapacityPages = 0
			},
		},
		{
			name: "root selects inactive object",
			mutate: func(p *Publication) {
				p.Root.ActiveMappingSlot = MappingSlotB
			},
		},
		{
			name: "fixed names reversed",
			mutate: func(p *Publication) {
				p.MappingSlots.A.Name = MappingSlotB
				p.MappingSlots.B.Name = MappingSlotA
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			candidate := validPublication(t)
			test.mutate(&candidate)
			requireInvalid(t, candidate)
		})
	}
}

func TestMetadataContentObjectsUseExactCanonicalByteLengths(t *testing.T) {
	publication := validPublication(t)
	mmSize, err := canonicalMMTemplateSize(publication.MMTemplate)
	if err != nil {
		t.Fatalf("MM template size: %v", err)
	}
	mapSize, err := canonicalPageMapSize(publication.PageMap)
	if err != nil {
		t.Fatalf("PageMap size: %v", err)
	}
	if publication.ContentObjects[2].ByteLength != mmSize {
		t.Fatalf("MM template bytes = %d, want %d", publication.ContentObjects[2].ByteLength, mmSize)
	}
	if publication.ContentObjects[3].ByteLength != mapSize {
		t.Fatalf("PageMap bytes = %d, want %d", publication.ContentObjects[3].ByteLength, mapSize)
	}

	publication.ContentObjects[2].ByteLength++
	requireInvalid(t, publication)

	publication = validPublication(t)
	publication.ContentObjects[3].ByteLength++
	requireInvalid(t, publication)
}

func TestOversizedCanonicalPageMapCannotUseOnePageSlot(t *testing.T) {
	publication := validPublication(t)
	publication.PageMap.Runs = nil
	const runCount = 80
	for index := uint64(0); index < runCount; index++ {
		publication.PageMap.Runs = append(publication.PageMap.Runs, PageMapRun{
			StartVAddr: 0x1000 + index*PageSize,
			PageCount:  1,
			FirstPage: PageID{
				OwnerID:            "owner-a",
				DeviceUUID:         "device-a",
				AllocationRecordID: 43 + index,
				DataPageIndex:      index,
			},
		})
	}
	publication.MMTemplate.VMAs = []VMA{{
		StartVAddr:      0x1000,
		EndVAddr:        0x1000 + runCount*PageSize,
		ProtectionFlags: ProtectionRead | ProtectionWrite,
		MappingFlags:    MappingPrivate | MappingAnonymous,
		BackingKind:     BackingAnonymous,
		PageMapRunStart: 0,
		PageMapRunCount: runCount,
	}}
	mmSize, err := canonicalMMTemplateSize(publication.MMTemplate)
	if err != nil {
		t.Fatalf("MM template size: %v", err)
	}
	mapSize, err := canonicalPageMapSize(publication.PageMap)
	if err != nil {
		t.Fatalf("PageMap size: %v", err)
	}
	if mapSize <= PageSize {
		t.Fatalf("test PageMap is only %d bytes", mapSize)
	}
	publication.ContentObjects[2].ByteLength = mmSize
	publication.ContentObjects[3].ByteLength = mapSize
	requireInvalid(t, publication)
}

func TestEnvelopeFailsClosed(t *testing.T) {
	encoded, err := Encode(validPublication(t))
	if err != nil {
		t.Fatalf("Encode(): %v", err)
	}

	for legacyVersion := 1; legacyVersion <= 5; legacyVersion++ {
		t.Run(fmt.Sprintf("V%d magic", legacyVersion), func(t *testing.T) {
			legacy := append([]byte(nil), encoded...)
			copy(legacy[:8], fmt.Sprintf("TRPUB%03d", legacyVersion))
			requireDecodeError(t, legacy, ErrWrongFormat)
		})
	}

	t.Run("V5 version field", func(t *testing.T) {
		legacy := append([]byte(nil), encoded...)
		binary.LittleEndian.PutUint32(legacy[8:12], 5)
		binary.LittleEndian.PutUint32(legacy[32:36], headerCRC(legacy[:envelopeHeaderSize]))
		requireDecodeError(t, legacy, ErrWrongFormat)
	})

	t.Run("unknown mandatory flags", func(t *testing.T) {
		candidate := append([]byte(nil), encoded...)
		binary.LittleEndian.PutUint32(candidate[28:32], 1)
		binary.LittleEndian.PutUint32(candidate[32:36], headerCRC(candidate[:envelopeHeaderSize]))
		requireDecodeError(t, candidate, ErrWrongFormat)
	})

	t.Run("reserved header", func(t *testing.T) {
		candidate := append([]byte(nil), encoded...)
		candidate[36] = 1
		binary.LittleEndian.PutUint32(candidate[32:36], headerCRC(candidate[:envelopeHeaderSize]))
		requireDecodeError(t, candidate, ErrWrongFormat)
	})

	t.Run("header checksum", func(t *testing.T) {
		candidate := append([]byte(nil), encoded...)
		candidate[16] ^= 1
		requireDecodeError(t, candidate, ErrCorrupt)
	})

	t.Run("payload checksum", func(t *testing.T) {
		candidate := append([]byte(nil), encoded...)
		candidate[len(candidate)-1] ^= 1
		requireDecodeError(t, candidate, ErrCorrupt)
	})

	t.Run("envelope trailing byte", func(t *testing.T) {
		candidate := append(append([]byte(nil), encoded...), 0)
		requireDecodeError(t, candidate, ErrCorrupt)
	})

	t.Run("payload trailing byte", func(t *testing.T) {
		payload, err := parseEnvelope(encoded)
		if err != nil {
			t.Fatalf("parse seed envelope: %v", err)
		}
		candidate, err := marshalEnvelope(append(payload, 0))
		if err != nil {
			t.Fatalf("marshal payload with trailing byte: %v", err)
		}
		requireDecodeError(t, candidate, ErrCorrupt)
	})

	t.Run("every truncation", func(t *testing.T) {
		for length := 0; length < len(encoded); length++ {
			if _, err := Decode(encoded[:length]); err == nil {
				t.Fatalf("truncated prefix of %d/%d bytes decoded", length, len(encoded))
			}
		}
	})
}

func TestTextualIdentityUTF8AndLengthLimits(t *testing.T) {
	exact := strings.Repeat("é", MaxIdentityBytes/2)
	publication := validPublication(t)
	publication.CheckpointID = exact
	publication.Root.CheckpointID = exact
	if _, err := Encode(publication); err != nil {
		t.Fatalf("exactly %d UTF-8 bytes rejected: %v", MaxIdentityBytes, err)
	}

	tests := []struct {
		name  string
		value string
	}{
		{name: "over limit", value: exact + "a"},
		{name: "invalid UTF-8", value: string([]byte{0xff})},
		{name: "surrounding whitespace", value: " checkpoint-a"},
		{name: "control character", value: "checkpoint\x00a"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			candidate := validPublication(t)
			candidate.CheckpointID = test.value
			candidate.Root.CheckpointID = test.value
			requireInvalid(t, candidate)
		})
	}
}

func TestSignedLongABIBounds(t *testing.T) {
	publication := validPublication(t)
	publication.Allocation.AllocationRecordID = MaxSignedLong
	publication.PageMap.Runs[0].FirstPage.AllocationRecordID = MaxSignedLong
	publication.Root.AllocationRecordID = MaxSignedLong
	encoded, err := Encode(publication)
	if err != nil {
		t.Fatalf("Long.MaxValue rejected: %v", err)
	}
	decoded, err := Decode(encoded)
	if err != nil {
		t.Fatalf("decode Long.MaxValue: %v", err)
	}
	if decoded.Allocation.AllocationRecordID != MaxSignedLong {
		t.Fatalf("allocation record ID = %d, want %d", decoded.Allocation.AllocationRecordID, MaxSignedLong)
	}

	tests := []struct {
		name   string
		mutate func(*Publication)
	}{
		{
			name: "zero allocation record",
			mutate: func(p *Publication) {
				p.Allocation.AllocationRecordID = 0
				p.Root.AllocationRecordID = 0
			},
		},
		{
			name: "allocation record above Long",
			mutate: func(p *Publication) {
				p.Allocation.AllocationRecordID = MaxSignedLong + 1
				p.Root.AllocationRecordID = MaxSignedLong + 1
			},
		},
		{
			name: "owner epoch above Long",
			mutate: func(p *Publication) {
				p.Devices[0].OwnerEpoch = MaxSignedLong + 1
			},
		},
		{
			name: "content length above Long",
			mutate: func(p *Publication) {
				p.ContentObjects[1].ByteLength = MaxSignedLong + 1
			},
		},
		{
			name: "PageID index above Long",
			mutate: func(p *Publication) {
				p.PageMap.Runs[1].FirstPage.DataPageIndex = MaxSignedLong + 1
			},
		},
		{
			name: "artifact UID above Long",
			mutate: func(p *Publication) {
				p.Artifacts.Entries[1].UID = MaxSignedLong + 1
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			candidate := validPublication(t)
			test.mutate(&candidate)
			requireInvalid(t, candidate)
		})
	}
}

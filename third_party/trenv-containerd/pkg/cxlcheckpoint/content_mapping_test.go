package cxlcheckpoint

import (
	"bytes"
	"encoding/binary"
	"errors"
	"reflect"
	"testing"
)

func validContentMappingFixture() (
	[]ContentObject,
	VirtualPageMap,
	ContentPlacementMap,
) {
	objects := []ContentObject{
		{
			ObjectID:         10,
			Kind:             ContentMemory,
			ByteLength:       3 * PageSize,
			LogicalPageStart: 0,
			PageCount:        3,
		},
		{
			ObjectID:         11,
			Kind:             ContentMemory,
			ByteLength:       2 * PageSize,
			LogicalPageStart: 3,
			PageCount:        2,
		},
		{
			ObjectID:         20,
			Kind:             ContentArtifact,
			ByteLength:       PageSize + 17,
			LogicalPageStart: 5,
			PageCount:        2,
		},
		{
			ObjectID:         30,
			Kind:             ContentMMTemplate,
			ByteLength:       100,
			LogicalPageStart: 7,
			PageCount:        1,
		},
		{
			ObjectID:         31,
			Kind:             ContentPageMap,
			ByteLength:       200,
			LogicalPageStart: 8,
			PageCount:        1,
		},
		{
			ObjectID:         32,
			Kind:             ContentPageMap,
			ByteLength:       0,
			LogicalPageStart: 9,
			PageCount:        1,
		},
		{
			ObjectID:         40,
			Kind:             ContentRestoreBlob,
			ByteLength:       PageSize + 1,
			LogicalPageStart: 10,
			PageCount:        2,
		},
		{
			ObjectID:         50,
			Kind:             ContentPublication,
			ByteLength:       PageSize,
			LogicalPageStart: 12,
			PageCount:        1,
		},
	}
	virtual := VirtualPageMap{
		VirtualPageMapID: "virtual-map-a",
		Version:          3,
		PageSize:         PageSize,
		Runs: []VirtualPageMapRun{
			{
				PagesImageID:    1,
				StartVAddr:      0x1000,
				PageCount:       2,
				ContentObjectID: 10,
				ObjectPageIndex: 0,
			},
			{
				PagesImageID:    1,
				StartVAddr:      0x4000,
				PageCount:       1,
				ContentObjectID: 10,
				ObjectPageIndex: 2,
			},
			{
				PagesImageID:    2,
				StartVAddr:      0x1000,
				PageCount:       2,
				ContentObjectID: 11,
				ObjectPageIndex: 0,
			},
		},
	}
	placement := ContentPlacementMap{
		ContentPlacementMapID: "placement-map-a",
		Version:               9,
		PageSize:              PageSize,
		Devices: []Device{
			{
				DeviceUUID:    "device-a",
				OwnerID:       "owner-a",
				OwnerEpoch:    7,
				DataPageCount: 1000,
			},
			{
				DeviceUUID:    "device-b",
				OwnerID:       "owner-b",
				OwnerEpoch:    9,
				DataPageCount: 1000,
			},
		},
		Runs: []ContentPlacementRun{
			{
				ContentObjectID:    10,
				ObjectPageIndex:    0,
				PageCount:          2,
				DeviceIndex:        0,
				AllocationRecordID: 101,
				DataPageIndex:      10,
			},
			{
				ContentObjectID:    10,
				ObjectPageIndex:    2,
				PageCount:          1,
				DeviceIndex:        1,
				AllocationRecordID: 202,
				DataPageIndex:      20,
			},
			{
				ContentObjectID:    11,
				ObjectPageIndex:    0,
				PageCount:          2,
				DeviceIndex:        1,
				AllocationRecordID: 202,
				DataPageIndex:      30,
			},
			{
				ContentObjectID:    20,
				ObjectPageIndex:    0,
				PageCount:          2,
				DeviceIndex:        0,
				AllocationRecordID: 101,
				DataPageIndex:      50,
			},
			{
				// Restore-blob page 0 aliases memory object 10 page 0. This is
				// the intended post-dedup representation.
				ContentObjectID:    40,
				ObjectPageIndex:    0,
				PageCount:          1,
				DeviceIndex:        0,
				AllocationRecordID: 101,
				DataPageIndex:      10,
			},
			{
				ContentObjectID:    40,
				ObjectPageIndex:    1,
				PageCount:          1,
				DeviceIndex:        1,
				AllocationRecordID: 303,
				DataPageIndex:      80,
			},
		},
	}
	return objects, virtual, placement
}

func TestV7ContentMappingsValidateResolveAndKeepDedupAliasPhysical(t *testing.T) {
	objects, virtual, placement := validContentMappingFixture()
	originalObjects := append([]ContentObject(nil), objects...)
	originalDevices := append([]Device(nil), placement.Devices...)
	if err := virtual.Validate(objects); err != nil {
		t.Fatalf("VirtualPageMap.Validate(): %v", err)
	}
	if err := placement.Validate(objects); err != nil {
		t.Fatalf("ContentPlacementMap.Validate(): %v", err)
	}
	if !reflect.DeepEqual(objects, originalObjects) {
		t.Fatal("mapping validation mutated the content-object context")
	}
	if !reflect.DeepEqual(placement.Devices, originalDevices) {
		t.Fatal("mapping validation mutated the portable device table")
	}

	logical, ok := virtual.ResolveVirtualPage(1, 0x2000)
	if !ok || logical.ContentObjectID != 10 || logical.ObjectPageIndex != 1 ||
		logical.ContiguousPageCount != 1 {
		t.Fatalf("ResolveVirtualPage() = %#v, %v", logical, ok)
	}
	if _, ok := virtual.ResolveVirtualPage(1, 0x3000); ok {
		t.Fatal("ResolveVirtualPage() resolved a sparse virtual hole")
	}
	if _, ok := virtual.ResolveVirtualPage(1, 0x2001); ok {
		t.Fatal("ResolveVirtualPage() accepted an unaligned address")
	}

	memory, ok := placement.ResolveContentPage(10, 0)
	if !ok {
		t.Fatal("ResolveContentPage(memory) did not resolve")
	}
	restore, ok := placement.ResolveContentPage(40, 0)
	if !ok {
		t.Fatal("ResolveContentPage(restore blob) did not resolve")
	}
	if memory.PageID != restore.PageID {
		t.Fatalf("dedup aliases differ: memory=%#v restore=%#v", memory, restore)
	}
	if memory.OwnerEpoch != 7 || memory.ContiguousPageCount != 2 {
		t.Fatalf("memory placement resolution = %#v", memory)
	}
	remote, ok := placement.ResolveContentPage(10, 2)
	if !ok || remote.PageID.OwnerID != "owner-b" ||
		remote.PageID.DeviceUUID != "device-b" || remote.OwnerEpoch != 9 ||
		remote.PageID.DataPageIndex != 20 {
		t.Fatalf("remote placement resolution = %#v, %v", remote, ok)
	}
	if _, ok := placement.ResolveContentPage(30, 0); ok {
		t.Fatal("ResolveContentPage() resolved excluded MMTemplate content")
	}
	if _, ok := placement.ResolveContentPage(40, 2); ok {
		t.Fatal("ResolveContentPage() resolved beyond an object")
	}
}

func TestV7ContentMappingResolversUseCanonicalFirstMiddleLastAndRejectLocalDamage(t *testing.T) {
	_, virtual, placement := validContentMappingFixture()
	virtualCases := []struct {
		name           string
		image          uint32
		address        uint64
		wantObject     uint64
		wantObjectPage uint64
		want           bool
	}{
		{name: "first", image: 1, address: 0x1000, wantObject: 10, wantObjectPage: 0, want: true},
		{name: "middle", image: 1, address: 0x4000, wantObject: 10, wantObjectPage: 2, want: true},
		{name: "last", image: 2, address: 0x2000, wantObject: 11, wantObjectPage: 1, want: true},
		{name: "hole before first", image: 1, address: 0, want: false},
		{name: "sparse middle hole", image: 1, address: 0x3000, want: false},
		{name: "unknown image", image: 3, address: 0x1000, want: false},
	}
	for _, test := range virtualCases {
		t.Run("virtual "+test.name, func(t *testing.T) {
			got, ok := virtual.ResolveVirtualPage(test.image, test.address)
			if ok != test.want {
				t.Fatalf("ResolveVirtualPage() ok = %v, want %v; result=%#v", ok, test.want, got)
			}
			if ok && (got.ContentObjectID != test.wantObject ||
				got.ObjectPageIndex != test.wantObjectPage) {
				t.Fatalf("ResolveVirtualPage() = %#v", got)
			}
		})
	}

	placementCases := []struct {
		name         string
		object       uint64
		page         uint64
		wantDevice   string
		wantDataPage uint64
		want         bool
	}{
		{name: "first", object: 10, page: 0, wantDevice: "device-a", wantDataPage: 10, want: true},
		{name: "middle", object: 20, page: 1, wantDevice: "device-a", wantDataPage: 51, want: true},
		{name: "last", object: 40, page: 1, wantDevice: "device-b", wantDataPage: 80, want: true},
		{name: "excluded object hole", object: 30, page: 0, want: false},
		{name: "before first object", object: 1, page: 0, want: false},
		{name: "after last page", object: 40, page: 2, want: false},
	}
	for _, test := range placementCases {
		t.Run("placement "+test.name, func(t *testing.T) {
			got, ok := placement.ResolveContentPage(test.object, test.page)
			if ok != test.want {
				t.Fatalf("ResolveContentPage() ok = %v, want %v; result=%#v", ok, test.want, got)
			}
			if ok && (got.PageID.DeviceUUID != test.wantDevice ||
				got.PageID.DataPageIndex != test.wantDataPage) {
				t.Fatalf("ResolveContentPage() = %#v", got)
			}
		})
	}

	t.Run("malformed virtual canonical order", func(t *testing.T) {
		malformed := virtual
		malformed.Runs = append([]VirtualPageMapRun(nil), virtual.Runs...)
		malformed.Runs[0], malformed.Runs[1] = malformed.Runs[1], malformed.Runs[0]
		if _, ok := malformed.ResolveVirtualPage(1, 0x1000); ok {
			t.Fatal("resolver accepted noncanonical virtual run order")
		}
	})
	t.Run("malformed virtual overlap", func(t *testing.T) {
		malformed := virtual
		malformed.Runs = append([]VirtualPageMapRun(nil), virtual.Runs...)
		malformed.Runs[1].StartVAddr = 0x2000
		if _, ok := malformed.ResolveVirtualPage(1, 0x2000); ok {
			t.Fatal("resolver accepted overlapping virtual runs")
		}
	})
	t.Run("malformed placement canonical order", func(t *testing.T) {
		malformed := placement
		malformed.Runs = append([]ContentPlacementRun(nil), placement.Runs...)
		malformed.Runs[0], malformed.Runs[1] = malformed.Runs[1], malformed.Runs[0]
		if _, ok := malformed.ResolveContentPage(10, 0); ok {
			t.Fatal("resolver accepted noncanonical placement run order")
		}
	})
	t.Run("malformed placement overlap", func(t *testing.T) {
		malformed := placement
		malformed.Runs = append([]ContentPlacementRun(nil), placement.Runs...)
		malformed.Runs[1].ObjectPageIndex = 1
		if _, ok := malformed.ResolveContentPage(10, 1); ok {
			t.Fatal("resolver accepted overlapping placement runs")
		}
	})
}

func TestV7ContentMappingWireIdentityInvariants(t *testing.T) {
	if ContentMappingEnvelopeHeaderBytes != uint64(contentMappingHeaderSize) {
		t.Fatalf("exported header size %d differs from internal size %d",
			ContentMappingEnvelopeHeaderBytes, contentMappingHeaderSize)
	}
	if MaxContentMappingBytes != uint64(MaxPayloadBytes) {
		t.Fatalf("mapping byte cap %d differs from existing 64 MiB cap %d",
			MaxContentMappingBytes, MaxPayloadBytes)
	}
	if len(VirtualPageMapMagicString) != 8 || len(ContentPlacementMapMagicString) != 8 {
		t.Fatal("V7 mapping magic is not exactly eight bytes")
	}
	if len(VirtualPageMapDomain) > contentMappingDomainFieldBytes ||
		len(ContentPlacementMapDomain) > contentMappingDomainFieldBytes {
		t.Fatal("V7 mapping domain exceeds its fixed header field")
	}
	if VirtualPageMapMagicString == MagicString ||
		ContentPlacementMapMagicString == MagicString ||
		VirtualPageMapMagicString == ContentPlacementMapMagicString ||
		VirtualPageMapDomain == ContentPlacementMapDomain {
		t.Fatal("V7 mapping wire identities are not domain separated")
	}
}

func TestV7ContentMappingCodecsAreDeterministicBoundedAndDomainSeparated(t *testing.T) {
	objects, virtual, placement := validContentMappingFixture()

	virtualBytes, err := CanonicalVirtualPageMapBytes(virtual, objects)
	if err != nil {
		t.Fatalf("CanonicalVirtualPageMapBytes(): %v", err)
	}
	virtualAgain, err := CanonicalVirtualPageMapBytes(virtual, objects)
	if err != nil {
		t.Fatalf("second CanonicalVirtualPageMapBytes(): %v", err)
	}
	if !bytes.Equal(virtualBytes, virtualAgain) {
		t.Fatal("identical VirtualPageMaps encoded differently")
	}
	virtualSize, err := CanonicalVirtualPageMapSize(virtual, objects)
	if err != nil || virtualSize != uint64(len(virtualBytes)) {
		t.Fatalf("CanonicalVirtualPageMapSize() = %d, %v; bytes=%d",
			virtualSize, err, len(virtualBytes))
	}
	assertContentMappingHeader(
		t, virtualBytes, VirtualPageMapMagicString, VirtualPageMapDomain)
	decodedVirtual, err := DecodeVirtualPageMap(virtualBytes, objects)
	if err != nil {
		t.Fatalf("DecodeVirtualPageMap(): %v", err)
	}
	if !reflect.DeepEqual(decodedVirtual, virtual) {
		t.Fatalf("VirtualPageMap round trip differs:\n got: %#v\nwant: %#v",
			decodedVirtual, virtual)
	}

	placementBytes, err := CanonicalContentPlacementMapBytes(placement, objects)
	if err != nil {
		t.Fatalf("CanonicalContentPlacementMapBytes(): %v", err)
	}
	placementAgain, err := CanonicalContentPlacementMapBytes(placement, objects)
	if err != nil {
		t.Fatalf("second CanonicalContentPlacementMapBytes(): %v", err)
	}
	if !bytes.Equal(placementBytes, placementAgain) {
		t.Fatal("identical ContentPlacementMaps encoded differently")
	}
	placementSize, err := CanonicalContentPlacementMapSize(placement, objects)
	if err != nil || placementSize != uint64(len(placementBytes)) {
		t.Fatalf("CanonicalContentPlacementMapSize() = %d, %v; bytes=%d",
			placementSize, err, len(placementBytes))
	}
	assertContentMappingHeader(
		t, placementBytes, ContentPlacementMapMagicString, ContentPlacementMapDomain)
	decodedPlacement, err := DecodeContentPlacementMap(placementBytes, objects)
	if err != nil {
		t.Fatalf("DecodeContentPlacementMap(): %v", err)
	}
	if !reflect.DeepEqual(decodedPlacement, placement) {
		t.Fatalf("ContentPlacementMap round trip differs:\n got: %#v\nwant: %#v",
			decodedPlacement, placement)
	}
	reencodedPlacement, err := CanonicalContentPlacementMapBytes(decodedPlacement, objects)
	if err != nil {
		t.Fatalf("re-encode ContentPlacementMap: %v", err)
	}
	if !bytes.Equal(reencodedPlacement, placementBytes) {
		t.Fatal("ContentPlacementMap decode/encode changed canonical bytes")
	}
	if len(virtualBytes) > int(MaxContentMappingBytes) ||
		len(placementBytes) > int(MaxContentMappingBytes) {
		t.Fatal("canonical content map exceeds its 64 MiB envelope bound")
	}
	if bytes.Equal(virtualBytes, placementBytes) {
		t.Fatal("the two mapping domains encoded identical bytes")
	}
	if _, err := DecodeVirtualPageMap(placementBytes, objects); !errors.Is(
		err, ErrWrongContentMappingFormat) {
		t.Fatalf("Virtual decoder accepted placement domain: %v", err)
	}
	if _, err := DecodeContentPlacementMap(virtualBytes, objects); !errors.Is(
		err, ErrWrongContentMappingFormat) {
		t.Fatalf("placement decoder accepted virtual domain: %v", err)
	}

	oldPageMap := PageMap{
		PageMapID:       "old-v6-page-map",
		Version:         1,
		ContentObjectID: 31,
		PageSize:        PageSize,
		Runs: []PageMapRun{{
			PagesImageID: 1,
			StartVAddr:   0x1000,
			PageCount:    1,
			FirstPage: PageID{
				OwnerID:            "owner-a",
				DeviceUUID:         "device-a",
				AllocationRecordID: 101,
				DataPageIndex:      10,
			},
		}},
	}
	oldBytes, err := canonicalPageMapBytes(oldPageMap)
	if err != nil {
		t.Fatalf("encode old PageMap: %v", err)
	}
	if _, err := DecodeVirtualPageMap(oldBytes, objects); !errors.Is(
		err, ErrWrongContentMappingFormat) && !errors.Is(err, ErrCorruptContentMapping) {
		t.Fatalf("Virtual decoder did not reject old PageMap bytes: %v", err)
	}
}

func assertContentMappingHeader(
	t *testing.T,
	encoded []byte,
	wantMagic string,
	wantDomain string,
) {
	t.Helper()
	if got := string(encoded[0:8]); got != wantMagic {
		t.Fatalf("mapping magic = %q, want %q", got, wantMagic)
	}
	if got := binary.LittleEndian.Uint32(encoded[8:12]); got != ContentMappingVersion {
		t.Fatalf("mapping version = %d, want %d", got, ContentMappingVersion)
	}
	if got := binary.LittleEndian.Uint32(encoded[12:16]); got != contentMappingHeaderSize {
		t.Fatalf("mapping header size = %d, want %d", got, contentMappingHeaderSize)
	}
	var domain [contentMappingDomainFieldBytes]byte
	copy(domain[:], encoded[16:40])
	if got := contentMappingDomainString(domain); got != wantDomain {
		t.Fatalf("mapping domain = %q, want %q", got, wantDomain)
	}
	if got := binary.LittleEndian.Uint64(encoded[40:48]); got != uint64(len(encoded))-ContentMappingEnvelopeHeaderBytes {
		t.Fatalf("payload length = %d, envelope bytes = %d", got, len(encoded))
	}
	if got, want := binary.LittleEndian.Uint32(encoded[48:52]),
		checksumCRC32C(encoded[contentMappingHeaderSize:]); got != want {
		t.Fatalf("payload CRC-32C = %#x, want %#x", got, want)
	}
	if got, want := binary.LittleEndian.Uint32(encoded[56:60]),
		contentMappingHeaderCRC(encoded[:contentMappingHeaderSize]); got != want {
		t.Fatalf("header CRC-32C = %#x, want %#x", got, want)
	}
}

func TestVirtualPageMapRejectsInvalidTopologyAndLogicalAliases(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*[]ContentObject, *VirtualPageMap)
	}{
		{
			name: "empty identity",
			mutate: func(_ *[]ContentObject, mapping *VirtualPageMap) {
				mapping.VirtualPageMapID = ""
			},
		},
		{
			name: "zero version",
			mutate: func(_ *[]ContentObject, mapping *VirtualPageMap) {
				mapping.Version = 0
			},
		},
		{
			name: "wrong page size",
			mutate: func(_ *[]ContentObject, mapping *VirtualPageMap) {
				mapping.PageSize = 8192
			},
		},
		{
			name: "empty runs",
			mutate: func(_ *[]ContentObject, mapping *VirtualPageMap) {
				mapping.Runs = nil
			},
		},
		{
			name: "zero pages image",
			mutate: func(_ *[]ContentObject, mapping *VirtualPageMap) {
				mapping.Runs[0].PagesImageID = 0
			},
		},
		{
			name: "unaligned virtual address",
			mutate: func(_ *[]ContentObject, mapping *VirtualPageMap) {
				mapping.Runs[0].StartVAddr++
			},
		},
		{
			name: "zero page count",
			mutate: func(_ *[]ContentObject, mapping *VirtualPageMap) {
				mapping.Runs[0].PageCount = 0
			},
		},
		{
			name: "virtual range signed-Long overflow",
			mutate: func(_ *[]ContentObject, mapping *VirtualPageMap) {
				mapping.Runs[2].StartVAddr = MaxSignedLong - MaxSignedLong%PageSize
			},
		},
		{
			name: "unknown content object",
			mutate: func(_ *[]ContentObject, mapping *VirtualPageMap) {
				mapping.Runs[0].ContentObjectID = 999
			},
		},
		{
			name: "excluded artifact object",
			mutate: func(_ *[]ContentObject, mapping *VirtualPageMap) {
				mapping.Runs[0].ContentObjectID = 20
			},
		},
		{
			name: "object range exceeds memory object",
			mutate: func(_ *[]ContentObject, mapping *VirtualPageMap) {
				mapping.Runs[1].ObjectPageIndex = 3
			},
		},
		{
			name: "virtual overlap",
			mutate: func(_ *[]ContentObject, mapping *VirtualPageMap) {
				mapping.Runs[1].StartVAddr = 0x2000
			},
		},
		{
			name: "noncanonical pages-image order",
			mutate: func(_ *[]ContentObject, mapping *VirtualPageMap) {
				mapping.Runs[2].PagesImageID = 1
				mapping.Runs[2].StartVAddr = 0x1000
			},
		},
		{
			name: "adjacent coalescible runs",
			mutate: func(_ *[]ContentObject, mapping *VirtualPageMap) {
				mapping.Runs[1].StartVAddr = 0x3000
			},
		},
		{
			name: "logical page gap",
			mutate: func(_ *[]ContentObject, mapping *VirtualPageMap) {
				mapping.Runs[0].PageCount = 1
			},
		},
		{
			name: "logical page duplicate alias",
			mutate: func(_ *[]ContentObject, mapping *VirtualPageMap) {
				mapping.Runs[1].ObjectPageIndex = 1
			},
		},
		{
			name: "missing second memory object",
			mutate: func(_ *[]ContentObject, mapping *VirtualPageMap) {
				mapping.Runs = mapping.Runs[:2]
			},
		},
		{
			name: "duplicate content object identity",
			mutate: func(objects *[]ContentObject, _ *VirtualPageMap) {
				(*objects)[1].ObjectID = (*objects)[0].ObjectID
			},
		},
		{
			name: "partial memory object",
			mutate: func(objects *[]ContentObject, _ *VirtualPageMap) {
				(*objects)[0].ByteLength--
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			objects, mapping, _ := validContentMappingFixture()
			test.mutate(&objects, &mapping)
			if err := mapping.Validate(objects); !errors.Is(err, ErrInvalidContentMapping) {
				t.Fatalf("Validate() error = %v, want ErrInvalidContentMapping", err)
			}
			if _, err := CanonicalVirtualPageMapBytes(mapping, objects); !errors.Is(
				err, ErrInvalidContentMapping) {
				t.Fatalf("canonical encode error = %v, want ErrInvalidContentMapping", err)
			}
		})
	}
}

func TestContentPlacementMapRejectsGapsWrongKindsAndNoncanonicalRuns(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*[]ContentObject, *ContentPlacementMap)
	}{
		{
			name: "empty identity",
			mutate: func(_ *[]ContentObject, mapping *ContentPlacementMap) {
				mapping.ContentPlacementMapID = ""
			},
		},
		{
			name: "zero version",
			mutate: func(_ *[]ContentObject, mapping *ContentPlacementMap) {
				mapping.Version = 0
			},
		},
		{
			name: "wrong page size",
			mutate: func(_ *[]ContentObject, mapping *ContentPlacementMap) {
				mapping.PageSize = 8192
			},
		},
		{
			name: "empty device table",
			mutate: func(_ *[]ContentObject, mapping *ContentPlacementMap) {
				mapping.Devices = nil
			},
		},
		{
			name: "unsorted device table",
			mutate: func(_ *[]ContentObject, mapping *ContentPlacementMap) {
				mapping.Devices[0], mapping.Devices[1] = mapping.Devices[1], mapping.Devices[0]
			},
		},
		{
			name: "duplicate device UUID",
			mutate: func(_ *[]ContentObject, mapping *ContentPlacementMap) {
				mapping.Devices[1].DeviceUUID = mapping.Devices[0].DeviceUUID
			},
		},
		{
			name: "zero device Owner epoch",
			mutate: func(_ *[]ContentObject, mapping *ContentPlacementMap) {
				mapping.Devices[0].OwnerEpoch = 0
			},
		},
		{
			name: "zero device capacity",
			mutate: func(_ *[]ContentObject, mapping *ContentPlacementMap) {
				mapping.Devices[0].DataPageCount = 0
			},
		},
		{
			name: "empty runs",
			mutate: func(_ *[]ContentObject, mapping *ContentPlacementMap) {
				mapping.Runs = nil
			},
		},
		{
			name: "unknown content object",
			mutate: func(_ *[]ContentObject, mapping *ContentPlacementMap) {
				mapping.Runs[0].ContentObjectID = 999
			},
		},
		{
			name: "excluded MMTemplate object",
			mutate: func(_ *[]ContentObject, mapping *ContentPlacementMap) {
				mapping.Runs[0].ContentObjectID = 30
			},
		},
		{
			name: "logical gap",
			mutate: func(_ *[]ContentObject, mapping *ContentPlacementMap) {
				mapping.Runs[1].ObjectPageIndex = 1
			},
		},
		{
			name: "noncanonical object order",
			mutate: func(_ *[]ContentObject, mapping *ContentPlacementMap) {
				mapping.Runs[0], mapping.Runs[1] = mapping.Runs[1], mapping.Runs[0]
			},
		},
		{
			name: "object range exceeds capacity",
			mutate: func(_ *[]ContentObject, mapping *ContentPlacementMap) {
				mapping.Runs[1].PageCount = 2
			},
		},
		{
			name: "invalid device index",
			mutate: func(_ *[]ContentObject, mapping *ContentPlacementMap) {
				mapping.Runs[0].DeviceIndex = 2
			},
		},
		{
			name: "zero allocation record",
			mutate: func(_ *[]ContentObject, mapping *ContentPlacementMap) {
				mapping.Runs[0].AllocationRecordID = 0
			},
		},
		{
			name: "data page exceeds signed Long",
			mutate: func(_ *[]ContentObject, mapping *ContentPlacementMap) {
				mapping.Runs[0].DataPageIndex = MaxSignedLong + 1
			},
		},
		{
			name: "physical range exceeds device",
			mutate: func(_ *[]ContentObject, mapping *ContentPlacementMap) {
				mapping.Runs[0].DataPageIndex = 999
			},
		},
		{
			name: "missing final eligible page",
			mutate: func(_ *[]ContentObject, mapping *ContentPlacementMap) {
				mapping.Runs = mapping.Runs[:len(mapping.Runs)-1]
			},
		},
		{
			name: "extra run after complete coverage",
			mutate: func(_ *[]ContentObject, mapping *ContentPlacementMap) {
				mapping.Runs = append(mapping.Runs, mapping.Runs[len(mapping.Runs)-1])
			},
		},
		{
			name: "adjacent coalescible physical runs",
			mutate: func(_ *[]ContentObject, mapping *ContentPlacementMap) {
				first := mapping.Runs[0]
				mapping.Runs = append(
					[]ContentPlacementRun{
						{
							ContentObjectID:    first.ContentObjectID,
							ObjectPageIndex:    0,
							PageCount:          1,
							DeviceIndex:        first.DeviceIndex,
							AllocationRecordID: first.AllocationRecordID,
							DataPageIndex:      first.DataPageIndex,
						},
						{
							ContentObjectID:    first.ContentObjectID,
							ObjectPageIndex:    1,
							PageCount:          1,
							DeviceIndex:        first.DeviceIndex,
							AllocationRecordID: first.AllocationRecordID,
							DataPageIndex:      first.DataPageIndex + 1,
						},
					},
					mapping.Runs[1:]...)
			},
		},
		{
			name: "no eligible content objects",
			mutate: func(objects *[]ContentObject, _ *ContentPlacementMap) {
				filtered := (*objects)[:0]
				for _, object := range *objects {
					if !placementCoveredKind(object.Kind) {
						filtered = append(filtered, object)
					}
				}
				*objects = filtered
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			objects, _, mapping := validContentMappingFixture()
			test.mutate(&objects, &mapping)
			assertNoPanic(t, func() {
				if err := mapping.Validate(objects); !errors.Is(err, ErrInvalidContentMapping) {
					t.Fatalf("Validate() error = %v, want ErrInvalidContentMapping", err)
				}
			})
			if _, err := CanonicalContentPlacementMapBytes(mapping, objects); !errors.Is(
				err, ErrInvalidContentMapping) {
				t.Fatalf("canonical encode error = %v, want ErrInvalidContentMapping", err)
			}
		})
	}
}

func TestContentPlacementMapMalformedBoundaryInputsNeverPanic(t *testing.T) {
	objects, _, valid := validContentMappingFixture()
	candidates := []ContentPlacementMap{
		{},
		{
			ContentPlacementMapID: "malformed",
			Version:               MaxSignedLong,
			PageSize:              PageSize,
			Devices:               valid.Devices,
			Runs: []ContentPlacementRun{{
				ContentObjectID:    MaxSignedLong,
				ObjectPageIndex:    MaxSignedLong,
				PageCount:          MaxSignedLong,
				DeviceIndex:        ^uint32(0),
				AllocationRecordID: MaxSignedLong,
				DataPageIndex:      MaxSignedLong,
			}},
		},
		{
			ContentPlacementMapID: valid.ContentPlacementMapID,
			Version:               valid.Version,
			PageSize:              valid.PageSize,
			Devices:               valid.Devices,
			Runs: append(
				append([]ContentPlacementRun(nil), valid.Runs...),
				valid.Runs[len(valid.Runs)-1]),
		},
	}
	for index, candidate := range candidates {
		candidate := candidate
		t.Run(string(rune('a'+index)), func(t *testing.T) {
			assertNoPanic(t, func() {
				_ = candidate.Validate(objects)
				_, _ = candidate.ResolveContentPage(MaxSignedLong, MaxSignedLong)
			})
		})
	}
}

func assertNoPanic(t *testing.T, operation func()) {
	t.Helper()
	defer func() {
		if recovered := recover(); recovered != nil {
			t.Fatalf("operation panicked: %v", recovered)
		}
	}()
	operation()
}

func TestContentPlacementMapEnvelopeExactLengthFromHeader(t *testing.T) {
	objects, _, placement := validContentMappingFixture()
	encoded, err := CanonicalContentPlacementMapBytes(placement, objects)
	if err != nil {
		t.Fatal(err)
	}
	header := append([]byte(nil), encoded[:contentMappingHeaderSize]...)
	exact := uint64(len(encoded))

	for _, capacity := range []uint64{exact, exact + PageSize} {
		got, err := ContentPlacementMapEnvelopeExactLengthFromHeader(header, capacity)
		if err != nil || got != exact {
			t.Fatalf("capacity %d: exact length = %d, %v; want %d",
				capacity, got, err, exact)
		}
	}

	t.Run("maximum payload", func(t *testing.T) {
		candidate := append([]byte(nil), header...)
		binary.LittleEndian.PutUint64(candidate[40:48], maxContentMappingPayloadBytes)
		repairContentMappingHeaderCRC(candidate)
		got, err := ContentPlacementMapEnvelopeExactLengthFromHeader(
			candidate, MaxContentMappingBytes)
		if err != nil || got != MaxContentMappingBytes {
			t.Fatalf("exact length = %d, %v; want %d", got, err, MaxContentMappingBytes)
		}
	})

	t.Run("payload checksum validation is deferred", func(t *testing.T) {
		candidate := append([]byte(nil), encoded...)
		binary.LittleEndian.PutUint32(
			candidate[48:52], binary.LittleEndian.Uint32(candidate[48:52])^1)
		repairContentMappingHeaderCRC(candidate)
		got, err := ContentPlacementMapEnvelopeExactLengthFromHeader(
			candidate[:contentMappingHeaderSize], exact)
		if err != nil || got != exact {
			t.Fatalf("exact length = %d, %v; want %d", got, err, exact)
		}
		if _, err := DecodeContentPlacementMap(candidate, objects); !errors.Is(
			err, ErrCorruptContentMapping) {
			t.Fatalf("DecodeContentPlacementMap() error = %v, want payload corruption", err)
		}
	})

	tests := []struct {
		name     string
		capacity uint64
		target   error
		mutate   func([]byte) []byte
	}{
		{
			name:     "truncated header",
			capacity: exact,
			target:   ErrCorruptContentMapping,
			mutate:   func(data []byte) []byte { return data[:len(data)-1] },
		},
		{
			name:     "extra header byte",
			capacity: exact,
			target:   ErrCorruptContentMapping,
			mutate:   func(data []byte) []byte { return append(data, 0) },
		},
		{
			name:     "wrong magic",
			capacity: exact,
			target:   ErrWrongContentMappingFormat,
			mutate: func(data []byte) []byte {
				data[0] ^= 1
				repairContentMappingHeaderCRC(data)
				return data
			},
		},
		{
			name:     "wrong version",
			capacity: exact,
			target:   ErrWrongContentMappingFormat,
			mutate: func(data []byte) []byte {
				binary.LittleEndian.PutUint32(data[8:12], ContentMappingVersion+1)
				repairContentMappingHeaderCRC(data)
				return data
			},
		},
		{
			name:     "wrong header size",
			capacity: exact,
			target:   ErrWrongContentMappingFormat,
			mutate: func(data []byte) []byte {
				binary.LittleEndian.PutUint32(data[12:16], contentMappingHeaderSize+1)
				repairContentMappingHeaderCRC(data)
				return data
			},
		},
		{
			name:     "wrong domain",
			capacity: exact,
			target:   ErrWrongContentMappingFormat,
			mutate: func(data []byte) []byte {
				data[16] ^= 1
				repairContentMappingHeaderCRC(data)
				return data
			},
		},
		{
			name:     "mandatory flags",
			capacity: exact,
			target:   ErrWrongContentMappingFormat,
			mutate: func(data []byte) []byte {
				binary.LittleEndian.PutUint32(data[52:56], 1)
				repairContentMappingHeaderCRC(data)
				return data
			},
		},
		{
			name:     "reserved byte",
			capacity: exact,
			target:   ErrWrongContentMappingFormat,
			mutate: func(data []byte) []byte {
				data[60] = 1
				repairContentMappingHeaderCRC(data)
				return data
			},
		},
		{
			name:     "corrupt header checksum",
			capacity: exact,
			target:   ErrCorruptContentMapping,
			mutate: func(data []byte) []byte {
				data[56] ^= 1
				return data
			},
		},
		{
			name:     "payload exceeds maximum",
			capacity: ^uint64(0),
			target:   ErrCorruptContentMapping,
			mutate: func(data []byte) []byte {
				binary.LittleEndian.PutUint64(data[40:48], maxContentMappingPayloadBytes+1)
				repairContentMappingHeaderCRC(data)
				return data
			},
		},
		{
			name:     "envelope length overflow",
			capacity: ^uint64(0),
			target:   ErrCorruptContentMapping,
			mutate: func(data []byte) []byte {
				binary.LittleEndian.PutUint64(data[40:48], ^uint64(0))
				repairContentMappingHeaderCRC(data)
				return data
			},
		},
		{
			name:     "zero capacity",
			capacity: 0,
			target:   ErrCorruptContentMapping,
			mutate:   func(data []byte) []byte { return data },
		},
		{
			name:     "capacity smaller than envelope",
			capacity: exact - 1,
			target:   ErrCorruptContentMapping,
			mutate:   func(data []byte) []byte { return data },
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			candidate := test.mutate(append([]byte(nil), header...))
			got, err := ContentPlacementMapEnvelopeExactLengthFromHeader(
				candidate, test.capacity)
			if got != 0 || !errors.Is(err, test.target) {
				t.Fatalf("exact length = %d, error = %v; want 0, %v",
					got, err, test.target)
			}
		})
	}
}

func TestV7ContentMappingEnvelopeRejectsCorruptionAndTrailingBytes(t *testing.T) {
	objects, virtual, placement := validContentMappingFixture()
	virtualBytes, err := CanonicalVirtualPageMapBytes(virtual, objects)
	if err != nil {
		t.Fatal(err)
	}
	placementBytes, err := CanonicalContentPlacementMapBytes(placement, objects)
	if err != nil {
		t.Fatal(err)
	}

	t.Run("truncation", func(t *testing.T) {
		for _, length := range []int{0, 1, 63, 64, len(virtualBytes) - 1} {
			if _, err := DecodeVirtualPageMap(virtualBytes[:length], objects); !errors.Is(
				err, ErrCorruptContentMapping) {
				t.Fatalf("length %d error = %v, want corruption", length, err)
			}
		}
	})

	tests := []struct {
		name   string
		target error
		mutate func([]byte)
	}{
		{
			name:   "wrong magic",
			target: ErrWrongContentMappingFormat,
			mutate: func(data []byte) { data[0] ^= 0xff },
		},
		{
			name:   "wrong version",
			target: ErrWrongContentMappingFormat,
			mutate: func(data []byte) {
				binary.LittleEndian.PutUint32(data[8:12], ContentMappingVersion+1)
				repairContentMappingHeaderCRC(data)
			},
		},
		{
			name:   "wrong header size",
			target: ErrWrongContentMappingFormat,
			mutate: func(data []byte) {
				binary.LittleEndian.PutUint32(data[12:16], contentMappingHeaderSize+1)
				repairContentMappingHeaderCRC(data)
			},
		},
		{
			name:   "wrong domain",
			target: ErrWrongContentMappingFormat,
			mutate: func(data []byte) {
				data[16] ^= 1
				repairContentMappingHeaderCRC(data)
			},
		},
		{
			name:   "mandatory flags",
			target: ErrWrongContentMappingFormat,
			mutate: func(data []byte) {
				binary.LittleEndian.PutUint32(data[52:56], 1)
				repairContentMappingHeaderCRC(data)
			},
		},
		{
			name:   "reserved header byte",
			target: ErrWrongContentMappingFormat,
			mutate: func(data []byte) {
				data[60] = 1
				repairContentMappingHeaderCRC(data)
			},
		},
		{
			name:   "header checksum",
			target: ErrCorruptContentMapping,
			mutate: func(data []byte) { data[56] ^= 1 },
		},
		{
			name:   "payload checksum",
			target: ErrCorruptContentMapping,
			mutate: func(data []byte) { data[len(data)-1] ^= 1 },
		},
		{
			name:   "oversized declared payload",
			target: ErrCorruptContentMapping,
			mutate: func(data []byte) {
				binary.LittleEndian.PutUint64(
					data[40:48], maxContentMappingPayloadBytes+1)
				repairContentMappingHeaderCRC(data)
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			corrupt := append([]byte(nil), virtualBytes...)
			test.mutate(corrupt)
			if _, err := DecodeVirtualPageMap(corrupt, objects); !errors.Is(err, test.target) {
				t.Fatalf("DecodeVirtualPageMap() error = %v, want %v", err, test.target)
			}
		})
	}

	t.Run("envelope trailing byte", func(t *testing.T) {
		trailing := append(append([]byte(nil), placementBytes...), 0)
		if _, err := DecodeContentPlacementMap(trailing, objects); !errors.Is(
			err, ErrCorruptContentMapping) {
			t.Fatalf("trailing-byte error = %v", err)
		}
	})

	t.Run("payload trailing byte with valid envelope", func(t *testing.T) {
		payload, err := parseContentMappingEnvelope(
			contentPlacementMapEnvelopeSpec, placementBytes)
		if err != nil {
			t.Fatal(err)
		}
		payload = append(payload, 0)
		encoded, err := marshalContentMappingEnvelope(
			contentPlacementMapEnvelopeSpec, payload)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := DecodeContentPlacementMap(encoded, objects); !errors.Is(
			err, ErrCorruptContentMapping) {
			t.Fatalf("payload trailing-byte error = %v", err)
		}
	})

	t.Run("impossible structural run count", func(t *testing.T) {
		encoder := newContentMappingEncoder()
		encoder.text(virtual.VirtualPageMapID)
		encoder.u64(virtual.Version)
		encoder.u64(virtual.PageSize)
		encoder.u32(uint32(maxCollectionElements + 1))
		encoded, err := marshalContentMappingEnvelope(
			virtualPageMapEnvelopeSpec, encoder.bytes())
		if err != nil {
			t.Fatal(err)
		}
		if _, err := DecodeVirtualPageMap(encoded, objects); !errors.Is(
			err, ErrCorruptContentMapping) {
			t.Fatalf("impossible-count error = %v", err)
		}
	})

	t.Run("invalid UTF-8 text", func(t *testing.T) {
		encoder := newContentMappingEncoder()
		encoder.u32(1)
		encoder.fixed([]byte{0xff})
		encoder.u64(virtual.Version)
		encoder.u64(virtual.PageSize)
		encoder.count(len(virtual.Runs))
		encoded, err := marshalContentMappingEnvelope(
			virtualPageMapEnvelopeSpec, encoder.bytes())
		if err != nil {
			t.Fatal(err)
		}
		if _, err := DecodeVirtualPageMap(encoded, objects); !errors.Is(
			err, ErrCorruptContentMapping) {
			t.Fatalf("invalid UTF-8 error = %v", err)
		}
	})

	t.Run("semantic error after valid checksums", func(t *testing.T) {
		invalid := placement
		invalid.Runs = append([]ContentPlacementRun(nil), placement.Runs...)
		invalid.Runs[0].AllocationRecordID = 0
		payload, err := marshalContentPlacementMapPayload(invalid)
		if err != nil {
			t.Fatal(err)
		}
		encoded, err := marshalContentMappingEnvelope(
			contentPlacementMapEnvelopeSpec, payload)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := DecodeContentPlacementMap(encoded, objects); !errors.Is(
			err, ErrInvalidContentMapping) {
			t.Fatalf("semantic decode error = %v", err)
		}
	})
}

func repairContentMappingHeaderCRC(data []byte) {
	binary.LittleEndian.PutUint32(
		data[56:60], contentMappingHeaderCRC(data[:contentMappingHeaderSize]))
}

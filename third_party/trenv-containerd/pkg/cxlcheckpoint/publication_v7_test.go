package cxlcheckpoint

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"reflect"
	"strings"
	"testing"
)

type publicationV7Fixture struct {
	publication PublicationV7
	template    MMTemplateV7
	virtual     VirtualPageMap
	manifest    ArtifactManifestV7
	initial     ContentPlacementMap
	root        ActiveContentPlacementRoot
}

func validPublicationV7Fixture(t *testing.T) publicationV7Fixture {
	t.Helper()
	template := MMTemplateV7{
		MMTemplateID:           "mm-template-7",
		Version:                3,
		RuntimeCompatibilityID: "runtime-compatible-fixture-only",
		PageSize:               PageSize,
		VMAs: []VMAV7{{
			PagesImageID:           1,
			StartVAddr:             0x1000,
			EndVAddr:               0x6000,
			ProtectionFlags:        ProtectionRead | ProtectionWrite,
			MappingFlags:           MappingPrivate | MappingAnonymous,
			BackingKind:            BackingAnonymous,
			VirtualPageMapRunStart: 0,
			VirtualPageMapRunCount: 2,
		}},
	}
	virtual := VirtualPageMap{
		VirtualPageMapID: "virtual-map-7",
		Version:          5,
		PageSize:         PageSize,
		Runs: []VirtualPageMapRun{
			{
				PagesImageID:    1,
				StartVAddr:      0x1000,
				PageCount:       2,
				ContentObjectID: 1,
				ObjectPageIndex: 0,
			},
			{
				PagesImageID:    1,
				StartVAddr:      0x5000,
				PageCount:       1,
				ContentObjectID: 1,
				ObjectPageIndex: 2,
			},
		},
	}
	manifest := ArtifactManifestV7{
		ArtifactManifestID: "artifact-manifest-7",
		Version:            4,
		Entries: []ArtifactEntryV7{
			{
				Path:            "a.bin",
				Type:            ArtifactRegular,
				Mode:            0o644,
				UID:             1000,
				GID:             1000,
				ByteLength:      2000,
				ContentObjectID: 2,
				ContentOffset:   0,
			},
			{
				Path:            "b.bin",
				Type:            ArtifactRegular,
				Mode:            0o600,
				UID:             1000,
				GID:             1000,
				ByteLength:      3000,
				ContentObjectID: 2,
				ContentOffset:   2000,
			},
			{Path: "dir", Type: ArtifactDirectory, Mode: 0o755},
			{Path: "link", Type: ArtifactSymlink, Mode: 0o777, LinkTarget: "/portable/absolute/target"},
		},
	}

	templateBytes, err := CanonicalMMTemplateV7Bytes(template)
	if err != nil {
		t.Fatalf("CanonicalMMTemplateV7Bytes(): %v", err)
	}
	mappingObjects := []ContentObject{
		{ObjectID: 1, Kind: ContentMemory, ByteLength: 3 * PageSize, LogicalPageStart: 0, PageCount: 3},
		{ObjectID: 2, Kind: ContentArtifact, ByteLength: 5000, LogicalPageStart: 3, PageCount: 2},
		{ObjectID: 3, Kind: ContentRestoreBlob, ByteLength: 1000, LogicalPageStart: 5, PageCount: 1},
	}
	virtualBytes, err := CanonicalVirtualPageMapBytes(virtual, mappingObjects)
	if err != nil {
		t.Fatalf("CanonicalVirtualPageMapBytes(): %v", err)
	}
	manifestBytes, err := CanonicalArtifactManifestV7Bytes(manifest)
	if err != nil {
		t.Fatalf("CanonicalArtifactManifestV7Bytes(): %v", err)
	}

	publication := PublicationV7{
		CheckpointID:     "checkpoint-7",
		ImmutableGraphID: "immutable-graph-7",
		DedupDomainID:    "dedup-domain-7",
		SharingPolicyID:  "same-tenant-verified-content-v1",
		InitialAllocation: InitialAllocationV7{
			OwnerID:            "owner-a",
			OwnerEpoch:         11,
			AllocationRecordID: 29,
			TotalPages:         17,
			Devices: []AllocationDeviceV7{
				{DeviceUUID: "device-a", DataPageCount: 128},
				{DeviceUUID: "device-b", DataPageCount: 128},
			},
			Extents: []AllocationExtentV7{
				{DeviceIndex: 0, StartDataPageIndex: 10, PageCount: 2, LogicalPageStart: 0},
				{DeviceIndex: 1, StartDataPageIndex: 20, PageCount: 3, LogicalPageStart: 2},
				{DeviceIndex: 0, StartDataPageIndex: 30, PageCount: 4, LogicalPageStart: 5},
				{DeviceIndex: 1, StartDataPageIndex: 40, PageCount: 1, LogicalPageStart: 9},
				{DeviceIndex: 0, StartDataPageIndex: 40, PageCount: 3, LogicalPageStart: 10},
				{DeviceIndex: 1, StartDataPageIndex: 50, PageCount: 4, LogicalPageStart: 13},
			},
		},
		Objects: []ContentObjectV7{
			{ObjectID: 1, Kind: ContentMemoryPayloadV7, ImmutableByteLength: 3 * PageSize, LogicalPageStart: 0, CapacityPages: 3},
			{ObjectID: 2, Kind: ContentArtifactPayloadV7, ImmutableByteLength: 5000, LogicalPageStart: 3, CapacityPages: 2},
			{ObjectID: 3, Kind: ContentRestoreBlobPayloadV7, ImmutableByteLength: 1000, LogicalPageStart: 5, CapacityPages: 1},
			{ObjectID: 4, Kind: ContentMMTemplateMetadataV7, ImmutableByteLength: uint64(len(templateBytes)), LogicalPageStart: 6, CapacityPages: 1},
			{ObjectID: 5, Kind: ContentVirtualPageMapMetadataV7, ImmutableByteLength: uint64(len(virtualBytes)), LogicalPageStart: 7, CapacityPages: 1},
			{ObjectID: 6, Kind: ContentArtifactManifestMetadataV7, ImmutableByteLength: uint64(len(manifestBytes)), LogicalPageStart: 8, CapacityPages: 1},
			{ObjectID: 7, Kind: ContentPlacementSlotAV7, ImmutableByteLength: 0, LogicalPageStart: 9, CapacityPages: 2},
			{ObjectID: 8, Kind: ContentPlacementSlotBV7, ImmutableByteLength: 0, LogicalPageStart: 11, CapacityPages: 2},
			{ObjectID: 9, Kind: ContentPublicationV7, ImmutableByteLength: 0, LogicalPageStart: 13, CapacityPages: 4},
		},
		MMTemplate: MMTemplateRefV7{
			ObjectID: 4, MMTemplateID: template.MMTemplateID, Version: template.Version,
			SHA256: sha256.Sum256(templateBytes),
		},
		VirtualPageMap: VirtualPageMapRefV7{
			ObjectID: 5, VirtualPageMapID: virtual.VirtualPageMapID, Version: virtual.Version,
			SHA256: sha256.Sum256(virtualBytes),
		},
		ArtifactManifest: ArtifactManifestRefV7{
			ObjectID: 6, ArtifactManifestID: manifest.ArtifactManifestID, Version: manifest.Version,
			SHA256: sha256.Sum256(manifestBytes),
		},
		PlacementSlots: PlacementSlotsV7{AObjectID: 7, BObjectID: 8},
	}
	if err := publication.Validate(); err != nil {
		t.Fatalf("PublicationV7.Validate(): %v", err)
	}
	initial, err := publication.InitialContentPlacementMap("initial-placement-7", 1)
	if err != nil {
		t.Fatalf("InitialContentPlacementMap(): %v", err)
	}
	publicationBytes, err := CanonicalPublicationV7Bytes(publication)
	if err != nil {
		t.Fatalf("CanonicalPublicationV7Bytes(): %v", err)
	}
	initialBytes, err := CanonicalContentPlacementMapBytes(initial, mappingObjects)
	if err != nil {
		t.Fatalf("CanonicalContentPlacementMapBytes(): %v", err)
	}
	deviceDigest, err := DeviceTableDigest(initial.Devices)
	if err != nil {
		t.Fatalf("DeviceTableDigest(): %v", err)
	}
	root := ActiveContentPlacementRoot{
		State:                      ActiveContentPlacementRootCommitted,
		RootID:                     "active-root-7",
		RootVersion:                1,
		CheckpointID:               publication.CheckpointID,
		ImmutablePublicationLength: uint64(len(publicationBytes)),
		ImmutablePublicationSHA256: sha256.Sum256(publicationBytes),
		VirtualPageMapID:           virtual.VirtualPageMapID,
		VirtualPageMapVersion:      virtual.Version,
		VirtualPageMapLength:       uint64(len(virtualBytes)),
		VirtualPageMapSHA256:       sha256.Sum256(virtualBytes),
		ActiveMappingSlot:          MappingSlotA,
		ContentPlacementMapID:      initial.ContentPlacementMapID,
		ContentPlacementMapVersion: initial.Version,
		ContentPlacementMapLength:  uint64(len(initialBytes)),
		ContentPlacementMapSHA256:  sha256.Sum256(initialBytes),
		PlacementDeviceTableSHA256: deviceDigest,
	}
	return publicationV7Fixture{
		publication: publication,
		template:    template,
		virtual:     virtual,
		manifest:    manifest,
		initial:     initial,
		root:        root,
	}
}

func clonePublicationV7Fixture(source publicationV7Fixture) publicationV7Fixture {
	clone := source
	clone.publication.Objects = append([]ContentObjectV7(nil), source.publication.Objects...)
	clone.publication.InitialAllocation.Devices = append(
		[]AllocationDeviceV7(nil), source.publication.InitialAllocation.Devices...)
	clone.publication.InitialAllocation.Extents = append(
		[]AllocationExtentV7(nil), source.publication.InitialAllocation.Extents...)
	clone.template.VMAs = append([]VMAV7(nil), source.template.VMAs...)
	clone.virtual.Runs = append([]VirtualPageMapRun(nil), source.virtual.Runs...)
	clone.manifest.Entries = append([]ArtifactEntryV7(nil), source.manifest.Entries...)
	clone.initial.Devices = append([]Device(nil), source.initial.Devices...)
	clone.initial.Runs = append([]ContentPlacementRun(nil), source.initial.Runs...)
	return clone
}

func TestPublicationV7CanonicalRoundTripAndWireSeparation(t *testing.T) {
	fixture := validPublicationV7Fixture(t)
	first, err := CanonicalPublicationV7Bytes(fixture.publication)
	if err != nil {
		t.Fatalf("CanonicalPublicationV7Bytes(first): %v", err)
	}
	second, err := CanonicalPublicationV7Bytes(fixture.publication)
	if err != nil {
		t.Fatalf("CanonicalPublicationV7Bytes(second): %v", err)
	}
	if !bytes.Equal(first, second) {
		t.Fatal("TRPUB007 encoding is not deterministic")
	}
	if got := string(first[0:8]); got != PublicationV7MagicString {
		t.Fatalf("magic = %q", got)
	}
	if got := string(first[16:40]); got != PublicationV7Domain {
		t.Fatalf("domain = %q", got)
	}
	if got := binary.LittleEndian.Uint32(first[12:16]); got != publicationV7HeaderSize {
		t.Fatalf("header size = %d", got)
	}
	if uint64(len(first)) > MaxPublicationV7Bytes {
		t.Fatalf("encoded publication is %d bytes", len(first))
	}
	size, err := CanonicalPublicationV7Size(fixture.publication)
	if err != nil || size != uint64(len(first)) {
		t.Fatalf("CanonicalPublicationV7Size() = %d, %v", size, err)
	}
	decoded, err := DecodePublicationV7(first)
	if err != nil {
		t.Fatalf("DecodePublicationV7(): %v", err)
	}
	if !reflect.DeepEqual(decoded, fixture.publication) {
		t.Fatalf("round trip differs:\n got %#v\nwant %#v", decoded, fixture.publication)
	}
	if _, err := Decode(first); !errors.Is(err, ErrWrongFormat) {
		t.Fatalf("V6 decoder accepted TRPUB007: %v", err)
	}
	if _, err := DecodeVirtualPageMap(first, nil); !errors.Is(err, ErrWrongContentMappingFormat) {
		t.Fatalf("VPM decoder accepted TRPUB007: %v", err)
	}
	for _, forbidden := range [][]byte{
		[]byte("/dev/dax"),
		[]byte("runtime-compatible-fixture-only"),
		[]byte("a.bin"),
		[]byte("/portable/absolute/target"),
	} {
		if bytes.Contains(first, forbidden) {
			t.Fatalf("publication embeds local path or standalone metadata bytes %q", forbidden)
		}
	}
	typeOfPublication := reflect.TypeOf(fixture.publication)
	if _, exists := typeOfPublication.FieldByName("ContractID"); exists {
		t.Fatal("PublicationV7 unexpectedly embeds a ContractID before static-root ABI binding exists")
	}
	for index := 0; index < typeOfPublication.NumField(); index++ {
		field := typeOfPublication.Field(index)
		if strings.Contains(strings.ToLower(field.Name), "path") {
			t.Fatalf("PublicationV7 has host-local path field %s", field.Name)
		}
		if field.Type == reflect.TypeOf(VirtualPageMap{}) ||
			field.Type == reflect.TypeOf(ContentPlacementMap{}) {
			t.Fatalf("PublicationV7 embeds a complete mapping in field %s", field.Name)
		}
	}
}

func TestPublicationV7ValidationRejectsCanonicalityAndControlViolations(t *testing.T) {
	base := validPublicationV7Fixture(t)
	tests := []struct {
		name   string
		mutate func(*PublicationV7)
	}{
		{"identity-empty", func(p *PublicationV7) { p.DedupDomainID = "" }},
		{"identity-leading-space", func(p *PublicationV7) { p.SharingPolicyID = " policy" }},
		{"identity-control", func(p *PublicationV7) { p.CheckpointID = "checkpoint\n" }},
		{"device-order", func(p *PublicationV7) {
			p.InitialAllocation.Devices[0], p.InitialAllocation.Devices[1] = p.InitialAllocation.Devices[1], p.InitialAllocation.Devices[0]
		}},
		{"device-duplicate", func(p *PublicationV7) {
			p.InitialAllocation.Devices[1].DeviceUUID = p.InitialAllocation.Devices[0].DeviceUUID
		}},
		{"device-local-path", func(p *PublicationV7) { p.InitialAllocation.Devices[0].DeviceUUID = "/dev/dax0.0" }},
		{"unused-compact-device", func(p *PublicationV7) {
			p.InitialAllocation.Devices = append(p.InitialAllocation.Devices,
				AllocationDeviceV7{DeviceUUID: "device-c", DataPageCount: 128})
		}},
		{"extent-logical-gap", func(p *PublicationV7) { p.InitialAllocation.Extents[1].LogicalPageStart++ }},
		{"extent-device-index", func(p *PublicationV7) { p.InitialAllocation.Extents[0].DeviceIndex = 2 }},
		{"extent-capacity", func(p *PublicationV7) { p.InitialAllocation.Extents[0].StartDataPageIndex = 127 }},
		{"extent-physical-overlap", func(p *PublicationV7) { p.InitialAllocation.Extents[4].StartDataPageIndex = 31 }},
		{"coalescible-extents", func(p *PublicationV7) {
			p.InitialAllocation.Extents[1].DeviceIndex = 0
			p.InitialAllocation.Extents[1].StartDataPageIndex = 12
		}},
		{"object-order", func(p *PublicationV7) { p.Objects[0], p.Objects[1] = p.Objects[1], p.Objects[0] }},
		{"object-logical-gap", func(p *PublicationV7) { p.Objects[1].LogicalPageStart++ }},
		{"memory-not-full", func(p *PublicationV7) { p.Objects[0].ImmutableByteLength-- }},
		{"payload-zero", func(p *PublicationV7) { p.Objects[1].ImmutableByteLength = 0 }},
		{"metadata-zero", func(p *PublicationV7) { p.Objects[3].ImmutableByteLength = 0 }},
		{"slot-nonzero-length", func(p *PublicationV7) { p.Objects[6].ImmutableByteLength = 1 }},
		{"publication-nonzero-length", func(p *PublicationV7) { p.Objects[8].ImmutableByteLength = 1 }},
		{"missing-memory", func(p *PublicationV7) { p.Objects[0].Kind = ContentArtifactPayloadV7 }},
		{"duplicate-control-kind", func(p *PublicationV7) { p.Objects[5].Kind = ContentMMTemplateMetadataV7 }},
		{"slot-reference-substitution", func(p *PublicationV7) { p.PlacementSlots.AObjectID = 8 }},
		{"slot-capacity-mismatch", func(p *PublicationV7) { p.Objects[7].CapacityPages = 1 }},
		{"typed-ref-wrong-kind", func(p *PublicationV7) { p.MMTemplate.ObjectID = 5 }},
		{"typed-ref-zero-digest", func(p *PublicationV7) { p.VirtualPageMap.SHA256 = [sha256.Size]byte{} }},
		{"publication-slot-too-small-for-canonical-self", func(p *PublicationV7) {
			p.CheckpointID = strings.Repeat("c", MaxPublicationV7IdentityBytes)
			p.ImmutableGraphID = strings.Repeat("g", MaxPublicationV7IdentityBytes)
			p.DedupDomainID = strings.Repeat("d", MaxPublicationV7IdentityBytes)
			p.SharingPolicyID = strings.Repeat("s", MaxPublicationV7IdentityBytes)
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			candidate := clonePublicationV7Fixture(base).publication
			test.mutate(&candidate)
			if err := candidate.Validate(); !errors.Is(err, ErrInvalidPublicationV7) {
				t.Fatalf("Validate() error = %v", err)
			}
			if _, err := CanonicalPublicationV7Bytes(candidate); !errors.Is(err, ErrInvalidPublicationV7) {
				t.Fatalf("encoder error = %v", err)
			}
		})
	}
	invalid := base.publication
	invalid.CheckpointID = ""
	err := invalid.Validate()
	if errors.Is(err, ErrInvalid) {
		t.Fatalf("V7 validation leaked V6 ErrInvalid: %v", err)
	}
}

func TestPublicationV7ImmutableObjectCapacityIsExactCeiling(t *testing.T) {
	base := validPublicationV7Fixture(t).publication
	tests := []struct {
		name        string
		objectIndex int
		kind        ContentKindV7
	}{
		{name: "memory", objectIndex: 0, kind: ContentMemoryPayloadV7},
		{name: "artifact", objectIndex: 1, kind: ContentArtifactPayloadV7},
		{name: "restore-blob", objectIndex: 2, kind: ContentRestoreBlobPayloadV7},
		{name: "MMTemplate", objectIndex: 3, kind: ContentMMTemplateMetadataV7},
		{name: "VirtualPageMap", objectIndex: 4, kind: ContentVirtualPageMapMetadataV7},
		{name: "ArtifactManifest", objectIndex: 5, kind: ContentArtifactManifestMetadataV7},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			objects := append([]ContentObjectV7(nil), base.Objects...)
			if objects[test.objectIndex].Kind != test.kind {
				t.Fatalf("fixture object %d kind = %d, want %d",
					test.objectIndex, objects[test.objectIndex].Kind, test.kind)
			}
			objects[test.objectIndex].CapacityPages++
			for index := test.objectIndex + 1; index < len(objects); index++ {
				objects[index].LogicalPageStart++
			}
			_, _, err := validateContentObjectsV7(
				objects, base.InitialAllocation.TotalPages+1)
			if !errors.Is(err, ErrInvalidPublicationV7) ||
				!strings.Contains(err.Error(), "capacity") ||
				!strings.Contains(err.Error(), "noncanonical") {
				t.Fatalf("+1 page capacity error = %v", err)
			}
		})
	}
	for _, test := range []struct {
		name       string
		byteLength uint64
		wantPages  uint64
	}{
		{name: "one-byte", byteLength: 1, wantPages: 1},
		{name: "one-page", byteLength: PublicationV7PageSize, wantPages: 1},
		{name: "page-plus-one", byteLength: PublicationV7PageSize + 1, wantPages: 2},
		{name: "max-signed", byteLength: MaxSignedLong, wantPages: MaxSignedLong/PublicationV7PageSize + 1},
	} {
		t.Run("overflow-safe-"+test.name, func(t *testing.T) {
			pages, ok := publicationV7ImmutableCapacityPages(test.byteLength)
			if !ok || pages != test.wantPages {
				t.Fatalf("publicationV7ImmutableCapacityPages(%d) = %d, %v; want %d, true",
					test.byteLength, pages, ok, test.wantPages)
			}
		})
	}
	if _, ok := publicationV7ImmutableCapacityPages(0); ok {
		t.Fatal("zero immutable length produced a capacity")
	}
	if _, ok := publicationV7ImmutableCapacityPages(MaxSignedLong + 1); ok {
		t.Fatal("out-of-ABI immutable length produced a capacity")
	}
}

func TestPublicationV7ControlLocatorsStorageAndPayloadFailClosed(t *testing.T) {
	fixture := validPublicationV7Fixture(t)
	for _, objectID := range []uint64{1, 2, 3} {
		if _, err := fixture.publication.ControlObjectPageRuns(objectID, PageSize); !errors.Is(err, ErrInvalidPublicationV7) {
			t.Fatalf("payload object %d received an InitialAllocation locator: %v", objectID, err)
		}
	}
	// Slot A crosses device-b then device-a in the immutable allocation. Valid
	// extents are already noncoalescible, so the canonical locator has two runs.
	runs, err := fixture.publication.ControlObjectPageRuns(7, 2*PageSize)
	if err != nil {
		t.Fatalf("ControlObjectPageRuns(slot A): %v", err)
	}
	if len(runs) != 2 || runs[0].FirstPage.DeviceUUID != "device-b" ||
		runs[0].FirstPage.DataPageIndex != 40 || runs[0].PageCount != 1 ||
		runs[1].FirstPage.DeviceUUID != "device-a" ||
		runs[1].FirstPage.DataPageIndex != 40 || runs[1].ObjectPageStart != 1 {
		t.Fatalf("fragmented slot locator = %#v", runs)
	}
	if _, err := fixture.publication.ControlObjectPageRuns(
		4, fixture.publication.Objects[3].ImmutableByteLength+1); !errors.Is(err, ErrInvalidPublicationV7) {
		t.Fatalf("metadata exact-length substitution accepted: %v", err)
	}
	storage, err := EncodePublicationV7ForStorage(fixture.publication)
	if err != nil {
		t.Fatalf("EncodePublicationV7ForStorage(): %v", err)
	}
	if storage.ContentObjectID != 9 || len(storage.PageRuns) != 1 ||
		storage.PageRuns[0].FirstPage.DeviceUUID != "device-b" ||
		storage.PageRuns[0].FirstPage.DataPageIndex != 50 {
		t.Fatalf("publication bootstrap = %#v", storage)
	}
	if storage.PageRuns[0].PageCount !=
		(uint64(len(storage.ExactBytes))+PageSize-1)/PageSize {
		t.Fatalf("bootstrap runs cover %d pages for %d exact bytes",
			storage.PageRuns[0].PageCount, len(storage.ExactBytes))
	}
	if len(storage.PaddedWriteRuns) != 1 ||
		storage.PaddedWriteRuns[0].PageCount != storage.CapacityPages {
		t.Fatalf("padded write runs do not cover the complete slot: %#v",
			storage.PaddedWriteRuns)
	}
	if uint64(len(storage.PaddedBytes)) != storage.CapacityPages*PageSize ||
		!bytes.Equal(storage.PaddedBytes[:len(storage.ExactBytes)], storage.ExactBytes) ||
		!publicationV7AllZero(storage.PaddedBytes[len(storage.ExactBytes):]) ||
		storage.SHA256 != sha256.Sum256(storage.ExactBytes) {
		t.Fatal("publication storage does not contain exact bytes plus zero-only padding")
	}
	if _, err := fixture.publication.ControlObjectPageRuns(9, uint64(len(storage.ExactBytes))+1); !errors.Is(err, ErrInvalidPublicationV7) {
		t.Fatalf("publication self-length substitution accepted: %v", err)
	}
}

func TestPublicationV7InitialPlacementIsDumpOnlyAndExact(t *testing.T) {
	fixture := validPublicationV7Fixture(t)
	objects, err := fixture.publication.MappingContentObjects()
	if err != nil {
		t.Fatal(err)
	}
	if len(objects) != 3 {
		t.Fatalf("mapping adapter returned %d objects, want only three payload objects", len(objects))
	}
	for _, object := range objects {
		if !placementCoveredKind(object.Kind) {
			t.Fatalf("mapping adapter leaked excluded kind %d", object.Kind)
		}
	}
	if err := fixture.initial.Validate(objects); err != nil {
		t.Fatalf("initial map Validate(): %v", err)
	}
	if err := fixture.publication.CrossCheckInitialContentPlacementMap(fixture.initial); err != nil {
		t.Fatalf("CrossCheckInitialContentPlacementMap(): %v", err)
	}
	if len(fixture.initial.Devices) != 2 || len(fixture.initial.Runs) != 4 {
		t.Fatalf("initial multi-DAX placement = %#v", fixture.initial)
	}
	mutated := fixture.initial
	mutated.Runs = append([]ContentPlacementRun(nil), fixture.initial.Runs...)
	mutated.Runs[0].DataPageIndex++
	if err := fixture.publication.CrossCheckInitialContentPlacementMap(mutated); !errors.Is(err, ErrInvalidPublicationV7) {
		t.Fatalf("substituted initial placement accepted: %v", err)
	}
	// This API intentionally has no object/page lookup. After a dedup root
	// switch, payload resolution is exclusively ContentPlacementMap authority;
	// ControlObjectPageRuns above rejects all three payload kinds.
}

func TestPublicationV7ImmutableGraphAndTypedReferenceCrossChecks(t *testing.T) {
	base := validPublicationV7Fixture(t)
	if err := base.publication.CrossCheckImmutableGraph(
		base.template, base.virtual, base.manifest); err != nil {
		t.Fatalf("CrossCheckImmutableGraph(): %v", err)
	}
	tests := []struct {
		name   string
		mutate func(*publicationV7Fixture)
	}{
		{"MMTemplate-digest", func(f *publicationV7Fixture) { f.publication.MMTemplate.SHA256[0] ^= 1 }},
		{"MMTemplate-length", func(f *publicationV7Fixture) { f.publication.Objects[3].ImmutableByteLength++ }},
		{"MMTemplate-semantic-id", func(f *publicationV7Fixture) { f.template.MMTemplateID = "other-template" }},
		{"VirtualPageMap-digest", func(f *publicationV7Fixture) { f.publication.VirtualPageMap.SHA256[0] ^= 1 }},
		{"VirtualPageMap-version", func(f *publicationV7Fixture) { f.virtual.Version++ }},
		{"VirtualPageMap-bytes", func(f *publicationV7Fixture) { f.virtual.Runs[1].StartVAddr = 0x4000 }},
		{"ArtifactManifest-digest", func(f *publicationV7Fixture) { f.publication.ArtifactManifest.SHA256[0] ^= 1 }},
		{"ArtifactManifest-version", func(f *publicationV7Fixture) { f.manifest.Version++ }},
		{"ArtifactManifest-gap", func(f *publicationV7Fixture) { f.manifest.Entries[1].ContentOffset++ }},
		{"typed-ref-kind-substitution", func(f *publicationV7Fixture) { f.publication.VirtualPageMap.ObjectID = 4 }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			candidate := clonePublicationV7Fixture(base)
			test.mutate(&candidate)
			if err := candidate.publication.CrossCheckImmutableGraph(
				candidate.template, candidate.virtual, candidate.manifest); err == nil {
				t.Fatal("substitution unexpectedly passed")
			}
		})
	}
}

func TestPublicationV7ActiveRootImmutableBindingAndSlotCapacity(t *testing.T) {
	base := validPublicationV7Fixture(t)
	if err := base.publication.CrossCheckActivePlacementRootImmutableBindings(
		base.root, base.virtual); err != nil {
		t.Fatalf("root immutable cross-check: %v", err)
	}
	tests := []struct {
		name   string
		mutate func(*publicationV7Fixture)
	}{
		{"publication-bytes", func(f *publicationV7Fixture) { f.publication.SharingPolicyID = "different-policy" }},
		{"root-checkpoint", func(f *publicationV7Fixture) { f.root.CheckpointID = "other-checkpoint" }},
		{"root-publication-length", func(f *publicationV7Fixture) { f.root.ImmutablePublicationLength++ }},
		{"root-publication-digest", func(f *publicationV7Fixture) { f.root.ImmutablePublicationSHA256[0] ^= 1 }},
		{"root-VPM-ID", func(f *publicationV7Fixture) { f.root.VirtualPageMapID = "other-map" }},
		{"root-VPM-length", func(f *publicationV7Fixture) { f.root.VirtualPageMapLength++ }},
		{"root-VPM-digest", func(f *publicationV7Fixture) { f.root.VirtualPageMapSHA256[0] ^= 1 }},
		{"root-selected-slot-capacity", func(f *publicationV7Fixture) { f.root.ContentPlacementMapLength = 3 * PageSize }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			candidate := clonePublicationV7Fixture(base)
			test.mutate(&candidate)
			if err := candidate.publication.CrossCheckActivePlacementRootImmutableBindings(
				candidate.root, candidate.virtual); !errors.Is(err, ErrInvalidPublicationV7) {
				t.Fatalf("error = %v", err)
			}
		})
	}
	for _, slot := range []MappingSlotName{MappingSlotA, MappingSlotB} {
		candidate := clonePublicationV7Fixture(base)
		candidate.root.ActiveMappingSlot = slot
		if err := candidate.publication.CrossCheckActivePlacementRootImmutableBindings(
			candidate.root, candidate.virtual); err != nil {
			t.Fatalf("slot %d: %v", slot, err)
		}
	}
}

func TestPublicationV7EnvelopeRejectsCorruptionAndCountAttacks(t *testing.T) {
	fixture := validPublicationV7Fixture(t)
	encoded, err := CanonicalPublicationV7Bytes(fixture.publication)
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name   string
		mutate func([]byte) []byte
		wrong  bool
	}{
		{"magic", func(data []byte) []byte { data[0] ^= 1; return data }, true},
		{"version", func(data []byte) []byte {
			binary.LittleEndian.PutUint32(data[8:12], 8)
			repairPublicationV7Header(data)
			return data
		}, true},
		{"header-size", func(data []byte) []byte {
			binary.LittleEndian.PutUint32(data[12:16], 65)
			repairPublicationV7Header(data)
			return data
		}, true},
		{"domain", func(data []byte) []byte { data[16] ^= 1; repairPublicationV7Header(data); return data }, true},
		{"flags", func(data []byte) []byte {
			binary.LittleEndian.PutUint32(data[52:56], 1)
			repairPublicationV7Header(data)
			return data
		}, true},
		{"reserved", func(data []byte) []byte { data[60] = 1; repairPublicationV7Header(data); return data }, true},
		{"header-crc", func(data []byte) []byte { data[56] ^= 1; return data }, false},
		{"payload-crc", func(data []byte) []byte { data[len(data)-1] ^= 1; return data }, false},
		{"truncated", func(data []byte) []byte { return data[:len(data)-1] }, false},
		{"trailing", func(data []byte) []byte { return append(data, 0) }, false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			candidate := test.mutate(append([]byte(nil), encoded...))
			_, err := DecodePublicationV7(candidate)
			want := ErrCorruptPublicationV7
			if test.wrong {
				want = ErrWrongPublicationV7Format
			}
			if !errors.Is(err, want) {
				t.Fatalf("DecodePublicationV7() error = %v, want %v", err, want)
			}
		})
	}

	countAttack := append([]byte(nil), encoded...)
	offset := int(publicationV7HeaderSize)
	for index := 0; index < 4; index++ {
		offset = skipPublicationV7Text(t, countAttack, offset)
	}
	offset = skipPublicationV7Text(t, countAttack, offset) // allocation Owner
	offset += 24                                           // epoch, record, total
	binary.LittleEndian.PutUint32(countAttack[offset:offset+4], MaxPublicationV7Devices+1)
	repairPublicationV7Checksums(countAttack)
	if _, err := DecodePublicationV7(countAttack); !errors.Is(err, ErrCorruptPublicationV7) {
		t.Fatalf("oversized device count error = %v", err)
	}

	lengthAttack := append([]byte(nil), encoded...)
	binary.LittleEndian.PutUint32(
		lengthAttack[publicationV7HeaderSize:publicationV7HeaderSize+4], ^uint32(0))
	repairPublicationV7Checksums(lengthAttack)
	if _, err := DecodePublicationV7(lengthAttack); !errors.Is(err, ErrCorruptPublicationV7) {
		t.Fatalf("oversized text length error = %v", err)
	}
	oversizedIdentityPayload := make([]byte, 4+MaxPublicationV7IdentityBytes+1)
	binary.LittleEndian.PutUint32(
		oversizedIdentityPayload[0:4], MaxPublicationV7IdentityBytes+1)
	for index := 4; index < len(oversizedIdentityPayload); index++ {
		oversizedIdentityPayload[index] = 'x'
	}
	oversizedIdentityEnvelope, err := marshalPublicationV7Envelope(oversizedIdentityPayload)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecodePublicationV7(oversizedIdentityEnvelope); !errors.Is(err, ErrCorruptPublicationV7) {
		t.Fatalf("4097-byte in-envelope identity error = %v", err)
	}

	declaredTooLarge := append([]byte(nil), encoded[:publicationV7HeaderSize]...)
	binary.LittleEndian.PutUint64(
		declaredTooLarge[40:48], maxPublicationV7PayloadBytes+1)
	repairPublicationV7Header(declaredTooLarge)
	if _, err := DecodePublicationV7(declaredTooLarge); !errors.Is(err, ErrCorruptPublicationV7) {
		t.Fatalf("oversized declared payload error = %v", err)
	}

	for length := 0; length < len(encoded); length++ {
		if _, err := DecodePublicationV7(encoded[:length]); err == nil {
			t.Fatalf("truncated prefix %d unexpectedly decoded", length)
		}
	}
}

func TestPublicationV7WireBoundsAreExact(t *testing.T) {
	if len(PublicationV7MagicString) != 8 || len(PublicationV7Domain) != 24 {
		t.Fatalf("wire identity lengths are magic=%d domain=%d",
			len(PublicationV7MagicString), len(PublicationV7Domain))
	}
	if PublicationV7EnvelopeHeaderBytes != 64 || MaxPublicationV7Bytes != 8<<20 {
		t.Fatalf("wire bounds are header=%d max=%d",
			PublicationV7EnvelopeHeaderBytes, MaxPublicationV7Bytes)
	}
	if PublicationV7PageSize != 4096 {
		t.Fatalf("implicit publication page size = %d", PublicationV7PageSize)
	}
	if PublicationV7PageSize != PageSize {
		t.Fatalf("implicit publication page size = %d", PublicationV7PageSize)
	}
	if PublicationV7MagicString == MagicString ||
		PublicationV7MagicString == ActiveContentPlacementRootMagicString ||
		PublicationV7MagicString == VirtualPageMapMagicString {
		t.Fatal("TRPUB007 is not domain-separated from existing envelopes")
	}
}

func skipPublicationV7Text(t *testing.T, data []byte, offset int) int {
	t.Helper()
	if offset+4 > len(data) {
		t.Fatal("test text offset is truncated")
	}
	length := int(binary.LittleEndian.Uint32(data[offset : offset+4]))
	offset += 4 + length
	if offset > len(data) {
		t.Fatal("test text exceeds data")
	}
	return offset
}

func repairPublicationV7Checksums(data []byte) {
	payload := data[publicationV7HeaderSize:]
	binary.LittleEndian.PutUint32(data[48:52], checksumCRC32C(payload))
	repairPublicationV7Header(data)
}

func repairPublicationV7Header(data []byte) {
	if len(data) >= int(publicationV7HeaderSize) {
		binary.LittleEndian.PutUint32(
			data[56:60], publicationV7HeaderCRC(data[:publicationV7HeaderSize]))
	}
}

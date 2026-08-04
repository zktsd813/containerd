package cxlcheckpoint

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

func TestInitialPublicationV7FragmentedTwoDAXHappyPath(t *testing.T) {
	input := validInitialPublicationV7TestInput(t)
	plan, err := BuildInitialPublicationV7Plan(input)
	if err != nil {
		t.Fatalf("BuildInitialPublicationV7Plan: %v", err)
	}
	if err := plan.Validate(); err != nil {
		t.Fatalf("plan.Validate: %v", err)
	}
	if len(plan.ObjectWrites) != len(input.Publication.Objects) {
		t.Fatalf("object write count = %d, want %d", len(plan.ObjectWrites), len(input.Publication.Objects))
	}

	var kindCounts [V7StorageContentKindCount + 1]int
	for index, write := range plan.ObjectWrites {
		object := input.Publication.Objects[index]
		if write.ObjectID != object.ObjectID || write.Kind != object.Kind ||
			write.LogicalPageStart != object.LogicalPageStart {
			t.Fatalf("write[%d] = %#v, publication object = %#v", index, write, object)
		}
		kindCounts[int(write.Kind)]++
		lookedUp, ok := plan.ObjectWriteByID(write.ObjectID)
		if !ok || !reflect.DeepEqual(lookedUp, write) {
			t.Fatalf("ObjectWriteByID(%d) = %#v, %v", write.ObjectID, lookedUp, ok)
		}
	}
	for kind := V7StorageFirstContentKind; kind <= V7StorageLastContentKind; kind++ {
		if kindCounts[int(kind)] != 1 {
			t.Fatalf("happy-path kind %d count = %d, want 1", kind, kindCounts[int(kind)])
		}
	}
	if _, ok := plan.ObjectWriteByID(0); ok {
		t.Fatal("ObjectWriteByID accepted an absent object")
	}

	if len(plan.InitialContentPlacementMap.Devices) != 2 ||
		plan.InitialContentPlacementMap.Devices[0].DeviceUUID != "device-a" ||
		plan.InitialContentPlacementMap.Devices[1].DeviceUUID != "device-b" {
		t.Fatalf("initial two-DAX device table = %#v", plan.InitialContentPlacementMap.Devices)
	}
	slotA := mustInitialPublicationV7WriteByID(t, plan, input.Publication.PlacementSlots.AObjectID)
	if len(slotA.CapacityPageRuns) != 2 ||
		slotA.CapacityPageRuns[0].FirstPage.DeviceUUID != "device-b" ||
		slotA.CapacityPageRuns[1].FirstPage.DeviceUUID != "device-a" {
		t.Fatalf("fragmented slot-A capacity runs = %#v", slotA.CapacityPageRuns)
	}
	if plan.ActiveContentPlacementRoot.State != ActiveContentPlacementRootCommitted ||
		plan.ActiveContentPlacementRoot.ActiveMappingSlot != MappingSlotA ||
		plan.ActiveContentPlacementRoot.RootVersion != InitialPublicationV7SemanticVersion {
		t.Fatalf("initial active root = %#v", plan.ActiveContentPlacementRoot)
	}
	if plan.StaticPublicationRoot.State != StaticPublicationRootV7Committed {
		t.Fatalf("static publication root state = %d", plan.StaticPublicationRoot.State)
	}
	if got := plan.RequiredVisibilityOrder(); got != [4]InitialPublicationV7VisibilityRequirement{
		InitialPublicationV7AllDAXBytesDurable,
		InitialPublicationV7OwnerAllocationCommitted,
		InitialPublicationV7StaticRootCreated,
		InitialPublicationV7ActiveRootGenesisCreated,
	} {
		t.Fatalf("visibility requirements = %#v", got)
	}

	decodedStatic, err := DecodeStaticPublicationRootV7(plan.StaticPublicationRootBytes)
	if err != nil || !reflect.DeepEqual(decodedStatic, plan.StaticPublicationRoot) {
		t.Fatalf("DecodeStaticPublicationRootV7 = %#v, %v", decodedStatic, err)
	}
	decodedActive, err := DecodeActiveContentPlacementRoot(plan.ActiveContentPlacementRootBytes)
	if err != nil || decodedActive != plan.ActiveContentPlacementRoot {
		t.Fatalf("DecodeActiveContentPlacementRoot = %#v, %v", decodedActive, err)
	}

	// The returned plan is detached from every caller-owned input slice.
	input.Publication.Objects[0].ObjectID = MaxSignedLong
	input.Publication.InitialAllocation.Extents[0].PageCount = 1
	input.MMTemplate.VMAs[0].EndVAddr = input.MMTemplate.VMAs[0].StartVAddr
	input.VirtualPageMap.Runs[0].PageCount = 1
	input.ArtifactManifest.Entries[0].Path = "substituted"
	if err := plan.Validate(); err != nil {
		t.Fatalf("caller mutation changed detached plan: %v", err)
	}
}

func TestInitialPublicationV7ExactBytesTailPaddingAndNeverPublishedB(t *testing.T) {
	input := validInitialPublicationV7TestInput(t)
	plan, err := BuildInitialPublicationV7Plan(input)
	if err != nil {
		t.Fatalf("BuildInitialPublicationV7Plan: %v", err)
	}
	contentObjects, err := plan.Publication.MappingContentObjects()
	if err != nil {
		t.Fatalf("MappingContentObjects: %v", err)
	}
	templateBytes, err := CanonicalMMTemplateV7Bytes(plan.MMTemplate)
	if err != nil {
		t.Fatalf("CanonicalMMTemplateV7Bytes: %v", err)
	}
	virtualBytes, err := CanonicalVirtualPageMapBytes(plan.VirtualPageMap, contentObjects)
	if err != nil {
		t.Fatalf("CanonicalVirtualPageMapBytes: %v", err)
	}
	manifestBytes, err := CanonicalArtifactManifestV7Bytes(plan.ArtifactManifest)
	if err != nil {
		t.Fatalf("CanonicalArtifactManifestV7Bytes: %v", err)
	}
	placementBytes, err := CanonicalContentPlacementMapBytes(
		plan.InitialContentPlacementMap, contentObjects)
	if err != nil {
		t.Fatalf("CanonicalContentPlacementMapBytes: %v", err)
	}
	publicationStorage, err := EncodePublicationV7ForStorage(plan.Publication)
	if err != nil {
		t.Fatalf("EncodePublicationV7ForStorage: %v", err)
	}
	canonicalByKind := map[ContentKindV7][]byte{
		ContentMMTemplateMetadataV7:       templateBytes,
		ContentVirtualPageMapMetadataV7:   virtualBytes,
		ContentArtifactManifestMetadataV7: manifestBytes,
		ContentPlacementSlotAV7:           placementBytes,
		ContentPublicationV7:              publicationStorage.ExactBytes,
	}

	for _, write := range plan.ObjectWrites {
		if write.CapacityBytes != write.CapacityPages*PublicationV7PageSize ||
			write.ZeroTail.ByteOffset != write.ExactByteLength ||
			write.ZeroTail.ByteLength != write.CapacityBytes-write.ExactByteLength {
			t.Fatalf("object %d has ambiguous exact/tail/capacity: %#v", write.ObjectID, write)
		}
		if got := initialPublicationV7TestRunPages(write.CapacityPageRuns); got != write.CapacityPages {
			t.Fatalf("object %d capacity runs cover %d pages, want %d", write.ObjectID, got, write.CapacityPages)
		}
		wantExactPages := uint64(0)
		if write.ExactByteLength != 0 {
			wantExactPages = (write.ExactByteLength + PublicationV7PageSize - 1) / PublicationV7PageSize
		}
		if got := initialPublicationV7TestRunPages(write.ExactPageRuns); got != wantExactPages {
			t.Fatalf("object %d exact runs cover %d pages, want %d", write.ObjectID, got, wantExactPages)
		}
		if write.Kind.placementPayload() {
			if write.WriteSource != InitialPublicationV7ExternalPayload || write.CanonicalBytes != nil {
				t.Fatalf("payload object %d carries bytes: %#v", write.ObjectID, write)
			}
			continue
		}
		if write.Kind == ContentPlacementSlotBV7 {
			continue
		}
		if write.WriteSource != InitialPublicationV7CanonicalControlBytes ||
			!bytes.Equal(write.CanonicalBytes, canonicalByKind[write.Kind]) {
			t.Fatalf("control object %d exact bytes mismatch", write.ObjectID)
		}
	}

	slotA := mustInitialPublicationV7WriteByID(t, plan, plan.Publication.PlacementSlots.AObjectID)
	if slotA.Kind != ContentPlacementSlotAV7 ||
		slotA.PlacementSlotState != InitialPublicationV7ActiveCommittedSlot ||
		!bytes.Equal(slotA.CanonicalBytes, placementBytes) ||
		slotA.ZeroTail.ByteLength == 0 {
		t.Fatalf("slot A plan = %#v", slotA)
	}
	slotB := mustInitialPublicationV7WriteByID(t, plan, plan.Publication.PlacementSlots.BObjectID)
	if slotB.Kind != ContentPlacementSlotBV7 ||
		slotB.WriteSource != InitialPublicationV7NeverPublishedZeroSlot ||
		slotB.PlacementSlotState != InitialPublicationV7NeverPublishedSlot ||
		slotB.ExactByteLength != 0 || slotB.CanonicalBytes != nil ||
		len(slotB.ExactPageRuns) != 0 || slotB.ZeroTail.ByteOffset != 0 ||
		slotB.ZeroTail.ByteLength != slotB.CapacityBytes {
		t.Fatalf("slot B is not wholly zero and never-published: %#v", slotB)
	}
	for index := len(publicationStorage.ExactBytes); index < len(publicationStorage.PaddedBytes); index++ {
		if publicationStorage.PaddedBytes[index] != 0 {
			t.Fatalf("publication padding byte %d is nonzero", index)
		}
	}
	publicationWrite := mustInitialPublicationV7WriteByID(t, plan, publicationStorage.ContentObjectID)
	if !bytes.Equal(publicationWrite.CanonicalBytes, publicationStorage.ExactBytes) ||
		!reflect.DeepEqual(publicationWrite.ExactPageRuns, publicationStorage.PageRuns) ||
		!reflect.DeepEqual(publicationWrite.CapacityPageRuns, publicationStorage.PaddedWriteRuns) {
		t.Fatalf("publication exact/padded plan does not match storage encoder")
	}

	// ObjectWriteByID must not expose the plan's slices.
	copyOfA := slotA
	copyOfA.CanonicalBytes[0] ^= 0xff
	copyOfA.CapacityPageRuns[0].PageCount++
	secondA := mustInitialPublicationV7WriteByID(t, plan, slotA.ObjectID)
	if bytes.Equal(copyOfA.CanonicalBytes, secondA.CanonicalBytes) ||
		reflect.DeepEqual(copyOfA.CapacityPageRuns, secondA.CapacityPageRuns) {
		t.Fatal("ObjectWriteByID did not return a defensive copy")
	}
}

func TestInitialPublicationV7SupportsRepeatedAndOptionalPayloadObjects(t *testing.T) {
	repeated := repeatedPayloadInitialPublicationV7TestInput(t)
	plan, err := BuildInitialPublicationV7Plan(repeated)
	if err != nil {
		t.Fatalf("repeated payload BuildInitialPublicationV7Plan: %v", err)
	}
	if err := plan.Validate(); err != nil {
		t.Fatalf("repeated payload plan.Validate: %v", err)
	}
	if len(plan.ObjectWrites) != 11 {
		t.Fatalf("repeated payload object writes = %d, want 11", len(plan.ObjectWrites))
	}
	counts := initialPublicationV7TestKindCounts(plan.ObjectWrites)
	if counts[ContentMemoryPayloadV7] != 2 || counts[ContentArtifactPayloadV7] != 2 ||
		counts[ContentRestoreBlobPayloadV7] != 1 {
		t.Fatalf("repeated payload counts = %#v", counts)
	}

	absentOptional := absentOptionalPayloadInitialPublicationV7TestInput(t)
	plan, err = BuildInitialPublicationV7Plan(absentOptional)
	if err != nil {
		t.Fatalf("absent optional payload BuildInitialPublicationV7Plan: %v", err)
	}
	if err := plan.Validate(); err != nil {
		t.Fatalf("absent optional payload plan.Validate: %v", err)
	}
	counts = initialPublicationV7TestKindCounts(plan.ObjectWrites)
	if counts[ContentMemoryPayloadV7] != 1 || counts[ContentArtifactPayloadV7] != 0 ||
		counts[ContentRestoreBlobPayloadV7] != 0 || len(plan.ObjectWrites) != 7 {
		t.Fatalf("optional-payload-free plan counts = %#v, writes = %d", counts, len(plan.ObjectWrites))
	}
}

func TestInitialPublicationV7RejectsIdentitySubstitutionAndNonGenesisVersions(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*InitialPublicationV7Input)
	}{
		{name: "MMTemplate identity", mutate: func(value *InitialPublicationV7Input) {
			value.MMTemplate.MMTemplateID = "substituted-template"
		}},
		{name: "VirtualPageMap identity", mutate: func(value *InitialPublicationV7Input) {
			value.VirtualPageMap.VirtualPageMapID = "substituted-vpm"
		}},
		{name: "ArtifactManifest identity", mutate: func(value *InitialPublicationV7Input) {
			value.ArtifactManifest.ArtifactManifestID = "substituted-manifest"
		}},
		{name: "checkpoint identity bound", mutate: func(value *InitialPublicationV7Input) {
			value.Publication.CheckpointID = strings.Repeat("c", MaxInitialPublicationV7IdentityBytes+1)
		}},
		{name: "device identity bound", mutate: func(value *InitialPublicationV7Input) {
			value.Publication.InitialAllocation.Devices[0].DeviceUUID =
				strings.Repeat("a", MaxInitialPublicationV7IdentityBytes+1)
		}},
		{name: "map identity bound", mutate: func(value *InitialPublicationV7Input) {
			value.InitialContentPlacementMapID = strings.Repeat("m", MaxInitialPublicationV7IdentityBytes+1)
		}},
		{name: "active root identity bound", mutate: func(value *InitialPublicationV7Input) {
			value.InitialActivePlacementRootID = strings.Repeat("r", MaxInitialPublicationV7IdentityBytes+1)
		}},
		{name: "MMTemplate version two", mutate: func(value *InitialPublicationV7Input) {
			value.MMTemplate.Version = 2
			rebindInitialPublicationV7TestMetadata(t, value)
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			candidate := cloneInitialPublicationV7Input(validInitialPublicationV7TestInput(t))
			test.mutate(&candidate)
			if _, err := BuildInitialPublicationV7Plan(candidate); !errors.Is(err, ErrInvalidInitialPublicationV7) {
				t.Fatalf("error = %v", err)
			}
		})
	}

	atLimit := validInitialPublicationV7TestInput(t)
	atLimit.InitialContentPlacementMapID = strings.Repeat("m", MaxInitialPublicationV7IdentityBytes)
	atLimit.InitialActivePlacementRootID = strings.Repeat("r", MaxInitialPublicationV7IdentityBytes)
	if _, err := BuildInitialPublicationV7Plan(atLimit); err != nil {
		t.Fatalf("exact 256-byte identities rejected: %v", err)
	}
}

func TestInitialPublicationV7RejectsInsufficientSlotCapacity(t *testing.T) {
	input := oversizedInitialPlacementMapV7TestInput(t)
	initialMap, err := input.Publication.InitialContentPlacementMap(
		input.InitialContentPlacementMapID, InitialPublicationV7SemanticVersion)
	if err != nil {
		t.Fatalf("InitialContentPlacementMap: %v", err)
	}
	contentObjects, err := input.Publication.MappingContentObjects()
	if err != nil {
		t.Fatalf("MappingContentObjects: %v", err)
	}
	exact, err := CanonicalContentPlacementMapBytes(initialMap, contentObjects)
	if err != nil {
		t.Fatalf("CanonicalContentPlacementMapBytes: %v", err)
	}
	slotA := initialPublicationV7TestObjectByKind(t, input.Publication, ContentPlacementSlotAV7)
	capacity := slotA.CapacityPages * PublicationV7PageSize
	if uint64(len(exact)) <= capacity {
		t.Fatalf("test setup map length %d does not exceed slot-A capacity %d", len(exact), capacity)
	}
	if len(initialMap.Runs) > MaxInitialPublicationV7Runs {
		t.Fatalf("test setup uses %d runs, exceeds preflight bound", len(initialMap.Runs))
	}
	if _, err := BuildInitialPublicationV7Plan(input); !errors.Is(err, ErrInvalidInitialPublicationV7) ||
		!strings.Contains(err.Error(), "slot capacity") {
		t.Fatalf("insufficient capacity error = %v", err)
	}
}

func TestInitialPublicationV7BoundsRunsDevicesAndIdentities(t *testing.T) {
	input := validInitialPublicationV7TestInput(t)
	input.VirtualPageMap.Runs = make([]VirtualPageMapRun, MaxInitialPublicationV7Runs+1)
	if err := validateInitialPublicationV7Input(input); !errors.Is(err, ErrInvalidInitialPublicationV7) {
		t.Fatalf("257 VirtualPageMap runs error = %v", err)
	}

	input = validInitialPublicationV7TestInput(t)
	input.Publication.InitialAllocation.Devices = make(
		[]AllocationDeviceV7, MaxInitialPublicationV7Devices+1)
	for index := range input.Publication.InitialAllocation.Devices {
		input.Publication.InitialAllocation.Devices[index] = AllocationDeviceV7{
			DeviceUUID: fmt.Sprintf("device-%03d", index), DataPageCount: 1,
		}
	}
	if _, err := BuildInitialPublicationV7Plan(input); !errors.Is(err, ErrInvalidInitialPublicationV7) {
		t.Fatalf("257 allocation devices error = %v", err)
	}

	boundaryMap := ContentPlacementMap{
		Version: InitialPublicationV7SemanticVersion,
		Devices: make([]Device, MaxInitialPublicationV7Devices),
		Runs:    make([]ContentPlacementRun, MaxInitialPublicationV7Runs),
	}
	if err := validateInitialPublicationV7MapBounds(boundaryMap); err != nil {
		t.Fatalf("exact map bounds rejected: %v", err)
	}
	boundaryMap.Devices = append(boundaryMap.Devices, Device{})
	if err := validateInitialPublicationV7MapBounds(boundaryMap); !errors.Is(err, ErrInvalidInitialPublicationV7) {
		t.Fatalf("257 map devices error = %v", err)
	}
	boundaryMap.Devices = boundaryMap.Devices[:MaxInitialPublicationV7Devices]
	boundaryMap.Runs = append(boundaryMap.Runs, ContentPlacementRun{})
	if err := validateInitialPublicationV7MapBounds(boundaryMap); !errors.Is(err, ErrInvalidInitialPublicationV7) {
		t.Fatalf("257 map runs error = %v", err)
	}

	runs := make([]AllocationPageRunV7, MaxInitialPublicationV7Runs)
	for index := range runs {
		runs[index] = AllocationPageRunV7{ObjectPageStart: uint64(index), PageCount: 1}
	}
	if err := validateInitialPublicationV7RunCoverage("boundary", runs, MaxInitialPublicationV7Runs); err != nil {
		t.Fatalf("exact run bound rejected: %v", err)
	}
	runs = append(runs, AllocationPageRunV7{
		ObjectPageStart: MaxInitialPublicationV7Runs, PageCount: 1,
	})
	if err := validateInitialPublicationV7RunCoverage(
		"over-bound", runs, MaxInitialPublicationV7Runs+1); !errors.Is(err, ErrInvalidInitialPublicationV7) {
		t.Fatalf("257 object runs error = %v", err)
	}
}

func TestInitialPublicationV7ValidateRejectsMappingRootAndWriteSubstitution(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*InitialPublicationV7Plan)
	}{
		{name: "mapping ID", mutate: func(value *InitialPublicationV7Plan) {
			value.InitialContentPlacementMap.ContentPlacementMapID = "substituted-map"
		}},
		{name: "mapping run", mutate: func(value *InitialPublicationV7Plan) {
			value.InitialContentPlacementMap.Runs[0].DataPageIndex++
		}},
		{name: "root map binding", mutate: func(value *InitialPublicationV7Plan) {
			value.ActiveContentPlacementRoot.ContentPlacementMapID = "substituted-map"
		}},
		{name: "root slot", mutate: func(value *InitialPublicationV7Plan) {
			value.ActiveContentPlacementRoot.ActiveMappingSlot = MappingSlotB
		}},
		{name: "root version", mutate: func(value *InitialPublicationV7Plan) {
			value.ActiveContentPlacementRoot.RootVersion++
		}},
		{name: "static root", mutate: func(value *InitialPublicationV7Plan) {
			value.StaticPublicationRoot.CheckpointID = "substituted-checkpoint"
		}},
		{name: "static root bytes", mutate: func(value *InitialPublicationV7Plan) {
			value.StaticPublicationRootBytes[0] ^= 0xff
		}},
		{name: "object write identity", mutate: func(value *InitialPublicationV7Plan) {
			value.ObjectWrites[0].ObjectID++
		}},
		{name: "slot A bytes", mutate: func(value *InitialPublicationV7Plan) {
			for index := range value.ObjectWrites {
				if value.ObjectWrites[index].Kind == ContentPlacementSlotAV7 {
					value.ObjectWrites[index].CanonicalBytes[0] ^= 0xff
					return
				}
			}
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			plan, err := BuildInitialPublicationV7Plan(validInitialPublicationV7TestInput(t))
			if err != nil {
				t.Fatalf("BuildInitialPublicationV7Plan: %v", err)
			}
			test.mutate(&plan)
			if err := plan.Validate(); !errors.Is(err, ErrInvalidInitialPublicationV7) {
				t.Fatalf("Validate substitution error = %v", err)
			}
		})
	}
}

func TestInitialPublicationV7APIHasNoExternalCapabilityOrPayloadBytes(t *testing.T) {
	for _, valueType := range []reflect.Type{
		reflect.TypeOf(InitialPublicationV7Input{}),
		reflect.TypeOf(InitialPublicationV7Plan{}),
		reflect.TypeOf(InitialPublicationV7ObjectWritePlan{}),
	} {
		for index := 0; index < valueType.NumField(); index++ {
			field := valueType.Field(index)
			switch field.Type.Kind() {
			case reflect.Chan, reflect.Func, reflect.Interface, reflect.Pointer, reflect.UnsafePointer:
				t.Fatalf("%s.%s exposes external capability kind %s", valueType.Name(), field.Name, field.Type.Kind())
			}
		}
	}
	inputType := reflect.TypeOf(InitialPublicationV7Input{})
	if _, exists := inputType.FieldByName("StaticPublicationRootID"); exists {
		t.Fatal("input invented an identity that TRPSR007 does not have")
	}
	for _, forbidden := range []string{
		"PayloadBytes", "DAX", "OwnerClient", "Store", "Callback", "Context", "Handle", "Executor", "Writer",
	} {
		if _, exists := inputType.FieldByName(forbidden); exists {
			t.Fatalf("input unexpectedly exposes %s", forbidden)
		}
	}
	planType := reflect.TypeOf(InitialPublicationV7Plan{})
	publicationStorageType := reflect.TypeOf(PublicationStorageV7{})
	for index := 0; index < planType.NumField(); index++ {
		if planType.Field(index).Type == publicationStorageType {
			t.Fatal("plan retains PublicationStorageV7 and its padded allocation")
		}
	}
	writeType := reflect.TypeOf(InitialPublicationV7ObjectWritePlan{})
	if _, exists := writeType.FieldByName("PayloadBytes"); exists {
		t.Fatal("object write plan carries payload bytes")
	}
}

func validInitialPublicationV7TestInput(t *testing.T) InitialPublicationV7Input {
	t.Helper()
	fixture := validPublicationV7Fixture(t)
	input := InitialPublicationV7Input{
		Publication:                  fixture.publication,
		MMTemplate:                   fixture.template,
		VirtualPageMap:               fixture.virtual,
		ArtifactManifest:             fixture.manifest,
		InitialContentPlacementMapID: "initial-placement-v7",
		InitialActivePlacementRootID: "active-root-v7",
	}
	input.MMTemplate.Version = InitialPublicationV7SemanticVersion
	input.VirtualPageMap.Version = InitialPublicationV7SemanticVersion
	input.ArtifactManifest.Version = InitialPublicationV7SemanticVersion
	rebindInitialPublicationV7TestMetadata(t, &input)
	return input
}

func repeatedPayloadInitialPublicationV7TestInput(t *testing.T) InitialPublicationV7Input {
	t.Helper()
	input := validInitialPublicationV7TestInput(t)
	input.VirtualPageMap.Runs[0].ContentObjectID = 1
	input.VirtualPageMap.Runs[1].ContentObjectID = 2
	input.VirtualPageMap.Runs[1].ObjectPageIndex = 0
	input.ArtifactManifest.Entries[0].ContentObjectID = 3
	input.ArtifactManifest.Entries[0].ContentOffset = 0
	input.ArtifactManifest.Entries[1].ContentObjectID = 4
	input.ArtifactManifest.Entries[1].ContentOffset = 0
	input.Publication.Objects = []ContentObjectV7{
		{ObjectID: 1, Kind: ContentMemoryPayloadV7, ImmutableByteLength: 2 * PageSize, LogicalPageStart: 0, CapacityPages: 2},
		{ObjectID: 2, Kind: ContentMemoryPayloadV7, ImmutableByteLength: PageSize, LogicalPageStart: 2, CapacityPages: 1},
		{ObjectID: 3, Kind: ContentArtifactPayloadV7, ImmutableByteLength: 2000, LogicalPageStart: 3, CapacityPages: 1},
		{ObjectID: 4, Kind: ContentArtifactPayloadV7, ImmutableByteLength: 3000, LogicalPageStart: 4, CapacityPages: 1},
		{ObjectID: 5, Kind: ContentRestoreBlobPayloadV7, ImmutableByteLength: 1000, LogicalPageStart: 5, CapacityPages: 1},
		{ObjectID: 6, Kind: ContentMMTemplateMetadataV7, ImmutableByteLength: 1, LogicalPageStart: 6, CapacityPages: 1},
		{ObjectID: 7, Kind: ContentVirtualPageMapMetadataV7, ImmutableByteLength: 1, LogicalPageStart: 7, CapacityPages: 1},
		{ObjectID: 8, Kind: ContentArtifactManifestMetadataV7, ImmutableByteLength: 1, LogicalPageStart: 8, CapacityPages: 1},
		{ObjectID: 9, Kind: ContentPlacementSlotAV7, LogicalPageStart: 9, CapacityPages: 2},
		{ObjectID: 10, Kind: ContentPlacementSlotBV7, LogicalPageStart: 11, CapacityPages: 2},
		{ObjectID: 11, Kind: ContentPublicationV7, LogicalPageStart: 13, CapacityPages: 4},
	}
	input.Publication.MMTemplate.ObjectID = 6
	input.Publication.VirtualPageMap.ObjectID = 7
	input.Publication.ArtifactManifest.ObjectID = 8
	input.Publication.PlacementSlots = PlacementSlotsV7{AObjectID: 9, BObjectID: 10}
	rebindInitialPublicationV7TestMetadata(t, &input)
	return input
}

func absentOptionalPayloadInitialPublicationV7TestInput(t *testing.T) InitialPublicationV7Input {
	t.Helper()
	input := validInitialPublicationV7TestInput(t)
	input.ArtifactManifest.Entries = append(
		[]ArtifactEntryV7(nil), input.ArtifactManifest.Entries[2:]...)
	input.Publication.InitialAllocation.TotalPages = 14
	input.Publication.InitialAllocation.Extents = []AllocationExtentV7{
		{DeviceIndex: 0, StartDataPageIndex: 10, PageCount: 2, LogicalPageStart: 0},
		{DeviceIndex: 1, StartDataPageIndex: 20, PageCount: 3, LogicalPageStart: 2},
		{DeviceIndex: 0, StartDataPageIndex: 30, PageCount: 4, LogicalPageStart: 5},
		{DeviceIndex: 1, StartDataPageIndex: 40, PageCount: 1, LogicalPageStart: 9},
		{DeviceIndex: 0, StartDataPageIndex: 40, PageCount: 3, LogicalPageStart: 10},
		{DeviceIndex: 1, StartDataPageIndex: 50, PageCount: 1, LogicalPageStart: 13},
	}
	input.Publication.Objects = []ContentObjectV7{
		{ObjectID: 1, Kind: ContentMemoryPayloadV7, ImmutableByteLength: 3 * PageSize, LogicalPageStart: 0, CapacityPages: 3},
		{ObjectID: 2, Kind: ContentMMTemplateMetadataV7, ImmutableByteLength: 1, LogicalPageStart: 3, CapacityPages: 1},
		{ObjectID: 3, Kind: ContentVirtualPageMapMetadataV7, ImmutableByteLength: 1, LogicalPageStart: 4, CapacityPages: 1},
		{ObjectID: 4, Kind: ContentArtifactManifestMetadataV7, ImmutableByteLength: 1, LogicalPageStart: 5, CapacityPages: 1},
		{ObjectID: 5, Kind: ContentPlacementSlotAV7, LogicalPageStart: 6, CapacityPages: 2},
		{ObjectID: 6, Kind: ContentPlacementSlotBV7, LogicalPageStart: 8, CapacityPages: 2},
		{ObjectID: 7, Kind: ContentPublicationV7, LogicalPageStart: 10, CapacityPages: 4},
	}
	input.Publication.MMTemplate.ObjectID = 2
	input.Publication.VirtualPageMap.ObjectID = 3
	input.Publication.ArtifactManifest.ObjectID = 4
	input.Publication.PlacementSlots = PlacementSlotsV7{AObjectID: 5, BObjectID: 6}
	rebindInitialPublicationV7TestMetadata(t, &input)
	return input
}

func oversizedInitialPlacementMapV7TestInput(t *testing.T) InitialPublicationV7Input {
	t.Helper()
	input := validInitialPublicationV7TestInput(t)
	const restorePages = uint64(232)
	input.Publication.InitialAllocation.TotalPages = 248
	input.Publication.InitialAllocation.Devices = []AllocationDeviceV7{
		{DeviceUUID: "device-a", DataPageCount: 1000},
		{DeviceUUID: "device-b", DataPageCount: 1000},
	}
	input.Publication.InitialAllocation.Extents = make([]AllocationExtentV7, 248)
	for index := range input.Publication.InitialAllocation.Extents {
		input.Publication.InitialAllocation.Extents[index] = AllocationExtentV7{
			DeviceIndex:        uint32(index % 2),
			StartDataPageIndex: 100 + uint64(index/2),
			PageCount:          1,
			LogicalPageStart:   uint64(index),
		}
	}
	input.Publication.Objects[2].ImmutableByteLength = restorePages * PageSize
	input.Publication.Objects[2].CapacityPages = restorePages
	logicalStarts := []uint64{0, 3, 5, 237, 238, 239, 240, 242, 244}
	for index := range input.Publication.Objects {
		input.Publication.Objects[index].LogicalPageStart = logicalStarts[index]
	}
	if err := input.Publication.CrossCheckImmutableGraph(
		input.MMTemplate, input.VirtualPageMap, input.ArtifactManifest); err != nil {
		t.Fatalf("oversized-map fixture graph: %v", err)
	}
	if _, err := EncodePublicationV7ForStorage(input.Publication); err != nil {
		t.Fatalf("oversized-map publication slot setup: %v", err)
	}
	return input
}

func rebindInitialPublicationV7TestMetadata(t *testing.T, input *InitialPublicationV7Input) {
	t.Helper()
	contentObjects := input.Publication.mappingContentObjectsValidated()
	templateBytes, err := CanonicalMMTemplateV7Bytes(input.MMTemplate)
	if err != nil {
		t.Fatalf("fixture CanonicalMMTemplateV7Bytes: %v", err)
	}
	virtualBytes, err := CanonicalVirtualPageMapBytes(input.VirtualPageMap, contentObjects)
	if err != nil {
		t.Fatalf("fixture CanonicalVirtualPageMapBytes: %v", err)
	}
	manifestBytes, err := CanonicalArtifactManifestV7Bytes(input.ArtifactManifest)
	if err != nil {
		t.Fatalf("fixture CanonicalArtifactManifestV7Bytes: %v", err)
	}
	input.Publication.MMTemplate = MMTemplateRefV7{
		ObjectID:     input.Publication.MMTemplate.ObjectID,
		MMTemplateID: input.MMTemplate.MMTemplateID,
		Version:      input.MMTemplate.Version,
		SHA256:       sha256.Sum256(templateBytes),
	}
	input.Publication.VirtualPageMap = VirtualPageMapRefV7{
		ObjectID:         input.Publication.VirtualPageMap.ObjectID,
		VirtualPageMapID: input.VirtualPageMap.VirtualPageMapID,
		Version:          input.VirtualPageMap.Version,
		SHA256:           sha256.Sum256(virtualBytes),
	}
	input.Publication.ArtifactManifest = ArtifactManifestRefV7{
		ObjectID:           input.Publication.ArtifactManifest.ObjectID,
		ArtifactManifestID: input.ArtifactManifest.ArtifactManifestID,
		Version:            input.ArtifactManifest.Version,
		SHA256:             sha256.Sum256(manifestBytes),
	}
	for index := range input.Publication.Objects {
		switch input.Publication.Objects[index].Kind {
		case ContentMMTemplateMetadataV7:
			input.Publication.Objects[index].ImmutableByteLength = uint64(len(templateBytes))
		case ContentVirtualPageMapMetadataV7:
			input.Publication.Objects[index].ImmutableByteLength = uint64(len(virtualBytes))
		case ContentArtifactManifestMetadataV7:
			input.Publication.Objects[index].ImmutableByteLength = uint64(len(manifestBytes))
		}
	}
	if err := input.Publication.CrossCheckImmutableGraph(
		input.MMTemplate, input.VirtualPageMap, input.ArtifactManifest); err != nil {
		t.Fatalf("fixture CrossCheckImmutableGraph: %v", err)
	}
}

func mustInitialPublicationV7WriteByID(
	t *testing.T,
	plan InitialPublicationV7Plan,
	objectID uint64,
) InitialPublicationV7ObjectWritePlan {
	t.Helper()
	write, ok := plan.ObjectWriteByID(objectID)
	if !ok {
		t.Fatalf("ObjectWriteByID(%d) is absent", objectID)
	}
	return write
}

func initialPublicationV7TestRunPages(runs []AllocationPageRunV7) uint64 {
	var pages uint64
	for _, run := range runs {
		pages += run.PageCount
	}
	return pages
}

func initialPublicationV7TestKindCounts(
	writes []InitialPublicationV7ObjectWritePlan,
) map[ContentKindV7]int {
	counts := make(map[ContentKindV7]int)
	for _, write := range writes {
		counts[write.Kind]++
	}
	return counts
}

func initialPublicationV7TestObjectByKind(
	t *testing.T,
	publication PublicationV7,
	kind ContentKindV7,
) ContentObjectV7 {
	t.Helper()
	for _, object := range publication.Objects {
		if object.Kind == kind {
			return object
		}
	}
	t.Fatalf("publication object kind %d is absent", kind)
	return ContentObjectV7{}
}

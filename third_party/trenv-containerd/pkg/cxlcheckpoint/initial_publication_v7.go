package cxlcheckpoint

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"reflect"
	"sort"
)

const (
	// InitialPublicationV7SemanticVersion is the only semantic version accepted
	// for the first immutable metadata objects, placement map, and active root.
	InitialPublicationV7SemanticVersion uint64 = 1

	// The initial plan uses the tightest identity and collection intersection of
	// TRPUB007, TRPSR007, and TRAPR007 even when an individual codec permits more.
	MaxInitialPublicationV7IdentityBytes = 256
	MaxInitialPublicationV7Devices       = 256
	MaxInitialPublicationV7Runs          = 256
)

var ErrInvalidInitialPublicationV7 = errors.New("invalid V7 initial publication plan")

// InitialPublicationV7Input contains only immutable values needed to derive a
// first publication. It deliberately has no payload bytes, DAX handle, Owner
// client, root store, runtime object, callback, or context.
type InitialPublicationV7Input struct {
	Publication      PublicationV7
	MMTemplate       MMTemplateV7
	VirtualPageMap   VirtualPageMap
	ArtifactManifest ArtifactManifestV7

	InitialContentPlacementMapID string
	InitialActivePlacementRootID string
}

// InitialPublicationV7WriteSource states where the meaningful prefix of an
// allocated object comes from. It prevents a nil byte slice from ambiguously
// meaning either external payload or an intentionally empty slot.
type InitialPublicationV7WriteSource uint8

const (
	InitialPublicationV7ExternalPayload InitialPublicationV7WriteSource = iota + 1
	InitialPublicationV7CanonicalControlBytes
	InitialPublicationV7NeverPublishedZeroSlot
)

// InitialPublicationV7PlacementSlotState is explicit only for A and B. In the
// genesis plan A is selected by one COMMITTED TRAPR007 root, while B has never
// contained a published placement map. B is not described as FREE or SEALED.
type InitialPublicationV7PlacementSlotState uint8

const (
	InitialPublicationV7NotAPlacementSlot InitialPublicationV7PlacementSlotState = iota
	InitialPublicationV7ActiveCommittedSlot
	InitialPublicationV7NeverPublishedSlot
)

// InitialPublicationV7ZeroRange describes an object-relative byte range that
// must contain only zero bytes. It never carries a materialized padding slice.
type InitialPublicationV7ZeroRange struct {
	ByteOffset uint64
	ByteLength uint64
}

// InitialPublicationV7ObjectWritePlan is one portable, complete allocation
// write description. CanonicalBytes is present only for control objects that
// this package can encode. Payload objects expose only exact length and runs.
// CapacityPageRuns always cover the complete reservation, including padding.
type InitialPublicationV7ObjectWritePlan struct {
	ObjectID         uint64
	Kind             ContentKindV7
	LogicalPageStart uint64
	ExactByteLength  uint64
	CapacityPages    uint64
	CapacityBytes    uint64

	WriteSource        InitialPublicationV7WriteSource
	PlacementSlotState InitialPublicationV7PlacementSlotState
	CanonicalBytes     []byte
	ExactPageRuns      []AllocationPageRunV7
	CapacityPageRuns   []AllocationPageRunV7
	ZeroTail           InitialPublicationV7ZeroRange
}

// InitialPublicationV7VisibilityRequirement names an external ordering
// obligation. BuildInitialPublicationV7Plan performs none of these actions.
type InitialPublicationV7VisibilityRequirement uint8

const (
	InitialPublicationV7AllDAXBytesDurable InitialPublicationV7VisibilityRequirement = iota + 1
	InitialPublicationV7OwnerAllocationCommitted
	InitialPublicationV7StaticRootCreated
	InitialPublicationV7ActiveRootGenesisCreated
)

// InitialPublicationV7Plan owns copies of every input slice and every encoded
// control byte slice. It has no mutation method or external capability. Treat
// the returned value as immutable; Validate detects any inconsistent mutation.
// ObjectWrites follows Publication.Objects exactly. Payload kinds may occur
// more than once, and artifact or restore payload kinds may be absent.
type InitialPublicationV7Plan struct {
	Publication      PublicationV7
	MMTemplate       MMTemplateV7
	VirtualPageMap   VirtualPageMap
	ArtifactManifest ArtifactManifestV7

	InitialContentPlacementMap ContentPlacementMap
	StaticPublicationRoot      StaticPublicationRootV7
	ActiveContentPlacementRoot ActiveContentPlacementRoot

	StaticPublicationRootBytes      []byte
	ActiveContentPlacementRootBytes []byte
	ObjectWrites                    []InitialPublicationV7ObjectWritePlan
}

// BuildInitialPublicationV7Plan is a pure preflight builder. It derives and
// cross-checks exact bytes and portable runs but performs no write, flush,
// allocation transition, etcd operation, Owner RPC, or runtime call.
//
// A caller that later executes the plan must establish this visibility order:
// all planned DAX bytes durable; Owner allocation COMMITTED; TRPSR007 created;
// then TRAPR007 version-1 genesis created. This function establishes none of
// those external facts and its success must not be interpreted as publication.
func BuildInitialPublicationV7Plan(
	input InitialPublicationV7Input,
) (InitialPublicationV7Plan, error) {
	return buildInitialPublicationV7Plan(cloneInitialPublicationV7Input(input))
}

func buildInitialPublicationV7Plan(
	input InitialPublicationV7Input,
) (InitialPublicationV7Plan, error) {
	// Apply the tight preflight bounds before any canonical encoder can allocate
	// for a graph that this slice would reject anyway.
	if err := validateInitialPublicationV7Input(input); err != nil {
		return InitialPublicationV7Plan{}, err
	}
	if err := input.Publication.CrossCheckImmutableGraph(
		input.MMTemplate, input.VirtualPageMap, input.ArtifactManifest); err != nil {
		return InitialPublicationV7Plan{}, initialPublicationV7FieldInvalid(
			"immutable publication graph", err)
	}

	contentObjects, err := input.Publication.MappingContentObjects()
	if err != nil {
		return InitialPublicationV7Plan{}, initialPublicationV7FieldInvalid(
			"mapping content objects", err)
	}
	initialMap, err := input.Publication.InitialContentPlacementMap(
		input.InitialContentPlacementMapID, InitialPublicationV7SemanticVersion)
	if err != nil {
		return InitialPublicationV7Plan{}, initialPublicationV7FieldInvalid(
			"initial ContentPlacementMap", err)
	}
	if err := input.Publication.CrossCheckInitialContentPlacementMap(initialMap); err != nil {
		return InitialPublicationV7Plan{}, initialPublicationV7FieldInvalid(
			"exact initial ContentPlacementMap", err)
	}
	if err := validateInitialPublicationV7MapBounds(initialMap); err != nil {
		return InitialPublicationV7Plan{}, err
	}

	templateBytes, err := CanonicalMMTemplateV7Bytes(input.MMTemplate)
	if err != nil {
		return InitialPublicationV7Plan{}, initialPublicationV7FieldInvalid(
			"canonical MMTemplateV7", err)
	}
	virtualPageMapBytes, err := CanonicalVirtualPageMapBytes(
		input.VirtualPageMap, contentObjects)
	if err != nil {
		return InitialPublicationV7Plan{}, initialPublicationV7FieldInvalid(
			"canonical VirtualPageMap", err)
	}
	manifestBytes, err := CanonicalArtifactManifestV7Bytes(input.ArtifactManifest)
	if err != nil {
		return InitialPublicationV7Plan{}, initialPublicationV7FieldInvalid(
			"canonical ArtifactManifestV7", err)
	}
	placementBytes, err := CanonicalContentPlacementMapBytes(initialMap, contentObjects)
	if err != nil {
		return InitialPublicationV7Plan{}, initialPublicationV7FieldInvalid(
			"canonical initial ContentPlacementMap", err)
	}
	publicationStorage, err := EncodePublicationV7ForStorage(input.Publication)
	if err != nil {
		return InitialPublicationV7Plan{}, initialPublicationV7FieldInvalid(
			"publication storage", err)
	}

	staticRoot, err := BuildStaticPublicationRootV7(input.Publication, publicationStorage)
	if err != nil {
		return InitialPublicationV7Plan{}, initialPublicationV7FieldInvalid(
			"static publication root", err)
	}
	staticRootBytes, err := CanonicalStaticPublicationRootV7Bytes(staticRoot)
	if err != nil {
		return InitialPublicationV7Plan{}, initialPublicationV7FieldInvalid(
			"canonical static publication root", err)
	}

	deviceDigest, err := DeviceTableDigest(initialMap.Devices)
	if err != nil {
		return InitialPublicationV7Plan{}, initialPublicationV7FieldInvalid(
			"initial placement device table", err)
	}
	activeRoot := ActiveContentPlacementRoot{
		State:                      ActiveContentPlacementRootCommitted,
		RootID:                     input.InitialActivePlacementRootID,
		RootVersion:                InitialPublicationV7SemanticVersion,
		CheckpointID:               input.Publication.CheckpointID,
		ImmutablePublicationLength: uint64(len(publicationStorage.ExactBytes)),
		ImmutablePublicationSHA256: publicationStorage.SHA256,
		VirtualPageMapID:           input.VirtualPageMap.VirtualPageMapID,
		VirtualPageMapVersion:      input.VirtualPageMap.Version,
		VirtualPageMapLength:       uint64(len(virtualPageMapBytes)),
		VirtualPageMapSHA256:       sha256.Sum256(virtualPageMapBytes),
		ActiveMappingSlot:          MappingSlotA,
		ContentPlacementMapID:      initialMap.ContentPlacementMapID,
		ContentPlacementMapVersion: initialMap.Version,
		ContentPlacementMapLength:  uint64(len(placementBytes)),
		ContentPlacementMapSHA256:  sha256.Sum256(placementBytes),
		PlacementDeviceTableSHA256: deviceDigest,
	}
	if err := activeRoot.CrossCheck(
		contentObjects,
		publicationStorage.ExactBytes,
		input.VirtualPageMap,
		initialMap,
	); err != nil {
		return InitialPublicationV7Plan{}, initialPublicationV7FieldInvalid(
			"active placement root exact cross-check", err)
	}
	if err := input.Publication.CrossCheckActivePlacementRootImmutableBindings(
		activeRoot, input.VirtualPageMap); err != nil {
		return InitialPublicationV7Plan{}, initialPublicationV7FieldInvalid(
			"active placement root immutable binding", err)
	}
	activeRootBytes, err := CanonicalActiveContentPlacementRootBytes(activeRoot)
	if err != nil {
		return InitialPublicationV7Plan{}, initialPublicationV7FieldInvalid(
			"canonical active placement root", err)
	}

	objectWrites, err := buildInitialPublicationV7ObjectWrites(
		input.Publication,
		publicationStorage,
		templateBytes,
		virtualPageMapBytes,
		manifestBytes,
		placementBytes,
	)
	if err != nil {
		return InitialPublicationV7Plan{}, err
	}
	plan := InitialPublicationV7Plan{
		Publication:                     cloneInitialPublicationGraphV7(input.Publication),
		MMTemplate:                      cloneInitialPublicationMMTemplateV7(input.MMTemplate),
		VirtualPageMap:                  cloneInitialPublicationVirtualPageMapV7(input.VirtualPageMap),
		ArtifactManifest:                cloneInitialPublicationArtifactManifestV7(input.ArtifactManifest),
		InitialContentPlacementMap:      cloneInitialPublicationContentPlacementMap(initialMap),
		StaticPublicationRoot:           cloneInitialPublicationStaticRootV7(staticRoot),
		ActiveContentPlacementRoot:      activeRoot,
		StaticPublicationRootBytes:      append([]byte(nil), staticRootBytes...),
		ActiveContentPlacementRootBytes: append([]byte(nil), activeRootBytes...),
		ObjectWrites:                    objectWrites,
	}
	if err := validateInitialPublicationV7PlanShape(plan); err != nil {
		return InitialPublicationV7Plan{}, err
	}
	return plan, nil
}

// Validate re-derives the complete plan and rejects any identity, mapping,
// root, byte, run, slot-state, tail, or padding substitution.
func (plan InitialPublicationV7Plan) Validate() error {
	rebuilt, err := buildInitialPublicationV7Plan(InitialPublicationV7Input{
		Publication:                  cloneInitialPublicationGraphV7(plan.Publication),
		MMTemplate:                   cloneInitialPublicationMMTemplateV7(plan.MMTemplate),
		VirtualPageMap:               cloneInitialPublicationVirtualPageMapV7(plan.VirtualPageMap),
		ArtifactManifest:             cloneInitialPublicationArtifactManifestV7(plan.ArtifactManifest),
		InitialContentPlacementMapID: plan.InitialContentPlacementMap.ContentPlacementMapID,
		InitialActivePlacementRootID: plan.ActiveContentPlacementRoot.RootID,
	})
	if err != nil {
		return initialPublicationV7FieldInvalid("rebuild initial publication plan", err)
	}
	if !reflect.DeepEqual(plan, rebuilt) {
		return initialPublicationV7Invalidf(
			"plan does not exactly match its canonical inputs, roots, bytes, and runs")
	}
	return nil
}

// RequiredVisibilityOrder returns a copy of the external ordering contract.
// It reports requirements only; it is not execution or durability evidence.
func (plan InitialPublicationV7Plan) RequiredVisibilityOrder() [4]InitialPublicationV7VisibilityRequirement {
	return [4]InitialPublicationV7VisibilityRequirement{
		InitialPublicationV7AllDAXBytesDurable,
		InitialPublicationV7OwnerAllocationCommitted,
		InitialPublicationV7StaticRootCreated,
		InitialPublicationV7ActiveRootGenesisCreated,
	}
}

// ObjectWriteByID returns a defensive copy of the plan for one canonical
// publication object ID. ObjectWrites is ordered by strictly increasing ID.
func (plan InitialPublicationV7Plan) ObjectWriteByID(
	objectID uint64,
) (InitialPublicationV7ObjectWritePlan, bool) {
	position := sort.Search(len(plan.ObjectWrites), func(index int) bool {
		return plan.ObjectWrites[index].ObjectID >= objectID
	})
	if position >= len(plan.ObjectWrites) || plan.ObjectWrites[position].ObjectID != objectID {
		return InitialPublicationV7ObjectWritePlan{}, false
	}
	return cloneInitialPublicationV7ObjectWrite(plan.ObjectWrites[position]), true
}

func validateInitialPublicationV7Input(input InitialPublicationV7Input) error {
	for _, identity := range []struct {
		name  string
		value string
	}{
		{name: "checkpoint ID", value: input.Publication.CheckpointID},
		{name: "immutable graph ID", value: input.Publication.ImmutableGraphID},
		{name: "dedup domain ID", value: input.Publication.DedupDomainID},
		{name: "sharing policy ID", value: input.Publication.SharingPolicyID},
		{name: "allocation Owner ID", value: input.Publication.InitialAllocation.OwnerID},
		{name: "MMTemplate ID", value: input.MMTemplate.MMTemplateID},
		{name: "runtime compatibility ID", value: input.MMTemplate.RuntimeCompatibilityID},
		{name: "VirtualPageMap ID", value: input.VirtualPageMap.VirtualPageMapID},
		{name: "ArtifactManifest ID", value: input.ArtifactManifest.ArtifactManifestID},
		{name: "initial ContentPlacementMap ID", value: input.InitialContentPlacementMapID},
		{name: "initial active-placement-root ID", value: input.InitialActivePlacementRootID},
	} {
		if err := validateInitialPublicationV7Identity(identity.name, identity.value); err != nil {
			return err
		}
	}
	for index, device := range input.Publication.InitialAllocation.Devices {
		if err := validateInitialPublicationV7Identity(
			fmt.Sprintf("allocation device %d UUID", index), device.DeviceUUID); err != nil {
			return err
		}
	}
	if len(input.Publication.InitialAllocation.Devices) > MaxInitialPublicationV7Devices {
		return initialPublicationV7Invalidf(
			"allocation device count %d exceeds %d",
			len(input.Publication.InitialAllocation.Devices), MaxInitialPublicationV7Devices)
	}
	if len(input.Publication.InitialAllocation.Extents) > MaxInitialPublicationV7Runs {
		return initialPublicationV7Invalidf(
			"allocation extent count %d exceeds %d",
			len(input.Publication.InitialAllocation.Extents), MaxInitialPublicationV7Runs)
	}
	if len(input.VirtualPageMap.Runs) > MaxInitialPublicationV7Runs {
		return initialPublicationV7Invalidf(
			"VirtualPageMap run count %d exceeds %d",
			len(input.VirtualPageMap.Runs), MaxInitialPublicationV7Runs)
	}
	for _, version := range []struct {
		name  string
		value uint64
	}{
		{name: "MMTemplate version", value: input.MMTemplate.Version},
		{name: "MMTemplate reference version", value: input.Publication.MMTemplate.Version},
		{name: "VirtualPageMap version", value: input.VirtualPageMap.Version},
		{name: "VirtualPageMap reference version", value: input.Publication.VirtualPageMap.Version},
		{name: "ArtifactManifest version", value: input.ArtifactManifest.Version},
		{name: "ArtifactManifest reference version", value: input.Publication.ArtifactManifest.Version},
	} {
		if version.value != InitialPublicationV7SemanticVersion {
			return initialPublicationV7Invalidf(
				"%s is %d, initial publication requires exactly %d",
				version.name, version.value, InitialPublicationV7SemanticVersion)
		}
	}
	return nil
}

func validateInitialPublicationV7MapBounds(mapping ContentPlacementMap) error {
	if mapping.Version != InitialPublicationV7SemanticVersion {
		return initialPublicationV7Invalidf(
			"initial ContentPlacementMap version is %d, expected %d",
			mapping.Version, InitialPublicationV7SemanticVersion)
	}
	if len(mapping.Devices) == 0 || len(mapping.Devices) > MaxInitialPublicationV7Devices {
		return initialPublicationV7Invalidf(
			"initial ContentPlacementMap device count %d is outside 1..%d",
			len(mapping.Devices), MaxInitialPublicationV7Devices)
	}
	if len(mapping.Runs) == 0 || len(mapping.Runs) > MaxInitialPublicationV7Runs {
		return initialPublicationV7Invalidf(
			"initial ContentPlacementMap run count %d is outside 1..%d",
			len(mapping.Runs), MaxInitialPublicationV7Runs)
	}
	return nil
}

func buildInitialPublicationV7ObjectWrites(
	publication PublicationV7,
	publicationStorage PublicationStorageV7,
	templateBytes []byte,
	virtualPageMapBytes []byte,
	manifestBytes []byte,
	placementBytes []byte,
) ([]InitialPublicationV7ObjectWritePlan, error) {
	result := make([]InitialPublicationV7ObjectWritePlan, len(publication.Objects))
	canonical := map[ContentKindV7][]byte{
		ContentMMTemplateMetadataV7:       templateBytes,
		ContentVirtualPageMapMetadataV7:   virtualPageMapBytes,
		ContentArtifactManifestMetadataV7: manifestBytes,
		ContentPlacementSlotAV7:           placementBytes,
		ContentPublicationV7:              publicationStorage.ExactBytes,
	}
	for objectIndex, object := range publication.Objects {
		capacityBytes, ok := mulLong(object.CapacityPages, PublicationV7PageSize)
		if !ok {
			return result, initialPublicationV7Invalidf(
				"object %d capacity overflows signed-Long ABI", object.ObjectID)
		}
		exactLength := object.ImmutableByteLength
		writeSource := InitialPublicationV7ExternalPayload
		slotState := InitialPublicationV7NotAPlacementSlot
		var exactBytes []byte
		switch object.Kind {
		case ContentMMTemplateMetadataV7,
			ContentVirtualPageMapMetadataV7,
			ContentArtifactManifestMetadataV7,
			ContentPlacementSlotAV7,
			ContentPublicationV7:
			exactBytes = canonical[object.Kind]
			exactLength = uint64(len(exactBytes))
			writeSource = InitialPublicationV7CanonicalControlBytes
		case ContentPlacementSlotBV7:
			exactLength = 0
			writeSource = InitialPublicationV7NeverPublishedZeroSlot
			slotState = InitialPublicationV7NeverPublishedSlot
		}
		if object.Kind == ContentPlacementSlotAV7 {
			slotState = InitialPublicationV7ActiveCommittedSlot
		}
		if exactLength > capacityBytes {
			return result, initialPublicationV7Invalidf(
				"object %d exact length %d exceeds capacity %d",
				object.ObjectID, exactLength, capacityBytes)
		}

		capacityRuns, err := publication.allocationPageRuns(
			object.LogicalPageStart, object.CapacityPages, object.LogicalPageStart)
		if err != nil {
			return result, initialPublicationV7FieldInvalid(
				fmt.Sprintf("object %d capacity runs", object.ObjectID), err)
		}
		var exactRuns []AllocationPageRunV7
		if exactLength != 0 {
			if object.Kind.placementPayload() {
				exactPages, ok := initialPublicationV7PagesForBytes(exactLength)
				if !ok {
					return result, initialPublicationV7Invalidf(
						"object %d exact length cannot be represented", object.ObjectID)
				}
				exactRuns, err = publication.allocationPageRuns(
					object.LogicalPageStart, exactPages, object.LogicalPageStart)
			} else {
				exactRuns, err = publication.controlObjectPageRunsValidated(
					object, exactLength, uint64(len(publicationStorage.ExactBytes)))
			}
			if err != nil {
				return result, initialPublicationV7FieldInvalid(
					fmt.Sprintf("object %d exact runs", object.ObjectID), err)
			}
		}
		if object.Kind == ContentPublicationV7 {
			if !equalAllocationPageRunsV7(exactRuns, publicationStorage.PageRuns) ||
				!equalAllocationPageRunsV7(capacityRuns, publicationStorage.PaddedWriteRuns) {
				return result, initialPublicationV7Invalidf(
					"publication object runs do not match EncodePublicationV7ForStorage")
			}
		}
		write := InitialPublicationV7ObjectWritePlan{
			ObjectID:           object.ObjectID,
			Kind:               object.Kind,
			LogicalPageStart:   object.LogicalPageStart,
			ExactByteLength:    exactLength,
			CapacityPages:      object.CapacityPages,
			CapacityBytes:      capacityBytes,
			WriteSource:        writeSource,
			PlacementSlotState: slotState,
			CanonicalBytes:     append([]byte(nil), exactBytes...),
			ExactPageRuns:      append([]AllocationPageRunV7(nil), exactRuns...),
			CapacityPageRuns:   append([]AllocationPageRunV7(nil), capacityRuns...),
			ZeroTail: InitialPublicationV7ZeroRange{
				ByteOffset: exactLength,
				ByteLength: capacityBytes - exactLength,
			},
		}
		if err := validateInitialPublicationV7ObjectWrite(write); err != nil {
			return result, err
		}
		result[objectIndex] = write
	}
	return result, nil
}

func validateInitialPublicationV7ObjectWrite(
	write InitialPublicationV7ObjectWritePlan,
) error {
	if !write.Kind.valid() {
		return initialPublicationV7Invalidf("object write has unknown kind %d", write.Kind)
	}
	wantCapacityBytes, capacityOK := mulLong(write.CapacityPages, PublicationV7PageSize)
	if write.CapacityPages == 0 || !capacityOK || write.CapacityBytes != wantCapacityBytes {
		return initialPublicationV7Invalidf(
			"object %d capacity bytes/pages are inconsistent", write.ObjectID)
	}
	if write.ExactByteLength > write.CapacityBytes ||
		write.ZeroTail.ByteOffset != write.ExactByteLength ||
		write.ZeroTail.ByteLength != write.CapacityBytes-write.ExactByteLength {
		return initialPublicationV7Invalidf(
			"object %d exact/tail/capacity ranges are ambiguous", write.ObjectID)
	}
	switch write.WriteSource {
	case InitialPublicationV7ExternalPayload:
		if !write.Kind.placementPayload() || write.CanonicalBytes != nil {
			return initialPublicationV7Invalidf(
				"object %d external payload source is invalid", write.ObjectID)
		}
	case InitialPublicationV7CanonicalControlBytes:
		if !write.Kind.pinnedControl() || write.Kind == ContentPlacementSlotBV7 ||
			uint64(len(write.CanonicalBytes)) != write.ExactByteLength ||
			write.ExactByteLength == 0 {
			return initialPublicationV7Invalidf(
				"object %d canonical control bytes are invalid", write.ObjectID)
		}
	case InitialPublicationV7NeverPublishedZeroSlot:
		if write.Kind != ContentPlacementSlotBV7 || write.ExactByteLength != 0 ||
			write.CanonicalBytes != nil || write.ZeroTail.ByteLength != write.CapacityBytes {
			return initialPublicationV7Invalidf(
				"object %d never-published zero slot is invalid", write.ObjectID)
		}
	default:
		return initialPublicationV7Invalidf(
			"object %d has unknown write source %d", write.ObjectID, write.WriteSource)
	}
	wantSlotState := InitialPublicationV7NotAPlacementSlot
	if write.Kind == ContentPlacementSlotAV7 {
		wantSlotState = InitialPublicationV7ActiveCommittedSlot
	} else if write.Kind == ContentPlacementSlotBV7 {
		wantSlotState = InitialPublicationV7NeverPublishedSlot
	}
	if write.PlacementSlotState != wantSlotState {
		return initialPublicationV7Invalidf(
			"object %d placement slot state is %d, expected %d",
			write.ObjectID, write.PlacementSlotState, wantSlotState)
	}
	exactPages := uint64(0)
	if write.ExactByteLength != 0 {
		var ok bool
		exactPages, ok = initialPublicationV7PagesForBytes(write.ExactByteLength)
		if !ok {
			return initialPublicationV7Invalidf(
				"object %d exact bytes cannot be represented as pages", write.ObjectID)
		}
	}
	if err := validateInitialPublicationV7RunCoverage(
		fmt.Sprintf("object %d exact", write.ObjectID), write.ExactPageRuns, exactPages); err != nil {
		return err
	}
	if err := validateInitialPublicationV7RunCoverage(
		fmt.Sprintf("object %d capacity", write.ObjectID),
		write.CapacityPageRuns,
		write.CapacityPages,
	); err != nil {
		return err
	}
	return nil
}

func validateInitialPublicationV7RunCoverage(
	name string,
	runs []AllocationPageRunV7,
	wantPages uint64,
) error {
	if len(runs) > MaxInitialPublicationV7Runs {
		return initialPublicationV7Invalidf(
			"%s run count %d exceeds %d", name, len(runs), MaxInitialPublicationV7Runs)
	}
	if wantPages == 0 {
		if len(runs) != 0 {
			return initialPublicationV7Invalidf("%s has runs for an empty byte range", name)
		}
		return nil
	}
	if len(runs) == 0 {
		return initialPublicationV7Invalidf("%s has no runs", name)
	}
	expected := uint64(0)
	for index, run := range runs {
		if run.ObjectPageStart != expected || run.PageCount == 0 {
			return initialPublicationV7Invalidf(
				"%s run %d is not gap-free at object page %d", name, index, expected)
		}
		next, ok := addLong(expected, run.PageCount)
		if !ok {
			return initialPublicationV7Invalidf("%s coverage overflows", name)
		}
		expected = next
	}
	if expected != wantPages {
		return initialPublicationV7Invalidf(
			"%s runs cover %d pages, expected %d", name, expected, wantPages)
	}
	return nil
}

func validateInitialPublicationV7PlanShape(plan InitialPublicationV7Plan) error {
	if plan.ActiveContentPlacementRoot.RootVersion != InitialPublicationV7SemanticVersion ||
		plan.InitialContentPlacementMap.Version != InitialPublicationV7SemanticVersion {
		return initialPublicationV7Invalidf("initial map/root versions are not exactly 1")
	}
	if plan.ActiveContentPlacementRoot.State != ActiveContentPlacementRootCommitted ||
		plan.ActiveContentPlacementRoot.ActiveMappingSlot != MappingSlotA {
		return initialPublicationV7Invalidf("initial active root is not COMMITTED on slot A")
	}
	if plan.StaticPublicationRoot.State != StaticPublicationRootV7Committed {
		return initialPublicationV7Invalidf("static publication root is not COMMITTED")
	}
	canonicalStatic, err := CanonicalStaticPublicationRootV7Bytes(plan.StaticPublicationRoot)
	if err != nil || !bytes.Equal(canonicalStatic, plan.StaticPublicationRootBytes) {
		return initialPublicationV7Invalidf("static publication root bytes are not exact canonical bytes")
	}
	canonicalActive, err := CanonicalActiveContentPlacementRootBytes(
		plan.ActiveContentPlacementRoot)
	if err != nil || !bytes.Equal(canonicalActive, plan.ActiveContentPlacementRootBytes) {
		return initialPublicationV7Invalidf("active placement root bytes are not exact canonical bytes")
	}
	if len(plan.ObjectWrites) != len(plan.Publication.Objects) {
		return initialPublicationV7Invalidf(
			"object write count %d does not match publication object count %d",
			len(plan.ObjectWrites), len(plan.Publication.Objects))
	}
	for index, write := range plan.ObjectWrites {
		object := plan.Publication.Objects[index]
		if write.ObjectID != object.ObjectID || write.Kind != object.Kind ||
			write.LogicalPageStart != object.LogicalPageStart {
			return initialPublicationV7Invalidf(
				"object write %d does not match publication object %d", index, object.ObjectID)
		}
		if err := validateInitialPublicationV7ObjectWrite(write); err != nil {
			return err
		}
	}
	return nil
}

func validateInitialPublicationV7Identity(name, value string) error {
	if err := validatePublicationV7Identity(name, value); err != nil {
		return initialPublicationV7FieldInvalid(name, err)
	}
	if len([]byte(value)) > MaxInitialPublicationV7IdentityBytes {
		return initialPublicationV7Invalidf(
			"%s is %d UTF-8 bytes, initial publication limit is %d",
			name, len([]byte(value)), MaxInitialPublicationV7IdentityBytes)
	}
	return nil
}

func initialPublicationV7PagesForBytes(byteLength uint64) (uint64, bool) {
	if byteLength == 0 || byteLength > MaxSignedLong {
		return 0, false
	}
	pages := byteLength / PublicationV7PageSize
	if byteLength%PublicationV7PageSize != 0 {
		pages++
	}
	return pages, pages > 0 && pages <= MaxSignedLong
}

func cloneInitialPublicationV7Input(input InitialPublicationV7Input) InitialPublicationV7Input {
	input.Publication = cloneInitialPublicationGraphV7(input.Publication)
	input.MMTemplate = cloneInitialPublicationMMTemplateV7(input.MMTemplate)
	input.VirtualPageMap = cloneInitialPublicationVirtualPageMapV7(input.VirtualPageMap)
	input.ArtifactManifest = cloneInitialPublicationArtifactManifestV7(input.ArtifactManifest)
	return input
}

func cloneInitialPublicationGraphV7(publication PublicationV7) PublicationV7 {
	publication.InitialAllocation.Devices = append(
		[]AllocationDeviceV7(nil), publication.InitialAllocation.Devices...)
	publication.InitialAllocation.Extents = append(
		[]AllocationExtentV7(nil), publication.InitialAllocation.Extents...)
	publication.Objects = append([]ContentObjectV7(nil), publication.Objects...)
	return publication
}

func cloneInitialPublicationMMTemplateV7(template MMTemplateV7) MMTemplateV7 {
	template.VMAs = append([]VMAV7(nil), template.VMAs...)
	return template
}

func cloneInitialPublicationVirtualPageMapV7(mapping VirtualPageMap) VirtualPageMap {
	mapping.Runs = append([]VirtualPageMapRun(nil), mapping.Runs...)
	return mapping
}

func cloneInitialPublicationArtifactManifestV7(manifest ArtifactManifestV7) ArtifactManifestV7 {
	manifest.Entries = append([]ArtifactEntryV7(nil), manifest.Entries...)
	return manifest
}

func cloneInitialPublicationContentPlacementMap(mapping ContentPlacementMap) ContentPlacementMap {
	mapping.Devices = append([]Device(nil), mapping.Devices...)
	mapping.Runs = append([]ContentPlacementRun(nil), mapping.Runs...)
	return mapping
}

func cloneInitialPublicationStaticRootV7(root StaticPublicationRootV7) StaticPublicationRootV7 {
	root.Devices = append([]StaticPublicationRootV7Device(nil), root.Devices...)
	root.Runs = append([]StaticPublicationRootV7Run(nil), root.Runs...)
	return root
}

func cloneInitialPublicationV7ObjectWrite(
	write InitialPublicationV7ObjectWritePlan,
) InitialPublicationV7ObjectWritePlan {
	write.CanonicalBytes = append([]byte(nil), write.CanonicalBytes...)
	write.ExactPageRuns = append([]AllocationPageRunV7(nil), write.ExactPageRuns...)
	write.CapacityPageRuns = append([]AllocationPageRunV7(nil), write.CapacityPageRuns...)
	return write
}

func initialPublicationV7FieldInvalid(context string, err error) error {
	return fmt.Errorf("%s: %v: %w", context, err, ErrInvalidInitialPublicationV7)
}

func initialPublicationV7Invalidf(format string, arguments ...interface{}) error {
	return fmt.Errorf(format+": %w", append(arguments, ErrInvalidInitialPublicationV7)...)
}

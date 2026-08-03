package cxlcheckpoint

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"
)

const (
	// PublicationV7Version is the immutable graph wire version. It is separate
	// from Version and does not change the live TRPUB006/V6 publication.
	PublicationV7Version uint32 = 7

	PublicationV7MagicString = "TRPUB007"
	PublicationV7Domain      = "immutable-publication-v1"

	PublicationV7EnvelopeHeaderBytes uint64 = 64
	MaxPublicationV7Bytes            uint64 = 8 << 20
	MaxPublicationV7IdentityBytes           = 4096
	// PublicationV7PageSize is implicit in TRPUB007 rather than repeated in
	// every graph. Validate cross-checks it against the mapping ABI before any
	// capacity or locator arithmetic.
	PublicationV7PageSize uint64 = 4096

	MaxPublicationV7Devices  = 256
	MaxPublicationV7Extents  = 256
	MaxPublicationV7Objects  = 4096
	MaxPublicationV7PageRuns = 256

	MaxPublicationV7SlotPages = (MaxPublicationV7Bytes + PublicationV7PageSize - 1) / PublicationV7PageSize
	MaxPlacementSlotV7Pages   = (MaxContentMappingBytes + PublicationV7PageSize - 1) / PublicationV7PageSize
)

var (
	// ErrWrongPublicationV7Format identifies an incompatible magic, version,
	// domain, mandatory flag, or reserved header field.
	ErrWrongPublicationV7Format = errors.New("not a TRPUB007 immutable publication")
	// ErrCorruptPublicationV7 identifies truncated, trailing, checksummed, or
	// structurally impossible publication bytes.
	ErrCorruptPublicationV7 = errors.New("corrupt TRPUB007 immutable publication")
	// ErrInvalidPublicationV7 identifies a structurally decoded graph whose
	// immutable allocation, object, or typed-reference semantics are invalid.
	ErrInvalidPublicationV7 = errors.New("invalid TRPUB007 immutable publication")
)

// ContentKindV7 is deliberately independent of the V6 ContentKind enum. Only
// the first three kinds are mutable-placement payload. The remaining objects
// are pinned control objects and are never covered by ContentPlacementMap.
type ContentKindV7 uint8

const (
	ContentMemoryPayloadV7 ContentKindV7 = iota + 1
	ContentArtifactPayloadV7
	ContentRestoreBlobPayloadV7
	ContentMMTemplateMetadataV7
	ContentVirtualPageMapMetadataV7
	ContentArtifactManifestMetadataV7
	ContentPlacementSlotAV7
	ContentPlacementSlotBV7
	ContentPublicationV7
)

func (kind ContentKindV7) valid() bool {
	return kind >= ContentMemoryPayloadV7 && kind <= ContentPublicationV7
}

func (kind ContentKindV7) placementPayload() bool {
	switch kind {
	case ContentMemoryPayloadV7, ContentArtifactPayloadV7, ContentRestoreBlobPayloadV7:
		return true
	default:
		return false
	}
}

func (kind ContentKindV7) pinnedControl() bool {
	return kind.valid() && !kind.placementPayload()
}

// AllocationDeviceV7 is a compact initial-allocation device. Owner identity
// and epoch are intentionally stored once in InitialAllocationV7. There is no
// local DAX path, shard number, mount, or executor route in this graph.
type AllocationDeviceV7 struct {
	DeviceUUID    string
	DataPageCount uint64
}

// AllocationExtentV7 maps a complete logical allocation slice to one device.
// DeviceIndex indexes InitialAllocationV7.Devices.
type AllocationExtentV7 struct {
	DeviceIndex        uint32
	StartDataPageIndex uint64
	PageCount          uint64
	LogicalPageStart   uint64
}

// InitialAllocationV7 is the checkpoint-level, single-Owner allocation made
// at dump time. It remains useful for pinned control locators and for creating
// the initial payload placement map. It is not an authoritative payload
// locator after a deduplication root switch.
type InitialAllocationV7 struct {
	OwnerID            string
	OwnerEpoch         uint64
	AllocationRecordID uint64
	TotalPages         uint64
	Devices            []AllocationDeviceV7
	Extents            []AllocationExtentV7
}

// ContentObjectV7 describes one logical slice of InitialAllocationV7.
// ImmutableByteLength is exact meaningful content length. It is zero only for
// A, B, and the publication slot because those exact bytes are selected by an
// external root and would otherwise make this immutable graph self-referential.
type ContentObjectV7 struct {
	ObjectID            uint64
	Kind                ContentKindV7
	ImmutableByteLength uint64
	LogicalPageStart    uint64
	CapacityPages       uint64
}

type MMTemplateRefV7 struct {
	ObjectID     uint64
	MMTemplateID string
	Version      uint64
	SHA256       [sha256.Size]byte
}

type VirtualPageMapRefV7 struct {
	ObjectID         uint64
	VirtualPageMapID string
	Version          uint64
	SHA256           [sha256.Size]byte
}

type ArtifactManifestRefV7 struct {
	ObjectID           uint64
	ArtifactManifestID string
	Version            uint64
	SHA256             [sha256.Size]byte
}

// PlacementSlotsV7 names the two fixed-capacity pinned control objects. The
// active slot and exact map length/hash live in ActiveContentPlacementRoot.
type PlacementSlotsV7 struct {
	AObjectID uint64
	BObjectID uint64
}

// PublicationV7 is the immutable checkpoint graph. It contains no current
// physical placement map, content bytes, direct PageID run, host-local path,
// Reader lease, or mutable reference count.
//
// This foundation intentionally has no ContractID field. A future static
// publication root/restore authorization must bind TRPUB007 together with the
// device-descriptor ABI before this graph becomes a live compatibility claim.
type PublicationV7 struct {
	CheckpointID     string
	ImmutableGraphID string
	DedupDomainID    string
	SharingPolicyID  string

	InitialAllocation InitialAllocationV7
	Objects           []ContentObjectV7

	MMTemplate       MMTemplateRefV7
	VirtualPageMap   VirtualPageMapRefV7
	ArtifactManifest ArtifactManifestRefV7
	PlacementSlots   PlacementSlotsV7
}

// AllocationPageRunV7 is a portable range derived from InitialAllocationV7.
// OwnerEpoch is explicit because the existing PageID type intentionally does
// not carry it. ObjectPageStart preserves canonical object-local order.
type AllocationPageRunV7 struct {
	ObjectPageStart uint64
	FirstPage       PageID
	OwnerEpoch      uint64
	PageCount       uint64
}

// PublicationStorageV7 is the only bootstrap result that directly publishes
// PageID runs. A future static root stores ExactBytes length/SHA and PageRuns;
// PageRuns cover only ceil(len(ExactBytes)/PageSize), never the unused slot.
// The Producer scatters the complete zero-padded slot through PaddedWriteRuns,
// which cover every CapacityPages page. The publication then derives every
// other pinned control locator from its InitialAllocationV7 table.
type PublicationStorageV7 struct {
	ContentObjectID  uint64
	LogicalPageStart uint64
	CapacityPages    uint64
	ExactBytes       []byte
	PaddedBytes      []byte
	SHA256           [sha256.Size]byte
	PageRuns         []AllocationPageRunV7
	PaddedWriteRuns  []AllocationPageRunV7
}

// Validate proves canonical immutable graph structure. It also computes the
// exact canonical envelope size and proves that the reserved publication slot
// can contain it without recording that self-referential length in the graph.
func (publication PublicationV7) Validate() error {
	if PublicationV7PageSize != PageSize {
		return publicationV7Invalidf(
			"implicit publication page size is %d, mapping ABI requires %d",
			PublicationV7PageSize, PageSize)
	}
	for _, field := range []struct {
		name  string
		value string
	}{
		{name: "checkpoint ID", value: publication.CheckpointID},
		{name: "immutable graph ID", value: publication.ImmutableGraphID},
		{name: "dedup domain ID", value: publication.DedupDomainID},
		{name: "sharing policy ID", value: publication.SharingPolicyID},
	} {
		if err := validatePublicationV7Identity(field.name, field.value); err != nil {
			return err
		}
	}

	if err := validateInitialAllocationV7(publication.InitialAllocation); err != nil {
		return err
	}
	objects, controls, err := validateContentObjectsV7(
		publication.Objects, publication.InitialAllocation.TotalPages)
	if err != nil {
		return err
	}
	if err := validatePublicationV7References(publication, objects, controls); err != nil {
		return err
	}

	payload, err := marshalPublicationV7Payload(publication)
	if err != nil {
		return err
	}
	encodedBytes := PublicationV7EnvelopeHeaderBytes + uint64(len(payload))
	if encodedBytes > MaxPublicationV7Bytes {
		return publicationV7Invalidf(
			"canonical publication is %d bytes, limit is %d",
			encodedBytes, MaxPublicationV7Bytes)
	}
	publicationSlot := objects[controls.publicationObjectID]
	capacityBytes, ok := mulLong(publicationSlot.CapacityPages, PublicationV7PageSize)
	if !ok || encodedBytes > capacityBytes {
		return publicationV7Invalidf(
			"canonical publication is %d bytes, publication slot capacity is %d",
			encodedBytes, capacityBytes)
	}
	return nil
}

type publicationV7ControlObjects struct {
	mmTemplateObjectID       uint64
	virtualPageMapObjectID   uint64
	artifactManifestObjectID uint64
	placementSlotAObjectID   uint64
	placementSlotBObjectID   uint64
	publicationObjectID      uint64
}

func validateInitialAllocationV7(allocation InitialAllocationV7) error {
	if err := validatePublicationV7Identity("allocation Owner ID", allocation.OwnerID); err != nil {
		return err
	}
	if err := publicationV7PositiveLong("allocation Owner epoch", allocation.OwnerEpoch); err != nil {
		return err
	}
	if err := publicationV7PositiveLong("allocation record ID", allocation.AllocationRecordID); err != nil {
		return err
	}
	if err := publicationV7PositiveLong("allocation total pages", allocation.TotalPages); err != nil {
		return err
	}
	if len(allocation.Devices) == 0 || len(allocation.Devices) > MaxPublicationV7Devices {
		return publicationV7Invalidf(
			"allocation device count %d is outside 1..%d",
			len(allocation.Devices), MaxPublicationV7Devices)
	}
	if len(allocation.Extents) == 0 || len(allocation.Extents) > MaxPublicationV7Extents {
		return publicationV7Invalidf(
			"allocation extent count %d is outside 1..%d",
			len(allocation.Extents), MaxPublicationV7Extents)
	}

	previousUUID := ""
	for index, device := range allocation.Devices {
		if err := validatePublicationV7DeviceUUID(device.DeviceUUID); err != nil {
			return publicationV7FieldInvalid(fmt.Sprintf("allocation device %d", index), err)
		}
		if index > 0 && previousUUID >= device.DeviceUUID {
			return publicationV7Invalidf(
				"allocation devices are duplicate or not strictly ordered by UUID at index %d", index)
		}
		if err := publicationV7PositiveLong("device data page count", device.DataPageCount); err != nil {
			return publicationV7FieldInvalid(fmt.Sprintf("allocation device %d", index), err)
		}
		previousUUID = device.DeviceUUID
	}

	expectedLogical := uint64(0)
	usedDevices := make([]bool, len(allocation.Devices))
	physicalByDevice := make([][]AllocationExtentV7, len(allocation.Devices))
	var previous AllocationExtentV7
	var previousPhysicalEnd uint64
	for index, extent := range allocation.Extents {
		if uint64(extent.DeviceIndex) >= uint64(len(allocation.Devices)) {
			return publicationV7Invalidf(
				"allocation extent %d device index %d exceeds table size %d",
				index, extent.DeviceIndex, len(allocation.Devices))
		}
		if err := publicationV7NonNegativeLong(
			"extent data page start", extent.StartDataPageIndex); err != nil {
			return publicationV7FieldInvalid(fmt.Sprintf("allocation extent %d", index), err)
		}
		if err := publicationV7PositiveLong("extent page count", extent.PageCount); err != nil {
			return publicationV7FieldInvalid(fmt.Sprintf("allocation extent %d", index), err)
		}
		if extent.LogicalPageStart != expectedLogical {
			return publicationV7Invalidf(
				"allocation extents have a gap, overlap, or noncanonical order at logical page %d",
				expectedLogical)
		}
		logicalEnd, ok := addLong(expectedLogical, extent.PageCount)
		if !ok {
			return publicationV7Invalidf("allocation logical coverage overflows signed-Long ABI")
		}
		device := allocation.Devices[extent.DeviceIndex]
		physicalEnd, ok := addLong(extent.StartDataPageIndex, extent.PageCount)
		if !ok || physicalEnd > device.DataPageCount {
			return publicationV7Invalidf(
				"allocation extent %d exceeds device %q capacity %d",
				index, device.DeviceUUID, device.DataPageCount)
		}
		if index > 0 && extent.DeviceIndex == previous.DeviceIndex &&
			previousPhysicalEnd == extent.StartDataPageIndex {
			return publicationV7Invalidf(
				"allocation extents %d and %d are adjacent and coalescible",
				index-1, index)
		}
		usedDevices[extent.DeviceIndex] = true
		physicalByDevice[extent.DeviceIndex] = append(
			physicalByDevice[extent.DeviceIndex], extent)
		expectedLogical = logicalEnd
		previous = extent
		previousPhysicalEnd = physicalEnd
	}
	if expectedLogical != allocation.TotalPages {
		return publicationV7Invalidf(
			"allocation extents cover %d pages, allocation declares %d",
			expectedLogical, allocation.TotalPages)
	}
	for index, used := range usedDevices {
		if !used {
			return publicationV7Invalidf(
				"compact allocation device %q is not referenced by any extent",
				allocation.Devices[index].DeviceUUID)
		}
		extents := append([]AllocationExtentV7(nil), physicalByDevice[index]...)
		sort.Slice(extents, func(left, right int) bool {
			return extents[left].StartDataPageIndex < extents[right].StartDataPageIndex
		})
		for extentIndex := 1; extentIndex < len(extents); extentIndex++ {
			previousEnd, ok := addLong(
				extents[extentIndex-1].StartDataPageIndex,
				extents[extentIndex-1].PageCount)
			if !ok || previousEnd > extents[extentIndex].StartDataPageIndex {
				return publicationV7Invalidf(
					"allocation extents overlap physically on device %q",
					allocation.Devices[index].DeviceUUID)
			}
		}
	}
	return nil
}

func validateContentObjectsV7(
	objects []ContentObjectV7,
	totalPages uint64,
) (map[uint64]ContentObjectV7, publicationV7ControlObjects, error) {
	var controls publicationV7ControlObjects
	if len(objects) == 0 || len(objects) > MaxPublicationV7Objects {
		return nil, controls, publicationV7Invalidf(
			"content object count %d is outside 1..%d",
			len(objects), MaxPublicationV7Objects)
	}
	byID := make(map[uint64]ContentObjectV7, len(objects))
	expectedLogical := uint64(0)
	previousObjectID := uint64(0)
	kindCounts := make(map[ContentKindV7]int)
	for index, object := range objects {
		if err := publicationV7PositiveLong("content object ID", object.ObjectID); err != nil {
			return nil, controls, publicationV7FieldInvalid(
				fmt.Sprintf("content object %d", index), err)
		}
		if index > 0 && previousObjectID >= object.ObjectID {
			return nil, controls, publicationV7Invalidf(
				"content objects are duplicate or not strictly ordered by object ID at index %d", index)
		}
		if !object.Kind.valid() {
			return nil, controls, publicationV7Invalidf(
				"content object %d has unknown V7 kind %d", index, object.Kind)
		}
		if err := publicationV7NonNegativeLong(
			"content immutable byte length", object.ImmutableByteLength); err != nil {
			return nil, controls, publicationV7FieldInvalid(
				fmt.Sprintf("content object %d", index), err)
		}
		if err := publicationV7PositiveLong("content capacity pages", object.CapacityPages); err != nil {
			return nil, controls, publicationV7FieldInvalid(
				fmt.Sprintf("content object %d", index), err)
		}
		if object.LogicalPageStart != expectedLogical {
			return nil, controls, publicationV7Invalidf(
				"content objects have a gap, overlap, or noncanonical order at logical page %d",
				expectedLogical)
		}
		zeroLengthKind := object.Kind == ContentPlacementSlotAV7 ||
			object.Kind == ContentPlacementSlotBV7 || object.Kind == ContentPublicationV7
		if zeroLengthKind != (object.ImmutableByteLength == 0) {
			return nil, controls, publicationV7Invalidf(
				"content object %d kind %d has invalid immutable byte length %d",
				object.ObjectID, object.Kind, object.ImmutableByteLength)
		}
		if !zeroLengthKind {
			requiredPages, ok := publicationV7ImmutableCapacityPages(
				object.ImmutableByteLength)
			if !ok {
				return nil, controls, publicationV7Invalidf(
					"content object %d immutable length %d cannot be represented as 4 KiB pages",
					object.ObjectID, object.ImmutableByteLength)
			}
			if object.CapacityPages != requiredPages {
				return nil, controls, publicationV7Invalidf(
					"content object %d kind %d capacity %d pages is noncanonical for immutable length %d; expected %d pages",
					object.ObjectID, object.Kind, object.CapacityPages,
					object.ImmutableByteLength, requiredPages)
			}
			if object.Kind == ContentMemoryPayloadV7 {
				capacityBytes, ok := mulLong(
					object.CapacityPages, PublicationV7PageSize)
				if !ok || object.ImmutableByteLength != capacityBytes {
					return nil, controls, publicationV7Invalidf(
						"memory payload object %d must fill every reserved page",
						object.ObjectID)
				}
			}
		}
		switch object.Kind {
		case ContentMMTemplateMetadataV7, ContentArtifactManifestMetadataV7:
			if object.ImmutableByteLength <= MetadataV7EnvelopeHeaderBytes ||
				object.ImmutableByteLength > MaxMetadataV7Bytes {
				return nil, controls, publicationV7Invalidf(
					"metadata object %d length %d is outside (%d,%d]",
					object.ObjectID, object.ImmutableByteLength,
					MetadataV7EnvelopeHeaderBytes, MaxMetadataV7Bytes)
			}
		case ContentVirtualPageMapMetadataV7:
			if object.ImmutableByteLength <= ContentMappingEnvelopeHeaderBytes ||
				object.ImmutableByteLength > MaxContentMappingBytes {
				return nil, controls, publicationV7Invalidf(
					"VirtualPageMap object %d length %d is outside (%d,%d]",
					object.ObjectID, object.ImmutableByteLength,
					ContentMappingEnvelopeHeaderBytes, MaxContentMappingBytes)
			}
		case ContentPlacementSlotAV7, ContentPlacementSlotBV7:
			if object.CapacityPages > MaxPlacementSlotV7Pages {
				return nil, controls, publicationV7Invalidf(
					"placement slot object %d capacity %d pages exceeds %d",
					object.ObjectID, object.CapacityPages, MaxPlacementSlotV7Pages)
			}
		case ContentPublicationV7:
			if object.CapacityPages > MaxPublicationV7SlotPages {
				return nil, controls, publicationV7Invalidf(
					"publication slot object %d capacity %d pages exceeds %d",
					object.ObjectID, object.CapacityPages, MaxPublicationV7SlotPages)
			}
		}
		nextLogical, ok := addLong(expectedLogical, object.CapacityPages)
		if !ok {
			return nil, controls, publicationV7Invalidf(
				"content object logical coverage overflows signed-Long ABI")
		}
		expectedLogical = nextLogical
		byID[object.ObjectID] = object
		kindCounts[object.Kind]++
		previousObjectID = object.ObjectID
		switch object.Kind {
		case ContentMMTemplateMetadataV7:
			controls.mmTemplateObjectID = object.ObjectID
		case ContentVirtualPageMapMetadataV7:
			controls.virtualPageMapObjectID = object.ObjectID
		case ContentArtifactManifestMetadataV7:
			controls.artifactManifestObjectID = object.ObjectID
		case ContentPlacementSlotAV7:
			controls.placementSlotAObjectID = object.ObjectID
		case ContentPlacementSlotBV7:
			controls.placementSlotBObjectID = object.ObjectID
		case ContentPublicationV7:
			controls.publicationObjectID = object.ObjectID
		}
	}
	if expectedLogical != totalPages {
		return nil, controls, publicationV7Invalidf(
			"content objects cover %d pages, allocation declares %d",
			expectedLogical, totalPages)
	}
	if kindCounts[ContentMemoryPayloadV7] == 0 {
		return nil, controls, publicationV7Invalidf(
			"immutable publication has no memory payload object")
	}
	for _, kind := range []ContentKindV7{
		ContentMMTemplateMetadataV7,
		ContentVirtualPageMapMetadataV7,
		ContentArtifactManifestMetadataV7,
		ContentPlacementSlotAV7,
		ContentPlacementSlotBV7,
		ContentPublicationV7,
	} {
		if kindCounts[kind] != 1 {
			return nil, controls, publicationV7Invalidf(
				"immutable publication requires exactly one object of kind %d, found %d",
				kind, kindCounts[kind])
		}
	}
	return byID, controls, nil
}

// publicationV7ImmutableCapacityPages computes ceil(byteLength / 4096)
// without the overflow-prone byteLength+pageSize-1 expression. Only A/B and
// Publication are reservation objects; every other kind must use this exact
// minimum capacity.
func publicationV7ImmutableCapacityPages(byteLength uint64) (uint64, bool) {
	if byteLength == 0 || byteLength > MaxSignedLong || PublicationV7PageSize == 0 {
		return 0, false
	}
	pages := byteLength / PublicationV7PageSize
	if byteLength%PublicationV7PageSize != 0 {
		if pages == MaxSignedLong {
			return 0, false
		}
		pages++
	}
	return pages, pages > 0 && pages <= MaxSignedLong
}

func validatePublicationV7References(
	publication PublicationV7,
	objects map[uint64]ContentObjectV7,
	controls publicationV7ControlObjects,
) error {
	if err := validatePublicationV7TypedRef(
		"MMTemplate", publication.MMTemplate.ObjectID,
		publication.MMTemplate.MMTemplateID, publication.MMTemplate.Version,
		publication.MMTemplate.SHA256,
		ContentMMTemplateMetadataV7, objects); err != nil {
		return err
	}
	if publication.MMTemplate.ObjectID != controls.mmTemplateObjectID {
		return publicationV7Invalidf("MMTemplate typed reference does not select the unique MMTemplate object")
	}
	if err := validatePublicationV7TypedRef(
		"VirtualPageMap", publication.VirtualPageMap.ObjectID,
		publication.VirtualPageMap.VirtualPageMapID, publication.VirtualPageMap.Version,
		publication.VirtualPageMap.SHA256,
		ContentVirtualPageMapMetadataV7, objects); err != nil {
		return err
	}
	if publication.VirtualPageMap.ObjectID != controls.virtualPageMapObjectID {
		return publicationV7Invalidf("VirtualPageMap typed reference does not select the unique VirtualPageMap object")
	}
	if err := validatePublicationV7TypedRef(
		"ArtifactManifest", publication.ArtifactManifest.ObjectID,
		publication.ArtifactManifest.ArtifactManifestID,
		publication.ArtifactManifest.Version, publication.ArtifactManifest.SHA256,
		ContentArtifactManifestMetadataV7, objects); err != nil {
		return err
	}
	if publication.ArtifactManifest.ObjectID != controls.artifactManifestObjectID {
		return publicationV7Invalidf("ArtifactManifest typed reference does not select the unique ArtifactManifest object")
	}

	if publication.PlacementSlots.AObjectID != controls.placementSlotAObjectID ||
		publication.PlacementSlots.BObjectID != controls.placementSlotBObjectID {
		return publicationV7Invalidf("placement slot references do not select the unique fixed A/B objects")
	}
	if publication.PlacementSlots.AObjectID == publication.PlacementSlots.BObjectID {
		return publicationV7Invalidf("placement slots A and B share object %d", publication.PlacementSlots.AObjectID)
	}
	a := objects[publication.PlacementSlots.AObjectID]
	b := objects[publication.PlacementSlots.BObjectID]
	if a.CapacityPages == 0 || a.CapacityPages != b.CapacityPages {
		return publicationV7Invalidf(
			"placement slot capacities differ: A=%d pages B=%d pages",
			a.CapacityPages, b.CapacityPages)
	}
	return nil
}

func validatePublicationV7TypedRef(
	name string,
	objectID uint64,
	semanticID string,
	version uint64,
	digest [sha256.Size]byte,
	expectedKind ContentKindV7,
	objects map[uint64]ContentObjectV7,
) error {
	if err := publicationV7PositiveLong(name+" object ID", objectID); err != nil {
		return err
	}
	if err := validatePublicationV7Identity(name+" semantic ID", semanticID); err != nil {
		return err
	}
	if err := publicationV7PositiveLong(name+" version", version); err != nil {
		return err
	}
	if publicationV7DigestIsZero(digest) {
		return publicationV7Invalidf("%s SHA-256 is zero", name)
	}
	object, exists := objects[objectID]
	if !exists || object.Kind != expectedKind {
		return publicationV7Invalidf(
			"%s object %d is missing or has kind %d, expected %d",
			name, objectID, object.Kind, expectedKind)
	}
	return nil
}

// MappingContentObjects returns only the payload catalog understood by the
// delivered V7 VirtualPageMap and ContentPlacementMap codecs. Pinned metadata,
// A/B slots, and the publication object are deliberately absent, preventing a
// placement map from mapping the bytes needed to bootstrap itself.
func (publication PublicationV7) MappingContentObjects() ([]ContentObject, error) {
	if err := publication.Validate(); err != nil {
		return nil, err
	}
	return publication.mappingContentObjectsValidated(), nil
}

// mappingContentObjectsValidated requires a successful PublicationV7.Validate
// in the caller. Keeping this adapter private prevents unvalidated graphs from
// bypassing the public boundary while avoiding repeated full graph encoding in
// compound cross-checks.
func (publication PublicationV7) mappingContentObjectsValidated() []ContentObject {
	objects := make([]ContentObject, 0, len(publication.Objects))
	for _, object := range publication.Objects {
		var kind ContentKind
		switch object.Kind {
		case ContentMemoryPayloadV7:
			kind = ContentMemory
		case ContentArtifactPayloadV7:
			kind = ContentArtifact
		case ContentRestoreBlobPayloadV7:
			kind = ContentRestoreBlob
		default:
			continue
		}
		objects = append(objects, ContentObject{
			ObjectID:         object.ObjectID,
			Kind:             kind,
			ByteLength:       object.ImmutableByteLength,
			LogicalPageStart: object.LogicalPageStart,
			PageCount:        object.CapacityPages,
		})
	}
	return objects
}

// ControlObjectPageRuns derives a pinned control object's initial physical
// runs. Payload kinds are rejected: after deduplication their initial pages may
// have been released or reused, so restore-time payload lookup must use only
// the ContentPlacementMap selected by ActiveContentPlacementRoot.
func (publication PublicationV7) ControlObjectPageRuns(
	objectID uint64,
	exactByteLength uint64,
) ([]AllocationPageRunV7, error) {
	if err := publication.Validate(); err != nil {
		return nil, err
	}
	object, exists := publication.objectByID(objectID)
	if !exists {
		return nil, publicationV7Invalidf("control locator references unknown object %d", objectID)
	}
	return publication.controlObjectPageRunsValidated(object, exactByteLength, 0)
}

func (publication PublicationV7) controlObjectPageRunsValidated(
	object ContentObjectV7,
	exactByteLength uint64,
	knownCanonicalPublicationLength uint64,
) ([]AllocationPageRunV7, error) {
	if !object.Kind.pinnedControl() {
		return nil, publicationV7Invalidf(
			"object %d kind %d is payload and must be resolved through the active placement map",
			object.ObjectID, object.Kind)
	}
	if err := publication.validateControlExactLength(
		object, exactByteLength, knownCanonicalPublicationLength); err != nil {
		return nil, err
	}
	pageCount := (exactByteLength + PublicationV7PageSize - 1) / PublicationV7PageSize
	return publication.allocationPageRuns(
		object.LogicalPageStart, pageCount, object.LogicalPageStart)
}

func (publication PublicationV7) validateControlExactLength(
	object ContentObjectV7,
	exactByteLength uint64,
	knownCanonicalPublicationLength uint64,
) error {
	if err := publicationV7PositiveLong("control object exact byte length", exactByteLength); err != nil {
		return err
	}
	capacityBytes, ok := mulLong(object.CapacityPages, PublicationV7PageSize)
	if !ok || exactByteLength > capacityBytes {
		return publicationV7Invalidf(
			"control object %d exact length %d exceeds capacity %d",
			object.ObjectID, exactByteLength, capacityBytes)
	}
	switch object.Kind {
	case ContentMMTemplateMetadataV7,
		ContentVirtualPageMapMetadataV7,
		ContentArtifactManifestMetadataV7:
		if exactByteLength != object.ImmutableByteLength {
			return publicationV7Invalidf(
				"control object %d exact length %d does not match immutable length %d",
				object.ObjectID, exactByteLength, object.ImmutableByteLength)
		}
	case ContentPlacementSlotAV7, ContentPlacementSlotBV7:
		if exactByteLength <= ContentMappingEnvelopeHeaderBytes ||
			exactByteLength > MaxContentMappingBytes {
			return publicationV7Invalidf(
				"placement slot object %d exact length %d is outside (%d,%d]",
				object.ObjectID, exactByteLength,
				ContentMappingEnvelopeHeaderBytes, MaxContentMappingBytes)
		}
	case ContentPublicationV7:
		want := knownCanonicalPublicationLength
		if want == 0 {
			payload, err := marshalPublicationV7Payload(publication)
			if err != nil {
				return err
			}
			want = PublicationV7EnvelopeHeaderBytes + uint64(len(payload))
		}
		if exactByteLength != want {
			return publicationV7Invalidf(
				"publication object exact length %d does not match canonical length %d",
				exactByteLength, want)
		}
	default:
		return publicationV7Invalidf("object %d is not pinned control metadata", object.ObjectID)
	}
	return nil
}

func (publication PublicationV7) allocationPageRuns(
	globalLogicalStart uint64,
	pageCount uint64,
	objectLogicalStart uint64,
) ([]AllocationPageRunV7, error) {
	if pageCount == 0 {
		return nil, publicationV7Invalidf("derived page run has zero pages")
	}
	rangeEnd, ok := addLong(globalLogicalStart, pageCount)
	if !ok || rangeEnd > publication.InitialAllocation.TotalPages {
		return nil, publicationV7Invalidf("derived logical page range exceeds initial allocation")
	}
	runs := make([]AllocationPageRunV7, 0, len(publication.InitialAllocation.Extents))
	covered := uint64(0)
	for _, extent := range publication.InitialAllocation.Extents {
		extentEnd, ok := addLong(extent.LogicalPageStart, extent.PageCount)
		if !ok {
			return nil, publicationV7Invalidf("allocation extent logical range overflows")
		}
		overlapStart := globalLogicalStart
		if extent.LogicalPageStart > overlapStart {
			overlapStart = extent.LogicalPageStart
		}
		overlapEnd := rangeEnd
		if extentEnd < overlapEnd {
			overlapEnd = extentEnd
		}
		if overlapStart >= overlapEnd {
			continue
		}
		runPages := overlapEnd - overlapStart
		physicalStart, ok := addLong(
			extent.StartDataPageIndex, overlapStart-extent.LogicalPageStart)
		if !ok {
			return nil, publicationV7Invalidf("derived physical page range overflows")
		}
		device := publication.InitialAllocation.Devices[extent.DeviceIndex]
		run := AllocationPageRunV7{
			ObjectPageStart: overlapStart - objectLogicalStart,
			FirstPage: PageID{
				OwnerID:            publication.InitialAllocation.OwnerID,
				DeviceUUID:         device.DeviceUUID,
				AllocationRecordID: publication.InitialAllocation.AllocationRecordID,
				DataPageIndex:      physicalStart,
			},
			OwnerEpoch: publication.InitialAllocation.OwnerEpoch,
			PageCount:  runPages,
		}
		if len(runs) > 0 && allocationPageRunsV7Coalescible(runs[len(runs)-1], run) {
			previous := &runs[len(runs)-1]
			combined, ok := addLong(previous.PageCount, run.PageCount)
			if !ok {
				return nil, publicationV7Invalidf("derived page-run length overflows")
			}
			previous.PageCount = combined
		} else {
			runs = append(runs, run)
			if len(runs) > MaxPublicationV7PageRuns {
				return nil, publicationV7Invalidf(
					"derived PageID run count exceeds %d", MaxPublicationV7PageRuns)
			}
		}
		covered, ok = addLong(covered, runPages)
		if !ok {
			return nil, publicationV7Invalidf("derived page coverage overflows")
		}
	}
	if covered != pageCount {
		return nil, publicationV7Invalidf(
			"derived PageID runs cover %d pages, expected %d", covered, pageCount)
	}
	return runs, nil
}

func allocationPageRunsV7Coalescible(left, right AllocationPageRunV7) bool {
	leftObjectEnd, objectOK := addLong(left.ObjectPageStart, left.PageCount)
	leftPhysicalEnd, physicalOK := addLong(left.FirstPage.DataPageIndex, left.PageCount)
	return objectOK && physicalOK && leftObjectEnd == right.ObjectPageStart &&
		left.FirstPage.OwnerID == right.FirstPage.OwnerID &&
		left.OwnerEpoch == right.OwnerEpoch &&
		left.FirstPage.DeviceUUID == right.FirstPage.DeviceUUID &&
		left.FirstPage.AllocationRecordID == right.FirstPage.AllocationRecordID &&
		leftPhysicalEnd == right.FirstPage.DataPageIndex
}

// InitialContentPlacementMap creates the dump-time payload map from the exact
// checkpoint allocation. Callers must publish this map through A/B and use the
// active root thereafter; this helper is never a restore-time fallback.
func (publication PublicationV7) InitialContentPlacementMap(
	mapID string,
	version uint64,
) (ContentPlacementMap, error) {
	if err := publication.Validate(); err != nil {
		return ContentPlacementMap{}, err
	}
	if err := validatePublicationV7Identity("initial ContentPlacementMap ID", mapID); err != nil {
		return ContentPlacementMap{}, err
	}
	if err := publicationV7PositiveLong("initial ContentPlacementMap version", version); err != nil {
		return ContentPlacementMap{}, err
	}
	contentObjects := publication.mappingContentObjectsValidated()
	devices := make([]Device, len(publication.InitialAllocation.Devices))
	deviceIndex := make(map[string]uint32, len(devices))
	for index, device := range publication.InitialAllocation.Devices {
		devices[index] = Device{
			DeviceUUID:    device.DeviceUUID,
			OwnerID:       publication.InitialAllocation.OwnerID,
			OwnerEpoch:    publication.InitialAllocation.OwnerEpoch,
			DataPageCount: device.DataPageCount,
		}
		deviceIndex[device.DeviceUUID] = uint32(index)
	}
	runs := make([]ContentPlacementRun, 0, len(publication.InitialAllocation.Extents))
	for _, object := range publication.Objects {
		if !object.Kind.placementPayload() {
			continue
		}
		pageRuns, err := publication.allocationPageRuns(
			object.LogicalPageStart, object.CapacityPages, object.LogicalPageStart)
		if err != nil {
			return ContentPlacementMap{}, err
		}
		for _, pageRun := range pageRuns {
			run := ContentPlacementRun{
				ContentObjectID:    object.ObjectID,
				ObjectPageIndex:    pageRun.ObjectPageStart,
				PageCount:          pageRun.PageCount,
				DeviceIndex:        deviceIndex[pageRun.FirstPage.DeviceUUID],
				AllocationRecordID: pageRun.FirstPage.AllocationRecordID,
				DataPageIndex:      pageRun.FirstPage.DataPageIndex,
			}
			if len(runs) > 0 && contentPlacementRunsV7Coalescible(runs[len(runs)-1], run) {
				combined, ok := addLong(runs[len(runs)-1].PageCount, run.PageCount)
				if !ok {
					return ContentPlacementMap{}, publicationV7Invalidf(
						"initial ContentPlacementMap run length overflows")
				}
				runs[len(runs)-1].PageCount = combined
			} else {
				runs = append(runs, run)
			}
		}
	}
	result := ContentPlacementMap{
		ContentPlacementMapID: mapID,
		Version:               version,
		PageSize:              PublicationV7PageSize,
		Devices:               devices,
		Runs:                  runs,
	}
	if err := result.Validate(contentObjects); err != nil {
		return ContentPlacementMap{}, publicationV7FieldInvalid(
			"initial ContentPlacementMap", err)
	}
	return result, nil
}

// CrossCheckImmutableGraph proves that all three typed immutable metadata
// references bind exact canonical bytes, semantic identities, semantic
// versions, and exact object lengths. It also proves MMTemplate/VPM topology
// and exact artifact-payload coverage. No content bytes or DAX I/O are read.
func (publication PublicationV7) CrossCheckImmutableGraph(
	template MMTemplateV7,
	virtualPageMap VirtualPageMap,
	manifest ArtifactManifestV7,
) error {
	if err := publication.Validate(); err != nil {
		return err
	}
	contentObjects := publication.mappingContentObjectsValidated()
	if err := template.Validate(); err != nil {
		return publicationV7FieldInvalid("MMTemplateV7", err)
	}
	if err := template.crossCheckVirtualPageMapValidated(
		publication, virtualPageMap, contentObjects); err != nil {
		return publicationV7FieldInvalid("MMTemplate/VirtualPageMap graph", err)
	}
	if err := manifest.Validate(); err != nil {
		return publicationV7FieldInvalid("ArtifactManifestV7", err)
	}
	if err := manifest.crossCheckPublicationValidated(publication); err != nil {
		return publicationV7FieldInvalid("ArtifactManifest/publication graph", err)
	}

	templateBytes, err := CanonicalMMTemplateV7Bytes(template)
	if err != nil {
		return publicationV7FieldInvalid("canonical MMTemplateV7", err)
	}
	virtualBytes, err := CanonicalVirtualPageMapBytes(virtualPageMap, contentObjects)
	if err != nil {
		return publicationV7FieldInvalid("canonical VirtualPageMap", err)
	}
	manifestBytes, err := CanonicalArtifactManifestV7Bytes(manifest)
	if err != nil {
		return publicationV7FieldInvalid("canonical ArtifactManifestV7", err)
	}
	if err := publication.crossCheckMMTemplateReference(template, templateBytes); err != nil {
		return err
	}
	if err := publication.crossCheckVirtualPageMapReference(
		virtualPageMap, virtualBytes); err != nil {
		return err
	}
	if err := publication.crossCheckArtifactManifestReference(
		manifest, manifestBytes); err != nil {
		return err
	}
	return nil
}

func (publication PublicationV7) crossCheckMMTemplateReference(
	template MMTemplateV7,
	canonical []byte,
) error {
	if template.MMTemplateID != publication.MMTemplate.MMTemplateID ||
		template.Version != publication.MMTemplate.Version {
		return publicationV7Invalidf(
			"MMTemplate semantic identity/version does not match typed reference")
	}
	return publication.crossCheckTypedObjectBytes(
		"MMTemplate", publication.MMTemplate.ObjectID,
		ContentMMTemplateMetadataV7, canonical, publication.MMTemplate.SHA256)
}

func (publication PublicationV7) crossCheckVirtualPageMapReference(
	virtualPageMap VirtualPageMap,
	canonical []byte,
) error {
	if virtualPageMap.VirtualPageMapID != publication.VirtualPageMap.VirtualPageMapID ||
		virtualPageMap.Version != publication.VirtualPageMap.Version {
		return publicationV7Invalidf(
			"VirtualPageMap semantic identity/version does not match typed reference")
	}
	return publication.crossCheckTypedObjectBytes(
		"VirtualPageMap", publication.VirtualPageMap.ObjectID,
		ContentVirtualPageMapMetadataV7, canonical, publication.VirtualPageMap.SHA256)
}

func (publication PublicationV7) crossCheckArtifactManifestReference(
	manifest ArtifactManifestV7,
	canonical []byte,
) error {
	if manifest.ArtifactManifestID != publication.ArtifactManifest.ArtifactManifestID ||
		manifest.Version != publication.ArtifactManifest.Version {
		return publicationV7Invalidf(
			"ArtifactManifest semantic identity/version does not match typed reference")
	}
	return publication.crossCheckTypedObjectBytes(
		"ArtifactManifest", publication.ArtifactManifest.ObjectID,
		ContentArtifactManifestMetadataV7, canonical,
		publication.ArtifactManifest.SHA256)
}

func (publication PublicationV7) crossCheckTypedObjectBytes(
	name string,
	objectID uint64,
	expectedKind ContentKindV7,
	canonical []byte,
	wantDigest [sha256.Size]byte,
) error {
	object, exists := publication.objectByID(objectID)
	if !exists || object.Kind != expectedKind {
		return publicationV7Invalidf(
			"%s typed reference does not target kind %d", name, expectedKind)
	}
	if uint64(len(canonical)) != object.ImmutableByteLength {
		return publicationV7Invalidf(
			"canonical %s length is %d, object binds %d",
			name, len(canonical), object.ImmutableByteLength)
	}
	if digest := sha256.Sum256(canonical); digest != wantDigest {
		return publicationV7Invalidf("canonical %s SHA-256 does not match typed reference", name)
	}
	return nil
}

// CrossCheckActivePlacementRootImmutableBindings verifies the immutable half
// of a TRAPR007 selection: exact TRPUB007 bytes, checkpoint identity, exact
// VirtualPageMap reference, selected A/B kind, and selected slot capacity for
// the root's ContentPlacementMap length. It deliberately does not validate the
// mutable map bytes/device digest; ActiveContentPlacementRoot.CrossCheck does
// that when a ContentPlacementMap is available.
func (publication PublicationV7) CrossCheckActivePlacementRootImmutableBindings(
	root ActiveContentPlacementRoot,
	virtualPageMap VirtualPageMap,
) error {
	if err := publication.Validate(); err != nil {
		return err
	}
	if err := root.Validate(); err != nil {
		return publicationV7FieldInvalid("active placement root", err)
	}
	contentObjects := publication.mappingContentObjectsValidated()
	virtualBytes, err := CanonicalVirtualPageMapBytes(virtualPageMap, contentObjects)
	if err != nil {
		return publicationV7FieldInvalid("canonical VirtualPageMap", err)
	}
	if err := publication.crossCheckVirtualPageMapReference(
		virtualPageMap, virtualBytes); err != nil {
		return err
	}
	payload, err := marshalPublicationV7Payload(publication)
	if err != nil {
		return err
	}
	publicationBytes, err := marshalPublicationV7Envelope(payload)
	if err != nil {
		return err
	}
	if root.CheckpointID != publication.CheckpointID {
		return publicationV7Invalidf(
			"active root checkpoint %q does not match publication checkpoint %q",
			root.CheckpointID, publication.CheckpointID)
	}
	if root.ImmutablePublicationLength != uint64(len(publicationBytes)) ||
		root.ImmutablePublicationSHA256 != sha256.Sum256(publicationBytes) {
		return publicationV7Invalidf(
			"active root immutable publication length/SHA-256 binding does not match TRPUB007")
	}
	if root.VirtualPageMapID != publication.VirtualPageMap.VirtualPageMapID ||
		root.VirtualPageMapVersion != publication.VirtualPageMap.Version ||
		root.VirtualPageMapLength != uint64(len(virtualBytes)) ||
		root.VirtualPageMapSHA256 != sha256.Sum256(virtualBytes) {
		return publicationV7Invalidf(
			"active root VirtualPageMap binding does not match the exact typed reference")
	}

	var selectedObjectID uint64
	var expectedKind ContentKindV7
	switch root.ActiveMappingSlot {
	case MappingSlotA:
		selectedObjectID = publication.PlacementSlots.AObjectID
		expectedKind = ContentPlacementSlotAV7
	case MappingSlotB:
		selectedObjectID = publication.PlacementSlots.BObjectID
		expectedKind = ContentPlacementSlotBV7
	default:
		return publicationV7Invalidf(
			"active root selects unknown placement slot %d", root.ActiveMappingSlot)
	}
	selected, exists := publication.objectByID(selectedObjectID)
	if !exists || selected.Kind != expectedKind {
		return publicationV7Invalidf(
			"active root selected slot object %d is missing or has kind %d, expected %d",
			selectedObjectID, selected.Kind, expectedKind)
	}
	capacityBytes, ok := mulLong(selected.CapacityPages, PublicationV7PageSize)
	if !ok || root.ContentPlacementMapLength > capacityBytes {
		return publicationV7Invalidf(
			"active root ContentPlacementMap length %d exceeds selected slot capacity %d",
			root.ContentPlacementMapLength, capacityBytes)
	}
	return nil
}

func contentPlacementRunsV7Coalescible(left, right ContentPlacementRun) bool {
	leftObjectEnd, objectOK := addLong(left.ObjectPageIndex, left.PageCount)
	leftPhysicalEnd, physicalOK := addLong(left.DataPageIndex, left.PageCount)
	return objectOK && physicalOK && left.ContentObjectID == right.ContentObjectID &&
		leftObjectEnd == right.ObjectPageIndex && left.DeviceIndex == right.DeviceIndex &&
		left.AllocationRecordID == right.AllocationRecordID &&
		leftPhysicalEnd == right.DataPageIndex
}

// CrossCheckInitialContentPlacementMap proves that map is exactly the
// dump-time placement derived from InitialAllocationV7. It must not be used to
// accept an active post-dedup map, where cross-Owner aliases are expected.
func (publication PublicationV7) CrossCheckInitialContentPlacementMap(
	mapping ContentPlacementMap,
) error {
	expected, err := publication.InitialContentPlacementMap(
		mapping.ContentPlacementMapID, mapping.Version)
	if err != nil {
		return err
	}
	if !equalPublicationV7Devices(expected.Devices, mapping.Devices) ||
		!equalPublicationV7PlacementRuns(expected.Runs, mapping.Runs) ||
		mapping.PageSize != expected.PageSize {
		return publicationV7Invalidf(
			"ContentPlacementMap does not exactly match the dump-time initial allocation")
	}
	return nil
}

func equalPublicationV7Devices(left, right []Device) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func equalPublicationV7PlacementRuns(left, right []ContentPlacementRun) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func (publication PublicationV7) objectByID(objectID uint64) (ContentObjectV7, bool) {
	position := sort.Search(len(publication.Objects), func(index int) bool {
		return publication.Objects[index].ObjectID >= objectID
	})
	if position >= len(publication.Objects) || publication.Objects[position].ObjectID != objectID {
		return ContentObjectV7{}, false
	}
	return publication.Objects[position], true
}

func validatePublicationV7Identity(name, value string) error {
	if value == "" {
		return publicationV7Invalidf("%s is empty", name)
	}
	if !utf8.ValidString(value) {
		return publicationV7Invalidf("%s is not valid UTF-8", name)
	}
	if len(value) > MaxPublicationV7IdentityBytes {
		return publicationV7Invalidf(
			"%s is %d UTF-8 bytes, limit is %d",
			name, len(value), MaxPublicationV7IdentityBytes)
	}
	if strings.TrimSpace(value) != value {
		return publicationV7Invalidf("%s has surrounding whitespace", name)
	}
	for _, character := range value {
		if unicode.IsControl(character) {
			return publicationV7Invalidf("%s contains a control character", name)
		}
	}
	return nil
}

func validatePublicationV7DeviceUUID(value string) error {
	if err := validatePublicationV7Identity("device UUID", value); err != nil {
		return err
	}
	fileURI := len(value) >= len("file:") && strings.EqualFold(value[:len("file:")], "file:")
	if strings.ContainsAny(value, "/\\") || value == "." || value == ".." || fileURI {
		return publicationV7Invalidf("device UUID %q looks like a local path", value)
	}
	return nil
}

func publicationV7PositiveLong(name string, value uint64) error {
	if value == 0 || value > MaxSignedLong {
		return publicationV7Invalidf(
			"%s %d is outside 1..%d", name, value, MaxSignedLong)
	}
	return nil
}

func publicationV7NonNegativeLong(name string, value uint64) error {
	if value > MaxSignedLong {
		return publicationV7Invalidf("%s %d exceeds %d", name, value, MaxSignedLong)
	}
	return nil
}

func publicationV7DigestIsZero(digest [sha256.Size]byte) bool {
	return digest == [sha256.Size]byte{}
}

func publicationV7FieldInvalid(context string, err error) error {
	return fmt.Errorf("%s: %v: %w", context, err, ErrInvalidPublicationV7)
}

func publicationV7Invalidf(format string, arguments ...interface{}) error {
	return fmt.Errorf(format+": %w", append(arguments, ErrInvalidPublicationV7)...)
}

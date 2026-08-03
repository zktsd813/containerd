package cxlcheckpoint

import (
	"errors"
	"fmt"
	"sort"
)

const (
	// ContentMappingVersion is the wire version of the VNext mapping
	// foundation. It does not change Version, MagicString, or the live
	// TRPUB006/V6 publication contract.
	ContentMappingVersion uint32 = 7

	// VirtualPageMapMagicString and ContentPlacementMapMagicString are
	// deliberately distinct from each other and from TRPUB006. The fixed
	// domain in each mapping envelope provides a second type discriminator.
	VirtualPageMapMagicString      = "TRVPM007"
	ContentPlacementMapMagicString = "TRCPM007"
	VirtualPageMapDomain           = "virtual-page-map-v1"
	ContentPlacementMapDomain      = "content-placement-map-v1"

	// ContentMappingEnvelopeHeaderBytes is the exact header size of both V7
	// mapping envelopes. MaxContentMappingBytes bounds the complete canonical
	// envelope, including this header, to the existing 64 MiB map budget.
	ContentMappingEnvelopeHeaderBytes uint64 = 64
	MaxContentMappingBytes            uint64 = MaxPayloadBytes
)

var (
	// ErrWrongContentMappingFormat identifies an incompatible magic, version,
	// domain, mandatory flag, or reserved header field.
	ErrWrongContentMappingFormat = errors.New("not a V7 content mapping")
	// ErrCorruptContentMapping identifies truncated, trailing, checksummed, or
	// structurally impossible V7 mapping bytes.
	ErrCorruptContentMapping = errors.New("corrupt V7 content mapping")
	// ErrInvalidContentMapping identifies a structurally decoded mapping whose
	// object, virtual, or physical semantics are invalid.
	ErrInvalidContentMapping = errors.New("invalid V7 content mapping")
)

// VirtualPageMapRun maps consecutive present virtual pages to consecutive
// pages inside one immutable logical content object. It deliberately contains
// no Owner, device, allocation-record, DAX path, or physical page identity.
type VirtualPageMapRun struct {
	PagesImageID    uint32
	StartVAddr      uint64
	PageCount       uint64
	ContentObjectID uint64
	ObjectPageIndex uint64
}

// VirtualPageMap is immutable virtual-memory topology. Physical placement may
// change in a later dedup epoch without rewriting this object.
type VirtualPageMap struct {
	VirtualPageMapID string
	Version          uint64
	PageSize         uint64
	Runs             []VirtualPageMapRun
}

// ContentPlacementRun maps consecutive object-local logical pages to one
// consecutive physical range. DeviceIndex indexes ContentPlacementMap.Devices;
// the Device supplies the stable Owner, Owner epoch, UUID, and capacity.
type ContentPlacementRun struct {
	ContentObjectID    uint64
	ObjectPageIndex    uint64
	PageCount          uint64
	DeviceIndex        uint32
	AllocationRecordID uint64
	DataPageIndex      uint64
}

// ContentPlacementMap is the mutable A/B mapping payload. A dedup epoch may
// add a canonical device-table entry and rewrite only the inactive placement
// map. The immutable virtual topology and artifact manifest remain unchanged.
//
// ContentMemory, ContentArtifact, and ContentRestoreBlob are the only covered
// kinds. MMTemplate, the current V6 PageMap/control slots, and the publication
// object are excluded so this map never needs to map its own bootstrap bytes.
type ContentPlacementMap struct {
	ContentPlacementMapID string
	Version               uint64
	PageSize              uint64
	Devices               []Device
	Runs                  []ContentPlacementRun
}

// VirtualPageResolution is the logical result for one present virtual page.
// ContiguousPageCount is the number of pages remaining in the same run,
// including the resolved page.
type VirtualPageResolution struct {
	ContentObjectID     uint64
	ObjectPageIndex     uint64
	ContiguousPageCount uint64
}

// ContentPlacementResolution is the physical result for one logical content
// page. OwnerEpoch is kept beside PageID because the existing PageID type does
// not carry the device epoch. ContiguousPageCount is the number of pages
// remaining in the same physical run, including the resolved page.
type ContentPlacementResolution struct {
	PageID              PageID
	OwnerEpoch          uint64
	ContiguousPageCount uint64
}

// Validate proves that m contains canonical, immutable virtual topology and
// references only in-bounds ContentMemory pages. The content-object slice is
// context from the enclosing checkpoint graph and is never retained or
// modified.
func (m VirtualPageMap) Validate(contentObjects []ContentObject) error {
	if err := validateIdentity("VirtualPageMap ID", m.VirtualPageMapID); err != nil {
		return contentMappingFieldInvalid("VirtualPageMap identity", err)
	}
	if err := positiveLong("VirtualPageMap version", m.Version); err != nil {
		return contentMappingFieldInvalid("VirtualPageMap version", err)
	}
	if m.PageSize != PageSize {
		return contentMappingInvalidf(
			"VirtualPageMap page size is %d, expected %d", m.PageSize, PageSize)
	}
	objects, _, err := validateContentMappingObjects(contentObjects)
	if err != nil {
		return err
	}
	if len(m.Runs) == 0 || len(m.Runs) > maxCollectionElements {
		return contentMappingInvalidf(
			"VirtualPageMap run count %d is outside 1..%d",
			len(m.Runs), maxCollectionElements)
	}

	var previous VirtualPageMapRun
	var previousVirtualEnd uint64
	var previousObjectEnd uint64
	logicalRanges := make([]virtualContentRange, 0, len(m.Runs))
	for index, run := range m.Runs {
		if run.PagesImageID == 0 {
			return contentMappingInvalidf(
				"VirtualPageMap run %d has a zero CRIU pages image ID", index)
		}
		if err := alignedAddress("VirtualPageMap virtual address", run.StartVAddr); err != nil {
			return contentMappingFieldInvalid(
				fmt.Sprintf("VirtualPageMap run %d", index), err)
		}
		if err := positiveLong("VirtualPageMap page count", run.PageCount); err != nil {
			return contentMappingFieldInvalid(
				fmt.Sprintf("VirtualPageMap run %d", index), err)
		}
		if err := positiveLong("VirtualPageMap content object ID", run.ContentObjectID); err != nil {
			return contentMappingFieldInvalid(
				fmt.Sprintf("VirtualPageMap run %d", index), err)
		}
		if err := nonNegativeLong("VirtualPageMap object page index", run.ObjectPageIndex); err != nil {
			return contentMappingFieldInvalid(
				fmt.Sprintf("VirtualPageMap run %d", index), err)
		}

		virtualBytes, ok := mulLong(run.PageCount, PageSize)
		if !ok {
			return contentMappingInvalidf(
				"VirtualPageMap run %d virtual byte range overflows signed-Long ABI", index)
		}
		virtualEnd, ok := addLong(run.StartVAddr, virtualBytes)
		if !ok {
			return contentMappingInvalidf(
				"VirtualPageMap run %d virtual range overflows signed-Long ABI", index)
		}
		objectEnd, ok := addLong(run.ObjectPageIndex, run.PageCount)
		if !ok {
			return contentMappingInvalidf(
				"VirtualPageMap run %d object range overflows signed-Long ABI", index)
		}
		object, exists := objects[run.ContentObjectID]
		if !exists {
			return contentMappingInvalidf(
				"VirtualPageMap run %d references unknown content object %d",
				index, run.ContentObjectID)
		}
		if object.Kind != ContentMemory {
			return contentMappingInvalidf(
				"VirtualPageMap run %d references content object %d of kind %d, expected memory",
				index, run.ContentObjectID, object.Kind)
		}
		if objectEnd > object.PageCount {
			return contentMappingInvalidf(
				"VirtualPageMap run %d exceeds content object %d page count %d",
				index, run.ContentObjectID, object.PageCount)
		}
		logicalRanges = append(logicalRanges, virtualContentRange{
			ContentObjectID: run.ContentObjectID,
			ObjectPageIndex: run.ObjectPageIndex,
			PageCount:       run.PageCount,
		})

		if index > 0 {
			if run.PagesImageID < previous.PagesImageID ||
				(run.PagesImageID == previous.PagesImageID && run.StartVAddr < previousVirtualEnd) {
				return contentMappingInvalidf(
					"VirtualPageMap runs overlap or are not ordered by pages image/address at index %d",
					index)
			}
			if run.PagesImageID == previous.PagesImageID &&
				run.StartVAddr == previousVirtualEnd &&
				run.ContentObjectID == previous.ContentObjectID &&
				run.ObjectPageIndex == previousObjectEnd {
				return contentMappingInvalidf(
					"VirtualPageMap runs %d and %d are adjacent and coalescible",
					index-1, index)
			}
		}
		previous = run
		previousVirtualEnd = virtualEnd
		previousObjectEnd = objectEnd
	}
	return validateVirtualContentCoverage(contentObjects, logicalRanges)
}

// Validate proves exact logical coverage of every dedup-eligible content
// object. Physical overlap is intentionally not rejected: two logical pages
// may alias one canonical physical page after content equality is established.
func (m ContentPlacementMap) Validate(contentObjects []ContentObject) error {
	if err := validateIdentity("ContentPlacementMap ID", m.ContentPlacementMapID); err != nil {
		return contentMappingFieldInvalid("ContentPlacementMap identity", err)
	}
	if err := positiveLong("ContentPlacementMap version", m.Version); err != nil {
		return contentMappingFieldInvalid("ContentPlacementMap version", err)
	}
	if m.PageSize != PageSize {
		return contentMappingInvalidf(
			"ContentPlacementMap page size is %d, expected %d", m.PageSize, PageSize)
	}
	if len(m.Devices) == 0 || len(m.Devices) > maxCollectionElements {
		return contentMappingInvalidf(
			"ContentPlacementMap device count %d is outside 1..%d",
			len(m.Devices), maxCollectionElements)
	}
	if _, err := validateDevices(m.Devices); err != nil {
		return contentMappingFieldInvalid("ContentPlacementMap device table", err)
	}
	objects, eligible, err := validateContentMappingObjects(contentObjects)
	if err != nil {
		return err
	}
	if len(eligible) == 0 {
		return contentMappingInvalidf("ContentPlacementMap has no dedup-eligible content objects")
	}
	if len(m.Runs) == 0 || len(m.Runs) > maxCollectionElements {
		return contentMappingInvalidf(
			"ContentPlacementMap run count %d is outside 1..%d",
			len(m.Runs), maxCollectionElements)
	}

	eligibleIndex := 0
	expectedObjectPage := uint64(0)
	var previous ContentPlacementRun
	var previousPhysicalEnd uint64
	for index, run := range m.Runs {
		if err := positiveLong("placement content object ID", run.ContentObjectID); err != nil {
			return contentMappingFieldInvalid(
				fmt.Sprintf("ContentPlacementMap run %d", index), err)
		}
		if err := nonNegativeLong("placement object page index", run.ObjectPageIndex); err != nil {
			return contentMappingFieldInvalid(
				fmt.Sprintf("ContentPlacementMap run %d", index), err)
		}
		if err := positiveLong("placement page count", run.PageCount); err != nil {
			return contentMappingFieldInvalid(
				fmt.Sprintf("ContentPlacementMap run %d", index), err)
		}
		if err := positiveLong("placement allocation record ID", run.AllocationRecordID); err != nil {
			return contentMappingFieldInvalid(
				fmt.Sprintf("ContentPlacementMap run %d", index), err)
		}
		if err := nonNegativeLong("placement data page index", run.DataPageIndex); err != nil {
			return contentMappingFieldInvalid(
				fmt.Sprintf("ContentPlacementMap run %d", index), err)
		}
		object, exists := objects[run.ContentObjectID]
		if !exists {
			return contentMappingInvalidf(
				"ContentPlacementMap run %d references unknown content object %d",
				index, run.ContentObjectID)
		}
		if !placementCoveredKind(object.Kind) {
			return contentMappingInvalidf(
				"ContentPlacementMap run %d references excluded content object %d of kind %d",
				index, run.ContentObjectID, object.Kind)
		}
		objectEnd, ok := addLong(run.ObjectPageIndex, run.PageCount)
		if !ok || objectEnd > object.PageCount {
			return contentMappingInvalidf(
				"ContentPlacementMap run %d exceeds content object %d page count %d",
				index, run.ContentObjectID, object.PageCount)
		}
		if uint64(run.DeviceIndex) >= uint64(len(m.Devices)) {
			return contentMappingInvalidf(
				"ContentPlacementMap run %d device index %d exceeds table size %d",
				index, run.DeviceIndex, len(m.Devices))
		}
		device := m.Devices[run.DeviceIndex]
		physicalEnd, ok := addLong(run.DataPageIndex, run.PageCount)
		if !ok || physicalEnd > device.DataPageCount {
			return contentMappingInvalidf(
				"ContentPlacementMap run %d exceeds device %q page count %d",
				index, device.DeviceUUID, device.DataPageCount)
		}

		if eligibleIndex >= len(eligible) ||
			run.ContentObjectID != eligible[eligibleIndex].ObjectID ||
			run.ObjectPageIndex != expectedObjectPage {
			var expected string
			if eligibleIndex >= len(eligible) {
				expected = "end of eligible content"
			} else {
				expected = fmt.Sprintf(
					"object %d page %d", eligible[eligibleIndex].ObjectID, expectedObjectPage)
			}
			return contentMappingInvalidf(
				"ContentPlacementMap run %d starts at object %d page %d, expected %s",
				index, run.ContentObjectID, run.ObjectPageIndex, expected)
		}

		if index > 0 &&
			run.ContentObjectID == previous.ContentObjectID &&
			run.ObjectPageIndex == previous.ObjectPageIndex+previous.PageCount &&
			run.DeviceIndex == previous.DeviceIndex &&
			run.AllocationRecordID == previous.AllocationRecordID &&
			run.DataPageIndex == previousPhysicalEnd {
			return contentMappingInvalidf(
				"ContentPlacementMap runs %d and %d are adjacent and coalescible",
				index-1, index)
		}

		expectedObjectPage = objectEnd
		if expectedObjectPage == object.PageCount {
			eligibleIndex++
			expectedObjectPage = 0
		}
		previous = run
		previousPhysicalEnd = physicalEnd
	}
	if eligibleIndex != len(eligible) || expectedObjectPage != 0 {
		if eligibleIndex >= len(eligible) {
			return contentMappingInvalidf(
				"ContentPlacementMap coverage state exceeds eligible content table")
		}
		object := eligible[eligibleIndex]
		return contentMappingInvalidf(
			"ContentPlacementMap ends before object %d page %d",
			object.ObjectID, expectedObjectPage)
	}
	return nil
}

type virtualContentRange struct {
	ContentObjectID uint64
	ObjectPageIndex uint64
	PageCount       uint64
}

func validateVirtualContentCoverage(
	contentObjects []ContentObject,
	ranges []virtualContentRange,
) error {
	memoryObjects := make([]ContentObject, 0, len(contentObjects))
	for _, object := range contentObjects {
		if object.Kind == ContentMemory {
			memoryObjects = append(memoryObjects, object)
		}
	}
	if len(memoryObjects) == 0 {
		return contentMappingInvalidf("VirtualPageMap has no memory content objects")
	}
	sort.Slice(memoryObjects, func(i, j int) bool {
		return memoryObjects[i].ObjectID < memoryObjects[j].ObjectID
	})
	sort.Slice(ranges, func(i, j int) bool {
		if ranges[i].ContentObjectID != ranges[j].ContentObjectID {
			return ranges[i].ContentObjectID < ranges[j].ContentObjectID
		}
		return ranges[i].ObjectPageIndex < ranges[j].ObjectPageIndex
	})

	objectIndex := 0
	expectedPage := uint64(0)
	for rangeIndex, logicalRange := range ranges {
		if objectIndex >= len(memoryObjects) ||
			logicalRange.ContentObjectID != memoryObjects[objectIndex].ObjectID ||
			logicalRange.ObjectPageIndex != expectedPage {
			var expected string
			if objectIndex >= len(memoryObjects) {
				expected = "end of memory content"
			} else {
				expected = fmt.Sprintf(
					"object %d page %d", memoryObjects[objectIndex].ObjectID, expectedPage)
			}
			return contentMappingInvalidf(
				"VirtualPageMap logical range %d starts at object %d page %d, expected %s",
				rangeIndex, logicalRange.ContentObjectID,
				logicalRange.ObjectPageIndex, expected)
		}
		rangeEnd, ok := addLong(logicalRange.ObjectPageIndex, logicalRange.PageCount)
		if !ok || rangeEnd > memoryObjects[objectIndex].PageCount {
			return contentMappingInvalidf(
				"VirtualPageMap logical range %d exceeds memory content object %d",
				rangeIndex, logicalRange.ContentObjectID)
		}
		expectedPage = rangeEnd
		if expectedPage == memoryObjects[objectIndex].PageCount {
			objectIndex++
			expectedPage = 0
		}
	}
	if objectIndex != len(memoryObjects) || expectedPage != 0 {
		if objectIndex >= len(memoryObjects) {
			return contentMappingInvalidf(
				"VirtualPageMap coverage state exceeds memory content table")
		}
		return contentMappingInvalidf(
			"VirtualPageMap ends before memory content object %d page %d",
			memoryObjects[objectIndex].ObjectID, expectedPage)
	}
	return nil
}

// ResolveVirtualPage safely resolves one aligned present virtual address. It
// returns false for a sparse hole or malformed/unrepresentable selected run.
// The O(log n) search assumes global canonical ordering, so m is authoritative
// only after successful Validate or DecodeVirtualPageMap. Direct use of an
// unvalidated struct is panic-safe and rejects locally detectable disorder,
// but does not prove the ordering of unrelated distant runs.
func (m VirtualPageMap) ResolveVirtualPage(
	pagesImageID uint32,
	virtualAddress uint64,
) (VirtualPageResolution, bool) {
	if m.PageSize != PageSize || pagesImageID == 0 || virtualAddress > MaxSignedLong ||
		virtualAddress%PageSize != 0 {
		return VirtualPageResolution{}, false
	}
	// Find the first canonical run whose key is strictly greater than the
	// requested image/address, then inspect its predecessor. Validate/Decode
	// proves global ordering once; constant-size neighbor checks catch local
	// damage without turning every restore lookup into O(n).
	position := sort.Search(len(m.Runs), func(index int) bool {
		run := m.Runs[index]
		return run.PagesImageID > pagesImageID ||
			(run.PagesImageID == pagesImageID && run.StartVAddr > virtualAddress)
	})
	if position == 0 {
		return VirtualPageResolution{}, false
	}
	runIndex := position - 1
	run := m.Runs[runIndex]
	if !virtualRunLocallyCanonical(m.Runs, runIndex) ||
		run.PagesImageID != pagesImageID || run.PageCount == 0 ||
		run.StartVAddr > virtualAddress || run.StartVAddr%PageSize != 0 {
		return VirtualPageResolution{}, false
	}
	bytes, ok := mulLong(run.PageCount, PageSize)
	if !ok {
		return VirtualPageResolution{}, false
	}
	end, ok := addLong(run.StartVAddr, bytes)
	if !ok || virtualAddress >= end {
		return VirtualPageResolution{}, false
	}
	deltaPages := (virtualAddress - run.StartVAddr) / PageSize
	objectPage, ok := addLong(run.ObjectPageIndex, deltaPages)
	if !ok || run.ContentObjectID == 0 || run.ContentObjectID > MaxSignedLong {
		return VirtualPageResolution{}, false
	}
	return VirtualPageResolution{
		ContentObjectID:     run.ContentObjectID,
		ObjectPageIndex:     objectPage,
		ContiguousPageCount: run.PageCount - deltaPages,
	}, true
}

// ResolveContentPage safely resolves one object-local logical page through the
// map's portable device table. The O(log n) search assumes global canonical
// ordering, so m is authoritative only after successful Validate or
// DecodeContentPlacementMap. Direct use of an unvalidated struct is panic-safe
// and rejects locally detectable disorder, but does not prove unrelated
// distant runs. Physical aliasing is preserved: two logical inputs may return
// the same PageID after deduplication.
func (m ContentPlacementMap) ResolveContentPage(
	contentObjectID uint64,
	objectPageIndex uint64,
) (ContentPlacementResolution, bool) {
	if m.PageSize != PageSize || contentObjectID == 0 || contentObjectID > MaxSignedLong ||
		objectPageIndex > MaxSignedLong {
		return ContentPlacementResolution{}, false
	}
	position := sort.Search(len(m.Runs), func(index int) bool {
		run := m.Runs[index]
		return run.ContentObjectID > contentObjectID ||
			(run.ContentObjectID == contentObjectID &&
				run.ObjectPageIndex > objectPageIndex)
	})
	if position == 0 {
		return ContentPlacementResolution{}, false
	}
	runIndex := position - 1
	run := m.Runs[runIndex]
	if !placementRunLocallyCanonical(m.Runs, runIndex) ||
		run.ContentObjectID != contentObjectID || run.PageCount == 0 ||
		objectPageIndex < run.ObjectPageIndex {
		return ContentPlacementResolution{}, false
	}
	objectEnd, ok := addLong(run.ObjectPageIndex, run.PageCount)
	if !ok || objectPageIndex >= objectEnd ||
		uint64(run.DeviceIndex) >= uint64(len(m.Devices)) {
		return ContentPlacementResolution{}, false
	}
	device := m.Devices[run.DeviceIndex]
	if validateDeviceUUID(device.DeviceUUID) != nil ||
		validateIdentity("device owner ID", device.OwnerID) != nil ||
		positiveLong("device owner epoch", device.OwnerEpoch) != nil ||
		positiveLong("device page count", device.DataPageCount) != nil ||
		positiveLong("allocation record ID", run.AllocationRecordID) != nil ||
		nonNegativeLong("data page index", run.DataPageIndex) != nil {
		return ContentPlacementResolution{}, false
	}
	delta := objectPageIndex - run.ObjectPageIndex
	dataPage, ok := addLong(run.DataPageIndex, delta)
	if !ok || dataPage >= device.DataPageCount {
		return ContentPlacementResolution{}, false
	}
	physicalEnd, ok := addLong(run.DataPageIndex, run.PageCount)
	if !ok || physicalEnd > device.DataPageCount {
		return ContentPlacementResolution{}, false
	}
	return ContentPlacementResolution{
		PageID: PageID{
			OwnerID:            device.OwnerID,
			DeviceUUID:         device.DeviceUUID,
			AllocationRecordID: run.AllocationRecordID,
			DataPageIndex:      dataPage,
		},
		OwnerEpoch:          device.OwnerEpoch,
		ContiguousPageCount: run.PageCount - delta,
	}, true
}

func virtualRunLocallyCanonical(runs []VirtualPageMapRun, index int) bool {
	current := runs[index]
	currentEnd, ok := virtualRunEnd(current)
	if !ok {
		return false
	}
	if index > 0 {
		previous := runs[index-1]
		if previous.PagesImageID > current.PagesImageID ||
			(previous.PagesImageID == current.PagesImageID &&
				previous.StartVAddr >= current.StartVAddr) {
			return false
		}
		previousEnd, previousOK := virtualRunEnd(previous)
		if !previousOK ||
			(previous.PagesImageID == current.PagesImageID &&
				previousEnd > current.StartVAddr) {
			return false
		}
	}
	if index+1 < len(runs) {
		next := runs[index+1]
		if current.PagesImageID > next.PagesImageID ||
			(current.PagesImageID == next.PagesImageID &&
				current.StartVAddr >= next.StartVAddr) {
			return false
		}
		if current.PagesImageID == next.PagesImageID &&
			currentEnd > next.StartVAddr {
			return false
		}
	}
	return true
}

func virtualRunEnd(run VirtualPageMapRun) (uint64, bool) {
	bytes, ok := mulLong(run.PageCount, PageSize)
	if !ok || run.PageCount == 0 {
		return 0, false
	}
	return addLong(run.StartVAddr, bytes)
}

func placementRunLocallyCanonical(runs []ContentPlacementRun, index int) bool {
	current := runs[index]
	currentEnd, ok := addLong(current.ObjectPageIndex, current.PageCount)
	if !ok || current.PageCount == 0 {
		return false
	}
	if index > 0 {
		previous := runs[index-1]
		if !placementRunKeyLess(previous, current) {
			return false
		}
		previousEnd, previousOK := addLong(previous.ObjectPageIndex, previous.PageCount)
		if !previousOK ||
			(previous.ContentObjectID == current.ContentObjectID &&
				previousEnd > current.ObjectPageIndex) {
			return false
		}
	}
	if index+1 < len(runs) {
		next := runs[index+1]
		if !placementRunKeyLess(current, next) ||
			(current.ContentObjectID == next.ContentObjectID &&
				currentEnd > next.ObjectPageIndex) {
			return false
		}
	}
	return true
}

func placementRunKeyLess(left, right ContentPlacementRun) bool {
	return left.ContentObjectID < right.ContentObjectID ||
		(left.ContentObjectID == right.ContentObjectID &&
			left.ObjectPageIndex < right.ObjectPageIndex)
}

func validateContentMappingObjects(
	contentObjects []ContentObject,
) (map[uint64]ContentObject, []ContentObject, error) {
	if len(contentObjects) == 0 || len(contentObjects) > maxCollectionElements {
		return nil, nil, contentMappingInvalidf(
			"content object count %d is outside 1..%d",
			len(contentObjects), maxCollectionElements)
	}
	objects := make(map[uint64]ContentObject, len(contentObjects))
	eligible := make([]ContentObject, 0, len(contentObjects))
	for index, object := range contentObjects {
		if err := positiveLong("content object ID", object.ObjectID); err != nil {
			return nil, nil, contentMappingFieldInvalid(
				fmt.Sprintf("content object %d", index), err)
		}
		if !object.Kind.valid() {
			return nil, nil, contentMappingInvalidf(
				"content object %d has unknown kind %d", index, object.Kind)
		}
		if err := nonNegativeLong("content byte length", object.ByteLength); err != nil {
			return nil, nil, contentMappingFieldInvalid(
				fmt.Sprintf("content object %d", index), err)
		}
		if err := nonNegativeLong("content logical page start", object.LogicalPageStart); err != nil {
			return nil, nil, contentMappingFieldInvalid(
				fmt.Sprintf("content object %d", index), err)
		}
		if err := positiveLong("content page count", object.PageCount); err != nil {
			return nil, nil, contentMappingFieldInvalid(
				fmt.Sprintf("content object %d", index), err)
		}
		capacity, ok := mulLong(object.PageCount, PageSize)
		if !ok || object.ByteLength > capacity {
			return nil, nil, contentMappingInvalidf(
				"content object %d byte length exceeds reserved pages", index)
		}
		if object.Kind == ContentMemory && object.ByteLength != capacity {
			return nil, nil, contentMappingInvalidf(
				"memory content object %d must fill every reserved page", index)
		}
		if _, ok := addLong(object.LogicalPageStart, object.PageCount); !ok {
			return nil, nil, contentMappingInvalidf(
				"content object %d logical range overflows signed-Long ABI", index)
		}
		if _, exists := objects[object.ObjectID]; exists {
			return nil, nil, contentMappingInvalidf(
				"duplicate content object ID %d", object.ObjectID)
		}
		objects[object.ObjectID] = object
		if placementCoveredKind(object.Kind) {
			eligible = append(eligible, object)
		}
	}
	sort.Slice(eligible, func(i, j int) bool {
		return eligible[i].ObjectID < eligible[j].ObjectID
	})
	return objects, eligible, nil
}

func placementCoveredKind(kind ContentKind) bool {
	switch kind {
	case ContentMemory, ContentArtifact, ContentRestoreBlob:
		return true
	default:
		return false
	}
}

func contentMappingFieldInvalid(context string, err error) error {
	return fmt.Errorf("%s: %v: %w", context, err, ErrInvalidContentMapping)
}

func contentMappingInvalidf(format string, arguments ...interface{}) error {
	return fmt.Errorf(format+": %w", append(arguments, ErrInvalidContentMapping)...)
}

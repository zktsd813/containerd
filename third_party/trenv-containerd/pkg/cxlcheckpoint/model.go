// Package cxlcheckpoint defines the strict, portable CXL checkpoint
// publication contract used after the legacy TrEnv publication formats.
//
// This package contains only a codec and semantic validation. It does not
// allocate DAX space, discover the current root, authorize a restore, resolve
// a host-local DAX path, or mutate a live cxld checkpoint.
package cxlcheckpoint

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"math"
	pathpkg "path"
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"
)

const (
	// Version is the only publication version accepted by this package.
	Version uint32 = 6
	// MagicString is the exact eight-byte publication magic.
	MagicString = "TRPUB006"
	// PageSize is the only content and virtual-memory page size in this ABI.
	PageSize uint64 = 4096
	// MaxIdentityBytes bounds every portable textual identity by UTF-8 bytes.
	MaxIdentityBytes = 4096
	// MaxSignedLong is the largest public numeric value shared with Scala/Java.
	MaxSignedLong uint64 = math.MaxInt64
	// MaxPayloadBytes is the strict upper bound on a TRPUB006 payload. Producers
	// must budget worst-case one-page PageMap runs within this envelope.
	MaxPayloadBytes = 64 << 20
	// MaxPublicationSlotPages is the largest page-aligned ContentPublication
	// reservation capable of holding the maximum envelope header and payload.
	MaxPublicationSlotPages = (uint64(envelopeHeaderSize) + MaxPayloadBytes + PageSize - 1) / PageSize

	maxCollectionElements = 1 << 20
)

var (
	publicationMagic = [8]byte{'T', 'R', 'P', 'U', 'B', '0', '0', '6'}

	// ErrWrongFormat identifies legacy or otherwise incompatible envelopes.
	ErrWrongFormat = errors.New("not a TRPUB006 publication")
	// ErrCorrupt identifies an envelope whose declared bytes fail integrity or
	// exact-length checks.
	ErrCorrupt = errors.New("corrupt TRPUB006 publication")
	// ErrInvalid identifies a well-formed V6 envelope with invalid semantics.
	ErrInvalid = errors.New("invalid TRPUB006 publication")
)

// ContentKind assigns one allocator and PageID model to all immutable content.
type ContentKind uint8

const (
	ContentMemory ContentKind = iota + 1
	ContentArtifact
	ContentMMTemplate
	ContentPageMap
	ContentRestoreBlob
	// ContentPublication is the page-aligned slot that stores this complete
	// encoded TRPUB006 envelope followed by zero padding. Its ByteLength is
	// the reserved slot capacity; the Scheduler root locator carries the
	// exact encoded byte length and SHA-256.
	ContentPublication
)

func (k ContentKind) valid() bool {
	return k >= ContentMemory && k <= ContentPublication
}

// BackingKind is the portable source category of a VMA. Kernel objects and
// host-local file descriptors are deliberately not publication data.
type BackingKind uint8

const (
	BackingAnonymous BackingKind = iota + 1
	BackingArtifact
	BackingRestoreBlob
	BackingZero
)

func (k BackingKind) valid() bool {
	return k >= BackingAnonymous && k <= BackingZero
}

// ArtifactType is the portable filesystem entry category.
type ArtifactType uint8

const (
	ArtifactRegular ArtifactType = iota + 1
	ArtifactDirectory
	ArtifactSymlink
)

func (t ArtifactType) valid() bool {
	return t >= ArtifactRegular && t <= ArtifactSymlink
}

// MappingSlotName identifies one of the two mapping slots reserved during
// checkpoint allocation. A dedup epoch may write only the inactive slot.
type MappingSlotName uint8

const (
	MappingSlotA MappingSlotName = iota + 1
	MappingSlotB
)

func (n MappingSlotName) valid() bool {
	return n == MappingSlotA || n == MappingSlotB
}

// RootState intentionally has one accepted value. Partially committed roots
// must never be encoded as discoverable publications.
type RootState uint8

const (
	RootCommitted RootState = 1
)

const (
	ProtectionRead uint64 = 1 << iota
	ProtectionWrite
	ProtectionExecute
	knownProtectionFlags = ProtectionRead | ProtectionWrite | ProtectionExecute
)

const (
	MappingPrivate uint64 = 1 << iota
	MappingShared
	MappingAnonymous
	MappingFixed
	MappingGrowsDown
	knownMappingFlags = MappingPrivate | MappingShared | MappingAnonymous | MappingFixed | MappingGrowsDown
)

// PageID is a stable physical content identity. AllocationRecordID is scoped
// by OwnerID; DeviceUUID and DataPageIndex locate the descriptor/content slot.
type PageID struct {
	OwnerID            string
	DeviceUUID         string
	AllocationRecordID uint64
	DataPageIndex      uint64
}

// PublicationPageRun identifies consecutive pages that contain the complete
// encoded TRPUB006 envelope. It deliberately contains no host-local path.
// PageCount covers only ceil(exact encoded bytes / PageSize), not the complete
// capacity of the pre-reserved publication slot.
type PublicationPageRun struct {
	FirstPage PageID
	PageCount uint64
}

// PublicationStorage is the result of preparing one validated TRPUB006
// publication for its pre-reserved CXL slot. ExactBytes and SHA256 are the
// Scheduler-visible root identity. PaddedBytes is the complete slot write:
// ExactBytes followed only by zero bytes.
type PublicationStorage struct {
	ContentObjectID  uint64
	LogicalPageStart uint64
	CapacityPages    uint64
	ExactBytes       []byte
	PaddedBytes      []byte
	SHA256           [sha256.Size]byte
	PageRuns         []PublicationPageRun
}

// Device describes a stable DAX identity. There is intentionally no local
// /dev path or shard index in the portable contract.
type Device struct {
	DeviceUUID    string
	OwnerID       string
	OwnerEpoch    uint64
	DataPageCount uint64
}

// ContentObject describes pages reserved from the unified content allocator.
// ByteLength is the exact meaningful length and PageCount is reserved capacity
// for every ordinary content kind. ContentPublication is the deliberate
// exception: its exact encoded length is self-referential, so ByteLength names
// the page-aligned slot capacity and the Scheduler root locator carries the
// exact encoded envelope length.
type ContentObject struct {
	ObjectID         uint64
	Kind             ContentKind
	ByteLength       uint64
	LogicalPageStart uint64
	PageCount        uint64
}

// AllocationExtent maps a contiguous logical allocation range onto one DAX
// device. All initial extents of one publication belong to InitialAllocation's
// single Owner, even if a later PageMap references other Owners after dedup.
type AllocationExtent struct {
	DeviceUUID         string
	StartDataPageIndex uint64
	PageCount          uint64
	LogicalPageStart   uint64
}

// InitialAllocation is the checkpoint-level allocation identity.
type InitialAllocation struct {
	OwnerID            string
	OwnerEpoch         uint64
	AllocationRecordID uint64
	TotalPages         uint64
	Extents            []AllocationExtent
}

// VMA is a portable virtual-memory range in one CRIU pages image.
// PagesImageID is checkpoint-portable CRIU image metadata; it is not a
// numeric pseudo-MM identifier or a kernel object. PageMapRunStart/Count name
// the sparse present-page runs that fall inside this VMA. Gaps are valid:
// pages absent from the CRIU pagemap must not be invented during restore.
type VMA struct {
	PagesImageID    uint32
	StartVAddr      uint64
	EndVAddr        uint64
	ProtectionFlags uint64
	MappingFlags    uint64
	BackingKind     BackingKind
	PageMapRunStart uint64
	PageMapRunCount uint64
}

// MMTemplate contains portable VMA shape only. Numeric pseudo-MM identifiers,
// mm_structs, page tables, and host-local DAX bindings remain executor-local.
type MMTemplate struct {
	TemplateID             string
	ContentObjectID        uint64
	RuntimeCompatibilityID string
	PageSize               uint64
	VMAs                   []VMA
}

// PageMapRun maps consecutive present virtual pages from one CRIU pages image
// to consecutive data pages under one PageID base. A sparse, non-contiguous,
// cross-device, or cross-Owner map is represented by multiple runs, including
// one-page runs when necessary.
type PageMapRun struct {
	PagesImageID uint32
	StartVAddr   uint64
	PageCount    uint64
	FirstPage    PageID
}

// PageMap is an immutable mapping version stored in one reserved mapping slot.
type PageMap struct {
	PageMapID       string
	Version         uint64
	ContentObjectID uint64
	PageSize        uint64
	Runs            []PageMapRun
}

// ArtifactEntry preserves portable filesystem metadata and exact file bytes.
// ContentObjectID/ContentOffset are used only for non-empty regular files.
type ArtifactEntry struct {
	Path            string
	Type            ArtifactType
	Mode            uint64
	UID             uint64
	GID             uint64
	ByteLength      uint64
	ContentObjectID uint64
	ContentOffset   uint64
	LinkTarget      string
}

// ArtifactManifest describes the action/runtime artifact namespace.
type ArtifactManifest struct {
	ManifestID string
	Entries    []ArtifactEntry
}

// MappingSlot binds a fixed A/B name to pre-reserved PageMap capacity.
type MappingSlot struct {
	Name            MappingSlotName
	ContentObjectID uint64
	CapacityPages   uint64
}

// MappingSlots always contains exactly one A slot and one B slot.
type MappingSlots struct {
	A MappingSlot
	B MappingSlot
}

// CommittedRoot is the only discoverable publication root.
type CommittedRoot struct {
	State               RootState
	RootID              string
	CheckpointID        string
	OwnerID             string
	AllocationRecordID  uint64
	MMTemplateID        string
	PageMapID           string
	PageMapVersion      uint64
	ArtifactManifestID  string
	ActiveMappingSlot   MappingSlotName
	DeviceTableDigest   [sha256.Size]byte
	PublicationSequence uint64
}

// Publication is the complete V6 portable checkpoint graph.
type Publication struct {
	CheckpointID   string
	Devices        []Device
	ContentObjects []ContentObject
	Allocation     InitialAllocation
	MMTemplate     MMTemplate
	PageMap        PageMap
	Artifacts      ArtifactManifest
	MappingSlots   MappingSlots
	Root           CommittedRoot
}

// Validate applies all cross-object V6 invariants without changing p.
func (p Publication) Validate() error {
	if err := validateIdentity("checkpoint ID", p.CheckpointID); err != nil {
		return err
	}
	if len(p.Devices) == 0 || len(p.Devices) > maxCollectionElements {
		return invalidf("device count %d is outside 1..%d", len(p.Devices), maxCollectionElements)
	}
	if len(p.ContentObjects) == 0 || len(p.ContentObjects) > maxCollectionElements {
		return invalidf("content object count %d is outside 1..%d", len(p.ContentObjects), maxCollectionElements)
	}
	devices, err := validateDevices(p.Devices)
	if err != nil {
		return err
	}
	contents, err := validateContentObjects(p.ContentObjects, p.Allocation.TotalPages)
	if err != nil {
		return err
	}
	if err := validateAllocation(p.Allocation, devices, p.ContentObjects); err != nil {
		return err
	}
	if err := validateMMTemplate(p.MMTemplate, p.PageMap, contents); err != nil {
		return err
	}
	if err := validatePageMap(p.PageMap, p.Allocation, devices, contents); err != nil {
		return err
	}
	if err := validateArtifacts(p.Artifacts, contents); err != nil {
		return err
	}
	if err := validateMappingSlots(p.MappingSlots, p.PageMap, contents); err != nil {
		return err
	}
	if err := validateRoot(p, devices); err != nil {
		return err
	}
	return nil
}

func validateDevices(devices []Device) (map[string]Device, error) {
	byUUID := make(map[string]Device, len(devices))
	previous := ""
	for i, device := range devices {
		if err := validateDeviceUUID(device.DeviceUUID); err != nil {
			return nil, fmt.Errorf("device %d: %w", i, err)
		}
		if err := validateIdentity("device owner ID", device.OwnerID); err != nil {
			return nil, fmt.Errorf("device %d: %w", i, err)
		}
		if err := positiveLong("device owner epoch", device.OwnerEpoch); err != nil {
			return nil, fmt.Errorf("device %d: %w", i, err)
		}
		if err := positiveLong("device page count", device.DataPageCount); err != nil {
			return nil, fmt.Errorf("device %d: %w", i, err)
		}
		if _, exists := byUUID[device.DeviceUUID]; exists {
			return nil, invalidf("duplicate device UUID %q", device.DeviceUUID)
		}
		if i > 0 && previous >= device.DeviceUUID {
			return nil, invalidf("device table is not strictly ordered by UUID")
		}
		previous = device.DeviceUUID
		byUUID[device.DeviceUUID] = device
	}
	return byUUID, nil
}

func validateContentObjects(objects []ContentObject, totalPages uint64) (map[uint64]ContentObject, error) {
	byID := make(map[uint64]ContentObject, len(objects))
	expectedLogical := uint64(0)
	publicationObjects := 0
	for i, object := range objects {
		if err := positiveLong("content object ID", object.ObjectID); err != nil {
			return nil, fmt.Errorf("content object %d: %w", i, err)
		}
		if !object.Kind.valid() {
			return nil, invalidf("content object %d has unknown kind %d", i, object.Kind)
		}
		if err := nonNegativeLong("content byte length", object.ByteLength); err != nil {
			return nil, fmt.Errorf("content object %d: %w", i, err)
		}
		if err := positiveLong("content page count", object.PageCount); err != nil {
			return nil, fmt.Errorf("content object %d: %w", i, err)
		}
		if err := nonNegativeLong("content logical page start", object.LogicalPageStart); err != nil {
			return nil, fmt.Errorf("content object %d: %w", i, err)
		}
		capacity, ok := mulLong(object.PageCount, PageSize)
		if !ok || object.ByteLength > capacity {
			return nil, invalidf("content object %d byte length exceeds reserved pages", i)
		}
		if object.Kind == ContentMemory && object.ByteLength != capacity {
			return nil, invalidf("memory content object %d must fill every reserved page", i)
		}
		if object.Kind == ContentPublication {
			publicationObjects++
			if object.ByteLength != capacity || object.ByteLength == 0 ||
				object.PageCount > MaxPublicationSlotPages {
				return nil, invalidf(
					"publication content object %d must be a non-empty page-aligned slot of at most %d pages",
					i, MaxPublicationSlotPages)
			}
		}
		if object.LogicalPageStart != expectedLogical {
			return nil, invalidf("content objects have a gap or overlap at logical page %d", expectedLogical)
		}
		expectedLogical, ok = addLong(expectedLogical, object.PageCount)
		if !ok {
			return nil, invalidf("content logical coverage overflows signed-Long ABI")
		}
		if _, exists := byID[object.ObjectID]; exists {
			return nil, invalidf("duplicate content object ID %d", object.ObjectID)
		}
		byID[object.ObjectID] = object
	}
	if expectedLogical != totalPages {
		return nil, invalidf("content objects cover %d pages, allocation declares %d", expectedLogical, totalPages)
	}
	if publicationObjects != 1 {
		return nil, invalidf(
			"publication must contain exactly one publication content slot, found %d",
			publicationObjects)
	}
	return byID, nil
}

func (p Publication) publicationContentSlot() (ContentObject, error) {
	var slot ContentObject
	found := false
	for _, object := range p.ContentObjects {
		if object.Kind != ContentPublication {
			continue
		}
		if found {
			return ContentObject{}, invalidf("publication contains more than one publication content slot")
		}
		slot = object
		found = true
	}
	if !found {
		return ContentObject{}, invalidf("publication contains no publication content slot")
	}
	return slot, nil
}

func (p Publication) publicationPageRuns(slot ContentObject, pageCount uint64) ([]PublicationPageRun, error) {
	if pageCount == 0 || pageCount > slot.PageCount {
		return nil, invalidf(
			"encoded publication requires %d pages outside slot capacity %d",
			pageCount, slot.PageCount)
	}
	rangeEnd, ok := addLong(slot.LogicalPageStart, pageCount)
	if !ok {
		return nil, invalidf("publication page range overflows signed-Long ABI")
	}
	runs := make([]PublicationPageRun, 0, len(p.Allocation.Extents))
	covered := uint64(0)
	for _, extent := range p.Allocation.Extents {
		extentEnd, extentOK := addLong(extent.LogicalPageStart, extent.PageCount)
		if !extentOK {
			return nil, invalidf("allocation extent logical range overflows signed-Long ABI")
		}
		overlapStart := slot.LogicalPageStart
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
		physicalStart, physicalOK := addLong(
			extent.StartDataPageIndex, overlapStart-extent.LogicalPageStart)
		if !physicalOK {
			return nil, invalidf("publication physical page range overflows signed-Long ABI")
		}
		run := PublicationPageRun{
			FirstPage: PageID{
				OwnerID:            p.Allocation.OwnerID,
				DeviceUUID:         extent.DeviceUUID,
				AllocationRecordID: p.Allocation.AllocationRecordID,
				DataPageIndex:      physicalStart,
			},
			PageCount: runPages,
		}
		if len(runs) > 0 {
			previous := &runs[len(runs)-1]
			previousEnd, previousOK := addLong(
				previous.FirstPage.DataPageIndex, previous.PageCount)
			if previousOK &&
				previous.FirstPage.OwnerID == run.FirstPage.OwnerID &&
				previous.FirstPage.DeviceUUID == run.FirstPage.DeviceUUID &&
				previous.FirstPage.AllocationRecordID == run.FirstPage.AllocationRecordID &&
				previousEnd == run.FirstPage.DataPageIndex {
				coalesced, coalescedOK := addLong(previous.PageCount, run.PageCount)
				if !coalescedOK {
					return nil, invalidf("publication PageID run length overflows signed-Long ABI")
				}
				previous.PageCount = coalesced
				covered += runPages
				continue
			}
		}
		runs = append(runs, run)
		covered += runPages
	}
	if covered != pageCount {
		return nil, invalidf(
			"publication slot allocation covers %d encoded pages, expected %d",
			covered, pageCount)
	}
	return runs, nil
}

func validateAllocation(allocation InitialAllocation, devices map[string]Device, objects []ContentObject) error {
	if err := validateIdentity("allocation owner ID", allocation.OwnerID); err != nil {
		return err
	}
	if err := positiveLong("allocation owner epoch", allocation.OwnerEpoch); err != nil {
		return err
	}
	if err := positiveLong("allocation record ID", allocation.AllocationRecordID); err != nil {
		return err
	}
	if err := positiveLong("allocation total pages", allocation.TotalPages); err != nil {
		return err
	}
	if len(allocation.Extents) == 0 || len(allocation.Extents) > maxCollectionElements {
		return invalidf("allocation extent count %d is outside 1..%d", len(allocation.Extents), maxCollectionElements)
	}
	expectedLogical := uint64(0)
	physical := make(map[string][]AllocationExtent)
	for i, extent := range allocation.Extents {
		if err := validateDeviceUUID(extent.DeviceUUID); err != nil {
			return fmt.Errorf("allocation extent %d: %w", i, err)
		}
		if err := nonNegativeLong("extent data page start", extent.StartDataPageIndex); err != nil {
			return fmt.Errorf("allocation extent %d: %w", i, err)
		}
		if err := positiveLong("extent page count", extent.PageCount); err != nil {
			return fmt.Errorf("allocation extent %d: %w", i, err)
		}
		if extent.LogicalPageStart != expectedLogical {
			return invalidf("allocation extents have a gap or overlap at logical page %d", expectedLogical)
		}
		var ok bool
		expectedLogical, ok = addLong(expectedLogical, extent.PageCount)
		if !ok {
			return invalidf("allocation logical coverage overflows signed-Long ABI")
		}
		device, exists := devices[extent.DeviceUUID]
		if !exists {
			return invalidf("allocation extent %d references unknown device %q", i, extent.DeviceUUID)
		}
		if device.OwnerID != allocation.OwnerID || device.OwnerEpoch != allocation.OwnerEpoch {
			return invalidf("allocation extent %d device is not controlled by the initial Owner/epoch", i)
		}
		end, ok := addLong(extent.StartDataPageIndex, extent.PageCount)
		if !ok || end > device.DataPageCount {
			return invalidf("allocation extent %d exceeds device %q", i, extent.DeviceUUID)
		}
		physical[extent.DeviceUUID] = append(physical[extent.DeviceUUID], extent)
	}
	if expectedLogical != allocation.TotalPages {
		return invalidf("allocation extents cover %d pages, expected %d", expectedLogical, allocation.TotalPages)
	}
	for deviceUUID, extents := range physical {
		sort.Slice(extents, func(i, j int) bool {
			return extents[i].StartDataPageIndex < extents[j].StartDataPageIndex
		})
		for i := 1; i < len(extents); i++ {
			previousEnd, _ := addLong(extents[i-1].StartDataPageIndex, extents[i-1].PageCount)
			if previousEnd > extents[i].StartDataPageIndex {
				return invalidf("allocation extents overlap physically on device %q", deviceUUID)
			}
		}
	}
	if len(objects) == 0 {
		return invalidf("initial allocation has no content objects")
	}
	return nil
}

func validateMMTemplate(template MMTemplate, pageMap PageMap, contents map[uint64]ContentObject) error {
	if err := validateIdentity("MM template ID", template.TemplateID); err != nil {
		return err
	}
	if err := validateIdentity("runtime compatibility ID", template.RuntimeCompatibilityID); err != nil {
		return err
	}
	if template.PageSize != PageSize {
		return invalidf("MM template page size is %d, expected %d", template.PageSize, PageSize)
	}
	content, exists := contents[template.ContentObjectID]
	if !exists || content.Kind != ContentMMTemplate {
		return invalidf("MM template content object %d is missing or has the wrong kind", template.ContentObjectID)
	}
	encodedSize, err := canonicalMMTemplateSize(template)
	if err != nil {
		return err
	}
	if content.ByteLength != encodedSize {
		return invalidf("MM template content object byte length is %d, canonical encoding is %d",
			content.ByteLength, encodedSize)
	}
	if len(template.VMAs) == 0 || len(template.VMAs) > maxCollectionElements {
		return invalidf("VMA count %d is outside 1..%d", len(template.VMAs), maxCollectionElements)
	}
	expectedRun := uint64(0)
	previousPagesImageID := uint32(0)
	previousEnd := uint64(0)
	for i, vma := range template.VMAs {
		if vma.PagesImageID == 0 {
			return invalidf("VMA %d has a zero CRIU pages image ID", i)
		}
		if err := alignedRange("VMA", vma.StartVAddr, vma.EndVAddr); err != nil {
			return fmt.Errorf("VMA %d: %w", i, err)
		}
		if i > 0 {
			if vma.PagesImageID < previousPagesImageID ||
				(vma.PagesImageID == previousPagesImageID && vma.StartVAddr < previousEnd) {
				return invalidf("VMAs overlap or are not ordered by pages image/address at index %d", i)
			}
		}
		previousPagesImageID = vma.PagesImageID
		previousEnd = vma.EndVAddr
		if vma.ProtectionFlags&^knownProtectionFlags != 0 {
			return invalidf("VMA %d has unknown protection flags %#x", i, vma.ProtectionFlags)
		}
		if vma.MappingFlags&^knownMappingFlags != 0 {
			return invalidf("VMA %d has unknown mapping flags %#x", i, vma.MappingFlags)
		}
		privacy := vma.MappingFlags & (MappingPrivate | MappingShared)
		if privacy != MappingPrivate && privacy != MappingShared {
			return invalidf("VMA %d must select exactly one of PRIVATE or SHARED", i)
		}
		if !vma.BackingKind.valid() {
			return invalidf("VMA %d has unknown backing kind %d", i, vma.BackingKind)
		}
		anonymous := vma.MappingFlags&MappingAnonymous != 0
		switch vma.BackingKind {
		case BackingAnonymous, BackingZero:
			if !anonymous {
				return invalidf("VMA %d anonymous/zero backing lacks the ANONYMOUS mapping flag", i)
			}
		case BackingArtifact, BackingRestoreBlob:
			if anonymous {
				return invalidf("VMA %d file/blob backing has the ANONYMOUS mapping flag", i)
			}
		}
		if vma.PageMapRunStart != expectedRun {
			return invalidf("VMA %d PageMap slice overlaps or has a run-table gap", i)
		}
		runEnd, ok := addLong(vma.PageMapRunStart, vma.PageMapRunCount)
		if !ok || runEnd > uint64(len(pageMap.Runs)) {
			return invalidf("VMA %d PageMap slice exceeds the run table", i)
		}
		previousRunEnd := vma.StartVAddr
		for runIndex := vma.PageMapRunStart; runIndex < runEnd; runIndex++ {
			run := pageMap.Runs[runIndex]
			if run.PagesImageID != vma.PagesImageID {
				return invalidf("VMA %d PageMap run names pages image %d, expected %d",
					i, run.PagesImageID, vma.PagesImageID)
			}
			if run.StartVAddr < previousRunEnd || run.StartVAddr < vma.StartVAddr {
				return invalidf("VMA %d PageMap present-page runs overlap or are not ordered", i)
			}
			bytes, ok := mulLong(run.PageCount, PageSize)
			if !ok {
				return invalidf("VMA %d PageMap coverage overflows", i)
			}
			previousRunEnd, ok = addLong(run.StartVAddr, bytes)
			if !ok {
				return invalidf("VMA %d virtual coverage overflows", i)
			}
			if previousRunEnd > vma.EndVAddr {
				return invalidf("VMA %d PageMap run extends beyond the VMA", i)
			}
		}
		expectedRun = runEnd
	}
	if expectedRun != uint64(len(pageMap.Runs)) {
		return invalidf("MM template consumes %d of %d PageMap runs", expectedRun, len(pageMap.Runs))
	}
	return nil
}

func validatePageMap(
	pageMap PageMap,
	initialAllocation InitialAllocation,
	devices map[string]Device,
	contents map[uint64]ContentObject,
) error {
	if err := validateIdentity("PageMap ID", pageMap.PageMapID); err != nil {
		return err
	}
	if err := positiveLong("PageMap version", pageMap.Version); err != nil {
		return err
	}
	if pageMap.PageSize != PageSize {
		return invalidf("PageMap page size is %d, expected %d", pageMap.PageSize, PageSize)
	}
	content, exists := contents[pageMap.ContentObjectID]
	if !exists || content.Kind != ContentPageMap {
		return invalidf("PageMap content object %d is missing or has the wrong kind", pageMap.ContentObjectID)
	}
	encodedSize, err := canonicalPageMapSize(pageMap)
	if err != nil {
		return err
	}
	if content.ByteLength != encodedSize {
		return invalidf("PageMap content object byte length is %d, canonical encoding is %d",
			content.ByteLength, encodedSize)
	}
	if len(pageMap.Runs) == 0 || len(pageMap.Runs) > maxCollectionElements {
		return invalidf("PageMap run count %d is outside 1..%d", len(pageMap.Runs), maxCollectionElements)
	}
	previousPagesImageID := uint32(0)
	previousEnd := uint64(0)
	for i, run := range pageMap.Runs {
		if run.PagesImageID == 0 {
			return invalidf("PageMap run %d has a zero CRIU pages image ID", i)
		}
		if err := alignedAddress("PageMap virtual address", run.StartVAddr); err != nil {
			return fmt.Errorf("PageMap run %d: %w", i, err)
		}
		if err := positiveLong("PageMap page count", run.PageCount); err != nil {
			return fmt.Errorf("PageMap run %d: %w", i, err)
		}
		bytes, ok := mulLong(run.PageCount, PageSize)
		if !ok {
			return invalidf("PageMap run %d byte range overflows", i)
		}
		end, ok := addLong(run.StartVAddr, bytes)
		if !ok {
			return invalidf("PageMap run %d virtual range overflows", i)
		}
		if i > 0 {
			if run.PagesImageID < previousPagesImageID ||
				(run.PagesImageID == previousPagesImageID && run.StartVAddr < previousEnd) {
				return invalidf("PageMap runs overlap or are not ordered by pages image/address at index %d", i)
			}
		}
		previousPagesImageID = run.PagesImageID
		previousEnd = end
		if err := validatePageID(run.FirstPage, initialAllocation, devices, run.PageCount); err != nil {
			return fmt.Errorf("PageMap run %d: %w", i, err)
		}
	}
	return nil
}

func validatePageID(
	page PageID,
	initialAllocation InitialAllocation,
	devices map[string]Device,
	runPages uint64,
) error {
	if err := validateIdentity("PageID owner ID", page.OwnerID); err != nil {
		return err
	}
	if err := validateDeviceUUID(page.DeviceUUID); err != nil {
		return err
	}
	if err := positiveLong("PageID allocation record ID", page.AllocationRecordID); err != nil {
		return err
	}
	if err := nonNegativeLong("PageID data page index", page.DataPageIndex); err != nil {
		return err
	}
	device, exists := devices[page.DeviceUUID]
	if !exists {
		return invalidf("PageID references unknown device %q", page.DeviceUUID)
	}
	if device.OwnerID != page.OwnerID {
		return invalidf("PageID Owner %q does not own device %q", page.OwnerID, page.DeviceUUID)
	}
	end, ok := addLong(page.DataPageIndex, runPages)
	if !ok || end > device.DataPageCount {
		return invalidf("PageID run exceeds device %q", page.DeviceUUID)
	}
	// The complete physical range is known for the checkpoint's initial
	// allocation, so require a run to fit within one extent. This prevents a
	// compact run from silently crossing into a different allocation record,
	// even when two extents happen to be physically adjacent. For canonical
	// pages from another allocation, descriptor/record validation belongs to
	// the resolving Owner because this portable publication intentionally does
	// not copy every Owner's allocation table.
	if page.OwnerID == initialAllocation.OwnerID &&
		page.AllocationRecordID == initialAllocation.AllocationRecordID {
		for _, extent := range initialAllocation.Extents {
			if extent.DeviceUUID != page.DeviceUUID || page.DataPageIndex < extent.StartDataPageIndex {
				continue
			}
			extentEnd, extentOK := addLong(extent.StartDataPageIndex, extent.PageCount)
			if extentOK && end <= extentEnd {
				return nil
			}
		}
		return invalidf("PageID run crosses the initial allocation extent boundary")
	}
	return nil
}

func validateArtifacts(manifest ArtifactManifest, contents map[uint64]ContentObject) error {
	if err := validateIdentity("artifact manifest ID", manifest.ManifestID); err != nil {
		return err
	}
	if len(manifest.Entries) > maxCollectionElements {
		return invalidf("artifact entry count %d exceeds %d", len(manifest.Entries), maxCollectionElements)
	}
	previous := ""
	for i, entry := range manifest.Entries {
		if err := validateArtifactPath(entry.Path); err != nil {
			return fmt.Errorf("artifact entry %d: %w", i, err)
		}
		if i > 0 && previous >= entry.Path {
			return invalidf("artifact entries are duplicate or not strictly ordered by path")
		}
		previous = entry.Path
		if !entry.Type.valid() {
			return invalidf("artifact entry %q has unknown type %d", entry.Path, entry.Type)
		}
		for _, field := range []struct {
			name  string
			value uint64
		}{
			{name: "mode", value: entry.Mode},
			{name: "UID", value: entry.UID},
			{name: "GID", value: entry.GID},
			{name: "byte length", value: entry.ByteLength},
			{name: "content object ID", value: entry.ContentObjectID},
			{name: "content offset", value: entry.ContentOffset},
		} {
			if err := nonNegativeLong("artifact "+field.name, field.value); err != nil {
				return fmt.Errorf("artifact entry %q: %w", entry.Path, err)
			}
		}
		switch entry.Type {
		case ArtifactRegular:
			if entry.LinkTarget != "" {
				return invalidf("regular artifact %q has a link target", entry.Path)
			}
			if entry.ByteLength == 0 {
				if entry.ContentObjectID != 0 || entry.ContentOffset != 0 {
					return invalidf("empty artifact %q has a content reference", entry.Path)
				}
				continue
			}
			content, exists := contents[entry.ContentObjectID]
			if !exists || content.Kind != ContentArtifact {
				return invalidf("artifact %q content object is missing or has the wrong kind", entry.Path)
			}
			end, ok := addLong(entry.ContentOffset, entry.ByteLength)
			if !ok || end > content.ByteLength {
				return invalidf("artifact %q byte range exceeds its content object", entry.Path)
			}
		case ArtifactDirectory:
			if entry.ByteLength != 0 || entry.ContentObjectID != 0 || entry.ContentOffset != 0 || entry.LinkTarget != "" {
				return invalidf("directory artifact %q carries file content", entry.Path)
			}
		case ArtifactSymlink:
			if err := validateText("artifact link target", entry.LinkTarget, false); err != nil {
				return fmt.Errorf("artifact entry %q: %w", entry.Path, err)
			}
			if entry.ByteLength != 0 || entry.ContentObjectID != 0 || entry.ContentOffset != 0 {
				return invalidf("symlink artifact %q carries file content", entry.Path)
			}
		}
	}
	return nil
}

func validateMappingSlots(slots MappingSlots, pageMap PageMap, contents map[uint64]ContentObject) error {
	if slots.A.Name != MappingSlotA || slots.B.Name != MappingSlotB {
		return invalidf("mapping slots must contain fixed A then B identities")
	}
	if slots.A.ContentObjectID == slots.B.ContentObjectID {
		return invalidf("mapping slots A and B share content object %d", slots.A.ContentObjectID)
	}
	for _, slot := range []MappingSlot{slots.A, slots.B} {
		if err := positiveLong("mapping slot content object ID", slot.ContentObjectID); err != nil {
			return err
		}
		if err := positiveLong("mapping slot capacity pages", slot.CapacityPages); err != nil {
			return err
		}
		content, exists := contents[slot.ContentObjectID]
		if !exists || content.Kind != ContentPageMap {
			return invalidf("mapping slot %d content object is missing or has the wrong kind", slot.Name)
		}
		if content.PageCount != slot.CapacityPages {
			return invalidf("mapping slot %d capacity does not match its content object", slot.Name)
		}
	}
	if pageMap.ContentObjectID != slots.A.ContentObjectID && pageMap.ContentObjectID != slots.B.ContentObjectID {
		return invalidf("PageMap content object is not one of the reserved A/B slots")
	}
	active := slots.A
	if pageMap.ContentObjectID == slots.B.ContentObjectID {
		active = slots.B
	}
	encodedSize, err := canonicalPageMapSize(pageMap)
	if err != nil {
		return err
	}
	capacityBytes, ok := mulLong(active.CapacityPages, PageSize)
	if !ok || encodedSize > capacityBytes {
		return invalidf("PageMap canonical encoding is %d bytes, active slot capacity is %d",
			encodedSize, capacityBytes)
	}
	return nil
}

func canonicalMMTemplateSize(template MMTemplate) (uint64, error) {
	encoder := newPayloadEncoder()
	encodeMMTemplate(encoder, template)
	if encoder.err != nil {
		return 0, encoder.err
	}
	return uint64(encoder.buffer.Len()), nil
}

// CanonicalMMTemplateSize returns the exact number of bytes that a producer
// must reserve for the portable MMTemplate object in this V6 codec.
func CanonicalMMTemplateSize(template MMTemplate) (uint64, error) {
	return canonicalMMTemplateSize(template)
}

func canonicalPageMapSize(pageMap PageMap) (uint64, error) {
	encoder := newPayloadEncoder()
	encodePageMap(encoder, pageMap)
	if encoder.err != nil {
		return 0, encoder.err
	}
	return uint64(encoder.buffer.Len()), nil
}

// CanonicalPageMapSize returns the exact bytes used by this PageMap version.
// The result lets a producer prove that the inactive A/B mapping slot has
// enough reserved pages before it publishes a new root.
func CanonicalPageMapSize(pageMap PageMap) (uint64, error) {
	return canonicalPageMapSize(pageMap)
}

func validateRoot(p Publication, devices map[string]Device) error {
	root := p.Root
	if root.State != RootCommitted {
		return invalidf("root state is %d, expected COMMITTED", root.State)
	}
	for _, field := range []struct {
		name  string
		value string
	}{
		{name: "root ID", value: root.RootID},
		{name: "root checkpoint ID", value: root.CheckpointID},
		{name: "root owner ID", value: root.OwnerID},
		{name: "root MM template ID", value: root.MMTemplateID},
		{name: "root PageMap ID", value: root.PageMapID},
		{name: "root artifact manifest ID", value: root.ArtifactManifestID},
	} {
		if err := validateIdentity(field.name, field.value); err != nil {
			return err
		}
	}
	if err := positiveLong("root allocation record ID", root.AllocationRecordID); err != nil {
		return err
	}
	if err := positiveLong("root PageMap version", root.PageMapVersion); err != nil {
		return err
	}
	if err := positiveLong("root publication sequence", root.PublicationSequence); err != nil {
		return err
	}
	if !root.ActiveMappingSlot.valid() {
		return invalidf("root has unknown active mapping slot %d", root.ActiveMappingSlot)
	}
	if root.CheckpointID != p.CheckpointID ||
		root.OwnerID != p.Allocation.OwnerID ||
		root.AllocationRecordID != p.Allocation.AllocationRecordID ||
		root.MMTemplateID != p.MMTemplate.TemplateID ||
		root.PageMapID != p.PageMap.PageMapID ||
		root.PageMapVersion != p.PageMap.Version ||
		root.ArtifactManifestID != p.Artifacts.ManifestID {
		return invalidf("committed root does not match publication object identities")
	}
	active, ok := p.MappingSlots.selected(root.ActiveMappingSlot)
	if !ok || active.ContentObjectID != p.PageMap.ContentObjectID {
		return invalidf("committed root active slot does not contain the current PageMap")
	}
	digest, err := DeviceTableDigest(p.Devices)
	if err != nil {
		return err
	}
	if !bytes.Equal(root.DeviceTableDigest[:], digest[:]) {
		return invalidf("committed root device-table digest does not match")
	}
	for _, device := range devices {
		if device.OwnerID == p.Allocation.OwnerID && device.OwnerEpoch == p.Allocation.OwnerEpoch {
			return nil
		}
	}
	return invalidf("device table has no device for the initial allocation Owner/epoch")
}

func (s MappingSlots) selected(name MappingSlotName) (MappingSlot, bool) {
	switch name {
	case MappingSlotA:
		return s.A, true
	case MappingSlotB:
		return s.B, true
	default:
		return MappingSlot{}, false
	}
}

// DeviceTableDigest returns SHA-256 over the canonical portable device table.
// Host-local DAX paths cannot influence this digest because Device has no path.
func DeviceTableDigest(devices []Device) ([sha256.Size]byte, error) {
	var zero [sha256.Size]byte
	if len(devices) == 0 || len(devices) > maxCollectionElements {
		return zero, invalidf("device count %d is outside 1..%d", len(devices), maxCollectionElements)
	}
	canonical := append([]Device(nil), devices...)
	sort.Slice(canonical, func(i, j int) bool {
		return canonical[i].DeviceUUID < canonical[j].DeviceUUID
	})
	if _, err := validateDevices(canonical); err != nil {
		return zero, err
	}
	encoder := newPayloadEncoder()
	encoder.count(len(canonical))
	for _, device := range canonical {
		encoder.text(device.DeviceUUID)
		encoder.text(device.OwnerID)
		encoder.u64(device.OwnerEpoch)
		encoder.u64(device.DataPageCount)
	}
	if encoder.err != nil {
		return zero, encoder.err
	}
	return sha256.Sum256(encoder.bytes()), nil
}

func validateIdentity(name, value string) error {
	return validateText(name, value, true)
}

func validateDeviceUUID(value string) error {
	if err := validateIdentity("device UUID", value); err != nil {
		return err
	}
	if strings.ContainsAny(value, "/\\") || value == "." || value == ".." {
		return invalidf("device UUID %q looks like a local path", value)
	}
	return nil
}

func validateText(name, value string, trim bool) error {
	if value == "" {
		return invalidf("%s is empty", name)
	}
	if !utf8.ValidString(value) {
		return invalidf("%s is not valid UTF-8", name)
	}
	if len([]byte(value)) > MaxIdentityBytes {
		return invalidf("%s is %d UTF-8 bytes, limit is %d", name, len([]byte(value)), MaxIdentityBytes)
	}
	if trim && strings.TrimSpace(value) != value {
		return invalidf("%s has surrounding whitespace", name)
	}
	for _, r := range value {
		if unicode.IsControl(r) {
			return invalidf("%s contains a control character", name)
		}
	}
	return nil
}

func validateArtifactPath(value string) error {
	if err := validateText("artifact path", value, false); err != nil {
		return err
	}
	if pathpkg.IsAbs(value) || value == "." || pathpkg.Clean(value) != value || strings.HasPrefix(value, "../") {
		return invalidf("artifact path %q is not a clean relative path", value)
	}
	return nil
}

func alignedAddress(name string, value uint64) error {
	if err := nonNegativeLong(name, value); err != nil {
		return err
	}
	if value%PageSize != 0 {
		return invalidf("%s %#x is not 4 KiB aligned", name, value)
	}
	return nil
}

func alignedRange(name string, start, end uint64) error {
	if err := alignedAddress(name+" start", start); err != nil {
		return err
	}
	if err := alignedAddress(name+" end", end); err != nil {
		return err
	}
	if start >= end {
		return invalidf("%s start %#x is not below end %#x", name, start, end)
	}
	return nil
}

func positiveLong(name string, value uint64) error {
	if value == 0 || value > MaxSignedLong {
		return invalidf("%s %d is outside 1..%d", name, value, MaxSignedLong)
	}
	return nil
}

func nonNegativeLong(name string, value uint64) error {
	if value > MaxSignedLong {
		return invalidf("%s %d exceeds %d", name, value, MaxSignedLong)
	}
	return nil
}

func addLong(left, right uint64) (uint64, bool) {
	if left > MaxSignedLong || right > MaxSignedLong || left > MaxSignedLong-right {
		return 0, false
	}
	return left + right, true
}

func mulLong(left, right uint64) (uint64, bool) {
	if left == 0 || right == 0 {
		return 0, true
	}
	if left > MaxSignedLong || right > MaxSignedLong || left > MaxSignedLong/right {
		return 0, false
	}
	return left * right, true
}

func invalidf(format string, arguments ...interface{}) error {
	return fmt.Errorf(format+": %w", append(arguments, ErrInvalid)...)
}

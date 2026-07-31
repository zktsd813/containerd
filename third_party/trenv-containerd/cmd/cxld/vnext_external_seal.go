package main

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"sort"

	"github.com/containerd/containerd/third_party/trenv-containerd/pkg/cxlcheckpoint"
	"golang.org/x/sys/unix"
)

type vnextExternalSealPlan struct {
	device            *vnextPersistentDevice
	fragmentGrant     vnextWriteGrant
	globalLogicalPage uint64
	localLogicalPage  uint64
	dataPageIndex     uint64
	contentCRC32C     uint32
	copyEngine        vnextCRCCopyEngine
}

type vnextPreparedExternalSeal struct {
	device            *vnextPersistentDevice
	globalLogicalPage uint64
	dataPageIndex     uint64
	contentObjectID   uint64
	contentKind       vnextContentKind
	contentPage       []byte
	descriptorOffset  uint64
	descriptorData    []byte
	alreadySealed     bool
}

// vnextExternalContentPageCRC is the complete producer claim accepted for one
// non-memory, non-publication content page. LogicalPage is the only placement
// input. The Owner derives the object, kind, payload length, DAX device, and
// physical page from its durable grant instead of trusting producer metadata.
type vnextExternalContentPageCRC struct {
	LogicalPage   uint64
	ContentCRC32C uint32
	CopyEngine    vnextCRCCopyEngine
}

type vnextExpectedExternalContentPage struct {
	LogicalPage     uint64
	ContentObjectID uint64
	ContentKind     vnextContentKind
	PayloadLength   uint32
}

var vnextExternalPayloadVisibilityHook = func(
	fileData []byte,
	_ func([]byte) error,
	invalidate func([]byte) error,
	engine vnextCRCCopyEngine,
) error {
	switch engine {
	case vnextCRCCopyEngineCPU,
		vnextCRCCopyEngineDMLSoftware,
		vnextCRCCopyEngineDMLHardware:
		// The producer and Owner can be different nodes connected through
		// non-coherent CXL. The producer's completed writeback does not
		// invalidate a cache line already held by the Owner, regardless of
		// whether CPU, DML software, or DML hardware performed the copy.
		// Never write back the Owner's potentially stale line here: discard
		// it, then let the caller copy the page from the shared mapping.
		return invalidate(fileData)
	default:
		return fmt.Errorf("unsupported external copy engine %d", engine)
	}
}

// sealExternalCRIUOutput is the writer-side bridge from strict TRREMAP006 and
// TRCRC006 into 64-byte V6 page descriptors. It validates the complete
// sidecar set and the complete memory-page mapping before sealing the first
// descriptor. A missing or mismatched sidecar therefore leaves the whole
// allocation abortable rather than partially accepting an unverified dump.
// This is a focused TRCRC primitive for tests and lower-level validation; the
// Owner service and RPC boundary use sealExternalCheckpointContent exclusively.
func (group *vnextOwnerGroup) sealExternalCRIUOutput(
	grant vnextOwnerWriteGrant,
	publication cxlcheckpoint.Publication,
	directory *vnextLocalDAXDirectory,
	sidecarBytes map[uint32][]byte,
) error {
	validated, err := directory.validateVNextCRCPageSidecars(publication, sidecarBytes)
	if err != nil {
		return err
	}
	group.mu.Lock()
	defer group.mu.Unlock()
	if err := group.checkUsableLocked(); err != nil {
		return err
	}
	transaction, err := group.validateGrantLocked(grant, vnextOwnerGranted)
	if err != nil {
		return err
	}
	if err := validateVNextPublicationAllocationGrant(publication, grant); err != nil {
		return err
	}
	plans, err := group.externalMemorySealPlansLocked(
		grant, transaction, publication, validated)
	if err != nil {
		return err
	}
	return group.sealExternalPlansLocked(plans, nil)
}

// sealExternalCheckpointContent is the complete producer-to-Owner seal
// boundary. Memory CRCs come from strict TRCRC006. Every other producer-written
// content page is named only by its allocation-global logical page and CRC.
// ContentPublication is deliberately absent because the Owner writes it after
// this method succeeds.
func (group *vnextOwnerGroup) sealExternalCheckpointContent(
	grant vnextOwnerWriteGrant,
	publication cxlcheckpoint.Publication,
	directory *vnextLocalDAXDirectory,
	sidecarBytes map[uint32][]byte,
	externalCRCs []vnextExternalContentPageCRC,
) error {
	validated, err := directory.validateVNextCRCPageSidecars(publication, sidecarBytes)
	if err != nil {
		return err
	}

	group.mu.Lock()
	defer group.mu.Unlock()
	if err := group.checkUsableLocked(); err != nil {
		return err
	}
	transaction, err := group.validateGrantLocked(grant, vnextOwnerGranted)
	if err != nil {
		return err
	}
	if err := validateVNextPublicationAllocationGrant(publication, grant); err != nil {
		return err
	}

	plans, err := group.externalMemorySealPlansLocked(
		grant, transaction, publication, validated)
	if err != nil {
		return err
	}
	validatedExternal, err := validateVNextExternalContentPageCRCs(grant, externalCRCs)
	if err != nil {
		return err
	}
	for _, record := range validatedExternal {
		plan, err := group.externalContentSealPlanLocked(grant, transaction, record)
		if err != nil {
			return err
		}
		plans = append(plans, plan)
	}
	return group.sealExternalPlansLocked(
		plans,
		func(prepared []vnextPreparedExternalSeal) error {
			return validateVNextCanonicalExternalContent(publication, prepared)
		})
}

func (group *vnextOwnerGroup) sealExternalPlansLocked(
	plans []vnextExternalSealPlan,
	validatePrepared func([]vnextPreparedExternalSeal) error,
) error {
	// Take every participating device lock in stable UUID order. The Owner
	// lock is already held, so no lifecycle operation can change the grant,
	// and the device locks prevent an in-process writer from changing a page
	// between validation and descriptor publication.
	lockedDevices := group.lockExternalSealDevicesLocked(plans)
	defer func() {
		for index := len(lockedDevices) - 1; index >= 0; index-- {
			lockedDevices[index].mu.Unlock()
		}
	}()

	// Phase one performs every authority, payload, visibility, padding, and
	// CRC check without changing a descriptor. Consequently any ordinary
	// validation failure leaves the entire allocation in RESERVED state and
	// it can be aborted as one checkpoint.
	prepared := make([]vnextPreparedExternalSeal, 0, len(plans))
	for _, plan := range plans {
		page, err := plan.device.prepareExternallyWrittenPageLocked(
			plan.fragmentGrant,
			plan.globalLogicalPage,
			plan.localLogicalPage,
			plan.dataPageIndex,
			plan.contentCRC32C,
			plan.copyEngine)
		if err != nil {
			return fmt.Errorf(
				"validate externally written data page %d: %w",
				plan.dataPageIndex, err)
		}
		prepared = append(prepared, page)
	}
	if validatePrepared != nil {
		if err := validatePrepared(prepared); err != nil {
			return err
		}
	}

	// Phase two publishes only descriptors. A storage I/O failure can still
	// interrupt this phase; restart recovery intentionally accepts a mix of
	// RESERVED and SEALED descriptors for a still-GRANTED allocation, so the
	// exact same request can retry or the whole checkpoint can be aborted.
	touchedDevices := make(map[*vnextPersistentDevice]struct{})
	for _, page := range prepared {
		if err := page.device.applyPreparedExternalSealLocked(page); err != nil {
			return fmt.Errorf(
				"seal externally written data page %d: %w",
				page.dataPageIndex, err)
		}
		if !page.alreadySealed {
			touchedDevices[page.device] = struct{}{}
		}
	}
	for _, device := range lockedDevices {
		if _, touched := touchedDevices[device]; !touched {
			continue
		}
		if err := device.storage.Sync(); err != nil {
			return device.poisonLocked(fmt.Errorf(
				"sync externally written page descriptors: %w", err))
		}
	}
	return nil
}

func (group *vnextOwnerGroup) externalMemorySealPlansLocked(
	grant vnextOwnerWriteGrant,
	transaction *vnextOwnerTransaction,
	publication cxlcheckpoint.Publication,
	validated []vnextValidatedPageCRC,
) ([]vnextExternalSealPlan, error) {
	expectedMemoryPages := make(map[uint64]struct{})
	for _, content := range publication.ContentObjects {
		if content.Kind != cxlcheckpoint.ContentMemory {
			continue
		}
		end, ok := vnextAdd(content.LogicalPageStart, content.PageCount)
		if !ok {
			return nil, fmt.Errorf("memory content logical range overflows: %w", errVNextCorrupt)
		}
		for logicalPage := content.LogicalPageStart; logicalPage < end; logicalPage++ {
			expectedMemoryPages[logicalPage] = struct{}{}
		}
	}
	if len(expectedMemoryPages) == 0 || len(validated) != len(expectedMemoryPages) {
		return nil, fmt.Errorf(
			"TRCRC006 covers %d pages, publication has %d memory pages: %w",
			len(validated), len(expectedMemoryPages), errVNextCRCSidecar)
	}

	plans := make([]vnextExternalSealPlan, 0, len(validated))
	seenLogicalPages := make(map[uint64]struct{}, len(validated))
	for _, page := range validated {
		if page.PageID.OwnerID != grant.OwnerID ||
			page.PageID.AllocationRecordID != grant.AllocationRecordID {
			return nil, fmt.Errorf(
				"writer PageMap references canonical page outside its initial allocation: %w",
				errVNextAuthority)
		}
		plan, globalLogicalPage, err :=
			group.externalSealPlanLocked(grant, transaction, page)
		if err != nil {
			return nil, err
		}
		if _, expected := expectedMemoryPages[globalLogicalPage]; !expected {
			return nil, fmt.Errorf(
				"TRCRC006 PageID resolves to non-memory logical page %d: %w",
				globalLogicalPage, errVNextAuthority)
		}
		if _, duplicate := seenLogicalPages[globalLogicalPage]; duplicate {
			return nil, fmt.Errorf(
				"TRCRC006 maps memory logical page %d more than once: %w",
				globalLogicalPage, errVNextCRCSidecar)
		}
		seenLogicalPages[globalLogicalPage] = struct{}{}
		plans = append(plans, plan)
	}
	if len(seenLogicalPages) != len(expectedMemoryPages) {
		return nil, fmt.Errorf(
			"TRCRC006 memory coverage is %d pages, expected %d: %w",
			len(seenLogicalPages), len(expectedMemoryPages), errVNextCRCSidecar)
	}
	return plans, nil
}

func vnextExpectedExternalContentPages(
	grant vnextOwnerWriteGrant,
) ([]vnextExpectedExternalContentPage, error) {
	expected := make([]vnextExpectedExternalContentPage, 0)
	for _, content := range grant.Contents {
		switch content.Kind {
		case vnextContentMemory, vnextContentPublication:
			continue
		case vnextContentArtifact,
			vnextContentMMTemplate,
			vnextContentPageMap,
			vnextContentRestoreBlob:
		default:
			return nil, fmt.Errorf(
				"grant content object %d has unsupported kind %d: %w",
				content.ObjectID, content.Kind, errVNextCorrupt)
		}
		end, ok := vnextAdd(content.LogicalPageStart, content.PageCount)
		if !ok {
			return nil, fmt.Errorf(
				"grant content object %d logical range overflows: %w",
				content.ObjectID, errVNextCorrupt)
		}
		for logicalPage := content.LogicalPageStart; logicalPage < end; logicalPage++ {
			pageWithinObject := logicalPage - content.LogicalPageStart
			consumed, ok := vnextMul(pageWithinObject, vnextContentPageSize)
			if !ok {
				return nil, fmt.Errorf(
					"grant content object %d byte offset overflows: %w",
					content.ObjectID, errVNextCorrupt)
			}
			payloadLength := vnextContentPageSize
			if consumed < content.ByteLength {
				remaining := content.ByteLength - consumed
				if remaining < payloadLength {
					payloadLength = remaining
				}
			}
			expected = append(expected, vnextExpectedExternalContentPage{
				LogicalPage:     logicalPage,
				ContentObjectID: content.ObjectID,
				ContentKind:     content.Kind,
				PayloadLength:   uint32(payloadLength),
			})
		}
	}
	return expected, nil
}

func validateVNextExternalContentPageCRCs(
	grant vnextOwnerWriteGrant,
	records []vnextExternalContentPageCRC,
) ([]vnextExternalContentPageCRC, error) {
	expected, err := vnextExpectedExternalContentPages(grant)
	if err != nil {
		return nil, err
	}
	expectedByPage := make(map[uint64]vnextExpectedExternalContentPage, len(expected))
	for _, page := range expected {
		expectedByPage[page.LogicalPage] = page
	}
	recordsByPage := make(map[uint64]vnextExternalContentPageCRC, len(records))
	for _, record := range records {
		if !record.CopyEngine.valid() {
			return nil, fmt.Errorf(
				"external content logical page %d has invalid copy engine %d: %w",
				record.LogicalPage, record.CopyEngine, errVNextCRCSidecar)
		}
		if _, duplicate := recordsByPage[record.LogicalPage]; duplicate {
			return nil, fmt.Errorf(
				"external content logical page %d has duplicate CRC records: %w",
				record.LogicalPage, errVNextCRCSidecar)
		}
		if _, exists := expectedByPage[record.LogicalPage]; !exists {
			kind, objectID, found := vnextGrantContentAtLogicalPage(grant, record.LogicalPage)
			if found && kind == vnextContentPublication {
				return nil, fmt.Errorf(
					"publication content object %d logical page %d is Owner-written and cannot have an external CRC record: %w",
					objectID, record.LogicalPage, errVNextCRCSidecar)
			}
			return nil, fmt.Errorf(
				"external CRC logical page %d is not producer-written non-memory content: %w",
				record.LogicalPage, errVNextCRCSidecar)
		}
		recordsByPage[record.LogicalPage] = record
	}
	if len(recordsByPage) != len(expectedByPage) {
		for _, page := range expected {
			if _, exists := recordsByPage[page.LogicalPage]; !exists {
				return nil, fmt.Errorf(
					"external content object %d logical page %d is missing its CRC record: %w",
					page.ContentObjectID, page.LogicalPage, errVNextCRCSidecar)
			}
		}
		return nil, fmt.Errorf(
			"external content CRC coverage is %d pages, expected %d: %w",
			len(recordsByPage), len(expectedByPage), errVNextCRCSidecar)
	}
	validated := make([]vnextExternalContentPageCRC, 0, len(expected))
	for _, page := range expected {
		validated = append(validated, recordsByPage[page.LogicalPage])
	}
	return validated, nil
}

func vnextGrantContentAtLogicalPage(
	grant vnextOwnerWriteGrant,
	logicalPage uint64,
) (vnextContentKind, uint64, bool) {
	for _, content := range grant.Contents {
		end, ok := vnextAdd(content.LogicalPageStart, content.PageCount)
		if !ok || logicalPage < content.LogicalPageStart || logicalPage >= end {
			continue
		}
		return content.Kind, content.ObjectID, true
	}
	return 0, 0, false
}

func (group *vnextOwnerGroup) lockExternalSealDevicesLocked(
	plans []vnextExternalSealPlan,
) []*vnextPersistentDevice {
	used := make(map[string]*vnextPersistentDevice)
	for _, plan := range plans {
		used[plan.device.superblock.DeviceUUID] = plan.device
	}
	deviceUUIDs := make([]string, 0, len(used))
	for deviceUUID := range used {
		deviceUUIDs = append(deviceUUIDs, deviceUUID)
	}
	sort.Strings(deviceUUIDs)
	locked := make([]*vnextPersistentDevice, 0, len(deviceUUIDs))
	for _, deviceUUID := range deviceUUIDs {
		device := used[deviceUUID]
		device.mu.Lock()
		locked = append(locked, device)
	}
	return locked
}

func validateVNextPublicationAllocationGrant(
	publication cxlcheckpoint.Publication,
	grant vnextOwnerWriteGrant,
) error {
	allocation := publication.Allocation
	if allocation.OwnerID != grant.OwnerID ||
		allocation.OwnerEpoch != grant.OwnerEpoch ||
		allocation.AllocationRecordID != grant.AllocationRecordID {
		return fmt.Errorf("publication initial allocation does not match writer grant: %w",
			errVNextAuthority)
	}
	if len(allocation.Extents) != len(grant.Extents) {
		return fmt.Errorf(
			"publication has %d initial extents, writer grant has %d: %w",
			len(allocation.Extents), len(grant.Extents), errVNextAuthority)
	}
	if len(publication.ContentObjects) != len(grant.Contents) {
		return fmt.Errorf(
			"publication has %d content objects, writer grant has %d: %w",
			len(publication.ContentObjects), len(grant.Contents), errVNextAuthority)
	}
	for index, object := range publication.ContentObjects {
		granted := grant.Contents[index]
		if uint8(object.Kind) != uint8(granted.Kind) ||
			object.ObjectID != granted.ObjectID ||
			object.ByteLength != granted.ByteLength ||
			object.LogicalPageStart != granted.LogicalPageStart ||
			object.PageCount != granted.PageCount {
			return fmt.Errorf(
				"publication content object %d differs from writer grant: %w",
				index, errVNextAuthority)
		}
	}
	var totalPages uint64
	for index, extent := range allocation.Extents {
		granted := grant.Extents[index]
		if extent.DeviceUUID != granted.DeviceUUID ||
			extent.StartDataPageIndex != granted.StartDataPageIndex ||
			extent.PageCount != granted.PageCount ||
			extent.LogicalPageStart != granted.GlobalLogicalStart {
			return fmt.Errorf(
				"publication initial extent %d differs from writer grant: %w",
				index, errVNextAuthority)
		}
		next, ok := vnextAdd(totalPages, extent.PageCount)
		if !ok {
			return fmt.Errorf("publication initial extent count overflows: %w", errVNextCorrupt)
		}
		totalPages = next
	}
	if allocation.TotalPages != totalPages {
		return fmt.Errorf(
			"publication allocation has %d pages, extents grant %d: %w",
			allocation.TotalPages, totalPages, errVNextAuthority)
	}
	return nil
}

func (group *vnextOwnerGroup) externalSealPlanLocked(
	grant vnextOwnerWriteGrant,
	transaction *vnextOwnerTransaction,
	page vnextValidatedPageCRC,
) (vnextExternalSealPlan, uint64, error) {
	device := group.devices[page.PageID.DeviceUUID]
	fragmentGrant, hasGrant := grant.fragmentGrants[page.PageID.DeviceUUID]
	if device == nil || !hasGrant {
		return vnextExternalSealPlan{}, 0, fmt.Errorf(
			"writer grant cannot resolve device %q: %w",
			page.PageID.DeviceUUID, errVNextAuthority)
	}
	for _, fragment := range transaction.Fragments {
		if fragment.DeviceUUID != page.PageID.DeviceUUID {
			continue
		}
		for _, extent := range fragment.Extents {
			end, ok := vnextAdd(extent.StartDataPageIndex, extent.PageCount)
			if !ok {
				return vnextExternalSealPlan{}, 0, fmt.Errorf(
					"Owner extent overflows: %w", errVNextCorrupt)
			}
			if page.PageID.DataPageIndex < extent.StartDataPageIndex ||
				page.PageID.DataPageIndex >= end {
				continue
			}
			pageWithinExtent := page.PageID.DataPageIndex - extent.StartDataPageIndex
			globalLogicalPage, ok := vnextAdd(extent.GlobalLogicalStart, pageWithinExtent)
			if !ok || globalLogicalPage < fragment.GlobalLogicalStart {
				return vnextExternalSealPlan{}, 0, fmt.Errorf(
					"Owner logical page overflows: %w", errVNextCorrupt)
			}
			localLogicalPage := globalLogicalPage - fragment.GlobalLogicalStart
			return vnextExternalSealPlan{
				device:            device,
				fragmentGrant:     fragmentGrant,
				globalLogicalPage: globalLogicalPage,
				localLogicalPage:  localLogicalPage,
				dataPageIndex:     page.PageID.DataPageIndex,
				contentCRC32C:     page.ContentCRC32C,
				copyEngine:        page.CopyEngine,
			}, globalLogicalPage, nil
		}
	}
	return vnextExternalSealPlan{}, 0, fmt.Errorf(
		"PageID device page %d is outside the writer grant: %w",
		page.PageID.DataPageIndex, errVNextAuthority)
}

func (group *vnextOwnerGroup) externalContentSealPlanLocked(
	grant vnextOwnerWriteGrant,
	transaction *vnextOwnerTransaction,
	record vnextExternalContentPageCRC,
) (vnextExternalSealPlan, error) {
	for _, fragment := range transaction.Fragments {
		fragmentEnd, ok := vnextAdd(fragment.GlobalLogicalStart, fragment.PageCount)
		if !ok {
			return vnextExternalSealPlan{}, fmt.Errorf(
				"Owner fragment logical range overflows: %w", errVNextCorrupt)
		}
		if record.LogicalPage < fragment.GlobalLogicalStart ||
			record.LogicalPage >= fragmentEnd {
			continue
		}
		device := group.devices[fragment.DeviceUUID]
		fragmentGrant, hasGrant := grant.fragmentGrants[fragment.DeviceUUID]
		if device == nil || !hasGrant {
			return vnextExternalSealPlan{}, fmt.Errorf(
				"writer grant cannot resolve device %q: %w",
				fragment.DeviceUUID, errVNextAuthority)
		}
		for _, extent := range fragment.Extents {
			extentEnd, ok := vnextAdd(extent.GlobalLogicalStart, extent.PageCount)
			if !ok {
				return vnextExternalSealPlan{}, fmt.Errorf(
					"Owner extent logical range overflows: %w", errVNextCorrupt)
			}
			if record.LogicalPage < extent.GlobalLogicalStart ||
				record.LogicalPage >= extentEnd {
				continue
			}
			pageWithinExtent := record.LogicalPage - extent.GlobalLogicalStart
			dataPageIndex, ok := vnextAdd(extent.StartDataPageIndex, pageWithinExtent)
			if !ok {
				return vnextExternalSealPlan{}, fmt.Errorf(
					"Owner external content data page overflows: %w", errVNextCorrupt)
			}
			return vnextExternalSealPlan{
				device:            device,
				fragmentGrant:     fragmentGrant,
				globalLogicalPage: record.LogicalPage,
				localLogicalPage:  record.LogicalPage - fragment.GlobalLogicalStart,
				dataPageIndex:     dataPageIndex,
				contentCRC32C:     record.ContentCRC32C,
				copyEngine:        record.CopyEngine,
			}, nil
		}
		return vnextExternalSealPlan{}, fmt.Errorf(
			"external content logical page %d is outside Owner fragment extents: %w",
			record.LogicalPage, errVNextAuthority)
	}
	return vnextExternalSealPlan{}, fmt.Errorf(
		"external content logical page %d is outside allocation %d: %w",
		record.LogicalPage, grant.AllocationRecordID, errVNextAuthority)
}

func validateVNextCanonicalExternalContent(
	publication cxlcheckpoint.Publication,
	prepared []vnextPreparedExternalSeal,
) error {
	mmTemplateBytes, err := cxlcheckpoint.CanonicalMMTemplateBytes(publication.MMTemplate)
	if err != nil {
		return fmt.Errorf("encode canonical MMTemplate content: %w", err)
	}
	pageMapBytes, err := cxlcheckpoint.CanonicalPageMapBytes(publication.PageMap)
	if err != nil {
		return fmt.Errorf("encode canonical PageMap content: %w", err)
	}
	objects := make(map[uint64]cxlcheckpoint.ContentObject, len(publication.ContentObjects))
	for _, object := range publication.ContentObjects {
		objects[object.ObjectID] = object
	}
	mmObject, exists := objects[publication.MMTemplate.ContentObjectID]
	if !exists {
		return fmt.Errorf("canonical MMTemplate object is missing: %w", errVNextCorrupt)
	}
	activeMapObject, exists := objects[publication.PageMap.ContentObjectID]
	if !exists {
		return fmt.Errorf("canonical PageMap object is missing: %w", errVNextCorrupt)
	}
	preparedByLogicalPage := make(map[uint64]vnextPreparedExternalSeal, len(prepared))
	for _, page := range prepared {
		if _, duplicate := preparedByLogicalPage[page.globalLogicalPage]; duplicate {
			return fmt.Errorf(
				"logical page %d was prepared more than once: %w",
				page.globalLogicalPage, errVNextCorrupt)
		}
		preparedByLogicalPage[page.globalLogicalPage] = page
	}
	if err := validateVNextCanonicalContentObject(
		"MMTemplate", mmObject, mmTemplateBytes, preparedByLogicalPage); err != nil {
		return err
	}
	if err := validateVNextCanonicalContentObject(
		"active PageMap", activeMapObject, pageMapBytes, preparedByLogicalPage); err != nil {
		return err
	}

	// The publication contains semantic bytes only for the active slot. The
	// inactive slot may hold an older PageMap, so it is covered by the grant-
	// derived length, zero-padding, and producer CRC checks above but cannot be
	// compared to publication.PageMap. If its durable ByteLength is zero, the
	// ExpectedZeroPadding check in preparation requires every capacity page to
	// be all zero.
	return nil
}

func validateVNextCanonicalContentObject(
	label string,
	object cxlcheckpoint.ContentObject,
	exactBytes []byte,
	preparedByLogicalPage map[uint64]vnextPreparedExternalSeal,
) error {
	if uint64(len(exactBytes)) != object.ByteLength {
		return fmt.Errorf(
			"canonical %s has %d bytes, content object %d declares %d: %w",
			label, len(exactBytes), object.ObjectID, object.ByteLength, errVNextCorrupt)
	}
	for pageWithinObject := uint64(0); pageWithinObject < object.PageCount; pageWithinObject++ {
		logicalPage, ok := vnextAdd(object.LogicalPageStart, pageWithinObject)
		if !ok {
			return fmt.Errorf("canonical %s logical page overflows: %w", label, errVNextCorrupt)
		}
		prepared, exists := preparedByLogicalPage[logicalPage]
		if !exists || prepared.contentObjectID != object.ObjectID ||
			uint8(prepared.contentKind) != uint8(object.Kind) {
			return fmt.Errorf(
				"canonical %s logical page %d is not backed by its durable content grant: %w",
				label, logicalPage, errVNextAuthority)
		}
		want := make([]byte, int(vnextContentPageSize))
		byteStart, ok := vnextMul(pageWithinObject, vnextContentPageSize)
		if !ok {
			return fmt.Errorf("canonical %s byte offset overflows: %w", label, errVNextCorrupt)
		}
		if byteStart < uint64(len(exactBytes)) {
			byteEnd, ok := vnextAdd(byteStart, vnextContentPageSize)
			if !ok {
				return fmt.Errorf("canonical %s byte range overflows: %w", label, errVNextCorrupt)
			}
			if byteEnd > uint64(len(exactBytes)) {
				byteEnd = uint64(len(exactBytes))
			}
			copy(want, exactBytes[int(byteStart):int(byteEnd)])
		}
		if !bytes.Equal(prepared.contentPage, want) {
			return fmt.Errorf(
				"%s content object %d logical page %d differs from its canonical CXL bytes: %w",
				label, object.ObjectID, logicalPage, errVNextCorrupt)
		}
	}
	return nil
}

func (device *vnextPersistentDevice) prepareExternallyWrittenPageLocked(
	grant vnextWriteGrant,
	globalLogicalPage uint64,
	logicalPage uint64,
	expectedDataPageIndex uint64,
	expectedCRC32C uint32,
	copyEngine vnextCRCCopyEngine,
) (vnextPreparedExternalSeal, error) {
	if err := device.checkUsableLocked(); err != nil {
		return vnextPreparedExternalSeal{}, err
	}
	if !copyEngine.valid() {
		return vnextPreparedExternalSeal{}, fmt.Errorf(
			"invalid external copy engine %d", copyEngine)
	}
	authorization, err := device.allocator.authorizePageWrite(grant, logicalPage)
	if err != nil {
		return vnextPreparedExternalSeal{}, err
	}
	if authorization.DataPageIndex != expectedDataPageIndex {
		return vnextPreparedExternalSeal{}, fmt.Errorf(
			"external PageID is data page %d, grant resolves page %d: %w",
			expectedDataPageIndex, authorization.DataPageIndex, errVNextAuthority)
	}
	current, err := device.readDescriptorLocked(authorization.DataPageIndex)
	if err != nil {
		return vnextPreparedExternalSeal{}, err
	}
	if current.State != vnextDescriptorReserved &&
		current.State != vnextDescriptorSealed {
		return vnextPreparedExternalSeal{}, fmt.Errorf(
			"external page descriptor is state %d: %w",
			current.State, errVNextInvalidState)
	}
	if current.AllocationRecordID != authorization.AllocationRecordID ||
		current.OriginContentObjectID != authorization.ContentObjectID ||
		current.ContentKind != authorization.ContentKind ||
		current.PayloadLength != authorization.ExpectedPayloadLength {
		return vnextPreparedExternalSeal{}, fmt.Errorf(
			"external page descriptor does not match writer authorization: %w",
			errVNextAuthority)
	}

	content, err := device.readVisibleExternalContentLocked(
		authorization.ContentOffset, copyEngine, current.State == vnextDescriptorReserved)
	if err != nil {
		return vnextPreparedExternalSeal{}, err
	}
	if authorization.ExpectedZeroPadding && !vnextAllZero(content) {
		return vnextPreparedExternalSeal{}, fmt.Errorf(
			"external logical page %d is reserved capacity padding and must be all zero: %w",
			globalLogicalPage, errVNextCorrupt)
	}
	payloadLength := int(authorization.ExpectedPayloadLength)
	if payloadLength <= 0 || payloadLength > len(content) {
		return vnextPreparedExternalSeal{}, fmt.Errorf(
			"external payload length %d is invalid", payloadLength)
	}
	expectedPage, sealed, err := buildVNextContentPage(
		authorization.ContentKind,
		content[:payloadLength],
		authorization.AllocationRecordID,
		authorization.ContentObjectID,
		authorization.OwnerTransaction)
	if err != nil {
		return vnextPreparedExternalSeal{}, err
	}
	if !bytes.Equal(expectedPage[:], content) {
		return vnextPreparedExternalSeal{}, fmt.Errorf(
			"external short payload has non-zero bytes beyond its exact length: %w",
			errVNextCorrupt)
	}
	if sealed.ContentCRC32 != expectedCRC32C {
		return vnextPreparedExternalSeal{}, fmt.Errorf(
			"external page CRC-32C is %#x, producer evidence records %#x: %w",
			sealed.ContentCRC32, expectedCRC32C, errVNextCorrupt)
	}
	if current.State == vnextDescriptorSealed {
		if current != sealed {
			return vnextPreparedExternalSeal{}, fmt.Errorf(
				"external page was already sealed with different metadata: %w",
				errVNextAuthority)
		}
		prepared := vnextPreparedExternalSeal{
			device:            device,
			globalLogicalPage: globalLogicalPage,
			dataPageIndex:     authorization.DataPageIndex,
			contentObjectID:   authorization.ContentObjectID,
			contentKind:       authorization.ContentKind,
			descriptorOffset:  authorization.DescriptorOffset,
			alreadySealed:     true,
		}
		if authorization.ContentKind == vnextContentMMTemplate ||
			authorization.ContentKind == vnextContentPageMap {
			prepared.contentPage = content
		}
		return prepared, nil
	}
	descriptorData, err := sealed.marshalBinary()
	if err != nil {
		return vnextPreparedExternalSeal{}, err
	}
	prepared := vnextPreparedExternalSeal{
		device:            device,
		globalLogicalPage: globalLogicalPage,
		dataPageIndex:     authorization.DataPageIndex,
		contentObjectID:   authorization.ContentObjectID,
		contentKind:       authorization.ContentKind,
		descriptorOffset:  authorization.DescriptorOffset,
		descriptorData:    descriptorData,
	}
	// Retain page bytes only for structured objects that require a canonical
	// comparison. Memory, artifact, and restore plans stay fixed-size, so the
	// two-phase seal does not keep a second checkpoint-sized payload copy.
	if authorization.ContentKind == vnextContentMMTemplate ||
		authorization.ContentKind == vnextContentPageMap {
		prepared.contentPage = content
	}
	return prepared, nil
}

// applyPreparedExternalSealLocked changes only the descriptor cache line. Its
// caller holds the device lock and has already validated every page in the
// checkpoint.
func (device *vnextPersistentDevice) applyPreparedExternalSealLocked(
	prepared vnextPreparedExternalSeal,
) error {
	if prepared.device != device {
		return fmt.Errorf("prepared descriptor belongs to another device: %w",
			errVNextAuthority)
	}
	if prepared.alreadySealed {
		return nil
	}
	if len(prepared.descriptorData) != int(vnextPageDescriptorSize) {
		return fmt.Errorf("prepared descriptor has %d bytes: %w",
			len(prepared.descriptorData), errVNextCorrupt)
	}
	if err := vnextWriteAtFull(
		device.storage, prepared.descriptorData, prepared.descriptorOffset); err != nil {
		return device.poisonLocked(fmt.Errorf("seal external page descriptor: %w", err))
	}
	return nil
}

func (device *vnextPersistentDevice) readVisibleExternalContentLocked(
	contentOffset uint64,
	copyEngine vnextCRCCopyEngine,
	needsVisibilityBarrier bool,
) ([]byte, error) {
	if err := vnextValidateUnsignedStorageRange(
		device.storage.Size(), contentOffset, int(vnextContentPageSize), "external mmap"); err != nil {
		return nil, err
	}
	if contentOffset%uint64(os.Getpagesize()) != 0 {
		return nil, errors.New("external content offset is not host-page aligned")
	}
	if device.storage.FD() > uintptr(maxInt()) {
		return nil, errors.New("external content file descriptor exceeds int ABI")
	}
	mappingAlignment := device.storage.MappingAlignment()
	if mappingAlignment < uint64(os.Getpagesize()) ||
		mappingAlignment%uint64(os.Getpagesize()) != 0 {
		return nil, errors.New("external content mapping alignment is invalid")
	}
	mappingOffset := vnextAlignDown(contentOffset, mappingAlignment)
	contentEnd := contentOffset + vnextContentPageSize
	mappingEnd := vnextAlignUpBounded(
		contentEnd, mappingAlignment, device.storage.Size())
	mappingLength := mappingEnd - mappingOffset
	if mappingLength == 0 || mappingLength > uint64(maxInt()) {
		return nil, errors.New("external content mapping length exceeds int ABI")
	}
	mapped, err := unix.Mmap(
		int(device.storage.FD()),
		int64(mappingOffset),
		int(mappingLength),
		unix.PROT_READ|unix.PROT_WRITE,
		unix.MAP_SHARED)
	if err != nil {
		return nil, fmt.Errorf("map externally written content page: %w", err)
	}
	defer unix.Munmap(mapped) //nolint:errcheck
	pageOffset := contentOffset - mappingOffset
	pageEnd := pageOffset + vnextContentPageSize
	page := mapped[int(pageOffset):int(pageEnd)]
	if needsVisibilityBarrier {
		err := vnextExternalPayloadVisibilityHook(
			page,
			func(data []byte) error {
				return directDaxFlushHook(device.file, data)
			},
			func(data []byte) error {
				return directDaxInvalidateHook(data)
			},
			copyEngine)
		if err != nil {
			return nil, fmt.Errorf("make external payload visible: %w", err)
		}
	}
	return append([]byte(nil), page...), nil
}

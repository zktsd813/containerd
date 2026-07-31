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
	device           *vnextPersistentDevice
	fragmentGrant    vnextWriteGrant
	localLogicalPage uint64
	dataPageIndex    uint64
	contentCRC32C    uint32
	copyEngine       vnextCRCCopyEngine
}

type vnextPreparedExternalSeal struct {
	device           *vnextPersistentDevice
	dataPageIndex    uint64
	descriptorOffset uint64
	descriptorData   []byte
	alreadySealed    bool
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

	expectedMemoryPages := make(map[uint64]struct{})
	for _, content := range publication.ContentObjects {
		if content.Kind != cxlcheckpoint.ContentMemory {
			continue
		}
		end, ok := vnextAdd(content.LogicalPageStart, content.PageCount)
		if !ok {
			return fmt.Errorf("memory content logical range overflows: %w", errVNextCorrupt)
		}
		for logicalPage := content.LogicalPageStart; logicalPage < end; logicalPage++ {
			expectedMemoryPages[logicalPage] = struct{}{}
		}
	}
	if len(expectedMemoryPages) == 0 || len(validated) != len(expectedMemoryPages) {
		return fmt.Errorf(
			"TRCRC006 covers %d pages, publication has %d memory pages: %w",
			len(validated), len(expectedMemoryPages), errVNextCRCSidecar)
	}

	plans := make([]vnextExternalSealPlan, 0, len(validated))
	seenLogicalPages := make(map[uint64]struct{}, len(validated))
	for _, page := range validated {
		if page.PageID.OwnerID != grant.OwnerID ||
			page.PageID.AllocationRecordID != grant.AllocationRecordID {
			return fmt.Errorf(
				"writer PageMap references canonical page outside its initial allocation: %w",
				errVNextAuthority)
		}
		plan, globalLogicalPage, err :=
			group.externalSealPlanLocked(grant, transaction, page)
		if err != nil {
			return err
		}
		if _, expected := expectedMemoryPages[globalLogicalPage]; !expected {
			return fmt.Errorf(
				"TRCRC006 PageID resolves to non-memory logical page %d: %w",
				globalLogicalPage, errVNextAuthority)
		}
		if _, duplicate := seenLogicalPages[globalLogicalPage]; duplicate {
			return fmt.Errorf(
				"TRCRC006 maps memory logical page %d more than once: %w",
				globalLogicalPage, errVNextCRCSidecar)
		}
		seenLogicalPages[globalLogicalPage] = struct{}{}
		plans = append(plans, plan)
	}
	if len(seenLogicalPages) != len(expectedMemoryPages) {
		return fmt.Errorf(
			"TRCRC006 memory coverage is %d pages, expected %d: %w",
			len(seenLogicalPages), len(expectedMemoryPages), errVNextCRCSidecar)
	}

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
				device:           device,
				fragmentGrant:    fragmentGrant,
				localLogicalPage: localLogicalPage,
				dataPageIndex:    page.PageID.DataPageIndex,
				contentCRC32C:    page.ContentCRC32C,
				copyEngine:       page.CopyEngine,
			}, globalLogicalPage, nil
		}
	}
	return vnextExternalSealPlan{}, 0, fmt.Errorf(
		"PageID device page %d is outside the writer grant: %w",
		page.PageID.DataPageIndex, errVNextAuthority)
}

func (device *vnextPersistentDevice) prepareExternallyWrittenPageLocked(
	grant vnextWriteGrant,
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
			"external page CRC-32C is %#x, TRCRC006 records %#x: %w",
			sealed.ContentCRC32, expectedCRC32C, errVNextCorrupt)
	}
	if current.State == vnextDescriptorSealed {
		if current != sealed {
			return vnextPreparedExternalSeal{}, fmt.Errorf(
				"external page was already sealed with different metadata: %w",
				errVNextAuthority)
		}
		return vnextPreparedExternalSeal{
			device:           device,
			dataPageIndex:    authorization.DataPageIndex,
			descriptorOffset: authorization.DescriptorOffset,
			alreadySealed:    true,
		}, nil
	}
	descriptorData, err := sealed.marshalBinary()
	if err != nil {
		return vnextPreparedExternalSeal{}, err
	}
	return vnextPreparedExternalSeal{
		device:           device,
		dataPageIndex:    authorization.DataPageIndex,
		descriptorOffset: authorization.DescriptorOffset,
		descriptorData:   descriptorData,
	}, nil
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

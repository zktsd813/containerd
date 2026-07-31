package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"sync"
)

const vnextMetadataZeroChunkBytes = 1 << 20

type vnextPersistentDevice struct {
	mu sync.Mutex

	file       *os.File
	storage    vnextDeviceStorage
	superblock vnextDeviceSuperblock
	allocator  *vnextCheckpointAllocator
	poisoned   error
}

// formatVNextFileDevice destructively creates a fresh VNext layout in a
// pre-sized regular file. Real devdax must use formatVNextDevDAXDevice because
// Linux devdax character devices do not implement read(2)/write(2).
func formatVNextFileDevice(
	file *os.File,
	deviceUUID string,
	ownerID string,
	ownerEpoch uint64,
	allocatorSlotBytes uint64,
) (*vnextPersistentDevice, error) {
	storage, err := newVNextRegularFileStorage(file)
	if err != nil {
		return nil, err
	}
	return formatVNextStorageDevice(
		file, storage, deviceUUID, ownerID, ownerEpoch, allocatorSlotBytes)
}

func formatVNextStorageDevice(
	file *os.File,
	storage vnextDeviceStorage,
	deviceUUID string,
	ownerID string,
	ownerEpoch uint64,
	allocatorSlotBytes uint64,
) (*vnextPersistentDevice, error) {
	if storage == nil {
		return nil, errors.New("VNext device storage is nil")
	}
	geometry, err := calculateVNextDeviceGeometry(storage.Size(), allocatorSlotBytes)
	if err != nil {
		return nil, err
	}
	superblock := vnextDeviceSuperblock{
		DeviceUUID: deviceUUID,
		OwnerID:    ownerID,
		OwnerEpoch: ownerEpoch,
		Sequence:   1,
		Geometry:   geometry,
	}
	if err := superblock.validate(); err != nil {
		return nil, err
	}

	// Offline format clears all authoritative control and descriptor bytes.
	// Payload bytes are not required to be zero because a page is invisible
	// until its bitmap bit and sealed descriptor are committed.
	if err := vnextZeroRange(storage, 0, geometry.ContentRegionBase); err != nil {
		return nil, fmt.Errorf("clear VNext metadata regions: %w", err)
	}
	if err := storage.Sync(); err != nil {
		return nil, fmt.Errorf("sync cleared VNext metadata: %w", err)
	}
	dataA, err := superblock.marshalBinary()
	if err != nil {
		return nil, err
	}
	if err := vnextWriteCommittedEnvelopeSlot(
		storage, geometry.SuperblockAOffset, vnextSuperblockSlotBytes, dataA); err != nil {
		return nil, fmt.Errorf("write superblock A: %w", err)
	}
	superblock.Sequence = 2
	dataB, err := superblock.marshalBinary()
	if err != nil {
		return nil, err
	}
	if err := vnextWriteCommittedEnvelopeSlot(
		storage, geometry.SuperblockBOffset, vnextSuperblockSlotBytes, dataB); err != nil {
		return nil, fmt.Errorf("write superblock B: %w", err)
	}

	allocator, err := newVNextCheckpointAllocator(superblock)
	if err != nil {
		return nil, err
	}
	device := &vnextPersistentDevice{
		file:       file,
		storage:    storage,
		superblock: superblock,
		allocator:  allocator,
	}
	if err := device.persistAllocatorLocked(); err != nil {
		return nil, fmt.Errorf("write allocator snapshot A: %w", err)
	}
	if err := device.persistAllocatorLocked(); err != nil {
		return nil, fmt.Errorf("write allocator snapshot B: %w", err)
	}
	return device, nil
}

func openVNextFileDevice(file *os.File) (*vnextPersistentDevice, error) {
	storage, err := newVNextRegularFileStorage(file)
	if err != nil {
		return nil, err
	}
	return openVNextStorageDevice(file, storage)
}

func openVNextStorageDevice(
	file *os.File,
	storage vnextDeviceStorage,
) (*vnextPersistentDevice, error) {
	if storage == nil {
		return nil, errors.New("VNext device storage is nil")
	}
	superblockA, errA := vnextReadSuperblockSlot(storage, 0)
	superblockB, errB := vnextReadSuperblockSlot(storage, vnextSuperblockSlotBytes)
	superblock, err := vnextSelectSuperblock(superblockA, errA, superblockB, errB)
	if err != nil {
		return nil, err
	}
	if storage.Size() != superblock.Geometry.DeviceBytes {
		return nil, fmt.Errorf(
			"device size is %d, superblock records %d: %w",
			storage.Size(), superblock.Geometry.DeviceBytes, errVNextWrongFormat)
	}

	allocatorA, allocatorErrA := vnextReadAllocatorSlot(
		storage,
		superblock.Geometry.AllocatorSlotAOffset,
		superblock.Geometry.AllocatorSlotBytes,
		superblock)
	allocatorB, allocatorErrB := vnextReadAllocatorSlot(
		storage,
		superblock.Geometry.AllocatorSlotBOffset,
		superblock.Geometry.AllocatorSlotBytes,
		superblock)
	allocator, err := vnextSelectAllocator(allocatorA, allocatorErrA, allocatorB, allocatorErrB)
	if err != nil {
		return nil, err
	}
	device := &vnextPersistentDevice{
		file:       file,
		storage:    storage,
		superblock: superblock,
		allocator:  allocator,
	}
	if err := device.recoverPendingLocked(); err != nil {
		device.poisoned = err
		return nil, fmt.Errorf("recover pending VNext allocator transaction: %w", err)
	}
	if err := device.reconcileDescriptorsLocked(); err != nil {
		device.poisoned = err
		return nil, fmt.Errorf("reconcile VNext descriptors: %w", err)
	}
	return device, nil
}

func (d *vnextPersistentDevice) reserve(
	request vnextCheckpointAllocationRequest,
) (vnextWriteGrant, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if err := d.checkUsableLocked(); err != nil {
		return vnextWriteGrant{}, err
	}
	grant, err := d.allocator.reserve(request)
	if err != nil {
		return vnextWriteGrant{}, err
	}
	if err := d.persistAllocatorLocked(); err != nil {
		return vnextWriteGrant{}, d.poisonLocked(fmt.Errorf("persist reservation: %w", err))
	}
	record, ok := d.allocator.lookup(request.CheckpointID)
	if !ok {
		return vnextWriteGrant{}, d.poisonLocked(errors.New("reserved allocation disappeared"))
	}
	if err := d.initializeReservedDescriptorsLocked(record); err != nil {
		return vnextWriteGrant{}, d.poisonLocked(fmt.Errorf("initialize reserved descriptors: %w", err))
	}
	return grant, nil
}

func (d *vnextPersistentDevice) writePage(
	grant vnextWriteGrant,
	logicalPage uint64,
	content []byte,
) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if err := d.checkUsableLocked(); err != nil {
		return err
	}
	authorization, err := d.allocator.authorizePageWrite(grant, logicalPage)
	if err != nil {
		return err
	}
	if uint32(len(content)) != authorization.ExpectedPayloadLength {
		return fmt.Errorf(
			"logical page %d has %d bytes, expected %d",
			logicalPage, len(content), authorization.ExpectedPayloadLength)
	}
	if authorization.ExpectedZeroPadding && !vnextAllZero(content) {
		return fmt.Errorf(
			"logical page %d is reserved capacity padding and must be all zero: %w",
			logicalPage, errVNextAuthority)
	}
	page, sealed, err := buildVNextContentPage(
		authorization.ContentKind,
		content,
		authorization.AllocationRecordID,
		authorization.ContentObjectID,
		authorization.OwnerTransaction)
	if err != nil {
		return err
	}
	current, err := d.readDescriptorLocked(authorization.DataPageIndex)
	if err != nil {
		return err
	}
	if current.State == vnextDescriptorSealed {
		if current != sealed {
			return fmt.Errorf(
				"logical page %d was already sealed with different metadata: %w",
				logicalPage, errVNextAuthority)
		}
		existingPage, err := d.readContentPageLocked(authorization.DataPageIndex)
		if err != nil {
			return err
		}
		if !bytes.Equal(existingPage, page[:]) {
			return fmt.Errorf(
				"logical page %d was already sealed with different content: %w",
				logicalPage, errVNextAuthority)
		}
		return nil
	}
	if current.State != vnextDescriptorReserved ||
		current.AllocationRecordID != authorization.AllocationRecordID ||
		current.OriginContentObjectID != authorization.ContentObjectID ||
		current.ContentKind != authorization.ContentKind ||
		current.PayloadLength != authorization.ExpectedPayloadLength {
		return fmt.Errorf(
			"descriptor for data page %d does not match producer grant: %w",
			authorization.DataPageIndex, errVNextAuthority)
	}

	if err := vnextWriteAtFull(d.storage, page[:], authorization.ContentOffset); err != nil {
		return d.poisonLocked(fmt.Errorf("write content page: %w", err))
	}
	if err := d.storage.Sync(); err != nil {
		return d.poisonLocked(fmt.Errorf("sync content page: %w", err))
	}
	descriptorData, err := sealed.marshalBinary()
	if err != nil {
		return err
	}
	if err := vnextWriteAtFull(d.storage, descriptorData, authorization.DescriptorOffset); err != nil {
		return d.poisonLocked(fmt.Errorf("seal page descriptor: %w", err))
	}
	if err := d.storage.Sync(); err != nil {
		return d.poisonLocked(fmt.Errorf("sync page descriptor: %w", err))
	}
	return nil
}

func (d *vnextPersistentDevice) commit(grant vnextWriteGrant) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if err := d.checkUsableLocked(); err != nil {
		return err
	}
	record, ok := d.allocator.lookup(grant.CheckpointID)
	if !ok || record.AllocationRecordID != grant.AllocationRecordID {
		return errors.New("commit grant does not name an allocation")
	}
	if err := d.validateSealedRecordLocked(record, true); err != nil {
		return err
	}
	if err := d.allocator.commit(grant); err != nil {
		return err
	}
	if err := d.persistAllocatorLocked(); err != nil {
		return d.poisonLocked(fmt.Errorf("persist commit: %w", err))
	}
	return nil
}

func (d *vnextPersistentDevice) abort(grant vnextWriteGrant) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if err := d.checkUsableLocked(); err != nil {
		return err
	}
	record, ok := d.allocator.lookup(grant.CheckpointID)
	if !ok || record.AllocationRecordID != grant.AllocationRecordID {
		return errors.New("abort grant does not name an allocation")
	}
	if err := d.allocator.beginAbort(grant); err != nil {
		return err
	}
	if err := d.persistAllocatorLocked(); err != nil {
		return d.poisonLocked(fmt.Errorf("persist abort decision: %w", err))
	}
	if err := d.clearRecordDescriptorsLocked(record, true, true); err != nil {
		return d.poisonLocked(fmt.Errorf("clear aborted descriptors: %w", err))
	}
	if err := d.allocator.finishAbort(record.AllocationRecordID); err != nil {
		return d.poisonLocked(fmt.Errorf("finish allocator abort: %w", err))
	}
	if err := d.persistAllocatorLocked(); err != nil {
		return d.poisonLocked(fmt.Errorf("persist freed abort pages: %w", err))
	}
	return nil
}

func (d *vnextPersistentDevice) reclaimCheckpoint(request vnextReclaimRequest) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if err := d.checkUsableLocked(); err != nil {
		return err
	}
	record, ok := d.allocator.lookup(request.CheckpointID)
	if !ok || record.AllocationRecordID != request.AllocationRecordID {
		return errors.New("reclaim request does not name an allocation")
	}
	// The conservative whole-checkpoint primitive only accepts private pages.
	// Cross-checkpoint reference accounting will replace this gate in the
	// later dedup/reclaim integration.
	if err := d.validateSealedRecordLocked(record, false); err != nil {
		return err
	}
	if err := d.allocator.beginReclaim(request); err != nil {
		return err
	}
	if err := d.persistAllocatorLocked(); err != nil {
		return d.poisonLocked(fmt.Errorf("persist reclaim decision: %w", err))
	}
	if err := d.clearRecordDescriptorsLocked(record, false, false); err != nil {
		return d.poisonLocked(fmt.Errorf("clear reclaimed descriptors: %w", err))
	}
	if err := d.allocator.finishReclaim(record.AllocationRecordID); err != nil {
		return d.poisonLocked(fmt.Errorf("finish allocator reclaim: %w", err))
	}
	if err := d.persistAllocatorLocked(); err != nil {
		return d.poisonLocked(fmt.Errorf("persist reclaimed free pages: %w", err))
	}
	return nil
}

func (d *vnextPersistentDevice) persistAllocatorLocked() error {
	data, sequence, err := d.allocator.marshalNextSnapshot()
	if err != nil {
		return err
	}
	offset := d.superblock.Geometry.AllocatorSlotAOffset
	if sequence%2 == 0 {
		offset = d.superblock.Geometry.AllocatorSlotBOffset
	}
	if err := vnextWriteCommittedEnvelopeSlot(
		d.storage,
		offset,
		d.superblock.Geometry.AllocatorSlotBytes,
		data); err != nil {
		return err
	}
	return d.allocator.markSnapshotDurable(sequence)
}

func (d *vnextPersistentDevice) initializeReservedDescriptorsLocked(
	record vnextAllocationRecord,
) error {
	for logicalPage := uint64(0); logicalPage < record.TotalPages; logicalPage++ {
		dataPage, err := vnextRecordPhysicalPage(&record, logicalPage)
		if err != nil {
			return err
		}
		current, err := d.readDescriptorLocked(dataPage)
		if err != nil {
			return err
		}
		segment, err := vnextRecordContentSegment(&record, logicalPage)
		if err != nil {
			return err
		}
		pageWithinObject := logicalPage - segment.LogicalPageStart
		consumed, ok := vnextMul(pageWithinObject, vnextContentPageSize)
		if !ok {
			return fmt.Errorf("content length overflow: %w", errVNextCorrupt)
		}
		payloadLength := vnextContentPageSize
		if consumed < segment.ByteLength {
			remaining := segment.ByteLength - consumed
			if remaining < payloadLength {
				payloadLength = remaining
			}
		}
		descriptor := vnextPageDescriptor{
			AllocationRecordID:      record.AllocationRecordID,
			OriginContentObjectID:   segment.ObjectID,
			LastOwnerTransactionSeq: record.OwnerTransaction,
			PayloadLength:           uint32(payloadLength),
			State:                   vnextDescriptorReserved,
			ContentKind:             segment.Kind,
		}
		if current.State == vnextDescriptorReserved && current == descriptor {
			continue
		}
		if current.State == vnextDescriptorSealed &&
			current.AllocationRecordID == descriptor.AllocationRecordID &&
			current.OriginContentObjectID == descriptor.OriginContentObjectID &&
			current.LastOwnerTransactionSeq == descriptor.LastOwnerTransactionSeq &&
			current.PayloadLength == descriptor.PayloadLength &&
			current.ContentKind == descriptor.ContentKind {
			continue
		}
		if current.State != vnextDescriptorFree {
			return fmt.Errorf(
				"new allocation page %d has non-matching descriptor state %d/allocation %d: %w",
				dataPage, current.State, current.AllocationRecordID, errVNextCorrupt)
		}
		raw, err := descriptor.marshalBinary()
		if err != nil {
			return err
		}
		offset, err := d.superblock.Geometry.descriptorOffset(dataPage)
		if err != nil {
			return err
		}
		if err := vnextWriteAtFull(d.storage, raw, offset); err != nil {
			return err
		}
	}
	return d.storage.Sync()
}

func (d *vnextPersistentDevice) validateSealedRecordLocked(
	record vnextAllocationRecord,
	validatePayload bool,
) error {
	for logicalPage := uint64(0); logicalPage < record.TotalPages; logicalPage++ {
		dataPage, err := vnextRecordPhysicalPage(&record, logicalPage)
		if err != nil {
			return err
		}
		segment, err := vnextRecordContentSegment(&record, logicalPage)
		if err != nil {
			return err
		}
		descriptor, err := d.readDescriptorLocked(dataPage)
		if err != nil {
			return err
		}
		if descriptor.State != vnextDescriptorSealed ||
			descriptor.AllocationRecordID != record.AllocationRecordID ||
			descriptor.OriginContentObjectID != segment.ObjectID ||
			descriptor.ContentKind != segment.Kind {
			return fmt.Errorf(
				"data page %d is not sealed for allocation %d: %w",
				dataPage, record.AllocationRecordID, errVNextInvalidState)
		}
		if descriptor.ContentReferenceCount != 1 {
			return fmt.Errorf(
				"data page %d has reference count %d, whole-checkpoint reclaim requires 1: %w",
				dataPage, descriptor.ContentReferenceCount, errVNextInvalidState)
		}
		if validatePayload {
			page, err := d.readContentPageLocked(dataPage)
			if err != nil {
				return err
			}
			if err := descriptor.validateContent(page); err != nil {
				return err
			}
		}
	}
	return nil
}

func (d *vnextPersistentDevice) clearRecordDescriptorsLocked(
	record vnextAllocationRecord,
	allowFree bool,
	allowReserved bool,
) error {
	dataPages := make([]uint64, 0, record.TotalPages)
	for logicalPage := uint64(0); logicalPage < record.TotalPages; logicalPage++ {
		dataPage, err := vnextRecordPhysicalPage(&record, logicalPage)
		if err != nil {
			return err
		}
		descriptor, err := d.readDescriptorLocked(dataPage)
		if err != nil {
			return err
		}
		if descriptor.State == vnextDescriptorFree && allowFree {
			dataPages = append(dataPages, dataPage)
			continue
		}
		if descriptor.AllocationRecordID != record.AllocationRecordID {
			return fmt.Errorf(
				"refusing to clear page %d owned by allocation %d: %w",
				dataPage, descriptor.AllocationRecordID, errVNextAuthority)
		}
		if descriptor.State != vnextDescriptorSealed &&
			!(allowReserved && descriptor.State == vnextDescriptorReserved) {
			return fmt.Errorf("reclaim descriptor state %d is invalid", descriptor.State)
		}
		dataPages = append(dataPages, dataPage)
	}
	zero := make([]byte, vnextPageDescriptorSize)
	for _, dataPage := range dataPages {
		offset, err := d.superblock.Geometry.descriptorOffset(dataPage)
		if err != nil {
			return err
		}
		if err := vnextWriteAtFull(d.storage, zero, offset); err != nil {
			return err
		}
	}
	return d.storage.Sync()
}

func (d *vnextPersistentDevice) recoverPendingLocked() error {
	recordIDs := make([]uint64, 0)
	d.allocator.mu.Lock()
	for recordID, record := range d.allocator.records {
		if record.State == vnextAllocationAbortPending ||
			record.State == vnextAllocationReclaimPending {
			recordIDs = append(recordIDs, recordID)
		}
	}
	d.allocator.mu.Unlock()
	for _, recordID := range recordIDs {
		d.allocator.mu.Lock()
		recordPointer := d.allocator.records[recordID]
		record := cloneVNextAllocationRecord(recordPointer)
		d.allocator.mu.Unlock()
		allowReserved := record.State == vnextAllocationAbortPending
		if err := d.clearRecordDescriptorsLocked(record, true, allowReserved); err != nil {
			return err
		}
		var err error
		if record.State == vnextAllocationAbortPending {
			err = d.allocator.finishAbort(recordID)
		} else {
			err = d.allocator.finishReclaim(recordID)
		}
		if err != nil {
			return err
		}
		if err := d.persistAllocatorLocked(); err != nil {
			return err
		}
	}
	return nil
}

func (d *vnextPersistentDevice) reconcileDescriptorsLocked() error {
	type pageOwner struct {
		recordID uint64
		state    vnextAllocationState
	}
	owners := make(map[uint64]pageOwner)
	d.allocator.mu.Lock()
	for _, record := range d.allocator.records {
		if !record.State.ownsPages() {
			continue
		}
		for _, extent := range record.Extents {
			for page := uint64(0); page < extent.PageCount; page++ {
				owners[extent.StartDataPageIndex+page] = pageOwner{
					recordID: record.AllocationRecordID,
					state:    record.State,
				}
			}
		}
	}
	pageCount := d.allocator.superblock.Geometry.DataPageCount
	d.allocator.mu.Unlock()

	for dataPage := uint64(0); dataPage < pageCount; dataPage++ {
		descriptor, err := d.readDescriptorLocked(dataPage)
		if err != nil {
			return err
		}
		owner, allocated := owners[dataPage]
		if !allocated {
			if descriptor.State != vnextDescriptorFree {
				return fmt.Errorf(
					"free bitmap page %d has descriptor state %d/allocation %d: %w",
					dataPage, descriptor.State, descriptor.AllocationRecordID, errVNextCorrupt)
			}
			continue
		}
		if descriptor.State == vnextDescriptorFree {
			if owner.state == vnextAllocationReserved {
				// A crash may happen after the durable reservation and before
				// the Owner initializes every descriptor. The bitmap remains
				// allocated, so this is a recoverable capacity leak, never a
				// double allocation.
				continue
			}
			return fmt.Errorf(
				"active allocation %d page %d has a FREE descriptor: %w",
				owner.recordID, dataPage, errVNextCorrupt)
		}
		if descriptor.AllocationRecordID != owner.recordID {
			return fmt.Errorf(
				"bitmap page %d belongs to allocation %d but descriptor names %d: %w",
				dataPage, owner.recordID, descriptor.AllocationRecordID, errVNextCorrupt)
		}
		switch owner.state {
		case vnextAllocationReserved:
			if descriptor.State != vnextDescriptorReserved &&
				descriptor.State != vnextDescriptorSealed {
				return fmt.Errorf(
					"reserved allocation %d has descriptor state %d: %w",
					owner.recordID, descriptor.State, errVNextCorrupt)
			}
		case vnextAllocationCommitted:
			if descriptor.State != vnextDescriptorSealed {
				return fmt.Errorf(
					"committed allocation %d has descriptor state %d: %w",
					owner.recordID, descriptor.State, errVNextCorrupt)
			}
		default:
			return fmt.Errorf(
				"recovery left allocation %d in transitional state %d: %w",
				owner.recordID, owner.state, errVNextCorrupt)
		}
	}
	return nil
}

func (d *vnextPersistentDevice) readDescriptorLocked(
	dataPageIndex uint64,
) (vnextPageDescriptor, error) {
	offset, err := d.superblock.Geometry.descriptorOffset(dataPageIndex)
	if err != nil {
		return vnextPageDescriptor{}, err
	}
	raw := make([]byte, vnextPageDescriptorSize)
	if err := vnextReadAtFull(d.storage, raw, offset); err != nil {
		return vnextPageDescriptor{}, err
	}
	return parseVNextPageDescriptor(raw)
}

func (d *vnextPersistentDevice) readContentPageLocked(dataPageIndex uint64) ([]byte, error) {
	offset, err := d.superblock.Geometry.contentOffset(dataPageIndex)
	if err != nil {
		return nil, err
	}
	raw := make([]byte, vnextContentPageSize)
	if err := vnextReadAtFull(d.storage, raw, offset); err != nil {
		return nil, err
	}
	return raw, nil
}

func (d *vnextPersistentDevice) checkUsableLocked() error {
	if d.poisoned != nil {
		return fmt.Errorf("VNext device is fail-closed after an ambiguous write: %w", d.poisoned)
	}
	return nil
}

func (d *vnextPersistentDevice) poisonLocked(err error) error {
	if err == nil {
		err = errors.New("unknown VNext persistent-device failure")
	}
	d.poisoned = err
	return err
}

func vnextReadSuperblockSlot(file io.ReaderAt, offset uint64) (vnextDeviceSuperblock, error) {
	data, err := vnextReadEnvelopeSlot(file, offset, vnextSuperblockSlotBytes, vnextDeviceMagic)
	if err != nil {
		return vnextDeviceSuperblock{}, err
	}
	return parseVNextDeviceSuperblock(data)
}

func vnextSelectSuperblock(
	first vnextDeviceSuperblock,
	firstErr error,
	second vnextDeviceSuperblock,
	secondErr error,
) (vnextDeviceSuperblock, error) {
	if firstErr != nil && secondErr != nil {
		return vnextDeviceSuperblock{}, fmt.Errorf(
			"neither VNext superblock is valid (A: %v; B: %v): %w",
			firstErr, secondErr, errVNextCorrupt)
	}
	if firstErr != nil {
		return second, nil
	}
	if secondErr != nil {
		return first, nil
	}
	if first.Sequence == second.Sequence && first != second {
		return vnextDeviceSuperblock{}, fmt.Errorf(
			"equal-sequence superblocks disagree: %w", errVNextCorrupt)
	}
	if second.Sequence > first.Sequence {
		return second, nil
	}
	return first, nil
}

func vnextReadAllocatorSlot(
	file io.ReaderAt,
	offset uint64,
	slotBytes uint64,
	superblock vnextDeviceSuperblock,
) (*vnextCheckpointAllocator, error) {
	data, err := vnextReadEnvelopeSlot(file, offset, slotBytes, vnextAllocatorMagic)
	if err != nil {
		return nil, err
	}
	return parseVNextAllocatorSnapshot(data, superblock)
}

func vnextSelectAllocator(
	first *vnextCheckpointAllocator,
	firstErr error,
	second *vnextCheckpointAllocator,
	secondErr error,
) (*vnextCheckpointAllocator, error) {
	if firstErr != nil && secondErr != nil {
		return nil, fmt.Errorf(
			"neither VNext allocator snapshot is valid (A: %v; B: %v): %w",
			firstErr, secondErr, errVNextCorrupt)
	}
	if firstErr != nil {
		return second, nil
	}
	if secondErr != nil {
		return first, nil
	}
	first.mu.Lock()
	firstSequence := first.snapshotSequence
	first.mu.Unlock()
	second.mu.Lock()
	secondSequence := second.snapshotSequence
	second.mu.Unlock()
	if firstSequence == secondSequence {
		firstBytes, _, firstMarshalErr := first.marshalNextSnapshot()
		secondBytes, _, secondMarshalErr := second.marshalNextSnapshot()
		if firstMarshalErr != nil || secondMarshalErr != nil || !bytes.Equal(firstBytes, secondBytes) {
			return nil, fmt.Errorf("equal-sequence allocator snapshots disagree: %w", errVNextCorrupt)
		}
	}
	if secondSequence > firstSequence {
		return second, nil
	}
	return first, nil
}

func vnextWriteCommittedEnvelopeSlot(
	file vnextSynchronizedWriterAt,
	offset uint64,
	slotBytes uint64,
	data []byte,
) error {
	if file == nil {
		return errors.New("slot file is nil")
	}
	if len(data) < int(vnextFormatHeaderSize) || uint64(len(data)) > slotBytes {
		return fmt.Errorf("envelope size %d does not fit slot %d", len(data), slotBytes)
	}
	invalidHeader := make([]byte, vnextFormatHeaderSize)
	if err := vnextWriteAtFull(file, invalidHeader, offset); err != nil {
		return err
	}
	if err := file.Sync(); err != nil {
		return err
	}
	payloadOffset, ok := vnextAdd(offset, uint64(vnextFormatHeaderSize))
	if !ok {
		return errors.New("slot payload offset overflow")
	}
	if err := vnextWriteAtFull(file, data[vnextFormatHeaderSize:], payloadOffset); err != nil {
		return err
	}
	if err := file.Sync(); err != nil {
		return err
	}
	// Writing the checksummed header last is the commit point. A torn header
	// cannot outrank the still-valid other A/B slot.
	if err := vnextWriteAtFull(file, data[:vnextFormatHeaderSize], offset); err != nil {
		return err
	}
	return file.Sync()
}

func vnextReadEnvelopeSlot(
	file io.ReaderAt,
	offset uint64,
	slotBytes uint64,
	expectedMagic [8]byte,
) ([]byte, error) {
	if slotBytes < uint64(vnextFormatHeaderSize) ||
		slotBytes > uint64(vnextFormatHeaderSize)+vnextMaxEnvelopePayload {
		return nil, fmt.Errorf("invalid envelope slot size %d", slotBytes)
	}
	header := make([]byte, vnextFormatHeaderSize)
	if err := vnextReadAtFull(file, header, offset); err != nil {
		return nil, err
	}
	var gotMagic [8]byte
	copy(gotMagic[:], header[:8])
	if gotMagic != expectedMagic {
		return nil, fmt.Errorf("slot magic %q does not match %q: %w", gotMagic, expectedMagic, errVNextWrongFormat)
	}
	payloadLength := binary.LittleEndian.Uint64(header[16:24])
	total, ok := vnextAdd(uint64(vnextFormatHeaderSize), payloadLength)
	if !ok || total > slotBytes || total > uint64(math.MaxInt) {
		return nil, fmt.Errorf("slot payload length %d is invalid: %w", payloadLength, errVNextCorrupt)
	}
	data := make([]byte, int(total))
	copy(data, header)
	if payloadLength != 0 {
		payloadOffset, _ := vnextAdd(offset, uint64(vnextFormatHeaderSize))
		if err := vnextReadAtFull(file, data[vnextFormatHeaderSize:], payloadOffset); err != nil {
			return nil, err
		}
	}
	// Validate now, before a caller interprets the payload-specific sequence.
	if _, err := vnextParseEnvelope(data, expectedMagic, vnextMaxEnvelopePayload); err != nil {
		return nil, err
	}
	return data, nil
}

func vnextZeroRange(file io.WriterAt, offset, length uint64) error {
	if length == 0 {
		return nil
	}
	zero := make([]byte, vnextMetadataZeroChunkBytes)
	var written uint64
	for written < length {
		chunk := uint64(len(zero))
		if remaining := length - written; remaining < chunk {
			chunk = remaining
		}
		writeOffset, ok := vnextAdd(offset, written)
		if !ok {
			return errors.New("zero range offset overflow")
		}
		if err := vnextWriteAtFull(file, zero[:chunk], writeOffset); err != nil {
			return err
		}
		written += chunk
	}
	return nil
}

func vnextWriteAtFull(file io.WriterAt, data []byte, offset uint64) error {
	if err := vnextValidateUnsignedStorageRange(
		uint64(math.MaxInt64), offset, len(data), "write"); err != nil {
		return err
	}
	for len(data) > 0 {
		count, err := file.WriteAt(data, int64(offset))
		if count > 0 {
			offset += uint64(count)
			data = data[count:]
		}
		if err != nil {
			return err
		}
		if count == 0 {
			return io.ErrShortWrite
		}
	}
	return nil
}

func vnextReadAtFull(file io.ReaderAt, data []byte, offset uint64) error {
	if err := vnextValidateUnsignedStorageRange(
		uint64(math.MaxInt64), offset, len(data), "read"); err != nil {
		return err
	}
	for len(data) > 0 {
		count, err := file.ReadAt(data, int64(offset))
		if count > 0 {
			offset += uint64(count)
			data = data[count:]
		}
		if err != nil {
			if err == io.EOF && len(data) == 0 {
				return nil
			}
			return err
		}
		if count == 0 {
			return io.ErrUnexpectedEOF
		}
	}
	return nil
}

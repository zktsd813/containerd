package trcxl007

import (
	"bytes"
	"errors"
	"fmt"
	"sort"
)

const reservedDescriptorIOBatchBytes = 64 << 10

var (
	// ErrDeviceMetadataDescriptorConflict means that a page selected by one
	// PREPARING allocation contains neither the canonical all-zero FREE
	// descriptor nor the byte-exact RESERVED descriptor derived from that
	// allocation. The conflict is detected during the read-only preflight, so
	// this operation performs no write or Sync before returning it.
	ErrDeviceMetadataDescriptorConflict = errors.New(
		"TRCXL007 persisted descriptor conflicts with Owner reservation")
)

// reservedDescriptorPersistenceRun is an internal, detached write plan. The
// Owner allocation record, rather than the caller-provided run list, is the
// source of every persisted descriptor byte.
type reservedDescriptorPersistenceRun struct {
	startDataPageIndex uint64
	pageCount          uint64
	descriptor         Descriptor
	descriptorWire     [PageDescriptorBytes]byte
	missingBitStart    uint64
}

// persistPreparingReservedDescriptors durably initializes this device's
// RESERVED descriptors for one exact PREPARING Owner allocation. It is
// intentionally package-private: a later Owner-group executor must supply the
// group authority and ordered PREPARING -> descriptor -> allocator protocol,
// especially for MEMBER devices that do not persist TROWN007 locally.
//
// The method changes descriptors only. It never writes content pages,
// allocator snapshots, superblocks, or Owner state. Every successful call has
// one Sync boundary regardless of whether recovery needed bounded writes.
func (device *DeviceMetadata) persistPreparingReservedDescriptors(
	record OwnerStateAllocationRecord,
	runs []OwnerReservedDescriptorRun,
) error {
	if device == nil || device.storage == nil {
		return fmt.Errorf("%w: opened device is nil", ErrDeviceMetadataStorage)
	}
	if device.reopenRequired {
		return ErrDeviceMetadataReopenRequired
	}
	if err := validateMetadataStorageSize(device.storage, device.geometry); err != nil {
		return err
	}

	prepared, totalPages, err := device.prepareReservedDescriptorPersistence(record, runs)
	if err != nil {
		return err
	}
	missingByteCount, ok := checkedAdd(totalPages, 7)
	if !ok || missingByteCount/8 > uint64(maxIntValue()) {
		return ownerAllocatorInputMismatchf(
			"device %q RESERVED missing-page bitmap length overflows",
			device.superblock.DeviceUUID)
	}
	missing := make([]byte, int(missingByteCount/8))
	readBuffer := make([]byte, reservedDescriptorIOBatchBytes)
	var missingPages uint64

	// Read every selected descriptor before the first mutation. A read failure
	// does not make A/B metadata ambiguous and therefore leaves this handle
	// reusable. A descriptor conflict is likewise a zero-write result.
	for runIndex := range prepared {
		run := &prepared[runIndex]
		for pageOffset := uint64(0); pageOffset < run.pageCount; {
			batchPages := run.pageCount - pageOffset
			if batchPages > uint64(reservedDescriptorIOBatchBytes/PageDescriptorBytes) {
				batchPages = uint64(reservedDescriptorIOBatchBytes / PageDescriptorBytes)
			}
			batchBytes := batchPages * uint64(PageDescriptorBytes)
			descriptorOffset, offsetErr := device.geometry.DescriptorOffset(
				run.startDataPageIndex + pageOffset)
			if offsetErr != nil {
				return ownerAllocatorInputMismatchf(
					"device %q descriptor offset: %v",
					device.superblock.DeviceUUID,
					offsetErr)
			}
			batch := readBuffer[:int(batchBytes)]
			if readErr := readMetadataExactAt(
				device.storage,
				device.geometry.DeviceBytes,
				batch,
				descriptorOffset); readErr != nil {
				return fmt.Errorf(
					"%w: preflight RESERVED descriptors on device %q at data page %d: %v",
					ErrDeviceMetadataStorage,
					device.superblock.DeviceUUID,
					run.startDataPageIndex+pageOffset,
					readErr)
			}

			for batchPage := uint64(0); batchPage < batchPages; batchPage++ {
				start := int(batchPage * uint64(PageDescriptorBytes))
				current := batch[start : start+PageDescriptorBytes]
				if allZero(current) {
					bit := run.missingBitStart + pageOffset + batchPage
					reservedDescriptorSetBit(missing, bit)
					missingPages++
					continue
				}
				if bytes.Equal(current, run.descriptorWire[:]) {
					continue
				}
				page := run.startDataPageIndex + pageOffset + batchPage
				return reservedDescriptorConflictf(current, page, run.descriptor)
			}
			pageOffset += batchPages
		}
	}

	if missingPages == 0 {
		// Exact bytes can still be visible only through volatile cache after a
		// previous Sync failure or crash. PREPARING has no independent durable
		// descriptor-commit marker, so every successful retry must establish a
		// fresh persistence boundary even when it needs no descriptor write.
		device.reopenRequired = true
		if syncErr := device.storage.Sync(); syncErr != nil {
			return fmt.Errorf(
				"%w: sync exact RESERVED descriptors on device %q: %v",
				ErrDeviceMetadataStorage,
				device.superblock.DeviceUUID,
				syncErr)
		}
		device.reopenRequired = false
		return nil
	}

	writeBuffer := make([]byte, reservedDescriptorIOBatchBytes)
	mutationStarted := false
	for runIndex := range prepared {
		run := &prepared[runIndex]
		for pageOffset := uint64(0); pageOffset < run.pageCount; {
			bit := run.missingBitStart + pageOffset
			if !reservedDescriptorBitSet(missing, bit) {
				pageOffset++
				continue
			}
			missingStart := pageOffset
			for pageOffset < run.pageCount &&
				reservedDescriptorBitSet(missing, run.missingBitStart+pageOffset) {
				pageOffset++
			}
			missingCount := pageOffset - missingStart
			for writtenPages := uint64(0); writtenPages < missingCount; {
				batchPages := missingCount - writtenPages
				if batchPages > uint64(reservedDescriptorIOBatchBytes/PageDescriptorBytes) {
					batchPages = uint64(reservedDescriptorIOBatchBytes / PageDescriptorBytes)
				}
				batchBytes := batchPages * uint64(PageDescriptorBytes)
				for batchPage := uint64(0); batchPage < batchPages; batchPage++ {
					start := int(batchPage * uint64(PageDescriptorBytes))
					copy(writeBuffer[start:start+PageDescriptorBytes], run.descriptorWire[:])
				}
				descriptorOffset, offsetErr := device.geometry.DescriptorOffset(
					run.startDataPageIndex + missingStart + writtenPages)
				if offsetErr != nil {
					return ownerAllocatorInputMismatchf(
						"device %q descriptor offset: %v",
						device.superblock.DeviceUUID,
						offsetErr)
				}
				// From the first attempted mutation onward, a write or Sync
				// failure can leave a mixture of FREE and exact RESERVED bytes.
				// Force a read-only reopen before recovery inspects that mixture.
				if !mutationStarted {
					device.reopenRequired = true
					mutationStarted = true
				}
				if writeErr := writeMetadataExactAt(
					device.storage,
					device.geometry.DeviceBytes,
					writeBuffer[:int(batchBytes)],
					descriptorOffset); writeErr != nil {
					return fmt.Errorf(
						"%w: write RESERVED descriptors on device %q at data page %d: %v",
						ErrDeviceMetadataStorage,
						device.superblock.DeviceUUID,
						run.startDataPageIndex+missingStart+writtenPages,
						writeErr)
				}
				writtenPages += batchPages
			}
		}
	}
	if !mutationStarted {
		return ownerAllocatorInputMismatchf(
			"device %q missing-page accounting selected no write",
			device.superblock.DeviceUUID)
	}
	if syncErr := device.storage.Sync(); syncErr != nil {
		return fmt.Errorf(
			"%w: sync RESERVED descriptors on device %q: %v",
			ErrDeviceMetadataStorage,
			device.superblock.DeviceUUID,
			syncErr)
	}
	device.reopenRequired = false
	return nil
}

func (device *DeviceMetadata) prepareReservedDescriptorPersistence(
	record OwnerStateAllocationRecord,
	runs []OwnerReservedDescriptorRun,
) ([]reservedDescriptorPersistenceRun, uint64, error) {
	if err := device.geometry.Validate(); err != nil {
		return nil, 0, err
	}
	if device.superblock.Geometry != device.geometry {
		return nil, 0, fmt.Errorf(
			"%w: opened geometry differs from active superblock",
			ErrDeviceMetadataGeometryMismatch)
	}
	if err := validateSuperblockBootstrap(device.superblock, device.bootstrap); err != nil {
		return nil, 0, err
	}
	if record.State != OwnerAllocationPreparing {
		return nil, 0, ownerAllocatorInputMismatchf(
			"allocation record %d state %d is not PREPARING",
			record.AllocationRecordID,
			record.State)
	}
	deviceByUUID := make(map[string]OwnerStateDevice, len(device.bootstrap.Devices))
	for _, member := range device.bootstrap.Devices {
		deviceByUUID[member.DeviceUUID] = member
	}
	if err := validateOwnerStateRecord(record, deviceByUUID); err != nil {
		return nil, 0, ownerAllocatorInputMismatchf(
			"PREPARING allocation record: %v", err)
	}

	switch device.superblock.OwnerGroupRole {
	case OwnerGroupRoleAnchor:
		if !device.ownerStatePresent {
			return nil, 0, fmt.Errorf(
				"%w: ANCHOR has no active Owner state",
				ErrDeviceMetadataRoleMismatch)
		}
		if err := device.ownerState.CrossCheckBootstrap(device.bootstrap); err != nil {
			return nil, 0, ownerAllocatorInputMismatchf(
				"active Owner state: %v", err)
		}
		activeRecord, found := reservedDescriptorOwnerRecord(
			device.ownerState, record.AllocationRecordID)
		if !found || !reservedDescriptorRecordsEqual(activeRecord, record) {
			return nil, 0, ownerAllocatorInputMismatchf(
				"ANCHOR active Owner state does not contain exact PREPARING record %d",
				record.AllocationRecordID)
		}
	case OwnerGroupRoleMember:
		if device.ownerStatePresent {
			return nil, 0, fmt.Errorf(
				"%w: MEMBER unexpectedly has active Owner state",
				ErrDeviceMetadataRoleMismatch)
		}
	default:
		return nil, 0, fmt.Errorf(
			"%w: unsupported role %d",
			ErrDeviceMetadataRoleMismatch,
			device.superblock.OwnerGroupRole)
	}

	localUUID := device.superblock.DeviceUUID
	var fragment *OwnerStateDeviceFragment
	for index := range record.Fragments {
		if record.Fragments[index].DeviceUUID != localUUID {
			continue
		}
		if fragment != nil {
			return nil, 0, ownerAllocatorInputMismatchf(
				"PREPARING record repeats device fragment %q", localUUID)
		}
		fragment = &record.Fragments[index]
	}
	if fragment == nil {
		return nil, 0, ownerAllocatorInputMismatchf(
			"PREPARING record has no fragment for device %q", localUUID)
	}
	if fragment.DeviceOwnerEpoch != device.superblock.OwnerEpoch {
		return nil, 0, ownerAllocatorInputMismatchf(
			"device %q fragment Owner epoch %d differs from opened epoch %d",
			localUUID,
			fragment.DeviceOwnerEpoch,
			device.superblock.OwnerEpoch)
	}

	placed := make([]ownerAllocatorPlacedRun, len(fragment.Extents))
	for index, extent := range fragment.Extents {
		placed[index] = ownerAllocatorPlacedRun{
			DeviceUUID:         localUUID,
			StartDataPageIndex: extent.StartDataPageIndex,
			LogicalPageStart:   extent.LogicalPageStart,
			PageCount:          extent.PageCount,
		}
	}
	expectedRuns, err := ownerReserveDescriptorRuns(
		record.ContentDemands,
		placed,
		record.AllocationRecordID,
		record.ReservationTransactionSequence)
	if err != nil {
		return nil, 0, ownerAllocatorInputMismatchf(
			"derive RESERVED descriptors for device %q: %v", localUUID, err)
	}
	if len(runs) != len(expectedRuns) {
		return nil, 0, ownerAllocatorInputMismatchf(
			"device %q RESERVED run count %d does not equal derived count %d",
			localUUID,
			len(runs),
			len(expectedRuns))
	}
	for index := range expectedRuns {
		if runs[index] != expectedRuns[index] {
			return nil, 0, ownerAllocatorInputMismatchf(
				"device %q RESERVED run %d differs from PREPARING record",
				localUUID,
				index)
		}
	}

	// OpenDeviceMetadata and commitAllocatorSnapshot already validate the full
	// canonical bitmap and its popcount. Repeating AllocatorSnapshot.CrossCheck
	// here would rescan every device page for an operation that selects only P
	// pages. Recheck the cached, unexported scalar/binding envelope in O(1), then
	// inspect only the selected P bitmap bits below.
	expectedBitmapBytes, bitmapLengthErr := device.geometry.AllocationBitmapBytes()
	if bitmapLengthErr != nil {
		return nil, 0, ownerAllocatorInputMismatchf(
			"device %q allocation bitmap geometry: %v", localUUID, bitmapLengthErr)
	}
	if device.allocator.DeviceBindingSHA256 != device.superblock.DeviceBindingSHA256() ||
		device.allocator.OwnerGroupIdentitySHA256 != device.superblock.OwnerGroupIdentitySHA256() ||
		device.allocator.OwnerEpoch != device.superblock.OwnerEpoch ||
		device.allocator.DataPageCount != device.geometry.DataPageCount ||
		device.allocator.AllocatedPageCount > device.allocator.DataPageCount ||
		device.allocator.BitmapByteLength != expectedBitmapBytes ||
		uint64(len(device.allocator.allocationBitmap)) != expectedBitmapBytes {
		return nil, 0, ownerAllocatorInputMismatchf(
			"device %q cached allocator scalar/binding envelope differs from opened metadata",
			localUUID)
	}
	if err := allocatorSnapshotValidateUnusedHighBits(
		device.allocator.allocationBitmap,
		device.allocator.DataPageCount); err != nil {
		return nil, 0, ownerAllocatorInputMismatchf(
			"device %q cached allocator final bitmap byte: %v", localUUID, err)
	}
	allocatorLength, lengthOK := checkedAdd(
		AllocatorSnapshotFixedBytes, device.allocator.BitmapByteLength)
	if !lengthOK ||
		device.allocator.SnapshotSequence !=
			device.superblock.ActiveAllocatorSnapshotSequence ||
		allocatorLength != device.superblock.ActiveAllocatorSnapshotLength {
		return nil, 0, ownerAllocatorInputMismatchf(
			"device %q active allocator sequence/length differs from selected superblock",
			localUUID)
	}
	beforeTargetSequence, sequenceOK := checkedAdd(device.allocator.SnapshotSequence, 1)
	beforeApply := sequenceOK &&
		beforeTargetSequence == fragment.TargetAllocatorSnapshotSequence &&
		device.allocator.AppliedOwnerTransactionSequence < record.ReservationTransactionSequence
	afterApply := device.allocator.SnapshotSequence == fragment.TargetAllocatorSnapshotSequence &&
		device.allocator.AppliedOwnerTransactionSequence == record.ReservationTransactionSequence
	if !beforeApply && !afterApply {
		return nil, 0, fmt.Errorf(
			"%w: device %q allocator sequence/applied transaction %d/%d is neither before nor after target %d/%d",
			ErrDeviceMetadataSequence,
			localUUID,
			device.allocator.SnapshotSequence,
			device.allocator.AppliedOwnerTransactionSequence,
			fragment.TargetAllocatorSnapshotSequence,
			record.ReservationTransactionSequence)
	}
	for _, extent := range fragment.Extents {
		end, ok := checkedAdd(extent.StartDataPageIndex, extent.PageCount)
		if !ok || end > device.allocator.DataPageCount {
			return nil, 0, ownerAllocatorInputMismatchf(
				"device %q fragment extent exceeds active allocator", localUUID)
		}
		for page := extent.StartDataPageIndex; page < end; page++ {
			unavailable, pageErr := device.allocator.PageUnavailable(page)
			if pageErr != nil {
				return nil, 0, ownerAllocatorInputMismatchf(
					"device %q allocator page %d: %v", localUUID, page, pageErr)
			}
			if unavailable != afterApply {
				want := "FREE before allocator apply"
				if afterApply {
					want = "ALLOCATED after allocator apply"
				}
				return nil, 0, fmt.Errorf(
					"%w: device %q data page %d is not %s",
					ErrDeviceMetadataSequence,
					localUUID,
					page,
					want)
			}
		}
	}

	prepared := make([]reservedDescriptorPersistenceRun, len(expectedRuns))
	for index, expected := range expectedRuns {
		wire, marshalErr := expected.Descriptor.MarshalBinary()
		if marshalErr != nil {
			return nil, 0, ownerAllocatorInputMismatchf(
				"device %q RESERVED run %d descriptor: %v",
				localUUID,
				index,
				marshalErr)
		}
		prepared[index] = reservedDescriptorPersistenceRun{
			startDataPageIndex: expected.StartDataPageIndex,
			pageCount:          expected.PageCount,
			descriptor:         expected.Descriptor,
		}
		copy(prepared[index].descriptorWire[:], wire)
	}
	// Physical ordering keeps bounded I/O deterministic without changing the
	// caller's required checkpoint-logical run order.
	sort.Slice(prepared, func(left, right int) bool {
		return prepared[left].startDataPageIndex < prepared[right].startDataPageIndex
	})
	var totalPages uint64
	for index := range prepared {
		prepared[index].missingBitStart = totalPages
		var ok bool
		totalPages, ok = checkedAdd(totalPages, prepared[index].pageCount)
		if !ok || totalPages > device.geometry.DataPageCount {
			return nil, 0, ownerAllocatorInputMismatchf(
				"device %q RESERVED page count overflows", localUUID)
		}
	}
	if totalPages == 0 {
		return nil, 0, ownerAllocatorInputMismatchf(
			"device %q PREPARING fragment selects no pages", localUUID)
	}
	return prepared, totalPages, nil
}

func reservedDescriptorOwnerRecord(
	state OwnerStateSnapshot,
	allocationRecordID uint64,
) (OwnerStateAllocationRecord, bool) {
	for _, candidate := range state.Records() {
		if candidate.AllocationRecordID == allocationRecordID {
			return candidate, true
		}
	}
	return OwnerStateAllocationRecord{}, false
}

func reservedDescriptorRecordsEqual(
	left, right OwnerStateAllocationRecord,
) bool {
	leftDemands, rightDemands := left.ContentDemands, right.ContentDemands
	leftFragments, rightFragments := left.Fragments, right.Fragments
	if !reservedDescriptorRecordScalarsEqual(left, right) ||
		len(leftDemands) != len(rightDemands) ||
		len(leftFragments) != len(rightFragments) {
		return false
	}
	for index := range leftDemands {
		if leftDemands[index] != rightDemands[index] {
			return false
		}
	}
	for index := range leftFragments {
		leftExtents := leftFragments[index].Extents
		rightExtents := rightFragments[index].Extents
		leftFragment := leftFragments[index]
		rightFragment := rightFragments[index]
		if leftFragment.DeviceUUID != rightFragment.DeviceUUID ||
			leftFragment.DeviceOwnerEpoch != rightFragment.DeviceOwnerEpoch ||
			leftFragment.TargetAllocatorSnapshotSequence !=
				rightFragment.TargetAllocatorSnapshotSequence ||
			len(leftExtents) != len(rightExtents) {
			return false
		}
		for extentIndex := range leftExtents {
			if leftExtents[extentIndex] != rightExtents[extentIndex] {
				return false
			}
		}
	}
	return true
}

func reservedDescriptorRecordScalarsEqual(
	left, right OwnerStateAllocationRecord,
) bool {
	return left.AllocationRecordID == right.AllocationRecordID &&
		left.ReservationTransactionSequence == right.ReservationTransactionSequence &&
		left.OwnerTransactionSequence == right.OwnerTransactionSequence &&
		left.State == right.State &&
		left.RequestID == right.RequestID &&
		left.CheckpointID == right.CheckpointID &&
		left.ProducerID == right.ProducerID &&
		left.DedupDomainID == right.DedupDomainID &&
		left.SharingPolicyID == right.SharingPolicyID &&
		left.RequestSHA256 == right.RequestSHA256 &&
		left.TotalDemandPages == right.TotalDemandPages &&
		left.MaxExtents == right.MaxExtents &&
		left.AuthorityEvidence == right.AuthorityEvidence
}

func reservedDescriptorConflictf(
	wire []byte,
	dataPageIndex uint64,
	want Descriptor,
) error {
	current, err := ParseDescriptor(wire)
	if err != nil {
		return fmt.Errorf(
			"%w: data page %d contains a noncanonical descriptor: %v",
			ErrDeviceMetadataDescriptorConflict,
			dataPageIndex,
			err)
	}
	return fmt.Errorf(
		"%w: data page %d has state/allocation/object/transaction/kind %d/%d/%d/%d/%d, expected %d/%d/%d/%d/%d",
		ErrDeviceMetadataDescriptorConflict,
		dataPageIndex,
		current.State,
		current.AllocationRecordID,
		current.OriginObjectID,
		current.OwnerTransactionSeq,
		current.ContentKind,
		want.State,
		want.AllocationRecordID,
		want.OriginObjectID,
		want.OwnerTransactionSeq,
		want.ContentKind)
}

func reservedDescriptorSetBit(bitmap []byte, bit uint64) {
	bitmap[bit/8] |= byte(1) << uint(bit%8)
}

func reservedDescriptorBitSet(bitmap []byte, bit uint64) bool {
	return bitmap[bit/8]&(byte(1)<<uint(bit%8)) != 0
}

package trcxl007

import (
	"bytes"
	"errors"
	"fmt"
	"sort"
)

const ownerCancelIOBatchBytes = 64 << 10

var (
	// ErrOwnerCancelDescriptorDispositionChanged means that descriptor bytes no
	// longer match the checkpoint-wide disposition selected by the executor.
	// Before an allocator applies the CANCELING transaction, recovery may scan
	// every DAX again and conservatively select Quarantine. After that applied
	// transaction becomes a durable disposition lock, the same change is an
	// irreconcilable contradiction.
	ErrOwnerCancelDescriptorDispositionChanged = errors.New(
		"TRCXL007 GRANTED cancellation descriptor disposition changed after global preflight")
	// ErrOwnerCancelContentNotZero means a complete post-Sync read-back found a
	// nonzero byte in capacity that would otherwise be returned to the free pool.
	// It must never be treated as permission to free the page.
	ErrOwnerCancelContentNotZero = errors.New(
		"TRCXL007 GRANTED cancellation content sanitization is incomplete")
)

type ownerCancelDescriptorClass uint8

const (
	ownerCancelDescriptorFree ownerCancelDescriptorClass = iota + 1
	ownerCancelDescriptorReserved
	ownerCancelDescriptorQuarantined
	ownerCancelDescriptorConflict
)

type ownerCancelDescriptorObservation struct {
	totalPages       uint64
	freePages        uint64
	reservedPages    uint64
	quarantinedPages uint64
	conflictPages    uint64
}

func (observation ownerCancelDescriptorObservation) requiresQuarantine() bool {
	return observation.quarantinedPages != 0 || observation.conflictPages != 0
}

func (observation ownerCancelDescriptorObservation) cleanDispositionComplete() bool {
	return observation.totalPages != 0 &&
		observation.freePages == observation.totalPages
}

func (observation ownerCancelDescriptorObservation) quarantineDispositionComplete() bool {
	return observation.totalPages != 0 &&
		observation.freePages == 0 && observation.reservedPages == 0 &&
		observation.quarantinedPages+observation.conflictPages == observation.totalPages
}

type ownerCancelPersistenceRun struct {
	startDataPageIndex uint64
	pageCount          uint64
	reservedWire       [PageDescriptorBytes]byte
	quarantinedWire    [PageDescriptorBytes]byte
	pageBitStart       uint64
}

// preflightOwnerCancelContent proves that every exact capacity-page write is
// representable before CANCELING is the first durable mutation. It performs no
// content read or write. DeviceMetadataStorage.Sync remains an abstract storage
// durability boundary; this package makes no physical non-coherent CXL claim.
func (device *DeviceMetadata) preflightOwnerCancelContent(
	authorityRecord OwnerStateAllocationRecord,
	cancelingTransaction uint64,
) error {
	prepared, _, err := device.prepareOwnerCancelPersistence(
		authorityRecord,
		cancelingTransaction)
	if err != nil {
		return err
	}
	for _, run := range prepared {
		for pageOffset := uint64(0); pageOffset < run.pageCount; {
			batchPages := ownerCancelBatchPages(run.pageCount - pageOffset)
			offset, offsetErr := device.geometry.ContentOffset(
				run.startDataPageIndex + pageOffset)
			if offsetErr != nil {
				return offsetErr
			}
			if _, offsetErr = metadataIOPosition(
				device.geometry.DeviceBytes,
				offset,
				batchPages*uint64(ContentPageBytes)); offsetErr != nil {
				return offsetErr
			}
			pageOffset += batchPages
		}
	}
	return nil
}

// persistCancelingContentZeroes overwrites every capacity page selected by one
// CANCELING record and completes one device Sync. The executor invokes it for
// every affected DAX before starting any read-back or descriptor mutation, so
// successful calls form an all-DAX sanitization durability barrier.
func (device *DeviceMetadata) persistCancelingContentZeroes(
	cancelingRecord OwnerStateAllocationRecord,
) error {
	if cancelingRecord.State != OwnerAllocationCanceling {
		return ownerCancelPersistenceMismatchf(
			"content zeroing requires CANCELING, found state %d",
			cancelingRecord.State)
	}
	prepared, _, err := device.prepareOwnerCancelPersistence(
		cancelingRecord,
		cancelingRecord.OwnerTransactionSequence)
	if err != nil {
		return err
	}
	zeroes := make([]byte, ownerCancelIOBatchBytes)
	device.reopenRequired = true
	for _, run := range prepared {
		for pageOffset := uint64(0); pageOffset < run.pageCount; {
			batchPages := ownerCancelBatchPages(run.pageCount - pageOffset)
			batchBytes := batchPages * uint64(ContentPageBytes)
			offset, offsetErr := device.geometry.ContentOffset(
				run.startDataPageIndex + pageOffset)
			if offsetErr != nil {
				return offsetErr
			}
			if writeErr := writeMetadataExactAt(
				device.storage,
				device.geometry.DeviceBytes,
				zeroes[:int(batchBytes)],
				offset); writeErr != nil {
				return fmt.Errorf(
					"%w: zero cancellation content on device %q at data page %d: %v",
					ErrDeviceMetadataStorage,
					device.superblock.DeviceUUID,
					run.startDataPageIndex+pageOffset,
					writeErr)
			}
			pageOffset += batchPages
		}
	}
	if err := device.storage.Sync(); err != nil {
		return fmt.Errorf(
			"%w: sync cancellation content on device %q: %v",
			ErrDeviceMetadataStorage,
			device.superblock.DeviceUUID,
			err)
	}
	device.reopenRequired = false
	return nil
}

// verifyCancelingContentZeroes reads every capacity byte after the executor has
// crossed the all-DAX content Sync barrier. Any nonzero byte fails closed.
func (device *DeviceMetadata) verifyCancelingContentZeroes(
	cancelingRecord OwnerStateAllocationRecord,
) error {
	if cancelingRecord.State != OwnerAllocationCanceling {
		return ownerCancelPersistenceMismatchf(
			"content verification requires CANCELING, found state %d",
			cancelingRecord.State)
	}
	prepared, _, err := device.prepareOwnerCancelPersistence(
		cancelingRecord,
		cancelingRecord.OwnerTransactionSequence)
	if err != nil {
		return err
	}
	buffer := make([]byte, ownerCancelIOBatchBytes)
	nonzero := false
	for _, run := range prepared {
		for pageOffset := uint64(0); pageOffset < run.pageCount; {
			batchPages := ownerCancelBatchPages(run.pageCount - pageOffset)
			batchBytes := batchPages * uint64(ContentPageBytes)
			offset, offsetErr := device.geometry.ContentOffset(
				run.startDataPageIndex + pageOffset)
			if offsetErr != nil {
				return offsetErr
			}
			batch := buffer[:int(batchBytes)]
			if readErr := readMetadataExactAt(
				device.storage,
				device.geometry.DeviceBytes,
				batch,
				offset); readErr != nil {
				device.reopenRequired = true
				return fmt.Errorf(
					"%w: verify cancellation content on device %q at data page %d: %v",
					ErrDeviceMetadataStorage,
					device.superblock.DeviceUUID,
					run.startDataPageIndex+pageOffset,
					readErr)
			}
			if !allZero(batch) {
				nonzero = true
			}
			pageOffset += batchPages
		}
	}
	if nonzero {
		return fmt.Errorf(
			"%w: device %q retains nonzero bytes in cancellation capacity",
			ErrOwnerCancelContentNotZero,
			device.superblock.DeviceUUID)
	}
	return nil
}

// inspectOwnerCancelDescriptors is read-only. The executor observes every
// affected DAX before selecting one checkpoint-wide disposition.
func (device *DeviceMetadata) inspectOwnerCancelDescriptors(
	authorityRecord OwnerStateAllocationRecord,
	cancelingTransaction uint64,
) (ownerCancelDescriptorObservation, error) {
	prepared, _, err := device.prepareOwnerCancelPersistence(
		authorityRecord,
		cancelingTransaction)
	if err != nil {
		return ownerCancelDescriptorObservation{}, err
	}
	observation, _, err := device.scanOwnerCancelDescriptors(
		prepared,
		0,
		authorityRecord.State == OwnerAllocationCanceling)
	return observation, err
}

// persistCancelingDescriptorDisposition changes descriptors only. Clean writes
// canonical FREE over exact RESERVED(R); Quarantine writes exact Q(C) over
// canonical FREE or exact RESERVED(R). Every other raw descriptor is preserved.
func (device *DeviceMetadata) persistCancelingDescriptorDisposition(
	cancelingRecord OwnerStateAllocationRecord,
	disposition OwnerCancelDisposition,
	requireComplete bool,
) error {
	if disposition != OwnerCancelClean && disposition != OwnerCancelQuarantine {
		return fmt.Errorf(
			"%w: unsupported cancellation disposition %d",
			ErrOwnerCancelDescriptorDispositionChanged,
			disposition)
	}
	if cancelingRecord.State != OwnerAllocationCanceling {
		return ownerCancelPersistenceMismatchf(
			"descriptor disposition requires CANCELING, found state %d",
			cancelingRecord.State)
	}
	prepared, totalPages, err := device.prepareOwnerCancelPersistence(
		cancelingRecord,
		cancelingRecord.OwnerTransactionSequence)
	if err != nil {
		return err
	}
	bitmapBytes, ok := checkedAdd(totalPages, 7)
	if !ok || bitmapBytes/8 > uint64(maxIntValue()) {
		return ownerCancelPersistenceMismatchf(
			"device %q cancellation descriptor bitmap length overflows",
			device.superblock.DeviceUUID)
	}
	observation, writePages, err := device.scanOwnerCancelDescriptors(
		prepared,
		disposition,
		true)
	if err != nil {
		return err
	}
	if disposition == OwnerCancelClean && observation.requiresQuarantine() {
		return fmt.Errorf(
			"%w: clean cancellation observed quarantine/conflict descriptors",
			ErrOwnerCancelDescriptorDispositionChanged)
	}
	if requireComplete {
		complete := observation.cleanDispositionComplete()
		if disposition == OwnerCancelQuarantine {
			complete = observation.quarantineDispositionComplete()
		}
		if !complete {
			return fmt.Errorf(
				"%w: allocator-applied disposition %d is not descriptor-complete on device %q",
				ErrOwnerCancelDescriptorDispositionChanged,
				disposition,
				device.superblock.DeviceUUID)
		}
	}
	if uint64(len(writePages)) != bitmapBytes/8 {
		return ownerCancelPersistenceMismatchf(
			"device %q cancellation descriptor write bitmap has wrong length",
			device.superblock.DeviceUUID)
	}

	zeroes := make([]byte, ownerCancelIOBatchBytes)
	writeBuffer := make([]byte, ownerCancelIOBatchBytes)
	for _, run := range prepared {
		for pageOffset := uint64(0); pageOffset < run.pageCount; {
			bit := run.pageBitStart + pageOffset
			if !reservedDescriptorBitSet(writePages, bit) {
				pageOffset++
				continue
			}
			writeStart := pageOffset
			for pageOffset < run.pageCount &&
				reservedDescriptorBitSet(writePages, run.pageBitStart+pageOffset) {
				pageOffset++
			}
			writeCount := pageOffset - writeStart
			for writtenPages := uint64(0); writtenPages < writeCount; {
				batchPages := ownerCancelDescriptorBatchPages(writeCount - writtenPages)
				batchBytes := batchPages * uint64(PageDescriptorBytes)
				var exact []byte
				if disposition == OwnerCancelClean {
					exact = zeroes[:int(batchBytes)]
				} else {
					for batchPage := uint64(0); batchPage < batchPages; batchPage++ {
						start := int(batchPage * uint64(PageDescriptorBytes))
						copy(
							writeBuffer[start:start+PageDescriptorBytes],
							run.quarantinedWire[:])
					}
					exact = writeBuffer[:int(batchBytes)]
				}
				offset, offsetErr := device.geometry.DescriptorOffset(
					run.startDataPageIndex + writeStart + writtenPages)
				if offsetErr != nil {
					return offsetErr
				}
				device.reopenRequired = true
				if writeErr := writeMetadataExactAt(
					device.storage,
					device.geometry.DeviceBytes,
					exact,
					offset); writeErr != nil {
					return fmt.Errorf(
						"%w: write cancellation descriptors on device %q at data page %d: %v",
						ErrDeviceMetadataStorage,
						device.superblock.DeviceUUID,
						run.startDataPageIndex+writeStart+writtenPages,
						writeErr)
				}
				writtenPages += batchPages
			}
		}
	}
	device.reopenRequired = true
	if err := device.storage.Sync(); err != nil {
		return fmt.Errorf(
			"%w: sync cancellation descriptors on device %q: %v",
			ErrDeviceMetadataStorage,
			device.superblock.DeviceUUID,
			err)
	}
	device.reopenRequired = false
	return nil
}

func (device *DeviceMetadata) prepareOwnerCancelPersistence(
	authorityRecord OwnerStateAllocationRecord,
	cancelingTransaction uint64,
) ([]ownerCancelPersistenceRun, uint64, error) {
	if device == nil || device.storage == nil {
		return nil, 0, fmt.Errorf("%w: opened device is nil", ErrDeviceMetadataStorage)
	}
	if device.reopenRequired {
		return nil, 0, ErrDeviceMetadataReopenRequired
	}
	if err := validateMetadataStorageSize(device.storage, device.geometry); err != nil {
		return nil, 0, err
	}
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
	if cancelingTransaction == 0 {
		return nil, 0, ownerCancelPersistenceMismatchf("cancellation transaction is zero")
	}

	grantedRecord := cloneOwnerStateRecord(authorityRecord)
	wantGrant, grantOK := checkedAdd(authorityRecord.ReservationTransactionSequence, 1)
	wantMinimumCancel, cancelOK := checkedAdd(authorityRecord.ReservationTransactionSequence, 2)
	switch authorityRecord.State {
	case OwnerAllocationGranted:
		if !grantOK || authorityRecord.OwnerTransactionSequence != wantGrant ||
			!cancelOK || cancelingTransaction < wantMinimumCancel {
			return nil, 0, ownerCancelPersistenceMismatchf(
				"GRANTED transaction %d/reservation %d cannot authorize cancellation %d",
				authorityRecord.OwnerTransactionSequence,
				authorityRecord.ReservationTransactionSequence,
				cancelingTransaction)
		}
	case OwnerAllocationCanceling:
		if authorityRecord.OwnerTransactionSequence != cancelingTransaction ||
			!cancelOK || cancelingTransaction < wantMinimumCancel || !grantOK {
			return nil, 0, ownerCancelPersistenceMismatchf(
				"CANCELING transaction %d is invalid for reservation %d",
				cancelingTransaction,
				authorityRecord.ReservationTransactionSequence)
		}
		grantedRecord.State = OwnerAllocationGranted
		grantedRecord.OwnerTransactionSequence = wantGrant
	default:
		return nil, 0, ownerCancelPersistenceMismatchf(
			"allocation %d state %d is neither GRANTED nor CANCELING",
			authorityRecord.AllocationRecordID,
			authorityRecord.State)
	}

	deviceByUUID := make(map[string]OwnerStateDevice, len(device.bootstrap.Devices))
	for _, member := range device.bootstrap.Devices {
		deviceByUUID[member.DeviceUUID] = member
	}
	if err := validateOwnerStateRecord(authorityRecord, deviceByUUID); err != nil {
		return nil, 0, ownerCancelPersistenceMismatchf(
			"cancellation authority record: %v", err)
	}
	if err := validateOwnerStateRecord(grantedRecord, deviceByUUID); err != nil {
		return nil, 0, ownerCancelPersistenceMismatchf(
			"derived GRANTED record: %v", err)
	}

	switch device.superblock.OwnerGroupRole {
	case OwnerGroupRoleAnchor:
		if !device.ownerStatePresent {
			return nil, 0, fmt.Errorf(
				"%w: ANCHOR has no active Owner state",
				ErrDeviceMetadataRoleMismatch)
		}
		active, found := reservedDescriptorOwnerRecord(
			device.ownerState,
			authorityRecord.AllocationRecordID)
		if !found || !reservedDescriptorRecordsEqual(active, authorityRecord) {
			return nil, 0, ownerCancelPersistenceMismatchf(
				"ANCHOR active Owner state does not contain exact cancellation authority record %d",
				authorityRecord.AllocationRecordID)
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

	allRuns, err := ownerReserveDescriptorsFromRecord(grantedRecord)
	if err != nil {
		return nil, 0, err
	}
	localUUID := device.superblock.DeviceUUID
	prepared := make([]ownerCancelPersistenceRun, 0, len(allRuns))
	for _, run := range allRuns {
		if run.DeviceUUID != localUUID {
			continue
		}
		reservedWire, marshalErr := run.Descriptor.MarshalBinary()
		if marshalErr != nil {
			return nil, 0, marshalErr
		}
		quarantined := run.Descriptor
		quarantined.State = DescriptorQuarantined
		quarantined.OwnerTransactionSeq = cancelingTransaction
		quarantinedWire, marshalErr := quarantined.MarshalBinary()
		if marshalErr != nil {
			return nil, 0, marshalErr
		}
		entry := ownerCancelPersistenceRun{
			startDataPageIndex: run.StartDataPageIndex,
			pageCount:          run.PageCount,
		}
		copy(entry.reservedWire[:], reservedWire)
		copy(entry.quarantinedWire[:], quarantinedWire)
		prepared = append(prepared, entry)
	}
	if len(prepared) == 0 {
		return nil, 0, ownerCancelPersistenceMismatchf(
			"cancellation record has no descriptor run for device %q", localUUID)
	}
	sort.Slice(prepared, func(left, right int) bool {
		return prepared[left].startDataPageIndex < prepared[right].startDataPageIndex
	})
	var totalPages uint64
	for index := range prepared {
		prepared[index].pageBitStart = totalPages
		var ok bool
		totalPages, ok = checkedAdd(totalPages, prepared[index].pageCount)
		if !ok || totalPages > device.geometry.DataPageCount {
			return nil, 0, ownerCancelPersistenceMismatchf(
				"device %q cancellation page count overflows", localUUID)
		}
	}
	return prepared, totalPages, nil
}

func (device *DeviceMetadata) scanOwnerCancelDescriptors(
	prepared []ownerCancelPersistenceRun,
	disposition OwnerCancelDisposition,
	latchReadFailure bool,
) (ownerCancelDescriptorObservation, []byte, error) {
	var totalPages uint64
	for _, run := range prepared {
		var ok bool
		totalPages, ok = checkedAdd(totalPages, run.pageCount)
		if !ok {
			return ownerCancelDescriptorObservation{}, nil,
				ownerCancelPersistenceMismatchf("cancellation descriptor page count overflows")
		}
	}
	bitmapBytes, ok := checkedAdd(totalPages, 7)
	if !ok || bitmapBytes/8 > uint64(maxIntValue()) {
		return ownerCancelDescriptorObservation{}, nil,
			ownerCancelPersistenceMismatchf("cancellation descriptor bitmap length overflows")
	}
	writes := make([]byte, int(bitmapBytes/8))
	buffer := make([]byte, ownerCancelIOBatchBytes)
	observation := ownerCancelDescriptorObservation{totalPages: totalPages}
	for _, run := range prepared {
		for pageOffset := uint64(0); pageOffset < run.pageCount; {
			batchPages := ownerCancelDescriptorBatchPages(run.pageCount - pageOffset)
			batchBytes := batchPages * uint64(PageDescriptorBytes)
			offset, err := device.geometry.DescriptorOffset(
				run.startDataPageIndex + pageOffset)
			if err != nil {
				return ownerCancelDescriptorObservation{}, nil, err
			}
			batch := buffer[:int(batchBytes)]
			if err := readMetadataExactAt(
				device.storage,
				device.geometry.DeviceBytes,
				batch,
				offset); err != nil {
				if latchReadFailure {
					device.reopenRequired = true
				}
				return ownerCancelDescriptorObservation{}, nil, fmt.Errorf(
					"%w: read cancellation descriptors on device %q at data page %d: %v",
					ErrDeviceMetadataStorage,
					device.superblock.DeviceUUID,
					run.startDataPageIndex+pageOffset,
					err)
			}
			for batchPage := uint64(0); batchPage < batchPages; batchPage++ {
				start := int(batchPage * uint64(PageDescriptorBytes))
				wire := batch[start : start+PageDescriptorBytes]
				class := classifyOwnerCancelDescriptor(
					wire,
					run.reservedWire[:],
					run.quarantinedWire[:])
				switch class {
				case ownerCancelDescriptorFree:
					observation.freePages++
				case ownerCancelDescriptorReserved:
					observation.reservedPages++
				case ownerCancelDescriptorQuarantined:
					observation.quarantinedPages++
				case ownerCancelDescriptorConflict:
					observation.conflictPages++
				default:
					return ownerCancelDescriptorObservation{}, nil,
						ownerCancelPersistenceMismatchf(
							"unknown cancellation descriptor class %d", class)
				}
				bit := run.pageBitStart + pageOffset + batchPage
				switch disposition {
				case 0:
					// Read-only observation.
				case OwnerCancelClean:
					if class == ownerCancelDescriptorQuarantined ||
						class == ownerCancelDescriptorConflict {
						return ownerCancelDescriptorObservation{}, nil, fmt.Errorf(
							"%w: device %q data page %d requires quarantine",
							ErrOwnerCancelDescriptorDispositionChanged,
							device.superblock.DeviceUUID,
							run.startDataPageIndex+pageOffset+batchPage)
					}
					if class == ownerCancelDescriptorReserved {
						reservedDescriptorSetBit(writes, bit)
					}
				case OwnerCancelQuarantine:
					if class == ownerCancelDescriptorFree ||
						class == ownerCancelDescriptorReserved {
						reservedDescriptorSetBit(writes, bit)
					}
				default:
					return ownerCancelDescriptorObservation{}, nil, fmt.Errorf(
						"%w: unsupported cancellation disposition %d",
						ErrOwnerCancelDescriptorDispositionChanged,
						disposition)
				}
			}
			pageOffset += batchPages
		}
	}
	return observation, writes, nil
}

func classifyOwnerCancelDescriptor(
	wire []byte,
	reservedWire []byte,
	quarantinedWire []byte,
) ownerCancelDescriptorClass {
	switch {
	case allZero(wire):
		return ownerCancelDescriptorFree
	case bytes.Equal(wire, reservedWire):
		return ownerCancelDescriptorReserved
	case bytes.Equal(wire, quarantinedWire):
		return ownerCancelDescriptorQuarantined
	default:
		return ownerCancelDescriptorConflict
	}
}

func ownerCancelBatchPages(remaining uint64) uint64 {
	limit := uint64(ownerCancelIOBatchBytes / ContentPageBytes)
	if remaining < limit {
		return remaining
	}
	return limit
}

func ownerCancelDescriptorBatchPages(remaining uint64) uint64 {
	limit := uint64(ownerCancelIOBatchBytes / PageDescriptorBytes)
	if remaining < limit {
		return remaining
	}
	return limit
}

func ownerCancelPersistenceMismatchf(format string, arguments ...interface{}) error {
	return fmt.Errorf(
		"%w: %s",
		ErrOwnerCancelDurableContradiction,
		fmt.Sprintf(format, arguments...))
}

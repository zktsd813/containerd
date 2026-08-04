package trcxl007

import (
	"bytes"
	"errors"
	"fmt"
	"sort"
)

var (
	// ErrOwnerAbortDescriptorDispositionChanged means descriptor bytes no
	// longer match the last global observation. Before any allocator applies
	// M, recovery may rescan and switch the whole checkpoint to quarantine.
	// After applied-M locks a disposition, the mismatch requires OFFLINE.
	ErrOwnerAbortDescriptorDispositionChanged = errors.New(
		"TRCXL007 abort descriptor disposition changed after global preflight")
)

type ownerAbortDescriptorClass uint8

const (
	ownerAbortDescriptorFree ownerAbortDescriptorClass = iota + 1
	ownerAbortDescriptorReserved
	ownerAbortDescriptorQuarantined
	ownerAbortDescriptorConflict
)

type ownerAbortDescriptorObservation struct {
	totalPages       uint64
	freePages        uint64
	reservedPages    uint64
	quarantinedPages uint64
	conflictPages    uint64
}

func (observation ownerAbortDescriptorObservation) requiresQuarantine() bool {
	return observation.quarantinedPages != 0 || observation.conflictPages != 0
}

func (observation ownerAbortDescriptorObservation) cleanDispositionComplete() bool {
	return observation.totalPages != 0 &&
		observation.freePages == observation.totalPages
}

func (observation ownerAbortDescriptorObservation) quarantineDispositionComplete() bool {
	return observation.totalPages != 0 &&
		observation.freePages == 0 &&
		observation.reservedPages == 0 &&
		observation.quarantinedPages+observation.conflictPages ==
			observation.totalPages
}

type ownerAbortDescriptorPersistenceRun struct {
	startDataPageIndex uint64
	pageCount          uint64
	reserved           Descriptor
	reservedWire       [PageDescriptorBytes]byte
	quarantined        Descriptor
	quarantinedWire    [PageDescriptorBytes]byte
	pageBitStart       uint64
}

// inspectPreparingAbortDescriptors is strictly read-only. The executor calls
// it for every affected device before the first descriptor disposition write,
// so a late device can never silently turn a partially clean abort into a
// per-device quarantine.
func (device *DeviceMetadata) inspectPreparingAbortDescriptors(
	authorityRecord OwnerStateAllocationRecord,
	abortingTransaction uint64,
) (ownerAbortDescriptorObservation, error) {
	prepared, _, err := device.prepareAbortDescriptorPersistence(
		authorityRecord,
		abortingTransaction)
	if err != nil {
		return ownerAbortDescriptorObservation{}, err
	}
	observation, _, err := device.scanAbortDescriptorPersistence(
		prepared,
		0)
	return observation, err
}

// persistAbortingDescriptorDisposition changes descriptor bytes only. It
// never touches payload/CRC/refcount content pages, Owner state, allocator
// snapshots, or superblocks. A quarantine operation writes exact Q(M) only
// over canonical FREE or exact checkpoint RESERVED(N); all torn/corrupt/
// foreign bytes are preserved byte-for-byte.
func (device *DeviceMetadata) persistAbortingDescriptorDisposition(
	abortingRecord OwnerStateAllocationRecord,
	disposition OwnerAbortDisposition,
) error {
	return device.persistAbortingDescriptorDispositionWithLock(
		abortingRecord,
		disposition,
		false)
}

// persistAbortingDescriptorDispositionWithLock forbids descriptor repair when
// an allocator has already applied the ABORTING transaction M.  In that case
// the bitmap is durable disposition evidence: a clean lock requires every
// selected descriptor to remain FREE, while a quarantine lock permits only
// exact Q(M) or raw conflicts.  Any later repairable class is a contradiction,
// not permission to rewrite it.
func (device *DeviceMetadata) persistAbortingDescriptorDispositionWithLock(
	abortingRecord OwnerStateAllocationRecord,
	disposition OwnerAbortDisposition,
	requireComplete bool,
) error {
	if disposition != OwnerAbortClean && disposition != OwnerAbortQuarantine {
		return fmt.Errorf(
			"%w: unsupported descriptor disposition %d",
			ErrOwnerAbortDescriptorDispositionChanged,
			disposition)
	}
	prepared, totalPages, err := device.prepareAbortDescriptorPersistence(
		abortingRecord,
		abortingRecord.OwnerTransactionSequence)
	if err != nil {
		return err
	}
	bitmapBytes, ok := checkedAdd(totalPages, 7)
	if !ok || bitmapBytes/8 > uint64(maxIntValue()) {
		return ownerAllocatorInputMismatchf(
			"device %q abort descriptor bitmap length overflows",
			device.superblock.DeviceUUID)
	}
	observation, writePages, err := device.scanAbortDescriptorPersistence(
		prepared,
		disposition)
	if err != nil {
		return err
	}
	if disposition == OwnerAbortClean && observation.requiresQuarantine() {
		return fmt.Errorf(
			"%w: clean disposition observed Q/conflict pages",
			ErrOwnerAbortDescriptorDispositionChanged)
	}
	if requireComplete {
		complete := observation.cleanDispositionComplete()
		if disposition == OwnerAbortQuarantine {
			complete = observation.quarantineDispositionComplete()
		}
		if !complete {
			return fmt.Errorf(
				"%w: allocator-applied disposition %d is not descriptor-complete on device %q",
				ErrOwnerAbortDescriptorDispositionChanged,
				disposition,
				device.superblock.DeviceUUID)
		}
	}
	if uint64(len(writePages)) != bitmapBytes/8 {
		return ownerAllocatorInputMismatchf(
			"device %q abort descriptor write bitmap has wrong length",
			device.superblock.DeviceUUID)
	}

	zeroBuffer := make([]byte, reservedDescriptorIOBatchBytes)
	writeBuffer := make([]byte, reservedDescriptorIOBatchBytes)
	for runIndex := range prepared {
		run := prepared[runIndex]
		for pageOffset := uint64(0); pageOffset < run.pageCount; {
			bit := run.pageBitStart + pageOffset
			if !reservedDescriptorBitSet(writePages, bit) {
				pageOffset++
				continue
			}
			writeStart := pageOffset
			for pageOffset < run.pageCount &&
				reservedDescriptorBitSet(
					writePages,
					run.pageBitStart+pageOffset) {
				pageOffset++
			}
			writeCount := pageOffset - writeStart
			for writtenPages := uint64(0); writtenPages < writeCount; {
				batchPages := writeCount - writtenPages
				if batchPages > uint64(
					reservedDescriptorIOBatchBytes/PageDescriptorBytes) {
					batchPages = uint64(
						reservedDescriptorIOBatchBytes / PageDescriptorBytes)
				}
				batchBytes := batchPages * uint64(PageDescriptorBytes)
				var exact []byte
				if disposition == OwnerAbortClean {
					exact = zeroBuffer[:int(batchBytes)]
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
					return ownerAllocatorInputMismatchf(
						"device %q abort descriptor offset: %v",
						device.superblock.DeviceUUID,
						offsetErr)
				}
				device.reopenRequired = true
				if writeErr := writeMetadataExactAt(
					device.storage,
					device.geometry.DeviceBytes,
					exact,
					offset); writeErr != nil {
					return fmt.Errorf(
						"%w: write abort descriptors on device %q at data page %d: %v",
						ErrDeviceMetadataStorage,
						device.superblock.DeviceUUID,
						run.startDataPageIndex+writeStart+writtenPages,
						writeErr)
				}
				writtenPages += batchPages
			}
		}
	}

	// Even an exact replay needs a fresh persistence boundary. A failed Sync is
	// ambiguous and deliberately leaves reopenRequired set.
	device.reopenRequired = true
	if err := device.storage.Sync(); err != nil {
		return fmt.Errorf(
			"%w: sync abort descriptors on device %q: %v",
			ErrDeviceMetadataStorage,
			device.superblock.DeviceUUID,
			err)
	}
	device.reopenRequired = false
	return nil
}

func (device *DeviceMetadata) prepareAbortDescriptorPersistence(
	authorityRecord OwnerStateAllocationRecord,
	abortingTransaction uint64,
) ([]ownerAbortDescriptorPersistenceRun, uint64, error) {
	if device == nil || device.storage == nil {
		return nil, 0, fmt.Errorf(
			"%w: opened device is nil",
			ErrDeviceMetadataStorage)
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
	if abortingTransaction == 0 {
		return nil, 0, ownerAllocatorInputMismatchf(
			"abort transaction is zero")
	}

	preparingRecord := cloneOwnerStateRecord(authorityRecord)
	switch authorityRecord.State {
	case OwnerAllocationPreparing:
		want, ok := checkedAdd(
			authorityRecord.OwnerTransactionSequence,
			1)
		if !ok || want != abortingTransaction {
			return nil, 0, ownerAllocatorInputMismatchf(
				"PREPARING transaction %d does not precede abort transaction %d",
				authorityRecord.OwnerTransactionSequence,
				abortingTransaction)
		}
	case OwnerAllocationAborting:
		if authorityRecord.OwnerTransactionSequence != abortingTransaction ||
			abortingTransaction <= 1 {
			return nil, 0, ownerAllocatorInputMismatchf(
				"ABORTING transaction %d differs from expected %d",
				authorityRecord.OwnerTransactionSequence,
				abortingTransaction)
		}
		preparingRecord.State = OwnerAllocationPreparing
		preparingRecord.OwnerTransactionSequence = abortingTransaction - 1
	default:
		return nil, 0, ownerAllocatorInputMismatchf(
			"allocation record %d state %d is neither PREPARING nor ABORTING",
			authorityRecord.AllocationRecordID,
			authorityRecord.State)
	}

	deviceByUUID := make(map[string]OwnerStateDevice, len(device.bootstrap.Devices))
	for _, member := range device.bootstrap.Devices {
		deviceByUUID[member.DeviceUUID] = member
	}
	if err := validateOwnerStateRecord(authorityRecord, deviceByUUID); err != nil {
		return nil, 0, ownerAllocatorInputMismatchf(
			"abort authority record: %v",
			err)
	}
	if err := validateOwnerStateRecord(preparingRecord, deviceByUUID); err != nil {
		return nil, 0, ownerAllocatorInputMismatchf(
			"derived PREPARING record: %v",
			err)
	}

	switch device.superblock.OwnerGroupRole {
	case OwnerGroupRoleAnchor:
		if !device.ownerStatePresent {
			return nil, 0, fmt.Errorf(
				"%w: ANCHOR has no active Owner state",
				ErrDeviceMetadataRoleMismatch)
		}
		activeRecord, found := reservedDescriptorOwnerRecord(
			device.ownerState,
			authorityRecord.AllocationRecordID)
		if !found || !reservedDescriptorRecordsEqual(
			activeRecord,
			authorityRecord) {
			return nil, 0, ownerAllocatorInputMismatchf(
				"ANCHOR active Owner state does not contain exact abort authority record %d",
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

	allRuns, err := ownerReserveDescriptorsFromRecord(preparingRecord)
	if err != nil {
		return nil, 0, err
	}
	localUUID := device.superblock.DeviceUUID
	prepared := make([]ownerAbortDescriptorPersistenceRun, 0, len(allRuns))
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
		quarantined.OwnerTransactionSeq = abortingTransaction
		quarantinedWire, marshalErr := quarantined.MarshalBinary()
		if marshalErr != nil {
			return nil, 0, marshalErr
		}
		entry := ownerAbortDescriptorPersistenceRun{
			startDataPageIndex: run.StartDataPageIndex,
			pageCount:          run.PageCount,
			reserved:           run.Descriptor,
			quarantined:        quarantined,
		}
		copy(entry.reservedWire[:], reservedWire)
		copy(entry.quarantinedWire[:], quarantinedWire)
		prepared = append(prepared, entry)
	}
	if len(prepared) == 0 {
		return nil, 0, ownerAllocatorInputMismatchf(
			"abort record has no descriptor run for device %q",
			localUUID)
	}
	sort.Slice(prepared, func(left, right int) bool {
		return prepared[left].startDataPageIndex <
			prepared[right].startDataPageIndex
	})
	var totalPages uint64
	for index := range prepared {
		prepared[index].pageBitStart = totalPages
		var ok bool
		totalPages, ok = checkedAdd(totalPages, prepared[index].pageCount)
		if !ok || totalPages > device.geometry.DataPageCount {
			return nil, 0, ownerAllocatorInputMismatchf(
				"device %q abort descriptor page count overflows",
				localUUID)
		}
	}
	return prepared, totalPages, nil
}

func (device *DeviceMetadata) scanAbortDescriptorPersistence(
	prepared []ownerAbortDescriptorPersistenceRun,
	disposition OwnerAbortDisposition,
) (ownerAbortDescriptorObservation, []byte, error) {
	var totalPages uint64
	for _, run := range prepared {
		var ok bool
		totalPages, ok = checkedAdd(totalPages, run.pageCount)
		if !ok {
			return ownerAbortDescriptorObservation{}, nil,
				ownerAllocatorInputMismatchf("abort descriptor page count overflows")
		}
	}
	bitmapBytes, ok := checkedAdd(totalPages, 7)
	if !ok || bitmapBytes/8 > uint64(maxIntValue()) {
		return ownerAbortDescriptorObservation{}, nil,
			ownerAllocatorInputMismatchf("abort descriptor bitmap length overflows")
	}
	writes := make([]byte, int(bitmapBytes/8))
	buffer := make([]byte, reservedDescriptorIOBatchBytes)
	observation := ownerAbortDescriptorObservation{totalPages: totalPages}
	for runIndex := range prepared {
		run := prepared[runIndex]
		for pageOffset := uint64(0); pageOffset < run.pageCount; {
			batchPages := run.pageCount - pageOffset
			if batchPages > uint64(
				reservedDescriptorIOBatchBytes/PageDescriptorBytes) {
				batchPages = uint64(
					reservedDescriptorIOBatchBytes / PageDescriptorBytes)
			}
			batchBytes := batchPages * uint64(PageDescriptorBytes)
			offset, err := device.geometry.DescriptorOffset(
				run.startDataPageIndex + pageOffset)
			if err != nil {
				return ownerAbortDescriptorObservation{}, nil, err
			}
			batch := buffer[:int(batchBytes)]
			if err := readMetadataExactAt(
				device.storage,
				device.geometry.DeviceBytes,
				batch,
				offset); err != nil {
				return ownerAbortDescriptorObservation{}, nil, fmt.Errorf(
					"%w: read abort descriptors on device %q at data page %d: %v",
					ErrDeviceMetadataStorage,
					device.superblock.DeviceUUID,
					run.startDataPageIndex+pageOffset,
					err)
			}
			for batchPage := uint64(0); batchPage < batchPages; batchPage++ {
				start := int(batchPage * uint64(PageDescriptorBytes))
				wire := batch[start : start+PageDescriptorBytes]
				class := classifyOwnerAbortDescriptor(
					wire,
					run.reservedWire[:],
					run.quarantinedWire[:])
				switch class {
				case ownerAbortDescriptorFree:
					observation.freePages++
				case ownerAbortDescriptorReserved:
					observation.reservedPages++
				case ownerAbortDescriptorQuarantined:
					observation.quarantinedPages++
				case ownerAbortDescriptorConflict:
					observation.conflictPages++
				default:
					return ownerAbortDescriptorObservation{}, nil,
						ownerAllocatorInputMismatchf(
							"unknown abort descriptor class %d",
							class)
				}
				bit := run.pageBitStart + pageOffset + batchPage
				switch disposition {
				case 0:
					// Read-only observation.
				case OwnerAbortClean:
					if class == ownerAbortDescriptorQuarantined ||
						class == ownerAbortDescriptorConflict {
						return ownerAbortDescriptorObservation{}, nil, fmt.Errorf(
							"%w: device %q data page %d requires quarantine",
							ErrOwnerAbortDescriptorDispositionChanged,
							device.superblock.DeviceUUID,
							run.startDataPageIndex+pageOffset+batchPage)
					}
					if class == ownerAbortDescriptorReserved {
						reservedDescriptorSetBit(writes, bit)
					}
				case OwnerAbortQuarantine:
					if class == ownerAbortDescriptorFree ||
						class == ownerAbortDescriptorReserved {
						reservedDescriptorSetBit(writes, bit)
					}
				default:
					return ownerAbortDescriptorObservation{}, nil, fmt.Errorf(
						"%w: unsupported disposition %d",
						ErrOwnerAbortDescriptorDispositionChanged,
						disposition)
				}
			}
			pageOffset += batchPages
		}
	}
	return observation, writes, nil
}

func classifyOwnerAbortDescriptor(
	wire []byte,
	reservedWire []byte,
	quarantinedWire []byte,
) ownerAbortDescriptorClass {
	switch {
	case allZero(wire):
		return ownerAbortDescriptorFree
	case bytes.Equal(wire, reservedWire):
		return ownerAbortDescriptorReserved
	case bytes.Equal(wire, quarantinedWire):
		return ownerAbortDescriptorQuarantined
	default:
		return ownerAbortDescriptorConflict
	}
}

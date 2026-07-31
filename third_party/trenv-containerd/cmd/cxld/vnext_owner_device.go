package main

import (
	"errors"
	"fmt"
)

// prepareOwnerFragment reserves an exact Owner-planned set of device-local
// extents at an Owner-scoped allocation ID. The grant is not safe to expose to
// a producer until the Owner control record reaches GRANTED.
func (d *vnextPersistentDevice) prepareOwnerFragment(
	request vnextCheckpointAllocationRequest,
	allocationRecordID uint64,
	extents []vnextPageExtent,
) (vnextWriteGrant, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if err := d.checkUsableLocked(); err != nil {
		return vnextWriteGrant{}, err
	}
	grant, err := d.allocator.reserveAtIDWithExtents(request, allocationRecordID, extents)
	if err != nil {
		return vnextWriteGrant{}, err
	}
	if err := d.persistAllocatorLocked(); err != nil {
		return vnextWriteGrant{}, d.poisonLocked(fmt.Errorf("persist Owner fragment reservation: %w", err))
	}
	record, ok := d.allocator.lookup(request.CheckpointID)
	if !ok || record.AllocationRecordID != allocationRecordID {
		return vnextWriteGrant{}, d.poisonLocked(errors.New("prepared Owner fragment disappeared"))
	}
	if err := d.initializeReservedDescriptorsLocked(record); err != nil {
		return vnextWriteGrant{}, d.poisonLocked(fmt.Errorf("initialize Owner fragment descriptors: %w", err))
	}
	return grant, nil
}

func (d *vnextPersistentDevice) ownerFragmentGrant(
	checkpointID string,
	allocationRecordID uint64,
) (vnextWriteGrant, error) {
	d.allocator.mu.Lock()
	defer d.allocator.mu.Unlock()
	record, ok := d.allocator.records[allocationRecordID]
	if !ok || record.CheckpointID != checkpointID {
		return vnextWriteGrant{}, fmt.Errorf(
			"checkpoint %q fragment allocation %d does not exist",
			checkpointID, allocationRecordID)
	}
	if record.State != vnextAllocationReserved {
		return vnextWriteGrant{}, fmt.Errorf(
			"fragment allocation %d is state %d, expected RESERVED: %w",
			allocationRecordID, record.State, errVNextInvalidState)
	}
	return d.allocator.grantFromRecordLocked(record), nil
}

func (d *vnextPersistentDevice) commitOwnerFragment(
	checkpointID string,
	allocationRecordID uint64,
) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if err := d.checkUsableLocked(); err != nil {
		return err
	}
	record, ok := d.allocator.lookup(checkpointID)
	if !ok || record.AllocationRecordID != allocationRecordID {
		return fmt.Errorf("Owner commit fragment does not exist")
	}
	if record.State == vnextAllocationCommitted {
		return nil
	}
	if record.State != vnextAllocationReserved {
		return fmt.Errorf(
			"Owner commit fragment is state %d: %w",
			record.State, errVNextInvalidState)
	}
	if err := d.validateSealedRecordLocked(record, true); err != nil {
		return err
	}
	if err := d.allocator.commitByOwner(allocationRecordID, checkpointID); err != nil {
		return err
	}
	if err := d.persistAllocatorLocked(); err != nil {
		return d.poisonLocked(fmt.Errorf("persist Owner fragment commit: %w", err))
	}
	return nil
}

func (d *vnextPersistentDevice) validateOwnerFragmentSealed(
	checkpointID string,
	allocationRecordID uint64,
) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if err := d.checkUsableLocked(); err != nil {
		return err
	}
	record, ok := d.allocator.lookup(checkpointID)
	if !ok || record.AllocationRecordID != allocationRecordID {
		return fmt.Errorf("Owner fragment does not exist")
	}
	if record.State == vnextAllocationCommitted {
		return nil
	}
	if record.State != vnextAllocationReserved {
		return fmt.Errorf("Owner fragment is state %d: %w", record.State, errVNextInvalidState)
	}
	return d.validateSealedRecordLocked(record, true)
}

func (d *vnextPersistentDevice) validateOwnerFragmentReclaimable(
	checkpointID string,
	allocationRecordID uint64,
) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if err := d.checkUsableLocked(); err != nil {
		return err
	}
	record, ok := d.allocator.lookup(checkpointID)
	if !ok || record.AllocationRecordID != allocationRecordID {
		return fmt.Errorf("Owner fragment does not exist")
	}
	if record.State == vnextAllocationReclaimed {
		return nil
	}
	if record.State != vnextAllocationCommitted {
		return fmt.Errorf("Owner fragment is state %d: %w", record.State, errVNextInvalidState)
	}
	return d.validateSealedRecordLocked(record, false)
}

func (d *vnextPersistentDevice) abortOwnerFragment(
	checkpointID string,
	allocationRecordID uint64,
) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if err := d.checkUsableLocked(); err != nil {
		return err
	}
	record, ok := d.allocator.lookup(checkpointID)
	if !ok {
		// A PREPARING Owner record lists every planned device, including
		// fragments that may not have reached their device allocator.
		return nil
	}
	if record.AllocationRecordID != allocationRecordID {
		return fmt.Errorf("checkpoint fragment has allocation %d, expected %d: %w",
			record.AllocationRecordID, allocationRecordID, errVNextAuthority)
	}
	switch record.State {
	case vnextAllocationAborted:
		return nil
	case vnextAllocationAbortPending:
		if err := d.clearRecordDescriptorsLocked(record, true, true); err != nil {
			return d.poisonLocked(fmt.Errorf("resume Owner fragment abort descriptor clear: %w", err))
		}
		if err := d.allocator.finishAbort(allocationRecordID); err != nil {
			return d.poisonLocked(err)
		}
		if err := d.persistAllocatorLocked(); err != nil {
			return d.poisonLocked(fmt.Errorf("persist resumed Owner fragment abort: %w", err))
		}
		return nil
	case vnextAllocationReserved:
		if err := d.allocator.beginAbortByOwner(allocationRecordID, checkpointID); err != nil {
			return err
		}
		if err := d.persistAllocatorLocked(); err != nil {
			return d.poisonLocked(fmt.Errorf("persist Owner fragment abort decision: %w", err))
		}
		if err := d.clearRecordDescriptorsLocked(record, true, true); err != nil {
			return d.poisonLocked(fmt.Errorf("clear Owner fragment descriptors: %w", err))
		}
		if err := d.allocator.finishAbort(allocationRecordID); err != nil {
			return d.poisonLocked(err)
		}
		if err := d.persistAllocatorLocked(); err != nil {
			return d.poisonLocked(fmt.Errorf("persist Owner fragment free bitmap: %w", err))
		}
		return nil
	default:
		return fmt.Errorf(
			"cannot abort Owner fragment in state %d: %w",
			record.State, errVNextInvalidState)
	}
}

func (d *vnextPersistentDevice) reclaimOwnerFragment(
	checkpointID string,
	allocationRecordID uint64,
) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if err := d.checkUsableLocked(); err != nil {
		return err
	}
	record, ok := d.allocator.lookup(checkpointID)
	if !ok || record.AllocationRecordID != allocationRecordID {
		return fmt.Errorf("Owner reclaim fragment does not exist")
	}
	switch record.State {
	case vnextAllocationReclaimed:
		return nil
	case vnextAllocationReclaimPending:
		if err := d.clearRecordDescriptorsLocked(record, true, false); err != nil {
			return d.poisonLocked(fmt.Errorf("resume Owner fragment reclaim descriptor clear: %w", err))
		}
		if err := d.allocator.finishReclaim(allocationRecordID); err != nil {
			return d.poisonLocked(err)
		}
		if err := d.persistAllocatorLocked(); err != nil {
			return d.poisonLocked(fmt.Errorf("persist resumed Owner fragment reclaim: %w", err))
		}
		return nil
	case vnextAllocationCommitted:
		if err := d.validateSealedRecordLocked(record, false); err != nil {
			return err
		}
		request := vnextReclaimRequest{
			Authority: vnextOwnerAuthority{
				DeviceUUID: d.superblock.DeviceUUID,
				OwnerID:    d.superblock.OwnerID,
				OwnerEpoch: d.superblock.OwnerEpoch,
			},
			CheckpointID:           checkpointID,
			AllocationRecordID:     allocationRecordID,
			ExpectedCommitSequence: record.OwnerTransaction,
		}
		if err := d.allocator.beginReclaim(request); err != nil {
			return err
		}
		if err := d.persistAllocatorLocked(); err != nil {
			return d.poisonLocked(fmt.Errorf("persist Owner fragment reclaim decision: %w", err))
		}
		if err := d.clearRecordDescriptorsLocked(record, false, false); err != nil {
			return d.poisonLocked(fmt.Errorf("clear Owner reclaimed descriptors: %w", err))
		}
		if err := d.allocator.finishReclaim(allocationRecordID); err != nil {
			return d.poisonLocked(err)
		}
		if err := d.persistAllocatorLocked(); err != nil {
			return d.poisonLocked(fmt.Errorf("persist Owner reclaimed free bitmap: %w", err))
		}
		return nil
	default:
		return fmt.Errorf(
			"cannot reclaim Owner fragment in state %d: %w",
			record.State, errVNextInvalidState)
	}
}

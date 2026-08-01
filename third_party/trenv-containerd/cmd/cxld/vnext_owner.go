package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"os"
	"sort"
	"sync"
)

var (
	errVNextOwnerPoisoned      = errors.New("VNext Owner group is fail-closed")
	errVNextOwnerCrashInjected = errors.New("simulated VNext Owner crash")
)

const (
	vnextOwnerFailBeforePrepare = "before-prepare-fragment"
	vnextOwnerFailAfterPrepare  = "after-prepare-fragment"
	vnextOwnerFailDuringCommit  = "during-commit-fragment"
	vnextOwnerFailDuringAbort   = "during-abort-fragment"
	vnextOwnerFailDuringReclaim = "during-reclaim-fragment"
)

type vnextOwnerPageExtentGrant struct {
	DeviceUUID         string
	StartDataPageIndex uint64
	PageCount          uint64
	GlobalLogicalStart uint64
}

type vnextOwnerWriteGrant struct {
	AllocationRecordID uint64
	RequestID          string
	CheckpointID       string
	ProducerID         string
	OwnerID            string
	OwnerEpoch         uint64
	Contents           []vnextContentSegment
	Extents            []vnextOwnerPageExtentGrant

	// Device-local tokens are deliberately not part of the portable grant
	// geometry. cxld uses them internally to validate the producer at each
	// single-writer device fragment.
	fragmentGrants map[string]vnextWriteGrant
}

type vnextOwnerGroup struct {
	mu sync.Mutex

	ownerID          string
	ownerEpoch       uint64
	devices          map[string]*vnextPersistentDevice
	deviceOrder      []string
	controlFile      *os.File
	controlSlotBytes uint64
	journal          *vnextOwnerJournal
	poisoned         error

	// faultHook is nil in production. Tests use it to stop at durable phase
	// boundaries and verify restart behavior.
	faultHook func(stage, deviceUUID string) error
}

type vnextOwnerRun struct {
	DeviceUUID         string
	StartDataPageIndex uint64
	PageCount          uint64
}

type vnextOwnerPlan struct {
	TotalPages uint64
	Fragments  []vnextOwnerDeviceFragment
}

// vnextOwnerInventoryDevice is deliberately limited to capacity information.
// It must never grow allocator geometry, bitmap state, free runs, local paths,
// file descriptors, grants, tokens, or transaction identities.
type vnextOwnerInventoryDevice struct {
	DeviceUUID     string
	TotalDataPages uint64
	FreeDataPages  uint64
}

// vnextOwnerInventorySnapshot is a point-in-time view of one live Owner. All
// fields are copied while vnextOwnerGroup.mu is held, so a multi-device
// reserve, abort, commit, reclaim, or recovery transition cannot be observed
// halfway through. SnapshotSequence is the durable Owner journal sequence; an
// inventory read itself is non-durable and never advances it.
type vnextOwnerInventorySnapshot struct {
	OwnerID          string
	OwnerEpoch       uint64
	SnapshotSequence uint64
	Devices          []vnextOwnerInventoryDevice
}

func formatVNextOwnerGroup(
	controlFile *os.File,
	controlSlotBytes uint64,
	devices []*vnextPersistentDevice,
) (*vnextOwnerGroup, error) {
	deviceMap, deviceOrder, ownerID, ownerEpoch, maxHighWater, err :=
		vnextValidateOwnerDevices(devices, true)
	if err != nil {
		return nil, err
	}
	if err := vnextValidateOwnerControlFile(controlFile, controlSlotBytes); err != nil {
		return nil, err
	}
	journal, err := newVNextOwnerJournal(ownerID, ownerEpoch, maxHighWater)
	if err != nil {
		return nil, err
	}
	group := &vnextOwnerGroup{
		ownerID:          ownerID,
		ownerEpoch:       ownerEpoch,
		devices:          deviceMap,
		deviceOrder:      deviceOrder,
		controlFile:      controlFile,
		controlSlotBytes: controlSlotBytes,
		journal:          journal,
	}
	if err := vnextZeroRange(controlFile, 0, controlSlotBytes*2); err != nil {
		return nil, fmt.Errorf("clear Owner control region: %w", err)
	}
	if err := controlFile.Sync(); err != nil {
		return nil, fmt.Errorf("sync Owner control region: %w", err)
	}
	if err := group.persistJournalLocked(journal.clone()); err != nil {
		return nil, fmt.Errorf("write Owner journal A: %w", err)
	}
	if err := group.persistJournalLocked(group.journal.clone()); err != nil {
		return nil, fmt.Errorf("write Owner journal B: %w", err)
	}
	return group, nil
}

func openVNextOwnerGroup(
	controlFile *os.File,
	controlSlotBytes uint64,
	devices []*vnextPersistentDevice,
) (*vnextOwnerGroup, error) {
	deviceMap, deviceOrder, ownerID, ownerEpoch, maxHighWater, err :=
		vnextValidateOwnerDevices(devices, false)
	if err != nil {
		return nil, err
	}
	if err := vnextValidateOwnerControlFile(controlFile, controlSlotBytes); err != nil {
		return nil, err
	}
	journalA, errA := vnextReadOwnerJournalSlot(controlFile, 0, controlSlotBytes, deviceMap)
	journalB, errB := vnextReadOwnerJournalSlot(controlFile, controlSlotBytes, controlSlotBytes, deviceMap)
	journal, err := vnextSelectOwnerJournal(journalA, errA, journalB, errB, deviceMap)
	if err != nil {
		return nil, err
	}
	if journal.OwnerID != ownerID || journal.OwnerEpoch != ownerEpoch {
		return nil, fmt.Errorf(
			"Owner journal %q/%d does not match attached devices %q/%d: %w",
			journal.OwnerID, journal.OwnerEpoch, ownerID, ownerEpoch, errVNextAuthority)
	}
	group := &vnextOwnerGroup{
		ownerID:          ownerID,
		ownerEpoch:       ownerEpoch,
		devices:          deviceMap,
		deviceOrder:      deviceOrder,
		controlFile:      controlFile,
		controlSlotBytes: controlSlotBytes,
		journal:          journal,
	}
	if journal.NextAllocationRecordID < maxHighWater {
		candidate := journal.clone()
		candidate.NextAllocationRecordID = maxHighWater
		if err := group.persistJournalLocked(candidate); err != nil {
			return nil, fmt.Errorf("advance Owner allocation high-water: %w", err)
		}
	}
	if err := group.recoverTransactionsLocked(); err != nil {
		group.poisoned = err
		return nil, err
	}
	if err := group.reconcileDeviceFragmentsLocked(); err != nil {
		group.poisoned = err
		return nil, err
	}
	return group, nil
}

func (group *vnextOwnerGroup) reserveWithScheduler(
	request vnextCheckpointAllocationRequest,
	authority *vnextOwnerSchedulerVerifiedAuthority,
) (vnextOwnerWriteGrant, error) {
	group.mu.Lock()
	defer group.mu.Unlock()
	if err := group.checkUsableLocked(); err != nil {
		return vnextOwnerWriteGrant{}, err
	}
	if err := validateVNextOwnerVerifiedSchedulerAuthority(authority); err != nil {
		return vnextOwnerWriteGrant{}, err
	}
	segments, totalPages, digest, err := group.validateOwnerRequestLocked(request)
	if err != nil {
		return vnextOwnerWriteGrant{}, err
	}
	if allocationID, exists := group.journal.RequestIndex[request.RequestID]; exists {
		transaction := group.journal.Transactions[allocationID]
		if transaction == nil || transaction.RequestDigest != digest ||
			transaction.CheckpointID != request.CheckpointID ||
			transaction.ProducerID != request.ProducerID {
			return vnextOwnerWriteGrant{}, fmt.Errorf(
				"Owner request ID %q conflicts with allocation %d: %w",
				request.RequestID, allocationID, errVNextAlreadyExists)
		}
		if transaction.SchedulerReserveProof != authority.proof() {
			return vnextOwnerWriteGrant{}, errVNextOwnerSchedulerReceiptConflict
		}
		switch transaction.State {
		case vnextOwnerGranted:
			// Reserve replay is placement recovery, not capability issuance.
			// Writer tokens may be reconstructed only by the exact internal
			// lifecycle operation that consumes them.
			return group.buildGrantGeometryLocked(transaction), nil
		case vnextOwnerRejectedNoSpace:
			return vnextOwnerWriteGrant{}, fmt.Errorf(
				"Owner allocation %d durably rejected the exact request: %w",
				allocationID, errVNextNoSpace)
		default:
			return vnextOwnerWriteGrant{}, fmt.Errorf(
				"Owner allocation %d is state %d, not writable: %w",
				allocationID, transaction.State, errVNextInvalidState)
		}
	}
	// Exact durable outcomes are resolved above even after admission closes.
	// Only an unseen request reaches this point, and it must be ordered with a
	// close/fence transition under this same Owner-group mutex before any
	// checkpoint-index, allocator, descriptor, or journal request mutation.
	if err := group.requireNewAllocationAdmissionLocked("reserve"); err != nil {
		return vnextOwnerWriteGrant{}, err
	}
	if allocationID, exists := group.journal.CheckpointIndex[request.CheckpointID]; exists {
		return vnextOwnerWriteGrant{}, fmt.Errorf(
			"checkpoint %q already names Owner allocation %d: %w",
			request.CheckpointID, allocationID, errVNextAlreadyExists)
	}
	allocationID := group.journal.NextAllocationRecordID
	if allocationID == 0 || allocationID >= uint64(math.MaxInt64) {
		return vnextOwnerWriteGrant{}, errors.New("Owner allocation ID high-water reached the signed ABI limit")
	}
	plan, err := group.planLocked(totalPages, request.MaxExtents)
	if err != nil {
		if !errors.Is(err, errVNextNoSpace) {
			return vnextOwnerWriteGrant{}, err
		}
		transaction := &vnextOwnerTransaction{
			AllocationRecordID:    allocationID,
			RequestID:             request.RequestID,
			CheckpointID:          request.CheckpointID,
			ProducerID:            request.ProducerID,
			RequestDigest:         digest,
			SchedulerReserveProof: authority.proof(),
			State:                 vnextOwnerRejectedNoSpace,
			TotalPages:            totalPages,
			MaxExtents:            request.MaxExtents,
			Contents:              append([]vnextContentSegment(nil), segments...),
		}
		candidate := group.journal.clone()
		candidate.Transactions[allocationID] = transaction
		candidate.RequestIndex[request.RequestID] = allocationID
		candidate.CheckpointIndex[request.CheckpointID] = allocationID
		candidate.NextAllocationRecordID = allocationID + 1
		if err := group.applySchedulerAuthorityLocked(candidate, authority); err != nil {
			return vnextOwnerWriteGrant{}, err
		}
		if persistErr := group.persistJournalLocked(candidate); persistErr != nil {
			return vnextOwnerWriteGrant{}, group.poisonLocked(fmt.Errorf(
				"persist Owner REJECTED_NO_SPACE: %w", persistErr))
		}
		return vnextOwnerWriteGrant{}, fmt.Errorf(
			"Owner allocation %d durably rejected the exact request: %w",
			allocationID, errVNextNoSpace)
	}
	transaction := &vnextOwnerTransaction{
		AllocationRecordID:    allocationID,
		RequestID:             request.RequestID,
		CheckpointID:          request.CheckpointID,
		ProducerID:            request.ProducerID,
		RequestDigest:         digest,
		SchedulerReserveProof: authority.proof(),
		State:                 vnextOwnerPreparing,
		TotalPages:            totalPages,
		MaxExtents:            request.MaxExtents,
		Contents:              append([]vnextContentSegment(nil), segments...),
		Fragments:             plan.Fragments,
	}
	candidate := group.journal.clone()
	candidate.Transactions[allocationID] = transaction
	candidate.RequestIndex[request.RequestID] = allocationID
	candidate.CheckpointIndex[request.CheckpointID] = allocationID
	candidate.NextAllocationRecordID = allocationID + 1
	if err := group.applySchedulerAuthorityLocked(candidate, authority); err != nil {
		return vnextOwnerWriteGrant{}, err
	}
	if err := group.persistJournalLocked(candidate); err != nil {
		return vnextOwnerWriteGrant{}, group.poisonLocked(fmt.Errorf("persist Owner PREPARING: %w", err))
	}

	fragmentGrants := make(map[string]vnextWriteGrant, len(transaction.Fragments))
	for _, fragment := range transaction.Fragments {
		if err := group.callFaultHookLocked(vnextOwnerFailBeforePrepare, fragment.DeviceUUID); err != nil {
			return vnextOwnerWriteGrant{}, group.handlePrepareFailureLocked(transaction, err)
		}
		fragmentRequest, err := vnextOwnerFragmentRequest(request, segments, fragment)
		if err != nil {
			return vnextOwnerWriteGrant{}, group.handlePrepareFailureLocked(transaction, err)
		}
		localExtents := make([]vnextPageExtent, len(fragment.Extents))
		var localLogical uint64
		for index, extent := range fragment.Extents {
			localExtents[index] = vnextPageExtent{
				StartDataPageIndex: extent.StartDataPageIndex,
				PageCount:          extent.PageCount,
				LogicalPageStart:   localLogical,
			}
			localLogical += extent.PageCount
		}
		grant, err := group.devices[fragment.DeviceUUID].prepareOwnerFragment(
			fragmentRequest, allocationID, localExtents)
		if err != nil {
			return vnextOwnerWriteGrant{}, group.handlePrepareFailureLocked(transaction, err)
		}
		fragmentGrants[fragment.DeviceUUID] = grant
		if err := group.callFaultHookLocked(vnextOwnerFailAfterPrepare, fragment.DeviceUUID); err != nil {
			if errors.Is(err, errVNextOwnerCrashInjected) {
				// PREPARING is durable. A new Owner instance will abort every
				// fragment listed by the plan, including those not yet prepared.
				return vnextOwnerWriteGrant{}, err
			}
			return vnextOwnerWriteGrant{}, group.handlePrepareFailureLocked(transaction, err)
		}
	}
	candidate = group.journal.clone()
	candidate.Transactions[allocationID].State = vnextOwnerGranted
	if err := group.persistJournalLocked(candidate); err != nil {
		return vnextOwnerWriteGrant{}, group.poisonLocked(fmt.Errorf("persist Owner GRANTED: %w", err))
	}
	grant, err := group.buildGrantLocked(group.journal.Transactions[allocationID])
	if err != nil {
		return vnextOwnerWriteGrant{}, group.poisonLocked(err)
	}
	grant.fragmentGrants = fragmentGrants
	return grant, nil
}

func (group *vnextOwnerGroup) applySchedulerAuthorityLocked(
	candidate *vnextOwnerJournal,
	authority *vnextOwnerSchedulerVerifiedAuthority,
) error {
	if candidate == nil || group.journal == nil {
		return fmt.Errorf("Owner Scheduler authority candidate is unavailable: %w", errVNextCorrupt)
	}
	if err := validateVNextOwnerVerifiedSchedulerAuthority(authority); err != nil {
		return err
	}
	if err := validateVNextOwnerSchedulerHighWaterAdvance(
		group.journal.SchedulerHighWater, authority.HighWater); err != nil {
		return err
	}
	candidate.SchedulerHighWater = authority.HighWater
	return nil
}

func (group *vnextOwnerGroup) inventory(
	expectedOwnerID string,
	expectedOwnerEpoch uint64,
) (vnextOwnerInventorySnapshot, error) {
	group.mu.Lock()
	defer group.mu.Unlock()

	if err := group.checkUsableLocked(); err != nil {
		return vnextOwnerInventorySnapshot{}, err
	}
	// Authenticate the complete Owner incarnation before reading or copying
	// any capacity data. A stale scheduler view must not receive inventory for
	// a replacement Owner that happens to serve the same endpoint.
	if expectedOwnerID != group.ownerID || expectedOwnerEpoch != group.ownerEpoch {
		return vnextOwnerInventorySnapshot{}, fmt.Errorf(
			"expected Owner %q/%d, live Owner is %q/%d: %w",
			expectedOwnerID,
			expectedOwnerEpoch,
			group.ownerID,
			group.ownerEpoch,
			errVNextAuthority)
	}
	if group.journal == nil || group.journal.SnapshotSequence == 0 ||
		group.journal.SnapshotSequence > uint64(math.MaxInt64) {
		return vnextOwnerInventorySnapshot{}, fmt.Errorf(
			"Owner journal sequence is outside the signed ABI: %w", errVNextCorrupt)
	}
	if len(group.deviceOrder) == 0 || len(group.deviceOrder) != len(group.devices) {
		return vnextOwnerInventorySnapshot{}, fmt.Errorf(
			"Owner device inventory is incomplete: %w", errVNextCorrupt)
	}

	snapshot := vnextOwnerInventorySnapshot{
		OwnerID:          group.ownerID,
		OwnerEpoch:       group.ownerEpoch,
		SnapshotSequence: group.journal.SnapshotSequence,
		Devices:          make([]vnextOwnerInventoryDevice, 0, len(group.deviceOrder)),
	}
	previousUUID := ""
	for index, deviceUUID := range group.deviceOrder {
		if deviceUUID == "" || (index > 0 && previousUUID >= deviceUUID) {
			return vnextOwnerInventorySnapshot{}, fmt.Errorf(
				"Owner device order is not strictly UUID-sorted: %w", errVNextCorrupt)
		}
		device := group.devices[deviceUUID]
		if device == nil {
			return vnextOwnerInventorySnapshot{}, fmt.Errorf(
				"Owner device %q is detached: %w", deviceUUID, errVNextCorrupt)
		}

		// The Owner group lock makes the snapshot atomic with respect to every
		// authoritative Owner operation. The device and allocator locks also
		// make this read safe against lower-level device maintenance and allow
		// a poisoned device to fail closed instead of advertising stale space.
		device.mu.Lock()
		if err := device.checkUsableLocked(); err != nil {
			device.mu.Unlock()
			return vnextOwnerInventorySnapshot{}, fmt.Errorf(
				"Owner device %q is not usable: %w", deviceUUID, err)
		}
		if device.allocator == nil ||
			device.superblock.DeviceUUID != deviceUUID ||
			device.superblock.OwnerID != group.ownerID ||
			device.superblock.OwnerEpoch != group.ownerEpoch ||
			device.allocator.superblock.DeviceUUID != deviceUUID ||
			device.allocator.superblock.OwnerID != group.ownerID ||
			device.allocator.superblock.OwnerEpoch != group.ownerEpoch ||
			device.allocator.superblock.Geometry.DataPageCount !=
				device.superblock.Geometry.DataPageCount {
			device.mu.Unlock()
			return vnextOwnerInventorySnapshot{}, fmt.Errorf(
				"Owner device %q identity is inconsistent: %w", deviceUUID, errVNextCorrupt)
		}
		totalPages := device.superblock.Geometry.DataPageCount
		if totalPages == 0 || totalPages > uint64(math.MaxInt64) {
			device.mu.Unlock()
			return vnextOwnerInventorySnapshot{}, fmt.Errorf(
				"Owner device %q capacity is outside the signed ABI: %w",
				deviceUUID, errVNextCorrupt)
		}
		device.allocator.mu.Lock()
		freePages := device.allocator.freePagesLocked()
		device.allocator.mu.Unlock()
		device.mu.Unlock()

		if freePages > totalPages || freePages > uint64(math.MaxInt64) {
			return vnextOwnerInventorySnapshot{}, fmt.Errorf(
				"Owner device %q capacity is outside the signed ABI: %w",
				deviceUUID, errVNextCorrupt)
		}
		snapshot.Devices = append(snapshot.Devices, vnextOwnerInventoryDevice{
			DeviceUUID:     deviceUUID,
			TotalDataPages: totalPages,
			FreeDataPages:  freePages,
		})
		previousUUID = deviceUUID
	}
	return snapshot, nil
}

func (group *vnextOwnerGroup) writePage(
	grant vnextOwnerWriteGrant,
	globalLogicalPage uint64,
	content []byte,
) error {
	group.mu.Lock()
	defer group.mu.Unlock()
	if err := group.checkUsableLocked(); err != nil {
		return err
	}
	transaction, err := group.validateGrantLocked(grant, vnextOwnerGranted)
	if err != nil {
		return err
	}
	for _, fragment := range transaction.Fragments {
		end, ok := vnextAdd(fragment.GlobalLogicalStart, fragment.PageCount)
		if !ok {
			return fmt.Errorf("Owner fragment logical range overflow: %w", errVNextCorrupt)
		}
		if globalLogicalPage < fragment.GlobalLogicalStart || globalLogicalPage >= end {
			continue
		}
		fragmentGrant, ok := grant.fragmentGrants[fragment.DeviceUUID]
		if !ok {
			return fmt.Errorf("Owner grant has no writer token for device %q: %w",
				fragment.DeviceUUID, errVNextAuthority)
		}
		return group.devices[fragment.DeviceUUID].writePage(
			fragmentGrant,
			globalLogicalPage-fragment.GlobalLogicalStart,
			content)
	}
	return fmt.Errorf("global logical page %d is outside allocation %d",
		globalLogicalPage, grant.AllocationRecordID)
}

func (group *vnextOwnerGroup) commitWithScheduler(
	grant vnextOwnerWriteGrant,
	authority *vnextOwnerSchedulerVerifiedAuthority,
) error {
	group.mu.Lock()
	defer group.mu.Unlock()
	if err := group.checkUsableLocked(); err != nil {
		return err
	}
	if err := validateVNextOwnerVerifiedSchedulerAuthority(authority); err != nil {
		return err
	}
	transaction := group.journal.Transactions[grant.AllocationRecordID]
	if transaction == nil || transaction.RequestID != grant.RequestID ||
		transaction.CheckpointID != grant.CheckpointID || transaction.ProducerID != grant.ProducerID ||
		grant.OwnerID != group.ownerID || grant.OwnerEpoch != group.ownerEpoch {
		return fmt.Errorf("Owner commit grant identity mismatch: %w", errVNextAuthority)
	}
	if transaction.State == vnextOwnerCommitted {
		if transaction.SchedulerCommitProof != authority.proof() {
			return errVNextOwnerSchedulerReceiptConflict
		}
		return nil
	}
	transaction, err := group.validateGrantLocked(grant, vnextOwnerGranted)
	if err != nil {
		return err
	}
	for _, fragment := range transaction.Fragments {
		if err := group.devices[fragment.DeviceUUID].validateOwnerFragmentSealed(
			transaction.CheckpointID, transaction.AllocationRecordID); err != nil {
			return fmt.Errorf("validate sealed fragment %q: %w", fragment.DeviceUUID, err)
		}
	}
	candidate := group.journal.clone()
	candidate.Transactions[transaction.AllocationRecordID].State = vnextOwnerCommitting
	candidate.Transactions[transaction.AllocationRecordID].SchedulerCommitProof = authority.proof()
	if err := group.applySchedulerAuthorityLocked(candidate, authority); err != nil {
		return err
	}
	if err := group.persistJournalLocked(candidate); err != nil {
		return group.poisonLocked(fmt.Errorf("persist Owner COMMITTING: %w", err))
	}
	if err := group.completeCommitLocked(group.journal.Transactions[transaction.AllocationRecordID]); err != nil {
		return group.poisonLocked(err)
	}
	candidate = group.journal.clone()
	candidate.Transactions[transaction.AllocationRecordID].State = vnextOwnerCommitted
	if err := group.persistJournalLocked(candidate); err != nil {
		return group.poisonLocked(fmt.Errorf("persist Owner COMMITTED: %w", err))
	}
	return nil
}

func (group *vnextOwnerGroup) abortWithScheduler(
	grant vnextOwnerWriteGrant,
	authority *vnextOwnerSchedulerVerifiedAuthority,
) error {
	group.mu.Lock()
	defer group.mu.Unlock()
	if err := group.checkUsableLocked(); err != nil {
		return err
	}
	if err := validateVNextOwnerVerifiedSchedulerAuthority(authority); err != nil {
		return err
	}
	transaction := group.journal.Transactions[grant.AllocationRecordID]
	if transaction == nil || transaction.RequestID != grant.RequestID ||
		transaction.CheckpointID != grant.CheckpointID || transaction.ProducerID != grant.ProducerID ||
		grant.OwnerID != group.ownerID || grant.OwnerEpoch != group.ownerEpoch {
		return fmt.Errorf("Owner abort grant does not name an allocation: %w", errVNextAuthority)
	}
	if transaction.State == vnextOwnerAborted {
		if transaction.AbortOrigin != vnextOwnerAbortByScheduler ||
			transaction.SchedulerAbortProof != authority.proof() {
			return errVNextOwnerSchedulerReceiptConflict
		}
		return nil
	}
	if transaction.State != vnextOwnerGranted {
		return fmt.Errorf("cannot abort Owner allocation in state %d: %w",
			transaction.State, errVNextInvalidState)
	}
	// A journal-only FENCED state does not prove that stale direct DAX access
	// has been physically revoked. Exact terminal replay above is read-only,
	// but the live GRANTED path must not free or reuse an extent.
	if err := group.requireReclaimSafetyLocked("abort"); err != nil {
		return err
	}
	if err := group.abortTransactionWithSchedulerLocked(transaction, authority); err != nil {
		return group.poisonLocked(err)
	}
	return nil
}

func (group *vnextOwnerGroup) reclaimCheckpoint(
	checkpointID string,
	allocationRecordID uint64,
) error {
	group.mu.Lock()
	defer group.mu.Unlock()
	if err := group.checkUsableLocked(); err != nil {
		return err
	}
	transaction := group.journal.Transactions[allocationRecordID]
	if transaction == nil || transaction.CheckpointID != checkpointID {
		return fmt.Errorf("Owner reclaim does not name an allocation")
	}
	if transaction.State == vnextOwnerReclaimed {
		return nil
	}
	if transaction.State != vnextOwnerCommitted {
		return fmt.Errorf("cannot reclaim Owner allocation in state %d: %w",
			transaction.State, errVNextInvalidState)
	}
	// A terminal RECLAIMED replay changes no allocator or journal state. Only
	// the live COMMITTED path reaches the physical-reuse safety gate.
	if err := group.requireReclaimSafetyLocked("reclaim"); err != nil {
		return err
	}
	for _, fragment := range transaction.Fragments {
		if err := group.devices[fragment.DeviceUUID].validateOwnerFragmentReclaimable(
			checkpointID, allocationRecordID); err != nil {
			return fmt.Errorf("validate reclaim fragment %q: %w", fragment.DeviceUUID, err)
		}
	}
	candidate := group.journal.clone()
	candidate.Transactions[allocationRecordID].State = vnextOwnerReclaiming
	if err := group.persistJournalLocked(candidate); err != nil {
		return group.poisonLocked(fmt.Errorf("persist Owner RECLAIMING: %w", err))
	}
	if err := group.completeReclaimLocked(group.journal.Transactions[allocationRecordID]); err != nil {
		return group.poisonLocked(err)
	}
	candidate = group.journal.clone()
	candidate.Transactions[allocationRecordID].State = vnextOwnerReclaimed
	if err := group.persistJournalLocked(candidate); err != nil {
		return group.poisonLocked(fmt.Errorf("persist Owner RECLAIMED: %w", err))
	}
	return nil
}

func (group *vnextOwnerGroup) validateOwnerRequestLocked(
	request vnextCheckpointAllocationRequest,
) ([]vnextContentSegment, uint64, [32]byte, error) {
	var zeroDigest [32]byte
	if request.RequestID == "" || len(request.RequestID) > vnextMaxIdentityBytes ||
		request.CheckpointID == "" || len(request.CheckpointID) > vnextMaxIdentityBytes ||
		request.ProducerID == "" || len(request.ProducerID) > vnextMaxIdentityBytes {
		return nil, 0, zeroDigest, errors.New("Owner allocation request identity is empty or too long")
	}
	if request.OwnerID != group.ownerID || request.OwnerEpoch != group.ownerEpoch {
		return nil, 0, zeroDigest, fmt.Errorf(
			"request Owner %q/%d does not match group %q/%d: %w",
			request.OwnerID, request.OwnerEpoch, group.ownerID, group.ownerEpoch, errVNextAuthority)
	}
	if request.MaxExtents == 0 || request.MaxExtents > vnextMaxExtentsPerRecord ||
		len(request.Contents) == 0 || len(request.Contents) > vnextMaxContentsPerRecord {
		return nil, 0, zeroDigest, errors.New("Owner allocation request has invalid content/extent bounds")
	}
	segments := make([]vnextContentSegment, 0, len(request.Contents))
	seenObjects := make(map[uint64]struct{}, len(request.Contents))
	var totalPages uint64
	for _, content := range request.Contents {
		if !content.Kind.valid() || content.ObjectID == 0 || content.PageCount == 0 {
			return nil, 0, zeroDigest, errors.New("Owner content object is invalid")
		}
		if _, exists := seenObjects[content.ObjectID]; exists {
			return nil, 0, zeroDigest, fmt.Errorf("Owner content object %d is duplicated", content.ObjectID)
		}
		seenObjects[content.ObjectID] = struct{}{}
		capacity, ok := vnextMul(content.PageCount, vnextContentPageSize)
		if !ok || content.ByteLength > capacity {
			return nil, 0, zeroDigest, errors.New("Owner content length exceeds reserved capacity")
		}
		if content.Kind == vnextContentMemory && content.ByteLength != capacity {
			return nil, 0, zeroDigest, fmt.Errorf(
				"memory object %d does not fill its reserved pages", content.ObjectID)
		}
		if content.Kind == vnextContentPublication && content.ByteLength != capacity {
			return nil, 0, zeroDigest, fmt.Errorf(
				"publication object %d is not a page-aligned slot", content.ObjectID)
		}
		nextTotal, ok := vnextAdd(totalPages, content.PageCount)
		if !ok || nextTotal > uint64(math.MaxInt64) {
			return nil, 0, zeroDigest, errors.New("Owner logical page count exceeds signed ABI")
		}
		segments = append(segments, vnextContentSegment{
			Kind:             content.Kind,
			ObjectID:         content.ObjectID,
			ByteLength:       content.ByteLength,
			LogicalPageStart: totalPages,
			PageCount:        content.PageCount,
		})
		totalPages = nextTotal
	}
	digest := vnextOwnerRequestDigest(request)
	return segments, totalPages, digest, nil
}

func (group *vnextOwnerGroup) planLocked(totalPages uint64, maxExtents uint32) (vnextOwnerPlan, error) {
	// First honor single-device preference. Candidate ranking is deterministic:
	// fewest extents, then smallest remaining free capacity (best fit), then
	// stable device UUID.
	type candidate struct {
		deviceUUID string
		runs       []vnextOwnerRun
		freeAfter  uint64
	}
	var candidates []candidate
	allRuns := make([]vnextOwnerRun, 0)
	for _, deviceUUID := range group.deviceOrder {
		device := group.devices[deviceUUID]
		freeRuns := device.allocator.freeRuns()
		var freePages uint64
		runs := make([]vnextOwnerRun, 0, len(freeRuns))
		for _, run := range freeRuns {
			freePages += run.PageCount
			runRecord := vnextOwnerRun{
				DeviceUUID:         deviceUUID,
				StartDataPageIndex: run.StartDataPageIndex,
				PageCount:          run.PageCount,
			}
			runs = append(runs, runRecord)
			allRuns = append(allRuns, runRecord)
		}
		selected, ok := vnextChooseOwnerRuns(runs, totalPages, maxExtents)
		if ok {
			candidates = append(candidates, candidate{
				deviceUUID: deviceUUID,
				runs:       selected,
				freeAfter:  freePages - totalPages,
			})
		}
	}
	if len(candidates) > 0 {
		sort.Slice(candidates, func(i, j int) bool {
			if len(candidates[i].runs) != len(candidates[j].runs) {
				return len(candidates[i].runs) < len(candidates[j].runs)
			}
			if candidates[i].freeAfter != candidates[j].freeAfter {
				return candidates[i].freeAfter < candidates[j].freeAfter
			}
			return candidates[i].deviceUUID < candidates[j].deviceUUID
		})
		return vnextOwnerPlanFromRuns(totalPages, candidates[0].runs), nil
	}
	selected, ok := vnextChooseOwnerRuns(allRuns, totalPages, maxExtents)
	if !ok {
		return vnextOwnerPlan{}, fmt.Errorf(
			"Owner needs %d pages within %d extents across %d devices: %w",
			totalPages, maxExtents, len(group.devices), errVNextNoSpace)
	}
	plan := vnextOwnerPlanFromRuns(totalPages, selected)
	if len(plan.Fragments) < 2 {
		return vnextOwnerPlan{}, fmt.Errorf("multi-device planner produced fewer than two fragments: %w", errVNextCorrupt)
	}
	return plan, nil
}

func vnextChooseOwnerRuns(
	runs []vnextOwnerRun,
	pageCount uint64,
	maxExtents uint32,
) ([]vnextOwnerRun, bool) {
	if pageCount == 0 || maxExtents == 0 {
		return nil, false
	}
	sortedRuns := append([]vnextOwnerRun(nil), runs...)
	sort.Slice(sortedRuns, func(i, j int) bool {
		if sortedRuns[i].PageCount != sortedRuns[j].PageCount {
			return sortedRuns[i].PageCount > sortedRuns[j].PageCount
		}
		if sortedRuns[i].DeviceUUID != sortedRuns[j].DeviceUUID {
			return sortedRuns[i].DeviceUUID < sortedRuns[j].DeviceUUID
		}
		return sortedRuns[i].StartDataPageIndex < sortedRuns[j].StartDataPageIndex
	})
	var sum uint64
	minimumRunCount := 0
	for index, run := range sortedRuns {
		if index >= int(maxExtents) {
			break
		}
		next, ok := vnextAdd(sum, run.PageCount)
		if !ok {
			return nil, false
		}
		sum = next
		if sum >= pageCount {
			minimumRunCount = index + 1
			break
		}
	}
	if minimumRunCount == 0 {
		return nil, false
	}
	if minimumRunCount == 1 {
		best := -1
		for index, run := range sortedRuns {
			if run.PageCount < pageCount {
				continue
			}
			if best < 0 || run.PageCount < sortedRuns[best].PageCount ||
				(run.PageCount == sortedRuns[best].PageCount && vnextOwnerRunLess(run, sortedRuns[best])) {
				best = index
			}
		}
		chosen := sortedRuns[best]
		chosen.PageCount = pageCount
		return []vnextOwnerRun{chosen}, true
	}
	selected := append([]vnextOwnerRun(nil), sortedRuns[:minimumRunCount-1]...)
	var selectedPages uint64
	selectedKeys := make(map[string]struct{}, len(selected))
	for _, run := range selected {
		selectedPages += run.PageCount
		selectedKeys[vnextOwnerRunKey(run)] = struct{}{}
	}
	remaining := pageCount - selectedPages
	best := -1
	for index, run := range sortedRuns {
		if _, used := selectedKeys[vnextOwnerRunKey(run)]; used || run.PageCount < remaining {
			continue
		}
		if best < 0 || run.PageCount < sortedRuns[best].PageCount ||
			(run.PageCount == sortedRuns[best].PageCount && vnextOwnerRunLess(run, sortedRuns[best])) {
			best = index
		}
	}
	if best < 0 {
		return nil, false
	}
	last := sortedRuns[best]
	last.PageCount = remaining
	selected = append(selected, last)
	return selected, true
}

func vnextOwnerPlanFromRuns(totalPages uint64, runs []vnextOwnerRun) vnextOwnerPlan {
	byDevice := make(map[string][]vnextOwnerRun)
	for _, run := range runs {
		byDevice[run.DeviceUUID] = append(byDevice[run.DeviceUUID], run)
	}
	deviceUUIDs := make([]string, 0, len(byDevice))
	for deviceUUID := range byDevice {
		deviceUUIDs = append(deviceUUIDs, deviceUUID)
	}
	sort.Strings(deviceUUIDs)
	plan := vnextOwnerPlan{TotalPages: totalPages}
	var globalLogical uint64
	for _, deviceUUID := range deviceUUIDs {
		deviceRuns := byDevice[deviceUUID]
		sort.Slice(deviceRuns, func(i, j int) bool {
			return deviceRuns[i].StartDataPageIndex < deviceRuns[j].StartDataPageIndex
		})
		fragment := vnextOwnerDeviceFragment{
			DeviceUUID:         deviceUUID,
			GlobalLogicalStart: globalLogical,
		}
		for _, run := range deviceRuns {
			fragment.Extents = append(fragment.Extents, vnextOwnerExtent{
				StartDataPageIndex: run.StartDataPageIndex,
				PageCount:          run.PageCount,
				GlobalLogicalStart: globalLogical + fragment.PageCount,
			})
			fragment.PageCount += run.PageCount
		}
		globalLogical += fragment.PageCount
		plan.Fragments = append(plan.Fragments, fragment)
	}
	return plan
}

func vnextOwnerFragmentRequest(
	request vnextCheckpointAllocationRequest,
	segments []vnextContentSegment,
	fragment vnextOwnerDeviceFragment,
) (vnextCheckpointAllocationRequest, error) {
	contents, err := vnextSliceOwnerContents(segments, fragment.GlobalLogicalStart, fragment.PageCount)
	if err != nil {
		return vnextCheckpointAllocationRequest{}, err
	}
	digestInput := request.RequestID + "\x00" + fragment.DeviceUUID
	fragmentID := sha256.Sum256([]byte(digestInput))
	return vnextCheckpointAllocationRequest{
		RequestID:    fmt.Sprintf("owner-fragment-%x", fragmentID[:]),
		CheckpointID: request.CheckpointID,
		ProducerID:   request.ProducerID,
		OwnerID:      request.OwnerID,
		OwnerEpoch:   request.OwnerEpoch,
		Contents:     contents,
		MaxExtents:   uint32(len(fragment.Extents)),
	}, nil
}

func vnextSliceOwnerContents(
	segments []vnextContentSegment,
	logicalStart uint64,
	pageCount uint64,
) ([]vnextContentRequest, error) {
	logicalEnd, ok := vnextAdd(logicalStart, pageCount)
	if !ok {
		return nil, errors.New("fragment logical range overflows")
	}
	contents := make([]vnextContentRequest, 0)
	for _, segment := range segments {
		segmentEnd, ok := vnextAdd(segment.LogicalPageStart, segment.PageCount)
		if !ok {
			return nil, errors.New("content segment logical range overflows")
		}
		start := logicalStart
		if start < segment.LogicalPageStart {
			start = segment.LogicalPageStart
		}
		end := logicalEnd
		if end > segmentEnd {
			end = segmentEnd
		}
		if start >= end {
			continue
		}
		chunkPages := end - start
		pageOffset := start - segment.LogicalPageStart
		chunkStartByte, ok := vnextMul(pageOffset, vnextContentPageSize)
		if !ok {
			return nil, errors.New("fragment content byte length overflows")
		}
		chunkCapacity, ok := vnextMul(chunkPages, vnextContentPageSize)
		if !ok {
			return nil, errors.New("fragment content capacity overflows")
		}
		var chunkBytes uint64
		if chunkStartByte < segment.ByteLength {
			chunkBytes = segment.ByteLength - chunkStartByte
			if chunkBytes > chunkCapacity {
				chunkBytes = chunkCapacity
			}
		}
		contents = append(contents, vnextContentRequest{
			Kind:       segment.Kind,
			ObjectID:   segment.ObjectID,
			ByteLength: chunkBytes,
			PageCount:  chunkPages,
		})
	}
	var covered uint64
	for _, content := range contents {
		covered += content.PageCount
	}
	if covered != pageCount {
		return nil, fmt.Errorf("fragment content covers %d of %d pages: %w",
			covered, pageCount, errVNextCorrupt)
	}
	return contents, nil
}

func vnextOwnerRequestDigest(request vnextCheckpointAllocationRequest) [32]byte {
	var buffer bytes.Buffer
	vnextWriteString(&buffer, request.RequestID)
	vnextWriteString(&buffer, request.CheckpointID)
	vnextWriteString(&buffer, request.ProducerID)
	vnextWriteString(&buffer, request.OwnerID)
	vnextWriteU64(&buffer, request.OwnerEpoch)
	vnextWriteU32(&buffer, request.MaxExtents)
	vnextWriteU32(&buffer, uint32(len(request.Contents)))
	for _, content := range request.Contents {
		buffer.WriteByte(byte(content.Kind))
		buffer.Write(make([]byte, 7))
		vnextWriteU64(&buffer, content.ObjectID)
		vnextWriteU64(&buffer, content.ByteLength)
		vnextWriteU64(&buffer, content.PageCount)
	}
	return sha256.Sum256(buffer.Bytes())
}

func (group *vnextOwnerGroup) buildGrantLocked(
	transaction *vnextOwnerTransaction,
) (vnextOwnerWriteGrant, error) {
	grant := group.buildGrantGeometryLocked(transaction)
	grant.fragmentGrants = make(map[string]vnextWriteGrant, len(transaction.Fragments))
	for _, fragment := range transaction.Fragments {
		fragmentGrant, err := group.devices[fragment.DeviceUUID].ownerFragmentGrant(
			transaction.CheckpointID, transaction.AllocationRecordID)
		if err != nil {
			return vnextOwnerWriteGrant{}, err
		}
		grant.fragmentGrants[fragment.DeviceUUID] = fragmentGrant
	}
	return grant, nil
}

// buildGrantGeometryLocked reconstructs only the immutable, producer-visible
// placement recorded in the Owner journal. It deliberately does not recover
// device write tokens, so it is safe for read-only status of SEALED and
// COMMITTED transactions whose producer authority has already ended.
func (group *vnextOwnerGroup) buildGrantGeometryLocked(
	transaction *vnextOwnerTransaction,
) vnextOwnerWriteGrant {
	grant := vnextOwnerWriteGrant{
		AllocationRecordID: transaction.AllocationRecordID,
		RequestID:          transaction.RequestID,
		CheckpointID:       transaction.CheckpointID,
		ProducerID:         transaction.ProducerID,
		OwnerID:            group.ownerID,
		OwnerEpoch:         group.ownerEpoch,
		Contents:           append([]vnextContentSegment(nil), transaction.Contents...),
	}
	for _, fragment := range transaction.Fragments {
		for _, extent := range fragment.Extents {
			grant.Extents = append(grant.Extents, vnextOwnerPageExtentGrant{
				DeviceUUID:         fragment.DeviceUUID,
				StartDataPageIndex: extent.StartDataPageIndex,
				PageCount:          extent.PageCount,
				GlobalLogicalStart: extent.GlobalLogicalStart,
			})
		}
	}
	return grant
}

func (group *vnextOwnerGroup) validateGrantLocked(
	grant vnextOwnerWriteGrant,
	expectedState vnextOwnerTransactionState,
) (*vnextOwnerTransaction, error) {
	if expectedState == vnextOwnerGranted {
		if err := group.requireProducerMutationAllowedLocked("producer-mutation"); err != nil {
			return nil, err
		}
	}
	transaction := group.journal.Transactions[grant.AllocationRecordID]
	if transaction == nil || transaction.RequestID != grant.RequestID ||
		transaction.CheckpointID != grant.CheckpointID || transaction.ProducerID != grant.ProducerID ||
		grant.OwnerID != group.ownerID || grant.OwnerEpoch != group.ownerEpoch {
		return nil, fmt.Errorf("Owner grant identity mismatch: %w", errVNextAuthority)
	}
	if transaction.State != expectedState {
		return nil, fmt.Errorf("Owner allocation is state %d, expected %d: %w",
			transaction.State, expectedState, errVNextInvalidState)
	}
	return transaction, nil
}

func (group *vnextOwnerGroup) handlePrepareFailureLocked(
	transaction *vnextOwnerTransaction,
	cause error,
) error {
	if err := group.abortTransactionLocked(transaction, vnextOwnerAbortByRecovery); err != nil {
		return group.poisonLocked(fmt.Errorf("prepare failed (%v), cleanup failed: %w", cause, err))
	}
	return cause
}

func (group *vnextOwnerGroup) abortTransactionLocked(
	transaction *vnextOwnerTransaction,
	origin vnextOwnerAbortOrigin,
) error {
	if origin != vnextOwnerAbortByProducer && origin != vnextOwnerAbortByRecovery {
		return fmt.Errorf("internal Owner abort origin is invalid: %w", errVNextCorrupt)
	}
	return group.beginAbortTransactionLocked(transaction, origin, nil)
}

func (group *vnextOwnerGroup) abortTransactionWithSchedulerLocked(
	transaction *vnextOwnerTransaction,
	authority *vnextOwnerSchedulerVerifiedAuthority,
) error {
	if err := validateVNextOwnerVerifiedSchedulerAuthority(authority); err != nil {
		return err
	}
	return group.beginAbortTransactionLocked(
		transaction, vnextOwnerAbortByScheduler, authority)
}

func (group *vnextOwnerGroup) beginAbortTransactionLocked(
	transaction *vnextOwnerTransaction,
	origin vnextOwnerAbortOrigin,
	authority *vnextOwnerSchedulerVerifiedAuthority,
) error {
	candidate := group.journal.clone()
	candidate.Transactions[transaction.AllocationRecordID].State = vnextOwnerAborting
	candidate.Transactions[transaction.AllocationRecordID].AbortOrigin = origin
	if origin == vnextOwnerAbortByScheduler {
		candidate.Transactions[transaction.AllocationRecordID].SchedulerAbortProof =
			authority.proof()
		if err := group.applySchedulerAuthorityLocked(candidate, authority); err != nil {
			return err
		}
	}
	if err := group.persistJournalLocked(candidate); err != nil {
		return fmt.Errorf("persist Owner ABORTING: %w", err)
	}
	return group.completeAbortTransactionLocked(
		group.journal.Transactions[transaction.AllocationRecordID])
}

func (group *vnextOwnerGroup) completeAbortTransactionLocked(
	transaction *vnextOwnerTransaction,
) error {
	if transaction == nil || transaction.State != vnextOwnerAborting ||
		!transaction.AbortOrigin.valid() {
		return fmt.Errorf("Owner ABORTING record is invalid: %w", errVNextCorrupt)
	}
	for _, fragment := range transaction.Fragments {
		if err := group.callFaultHookLocked(vnextOwnerFailDuringAbort, fragment.DeviceUUID); err != nil {
			return err
		}
		if err := group.devices[fragment.DeviceUUID].abortOwnerFragment(
			transaction.CheckpointID, transaction.AllocationRecordID); err != nil {
			return fmt.Errorf("abort fragment %q: %w", fragment.DeviceUUID, err)
		}
	}
	candidate := group.journal.clone()
	candidate.Transactions[transaction.AllocationRecordID].State = vnextOwnerAborted
	if err := group.persistJournalLocked(candidate); err != nil {
		return fmt.Errorf("persist Owner ABORTED: %w", err)
	}
	return nil
}

func (group *vnextOwnerGroup) completeCommitLocked(transaction *vnextOwnerTransaction) error {
	for _, fragment := range transaction.Fragments {
		if err := group.callFaultHookLocked(vnextOwnerFailDuringCommit, fragment.DeviceUUID); err != nil {
			return err
		}
		if err := group.devices[fragment.DeviceUUID].commitOwnerFragment(
			transaction.CheckpointID, transaction.AllocationRecordID); err != nil {
			return fmt.Errorf("commit fragment %q: %w", fragment.DeviceUUID, err)
		}
	}
	return nil
}

func (group *vnextOwnerGroup) completeReclaimLocked(transaction *vnextOwnerTransaction) error {
	for _, fragment := range transaction.Fragments {
		if err := group.callFaultHookLocked(vnextOwnerFailDuringReclaim, fragment.DeviceUUID); err != nil {
			return err
		}
		if err := group.devices[fragment.DeviceUUID].reclaimOwnerFragment(
			transaction.CheckpointID, transaction.AllocationRecordID); err != nil {
			return fmt.Errorf("reclaim fragment %q: %w", fragment.DeviceUUID, err)
		}
	}
	return nil
}

func (group *vnextOwnerGroup) recoverTransactionsLocked() error {
	allocationIDs := make([]uint64, 0, len(group.journal.Transactions))
	for allocationID := range group.journal.Transactions {
		allocationIDs = append(allocationIDs, allocationID)
	}
	sort.Slice(allocationIDs, func(i, j int) bool { return allocationIDs[i] < allocationIDs[j] })
	for _, allocationID := range allocationIDs {
		transaction := group.journal.Transactions[allocationID]
		switch transaction.State {
		case vnextOwnerPreparing, vnextOwnerAborting:
			if err := group.requireReclaimSafetyLocked("restart-abort"); err != nil {
				return fmt.Errorf(
					"Owner allocation %d cannot be freed during fenced recovery: %w",
					allocationID,
					err)
			}
			if transaction.State == vnextOwnerPreparing {
				if err := group.abortTransactionLocked(
					transaction, vnextOwnerAbortByRecovery); err != nil {
					return fmt.Errorf("recover Owner abort %d: %w", allocationID, err)
				}
				continue
			}
			if err := group.completeAbortTransactionLocked(transaction); err != nil {
				return fmt.Errorf("recover Owner abort %d: %w", allocationID, err)
			}
		case vnextOwnerCommitting:
			if err := group.completeCommitLocked(transaction); err != nil {
				return fmt.Errorf("recover Owner commit %d: %w", allocationID, err)
			}
			candidate := group.journal.clone()
			candidate.Transactions[allocationID].State = vnextOwnerCommitted
			if err := group.persistJournalLocked(candidate); err != nil {
				return err
			}
		case vnextOwnerReclaiming:
			if err := group.requireReclaimSafetyLocked("restart-reclaim"); err != nil {
				return fmt.Errorf(
					"Owner allocation %d cannot be reused during fenced recovery: %w",
					allocationID,
					err)
			}
			if err := group.completeReclaimLocked(transaction); err != nil {
				return fmt.Errorf("recover Owner reclaim %d: %w", allocationID, err)
			}
			candidate := group.journal.clone()
			candidate.Transactions[allocationID].State = vnextOwnerReclaimed
			if err := group.persistJournalLocked(candidate); err != nil {
				return err
			}
		case vnextOwnerQuarantined:
			return fmt.Errorf("Owner allocation %d is quarantined: %w", allocationID, errVNextOwnerPoisoned)
		case vnextOwnerRejectedNoSpace:
			// The negative result is already terminal and owns no device pages.
			continue
		}
	}
	return nil
}

func (group *vnextOwnerGroup) reconcileDeviceFragmentsLocked() error {
	expected := make(map[string]map[uint64]*vnextOwnerTransaction)
	negativeTombstones := make(map[uint64]struct{})
	for _, transaction := range group.journal.Transactions {
		if transaction.State == vnextOwnerRejectedNoSpace {
			if len(transaction.Fragments) != 0 {
				return fmt.Errorf("REJECTED_NO_SPACE Owner allocation %d has device fragments: %w",
					transaction.AllocationRecordID, errVNextCorrupt)
			}
			negativeTombstones[transaction.AllocationRecordID] = struct{}{}
			continue
		}
		if len(transaction.Fragments) == 0 {
			return fmt.Errorf("Owner allocation %d has no device fragments: %w",
				transaction.AllocationRecordID, errVNextCorrupt)
		}
		for _, fragment := range transaction.Fragments {
			if expected[fragment.DeviceUUID] == nil {
				expected[fragment.DeviceUUID] = make(map[uint64]*vnextOwnerTransaction)
			}
			expected[fragment.DeviceUUID][transaction.AllocationRecordID] = transaction
		}
	}
	// Journal-to-device validation is required as well as the reverse scan.
	// Otherwise a lost device snapshot could silently erase one fragment while
	// the Owner still advertises a complete checkpoint.
	for deviceUUID, transactions := range expected {
		device := group.devices[deviceUUID]
		device.allocator.mu.Lock()
		for allocationID, transaction := range transactions {
			record := device.allocator.records[allocationID]
			switch transaction.State {
			case vnextOwnerGranted:
				if record == nil || record.State != vnextAllocationReserved {
					device.allocator.mu.Unlock()
					return fmt.Errorf("GRANTED Owner allocation %d is missing RESERVED fragment on %q: %w",
						allocationID, deviceUUID, errVNextCorrupt)
				}
			case vnextOwnerCommitted:
				if record == nil || record.State != vnextAllocationCommitted {
					device.allocator.mu.Unlock()
					return fmt.Errorf("COMMITTED Owner allocation %d is missing COMMITTED fragment on %q: %w",
						allocationID, deviceUUID, errVNextCorrupt)
				}
			case vnextOwnerReclaimed:
				if record == nil || record.State != vnextAllocationReclaimed {
					device.allocator.mu.Unlock()
					return fmt.Errorf("RECLAIMED Owner allocation %d is missing RECLAIMED fragment on %q: %w",
						allocationID, deviceUUID, errVNextCorrupt)
				}
			case vnextOwnerAborted:
				if record != nil && record.State != vnextAllocationAborted {
					device.allocator.mu.Unlock()
					return fmt.Errorf("ABORTED Owner allocation %d has state %d fragment on %q: %w",
						allocationID, record.State, deviceUUID, errVNextCorrupt)
				}
			default:
				device.allocator.mu.Unlock()
				return fmt.Errorf("Owner recovery left transaction %d in state %d: %w",
					allocationID, transaction.State, errVNextCorrupt)
			}
			if record != nil {
				var fragment *vnextOwnerDeviceFragment
				for index := range transaction.Fragments {
					if transaction.Fragments[index].DeviceUUID == deviceUUID {
						fragment = &transaction.Fragments[index]
						break
					}
				}
				if fragment == nil {
					device.allocator.mu.Unlock()
					return fmt.Errorf(
						"Owner transaction %d has no fragment for device %q: %w",
						allocationID, deviceUUID, errVNextCorrupt)
				}
				if err := validateVNextOwnerDeviceRecord(
					group.ownerID, group.ownerEpoch, transaction, *fragment, record); err != nil {
					device.allocator.mu.Unlock()
					return fmt.Errorf(
						"device %q allocation %d disagrees with Owner journal: %w",
						deviceUUID, allocationID, err)
				}
			}
		}
		device.allocator.mu.Unlock()
	}
	for deviceUUID, device := range group.devices {
		device.allocator.mu.Lock()
		for allocationID, record := range device.allocator.records {
			if _, rejected := negativeTombstones[allocationID]; rejected {
				device.allocator.mu.Unlock()
				return fmt.Errorf("device %q has allocator record for REJECTED_NO_SPACE allocation %d: %w",
					deviceUUID, allocationID, errVNextCorrupt)
			}
			transaction := expected[deviceUUID][allocationID]
			if transaction == nil {
				if record.State == vnextAllocationAborted || record.State == vnextAllocationReclaimed {
					continue
				}
				device.allocator.mu.Unlock()
				return fmt.Errorf("device %q has active orphan allocation %d: %w",
					deviceUUID, allocationID, errVNextCorrupt)
			}
			if record.CheckpointID != transaction.CheckpointID || record.OwnerID != group.ownerID ||
				record.OwnerEpoch != group.ownerEpoch {
				device.allocator.mu.Unlock()
				return fmt.Errorf("device %q allocation %d identity disagrees with Owner journal: %w",
					deviceUUID, allocationID, errVNextCorrupt)
			}
		}
		device.allocator.mu.Unlock()
	}
	return nil
}

func validateVNextOwnerDeviceRecord(
	ownerID string,
	ownerEpoch uint64,
	transaction *vnextOwnerTransaction,
	fragment vnextOwnerDeviceFragment,
	record *vnextAllocationRecord,
) error {
	requestContents := make([]vnextContentRequest, len(transaction.Contents))
	for index, content := range transaction.Contents {
		requestContents[index] = vnextContentRequest{
			Kind:       content.Kind,
			ObjectID:   content.ObjectID,
			ByteLength: content.ByteLength,
			PageCount:  content.PageCount,
		}
	}
	fragmentRequest, err := vnextOwnerFragmentRequest(
		vnextCheckpointAllocationRequest{
			RequestID:    transaction.RequestID,
			CheckpointID: transaction.CheckpointID,
			ProducerID:   transaction.ProducerID,
			OwnerID:      ownerID,
			OwnerEpoch:   ownerEpoch,
			Contents:     requestContents,
			MaxExtents:   transaction.MaxExtents,
		},
		transaction.Contents,
		fragment)
	if err != nil {
		return err
	}
	expectedContents := make([]vnextContentSegment, len(fragmentRequest.Contents))
	var localLogical uint64
	for index, content := range fragmentRequest.Contents {
		expectedContents[index] = vnextContentSegment{
			Kind:             content.Kind,
			ObjectID:         content.ObjectID,
			ByteLength:       content.ByteLength,
			LogicalPageStart: localLogical,
			PageCount:        content.PageCount,
		}
		localLogical += content.PageCount
	}
	expectedExtents := make([]vnextPageExtent, len(fragment.Extents))
	localLogical = 0
	for index, extent := range fragment.Extents {
		expectedExtents[index] = vnextPageExtent{
			StartDataPageIndex: extent.StartDataPageIndex,
			PageCount:          extent.PageCount,
			LogicalPageStart:   localLogical,
		}
		localLogical += extent.PageCount
	}
	if record.AllocationRecordID != transaction.AllocationRecordID ||
		record.RequestID != fragmentRequest.RequestID ||
		record.CheckpointID != transaction.CheckpointID ||
		record.ProducerID != transaction.ProducerID ||
		record.OwnerID != ownerID ||
		record.OwnerEpoch != ownerEpoch ||
		record.TotalPages != fragment.PageCount ||
		record.MaxExtents != uint32(len(fragment.Extents)) ||
		!vnextContentSegmentsEqual(record.Contents, expectedContents) ||
		!vnextPageExtentsEqual(record.Extents, expectedExtents) {
		return errVNextCorrupt
	}
	return nil
}

func vnextContentSegmentsEqual(left, right []vnextContentSegment) bool {
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

func (group *vnextOwnerGroup) persistJournalLocked(candidate *vnextOwnerJournal) error {
	if candidate.SnapshotSequence == math.MaxUint64 {
		return errors.New("Owner journal sequence is exhausted")
	}
	sequence := candidate.SnapshotSequence + 1
	data, err := candidate.marshalAtSequence(sequence, group.devices)
	if err != nil {
		return err
	}
	if uint64(len(data)) > group.controlSlotBytes {
		return fmt.Errorf("Owner journal needs %d bytes, slot capacity is %d: %w",
			len(data), group.controlSlotBytes, errVNextMetadataFull)
	}
	offset := uint64(0)
	if sequence%2 == 0 {
		offset = group.controlSlotBytes
	}
	if err := vnextWriteCommittedEnvelopeSlot(
		group.controlFile, offset, group.controlSlotBytes, data); err != nil {
		return err
	}
	candidate.SnapshotSequence = sequence
	group.journal = candidate
	return nil
}

func vnextValidateOwnerDevices(
	devices []*vnextPersistentDevice,
	formatting bool,
) (map[string]*vnextPersistentDevice, []string, string, uint64, uint64, error) {
	if len(devices) == 0 {
		return nil, nil, "", 0, 0, errors.New("Owner group requires at least one DAX device")
	}
	deviceMap := make(map[string]*vnextPersistentDevice, len(devices))
	var ownerID string
	var ownerEpoch uint64
	var maxHighWater uint64 = 1
	for _, device := range devices {
		if device == nil || device.poisoned != nil {
			return nil, nil, "", 0, 0, errors.New("Owner group cannot attach nil or poisoned device")
		}
		if ownerID == "" {
			ownerID = device.superblock.OwnerID
			ownerEpoch = device.superblock.OwnerEpoch
		}
		if device.superblock.OwnerID != ownerID || device.superblock.OwnerEpoch != ownerEpoch {
			return nil, nil, "", 0, 0, fmt.Errorf("DAX device owner mismatch: %w", errVNextAuthority)
		}
		deviceUUID := device.superblock.DeviceUUID
		if _, exists := deviceMap[deviceUUID]; exists {
			return nil, nil, "", 0, 0, fmt.Errorf("duplicate DAX device UUID %q", deviceUUID)
		}
		if formatting {
			device.allocator.mu.Lock()
			for _, record := range device.allocator.records {
				if record.State.ownsPages() {
					device.allocator.mu.Unlock()
					return nil, nil, "", 0, 0, fmt.Errorf(
						"cannot format Owner group with active device allocation %d",
						record.AllocationRecordID)
				}
			}
			device.allocator.mu.Unlock()
		}
		if highWater := device.allocator.allocationIDHighWater(); highWater > maxHighWater {
			maxHighWater = highWater
		}
		deviceMap[deviceUUID] = device
	}
	deviceOrder := make([]string, 0, len(deviceMap))
	for deviceUUID := range deviceMap {
		deviceOrder = append(deviceOrder, deviceUUID)
	}
	sort.Strings(deviceOrder)
	return deviceMap, deviceOrder, ownerID, ownerEpoch, maxHighWater, nil
}

func vnextValidateOwnerControlFile(file *os.File, slotBytes uint64) error {
	if file == nil {
		return errors.New("Owner control file is nil")
	}
	if slotBytes < vnextMinimumOwnerControlSlotBytes ||
		slotBytes%vnextContentPageSize != 0 ||
		slotBytes > uint64(vnextFormatHeaderSize)+vnextMaxEnvelopePayload {
		return fmt.Errorf("Owner control slot size %d is invalid", slotBytes)
	}
	stat, err := file.Stat()
	if err != nil {
		return err
	}
	expected, ok := vnextMul(slotBytes, 2)
	if !ok || stat.Size() < 0 || uint64(stat.Size()) != expected {
		return fmt.Errorf("Owner control file is %d bytes, expected %d", stat.Size(), expected)
	}
	return nil
}

func vnextReadOwnerJournalSlot(
	file *os.File,
	offset uint64,
	slotBytes uint64,
	devices map[string]*vnextPersistentDevice,
) (*vnextOwnerJournal, error) {
	data, err := vnextReadEnvelopeSlot(file, offset, slotBytes, vnextOwnerJournalMagic)
	if err != nil {
		return nil, err
	}
	return parseVNextOwnerJournal(data, devices)
}

func vnextSelectOwnerJournal(
	first *vnextOwnerJournal,
	firstErr error,
	second *vnextOwnerJournal,
	secondErr error,
	devices map[string]*vnextPersistentDevice,
) (*vnextOwnerJournal, error) {
	if firstErr != nil && secondErr != nil {
		return nil, fmt.Errorf("neither Owner journal slot is valid (A: %v; B: %v): %w",
			firstErr, secondErr, errVNextCorrupt)
	}
	if firstErr != nil {
		return second, nil
	}
	if secondErr != nil {
		return first, nil
	}
	if first.SnapshotSequence == second.SnapshotSequence {
		firstData, firstMarshalErr := first.marshalAtSequence(first.SnapshotSequence, devices)
		secondData, secondMarshalErr := second.marshalAtSequence(second.SnapshotSequence, devices)
		if firstMarshalErr != nil || secondMarshalErr != nil || !bytes.Equal(firstData, secondData) {
			return nil, fmt.Errorf("equal-sequence Owner journals disagree: %w", errVNextCorrupt)
		}
	}
	if second.SnapshotSequence > first.SnapshotSequence {
		return second, nil
	}
	return first, nil
}

func (group *vnextOwnerGroup) checkUsableLocked() error {
	if group.poisoned != nil {
		return fmt.Errorf("%w: %v", errVNextOwnerPoisoned, group.poisoned)
	}
	return nil
}

func (group *vnextOwnerGroup) poisonLocked(err error) error {
	if err == nil {
		err = errors.New("unknown Owner group failure")
	}
	group.poisoned = err
	return err
}

func (group *vnextOwnerGroup) callFaultHookLocked(stage, deviceUUID string) error {
	if group.faultHook == nil {
		return nil
	}
	return group.faultHook(stage, deviceUUID)
}

func vnextOwnerRunLess(left, right vnextOwnerRun) bool {
	if left.DeviceUUID != right.DeviceUUID {
		return left.DeviceUUID < right.DeviceUUID
	}
	return left.StartDataPageIndex < right.StartDataPageIndex
}

func vnextOwnerRunKey(run vnextOwnerRun) string {
	var raw [16]byte
	binary.LittleEndian.PutUint64(raw[0:8], run.StartDataPageIndex)
	binary.LittleEndian.PutUint64(raw[8:16], run.PageCount)
	return run.DeviceUUID + string(raw[:])
}

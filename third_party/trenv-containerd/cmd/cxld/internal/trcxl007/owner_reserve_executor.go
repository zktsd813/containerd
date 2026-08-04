package trcxl007

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"sort"

	"github.com/containerd/containerd/third_party/trenv-containerd/pkg/cxlcheckpoint"
)

var (
	// ErrOwnerReserveRecoveryRequired means PREPARING may already be durable.
	// The caller must not create another allocation; it must reopen if required
	// and forward-recover this exact record.
	ErrOwnerReserveRecoveryRequired = errors.New(
		"TRCXL007 Owner reserve requires forward recovery")
	ErrOwnerReserveNoPreparing = errors.New(
		"TRCXL007 Owner state has no active PREPARING allocation")
	// ErrOwnerReserveAbortRequired is deliberately a follow-on marker, not an
	// implemented rollback. Torn/foreign descriptors and impossible allocator
	// states require the later abort/quarantine protocol.
	ErrOwnerReserveAbortRequired = errors.New(
		"TRCXL007 Owner reserve requires abort or quarantine")
	ErrOwnerReserveTransitionBlocked = errors.New(
		"TRCXL007 Owner reserve is blocked by an in-progress Owner transition")
)

// OwnerReserveExecutionResult is the narrow durable result of one serialized
// reserve execution. Record is detached. ForwardRecovered reports that an
// already-durable PREPARING record, rather than a caller plan, drove execution.
type OwnerReserveExecutionResult struct {
	Outcome          OwnerReserveOutcome
	Record           OwnerStateAllocationRecord
	ForwardRecovered bool
}

type ownerReserveExecutionError struct {
	cause            error
	recoveryRequired bool
	abortRequired    bool
	reopenRequired   bool
}

func (executionError *ownerReserveExecutionError) Error() string {
	qualifier := "Owner reserve execution failed"
	if executionError.abortRequired {
		qualifier = "Owner reserve execution needs abort/quarantine"
	} else if executionError.recoveryRequired {
		qualifier = "Owner reserve execution needs forward recovery"
	}
	if executionError.reopenRequired {
		qualifier += " after reopening the device group"
	}
	return fmt.Sprintf("%s: %v", qualifier, executionError.cause)
}

func (executionError *ownerReserveExecutionError) Unwrap() error {
	return executionError.cause
}

func (executionError *ownerReserveExecutionError) Is(target error) bool {
	return (target == ErrOwnerReserveRecoveryRequired && executionError.recoveryRequired) ||
		(target == ErrOwnerReserveAbortRequired && executionError.abortRequired) ||
		(target == ErrOwnerDeviceGroupReopenRequired && executionError.reopenRequired)
}

type ownerReserveRecoveryDevice struct {
	deviceIndex int
	deviceUUID  string
	fragment    OwnerStateDeviceFragment
	runs        []OwnerReservedDescriptorRun
	desired     AllocatorSnapshot
	beforeApply bool
}

type ownerReserveRecoveryPlan struct {
	preparingState  OwnerStateSnapshot
	preparingRecord OwnerStateAllocationRecord
	grantedState    OwnerStateSnapshot
	grantedRecord   OwnerStateAllocationRecord
	devices         []ownerReserveRecoveryDevice
}

// ExecuteCheckpointReserve serializes one checkpoint allocation inside this
// opened OwnerDeviceGroup. The service layer must authenticate Scheduler and
// Producer authority before constructing OwnerReserveRequest; this layer only
// validates and persists their SHA-256 commitments. It is a single-process
// mutex, not a distributed Owner fence, and it has no fallback path.
func (group *OwnerDeviceGroup) ExecuteCheckpointReserve(
	request OwnerReserveRequest,
) (OwnerReserveExecutionResult, error) {
	if !group.ownerDeviceGroupHandleValid() {
		return OwnerReserveExecutionResult{}, ErrOwnerDeviceGroupInput
	}
	group.executionState.mu.Lock()
	defer group.executionState.mu.Unlock()
	if group.ownerDeviceGroupOfflineRequiredLocked() {
		return OwnerReserveExecutionResult{}, ErrOwnerDeviceGroupOfflineRequired
	}
	if group.ownerDeviceGroupReopenRequiredLocked() {
		return OwnerReserveExecutionResult{}, ErrOwnerDeviceGroupReopenRequired
	}

	ownerState, err := group.ownerStateLocked()
	if err != nil {
		return OwnerReserveExecutionResult{}, err
	}
	preparing, present, err := ownerReserveActivePreparing(ownerState)
	if err != nil {
		return OwnerReserveExecutionResult{}, group.ownerReserveFailureLocked(err, true, true)
	}
	replay, exactReplay, replayErr := ownerReserveExactRequestReplay(ownerState, request)
	if replayErr != nil {
		return OwnerReserveExecutionResult{}, replayErr
	}
	// Any earlier COMMITTING/ABORTING/RECLAIMING record blocks allocation and
	// recovery even when the last record is PREPARING. Otherwise a newer
	// reservation could bypass an unfinished older ownership transition. An
	// unrelated transition does not hide an already-terminal exact replay.
	if transitional, blocked := ownerReserveTransitionalRecord(ownerState); blocked {
		if exactReplay && ownerReserveRecordIsTerminal(replay) {
			return ownerReserveExecutionResult(OwnerReserveReplay, replay, false), nil
		}
		return OwnerReserveExecutionResult{}, fmt.Errorf(
			"%w: allocation %d remains in state %d",
			ErrOwnerReserveTransitionBlocked,
			transitional.AllocationRecordID,
			transitional.State)
	}
	if exactReplay && ownerReserveRecordIsTerminal(replay) {
		return ownerReserveExecutionResult(OwnerReserveReplay, replay, false), nil
	}
	if present {
		if !exactReplay || replay.AllocationRecordID != preparing.AllocationRecordID {
			return OwnerReserveExecutionResult{}, ownerReserveConflictf(
				"active PREPARING allocation %d blocks request %q",
				preparing.AllocationRecordID,
				request.RequestID)
		}
		return group.recoverPreparingLocked(ownerState, preparing, OwnerReserveReplay)
	}
	committed, allocatorInputs, err := group.plannerInputsLocked()
	if err != nil {
		return OwnerReserveExecutionResult{}, err
	}
	plan, err := PlanOwnerCheckpointReserve(committed, allocatorInputs, request)
	if err != nil {
		return OwnerReserveExecutionResult{}, err
	}
	switch plan.Outcome {
	case OwnerReserveReplay:
		if plan.Record.State == OwnerAllocationPreparing {
			return OwnerReserveExecutionResult{}, group.ownerReserveFailureLocked(
				ownerAllocatorInputMismatchf("planner replayed PREPARING after preflight found none"),
				true,
				true)
		}
		return ownerReserveExecutionResult(plan.Outcome, plan.Record, false), nil
	case OwnerReserveRejectedNoSpace:
		return group.executeRejectedNoSpaceLocked(plan)
	case OwnerReservePlanned:
		return group.executeFreshReserveLocked(committed, plan)
	default:
		return OwnerReserveExecutionResult{}, ownerAllocatorInputMismatchf(
			"planner returned unsupported outcome %d", plan.Outcome)
	}
}

// RecoverPreparingCheckpointReserve forward-recovers the one exact active
// PREPARING record without accepting a caller request, digest, plan, or raw
// authority. Torn/foreign descriptors remain fail-closed and explicitly need
// the follow-on abort/quarantine implementation.
func (group *OwnerDeviceGroup) RecoverPreparingCheckpointReserve() (
	OwnerReserveExecutionResult,
	error,
) {
	if !group.ownerDeviceGroupHandleValid() {
		return OwnerReserveExecutionResult{}, ErrOwnerDeviceGroupInput
	}
	group.executionState.mu.Lock()
	defer group.executionState.mu.Unlock()
	if group.ownerDeviceGroupOfflineRequiredLocked() {
		return OwnerReserveExecutionResult{}, ErrOwnerDeviceGroupOfflineRequired
	}
	if group.ownerDeviceGroupReopenRequiredLocked() {
		return OwnerReserveExecutionResult{}, ErrOwnerDeviceGroupReopenRequired
	}
	ownerState, err := group.ownerStateLocked()
	if err != nil {
		return OwnerReserveExecutionResult{}, err
	}
	preparing, present, err := ownerReserveActivePreparing(ownerState)
	if err != nil {
		return OwnerReserveExecutionResult{}, group.ownerReserveFailureLocked(err, true, true)
	}
	if transitional, blocked := ownerReserveTransitionalRecord(ownerState); blocked {
		return OwnerReserveExecutionResult{}, fmt.Errorf(
			"%w: allocation %d remains in state %d",
			ErrOwnerReserveTransitionBlocked,
			transitional.AllocationRecordID,
			transitional.State)
	}
	if !present {
		return OwnerReserveExecutionResult{}, ErrOwnerReserveNoPreparing
	}
	return group.recoverPreparingLocked(ownerState, preparing, OwnerReserveReplay)
}

func ownerReserveExecutionResult(
	outcome OwnerReserveOutcome,
	record OwnerStateAllocationRecord,
	forwardRecovered bool,
) OwnerReserveExecutionResult {
	return OwnerReserveExecutionResult{
		Outcome:          outcome,
		Record:           cloneOwnerStateRecord(record),
		ForwardRecovered: forwardRecovered,
	}
}

func (group *OwnerDeviceGroup) ownerStateLocked() (OwnerStateSnapshot, error) {
	if group == nil || group.anchor == nil {
		return OwnerStateSnapshot{}, ErrOwnerDeviceGroupInput
	}
	_, ownerState, present := group.anchor.ActiveOwnerState()
	if !present {
		return OwnerStateSnapshot{}, ownerDeviceGroupMismatchf(
			"ANCHOR has no selected Owner state")
	}
	if err := ownerState.CrossCheckBootstrap(group.bootstrap); err != nil {
		return OwnerStateSnapshot{}, ownerDeviceGroupMismatchf(
			"ANCHOR Owner state: %v", err)
	}
	return ownerState, nil
}

func ownerReserveActivePreparing(
	ownerState OwnerStateSnapshot,
) (OwnerStateAllocationRecord, bool, error) {
	records := ownerState.Records()
	preparingIndex := -1
	for index := range records {
		if records[index].State != OwnerAllocationPreparing {
			continue
		}
		if preparingIndex >= 0 {
			return OwnerStateAllocationRecord{}, false, ownerAllocatorInputMismatchf(
				"Owner state contains multiple PREPARING allocations %d and %d",
				records[preparingIndex].AllocationRecordID,
				records[index].AllocationRecordID)
		}
		preparingIndex = index
	}
	if preparingIndex < 0 {
		return OwnerStateAllocationRecord{}, false, nil
	}
	if preparingIndex != len(records)-1 {
		return OwnerStateAllocationRecord{}, false, ownerAllocatorInputMismatchf(
			"PREPARING allocation %d is not the last Owner record",
			records[preparingIndex].AllocationRecordID)
	}
	record := records[preparingIndex]
	wantNextAllocation, ok := checkedAdd(record.AllocationRecordID, 1)
	if !ok || ownerState.NextAllocationRecordID != wantNextAllocation {
		return OwnerStateAllocationRecord{}, false, ownerAllocatorInputMismatchf(
			"PREPARING allocation %d requires next allocation ID %d, found %d",
			record.AllocationRecordID,
			wantNextAllocation,
			ownerState.NextAllocationRecordID)
	}
	wantNextTransaction, ok := checkedAdd(record.OwnerTransactionSequence, 1)
	if !ok || ownerState.NextOwnerTransactionSequence != wantNextTransaction {
		return OwnerStateAllocationRecord{}, false, ownerAllocatorInputMismatchf(
			"PREPARING transaction %d requires Owner next transaction %d, found %d",
			record.OwnerTransactionSequence,
			wantNextTransaction,
			ownerState.NextOwnerTransactionSequence)
	}
	return record, true, nil
}

func ownerReserveTransitionalRecord(
	ownerState OwnerStateSnapshot,
) (OwnerStateAllocationRecord, bool) {
	for _, record := range ownerState.Records() {
		switch record.State {
		case OwnerAllocationCommitting,
			OwnerAllocationAborting,
			OwnerAllocationReclaiming:
			return record, true
		}
	}
	return OwnerStateAllocationRecord{}, false
}

func ownerReserveRecordIsTerminal(record OwnerStateAllocationRecord) bool {
	switch record.State {
	case OwnerAllocationPreparing,
		OwnerAllocationCommitting,
		OwnerAllocationAborting,
		OwnerAllocationReclaiming:
		return false
	default:
		return record.State.valid()
	}
}

func ownerReserveExactRequestReplay(
	ownerState OwnerStateSnapshot,
	request OwnerReserveRequest,
) (OwnerStateAllocationRecord, bool, error) {
	totalDemandPages, err := validateOwnerReserveRequestAgainstState(request, ownerState)
	if err != nil {
		return OwnerStateAllocationRecord{}, false, err
	}
	requestSHA256, err := OwnerReserveRequestSHA256(request)
	if err != nil {
		return OwnerStateAllocationRecord{}, false, err
	}
	return ownerReserveReplay(ownerState, request, requestSHA256, totalDemandPages)
}

func (group *OwnerDeviceGroup) ownerReserveFailureLocked(
	cause error,
	recoveryRequired bool,
	abortRequired bool,
) error {
	if cause == nil {
		cause = errors.New("unspecified Owner reserve execution failure")
	}
	reopenRequired := group.ownerDeviceGroupReopenRequiredLocked()
	if !recoveryRequired && !abortRequired && !reopenRequired {
		return cause
	}
	return &ownerReserveExecutionError{
		cause:            cause,
		recoveryRequired: recoveryRequired,
		abortRequired:    abortRequired,
		reopenRequired:   reopenRequired,
	}
}

func ownerReserveFailureNeedsAbort(cause error) bool {
	return errors.Is(cause, ErrDeviceMetadataDescriptorConflict) ||
		errors.Is(cause, ErrOwnerReserveAbortRequired)
}

func (group *OwnerDeviceGroup) executeRejectedNoSpaceLocked(
	plan OwnerCheckpointReservePlan,
) (OwnerReserveExecutionResult, error) {
	if plan.Record.State != OwnerAllocationRejectedNoSpace ||
		plan.RejectedOwnerState.SnapshotSequence == 0 {
		return OwnerReserveExecutionResult{}, ownerAllocatorInputMismatchf(
			"REJECTED_NO_SPACE plan has an invalid record or Owner snapshot")
	}
	current, err := group.ownerStateLocked()
	if err != nil {
		return OwnerReserveExecutionResult{}, err
	}
	if err := group.preflightOwnerStateTransitionLocked(
		current,
		plan.RejectedOwnerState,
		group.anchor.ownerStateSlot); err != nil {
		return OwnerReserveExecutionResult{}, err
	}
	if err := group.anchor.commitOwnerState(plan.RejectedOwnerState); err != nil {
		return OwnerReserveExecutionResult{}, group.ownerReserveFailureLocked(err, false, false)
	}
	if err := group.refreshOwnerDeviceGroupMetadataLocked(); err != nil {
		group.executionState.reopenRequired = true
		return OwnerReserveExecutionResult{}, group.ownerReserveFailureLocked(err, false, false)
	}
	selected, err := group.ownerStateLocked()
	if err != nil {
		return OwnerReserveExecutionResult{}, err
	}
	replay, found := reservedDescriptorOwnerRecord(
		selected,
		plan.Record.AllocationRecordID)
	if !found || !reservedDescriptorRecordsEqual(replay, plan.Record) ||
		!ownerStateSnapshotsCanonicalEqual(
			selected,
			plan.RejectedOwnerState,
			group.anchor.geometry) {
		group.executionState.reopenRequired = true
		return OwnerReserveExecutionResult{}, group.ownerReserveFailureLocked(
			ownerAllocatorInputMismatchf(
				"freshly selected REJECTED_NO_SPACE record differs from committed plan"),
			false,
			true)
	}
	return ownerReserveExecutionResult(plan.Outcome, replay, false), nil
}

func (group *OwnerDeviceGroup) executeFreshReserveLocked(
	committed OwnerStateSnapshot,
	plan OwnerCheckpointReservePlan,
) (OwnerReserveExecutionResult, error) {
	recoveryPlan, err := group.preflightFreshReserveLocked(committed, plan)
	if err != nil {
		return OwnerReserveExecutionResult{}, err
	}
	if err := group.anchor.commitOwnerState(recoveryPlan.preparingState); err != nil {
		// Any attempted header-last mutation is ambiguous: PREPARING may be the
		// selected durable state even when the call returned an error.
		return OwnerReserveExecutionResult{}, group.ownerReserveFailureLocked(
			err,
			group.anchor.reopenRequired,
			false)
	}
	// Descriptor inspection intentionally follows durable PREPARING: that
	// Owner record is the authority that lets MEMBER devices accept the exact
	// derived descriptor bytes. A pre-existing torn/foreign descriptor can
	// therefore strand PREPARING and require abort/quarantine; it is never
	// overwritten speculatively before the group has durable recovery evidence.
	return group.executePreparingRecoveryPlanLocked(
		recoveryPlan,
		plan.Outcome,
		false)
}

func (group *OwnerDeviceGroup) recoverPreparingLocked(
	ownerState OwnerStateSnapshot,
	preparing OwnerStateAllocationRecord,
	outcome OwnerReserveOutcome,
) (OwnerReserveExecutionResult, error) {
	recoveryPlan, err := group.buildPreparingRecoveryPlanLocked(ownerState, preparing)
	if err != nil {
		return OwnerReserveExecutionResult{}, group.ownerReserveFailureLocked(err, true, true)
	}
	return group.executePreparingRecoveryPlanLocked(recoveryPlan, outcome, true)
}

func (group *OwnerDeviceGroup) executePreparingRecoveryPlanLocked(
	recoveryPlan ownerReserveRecoveryPlan,
	outcome OwnerReserveOutcome,
	forwardRecovered bool,
) (OwnerReserveExecutionResult, error) {
	// Descriptor and allocator metadata deliberately remain at PREPARING
	// transaction N. Only the final Owner record advances to GRANTED N+1.
	preparingTransaction := recoveryPlan.preparingRecord.OwnerTransactionSequence
	if recoveryPlan.grantedRecord.OwnerTransactionSequence != preparingTransaction+1 {
		return OwnerReserveExecutionResult{}, group.ownerReserveFailureLocked(
			ownerAllocatorInputMismatchf(
				"GRANTED transaction does not immediately follow PREPARING transaction"),
			true,
			true)
	}

	// All affected devices establish descriptor durability before the first
	// allocator bitmap can select any reserved page.
	for index := range recoveryPlan.devices {
		entry := recoveryPlan.devices[index]
		device := group.devices[entry.deviceIndex].metadata
		if err := device.persistPreparingReservedDescriptors(
			recoveryPlan.preparingRecord,
			entry.runs); err != nil {
			return OwnerReserveExecutionResult{}, group.ownerReserveFailureLocked(
				err,
				true,
				ownerReserveFailureNeedsAbort(err))
		}
	}

	for index := range recoveryPlan.devices {
		entry := recoveryPlan.devices[index]
		if !entry.beforeApply {
			continue
		}
		device := group.devices[entry.deviceIndex].metadata
		if err := device.commitAllocatorSnapshot(entry.desired); err != nil {
			return OwnerReserveExecutionResult{}, group.ownerReserveFailureLocked(
				err,
				true,
				false)
		}
	}

	// Re-select every device's A/B metadata from storage before trusting cached
	// commit results or exposing GRANTED. Any mismatch poisons this group object.
	if err := group.refreshOwnerDeviceGroupMetadataLocked(); err != nil {
		group.executionState.reopenRequired = true
		return OwnerReserveExecutionResult{}, group.ownerReserveFailureLocked(err, true, false)
	}
	selectedOwner, err := group.ownerStateLocked()
	if err != nil {
		group.executionState.reopenRequired = true
		return OwnerReserveExecutionResult{}, group.ownerReserveFailureLocked(err, true, false)
	}
	selectedPreparing, present, err := ownerReserveActivePreparing(selectedOwner)
	if err != nil || !present ||
		!reservedDescriptorRecordsEqual(selectedPreparing, recoveryPlan.preparingRecord) ||
		!ownerStateSnapshotsCanonicalEqual(
			selectedOwner,
			recoveryPlan.preparingState,
			group.anchor.geometry) {
		if err == nil {
			err = ownerAllocatorInputMismatchf(
				"fresh Owner observation does not contain the exact PREPARING record")
		}
		group.executionState.reopenRequired = true
		return OwnerReserveExecutionResult{}, group.ownerReserveFailureLocked(err, true, true)
	}
	reconciled, err := group.buildPreparingRecoveryPlanLocked(
		selectedOwner,
		selectedPreparing)
	if err != nil {
		group.executionState.reopenRequired = true
		return OwnerReserveExecutionResult{}, group.ownerReserveFailureLocked(err, true, true)
	}
	for index := range reconciled.devices {
		if reconciled.devices[index].beforeApply {
			group.executionState.reopenRequired = true
			return OwnerReserveExecutionResult{}, group.ownerReserveFailureLocked(
				ownerAllocatorInputMismatchf(
					"device %q allocator remained before target after commit",
					reconciled.devices[index].deviceUUID),
				true,
				true)
		}
		device := group.devices[reconciled.devices[index].deviceIndex].metadata
		if err := verifyOwnerReserveDescriptorsExact(
			device,
			reconciled.devices[index].runs); err != nil {
			group.executionState.reopenRequired = true
			return OwnerReserveExecutionResult{}, group.ownerReserveFailureLocked(
				err,
				true,
				true)
		}
	}
	if !ownerStateSnapshotsCanonicalEqual(
		reconciled.grantedState,
		recoveryPlan.grantedState,
		group.anchor.geometry) ||
		!reservedDescriptorRecordsEqual(
			reconciled.grantedRecord,
			recoveryPlan.grantedRecord) {
		group.executionState.reopenRequired = true
		return OwnerReserveExecutionResult{}, group.ownerReserveFailureLocked(
			ownerAllocatorInputMismatchf(
				"fresh reconciliation derived a different GRANTED transition"),
			true,
			true)
	}

	if err := group.anchor.commitOwnerState(reconciled.grantedState); err != nil {
		return OwnerReserveExecutionResult{}, group.ownerReserveFailureLocked(err, true, false)
	}
	// Do not expose the grant until the final Owner Sync has completed and a
	// fresh selector observes the exact GRANTED snapshot.
	if err := group.refreshOwnerDeviceGroupMetadataLocked(); err != nil {
		group.executionState.reopenRequired = true
		return OwnerReserveExecutionResult{}, group.ownerReserveFailureLocked(err, true, false)
	}
	grantedOwner, err := group.ownerStateLocked()
	if err != nil {
		group.executionState.reopenRequired = true
		return OwnerReserveExecutionResult{}, group.ownerReserveFailureLocked(err, true, false)
	}
	selectedGrant, found := reservedDescriptorOwnerRecord(
		grantedOwner,
		reconciled.grantedRecord.AllocationRecordID)
	if !found || !reservedDescriptorRecordsEqual(selectedGrant, reconciled.grantedRecord) ||
		!ownerStateSnapshotsCanonicalEqual(
			grantedOwner,
			reconciled.grantedState,
			group.anchor.geometry) {
		group.executionState.reopenRequired = true
		return OwnerReserveExecutionResult{}, group.ownerReserveFailureLocked(
			ownerAllocatorInputMismatchf(
				"fresh Owner observation does not contain the exact GRANTED record"),
			true,
			true)
	}
	return ownerReserveExecutionResult(outcome, selectedGrant, forwardRecovered), nil
}

func (group *OwnerDeviceGroup) preflightFreshReserveLocked(
	committed OwnerStateSnapshot,
	plan OwnerCheckpointReservePlan,
) (ownerReserveRecoveryPlan, error) {
	preparingRecord, present, err := ownerReserveActivePreparing(plan.PreparingOwnerState)
	if err != nil || !present {
		if err == nil {
			err = ownerAllocatorInputMismatchf(
				"PLANNED result has no exact last PREPARING record")
		}
		return ownerReserveRecoveryPlan{}, err
	}
	recoveryPlan, err := group.buildPreparingRecoveryPlanLocked(
		plan.PreparingOwnerState,
		preparingRecord)
	if err != nil {
		return ownerReserveRecoveryPlan{}, err
	}
	if !ownerStateSnapshotsCanonicalEqual(
		recoveryPlan.grantedState,
		plan.GrantedOwnerState,
		group.anchor.geometry) ||
		!reservedDescriptorRecordsEqual(recoveryPlan.grantedRecord, plan.Record) {
		return ownerReserveRecoveryPlan{}, ownerAllocatorInputMismatchf(
			"planner GRANTED output differs from PREPARING-derived transition")
	}
	if err := group.preflightOwnerStateTransitionLocked(
		committed,
		plan.PreparingOwnerState,
		group.anchor.ownerStateSlot); err != nil {
		return ownerReserveRecoveryPlan{}, err
	}
	preparingSlot := otherOwnerStateSlot(group.anchor.ownerStateSlot)
	if err := group.preflightOwnerStateTransitionLocked(
		plan.PreparingOwnerState,
		recoveryPlan.grantedState,
		preparingSlot); err != nil {
		return ownerReserveRecoveryPlan{}, err
	}

	updates := make(map[string]OwnerAllocatorSnapshotUpdate, len(plan.AllocatorUpdates))
	for _, update := range plan.AllocatorUpdates {
		if _, exists := updates[update.DeviceUUID]; exists {
			return ownerReserveRecoveryPlan{}, ownerAllocatorInputMismatchf(
				"planner repeats allocator update for device %q", update.DeviceUUID)
		}
		updates[update.DeviceUUID] = update
	}
	if len(updates) != len(recoveryPlan.devices) {
		return ownerReserveRecoveryPlan{}, ownerAllocatorInputMismatchf(
			"planner allocator update count %d differs from affected device count %d",
			len(updates),
			len(recoveryPlan.devices))
	}
	for index := range recoveryPlan.devices {
		entry := &recoveryPlan.devices[index]
		if !entry.beforeApply {
			return ownerReserveRecoveryPlan{}, ownerAllocatorInputMismatchf(
				"fresh device %q allocator is already at the target", entry.deviceUUID)
		}
		update, exists := updates[entry.deviceUUID]
		current := group.devices[entry.deviceIndex].metadata.allocator
		if !exists || update.PreviousSnapshotSequence != current.SnapshotSequence ||
			!allocatorSnapshotsExactEqual(update.DesiredSnapshot, entry.desired) {
			return ownerReserveRecoveryPlan{}, ownerAllocatorInputMismatchf(
				"planner allocator update for device %q differs from record-derived target",
				entry.deviceUUID)
		}
	}
	expectedDescriptors, err := ownerReserveDescriptorsFromRecord(preparingRecord)
	if err != nil {
		return ownerReserveRecoveryPlan{}, err
	}
	if !ownerReserveDescriptorRunsEqual(expectedDescriptors, plan.ReservedDescriptors) {
		return ownerReserveRecoveryPlan{}, ownerAllocatorInputMismatchf(
			"planner RESERVED descriptor runs differ from PREPARING record")
	}
	return recoveryPlan, nil
}

func (group *OwnerDeviceGroup) buildPreparingRecoveryPlanLocked(
	preparingState OwnerStateSnapshot,
	preparingRecord OwnerStateAllocationRecord,
) (ownerReserveRecoveryPlan, error) {
	active, present, err := ownerReserveActivePreparing(preparingState)
	if err != nil || !present ||
		!reservedDescriptorRecordsEqual(active, preparingRecord) {
		if err == nil {
			err = ownerAllocatorInputMismatchf(
				"Owner state does not contain the exact supplied PREPARING record")
		}
		return ownerReserveRecoveryPlan{}, err
	}
	if err := preparingState.CrossCheckBootstrap(group.bootstrap); err != nil {
		return ownerReserveRecoveryPlan{}, err
	}
	grantedState, grantedRecord, err := ownerReserveGrantFromPreparing(
		preparingState,
		preparingRecord,
		group.anchor.geometry)
	if err != nil {
		return ownerReserveRecoveryPlan{}, err
	}
	if err := group.preflightOwnerStateEncodingLocked(grantedState); err != nil {
		return ownerReserveRecoveryPlan{}, err
	}

	deviceByUUID := make(map[string]OwnerStateDevice, len(group.bootstrap.Devices))
	for _, member := range group.bootstrap.Devices {
		deviceByUUID[member.DeviceUUID] = member
	}
	if err := validateOwnerStateRecord(preparingRecord, deviceByUUID); err != nil {
		return ownerReserveRecoveryPlan{}, ownerAllocatorInputMismatchf(
			"active PREPARING record: %v", err)
	}
	derivedRuns, err := ownerReserveDescriptorsFromRecord(preparingRecord)
	if err != nil {
		return ownerReserveRecoveryPlan{}, err
	}
	runsByDevice := make(map[string][]OwnerReservedDescriptorRun)
	for _, run := range derivedRuns {
		runsByDevice[run.DeviceUUID] = append(runsByDevice[run.DeviceUUID], run)
	}
	indexByUUID := make(map[string]int, len(group.devices))
	for index := range group.devices {
		indexByUUID[group.devices[index].deviceUUID] = index
	}

	devices := make([]ownerReserveRecoveryDevice, 0, len(preparingRecord.Fragments))
	affected := make(map[string]bool, len(preparingRecord.Fragments))
	for _, fragment := range preparingRecord.Fragments {
		deviceIndex, exists := indexByUUID[fragment.DeviceUUID]
		member, memberExists := deviceByUUID[fragment.DeviceUUID]
		if !exists || !memberExists || affected[fragment.DeviceUUID] {
			return ownerReserveRecoveryPlan{}, ownerAllocatorInputMismatchf(
				"PREPARING fragment device %q is missing, extra, or duplicated",
				fragment.DeviceUUID)
		}
		if fragment.DeviceOwnerEpoch != member.DeviceOwnerEpoch ||
			fragment.DeviceOwnerEpoch != group.devices[deviceIndex].metadata.superblock.OwnerEpoch {
			return ownerReserveRecoveryPlan{}, ownerAllocatorInputMismatchf(
				"PREPARING fragment device %q Owner epoch differs", fragment.DeviceUUID)
		}
		affected[fragment.DeviceUUID] = true
		entry, err := group.classifyPreparingAllocatorLocked(
			deviceIndex,
			fragment,
			preparingRecord.OwnerTransactionSequence,
			preparingState.NextOwnerTransactionSequence)
		if err != nil {
			return ownerReserveRecoveryPlan{}, err
		}
		entry.runs = append(
			[]OwnerReservedDescriptorRun(nil),
			runsByDevice[fragment.DeviceUUID]...)
		if len(entry.runs) == 0 {
			return ownerReserveRecoveryPlan{}, ownerAllocatorInputMismatchf(
				"PREPARING fragment device %q derived no descriptors", fragment.DeviceUUID)
		}
		devices = append(devices, entry)
	}
	for index := range group.devices {
		if affected[group.devices[index].deviceUUID] {
			continue
		}
		applied := group.devices[index].metadata.allocator.AppliedOwnerTransactionSequence
		if applied >= preparingRecord.OwnerTransactionSequence {
			return ownerReserveRecoveryPlan{}, ownerAllocatorInputMismatchf(
				"unaffected device %q carries foreign applied transaction %d at/after PREPARING %d",
				group.devices[index].deviceUUID,
				applied,
				preparingRecord.OwnerTransactionSequence)
		}
	}
	sort.Slice(devices, func(left, right int) bool {
		return devices[left].deviceUUID < devices[right].deviceUUID
	})
	return ownerReserveRecoveryPlan{
		preparingState:  preparingState.Clone(),
		preparingRecord: cloneOwnerStateRecord(preparingRecord),
		grantedState:    grantedState,
		grantedRecord:   grantedRecord,
		devices:         devices,
	}, nil
}

func (group *OwnerDeviceGroup) classifyPreparingAllocatorLocked(
	deviceIndex int,
	fragment OwnerStateDeviceFragment,
	preparingTransaction uint64,
	issuedTransactionHighWater uint64,
) (ownerReserveRecoveryDevice, error) {
	if deviceIndex < 0 || deviceIndex >= len(group.devices) {
		return ownerReserveRecoveryDevice{}, ownerAllocatorInputMismatchf(
			"affected device index %d is outside the group", deviceIndex)
	}
	opened := group.devices[deviceIndex]
	if opened.metadata == nil || opened.deviceUUID != fragment.DeviceUUID {
		return ownerReserveRecoveryDevice{}, ownerAllocatorInputMismatchf(
			"affected device %q does not match opened group", fragment.DeviceUUID)
	}
	current := opened.metadata.allocator
	if err := current.CrossCheck(
		opened.geometry,
		opened.metadata.superblock.DeviceBindingSHA256(),
		opened.metadata.superblock.OwnerGroupIdentitySHA256(),
		opened.metadata.superblock.OwnerEpoch); err != nil {
		return ownerReserveRecoveryDevice{}, ownerAllocatorInputMismatchf(
			"device %q active allocator: %v", fragment.DeviceUUID, err)
	}
	nextSequence, sequenceOK := checkedAdd(current.SnapshotSequence, 1)
	beforeApply := sequenceOK &&
		nextSequence == fragment.TargetAllocatorSnapshotSequence &&
		current.AppliedOwnerTransactionSequence < preparingTransaction
	afterApply := current.SnapshotSequence == fragment.TargetAllocatorSnapshotSequence &&
		current.AppliedOwnerTransactionSequence == preparingTransaction
	if !beforeApply && !afterApply {
		return ownerReserveRecoveryDevice{}, ownerAllocatorInputMismatchf(
			"device %q allocator %d/%d is neither before nor after PREPARING target %d/%d",
			fragment.DeviceUUID,
			current.SnapshotSequence,
			current.AppliedOwnerTransactionSequence,
			fragment.TargetAllocatorSnapshotSequence,
			preparingTransaction)
	}

	bitmap := current.BitmapBytes()
	for _, extent := range fragment.Extents {
		end, ok := checkedAdd(extent.StartDataPageIndex, extent.PageCount)
		if !ok || end > current.DataPageCount {
			return ownerReserveRecoveryDevice{}, ownerAllocatorInputMismatchf(
				"device %q PREPARING extent exceeds allocator", fragment.DeviceUUID)
		}
		for page := extent.StartDataPageIndex; page < end; page++ {
			unavailable := ownerAllocatorBitmapSet(bitmap, page)
			if unavailable != afterApply {
				want := "FREE before allocator application"
				if afterApply {
					want = "ALLOCATED after allocator application"
				}
				return ownerReserveRecoveryDevice{}, ownerAllocatorInputMismatchf(
					"device %q page %d is not %s",
					fragment.DeviceUUID,
					page,
					want)
			}
			if beforeApply {
				ownerAllocatorSetBitmap(bitmap, page)
			}
		}
	}
	desired := current.Clone()
	if beforeApply {
		var err error
		desired, err = NewAllocatorSnapshot(AllocatorSnapshotConfig{
			DeviceBindingSHA256:             current.DeviceBindingSHA256,
			OwnerGroupIdentitySHA256:        current.OwnerGroupIdentitySHA256,
			OwnerEpoch:                      current.OwnerEpoch,
			SnapshotSequence:                fragment.TargetAllocatorSnapshotSequence,
			AppliedOwnerTransactionSequence: preparingTransaction,
			DataPageCount:                   current.DataPageCount,
		}, bitmap)
		if err != nil {
			return ownerReserveRecoveryDevice{}, err
		}
		if err := group.preflightAllocatorCommitLocked(
			opened.metadata,
			desired,
			issuedTransactionHighWater); err != nil {
			return ownerReserveRecoveryDevice{}, err
		}
	} else if _, err := CanonicalAllocatorSnapshotBytes(desired, opened.geometry); err != nil {
		return ownerReserveRecoveryDevice{}, err
	}
	return ownerReserveRecoveryDevice{
		deviceIndex: deviceIndex,
		deviceUUID:  fragment.DeviceUUID,
		fragment:    cloneOwnerStateFragment(fragment),
		desired:     desired,
		beforeApply: beforeApply,
	}, nil
}

func ownerReserveDescriptorsFromRecord(
	record OwnerStateAllocationRecord,
) ([]OwnerReservedDescriptorRun, error) {
	placed := make([]ownerAllocatorPlacedRun, 0, record.MaxExtents)
	for _, fragment := range record.Fragments {
		for _, extent := range fragment.Extents {
			placed = append(placed, ownerAllocatorPlacedRun{
				DeviceUUID:         fragment.DeviceUUID,
				StartDataPageIndex: extent.StartDataPageIndex,
				LogicalPageStart:   extent.LogicalPageStart,
				PageCount:          extent.PageCount,
			})
		}
	}
	sort.Slice(placed, func(left, right int) bool {
		if placed[left].LogicalPageStart != placed[right].LogicalPageStart {
			return placed[left].LogicalPageStart < placed[right].LogicalPageStart
		}
		if placed[left].DeviceUUID != placed[right].DeviceUUID {
			return placed[left].DeviceUUID < placed[right].DeviceUUID
		}
		return placed[left].StartDataPageIndex < placed[right].StartDataPageIndex
	})
	runs, err := ownerReserveDescriptorRuns(
		record.ContentDemands,
		placed,
		record.AllocationRecordID,
		record.OwnerTransactionSequence)
	if err != nil {
		return nil, ownerAllocatorInputMismatchf(
			"derive RESERVED descriptors from PREPARING record: %v", err)
	}
	for _, run := range runs {
		if run.Descriptor.State != DescriptorReserved ||
			run.Descriptor.OwnerTransactionSeq != record.OwnerTransactionSequence {
			return nil, ownerAllocatorInputMismatchf(
				"derived descriptor does not retain PREPARING transaction %d",
				record.OwnerTransactionSequence)
		}
	}
	return runs, nil
}

func ownerReserveGrantFromPreparing(
	preparingState OwnerStateSnapshot,
	preparingRecord OwnerStateAllocationRecord,
	anchorGeometry DeviceGeometry,
) (OwnerStateSnapshot, OwnerStateAllocationRecord, error) {
	active, present, err := ownerReserveActivePreparing(preparingState)
	if err != nil || !present ||
		!reservedDescriptorRecordsEqual(active, preparingRecord) {
		if err == nil {
			err = ownerAllocatorInputMismatchf(
				"cannot derive GRANTED without exact last PREPARING record")
		}
		return OwnerStateSnapshot{}, OwnerStateAllocationRecord{}, err
	}
	grantedTransaction, err := ownerReserveAddSequence(
		preparingRecord.OwnerTransactionSequence,
		1,
		"recovered GRANTED record transaction")
	if err != nil {
		return OwnerStateSnapshot{}, OwnerStateAllocationRecord{}, err
	}
	if grantedTransaction != preparingState.NextOwnerTransactionSequence {
		return OwnerStateSnapshot{}, OwnerStateAllocationRecord{}, ownerAllocatorInputMismatchf(
			"GRANTED transaction %d differs from PREPARING next transaction %d",
			grantedTransaction,
			preparingState.NextOwnerTransactionSequence)
	}
	grantedSnapshotSequence, err := ownerReserveAddSequence(
		preparingState.SnapshotSequence,
		1,
		"recovered GRANTED Owner-state snapshot sequence")
	if err != nil {
		return OwnerStateSnapshot{}, OwnerStateAllocationRecord{}, err
	}
	grantedNextTransaction, err := ownerReserveAddSequence(
		preparingState.NextOwnerTransactionSequence,
		1,
		"post-recovered-GRANTED Owner transaction")
	if err != nil {
		return OwnerStateSnapshot{}, OwnerStateAllocationRecord{}, err
	}
	grantedRecord := cloneOwnerStateRecord(preparingRecord)
	grantedRecord.State = OwnerAllocationGranted
	grantedRecord.OwnerTransactionSequence = grantedTransaction
	grantedState, err := ownerReserveReplaceLastRecordSnapshot(
		preparingState,
		grantedRecord,
		grantedSnapshotSequence,
		preparingState.NextAllocationRecordID,
		grantedNextTransaction,
		anchorGeometry)
	if err != nil {
		return OwnerStateSnapshot{}, OwnerStateAllocationRecord{}, err
	}
	return grantedState, grantedRecord, nil
}

func ownerReserveDescriptorRunsEqual(
	left, right []OwnerReservedDescriptorRun,
) bool {
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

func allocatorSnapshotsExactEqual(left, right AllocatorSnapshot) bool {
	return left.DeviceBindingSHA256 == right.DeviceBindingSHA256 &&
		left.OwnerGroupIdentitySHA256 == right.OwnerGroupIdentitySHA256 &&
		left.OwnerEpoch == right.OwnerEpoch &&
		left.SnapshotSequence == right.SnapshotSequence &&
		left.AppliedOwnerTransactionSequence == right.AppliedOwnerTransactionSequence &&
		left.DataPageCount == right.DataPageCount &&
		left.AllocatedPageCount == right.AllocatedPageCount &&
		left.BitmapByteLength == right.BitmapByteLength &&
		bytes.Equal(left.allocationBitmap, right.allocationBitmap)
}

func ownerStateSnapshotsCanonicalEqual(
	left, right OwnerStateSnapshot,
	geometry DeviceGeometry,
) bool {
	leftWire, leftErr := CanonicalOwnerStateBytes(left, geometry)
	rightWire, rightErr := CanonicalOwnerStateBytes(right, geometry)
	return leftErr == nil && rightErr == nil && bytes.Equal(leftWire, rightWire)
}

func cloneOwnerStateFragment(source OwnerStateDeviceFragment) OwnerStateDeviceFragment {
	source.Extents = append([]OwnerStateExtent(nil), source.Extents...)
	return source
}

func (group *OwnerDeviceGroup) preflightOwnerStateEncodingLocked(
	next OwnerStateSnapshot,
) error {
	if group == nil || group.anchor == nil {
		return ErrOwnerDeviceGroupInput
	}
	if err := next.CrossCheckBootstrap(group.bootstrap); err != nil {
		return err
	}
	exact, err := CanonicalOwnerStateBytes(next, group.anchor.geometry)
	if err != nil {
		return err
	}
	if uint64(len(exact)) > group.anchor.ownerStateReadLimitBytes {
		return fmt.Errorf(
			"%w: preflight envelope %d exceeds opened policy %d",
			ErrDeviceMetadataOwnerStateReadLimit,
			len(exact),
			group.anchor.ownerStateReadLimitBytes)
	}
	return nil
}

func (group *OwnerDeviceGroup) preflightOwnerStateTransitionLocked(
	current OwnerStateSnapshot,
	next OwnerStateSnapshot,
	currentSlot OwnerStateSlot,
) error {
	if group == nil || group.anchor == nil || !group.anchor.ownerStatePresent ||
		group.anchor.superblock.OwnerGroupRole != OwnerGroupRoleAnchor {
		return fmt.Errorf("%w: group has no writable ANCHOR Owner state",
			ErrDeviceMetadataRoleMismatch)
	}
	if group.anchor.reopenRequired {
		return ErrOwnerDeviceGroupReopenRequired
	}
	if err := validateMetadataStorageSize(
		group.anchor.storage,
		group.anchor.geometry); err != nil {
		return err
	}
	wantSequence, ok := checkedAdd(current.SnapshotSequence, 1)
	if !ok || wantSequence > cxlcheckpoint.MaxSignedLong ||
		next.SnapshotSequence != wantSequence {
		return fmt.Errorf(
			"%w: preflight Owner-state sequence %d, expected %d",
			ErrDeviceMetadataSequence,
			next.SnapshotSequence,
			wantSequence)
	}
	if next.NextAllocationRecordID < current.NextAllocationRecordID ||
		next.NextOwnerTransactionSequence <= current.NextOwnerTransactionSequence {
		return fmt.Errorf(
			"%w: preflight Owner high-water transition regresses or does not advance",
			ErrDeviceMetadataSequence)
	}
	if err := group.preflightOwnerStateEncodingLocked(next); err != nil {
		return err
	}
	targetSlot := otherOwnerStateSlot(currentSlot)
	if !currentSlot.valid() || !targetSlot.valid() {
		return fmt.Errorf("%w: invalid Owner-state A/B selection",
			ErrDeviceMetadataSequence)
	}
	offset, err := ownerStateSlotOffset(group.anchor.geometry, targetSlot)
	if err != nil {
		return err
	}
	_, err = metadataIOPosition(
		group.anchor.geometry.DeviceBytes,
		offset,
		group.anchor.geometry.OwnerStateSnapshotSlotBytes)
	return err
}

func (group *OwnerDeviceGroup) preflightAllocatorCommitLocked(
	device *DeviceMetadata,
	next AllocatorSnapshot,
	issuedTransactionHighWater uint64,
) error {
	if device == nil || device.storage == nil {
		return fmt.Errorf("%w: opened device is nil", ErrDeviceMetadataStorage)
	}
	if device.reopenRequired {
		return ErrOwnerDeviceGroupReopenRequired
	}
	if err := validateMetadataStorageSize(device.storage, device.geometry); err != nil {
		return err
	}
	wantSequence, ok := checkedAdd(device.allocator.SnapshotSequence, 1)
	if !ok || wantSequence > cxlcheckpoint.MaxSignedLong ||
		next.SnapshotSequence != wantSequence {
		return fmt.Errorf(
			"%w: preflight allocator sequence %d, expected %d",
			ErrDeviceMetadataSequence,
			next.SnapshotSequence,
			wantSequence)
	}
	if next.AppliedOwnerTransactionSequence <
		device.allocator.AppliedOwnerTransactionSequence {
		return fmt.Errorf("%w: preflight allocator applied transaction regresses",
			ErrDeviceMetadataSequence)
	}
	bitmapChanged := !bytes.Equal(
		next.allocationBitmap,
		device.allocator.allocationBitmap)
	transactionAdvanced := next.AppliedOwnerTransactionSequence >
		device.allocator.AppliedOwnerTransactionSequence
	if (bitmapChanged && !transactionAdvanced) ||
		(!bitmapChanged && !transactionAdvanced) {
		return fmt.Errorf(
			"%w: preflight allocator update is not a legal bitmap/transaction advance",
			ErrDeviceMetadataSequence)
	}
	if next.AppliedOwnerTransactionSequence >= issuedTransactionHighWater {
		return fmt.Errorf(
			"%w: allocator transaction %d is not issued below PREPARING high-water %d",
			ErrDeviceMetadataSequence,
			next.AppliedOwnerTransactionSequence,
			issuedTransactionHighWater)
	}
	exact, err := CanonicalAllocatorSnapshotBytes(next, device.geometry)
	if err != nil {
		return err
	}
	targetAllocatorSlot := otherSuperblockSlot(
		device.superblock.ActiveAllocatorSnapshotSlot)
	targetSuperblockSlot := otherSuperblockSlot(device.superblockSlot)
	if !targetAllocatorSlot.valid() || !targetSuperblockSlot.valid() {
		return fmt.Errorf("%w: invalid allocator/superblock A/B selection",
			ErrDeviceMetadataSequence)
	}
	nextSuperblockSequence, ok := checkedAdd(
		device.superblock.SuperblockSequence,
		1)
	if !ok || nextSuperblockSequence > cxlcheckpoint.MaxSignedLong {
		return fmt.Errorf("%w: preflight superblock sequence overflows",
			ErrDeviceMetadataSequence)
	}
	nextSuperblock := device.superblock
	nextSuperblock.SuperblockSequence = nextSuperblockSequence
	nextSuperblock.ActiveAllocatorSnapshotSlot = targetAllocatorSlot
	nextSuperblock.ActiveAllocatorSnapshotSequence = next.SnapshotSequence
	nextSuperblock.ActiveAllocatorSnapshotLength = uint64(len(exact))
	nextSuperblock.ActiveAllocatorSnapshotSHA256 = sha256.Sum256(exact)
	if err := validateAllocatorSnapshotAgainstSuperblock(
		nextSuperblock,
		next,
		exact); err != nil {
		return err
	}
	if _, err := CanonicalSuperblockBytes(nextSuperblock); err != nil {
		return err
	}
	allocatorOffset, err := allocatorSnapshotSlotOffset(
		device.geometry,
		targetAllocatorSlot)
	if err != nil {
		return err
	}
	if _, err := metadataIOPosition(
		device.geometry.DeviceBytes,
		allocatorOffset,
		device.geometry.AllocatorSnapshotSlotBytes); err != nil {
		return err
	}
	superblockOffset, err := superblockSlotOffset(
		device.geometry,
		targetSuperblockSlot)
	if err != nil {
		return err
	}
	_, err = metadataIOPosition(
		device.geometry.DeviceBytes,
		superblockOffset,
		SuperblockSlotBytes)
	return err
}

func (group *OwnerDeviceGroup) refreshOwnerDeviceGroupMetadataLocked() error {
	if group == nil || group.anchor == nil || len(group.devices) == 0 {
		return ErrOwnerDeviceGroupInput
	}
	refreshed := make([]*DeviceMetadata, len(group.devices))
	anchorIndex := -1
	for index := range group.devices {
		current := group.devices[index]
		if current.metadata == nil || current.metadata.storage == nil {
			return fmt.Errorf("%w: device %q has no storage",
				ErrDeviceMetadataStorage,
				current.deviceUUID)
		}
		opened, err := OpenDeviceMetadata(
			current.metadata.storage,
			DeviceOpenInput{
				Geometry:                 current.geometry,
				OwnerStateBootstrap:      group.bootstrap,
				OwnerStateReadLimitBytes: current.metadata.ownerStateReadLimitBytes,
			})
		if err != nil {
			return fmt.Errorf("refresh Owner-group device %q: %w",
				current.deviceUUID,
				err)
		}
		_, superblock := opened.ActiveSuperblock()
		if superblock.DeviceUUID != current.deviceUUID ||
			superblock.Geometry != current.geometry {
			return ownerDeviceGroupMismatchf(
				"refreshed device expected as %q selected a different identity/geometry",
				current.deviceUUID)
		}
		expectedRole := OwnerGroupRoleMember
		if current.deviceUUID == group.bootstrap.AnchorDeviceUUID {
			expectedRole = OwnerGroupRoleAnchor
			anchorIndex = index
		}
		if superblock.OwnerGroupRole != expectedRole {
			return ownerDeviceGroupMismatchf(
				"refreshed device %q role %s differs from expected %s",
				current.deviceUUID,
				superblock.OwnerGroupRole,
				expectedRole)
		}
		refreshed[index] = opened
	}
	if anchorIndex < 0 || refreshed[anchorIndex] == nil {
		return ownerDeviceGroupMismatchf("refreshed group has no ANCHOR")
	}
	_, ownerState, present := refreshed[anchorIndex].ActiveOwnerState()
	if !present {
		return ownerDeviceGroupMismatchf("refreshed ANCHOR has no Owner state")
	}
	if err := ownerState.CrossCheckBootstrap(group.bootstrap); err != nil {
		return ownerDeviceGroupMismatchf("refreshed ANCHOR Owner state: %v", err)
	}
	for index := range refreshed {
		_, allocator := refreshed[index].ActiveAllocatorSnapshot()
		if allocator.AppliedOwnerTransactionSequence >=
			ownerState.NextOwnerTransactionSequence {
			return ownerDeviceGroupMismatchf(
				"refreshed device %q applied transaction %d is not below Owner next %d",
				group.devices[index].deviceUUID,
				allocator.AppliedOwnerTransactionSequence,
				ownerState.NextOwnerTransactionSequence)
		}
	}
	for index := range group.devices {
		group.devices[index].metadata = refreshed[index]
	}
	group.anchor = refreshed[anchorIndex]
	return nil
}

func verifyOwnerReserveDescriptorsExact(
	device *DeviceMetadata,
	runs []OwnerReservedDescriptorRun,
) error {
	if device == nil || device.storage == nil {
		return fmt.Errorf("%w: opened device is nil", ErrDeviceMetadataStorage)
	}
	buffer := make([]byte, reservedDescriptorIOBatchBytes)
	for _, run := range runs {
		wire, err := run.Descriptor.MarshalBinary()
		if err != nil {
			return err
		}
		for pageOffset := uint64(0); pageOffset < run.PageCount; {
			batchPages := run.PageCount - pageOffset
			if batchPages > uint64(reservedDescriptorIOBatchBytes/PageDescriptorBytes) {
				batchPages = uint64(reservedDescriptorIOBatchBytes / PageDescriptorBytes)
			}
			batchBytes := batchPages * uint64(PageDescriptorBytes)
			offset, err := device.geometry.DescriptorOffset(
				run.StartDataPageIndex + pageOffset)
			if err != nil {
				return err
			}
			batch := buffer[:int(batchBytes)]
			if err := readMetadataExactAt(
				device.storage,
				device.geometry.DeviceBytes,
				batch,
				offset); err != nil {
				return fmt.Errorf("%w: verify RESERVED descriptors: %v",
					ErrDeviceMetadataStorage,
					err)
			}
			for batchPage := uint64(0); batchPage < batchPages; batchPage++ {
				start := int(batchPage * uint64(PageDescriptorBytes))
				current := batch[start : start+PageDescriptorBytes]
				if !bytes.Equal(current, wire) {
					return reservedDescriptorConflictf(
						current,
						run.StartDataPageIndex+pageOffset+batchPage,
						run.Descriptor)
				}
			}
			pageOffset += batchPages
		}
	}
	return nil
}

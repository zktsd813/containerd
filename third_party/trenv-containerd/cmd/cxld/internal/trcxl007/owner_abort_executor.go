package trcxl007

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"sort"

	"github.com/containerd/containerd/third_party/trenv-containerd/pkg/cxlcheckpoint"
)

var (
	ErrInvalidOwnerPreparingAbortRequest = errors.New(
		"invalid TRCXL007 PREPARING abort request")
	ErrOwnerAbortAuthorityConflict = errors.New(
		"TRCXL007 PREPARING abort authority does not match durable commitment")
	ErrOwnerAbortConflict = errors.New(
		"TRCXL007 PREPARING abort conflicts with durable Owner state")
	ErrOwnerAbortRecoveryRequired = errors.New(
		"TRCXL007 PREPARING abort requires forward recovery")
	ErrOwnerAbortNoAborting = errors.New(
		"TRCXL007 Owner state has no active ABORTING allocation")
	ErrOwnerAbortDurableContradiction = errors.New(
		"TRCXL007 PREPARING abort found an irreconcilable durable contradiction")
)

// OwnerAbortDisposition is checkpoint-global. Per-device clean/quarantine
// choices are forbidden because one checkpoint is the allocation/recovery
// unit.
type OwnerAbortDisposition uint8

const (
	OwnerAbortClean OwnerAbortDisposition = iota + 1
	OwnerAbortQuarantine
)

// OwnerPreparingAbortRequest contains identities and an already-authenticated
// SHA-256 commitment only. The service layer verifies the raw reclaim secret;
// raw capabilities/tokens are never accepted or persisted here.
type OwnerPreparingAbortRequest struct {
	ClusterID              string
	OwnerGroupID           string
	CurrentOwnerID         string
	AnchorDeviceUUID       string
	StorageCompatibilityID string

	OwnerEpoch                 uint64
	GroupConfigurationSequence uint64
	MembershipSHA256           [sha256.Size]byte

	AllocationRecordID     uint64
	RequestID              string
	CheckpointID           string
	ReclaimAuthoritySHA256 [sha256.Size]byte
}

// OwnerAbortExecutionResult is detached from cached Owner state. Replayed is
// true only for an already-terminal exact request. ForwardRecovered is true
// when an already-durable ABORTING record drove the operation.
type OwnerAbortExecutionResult struct {
	Record           OwnerStateAllocationRecord
	Disposition      OwnerAbortDisposition
	ForwardRecovered bool
	Replayed         bool
}

type ownerAbortExecutionError struct {
	cause          error
	recoveryNeeded bool
	reopenNeeded   bool
	offlineNeeded  bool
}

func (executionError *ownerAbortExecutionError) Error() string {
	qualifier := "Owner PREPARING abort failed"
	if executionError.offlineNeeded {
		qualifier = "Owner PREPARING abort requires the group to be taken offline"
	} else if executionError.recoveryNeeded {
		qualifier = "Owner PREPARING abort needs forward recovery"
	}
	if executionError.reopenNeeded && !executionError.offlineNeeded {
		qualifier += " after reopening the device group"
	}
	return fmt.Sprintf("%s: %v", qualifier, executionError.cause)
}

func (executionError *ownerAbortExecutionError) Unwrap() error {
	return executionError.cause
}

func (executionError *ownerAbortExecutionError) Is(target error) bool {
	return (target == ErrOwnerAbortRecoveryRequired &&
		executionError.recoveryNeeded) ||
		(target == ErrOwnerDeviceGroupReopenRequired &&
			executionError.reopenNeeded) ||
		(target == ErrOwnerDeviceGroupOfflineRequired &&
			executionError.offlineNeeded) ||
		(target == ErrOwnerAbortDurableContradiction &&
			executionError.offlineNeeded)
}

type ownerAbortRecoveryDevice struct {
	deviceIndex        int
	deviceUUID         string
	fragment           OwnerStateDeviceFragment
	beforeApply        bool
	appliedDisposition OwnerAbortDisposition
	desiredClean       AllocatorSnapshot
	desiredQuarantine  AllocatorSnapshot
}

type ownerAbortRecoveryPlan struct {
	abortingState       OwnerStateSnapshot
	abortingRecord      OwnerStateAllocationRecord
	cleanTerminalState  OwnerStateSnapshot
	cleanTerminalRecord OwnerStateAllocationRecord
	qTerminalState      OwnerStateSnapshot
	qTerminalRecord     OwnerStateAllocationRecord
	devices             []ownerAbortRecoveryDevice
}

// AbortPreparingCheckpoint authorizes and executes PREPARING -> ABORTING ->
// ABORTED/QUARANTINED under the same identity-checked single-process group
// mutex as reservation. It is not a distributed Owner fence.
func (group *OwnerDeviceGroup) AbortPreparingCheckpoint(
	request OwnerPreparingAbortRequest,
) (OwnerAbortExecutionResult, error) {
	if !group.ownerDeviceGroupHandleValid() {
		return OwnerAbortExecutionResult{}, ErrOwnerDeviceGroupInput
	}
	group.executionState.mu.Lock()
	defer group.executionState.mu.Unlock()
	if group.ownerDeviceGroupOfflineRequiredLocked() {
		return OwnerAbortExecutionResult{}, ErrOwnerDeviceGroupOfflineRequired
	}
	if group.ownerDeviceGroupReopenRequiredLocked() {
		return OwnerAbortExecutionResult{}, ErrOwnerDeviceGroupReopenRequired
	}
	ownerState, err := group.ownerStateLocked()
	if err != nil {
		return OwnerAbortExecutionResult{}, err
	}
	target, err := validateOwnerPreparingAbortRequestAgainstState(
		request,
		ownerState)
	if err != nil {
		return OwnerAbortExecutionResult{}, err
	}
	if target.State == OwnerAllocationAborted {
		return ownerAbortResult(target, false, true), nil
	}
	if target.State == OwnerAllocationQuarantined {
		if target.OwnerVerifiedSealSHA256 != ([sha256.Size]byte{}) {
			return OwnerAbortExecutionResult{}, ownerAbortConflictf(
				"allocation %d is QUARANTINED with post-seal provenance",
				target.AllocationRecordID)
		}
		// A zero seal identifies reservation/abort/cancellation provenance, so
		// this exact terminal record is safe to replay without any device I/O.
		return ownerAbortResult(target, false, true), nil
	}

	if target.State == OwnerAllocationPreparing {
		preparing, present, preparingErr := ownerReserveActivePreparing(ownerState)
		if preparingErr != nil || !present || !reservedDescriptorRecordsEqual(
			preparing,
			target) {
			if preparingErr == nil {
				preparingErr = ownerAbortOfflinef(
					"allocation %d is not the exact active PREPARING record",
					target.AllocationRecordID)
			} else if !errors.Is(
				preparingErr,
				ErrOwnerAbortDurableContradiction) {
				preparingErr = ownerAbortOfflinef(
					"active PREPARING invariant: %v",
					preparingErr)
			}
			return OwnerAbortExecutionResult{}, group.ownerAbortFailureLocked(
				preparingErr,
				false,
				true)
		}
		if transitional, present := ownerAbortOtherTransitionalRecord(
			ownerState,
			target.AllocationRecordID); present {
			return OwnerAbortExecutionResult{}, group.ownerAbortFailureLocked(
				ownerAbortOfflinef(
					"allocation %d remains in state %d beside active PREPARING %d",
					transitional.AllocationRecordID,
					transitional.State,
					target.AllocationRecordID),
				false,
				true)
		}
		plan, planErr := group.preflightFreshPreparingAbortLocked(
			ownerState,
			preparing)
		if planErr != nil {
			if errors.Is(planErr, ErrOwnerAbortDurableContradiction) {
				return OwnerAbortExecutionResult{}, group.ownerAbortFailureLocked(
					planErr,
					false,
					true)
			}
			return OwnerAbortExecutionResult{}, planErr
		}
		if commitErr := group.anchor.commitOwnerState(plan.abortingState); commitErr != nil {
			// commitOwnerState performs deterministic validation before it marks
			// the device ambiguous.  PREPARING remains the only durable state
			// when one of those checks fails, so forward recovery is required
			// only after the commit actually reached its mutation boundary.
			recoveryRequired := group.anchor.reopenRequired
			return OwnerAbortExecutionResult{}, group.ownerAbortFailureLocked(
				commitErr,
				recoveryRequired,
				false)
		}
		return group.executeAbortingRecoveryPlanLocked(plan, false)
	}

	if target.State == OwnerAllocationAborting {
		aborting, present, abortingErr := ownerAbortActiveAborting(ownerState)
		if abortingErr != nil || !present || !reservedDescriptorRecordsEqual(
			aborting,
			target) {
			if abortingErr == nil {
				abortingErr = ownerAbortOfflinef(
					"allocation %d is not the exact active ABORTING record",
					target.AllocationRecordID)
			}
			return OwnerAbortExecutionResult{}, group.ownerAbortFailureLocked(
				abortingErr,
				false,
				true)
		}
		if transitional, present := ownerAbortOtherTransitionalRecord(
			ownerState,
			target.AllocationRecordID); present {
			return OwnerAbortExecutionResult{}, group.ownerAbortFailureLocked(
				ownerAbortOfflinef(
					"allocation %d remains in state %d beside active ABORTING %d",
					transitional.AllocationRecordID,
					transitional.State,
					target.AllocationRecordID),
				false,
				true)
		}
		return group.recoverAbortingLocked(ownerState, aborting, true)
	}

	return OwnerAbortExecutionResult{}, ownerAbortConflictf(
		"allocation %d is in state %d, not PREPARING/ABORTING/terminal abort",
		target.AllocationRecordID,
		target.State)
}

// RecoverAbortingCheckpoint continues only an exact durable ABORTING record.
// It accepts no request or authority and therefore cannot infer fresh abort
// permission for a PREPARING record.
func (group *OwnerDeviceGroup) RecoverAbortingCheckpoint() (
	OwnerAbortExecutionResult,
	error,
) {
	if !group.ownerDeviceGroupHandleValid() {
		return OwnerAbortExecutionResult{}, ErrOwnerDeviceGroupInput
	}
	group.executionState.mu.Lock()
	defer group.executionState.mu.Unlock()
	if group.ownerDeviceGroupOfflineRequiredLocked() {
		return OwnerAbortExecutionResult{}, ErrOwnerDeviceGroupOfflineRequired
	}
	if group.ownerDeviceGroupReopenRequiredLocked() {
		return OwnerAbortExecutionResult{}, ErrOwnerDeviceGroupReopenRequired
	}
	ownerState, err := group.ownerStateLocked()
	if err != nil {
		return OwnerAbortExecutionResult{}, err
	}
	aborting, present, err := ownerAbortActiveAborting(ownerState)
	if err != nil {
		return OwnerAbortExecutionResult{}, group.ownerAbortFailureLocked(
			err,
			false,
			true)
	}
	if !present {
		return OwnerAbortExecutionResult{}, ErrOwnerAbortNoAborting
	}
	if transitional, other := ownerAbortOtherTransitionalRecord(
		ownerState,
		aborting.AllocationRecordID); other {
		return OwnerAbortExecutionResult{}, group.ownerAbortFailureLocked(
			ownerAbortOfflinef(
				"allocation %d remains in state %d beside active ABORTING %d",
				transitional.AllocationRecordID,
				transitional.State,
				aborting.AllocationRecordID),
			false,
			true)
	}
	return group.recoverAbortingLocked(ownerState, aborting, true)
}

func ownerAbortResult(
	record OwnerStateAllocationRecord,
	forwardRecovered bool,
	replayed bool,
) OwnerAbortExecutionResult {
	disposition := OwnerAbortClean
	if record.State == OwnerAllocationQuarantined {
		disposition = OwnerAbortQuarantine
	}
	return OwnerAbortExecutionResult{
		Record:           cloneOwnerStateRecord(record),
		Disposition:      disposition,
		ForwardRecovered: forwardRecovered,
		Replayed:         replayed,
	}
}

func validateOwnerPreparingAbortRequestAgainstState(
	request OwnerPreparingAbortRequest,
	ownerState OwnerStateSnapshot,
) (OwnerStateAllocationRecord, error) {
	if err := validateOwnerPreparingAbortRequest(request); err != nil {
		return OwnerStateAllocationRecord{}, err
	}
	if request.ClusterID != ownerState.ClusterID ||
		request.OwnerGroupID != ownerState.OwnerGroupID ||
		request.CurrentOwnerID != ownerState.CurrentOwnerID ||
		request.AnchorDeviceUUID != ownerState.AnchorDeviceUUID ||
		request.StorageCompatibilityID != ownerState.StorageCompatibilityID ||
		request.OwnerEpoch != ownerState.OwnerEpoch ||
		request.GroupConfigurationSequence !=
			ownerState.GroupConfigurationSequence ||
		request.MembershipSHA256 != ownerState.MembershipSHA256 {
		return OwnerStateAllocationRecord{}, ownerAbortAuthorityf(
			"request static Owner-group identity differs from durable state")
	}
	var byID *OwnerStateAllocationRecord
	for _, record := range ownerState.Records() {
		if record.AllocationRecordID != request.AllocationRecordID {
			continue
		}
		copy := cloneOwnerStateRecord(record)
		byID = &copy
		break
	}
	if byID == nil || byID.RequestID != request.RequestID ||
		byID.CheckpointID != request.CheckpointID {
		return OwnerStateAllocationRecord{}, ownerAbortConflictf(
			"allocation/request/checkpoint identity does not name one durable record")
	}
	if byID.AuthorityEvidence.ReclaimAuthoritySHA256 == ([sha256.Size]byte{}) ||
		byID.AuthorityEvidence.ReclaimAuthoritySHA256 !=
			request.ReclaimAuthoritySHA256 {
		return OwnerStateAllocationRecord{}, ownerAbortAuthorityf(
			"reclaim authority SHA-256 differs from the durable PREPARING commitment")
	}
	return *byID, nil
}

func validateOwnerPreparingAbortRequest(
	request OwnerPreparingAbortRequest,
) error {
	for _, identity := range []struct {
		name  string
		value string
	}{
		{"cluster ID", request.ClusterID},
		{"Owner-group ID", request.OwnerGroupID},
		{"current Owner ID", request.CurrentOwnerID},
		{"anchor device UUID", request.AnchorDeviceUUID},
		{"request ID", request.RequestID},
		{"checkpoint ID", request.CheckpointID},
	} {
		if err := validateOwnerStateIdentity(identity.name, identity.value); err != nil {
			return ownerAbortInvalidf("%v", err)
		}
	}
	if err := validateOwnerStateDeviceUUID(
		"anchor device UUID",
		request.AnchorDeviceUUID); err != nil {
		return ownerAbortInvalidf("%v", err)
	}
	if request.StorageCompatibilityID !=
		cxlcheckpoint.V7StorageCompatibilityID {
		return ownerAbortInvalidf(
			"storage compatibility ID differs from compiled V7")
	}
	for _, field := range []struct {
		name  string
		value uint64
	}{
		{"Owner epoch", request.OwnerEpoch},
		{"group-configuration sequence", request.GroupConfigurationSequence},
		{"allocation-record ID", request.AllocationRecordID},
	} {
		if err := ownerStatePositiveLong(field.name, field.value); err != nil {
			return ownerAbortInvalidf("%v", err)
		}
	}
	if request.MembershipSHA256 == ([sha256.Size]byte{}) {
		return ownerAbortInvalidf("membership SHA-256 is zero")
	}
	if request.ReclaimAuthoritySHA256 == ([sha256.Size]byte{}) {
		return ownerAbortInvalidf("reclaim authority SHA-256 is zero")
	}
	return nil
}

func ownerAbortActiveAborting(
	ownerState OwnerStateSnapshot,
) (OwnerStateAllocationRecord, bool, error) {
	records := ownerState.Records()
	abortingIndex := -1
	for index := range records {
		if records[index].State != OwnerAllocationAborting {
			continue
		}
		if abortingIndex >= 0 {
			return OwnerStateAllocationRecord{}, false, ownerAbortOfflinef(
				"Owner state contains multiple ABORTING allocations %d and %d",
				records[abortingIndex].AllocationRecordID,
				records[index].AllocationRecordID)
		}
		abortingIndex = index
	}
	if abortingIndex < 0 {
		return OwnerStateAllocationRecord{}, false, nil
	}
	if abortingIndex != len(records)-1 {
		return OwnerStateAllocationRecord{}, false, ownerAbortOfflinef(
			"ABORTING allocation %d is not the last Owner record",
			records[abortingIndex].AllocationRecordID)
	}
	record := records[abortingIndex]
	wantAllocation, allocationOK := checkedAdd(record.AllocationRecordID, 1)
	wantTransaction, transactionOK := checkedAdd(
		record.OwnerTransactionSequence,
		1)
	if !allocationOK || !transactionOK ||
		ownerState.NextAllocationRecordID != wantAllocation ||
		ownerState.NextOwnerTransactionSequence != wantTransaction {
		return OwnerStateAllocationRecord{}, false, ownerAbortOfflinef(
			"ABORTING allocation %d has invalid Owner high-water %d/%d",
			record.AllocationRecordID,
			ownerState.NextAllocationRecordID,
			ownerState.NextOwnerTransactionSequence)
	}
	wantAbortingTransaction, reservationOK := checkedAdd(
		record.ReservationTransactionSequence,
		1)
	if !reservationOK || wantAbortingTransaction != record.OwnerTransactionSequence {
		return OwnerStateAllocationRecord{}, false, ownerAbortOfflinef(
			"ABORTING transaction %d does not immediately follow reservation transaction %d",
			record.OwnerTransactionSequence,
			record.ReservationTransactionSequence)
	}
	return record, true, nil
}

func ownerAbortOtherTransitionalRecord(
	ownerState OwnerStateSnapshot,
	exceptAllocationRecordID uint64,
) (OwnerStateAllocationRecord, bool) {
	for _, record := range ownerState.Records() {
		if record.AllocationRecordID == exceptAllocationRecordID {
			continue
		}
		switch record.State {
		case OwnerAllocationPreparing,
			OwnerAllocationCommitting,
			OwnerAllocationAborting,
			OwnerAllocationReclaiming,
			OwnerAllocationCanceling:
			return record, true
		}
	}
	return OwnerStateAllocationRecord{}, false
}

func (group *OwnerDeviceGroup) preflightFreshPreparingAbortLocked(
	preparingState OwnerStateSnapshot,
	preparingRecord OwnerStateAllocationRecord,
) (ownerAbortRecoveryPlan, error) {
	reservePlan, err := group.buildPreparingRecoveryPlanLocked(
		preparingState,
		preparingRecord)
	if err != nil {
		// The read limit and backing-size checks are operational preflight
		// failures.  They say nothing contradictory about the durable
		// PREPARING record and must remain retryable on the same handle.
		if errors.Is(err, ErrDeviceMetadataOwnerStateReadLimit) ||
			errors.Is(err, ErrDeviceMetadataSizeMismatch) ||
			errors.Is(err, ErrDeviceMetadataSequence) ||
			errors.Is(err, ErrOwnerReserveSequenceOverflow) {
			return ownerAbortRecoveryPlan{}, err
		}
		return ownerAbortRecoveryPlan{}, ownerAbortOfflinef(
			"classify PREPARING allocation before abort: %v",
			err)
	}
	abortingTransaction, err := ownerReserveAddSequence(
		preparingRecord.ReservationTransactionSequence,
		1,
		"ABORTING transaction")
	if err != nil {
		return ownerAbortRecoveryPlan{}, err
	}
	if abortingTransaction != preparingState.NextOwnerTransactionSequence {
		return ownerAbortRecoveryPlan{}, ownerAbortOfflinef(
			"ABORTING transaction %d differs from PREPARING next %d",
			abortingTransaction,
			preparingState.NextOwnerTransactionSequence)
	}
	abortingRecord := cloneOwnerStateRecord(preparingRecord)
	abortingRecord.State = OwnerAllocationAborting
	abortingRecord.OwnerTransactionSequence = abortingTransaction
	currentByUUID := make(map[string]AllocatorSnapshot, len(reservePlan.devices))
	for _, entry := range reservePlan.devices {
		currentByUUID[entry.deviceUUID] =
			group.devices[entry.deviceIndex].metadata.allocator.Clone()
	}
	for index := range abortingRecord.Fragments {
		current, exists := currentByUUID[abortingRecord.Fragments[index].DeviceUUID]
		if !exists {
			return ownerAbortRecoveryPlan{}, ownerAbortOfflinef(
				"PREPARING fragment device %q has no opened allocator",
				abortingRecord.Fragments[index].DeviceUUID)
		}
		target, ok := checkedAdd(current.SnapshotSequence, 1)
		if !ok || target > cxlcheckpoint.MaxSignedLong {
			return ownerAbortRecoveryPlan{}, fmt.Errorf(
				"%w: abort allocator target overflows for device %q",
				ErrDeviceMetadataSequence,
				abortingRecord.Fragments[index].DeviceUUID)
		}
		abortingRecord.Fragments[index].TargetAllocatorSnapshotSequence = target
	}
	abortingSnapshotSequence, err := ownerReserveAddSequence(
		preparingState.SnapshotSequence,
		1,
		"ABORTING Owner-state snapshot")
	if err != nil {
		return ownerAbortRecoveryPlan{}, err
	}
	abortingNextTransaction, err := ownerReserveAddSequence(
		abortingTransaction,
		1,
		"post-ABORTING Owner transaction")
	if err != nil {
		return ownerAbortRecoveryPlan{}, err
	}
	abortingState, err := ownerReserveReplaceLastRecordSnapshot(
		preparingState,
		abortingRecord,
		abortingSnapshotSequence,
		preparingState.NextAllocationRecordID,
		abortingNextTransaction,
		group.anchor.geometry)
	if err != nil {
		return ownerAbortRecoveryPlan{}, err
	}
	plan, err := group.buildAbortingRecoveryPlanLocked(
		abortingState,
		abortingRecord,
		true)
	if err != nil {
		return ownerAbortRecoveryPlan{}, err
	}
	if err := group.preflightOwnerStateTransitionLocked(
		preparingState,
		abortingState,
		group.anchor.ownerStateSlot); err != nil {
		return ownerAbortRecoveryPlan{}, err
	}
	abortingSlot := otherOwnerStateSlot(group.anchor.ownerStateSlot)
	if err := group.preflightOwnerStateTransitionLocked(
		abortingState,
		plan.cleanTerminalState,
		abortingSlot); err != nil {
		return ownerAbortRecoveryPlan{}, err
	}
	if err := group.preflightOwnerStateTransitionLocked(
		abortingState,
		plan.qTerminalState,
		abortingSlot); err != nil {
		return ownerAbortRecoveryPlan{}, err
	}
	// Global read-only descriptor preflight occurs before ABORTING is the first
	// durable mutation. Both terminal dispositions and both allocator targets
	// were preflighted above because post-ABORTING evidence may pin either one.
	if _, err := group.observeAbortDescriptorsLocked(
		preparingRecord,
		abortingTransaction,
		plan.devices); err != nil {
		return ownerAbortRecoveryPlan{}, err
	}
	return plan, nil
}

func (group *OwnerDeviceGroup) recoverAbortingLocked(
	abortingState OwnerStateSnapshot,
	abortingRecord OwnerStateAllocationRecord,
	forwardRecovered bool,
) (OwnerAbortExecutionResult, error) {
	plan, err := group.buildAbortingRecoveryPlanLocked(
		abortingState,
		abortingRecord,
		false)
	if err != nil {
		offline := ownerAbortDurablePlanFailureRequiresOffline(err)
		return OwnerAbortExecutionResult{}, group.ownerAbortFailureLocked(
			err,
			!offline,
			offline)
	}
	return group.executeAbortingRecoveryPlanLocked(plan, forwardRecovered)
}

func (group *OwnerDeviceGroup) buildAbortingRecoveryPlanLocked(
	abortingState OwnerStateSnapshot,
	abortingRecord OwnerStateAllocationRecord,
	allowProposedState bool,
) (ownerAbortRecoveryPlan, error) {
	if !allowProposedState {
		active, present, err := ownerAbortActiveAborting(abortingState)
		if err != nil || !present || !reservedDescriptorRecordsEqual(
			active,
			abortingRecord) {
			if err == nil {
				err = ownerAbortOfflinef(
					"Owner state does not contain exact active ABORTING record")
			}
			return ownerAbortRecoveryPlan{}, err
		}
	}
	if err := abortingState.CrossCheckBootstrap(group.bootstrap); err != nil {
		return ownerAbortRecoveryPlan{}, err
	}
	wantAbortingTransaction, reservationOK := checkedAdd(
		abortingRecord.ReservationTransactionSequence,
		1)
	if abortingRecord.State != OwnerAllocationAborting ||
		!reservationOK ||
		wantAbortingTransaction != abortingRecord.OwnerTransactionSequence {
		return ownerAbortRecoveryPlan{}, ownerAbortOfflinef(
			"record %d is not a valid ABORTING record",
			abortingRecord.AllocationRecordID)
	}
	preparingTransaction := abortingRecord.ReservationTransactionSequence
	terminalTransaction, err := ownerReserveAddSequence(
		abortingRecord.OwnerTransactionSequence,
		1,
		"abort terminal transaction")
	if err != nil {
		return ownerAbortRecoveryPlan{}, err
	}
	terminalSnapshotSequence, err := ownerReserveAddSequence(
		abortingState.SnapshotSequence,
		1,
		"abort terminal Owner-state snapshot")
	if err != nil {
		return ownerAbortRecoveryPlan{}, err
	}
	terminalNextTransaction, err := ownerReserveAddSequence(
		terminalTransaction,
		1,
		"post-abort-terminal Owner transaction")
	if err != nil {
		return ownerAbortRecoveryPlan{}, err
	}
	cleanRecord := cloneOwnerStateRecord(abortingRecord)
	cleanRecord.State = OwnerAllocationAborted
	cleanRecord.OwnerTransactionSequence = terminalTransaction
	qRecord := cloneOwnerStateRecord(abortingRecord)
	qRecord.State = OwnerAllocationQuarantined
	qRecord.OwnerTransactionSequence = terminalTransaction
	cleanState, err := ownerReserveReplaceLastRecordSnapshot(
		abortingState,
		cleanRecord,
		terminalSnapshotSequence,
		abortingState.NextAllocationRecordID,
		terminalNextTransaction,
		group.anchor.geometry)
	if err != nil {
		return ownerAbortRecoveryPlan{}, err
	}
	qState, err := ownerReserveReplaceLastRecordSnapshot(
		abortingState,
		qRecord,
		terminalSnapshotSequence,
		abortingState.NextAllocationRecordID,
		terminalNextTransaction,
		group.anchor.geometry)
	if err != nil {
		return ownerAbortRecoveryPlan{}, err
	}
	if err := group.preflightOwnerStateEncodingLocked(cleanState); err != nil {
		return ownerAbortRecoveryPlan{}, err
	}
	if err := group.preflightOwnerStateEncodingLocked(qState); err != nil {
		return ownerAbortRecoveryPlan{}, err
	}
	if !allowProposedState {
		// Recovery must preflight the actual currently selected ABORTING slot,
		// not merely prove that the terminal envelope can be encoded. This keeps
		// deterministic slot/range/read-limit failures ahead of every descriptor
		// or allocator mutation.
		if err := group.preflightOwnerStateTransitionLocked(
			abortingState,
			cleanState,
			group.anchor.ownerStateSlot); err != nil {
			return ownerAbortRecoveryPlan{}, err
		}
		if err := group.preflightOwnerStateTransitionLocked(
			abortingState,
			qState,
			group.anchor.ownerStateSlot); err != nil {
			return ownerAbortRecoveryPlan{}, err
		}
	}

	indexByUUID := make(map[string]int, len(group.devices))
	for index := range group.devices {
		indexByUUID[group.devices[index].deviceUUID] = index
	}
	affected := make(map[string]bool, len(abortingRecord.Fragments))
	devices := make([]ownerAbortRecoveryDevice, 0, len(abortingRecord.Fragments))
	for _, fragment := range abortingRecord.Fragments {
		deviceIndex, exists := indexByUUID[fragment.DeviceUUID]
		if !exists || affected[fragment.DeviceUUID] {
			return ownerAbortRecoveryPlan{}, ownerAbortOfflinef(
				"ABORTING fragment device %q is missing or repeated",
				fragment.DeviceUUID)
		}
		affected[fragment.DeviceUUID] = true
		entry, classifyErr := group.classifyAbortingAllocatorLocked(
			deviceIndex,
			fragment,
			preparingTransaction,
			abortingRecord.OwnerTransactionSequence,
			abortingState.NextOwnerTransactionSequence)
		if classifyErr != nil {
			return ownerAbortRecoveryPlan{}, classifyErr
		}
		devices = append(devices, entry)
	}
	for index := range group.devices {
		if affected[group.devices[index].deviceUUID] {
			continue
		}
		applied := group.devices[index].metadata.allocator.
			AppliedOwnerTransactionSequence
		if applied >= preparingTransaction {
			return ownerAbortRecoveryPlan{}, ownerAbortOfflinef(
				"unaffected device %q carries transaction %d at/after PREPARING %d",
				group.devices[index].deviceUUID,
				applied,
				preparingTransaction)
		}
	}
	sort.Slice(devices, func(left, right int) bool {
		return devices[left].deviceUUID < devices[right].deviceUUID
	})
	return ownerAbortRecoveryPlan{
		abortingState:       abortingState.Clone(),
		abortingRecord:      cloneOwnerStateRecord(abortingRecord),
		cleanTerminalState:  cleanState,
		cleanTerminalRecord: cleanRecord,
		qTerminalState:      qState,
		qTerminalRecord:     qRecord,
		devices:             devices,
	}, nil
}

func (group *OwnerDeviceGroup) classifyAbortingAllocatorLocked(
	deviceIndex int,
	fragment OwnerStateDeviceFragment,
	preparingTransaction uint64,
	abortingTransaction uint64,
	issuedTransactionHighWater uint64,
) (ownerAbortRecoveryDevice, error) {
	if deviceIndex < 0 || deviceIndex >= len(group.devices) {
		return ownerAbortRecoveryDevice{}, ownerAbortOfflinef(
			"ABORTING device index %d is outside group",
			deviceIndex)
	}
	opened := group.devices[deviceIndex]
	if opened.metadata == nil || opened.deviceUUID != fragment.DeviceUUID {
		return ownerAbortRecoveryDevice{}, ownerAbortOfflinef(
			"ABORTING device %q does not match opened group",
			fragment.DeviceUUID)
	}
	current := opened.metadata.allocator
	if err := current.CrossCheck(
		opened.geometry,
		opened.metadata.superblock.DeviceBindingSHA256(),
		opened.metadata.superblock.OwnerGroupIdentitySHA256(),
		opened.metadata.superblock.OwnerEpoch); err != nil {
		return ownerAbortRecoveryDevice{}, ownerAbortOfflinef(
			"device %q active allocator: %v",
			fragment.DeviceUUID,
			err)
	}
	nextSequence, sequenceOK := checkedAdd(current.SnapshotSequence, 1)
	beforeApply := sequenceOK &&
		nextSequence == fragment.TargetAllocatorSnapshotSequence &&
		current.AppliedOwnerTransactionSequence <= preparingTransaction
	afterApply := current.SnapshotSequence ==
		fragment.TargetAllocatorSnapshotSequence &&
		current.AppliedOwnerTransactionSequence == abortingTransaction
	if !beforeApply && !afterApply {
		return ownerAbortRecoveryDevice{}, ownerAbortOfflinef(
			"device %q allocator %d/%d is neither before nor after abort target %d/%d",
			fragment.DeviceUUID,
			current.SnapshotSequence,
			current.AppliedOwnerTransactionSequence,
			fragment.TargetAllocatorSnapshotSequence,
			abortingTransaction)
	}

	bitmap := current.BitmapBytes()
	selectedState, err := ownerAbortSelectedBitmapState(bitmap, fragment)
	if err != nil {
		return ownerAbortRecoveryDevice{}, err
	}
	entry := ownerAbortRecoveryDevice{
		deviceIndex: deviceIndex,
		deviceUUID:  fragment.DeviceUUID,
		fragment:    cloneOwnerStateFragment(fragment),
		beforeApply: beforeApply,
	}
	if afterApply {
		if selectedState == OwnerAbortClean {
			entry.appliedDisposition = OwnerAbortClean
		} else if selectedState == OwnerAbortQuarantine {
			entry.appliedDisposition = OwnerAbortQuarantine
		} else {
			return ownerAbortRecoveryDevice{}, ownerAbortOfflinef(
				"device %q applied abort transaction has mixed selected bits",
				fragment.DeviceUUID)
		}
		entry.desiredClean = current.Clone()
		entry.desiredQuarantine = current.Clone()
		return entry, nil
	}

	if current.AppliedOwnerTransactionSequence == preparingTransaction {
		if selectedState != OwnerAbortQuarantine {
			return ownerAbortRecoveryDevice{}, ownerAbortOfflinef(
				"device %q applied PREPARING transaction but selected pages are not all allocated",
				fragment.DeviceUUID)
		}
	} else if selectedState != OwnerAbortClean {
		return ownerAbortRecoveryDevice{}, ownerAbortOfflinef(
			"device %q has pre-PREPARING allocator but selected pages are not all FREE",
			fragment.DeviceUUID)
	}
	cleanBitmap := append([]byte(nil), bitmap...)
	qBitmap := append([]byte(nil), bitmap...)
	for _, extent := range fragment.Extents {
		end, ok := checkedAdd(extent.StartDataPageIndex, extent.PageCount)
		if !ok || end > current.DataPageCount {
			return ownerAbortRecoveryDevice{}, ownerAbortOfflinef(
				"device %q abort extent exceeds allocator",
				fragment.DeviceUUID)
		}
		for page := extent.StartDataPageIndex; page < end; page++ {
			ownerAbortClearBitmap(cleanBitmap, page)
			ownerAllocatorSetBitmap(qBitmap, page)
		}
	}
	entry.desiredClean, err = NewAllocatorSnapshot(AllocatorSnapshotConfig{
		DeviceBindingSHA256:             current.DeviceBindingSHA256,
		OwnerGroupIdentitySHA256:        current.OwnerGroupIdentitySHA256,
		OwnerEpoch:                      current.OwnerEpoch,
		SnapshotSequence:                fragment.TargetAllocatorSnapshotSequence,
		AppliedOwnerTransactionSequence: abortingTransaction,
		DataPageCount:                   current.DataPageCount,
	}, cleanBitmap)
	if err != nil {
		return ownerAbortRecoveryDevice{}, err
	}
	entry.desiredQuarantine, err = NewAllocatorSnapshot(AllocatorSnapshotConfig{
		DeviceBindingSHA256:             current.DeviceBindingSHA256,
		OwnerGroupIdentitySHA256:        current.OwnerGroupIdentitySHA256,
		OwnerEpoch:                      current.OwnerEpoch,
		SnapshotSequence:                fragment.TargetAllocatorSnapshotSequence,
		AppliedOwnerTransactionSequence: abortingTransaction,
		DataPageCount:                   current.DataPageCount,
	}, qBitmap)
	if err != nil {
		return ownerAbortRecoveryDevice{}, err
	}
	if err := group.preflightAllocatorCommitLocked(
		opened.metadata,
		entry.desiredClean,
		issuedTransactionHighWater); err != nil {
		return ownerAbortRecoveryDevice{}, err
	}
	if err := group.preflightAllocatorCommitLocked(
		opened.metadata,
		entry.desiredQuarantine,
		issuedTransactionHighWater); err != nil {
		return ownerAbortRecoveryDevice{}, err
	}
	return entry, nil
}

func ownerAbortSelectedBitmapState(
	bitmap []byte,
	fragment OwnerStateDeviceFragment,
) (OwnerAbortDisposition, error) {
	seen := false
	first := false
	for _, extent := range fragment.Extents {
		end, ok := checkedAdd(extent.StartDataPageIndex, extent.PageCount)
		if !ok {
			return 0, ownerAbortOfflinef("abort extent overflows")
		}
		for page := extent.StartDataPageIndex; page < end; page++ {
			if page/8 >= uint64(len(bitmap)) {
				return 0, ownerAbortOfflinef(
					"abort page %d exceeds allocator bitmap",
					page)
			}
			set := ownerAllocatorBitmapSet(bitmap, page)
			if !seen {
				first = set
				seen = true
			} else if set != first {
				return 0, nil
			}
		}
	}
	if !seen {
		return 0, ownerAbortOfflinef("abort fragment selects no pages")
	}
	if first {
		return OwnerAbortQuarantine, nil
	}
	return OwnerAbortClean, nil
}

func ownerAbortClearBitmap(bitmap []byte, page uint64) {
	bitmap[page/8] &^= byte(1) << uint(page%8)
}

func (group *OwnerDeviceGroup) observeAbortDescriptorsLocked(
	authorityRecord OwnerStateAllocationRecord,
	abortingTransaction uint64,
	devices []ownerAbortRecoveryDevice,
) ([]ownerAbortDescriptorObservation, error) {
	observations := make([]ownerAbortDescriptorObservation, len(devices))
	for index := range devices {
		entry := devices[index]
		observation, err := group.devices[entry.deviceIndex].metadata.
			inspectPreparingAbortDescriptors(
				authorityRecord,
				abortingTransaction)
		if err != nil {
			return nil, err
		}
		observations[index] = observation
	}
	return observations, nil
}

func ownerAbortChooseDisposition(
	devices []ownerAbortRecoveryDevice,
	observations []ownerAbortDescriptorObservation,
) (OwnerAbortDisposition, error) {
	if len(devices) == 0 || len(devices) != len(observations) {
		return 0, ownerAbortOfflinef(
			"abort device/descriptor observation counts differ")
	}
	fixed := OwnerAbortDisposition(0)
	for _, entry := range devices {
		if entry.appliedDisposition == 0 {
			continue
		}
		if fixed == 0 {
			fixed = entry.appliedDisposition
		} else if fixed != entry.appliedDisposition {
			return 0, ownerAbortOfflinef(
				"applied abort allocators disagree on clean/quarantine disposition")
		}
	}
	if fixed != 0 {
		for index, observation := range observations {
			complete := observation.cleanDispositionComplete()
			if fixed == OwnerAbortQuarantine {
				complete = observation.quarantineDispositionComplete()
			}
			if !complete {
				return 0, ownerAbortOfflinef(
					"device %q descriptors contradict applied allocator disposition %d",
					devices[index].deviceUUID,
					fixed)
			}
		}
		return fixed, nil
	}
	for _, observation := range observations {
		if observation.requiresQuarantine() {
			return OwnerAbortQuarantine, nil
		}
	}
	return OwnerAbortClean, nil
}

func (group *OwnerDeviceGroup) executeAbortingRecoveryPlanLocked(
	plan ownerAbortRecoveryPlan,
	forwardRecovered bool,
) (OwnerAbortExecutionResult, error) {
	observations, err := group.observeAbortDescriptorsLocked(
		plan.abortingRecord,
		plan.abortingRecord.OwnerTransactionSequence,
		plan.devices)
	if err != nil {
		return OwnerAbortExecutionResult{}, group.ownerAbortFailureLocked(
			err,
			true,
			false)
	}
	disposition, err := ownerAbortChooseDisposition(plan.devices, observations)
	if err != nil {
		return OwnerAbortExecutionResult{}, group.ownerAbortFailureLocked(
			err,
			false,
			true)
	}
	hasAppliedMLock := false
	for _, entry := range plan.devices {
		if entry.appliedDisposition != 0 {
			hasAppliedMLock = true
			break
		}
	}

	// Global preflight above covered every selected descriptor on every DAX.
	// All device Sync boundaries complete before the first allocator mutation.
	for index := range plan.devices {
		entry := plan.devices[index]
		device := group.devices[entry.deviceIndex].metadata
		if err := device.persistAbortingDescriptorDispositionWithLock(
			plan.abortingRecord,
			disposition,
			hasAppliedMLock); err != nil {
			offline := hasAppliedMLock && errors.Is(
				err,
				ErrOwnerAbortDescriptorDispositionChanged)
			return OwnerAbortExecutionResult{}, group.ownerAbortFailureLocked(
				err,
				!offline,
				offline)
		}
	}

	for index := range plan.devices {
		entry := plan.devices[index]
		if !entry.beforeApply {
			continue
		}
		desired := entry.desiredClean
		if disposition == OwnerAbortQuarantine {
			desired = entry.desiredQuarantine
		}
		if err := group.devices[entry.deviceIndex].metadata.
			commitAllocatorSnapshot(desired); err != nil {
			return OwnerAbortExecutionResult{}, group.ownerAbortFailureLocked(
				err,
				true,
				false)
		}
	}

	if err := group.refreshOwnerDeviceGroupMetadataLocked(); err != nil {
		group.executionState.reopenRequired = true
		return OwnerAbortExecutionResult{}, group.ownerAbortFailureLocked(
			err,
			true,
			false)
	}
	selectedOwner, err := group.ownerStateLocked()
	if err != nil {
		group.executionState.reopenRequired = true
		return OwnerAbortExecutionResult{}, group.ownerAbortFailureLocked(
			err,
			true,
			false)
	}
	selectedAborting, present, err := ownerAbortActiveAborting(selectedOwner)
	if err != nil || !present || !reservedDescriptorRecordsEqual(
		selectedAborting,
		plan.abortingRecord) || !ownerStateSnapshotsCanonicalEqual(
		selectedOwner,
		plan.abortingState,
		group.anchor.geometry) {
		if err == nil {
			err = ownerAbortOfflinef(
				"fresh Owner observation differs from exact ABORTING state")
		}
		return OwnerAbortExecutionResult{}, group.ownerAbortFailureLocked(
			err,
			false,
			true)
	}
	reconciled, err := group.buildAbortingRecoveryPlanLocked(
		selectedOwner,
		selectedAborting,
		false)
	if err != nil {
		offline := ownerAbortDurablePlanFailureRequiresOffline(err)
		return OwnerAbortExecutionResult{}, group.ownerAbortFailureLocked(
			err,
			!offline,
			offline)
	}
	for _, entry := range reconciled.devices {
		if entry.beforeApply {
			return OwnerAbortExecutionResult{}, group.ownerAbortFailureLocked(
				ownerAbortOfflinef(
					"device %q allocator remained before abort target",
					entry.deviceUUID),
				false,
				true)
		}
	}
	reconciledObservations, err := group.observeAbortDescriptorsLocked(
		selectedAborting,
		selectedAborting.OwnerTransactionSequence,
		reconciled.devices)
	if err != nil {
		return OwnerAbortExecutionResult{}, group.ownerAbortFailureLocked(
			err,
			true,
			false)
	}
	reconciledDisposition, err := ownerAbortChooseDisposition(
		reconciled.devices,
		reconciledObservations)
	if err != nil || reconciledDisposition != disposition {
		if err == nil {
			err = ownerAbortOfflinef(
				"fresh disposition %d differs from executed disposition %d",
				reconciledDisposition,
				disposition)
		}
		return OwnerAbortExecutionResult{}, group.ownerAbortFailureLocked(
			err,
			false,
			true)
	}

	terminalState := reconciled.cleanTerminalState
	terminalRecord := reconciled.cleanTerminalRecord
	if disposition == OwnerAbortQuarantine {
		terminalState = reconciled.qTerminalState
		terminalRecord = reconciled.qTerminalRecord
	}
	if err := group.anchor.commitOwnerState(terminalState); err != nil {
		return OwnerAbortExecutionResult{}, group.ownerAbortFailureLocked(
			err,
			true,
			false)
	}
	if err := group.refreshOwnerDeviceGroupMetadataLocked(); err != nil {
		group.executionState.reopenRequired = true
		return OwnerAbortExecutionResult{}, group.ownerAbortFailureLocked(
			err,
			true,
			false)
	}
	terminalOwner, err := group.ownerStateLocked()
	if err != nil || !ownerStateSnapshotsCanonicalEqual(
		terminalOwner,
		terminalState,
		group.anchor.geometry) {
		if err == nil {
			err = ownerAbortOfflinef(
				"fresh Owner observation differs from exact abort terminal state")
		}
		return OwnerAbortExecutionResult{}, group.ownerAbortFailureLocked(
			err,
			false,
			true)
	}
	selectedTerminal, found := reservedDescriptorOwnerRecord(
		terminalOwner,
		terminalRecord.AllocationRecordID)
	if !found || !reservedDescriptorRecordsEqual(
		selectedTerminal,
		terminalRecord) {
		return OwnerAbortExecutionResult{}, group.ownerAbortFailureLocked(
			ownerAbortOfflinef(
				"fresh Owner observation lacks exact abort terminal record"),
			false,
			true)
	}
	return ownerAbortResult(selectedTerminal, forwardRecovered, false), nil
}

func ownerAbortDurablePlanFailureRequiresOffline(err error) bool {
	return errors.Is(err, ErrOwnerAbortDurableContradiction) ||
		errors.Is(err, ErrOwnerReserveSequenceOverflow) ||
		errors.Is(err, ErrDeviceMetadataSequence)
}

func (group *OwnerDeviceGroup) ownerAbortFailureLocked(
	cause error,
	recoveryRequired bool,
	offlineRequired bool,
) error {
	if cause == nil {
		cause = errors.New("unspecified Owner PREPARING abort failure")
	}
	if offlineRequired || errors.Is(cause, ErrOwnerAbortDurableContradiction) {
		group.executionState.offlineRequired = true
		offlineRequired = true
		recoveryRequired = false
	}
	reopenRequired := group.ownerDeviceGroupReopenRequiredLocked()
	if !recoveryRequired && !offlineRequired && !reopenRequired {
		return cause
	}
	return &ownerAbortExecutionError{
		cause:          cause,
		recoveryNeeded: recoveryRequired,
		reopenNeeded:   reopenRequired,
		offlineNeeded:  offlineRequired,
	}
}

func ownerAbortInvalidf(format string, arguments ...interface{}) error {
	return fmt.Errorf(
		"%w: %s",
		ErrInvalidOwnerPreparingAbortRequest,
		fmt.Sprintf(format, arguments...))
}

func ownerAbortAuthorityf(format string, arguments ...interface{}) error {
	return fmt.Errorf(
		"%w: %s",
		ErrOwnerAbortAuthorityConflict,
		fmt.Sprintf(format, arguments...))
}

func ownerAbortConflictf(format string, arguments ...interface{}) error {
	return fmt.Errorf(
		"%w: %s",
		ErrOwnerAbortConflict,
		fmt.Sprintf(format, arguments...))
}

func ownerAbortOfflinef(format string, arguments ...interface{}) error {
	return fmt.Errorf(
		"%w: %s",
		ErrOwnerAbortDurableContradiction,
		fmt.Sprintf(format, arguments...))
}

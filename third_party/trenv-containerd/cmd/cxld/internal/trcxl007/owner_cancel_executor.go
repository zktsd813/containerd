package trcxl007

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"sort"

	"github.com/containerd/containerd/third_party/trenv-containerd/pkg/cxlcheckpoint"
)

const (
	// OwnerGrantedCancelFenceDigestDomain names the service-level evidence that
	// binds Producer capability revocation, write/DSA drain, and the required
	// visibility fence to one exact checkpoint. This package receives only its
	// already-authenticated SHA-256 commitment; it does not authenticate raw
	// tokens or implement the production distributed fence.
	OwnerGrantedCancelFenceDigestDomain = "TRCXL007-owner-granted-cancel-fence-v1"
)

var (
	ErrInvalidOwnerGrantedCancelRequest = errors.New(
		"invalid TRCXL007 GRANTED cancellation request")
	ErrOwnerCancelAuthorityConflict = errors.New(
		"TRCXL007 GRANTED cancellation authority does not match durable commitment")
	ErrOwnerCancelFenceRequired = errors.New(
		"TRCXL007 GRANTED cancellation requires authenticated Producer write-fence evidence")
	ErrOwnerCancelConflict = errors.New(
		"TRCXL007 GRANTED cancellation conflicts with durable Owner state")
	ErrOwnerCancelTransitionBlocked = errors.New(
		"TRCXL007 GRANTED cancellation is blocked by an in-progress Owner transition")
	ErrOwnerCancelRecoveryRequired = errors.New(
		"TRCXL007 GRANTED cancellation requires forward recovery")
	ErrOwnerCancelNoCanceling = errors.New(
		"TRCXL007 Owner state has no active CANCELING allocation")
	ErrOwnerCancelDurableContradiction = errors.New(
		"TRCXL007 GRANTED cancellation found an irreconcilable durable contradiction")
)

// OwnerCancelDisposition is one checkpoint-wide result. Per-DAX or per-page
// disposition choices are forbidden.
type OwnerCancelDisposition uint8

const (
	OwnerCancelClean OwnerCancelDisposition = iota + 1
	OwnerCancelQuarantine
)

// OwnerGrantedCancelRequest contains stable identities and commitments only.
// ProducerWriteFenceSHA256 is evidence that the authenticated service already
// revoked this exact Producer capability, drained all writes/DSA jobs, and
// completed its platform visibility fence. Knowing this digest is not service
// authorization. Raw capabilities, signatures, and bearer secrets never enter
// shared Owner state or this persistence API.
type OwnerGrantedCancelRequest struct {
	ClusterID              string
	OwnerGroupID           string
	CurrentOwnerID         string
	AnchorDeviceUUID       string
	StorageCompatibilityID string

	OwnerEpoch                 uint64
	GroupConfigurationSequence uint64
	MembershipSHA256           [sha256.Size]byte

	AllocationRecordID uint64
	RequestID          string
	CheckpointID       string
	ProducerID         string

	ProducerCapabilitySHA256 [sha256.Size]byte
	ProducerWriteFenceSHA256 [sha256.Size]byte
	ReclaimAuthoritySHA256   [sha256.Size]byte
}

// OwnerCancelExecutionResult is detached. ForwardRecovered means a durable
// CANCELING record drove execution. Replayed means an exact terminal record was
// returned without a new mutation.
type OwnerCancelExecutionResult struct {
	Record           OwnerStateAllocationRecord
	Disposition      OwnerCancelDisposition
	ForwardRecovered bool
	Replayed         bool
}

type ownerCancelExecutionError struct {
	cause          error
	recoveryNeeded bool
	reopenNeeded   bool
	offlineNeeded  bool
}

func (executionError *ownerCancelExecutionError) Error() string {
	qualifier := "Owner GRANTED cancellation failed"
	if executionError.offlineNeeded {
		qualifier = "Owner GRANTED cancellation requires the group to be taken offline"
	} else if executionError.recoveryNeeded {
		qualifier = "Owner GRANTED cancellation needs forward recovery"
	}
	if executionError.reopenNeeded && !executionError.offlineNeeded {
		qualifier += " after reopening the device group"
	}
	return fmt.Sprintf("%s: %v", qualifier, executionError.cause)
}

func (executionError *ownerCancelExecutionError) Unwrap() error {
	return executionError.cause
}

func (executionError *ownerCancelExecutionError) Is(target error) bool {
	return (target == ErrOwnerCancelRecoveryRequired && executionError.recoveryNeeded) ||
		(target == ErrOwnerDeviceGroupReopenRequired && executionError.reopenNeeded) ||
		(target == ErrOwnerDeviceGroupOfflineRequired && executionError.offlineNeeded) ||
		(target == ErrOwnerCancelDurableContradiction && executionError.offlineNeeded)
}

type ownerCancelRecoveryDevice struct {
	deviceIndex        int
	deviceUUID         string
	fragment           OwnerStateDeviceFragment
	beforeApply        bool
	appliedDisposition OwnerCancelDisposition
	desiredClean       AllocatorSnapshot
	desiredQuarantine  AllocatorSnapshot
}

type ownerCancelRecoveryPlan struct {
	cancelingState      OwnerStateSnapshot
	cancelingRecord     OwnerStateAllocationRecord
	cleanTerminalState  OwnerStateSnapshot
	cleanTerminalRecord OwnerStateAllocationRecord
	qTerminalState      OwnerStateSnapshot
	qTerminalRecord     OwnerStateAllocationRecord
	devices             []ownerCancelRecoveryDevice
}

// CancelGrantedCheckpoint executes unpublished exclusive-allocation cleanup:
// GRANTED -> CANCELING -> CANCELED/QUARANTINED. It is deliberately separate
// from PREPARING abort and COMMITTED reclaim. The shared group mutex is only a
// single-process serialization primitive; production must not wire this method
// until its authenticated service and distributed Producer fence exist.
func (group *OwnerDeviceGroup) CancelGrantedCheckpoint(
	request OwnerGrantedCancelRequest,
) (OwnerCancelExecutionResult, error) {
	if !group.ownerDeviceGroupHandleValid() {
		return OwnerCancelExecutionResult{}, ErrOwnerDeviceGroupInput
	}
	group.executionState.mu.Lock()
	defer group.executionState.mu.Unlock()
	if group.ownerDeviceGroupOfflineRequiredLocked() {
		return OwnerCancelExecutionResult{}, ErrOwnerDeviceGroupOfflineRequired
	}
	if group.ownerDeviceGroupReopenRequiredLocked() {
		return OwnerCancelExecutionResult{}, ErrOwnerDeviceGroupReopenRequired
	}
	ownerState, err := group.ownerStateLocked()
	if err != nil {
		return OwnerCancelExecutionResult{}, err
	}
	target, err := validateOwnerGrantedCancelRequestAgainstState(request, ownerState)
	if err != nil {
		return OwnerCancelExecutionResult{}, err
	}
	switch target.State {
	case OwnerAllocationCanceled, OwnerAllocationQuarantined:
		// QUARANTINED does not encode which service operation selected it. The
		// exact durable identity and authority commitments above are the only
		// reliable invariant, so terminal replay is deliberately conservative:
		// return the record without descriptor, payload, allocator, or Owner I/O.
		return ownerCancelResult(target, false, true), nil
	case OwnerAllocationGranted:
		if transitional, blocked := ownerCancelOtherTransitionalRecord(ownerState, 0); blocked {
			return OwnerCancelExecutionResult{}, fmt.Errorf(
				"%w: allocation %d remains in state %d",
				ErrOwnerCancelTransitionBlocked,
				transitional.AllocationRecordID,
				transitional.State)
		}
		plan, planErr := group.preflightFreshGrantedCancelLocked(ownerState, target)
		if planErr != nil {
			if errors.Is(planErr, ErrOwnerCancelDurableContradiction) {
				return OwnerCancelExecutionResult{}, group.ownerCancelFailureLocked(
					planErr,
					false,
					true)
			}
			return OwnerCancelExecutionResult{}, planErr
		}
		if commitErr := group.anchor.commitOwnerState(plan.cancelingState); commitErr != nil {
			return OwnerCancelExecutionResult{}, group.ownerCancelFailureLocked(
				commitErr,
				group.anchor.reopenRequired,
				false)
		}
		return group.executeCancelingRecoveryPlanLocked(plan, false)
	case OwnerAllocationCanceling:
		canceling, present, activeErr := ownerCancelActiveCanceling(ownerState)
		if activeErr != nil || !present || !reservedDescriptorRecordsEqual(canceling, target) {
			if activeErr == nil {
				activeErr = ownerCancelOfflinef(
					"allocation %d is not the exact active CANCELING record",
					target.AllocationRecordID)
			}
			return OwnerCancelExecutionResult{}, group.ownerCancelFailureLocked(
				activeErr,
				false,
				true)
		}
		if transitional, other := ownerCancelOtherTransitionalRecord(
			ownerState,
			target.AllocationRecordID); other {
			return OwnerCancelExecutionResult{}, group.ownerCancelFailureLocked(
				ownerCancelOfflinef(
					"allocation %d remains in state %d beside active CANCELING %d",
					transitional.AllocationRecordID,
					transitional.State,
					target.AllocationRecordID),
				false,
				true)
		}
		return group.recoverCancelingLocked(ownerState, canceling, true)
	default:
		return OwnerCancelExecutionResult{}, ownerCancelConflictf(
			"allocation %d is in state %d, not GRANTED/CANCELING/terminal cancellation",
			target.AllocationRecordID,
			target.State)
	}
}

// RecoverCancelingCheckpoint resumes the one exact durable CANCELING record.
// It accepts no caller-selected target or fresh authority: durable CANCELING is
// the evidence that the authenticated service completed the Producer fence
// before allowing the transition.
func (group *OwnerDeviceGroup) RecoverCancelingCheckpoint() (
	OwnerCancelExecutionResult,
	error,
) {
	if !group.ownerDeviceGroupHandleValid() {
		return OwnerCancelExecutionResult{}, ErrOwnerDeviceGroupInput
	}
	group.executionState.mu.Lock()
	defer group.executionState.mu.Unlock()
	if group.ownerDeviceGroupOfflineRequiredLocked() {
		return OwnerCancelExecutionResult{}, ErrOwnerDeviceGroupOfflineRequired
	}
	if group.ownerDeviceGroupReopenRequiredLocked() {
		return OwnerCancelExecutionResult{}, ErrOwnerDeviceGroupReopenRequired
	}
	ownerState, err := group.ownerStateLocked()
	if err != nil {
		return OwnerCancelExecutionResult{}, err
	}
	canceling, present, err := ownerCancelActiveCanceling(ownerState)
	if err != nil {
		return OwnerCancelExecutionResult{}, group.ownerCancelFailureLocked(err, false, true)
	}
	if !present {
		return OwnerCancelExecutionResult{}, ErrOwnerCancelNoCanceling
	}
	if transitional, other := ownerCancelOtherTransitionalRecord(
		ownerState,
		canceling.AllocationRecordID); other {
		return OwnerCancelExecutionResult{}, group.ownerCancelFailureLocked(
			ownerCancelOfflinef(
				"allocation %d remains in state %d beside active CANCELING %d",
				transitional.AllocationRecordID,
				transitional.State,
				canceling.AllocationRecordID),
			false,
			true)
	}
	return group.recoverCancelingLocked(ownerState, canceling, true)
}

func ownerCancelResult(
	record OwnerStateAllocationRecord,
	forwardRecovered bool,
	replayed bool,
) OwnerCancelExecutionResult {
	disposition := OwnerCancelClean
	if record.State == OwnerAllocationQuarantined {
		disposition = OwnerCancelQuarantine
	}
	return OwnerCancelExecutionResult{
		Record:           cloneOwnerStateRecord(record),
		Disposition:      disposition,
		ForwardRecovered: forwardRecovered,
		Replayed:         replayed,
	}
}

func validateOwnerGrantedCancelRequestAgainstState(
	request OwnerGrantedCancelRequest,
	ownerState OwnerStateSnapshot,
) (OwnerStateAllocationRecord, error) {
	if err := validateOwnerGrantedCancelRequest(request); err != nil {
		return OwnerStateAllocationRecord{}, err
	}
	if request.ClusterID != ownerState.ClusterID ||
		request.OwnerGroupID != ownerState.OwnerGroupID ||
		request.CurrentOwnerID != ownerState.CurrentOwnerID ||
		request.AnchorDeviceUUID != ownerState.AnchorDeviceUUID ||
		request.StorageCompatibilityID != ownerState.StorageCompatibilityID ||
		request.OwnerEpoch != ownerState.OwnerEpoch ||
		request.GroupConfigurationSequence != ownerState.GroupConfigurationSequence ||
		request.MembershipSHA256 != ownerState.MembershipSHA256 {
		return OwnerStateAllocationRecord{}, ownerCancelAuthorityf(
			"request static Owner-group identity differs from durable state")
	}
	var target *OwnerStateAllocationRecord
	for _, record := range ownerState.Records() {
		if record.AllocationRecordID != request.AllocationRecordID {
			continue
		}
		copy := cloneOwnerStateRecord(record)
		target = &copy
		break
	}
	if target == nil || target.RequestID != request.RequestID ||
		target.CheckpointID != request.CheckpointID ||
		target.ProducerID != request.ProducerID {
		return OwnerStateAllocationRecord{}, ownerCancelConflictf(
			"allocation/request/checkpoint/Producer identity does not name one durable record")
	}
	if target.AuthorityEvidence.ProducerCapabilitySHA256 == ([sha256.Size]byte{}) ||
		target.AuthorityEvidence.ProducerCapabilitySHA256 != request.ProducerCapabilitySHA256 {
		return OwnerStateAllocationRecord{}, ownerCancelAuthorityf(
			"Producer capability SHA-256 differs from durable commitment")
	}
	if target.AuthorityEvidence.ReclaimAuthoritySHA256 == ([sha256.Size]byte{}) ||
		target.AuthorityEvidence.ReclaimAuthoritySHA256 != request.ReclaimAuthoritySHA256 {
		return OwnerStateAllocationRecord{}, ownerCancelAuthorityf(
			"reclaim authority SHA-256 differs from durable commitment")
	}
	return *target, nil
}

func validateOwnerGrantedCancelRequest(request OwnerGrantedCancelRequest) error {
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
		{"Producer ID", request.ProducerID},
	} {
		if err := validateOwnerStateIdentity(identity.name, identity.value); err != nil {
			return ownerCancelInvalidf("%v", err)
		}
	}
	if err := validateOwnerStateDeviceUUID("anchor device UUID", request.AnchorDeviceUUID); err != nil {
		return ownerCancelInvalidf("%v", err)
	}
	if request.StorageCompatibilityID != cxlcheckpoint.V7StorageCompatibilityID {
		return ownerCancelInvalidf("storage compatibility ID differs from compiled V7")
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
			return ownerCancelInvalidf("%v", err)
		}
	}
	if request.MembershipSHA256 == ([sha256.Size]byte{}) {
		return ownerCancelInvalidf("membership SHA-256 is zero")
	}
	if request.ProducerCapabilitySHA256 == ([sha256.Size]byte{}) {
		return ownerCancelInvalidf("Producer capability SHA-256 is zero")
	}
	if request.ReclaimAuthoritySHA256 == ([sha256.Size]byte{}) {
		return ownerCancelInvalidf("reclaim authority SHA-256 is zero")
	}
	if request.ProducerWriteFenceSHA256 == ([sha256.Size]byte{}) {
		return fmt.Errorf("%w: Producer write-fence SHA-256 is zero", ErrOwnerCancelFenceRequired)
	}
	return nil
}

func ownerCancelActiveCanceling(
	ownerState OwnerStateSnapshot,
) (OwnerStateAllocationRecord, bool, error) {
	records := ownerState.Records()
	index := -1
	for current := range records {
		if records[current].State != OwnerAllocationCanceling {
			continue
		}
		if index >= 0 {
			return OwnerStateAllocationRecord{}, false, ownerCancelOfflinef(
				"Owner state contains multiple CANCELING allocations %d and %d",
				records[index].AllocationRecordID,
				records[current].AllocationRecordID)
		}
		index = current
	}
	if index < 0 {
		return OwnerStateAllocationRecord{}, false, nil
	}
	record := records[index]
	wantNext, nextOK := checkedAdd(record.OwnerTransactionSequence, 1)
	wantMinimum, minimumOK := checkedAdd(record.ReservationTransactionSequence, 2)
	if !nextOK || !minimumOK ||
		ownerState.NextOwnerTransactionSequence != wantNext ||
		record.OwnerTransactionSequence < wantMinimum {
		return OwnerStateAllocationRecord{}, false, ownerCancelOfflinef(
			"CANCELING allocation %d has invalid transaction/high-water %d/%d (reservation %d)",
			record.AllocationRecordID,
			record.OwnerTransactionSequence,
			ownerState.NextOwnerTransactionSequence,
			record.ReservationTransactionSequence)
	}
	return record, true, nil
}

func ownerCancelOtherTransitionalRecord(
	ownerState OwnerStateSnapshot,
	exceptAllocationRecordID uint64,
) (OwnerStateAllocationRecord, bool) {
	for _, record := range ownerState.Records() {
		if exceptAllocationRecordID != 0 && record.AllocationRecordID == exceptAllocationRecordID {
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

func (group *OwnerDeviceGroup) preflightFreshGrantedCancelLocked(
	grantedState OwnerStateSnapshot,
	grantedRecord OwnerStateAllocationRecord,
) (ownerCancelRecoveryPlan, error) {
	active, found := reservedDescriptorOwnerRecord(
		grantedState,
		grantedRecord.AllocationRecordID)
	if !found || !reservedDescriptorRecordsEqual(active, grantedRecord) ||
		grantedRecord.State != OwnerAllocationGranted {
		return ownerCancelRecoveryPlan{}, ownerCancelOfflinef(
			"Owner state does not contain exact GRANTED allocation %d",
			grantedRecord.AllocationRecordID)
	}
	cancelingTransaction := grantedState.NextOwnerTransactionSequence
	wantGrant, grantOK := checkedAdd(grantedRecord.ReservationTransactionSequence, 1)
	wantMinimumCancel, cancelOK := checkedAdd(grantedRecord.ReservationTransactionSequence, 2)
	if !grantOK || !cancelOK || grantedRecord.OwnerTransactionSequence != wantGrant ||
		cancelingTransaction < wantMinimumCancel {
		return ownerCancelRecoveryPlan{}, ownerCancelOfflinef(
			"GRANTED allocation %d has invalid reservation/current/cancel transaction %d/%d/%d",
			grantedRecord.AllocationRecordID,
			grantedRecord.ReservationTransactionSequence,
			grantedRecord.OwnerTransactionSequence,
			cancelingTransaction)
	}
	cancelingSnapshotSequence, err := ownerReserveAddSequence(
		grantedState.SnapshotSequence,
		1,
		"CANCELING Owner-state snapshot")
	if err != nil {
		return ownerCancelRecoveryPlan{}, err
	}
	cancelingNextTransaction, err := ownerReserveAddSequence(
		cancelingTransaction,
		1,
		"post-CANCELING Owner transaction")
	if err != nil {
		return ownerCancelRecoveryPlan{}, err
	}
	cancelingRecord := cloneOwnerStateRecord(grantedRecord)
	cancelingRecord.State = OwnerAllocationCanceling
	cancelingRecord.OwnerTransactionSequence = cancelingTransaction
	indexByUUID := make(map[string]int, len(group.devices))
	for index := range group.devices {
		indexByUUID[group.devices[index].deviceUUID] = index
	}
	for index := range cancelingRecord.Fragments {
		fragment := &cancelingRecord.Fragments[index]
		deviceIndex, exists := indexByUUID[fragment.DeviceUUID]
		if !exists || group.devices[deviceIndex].metadata == nil {
			return ownerCancelRecoveryPlan{}, ownerCancelOfflinef(
				"GRANTED fragment device %q is absent", fragment.DeviceUUID)
		}
		target, targetOK := checkedAdd(
			group.devices[deviceIndex].metadata.allocator.SnapshotSequence,
			1)
		if !targetOK || target > cxlcheckpoint.MaxSignedLong {
			return ownerCancelRecoveryPlan{}, fmt.Errorf(
				"%w: cancellation allocator target overflows for device %q",
				ErrDeviceMetadataSequence,
				fragment.DeviceUUID)
		}
		fragment.TargetAllocatorSnapshotSequence = target
	}
	cancelingState, err := ownerCancelReplaceRecordSnapshot(
		grantedState,
		cancelingRecord,
		cancelingSnapshotSequence,
		grantedState.NextAllocationRecordID,
		cancelingNextTransaction,
		group.anchor.geometry)
	if err != nil {
		return ownerCancelRecoveryPlan{}, err
	}
	plan, err := group.buildCancelingRecoveryPlanLocked(
		cancelingState,
		cancelingRecord,
		true)
	if err != nil {
		return ownerCancelRecoveryPlan{}, err
	}
	if err := group.preflightOwnerStateTransitionLocked(
		grantedState,
		cancelingState,
		group.anchor.ownerStateSlot); err != nil {
		return ownerCancelRecoveryPlan{}, err
	}
	cancelingSlot := otherOwnerStateSlot(group.anchor.ownerStateSlot)
	if err := group.preflightOwnerStateTransitionLocked(
		cancelingState,
		plan.cleanTerminalState,
		cancelingSlot); err != nil {
		return ownerCancelRecoveryPlan{}, err
	}
	if err := group.preflightOwnerStateTransitionLocked(
		cancelingState,
		plan.qTerminalState,
		cancelingSlot); err != nil {
		return ownerCancelRecoveryPlan{}, err
	}
	// Every descriptor and content range is checked before durable CANCELING.
	// No payload is modified during this phase.
	if _, err := group.observeOwnerCancelDescriptorsLocked(
		grantedRecord,
		cancelingTransaction,
		plan.devices); err != nil {
		return ownerCancelRecoveryPlan{}, err
	}
	for _, entry := range plan.devices {
		if err := group.devices[entry.deviceIndex].metadata.preflightOwnerCancelContent(
			grantedRecord,
			cancelingTransaction); err != nil {
			return ownerCancelRecoveryPlan{}, err
		}
	}
	return plan, nil
}

func (group *OwnerDeviceGroup) recoverCancelingLocked(
	cancelingState OwnerStateSnapshot,
	cancelingRecord OwnerStateAllocationRecord,
	forwardRecovered bool,
) (OwnerCancelExecutionResult, error) {
	plan, err := group.buildCancelingRecoveryPlanLocked(
		cancelingState,
		cancelingRecord,
		false)
	if err != nil {
		offline := ownerCancelDurablePlanFailureRequiresOffline(err)
		return OwnerCancelExecutionResult{}, group.ownerCancelFailureLocked(
			err,
			!offline,
			offline)
	}
	return group.executeCancelingRecoveryPlanLocked(plan, forwardRecovered)
}

func (group *OwnerDeviceGroup) buildCancelingRecoveryPlanLocked(
	cancelingState OwnerStateSnapshot,
	cancelingRecord OwnerStateAllocationRecord,
	allowProposedState bool,
) (ownerCancelRecoveryPlan, error) {
	if !allowProposedState {
		active, present, err := ownerCancelActiveCanceling(cancelingState)
		if err != nil || !present || !reservedDescriptorRecordsEqual(active, cancelingRecord) {
			if err == nil {
				err = ownerCancelOfflinef(
					"Owner state does not contain exact active CANCELING record")
			}
			return ownerCancelRecoveryPlan{}, err
		}
	}
	if err := cancelingState.CrossCheckBootstrap(group.bootstrap); err != nil {
		return ownerCancelRecoveryPlan{}, err
	}
	wantMinimum, minimumOK := checkedAdd(
		cancelingRecord.ReservationTransactionSequence,
		2)
	if cancelingRecord.State != OwnerAllocationCanceling || !minimumOK ||
		cancelingRecord.OwnerTransactionSequence < wantMinimum {
		return ownerCancelRecoveryPlan{}, ownerCancelOfflinef(
			"record %d is not a valid CANCELING record",
			cancelingRecord.AllocationRecordID)
	}
	terminalTransaction, err := ownerReserveAddSequence(
		cancelingRecord.OwnerTransactionSequence,
		1,
		"cancellation terminal transaction")
	if err != nil {
		return ownerCancelRecoveryPlan{}, err
	}
	terminalSnapshotSequence, err := ownerReserveAddSequence(
		cancelingState.SnapshotSequence,
		1,
		"cancellation terminal Owner-state snapshot")
	if err != nil {
		return ownerCancelRecoveryPlan{}, err
	}
	terminalNextTransaction, err := ownerReserveAddSequence(
		terminalTransaction,
		1,
		"post-cancellation-terminal Owner transaction")
	if err != nil {
		return ownerCancelRecoveryPlan{}, err
	}
	cleanRecord := cloneOwnerStateRecord(cancelingRecord)
	cleanRecord.State = OwnerAllocationCanceled
	cleanRecord.OwnerTransactionSequence = terminalTransaction
	qRecord := cloneOwnerStateRecord(cancelingRecord)
	qRecord.State = OwnerAllocationQuarantined
	qRecord.OwnerTransactionSequence = terminalTransaction
	cleanState, err := ownerCancelReplaceRecordSnapshot(
		cancelingState,
		cleanRecord,
		terminalSnapshotSequence,
		cancelingState.NextAllocationRecordID,
		terminalNextTransaction,
		group.anchor.geometry)
	if err != nil {
		return ownerCancelRecoveryPlan{}, err
	}
	qState, err := ownerCancelReplaceRecordSnapshot(
		cancelingState,
		qRecord,
		terminalSnapshotSequence,
		cancelingState.NextAllocationRecordID,
		terminalNextTransaction,
		group.anchor.geometry)
	if err != nil {
		return ownerCancelRecoveryPlan{}, err
	}
	if err := group.preflightOwnerStateEncodingLocked(cleanState); err != nil {
		return ownerCancelRecoveryPlan{}, err
	}
	if err := group.preflightOwnerStateEncodingLocked(qState); err != nil {
		return ownerCancelRecoveryPlan{}, err
	}
	if !allowProposedState {
		if err := group.preflightOwnerStateTransitionLocked(
			cancelingState,
			cleanState,
			group.anchor.ownerStateSlot); err != nil {
			return ownerCancelRecoveryPlan{}, err
		}
		if err := group.preflightOwnerStateTransitionLocked(
			cancelingState,
			qState,
			group.anchor.ownerStateSlot); err != nil {
			return ownerCancelRecoveryPlan{}, err
		}
	}

	indexByUUID := make(map[string]int, len(group.devices))
	for index := range group.devices {
		indexByUUID[group.devices[index].deviceUUID] = index
	}
	affected := make(map[string]bool, len(cancelingRecord.Fragments))
	devices := make([]ownerCancelRecoveryDevice, 0, len(cancelingRecord.Fragments))
	for _, fragment := range cancelingRecord.Fragments {
		deviceIndex, exists := indexByUUID[fragment.DeviceUUID]
		if !exists || affected[fragment.DeviceUUID] {
			return ownerCancelRecoveryPlan{}, ownerCancelOfflinef(
				"CANCELING fragment device %q is missing or repeated",
				fragment.DeviceUUID)
		}
		affected[fragment.DeviceUUID] = true
		entry, classifyErr := group.classifyCancelingAllocatorLocked(
			deviceIndex,
			fragment,
			cancelingRecord.OwnerTransactionSequence,
			cancelingState.NextOwnerTransactionSequence)
		if classifyErr != nil {
			return ownerCancelRecoveryPlan{}, classifyErr
		}
		devices = append(devices, entry)
	}
	// An unaffected device may contain later work applied after this record's R,
	// but no allocator may claim C or a later transaction: C is the unique active
	// cancellation transaction issued by the Owner high-water.
	for index := range group.devices {
		opened := group.devices[index]
		if affected[opened.deviceUUID] {
			continue
		}
		if opened.metadata == nil ||
			opened.metadata.allocator.AppliedOwnerTransactionSequence >=
				cancelingRecord.OwnerTransactionSequence {
			applied := uint64(0)
			if opened.metadata != nil {
				applied = opened.metadata.allocator.AppliedOwnerTransactionSequence
			}
			return ownerCancelRecoveryPlan{}, ownerCancelOfflinef(
				"unaffected device %q applied transaction %d collides with cancellation %d",
				opened.deviceUUID,
				applied,
				cancelingRecord.OwnerTransactionSequence)
		}
	}
	sort.Slice(devices, func(left, right int) bool {
		return devices[left].deviceUUID < devices[right].deviceUUID
	})
	return ownerCancelRecoveryPlan{
		cancelingState:      cancelingState.Clone(),
		cancelingRecord:     cloneOwnerStateRecord(cancelingRecord),
		cleanTerminalState:  cleanState,
		cleanTerminalRecord: cleanRecord,
		qTerminalState:      qState,
		qTerminalRecord:     qRecord,
		devices:             devices,
	}, nil
}

func (group *OwnerDeviceGroup) classifyCancelingAllocatorLocked(
	deviceIndex int,
	fragment OwnerStateDeviceFragment,
	cancelingTransaction uint64,
	issuedTransactionHighWater uint64,
) (ownerCancelRecoveryDevice, error) {
	if deviceIndex < 0 || deviceIndex >= len(group.devices) {
		return ownerCancelRecoveryDevice{}, ownerCancelOfflinef(
			"CANCELING device index %d is outside group", deviceIndex)
	}
	opened := group.devices[deviceIndex]
	if opened.metadata == nil || opened.deviceUUID != fragment.DeviceUUID {
		return ownerCancelRecoveryDevice{}, ownerCancelOfflinef(
			"CANCELING device %q does not match opened group", fragment.DeviceUUID)
	}
	current := opened.metadata.allocator
	if err := current.CrossCheck(
		opened.geometry,
		opened.metadata.superblock.DeviceBindingSHA256(),
		opened.metadata.superblock.OwnerGroupIdentitySHA256(),
		opened.metadata.superblock.OwnerEpoch); err != nil {
		return ownerCancelRecoveryDevice{}, ownerCancelOfflinef(
			"device %q active allocator: %v", fragment.DeviceUUID, err)
	}
	nextSequence, sequenceOK := checkedAdd(current.SnapshotSequence, 1)
	beforeApply := sequenceOK &&
		nextSequence == fragment.TargetAllocatorSnapshotSequence &&
		current.AppliedOwnerTransactionSequence < cancelingTransaction
	afterApply := current.SnapshotSequence == fragment.TargetAllocatorSnapshotSequence &&
		current.AppliedOwnerTransactionSequence == cancelingTransaction
	if !beforeApply && !afterApply {
		return ownerCancelRecoveryDevice{}, ownerCancelOfflinef(
			"device %q allocator %d/%d is neither before nor after cancellation target %d/%d",
			fragment.DeviceUUID,
			current.SnapshotSequence,
			current.AppliedOwnerTransactionSequence,
			fragment.TargetAllocatorSnapshotSequence,
			cancelingTransaction)
	}

	bitmap := current.BitmapBytes()
	selectedState, err := ownerCancelSelectedBitmapState(bitmap, fragment)
	if err != nil {
		return ownerCancelRecoveryDevice{}, err
	}
	entry := ownerCancelRecoveryDevice{
		deviceIndex: deviceIndex,
		deviceUUID:  fragment.DeviceUUID,
		fragment:    cloneOwnerStateFragment(fragment),
		beforeApply: beforeApply,
	}
	if afterApply {
		if selectedState != OwnerCancelClean && selectedState != OwnerCancelQuarantine {
			return ownerCancelRecoveryDevice{}, ownerCancelOfflinef(
				"device %q applied cancellation transaction has mixed selected bits",
				fragment.DeviceUUID)
		}
		entry.appliedDisposition = selectedState
		entry.desiredClean = current.Clone()
		entry.desiredQuarantine = current.Clone()
		return entry, nil
	}
	if selectedState != OwnerCancelQuarantine {
		return ownerCancelRecoveryDevice{}, ownerCancelOfflinef(
			"device %q GRANTED pages are not all allocated before cancellation",
			fragment.DeviceUUID)
	}
	cleanBitmap := append([]byte(nil), bitmap...)
	qBitmap := append([]byte(nil), bitmap...)
	for _, extent := range fragment.Extents {
		end, ok := checkedAdd(extent.StartDataPageIndex, extent.PageCount)
		if !ok || end > current.DataPageCount {
			return ownerCancelRecoveryDevice{}, ownerCancelOfflinef(
				"device %q cancellation extent exceeds allocator",
				fragment.DeviceUUID)
		}
		for page := extent.StartDataPageIndex; page < end; page++ {
			ownerCancelClearBitmap(cleanBitmap, page)
			ownerAllocatorSetBitmap(qBitmap, page)
		}
	}
	entry.desiredClean, err = NewAllocatorSnapshot(AllocatorSnapshotConfig{
		DeviceBindingSHA256:             current.DeviceBindingSHA256,
		OwnerGroupIdentitySHA256:        current.OwnerGroupIdentitySHA256,
		OwnerEpoch:                      current.OwnerEpoch,
		SnapshotSequence:                fragment.TargetAllocatorSnapshotSequence,
		AppliedOwnerTransactionSequence: cancelingTransaction,
		DataPageCount:                   current.DataPageCount,
	}, cleanBitmap)
	if err != nil {
		return ownerCancelRecoveryDevice{}, err
	}
	entry.desiredQuarantine, err = NewAllocatorSnapshot(AllocatorSnapshotConfig{
		DeviceBindingSHA256:             current.DeviceBindingSHA256,
		OwnerGroupIdentitySHA256:        current.OwnerGroupIdentitySHA256,
		OwnerEpoch:                      current.OwnerEpoch,
		SnapshotSequence:                fragment.TargetAllocatorSnapshotSequence,
		AppliedOwnerTransactionSequence: cancelingTransaction,
		DataPageCount:                   current.DataPageCount,
	}, qBitmap)
	if err != nil {
		return ownerCancelRecoveryDevice{}, err
	}
	if err := group.preflightAllocatorCommitLocked(
		opened.metadata,
		entry.desiredClean,
		issuedTransactionHighWater); err != nil {
		return ownerCancelRecoveryDevice{}, err
	}
	if err := group.preflightAllocatorCommitLocked(
		opened.metadata,
		entry.desiredQuarantine,
		issuedTransactionHighWater); err != nil {
		return ownerCancelRecoveryDevice{}, err
	}
	return entry, nil
}

func ownerCancelSelectedBitmapState(
	bitmap []byte,
	fragment OwnerStateDeviceFragment,
) (OwnerCancelDisposition, error) {
	seen := false
	first := false
	for _, extent := range fragment.Extents {
		end, ok := checkedAdd(extent.StartDataPageIndex, extent.PageCount)
		if !ok {
			return 0, ownerCancelOfflinef("cancellation extent overflows")
		}
		for page := extent.StartDataPageIndex; page < end; page++ {
			if page/8 >= uint64(len(bitmap)) {
				return 0, ownerCancelOfflinef(
					"cancellation page %d exceeds allocator bitmap", page)
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
		return 0, ownerCancelOfflinef("cancellation fragment selects no pages")
	}
	if first {
		return OwnerCancelQuarantine, nil
	}
	return OwnerCancelClean, nil
}

func ownerCancelClearBitmap(bitmap []byte, page uint64) {
	bitmap[page/8] &^= byte(1) << uint(page%8)
}

func (group *OwnerDeviceGroup) observeOwnerCancelDescriptorsLocked(
	authorityRecord OwnerStateAllocationRecord,
	cancelingTransaction uint64,
	devices []ownerCancelRecoveryDevice,
) ([]ownerCancelDescriptorObservation, error) {
	observations := make([]ownerCancelDescriptorObservation, len(devices))
	for index, entry := range devices {
		observation, err := group.devices[entry.deviceIndex].metadata.
			inspectOwnerCancelDescriptors(authorityRecord, cancelingTransaction)
		if err != nil {
			return nil, err
		}
		observations[index] = observation
	}
	return observations, nil
}

func ownerCancelChooseDisposition(
	devices []ownerCancelRecoveryDevice,
	observations []ownerCancelDescriptorObservation,
) (OwnerCancelDisposition, error) {
	if len(devices) == 0 || len(devices) != len(observations) {
		return 0, ownerCancelOfflinef(
			"cancellation device/descriptor observation counts differ")
	}
	fixed := OwnerCancelDisposition(0)
	for _, entry := range devices {
		if entry.appliedDisposition == 0 {
			continue
		}
		if fixed == 0 {
			fixed = entry.appliedDisposition
		} else if fixed != entry.appliedDisposition {
			return 0, ownerCancelOfflinef(
				"applied cancellation allocators disagree on Clean/Quarantine disposition")
		}
	}
	if fixed != 0 {
		for index, observation := range observations {
			complete := observation.cleanDispositionComplete()
			if fixed == OwnerCancelQuarantine {
				complete = observation.quarantineDispositionComplete()
			}
			if !complete {
				return 0, ownerCancelOfflinef(
					"device %q descriptors contradict applied cancellation disposition %d",
					devices[index].deviceUUID,
					fixed)
			}
		}
		return fixed, nil
	}
	for _, observation := range observations {
		if observation.requiresQuarantine() {
			return OwnerCancelQuarantine, nil
		}
	}
	return OwnerCancelClean, nil
}

func (group *OwnerDeviceGroup) executeCancelingRecoveryPlanLocked(
	plan ownerCancelRecoveryPlan,
	forwardRecovered bool,
) (OwnerCancelExecutionResult, error) {
	observations, err := group.observeOwnerCancelDescriptorsLocked(
		plan.cancelingRecord,
		plan.cancelingRecord.OwnerTransactionSequence,
		plan.devices)
	if err != nil {
		return OwnerCancelExecutionResult{}, group.ownerCancelFailureLocked(err, true, false)
	}
	disposition, err := ownerCancelChooseDisposition(plan.devices, observations)
	if err != nil {
		return OwnerCancelExecutionResult{}, group.ownerCancelFailureLocked(err, false, true)
	}
	hasAppliedLock := false
	for _, entry := range plan.devices {
		if entry.appliedDisposition != 0 {
			hasAppliedLock = true
			break
		}
	}

	if disposition == OwnerCancelClean {
		if !hasAppliedLock {
			// Zero and Sync every DAX before the first read-back. No descriptor or
			// allocator can make a page reusable during this phase.
			for _, entry := range plan.devices {
				if err := group.devices[entry.deviceIndex].metadata.
					persistCancelingContentZeroes(plan.cancelingRecord); err != nil {
					return OwnerCancelExecutionResult{}, group.ownerCancelFailureLocked(
						err,
						true,
						false)
				}
			}
		}
		for _, entry := range plan.devices {
			if err := group.devices[entry.deviceIndex].metadata.
				verifyCancelingContentZeroes(plan.cancelingRecord); err != nil {
				if errors.Is(err, ErrOwnerCancelContentNotZero) {
					if hasAppliedLock {
						return OwnerCancelExecutionResult{}, group.ownerCancelFailureLocked(
							err,
							false,
							true)
					}
					// No allocator has made any selected page reusable. Preserve the
					// whole checkpoint by switching to Quarantine, but still read every
					// affected DAX so an I/O failure cannot be hidden by this fallback.
					disposition = OwnerCancelQuarantine
					continue
				}
				return OwnerCancelExecutionResult{}, group.ownerCancelFailureLocked(
					err,
					true,
					false)
			}
		}
	}

	// All descriptor Sync boundaries finish before the first allocator commit.
	for _, entry := range plan.devices {
		if err := group.devices[entry.deviceIndex].metadata.
			persistCancelingDescriptorDisposition(
				plan.cancelingRecord,
				disposition,
				hasAppliedLock); err != nil {
			offline := hasAppliedLock && errors.Is(
				err,
				ErrOwnerCancelDescriptorDispositionChanged)
			return OwnerCancelExecutionResult{}, group.ownerCancelFailureLocked(
				err,
				!offline,
				offline)
		}
	}

	for _, entry := range plan.devices {
		if !entry.beforeApply {
			continue
		}
		desired := entry.desiredClean
		if disposition == OwnerCancelQuarantine {
			desired = entry.desiredQuarantine
		}
		if err := group.devices[entry.deviceIndex].metadata.
			commitAllocatorSnapshot(desired); err != nil {
			return OwnerCancelExecutionResult{}, group.ownerCancelFailureLocked(
				err,
				true,
				false)
		}
	}

	if err := group.refreshOwnerDeviceGroupMetadataLocked(); err != nil {
		group.executionState.reopenRequired = true
		return OwnerCancelExecutionResult{}, group.ownerCancelFailureLocked(err, true, false)
	}
	selectedOwner, err := group.ownerStateLocked()
	if err != nil {
		group.executionState.reopenRequired = true
		return OwnerCancelExecutionResult{}, group.ownerCancelFailureLocked(err, true, false)
	}
	selectedCanceling, present, err := ownerCancelActiveCanceling(selectedOwner)
	if err != nil || !present || !reservedDescriptorRecordsEqual(
		selectedCanceling,
		plan.cancelingRecord) || !ownerStateSnapshotsCanonicalEqual(
		selectedOwner,
		plan.cancelingState,
		group.anchor.geometry) {
		if err == nil {
			err = ownerCancelOfflinef(
				"fresh Owner observation differs from exact CANCELING state")
		}
		return OwnerCancelExecutionResult{}, group.ownerCancelFailureLocked(err, false, true)
	}
	reconciled, err := group.buildCancelingRecoveryPlanLocked(
		selectedOwner,
		selectedCanceling,
		false)
	if err != nil {
		offline := ownerCancelDurablePlanFailureRequiresOffline(err)
		return OwnerCancelExecutionResult{}, group.ownerCancelFailureLocked(
			err,
			!offline,
			offline)
	}
	for _, entry := range reconciled.devices {
		if entry.beforeApply {
			return OwnerCancelExecutionResult{}, group.ownerCancelFailureLocked(
				ownerCancelOfflinef(
					"device %q allocator remained before cancellation target",
					entry.deviceUUID),
				false,
				true)
		}
	}
	reconciledObservations, err := group.observeOwnerCancelDescriptorsLocked(
		selectedCanceling,
		selectedCanceling.OwnerTransactionSequence,
		reconciled.devices)
	if err != nil {
		return OwnerCancelExecutionResult{}, group.ownerCancelFailureLocked(err, true, false)
	}
	reconciledDisposition, err := ownerCancelChooseDisposition(
		reconciled.devices,
		reconciledObservations)
	if err != nil || reconciledDisposition != disposition {
		if err == nil {
			err = ownerCancelOfflinef(
				"fresh disposition %d differs from executed disposition %d",
				reconciledDisposition,
				disposition)
		}
		return OwnerCancelExecutionResult{}, group.ownerCancelFailureLocked(err, false, true)
	}
	if disposition == OwnerCancelClean {
		for _, entry := range reconciled.devices {
			if err := group.devices[entry.deviceIndex].metadata.
				verifyCancelingContentZeroes(selectedCanceling); err != nil {
				offline := errors.Is(err, ErrOwnerCancelContentNotZero)
				return OwnerCancelExecutionResult{}, group.ownerCancelFailureLocked(
					err,
					!offline,
					offline)
			}
		}
	}

	terminalState := reconciled.cleanTerminalState
	terminalRecord := reconciled.cleanTerminalRecord
	if disposition == OwnerCancelQuarantine {
		terminalState = reconciled.qTerminalState
		terminalRecord = reconciled.qTerminalRecord
	}
	if err := group.anchor.commitOwnerState(terminalState); err != nil {
		return OwnerCancelExecutionResult{}, group.ownerCancelFailureLocked(err, true, false)
	}
	if err := group.refreshOwnerDeviceGroupMetadataLocked(); err != nil {
		group.executionState.reopenRequired = true
		return OwnerCancelExecutionResult{}, group.ownerCancelFailureLocked(err, true, false)
	}
	terminalOwner, err := group.ownerStateLocked()
	if err != nil || !ownerStateSnapshotsCanonicalEqual(
		terminalOwner,
		terminalState,
		group.anchor.geometry) {
		if err == nil {
			err = ownerCancelOfflinef(
				"fresh Owner observation differs from exact cancellation terminal state")
		}
		return OwnerCancelExecutionResult{}, group.ownerCancelFailureLocked(err, false, true)
	}
	selectedTerminal, found := reservedDescriptorOwnerRecord(
		terminalOwner,
		terminalRecord.AllocationRecordID)
	if !found || !reservedDescriptorRecordsEqual(selectedTerminal, terminalRecord) {
		return OwnerCancelExecutionResult{}, group.ownerCancelFailureLocked(
			ownerCancelOfflinef(
				"fresh Owner observation lacks exact cancellation terminal record"),
			false,
			true)
	}
	return ownerCancelResult(selectedTerminal, forwardRecovered, false), nil
}

func ownerCancelReplaceRecordSnapshot(
	base OwnerStateSnapshot,
	record OwnerStateAllocationRecord,
	snapshotSequence uint64,
	nextAllocationRecordID uint64,
	nextTransactionSequence uint64,
	anchorGeometry DeviceGeometry,
) (OwnerStateSnapshot, error) {
	records := base.Records()
	index := -1
	for current := range records {
		if records[current].AllocationRecordID != record.AllocationRecordID {
			continue
		}
		if index >= 0 {
			return OwnerStateSnapshot{}, ownerCancelOfflinef(
				"allocation record %d appears more than once",
				record.AllocationRecordID)
		}
		index = current
	}
	if index < 0 {
		return OwnerStateSnapshot{}, ownerCancelOfflinef(
			"cannot replace missing allocation record %d",
			record.AllocationRecordID)
	}
	if !ownerCancelRecordImmutableShapeEqual(records[index], record) {
		return OwnerStateSnapshot{}, ownerCancelOfflinef(
			"allocation record %d changed immutable cancellation authority or allocation shape",
			record.AllocationRecordID)
	}
	records[index] = cloneOwnerStateRecord(record)
	return ownerReserveNewSnapshot(
		base,
		records,
		snapshotSequence,
		nextAllocationRecordID,
		nextTransactionSequence,
		anchorGeometry)
}

// ownerCancelRecordImmutableShapeEqual admits only the fields that this state
// machine is allowed to advance: State, OwnerTransactionSequence, and each
// fragment's TargetAllocatorSnapshotSequence. In particular, immutable R and
// every identity, request, demand, extent, and authority commitment must remain
// byte-for-byte equivalent under the canonical in-memory representation.
func ownerCancelRecordImmutableShapeEqual(
	left OwnerStateAllocationRecord,
	right OwnerStateAllocationRecord,
) bool {
	if len(left.Fragments) != len(right.Fragments) {
		return false
	}
	left = cloneOwnerStateRecord(left)
	right = cloneOwnerStateRecord(right)
	right.State = left.State
	right.OwnerTransactionSequence = left.OwnerTransactionSequence
	for index := range left.Fragments {
		right.Fragments[index].TargetAllocatorSnapshotSequence =
			left.Fragments[index].TargetAllocatorSnapshotSequence
	}
	return reservedDescriptorRecordsEqual(left, right)
}

func ownerCancelDurablePlanFailureRequiresOffline(err error) bool {
	return errors.Is(err, ErrOwnerCancelDurableContradiction) ||
		errors.Is(err, ErrOwnerReserveSequenceOverflow) ||
		errors.Is(err, ErrDeviceMetadataSequence)
}

func (group *OwnerDeviceGroup) ownerCancelFailureLocked(
	cause error,
	recoveryRequired bool,
	offlineRequired bool,
) error {
	if cause == nil {
		cause = errors.New("unspecified Owner GRANTED cancellation failure")
	}
	if offlineRequired || errors.Is(cause, ErrOwnerCancelDurableContradiction) {
		group.executionState.offlineRequired = true
		offlineRequired = true
		recoveryRequired = false
	}
	reopenRequired := group.ownerDeviceGroupReopenRequiredLocked()
	if !recoveryRequired && !offlineRequired && !reopenRequired {
		return cause
	}
	return &ownerCancelExecutionError{
		cause:          cause,
		recoveryNeeded: recoveryRequired,
		reopenNeeded:   reopenRequired,
		offlineNeeded:  offlineRequired,
	}
}

func ownerCancelInvalidf(format string, arguments ...interface{}) error {
	return fmt.Errorf(
		"%w: %s",
		ErrInvalidOwnerGrantedCancelRequest,
		fmt.Sprintf(format, arguments...))
}

func ownerCancelAuthorityf(format string, arguments ...interface{}) error {
	return fmt.Errorf(
		"%w: %s",
		ErrOwnerCancelAuthorityConflict,
		fmt.Sprintf(format, arguments...))
}

func ownerCancelConflictf(format string, arguments ...interface{}) error {
	return fmt.Errorf(
		"%w: %s",
		ErrOwnerCancelConflict,
		fmt.Sprintf(format, arguments...))
}

func ownerCancelOfflinef(format string, arguments ...interface{}) error {
	return fmt.Errorf(
		"%w: %s",
		ErrOwnerCancelDurableContradiction,
		fmt.Sprintf(format, arguments...))
}

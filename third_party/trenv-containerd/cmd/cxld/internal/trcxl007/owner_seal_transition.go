package trcxl007

import (
	"crypto/sha256"
	"errors"
	"fmt"
)

var (
	// ErrInvalidOwnerSealStateTransition identifies a compact-plan, seal,
	// Owner-group, allocation-record, or lifecycle-sequence mismatch. Planning
	// is pure: this error never implies that Owner state or DAX media changed.
	ErrInvalidOwnerSealStateTransition = errors.New(
		"invalid TRCXL007 Owner seal state transition")
)

// OwnerSealStateTransitions contains the two full Owner-state snapshots that
// bracket descriptor persistence. Both snapshots are detached from the input
// GRANTED state and from each other. Accessors return another deep copy.
//
// Planning these values does not make either snapshot durable and does not
// claim that any payload, descriptor, allocator, device, or publication I/O
// occurred.
type OwnerSealStateTransitions struct {
	committing OwnerStateSnapshot
	committed  OwnerStateSnapshot
}

// Committing returns the detached Q+1 COMMITTING snapshot.
func (transitions OwnerSealStateTransitions) Committing() OwnerStateSnapshot {
	return transitions.committing.Clone()
}

// Committed returns the detached Q+2 COMMITTED snapshot.
func (transitions OwnerSealStateTransitions) Committed() OwnerStateSnapshot {
	return transitions.committed.Clone()
}

// PlanFreshOwnerSealStateTransitions derives the exact durable state sequence
// for one freshly verified GRANTED allocation:
//
//   - COMMITTING: snapshot Q+1, target transaction S, next transaction S+1;
//   - COMMITTED: snapshot Q+2, target transaction S+1, next transaction S+2.
//
// Both records carry the same nonzero Owner-verified seal H. The target is
// selected by AllocationRecordID, not by record position. Every other record,
// the complete device table, and NextAllocationRecordID are preserved exactly.
// This function performs no I/O and makes no durability claim.
func PlanFreshOwnerSealStateTransitions(
	granted OwnerStateSnapshot,
	plan OwnerSealPlan,
	seal OwnerVerifiedSeal,
) (OwnerSealStateTransitions, error) {
	owner := granted.Clone()
	if err := ownerSealValidatePlanAndSeal(plan, seal); err != nil {
		return OwnerSealStateTransitions{}, err
	}
	records, targetIndex, err := ownerSealCrossCheckStatePhase(
		owner,
		plan,
		seal,
		OwnerAllocationGranted,
		plan.OwnerSnapshotSequence(),
		plan.SealTransactionSequence(),
		plan.GrantTransactionSequence(),
		[sha256.Size]byte{},
	)
	if err != nil {
		return OwnerSealStateTransitions{}, err
	}

	sealSHA256 := seal.SHA256()
	committingRecords := cloneOwnerStateRecords(records)
	committingRecords[targetIndex].State = OwnerAllocationCommitting
	committingRecords[targetIndex].OwnerTransactionSequence = plan.SealTransactionSequence()
	committingRecords[targetIndex].OwnerVerifiedSealSHA256 = sealSHA256
	committing, err := ownerSealBuildStateSnapshot(
		owner,
		plan.CommittingOwnerSnapshotSequence(),
		plan.TerminalTransactionSequence(),
		committingRecords,
	)
	if err != nil {
		return OwnerSealStateTransitions{}, ownerSealStateTransitionInvalidf(
			"construct COMMITTING snapshot: %v", err)
	}
	if _, _, err := ownerSealCrossCheckStatePhase(
		committing,
		plan,
		seal,
		OwnerAllocationCommitting,
		plan.CommittingOwnerSnapshotSequence(),
		plan.TerminalTransactionSequence(),
		plan.SealTransactionSequence(),
		sealSHA256,
	); err != nil {
		return OwnerSealStateTransitions{}, ownerSealStateTransitionInvalidf(
			"constructed COMMITTING snapshot: %v", err)
	}

	committedRecords := committing.Records()
	committedRecords[targetIndex].State = OwnerAllocationCommitted
	committedRecords[targetIndex].OwnerTransactionSequence = plan.TerminalTransactionSequence()
	committedRecords[targetIndex].OwnerVerifiedSealSHA256 = sealSHA256
	committed, err := ownerSealBuildStateSnapshot(
		committing,
		plan.TerminalOwnerSnapshotSequence(),
		plan.NextTransactionSequenceAfterTerminal(),
		committedRecords,
	)
	if err != nil {
		return OwnerSealStateTransitions{}, ownerSealStateTransitionInvalidf(
			"construct COMMITTED snapshot: %v", err)
	}
	if _, _, err := ownerSealCrossCheckStatePhase(
		committed,
		plan,
		seal,
		OwnerAllocationCommitted,
		plan.TerminalOwnerSnapshotSequence(),
		plan.NextTransactionSequenceAfterTerminal(),
		plan.TerminalTransactionSequence(),
		sealSHA256,
	); err != nil {
		return OwnerSealStateTransitions{}, ownerSealStateTransitionInvalidf(
			"constructed COMMITTED snapshot: %v", err)
	}

	return OwnerSealStateTransitions{
		committing: committing.Clone(),
		committed:  committed.Clone(),
	}, nil
}

// PlanCommittingOwnerSealCompletion derives the exact Q+2 COMMITTED snapshot
// from an exact durable Q+1 COMMITTING snapshot. If the supplied snapshot is
// already the exact planned Q+2 COMMITTED terminal state, it is returned as a
// detached mutation-free replay. Later unrelated Owner snapshots are outside
// this narrow pure planner and must be handled by the service layer.
func PlanCommittingOwnerSealCompletion(
	committing OwnerStateSnapshot,
	plan OwnerSealPlan,
	seal OwnerVerifiedSeal,
) (OwnerStateSnapshot, error) {
	owner := committing.Clone()
	if err := ownerSealValidatePlanAndSeal(plan, seal); err != nil {
		return OwnerStateSnapshot{}, err
	}
	sealSHA256 := seal.SHA256()

	if owner.SnapshotSequence == plan.TerminalOwnerSnapshotSequence() {
		if _, _, err := ownerSealCrossCheckStatePhase(
			owner,
			plan,
			seal,
			OwnerAllocationCommitted,
			plan.TerminalOwnerSnapshotSequence(),
			plan.NextTransactionSequenceAfterTerminal(),
			plan.TerminalTransactionSequence(),
			sealSHA256,
		); err != nil {
			return OwnerStateSnapshot{}, ownerSealStateTransitionInvalidf(
				"COMMITTED replay: %v", err)
		}
		return owner.Clone(), nil
	}

	records, targetIndex, err := ownerSealCrossCheckStatePhase(
		owner,
		plan,
		seal,
		OwnerAllocationCommitting,
		plan.CommittingOwnerSnapshotSequence(),
		plan.TerminalTransactionSequence(),
		plan.SealTransactionSequence(),
		sealSHA256,
	)
	if err != nil {
		return OwnerStateSnapshot{}, err
	}
	records[targetIndex].State = OwnerAllocationCommitted
	records[targetIndex].OwnerTransactionSequence = plan.TerminalTransactionSequence()
	records[targetIndex].OwnerVerifiedSealSHA256 = sealSHA256
	committed, err := ownerSealBuildStateSnapshot(
		owner,
		plan.TerminalOwnerSnapshotSequence(),
		plan.NextTransactionSequenceAfterTerminal(),
		records,
	)
	if err != nil {
		return OwnerStateSnapshot{}, ownerSealStateTransitionInvalidf(
			"construct COMMITTED completion snapshot: %v", err)
	}
	if _, _, err := ownerSealCrossCheckStatePhase(
		committed,
		plan,
		seal,
		OwnerAllocationCommitted,
		plan.TerminalOwnerSnapshotSequence(),
		plan.NextTransactionSequenceAfterTerminal(),
		plan.TerminalTransactionSequence(),
		sealSHA256,
	); err != nil {
		return OwnerStateSnapshot{}, ownerSealStateTransitionInvalidf(
			"constructed COMMITTED completion snapshot: %v", err)
	}
	return committed.Clone(), nil
}

func ownerSealValidatePlanAndSeal(plan OwnerSealPlan, seal OwnerVerifiedSeal) error {
	if err := plan.Validate(); err != nil {
		return ownerSealStateTransitionInvalidf("seal plan: %v", err)
	}
	if err := seal.Validate(plan); err != nil {
		return ownerSealStateTransitionInvalidf("Owner-verified seal: %v", err)
	}
	return nil
}

func ownerSealCrossCheckStatePhase(
	snapshot OwnerStateSnapshot,
	plan OwnerSealPlan,
	seal OwnerVerifiedSeal,
	wantState OwnerAllocationState,
	wantSnapshotSequence uint64,
	wantNextTransaction uint64,
	wantCurrentTransaction uint64,
	wantSeal [sha256.Size]byte,
) ([]OwnerStateAllocationRecord, int, error) {
	// Only an opaque seal returned by a complete transcript may authorize a
	// transition planner. Media reconstruction uses the scalar-only checker
	// below and must separately verify a recomputed opaque seal before any
	// completion transition.
	if wantState != OwnerAllocationGranted && wantSeal != seal.SHA256() {
		return nil, -1, ownerSealStateTransitionInvalidf(
			"planned phase seal differs from the supplied Owner-verified seal")
	}
	return ownerSealCrossCheckStatePhaseDigest(
		snapshot,
		plan,
		wantState,
		wantSnapshotSequence,
		wantNextTransaction,
		wantCurrentTransaction,
		wantSeal,
	)
}

// ownerSealCrossCheckStatePhaseDigest validates the durable state phase using
// only its persisted seal digest. It does not create, accept, or prove an
// OwnerVerifiedSeal. Recovery may use it while reconstructing a plan, but a
// caller must still finish a complete transcript and use
// ownerSealCrossCheckStatePhase before planning a state mutation.
func ownerSealCrossCheckStatePhaseDigest(
	snapshot OwnerStateSnapshot,
	plan OwnerSealPlan,
	wantState OwnerAllocationState,
	wantSnapshotSequence uint64,
	wantNextTransaction uint64,
	wantCurrentTransaction uint64,
	wantSeal [sha256.Size]byte,
) ([]OwnerStateAllocationRecord, int, error) {
	owner := snapshot.Clone()
	if err := owner.Validate(); err != nil {
		return nil, -1, ownerSealStateTransitionInvalidf("Owner state: %v", err)
	}
	if owner.ClusterID != plan.ClusterID() ||
		owner.OwnerGroupID != plan.OwnerGroupID() ||
		owner.CurrentOwnerID != plan.OwnerID() ||
		owner.AnchorDeviceUUID != plan.AnchorDeviceUUID() ||
		owner.StorageCompatibilityID != plan.StorageCompatibilityID() ||
		owner.OwnerEpoch != plan.OwnerEpoch() ||
		owner.GroupConfigurationSequence != plan.GroupConfigurationSequence() ||
		owner.MembershipSHA256 != plan.MembershipSHA256() {
		return nil, -1, ownerSealStateTransitionInvalidf(
			"Owner-group identity, membership, epoch, or configuration differs from seal plan")
	}
	if owner.SnapshotSequence != wantSnapshotSequence ||
		owner.NextOwnerTransactionSequence != wantNextTransaction {
		return nil, -1, ownerSealStateTransitionInvalidf(
			"Owner snapshot/next-transaction sequence is %d/%d, want %d/%d",
			owner.SnapshotSequence,
			owner.NextOwnerTransactionSequence,
			wantSnapshotSequence,
			wantNextTransaction)
	}

	records := owner.Records()
	targetIndex := -1
	for index := range records {
		if records[index].AllocationRecordID == plan.AllocationRecordID() {
			targetIndex = index
			break
		}
	}
	if targetIndex < 0 {
		return nil, -1, ownerSealStateTransitionInvalidf(
			"allocation record %d is absent", plan.AllocationRecordID())
	}
	target := records[targetIndex]
	if target.State != wantState ||
		target.OwnerTransactionSequence != wantCurrentTransaction ||
		target.OwnerVerifiedSealSHA256 != wantSeal {
		return nil, -1, ownerSealStateTransitionInvalidf(
			"allocation %d state/transaction/seal differs from planned phase",
			target.AllocationRecordID)
	}
	if target.AllocationRecordID != plan.AllocationRecordID() ||
		target.ReservationTransactionSequence != plan.ReservationTransactionSequence() ||
		target.RequestID != plan.RequestID() ||
		target.CheckpointID != plan.CheckpointID() ||
		target.ProducerID != plan.ProducerID() ||
		target.DedupDomainID != plan.DedupDomainID() ||
		target.SharingPolicyID != plan.SharingPolicyID() ||
		target.RequestSHA256 != plan.RequestSHA256() ||
		target.TotalDemandPages != plan.TotalPages() ||
		target.AuthorityEvidence != plan.AuthorityEvidence() {
		return nil, -1, ownerSealStateTransitionInvalidf(
			"allocation %d identity, demand, request, or authority differs from seal plan",
			target.AllocationRecordID)
	}

	// The plan commits the complete canonical GRANTED record. Normalize only
	// the three lifecycle fields changed by this state machine before hashing,
	// so mutations to MaxExtents, demands, fragments, allocator targets, or any
	// other retained field are rejected during fresh planning and recovery.
	hypotheticalGrant := cloneOwnerStateRecord(target)
	hypotheticalGrant.State = OwnerAllocationGranted
	hypotheticalGrant.OwnerTransactionSequence = plan.GrantTransactionSequence()
	hypotheticalGrant.OwnerVerifiedSealSHA256 = [sha256.Size]byte{}
	if producerScatterGrantRecordSHA256(hypotheticalGrant) != plan.GrantRecordSHA256() {
		return nil, -1, ownerSealStateTransitionInvalidf(
			"allocation %d canonical hypothetical GRANTED-record SHA-256 differs",
			target.AllocationRecordID)
	}
	return records, targetIndex, nil
}

func ownerSealBuildStateSnapshot(
	base OwnerStateSnapshot,
	snapshotSequence uint64,
	nextTransactionSequence uint64,
	records []OwnerStateAllocationRecord,
) (OwnerStateSnapshot, error) {
	return NewOwnerStateSnapshot(OwnerStateConfig{
		ClusterID:                    base.ClusterID,
		OwnerGroupID:                 base.OwnerGroupID,
		CurrentOwnerID:               base.CurrentOwnerID,
		AnchorDeviceUUID:             base.AnchorDeviceUUID,
		StorageCompatibilityID:       base.StorageCompatibilityID,
		OwnerEpoch:                   base.OwnerEpoch,
		GroupConfigurationSequence:   base.GroupConfigurationSequence,
		MembershipSHA256:             base.MembershipSHA256,
		SnapshotSequence:             snapshotSequence,
		NextAllocationRecordID:       base.NextAllocationRecordID,
		NextOwnerTransactionSequence: nextTransactionSequence,
		Devices:                      base.Devices(),
		Records:                      records,
	})
}

func ownerSealStateTransitionInvalidf(format string, arguments ...interface{}) error {
	return fmt.Errorf(
		"%w: %s",
		ErrInvalidOwnerSealStateTransition,
		fmt.Sprintf(format, arguments...))
}

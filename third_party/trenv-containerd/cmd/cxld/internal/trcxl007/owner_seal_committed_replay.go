package trcxl007

import (
	"crypto/sha256"

	"github.com/containerd/containerd/third_party/trenv-containerd/pkg/cxlcheckpoint"
)

// CommittedOwnerSealReplayPlan is a detached, mutation-free reconstruction of
// one terminal COMMITTED candidate. It retains only the same compact plan and
// durable H comparison scalar used by COMMITTING recovery. It does
// not contain and cannot mint an OwnerVerifiedSeal, and it does not claim that
// descriptors, payload, or a publication root were reread in this process.
type CommittedOwnerSealReplayPlan struct {
	plan                            OwnerSealPlan
	expectedOwnerVerifiedSealSHA256 [sha256.Size]byte
}

// Plan returns a detached copy of the compact initial-allocation seal plan.
func (replay CommittedOwnerSealReplayPlan) Plan() OwnerSealPlan {
	return cloneOwnerSealPlan(replay.plan)
}

// ExpectedOwnerVerifiedSealSHA256 returns the terminal record's durable H as
// a comparison value. It is not an OwnerVerifiedSeal or proof of a reread.
func (replay CommittedOwnerSealReplayPlan) ExpectedOwnerVerifiedSealSHA256() [sha256.Size]byte {
	return replay.expectedOwnerVerifiedSealSHA256
}

// VerifyRecomputedSeal accepts only an opaque seal returned by a complete
// transcript for this exact reconstructed plan and equal to durable H. Pure
// reconstruction alone does not authorize restore, serving, republication, or
// any terminal-state claim about current media; those paths must provide this
// complete-transcript proof.
func (replay CommittedOwnerSealReplayPlan) VerifyRecomputedSeal(
	seal OwnerVerifiedSeal,
) error {
	plan := cloneOwnerSealPlan(replay.plan)
	if err := plan.Validate(); err != nil {
		return ownerSealRecoveryErrorf("committed replay compact plan: %v", err)
	}
	if replay.expectedOwnerVerifiedSealSHA256 == ([sha256.Size]byte{}) {
		return ownerSealRecoveryErrorf(
			"expected COMMITTED Owner-verified seal SHA-256 is zero")
	}
	if err := seal.Validate(plan); err != nil {
		return ownerSealRecoveryErrorf(
			"recomputed COMMITTED Owner-verified seal: %v", err)
	}
	if seal.SHA256() != replay.expectedOwnerVerifiedSealSHA256 {
		return ownerSealRecoveryErrorf(
			"recomputed Owner-verified seal SHA-256 differs from durable COMMITTED H")
	}
	return nil
}

// BuildCommittedOwnerSealReplayPlan reconstructs one terminal candidate plan
// from a TROWN007 COMMITTED snapshot and the canonical unpadded TRPUB007 and
// initial slot-A TRCPM007 envelopes. It is pure and plans no state or media
// mutation. The durable H can reject a validly encoded retained-field or
// envelope substitution only after a complete transcript recomputes the
// candidate seal; this builder deliberately does not treat reconstruction as
// that proof.
//
// A legal terminal state is the immediate Q+2 / S+1 result of the seal state
// machine. The function reverses only the target state, current transaction,
// and two snapshot high-water scalars changed by COMMITTING -> COMMITTED. It
// delegates the full media join to BuildCommittingOwnerSealRecoveryPlan, then
// checks the original terminal snapshot against the reconstructed plan. No
// caller data, CRC vector, per-page table, capability, I/O seam, or opaque seal
// is retained.
func BuildCommittedOwnerSealReplayPlan(
	committedState OwnerStateSnapshot,
	allocationRecordID uint64,
	publicationEnvelope []byte,
	initialPlacementEnvelope []byte,
) (CommittedOwnerSealReplayPlan, error) {
	owner := committedState.Clone()
	if err := owner.Validate(); err != nil {
		return committedOwnerSealReplayFailure("Owner state: %v", err)
	}
	if allocationRecordID == 0 || allocationRecordID > cxlcheckpoint.MaxSignedLong {
		return committedOwnerSealReplayFailure(
			"allocation record ID %d is outside 1..%d",
			allocationRecordID, cxlcheckpoint.MaxSignedLong)
	}
	records := owner.Records()
	record, found := producerScatterRecordByID(records, allocationRecordID)
	if !found {
		return committedOwnerSealReplayFailure(
			"allocation record %d is absent", allocationRecordID)
	}
	if record.State != OwnerAllocationCommitted {
		return committedOwnerSealReplayFailure(
			"allocation record %d state is %d, want COMMITTED",
			allocationRecordID, record.State)
	}
	if record.OwnerVerifiedSealSHA256 == ([sha256.Size]byte{}) {
		return committedOwnerSealReplayFailure(
			"COMMITTED allocation %d has a zero Owner-verified seal",
			allocationRecordID)
	}

	// COMMITTED is Q+2 with current transaction S+1 and next transaction S+2.
	// Reversing it must produce a positive Q+1 COMMITTING snapshot at S with
	// next transaction S+1. All arithmetic is checked before subtraction.
	if owner.SnapshotSequence <= 2 {
		return committedOwnerSealReplayFailure(
			"COMMITTED snapshot sequence %d cannot derive positive Q and Q+1 sequences",
			owner.SnapshotSequence)
	}
	if record.OwnerTransactionSequence <= 1 || owner.NextOwnerTransactionSequence <= 1 {
		return committedOwnerSealReplayFailure(
			"COMMITTED transaction high water cannot derive a positive seal transaction")
	}
	wantTerminalNext, ok := checkedAdd(record.OwnerTransactionSequence, 1)
	if !ok || wantTerminalNext > cxlcheckpoint.MaxSignedLong ||
		owner.NextOwnerTransactionSequence != wantTerminalNext {
		return committedOwnerSealReplayFailure(
			"COMMITTED next transaction is %d, want terminal transaction %d plus one",
			owner.NextOwnerTransactionSequence,
			record.OwnerTransactionSequence)
	}

	committingRecords := cloneOwnerStateRecords(records)
	targetIndex := -1
	for index := range committingRecords {
		if committingRecords[index].AllocationRecordID == allocationRecordID {
			targetIndex = index
			break
		}
	}
	if targetIndex < 0 {
		return committedOwnerSealReplayFailure(
			"allocation record %d disappeared while detaching state",
			allocationRecordID)
	}
	committingRecords[targetIndex].State = OwnerAllocationCommitting
	committingRecords[targetIndex].OwnerTransactionSequence--
	committing, err := ownerSealBuildStateSnapshot(
		owner,
		owner.SnapshotSequence-1,
		owner.NextOwnerTransactionSequence-1,
		committingRecords,
	)
	if err != nil {
		return committedOwnerSealReplayFailure(
			"reconstruct immediate COMMITTING snapshot: %v", err)
	}

	recovery, err := BuildCommittingOwnerSealRecoveryPlan(
		committing,
		allocationRecordID,
		publicationEnvelope,
		initialPlacementEnvelope,
	)
	if err != nil {
		return committedOwnerSealReplayFailure(
			"reconstruct compact plan through COMMITTING: %v", err)
	}
	plan := recovery.Plan()
	expectedH := recovery.ExpectedOwnerVerifiedSealSHA256()
	if expectedH != record.OwnerVerifiedSealSHA256 {
		return committedOwnerSealReplayFailure(
			"reconstructed COMMITTING H differs from terminal COMMITTED H")
	}
	if _, _, err := ownerSealCrossCheckStatePhaseDigest(
		owner,
		plan,
		OwnerAllocationCommitted,
		plan.TerminalOwnerSnapshotSequence(),
		plan.NextTransactionSequenceAfterTerminal(),
		plan.TerminalTransactionSequence(),
		expectedH,
	); err != nil {
		return committedOwnerSealReplayFailure(
			"exact terminal COMMITTED phase: %v", err)
	}

	return CommittedOwnerSealReplayPlan{
		plan:                            cloneOwnerSealPlan(plan),
		expectedOwnerVerifiedSealSHA256: expectedH,
	}, nil
}

func committedOwnerSealReplayFailure(
	format string,
	arguments ...interface{},
) (CommittedOwnerSealReplayPlan, error) {
	return CommittedOwnerSealReplayPlan{}, ownerSealRecoveryErrorf(format, arguments...)
}

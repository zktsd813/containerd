package trcxl007

import (
	"context"
	"errors"
	"fmt"

	"github.com/containerd/containerd/third_party/trenv-containerd/cmd/cxld/internal/trcxl007dml"
	"github.com/containerd/containerd/third_party/trenv-containerd/pkg/cxlcheckpoint"
)

var (
	// ErrInvalidOwnerSealExecutor identifies an invalid local executor, copied
	// executor handle, nil context, or malformed local execution input. It does
	// not imply that any persistent state changed.
	ErrInvalidOwnerSealExecutor = errors.New("invalid TRCXL007 Owner seal executor")

	// ErrOwnerSealPhaseConflict identifies a request that does not select the
	// exact durable GRANTED, COMMITTING, or immediate COMMITTED phase required by
	// the chosen operation.
	ErrOwnerSealPhaseConflict = errors.New("TRCXL007 Owner seal lifecycle phase conflict")

	// ErrOwnerSealNoCommitting identifies recovery when there is no unique exact
	// durable COMMITTING allocation. Recovery never lets a caller select or mint
	// a transitional record.
	ErrOwnerSealNoCommitting = errors.New("TRCXL007 Owner state has no unique COMMITTING allocation")

	// ErrOwnerSealRecoveryRequired means COMMITTING may already be durable. The
	// caller must establish the external writer fence, reopen the complete Owner
	// group when requested, and forward-recover the same allocation.
	ErrOwnerSealRecoveryRequired = errors.New("TRCXL007 Owner seal requires forward recovery")

	// ErrOwnerSealQuarantineRequired is a checkpoint-local marker for stable
	// content, descriptor, or seal disagreement. This executor does not implement
	// or authorize a COMMITTING/COMMITTED -> QUARANTINED state mutation.
	ErrOwnerSealQuarantineRequired = errors.New("TRCXL007 Owner seal checkpoint requires quarantine")

	// ErrOwnerSealDurableContradiction identifies an allocator, device identity,
	// epoch, membership, authority, or exact Owner-state contradiction. It is a
	// sticky OFFLINE input for the complete Owner group.
	ErrOwnerSealDurableContradiction = errors.New("TRCXL007 Owner seal found a durable authority contradiction")
)

// OwnerGrantedSealInput is a daemon-local, already-authenticated completion
// handoff. The plans are canonical local values and ProducerResult is the
// opaque result returned by the Producer scatter path. Its CRC vector is used
// only for a streaming advisory comparison; it never supplies descriptor CRCs,
// OwnerVerifiedSeal H, or transition authority.
//
// This is not a network wire request. In particular it contains no content
// source, read pass, DAX path/view, BackingID, raw capability, or Copier.
type OwnerGrantedSealInput struct {
	AllocationRecordID uint64
	PublicationPlan    cxlcheckpoint.InitialPublicationV7Plan
	ProducerPlan       ProducerScatterPlan
	ProducerResult     ProducerScatterResult
}

// OwnerSealExecutionResult is detached from the executor and cached metadata.
// ProducerCRCMatch is meaningful only for fresh GRANTED execution. A false
// value records an advisory Producer/Owner CRC disagreement but does not alter
// H or descriptor materialization. The result contains no source, pass, byte
// view, backing identity, Copier, or opaque OwnerVerifiedSeal.
type OwnerSealExecutionResult struct {
	Record           OwnerStateAllocationRecord
	ProducerCRCMatch bool
	ForwardRecovered bool
	Replayed         bool
}

type ownerSealCopierFactory func() (trcxl007dml.Copier, error)

// OwnerSealExecutor is a local host boundary bound at construction time to one
// validated Owner device group and one trusted local direct-content adapter.
// The abstract source remains a trust contract: construction does not prove
// physical DAX provenance. Production wiring must supply the concrete adapter
// derived from already-opened local DAX devices and must never deserialize it
// from a network request.
//
// Every lifecycle method takes the OwnerDeviceGroup process-local execution
// mutex. The caller must additionally hold the distributed Owner writer fence,
// prove Producer write authority has ended, and keep that fence for the whole
// call. This value must not be copied.
type OwnerSealExecutor struct {
	group         *OwnerDeviceGroup
	source        OwnerSealContentSource
	copierFactory ownerSealCopierFactory
	self          *OwnerSealExecutor
}

// NewOwnerSealExecutor binds the validated local group and trusted local source.
// Hardware is opened lazily by a lifecycle call, but the production factory is
// fixed to trcxl007dml.OpenHardware and has no CPU/software fallback. Copier or
// alternate-factory injection is available only through the package-private
// test seam below.
func NewOwnerSealExecutor(
	group *OwnerDeviceGroup,
	source OwnerSealContentSource,
) (*OwnerSealExecutor, error) {
	return newOwnerSealExecutor(group, source, trcxl007dml.OpenHardware)
}

func newOwnerSealExecutor(
	group *OwnerDeviceGroup,
	source OwnerSealContentSource,
	copierFactory ownerSealCopierFactory,
) (*OwnerSealExecutor, error) {
	if group == nil || !group.ownerDeviceGroupHandleValid() {
		return nil, ownerSealExecutorInvalidf("Owner device-group handle is invalid")
	}
	if interfaceIsNil(source) {
		return nil, ownerSealExecutorInvalidf("trusted local content source is nil")
	}
	if copierFactory == nil {
		return nil, ownerSealExecutorInvalidf("hardware Copier factory is nil")
	}
	executor := &OwnerSealExecutor{
		group:         group,
		source:        source,
		copierFactory: copierFactory,
	}
	executor.self = executor
	return executor, nil
}

// ExecuteGrantedCheckpointSeal executes only an exact durable GRANTED record.
// It performs the three hardware rereads and durable GRANTED -> COMMITTING ->
// COMMITTED sequence described by TRCXL007. The Producer result is advisory;
// every authoritative CRC and H comes from a fresh Owner hardware reread.
func (executor *OwnerSealExecutor) ExecuteGrantedCheckpointSeal(
	ctx context.Context,
	input OwnerGrantedSealInput,
) (OwnerSealExecutionResult, error) {
	if err := executor.validateCall(ctx); err != nil {
		return OwnerSealExecutionResult{}, err
	}
	group := executor.group
	group.executionState.mu.Lock()
	defer group.executionState.mu.Unlock()
	if err := executor.validateLockedEntry(ctx); err != nil {
		return OwnerSealExecutionResult{}, err
	}
	return executor.executeGrantedLocked(ctx, input)
}

// RecoverCommittingCheckpointSeal forward-recovers the unique exact durable
// COMMITTING allocation. It accepts no caller-selected record, plan, digest,
// source, or recovery mode; all of those are selected from the bound group and
// trusted local media while the group lock and external fence remain held.
func (executor *OwnerSealExecutor) RecoverCommittingCheckpointSeal(
	ctx context.Context,
) (OwnerSealExecutionResult, error) {
	if err := executor.validateCall(ctx); err != nil {
		return OwnerSealExecutionResult{}, err
	}
	group := executor.group
	group.executionState.mu.Lock()
	defer group.executionState.mu.Unlock()
	if err := executor.validateLockedEntry(ctx); err != nil {
		return OwnerSealExecutionResult{}, err
	}
	return executor.recoverCommittingLocked(ctx)
}

// ReplayCommittedCheckpointSeal validates one exact immediate COMMITTED record
// without persistent mutation. It performs bounded media reconstruction,
// structural target-only preflight, one fresh hardware reread with exact
// per-page descriptor comparison, Copier Close, and a final fresh COMMITTED
// reselect. It performs no descriptor/allocator/Owner write, sequence advance,
// or Sync.
func (executor *OwnerSealExecutor) ReplayCommittedCheckpointSeal(
	ctx context.Context,
	allocationRecordID uint64,
) (OwnerSealExecutionResult, error) {
	if err := executor.validateCall(ctx); err != nil {
		return OwnerSealExecutionResult{}, err
	}
	group := executor.group
	group.executionState.mu.Lock()
	defer group.executionState.mu.Unlock()
	if err := executor.validateLockedEntry(ctx); err != nil {
		return OwnerSealExecutionResult{}, err
	}
	return executor.replayCommittedLocked(ctx, allocationRecordID)
}

func (executor *OwnerSealExecutor) executeGrantedLocked(
	ctx context.Context,
	input OwnerGrantedSealInput,
) (result OwnerSealExecutionResult, resultErr error) {
	group := executor.group
	granted, err := group.ownerStateLocked()
	if err != nil {
		return OwnerSealExecutionResult{}, executor.classifyBeforeCommittingLocked(err)
	}
	if transitional, present := ownerSealOtherTransitionalRecord(granted, 0); present {
		return OwnerSealExecutionResult{}, fmt.Errorf(
			"%w: allocation %d remains in state %d",
			ErrOwnerSealPhaseConflict,
			transitional.AllocationRecordID,
			transitional.State)
	}
	plan, err := BuildFreshOwnerSealPlan(
		granted,
		input.AllocationRecordID,
		input.ProducerPlan,
		input.PublicationPlan)
	if err != nil {
		return OwnerSealExecutionResult{}, fmt.Errorf(
			"%w: build exact fresh plan: %v", ErrOwnerSealPhaseConflict, err)
	}
	producerCRC, err := plan.CrossCheckProducerScatterResult(input.ProducerResult)
	if err != nil {
		return OwnerSealExecutionResult{}, ownerSealExecutorInvalidf(
			"Producer scatter result: %v", err)
	}
	if err := group.preflightOwnerSealDescriptorsLocked(
		plan, ownerSealDescriptorFreshReservedOnly); err != nil {
		return OwnerSealExecutionResult{}, executor.classifyBeforeCommittingLocked(err)
	}

	guard, err := executor.openCopier()
	if err != nil {
		return OwnerSealExecutionResult{}, err
	}
	defer func() {
		if !guard.closed {
			resultErr = guard.close(resultErr)
			if resultErr != nil {
				result = OwnerSealExecutionResult{}
			}
		}
	}()

	advisory := ownerSealProducerCRCAdvisory{
		vector:  producerCRC,
		matched: true,
	}
	seal, err := runOwnerSealRereadTranscriptPass(
		ctx, plan, executor.source, guard.copier, advisory.append)
	if err != nil {
		return OwnerSealExecutionResult{}, err
	}
	transitions, err := PlanFreshOwnerSealStateTransitions(granted, plan, seal)
	if err != nil {
		return OwnerSealExecutionResult{}, err
	}
	committing := transitions.Committing()
	committed := transitions.Committed()
	if err := group.commitExactOwnerSealStateLocked(granted, committing); err != nil {
		if group.anchor != nil && group.anchor.reopenRequired {
			return OwnerSealExecutionResult{}, executor.ownerSealFailureLocked(
				err, true, false, false, true)
		}
		return OwnerSealExecutionResult{}, executor.classifyBeforeCommittingLocked(err)
	}
	if _, err := group.refreshAndRequireOwnerSealStateLocked(committing); err != nil {
		return OwnerSealExecutionResult{}, executor.classifyAfterCommittingLocked(err, false)
	}

	sink, err := group.newOwnerSealDescriptorSinkLocked(
		plan, ownerSealDescriptorFreshReservedOnly)
	if err != nil {
		return OwnerSealExecutionResult{}, executor.classifyAfterCommittingLocked(err, true)
	}
	if _, err := executor.runDescriptorMaterializationLocked(
		ctx, plan, seal, guard.copier, sink); err != nil {
		return OwnerSealExecutionResult{}, executor.classifyAfterCommittingLocked(err, true)
	}
	if err := executor.runPostSyncTerminalPassLocked(
		ctx, committing, plan, seal, guard); err != nil {
		return OwnerSealExecutionResult{}, err
	}
	if err := group.commitExactOwnerSealStateLocked(committing, committed); err != nil {
		return OwnerSealExecutionResult{}, executor.ownerSealFailureLocked(
			err, true, false, false, true)
	}
	selected, err := group.refreshAndRequireOwnerSealStateLocked(committed)
	if err != nil {
		return OwnerSealExecutionResult{}, executor.classifyAfterCommittingLocked(err, false)
	}
	record, found := producerScatterRecordByID(
		selected.Records(), plan.AllocationRecordID())
	if !found {
		return OwnerSealExecutionResult{}, executor.ownerSealFailureLocked(
			ownerSealDurableContradictionf("final COMMITTED record disappeared"),
			false, false, true, true)
	}
	return ownerSealExecutionResult(record, advisory.matched, false, false), nil
}

func (executor *OwnerSealExecutor) recoverCommittingLocked(
	ctx context.Context,
) (result OwnerSealExecutionResult, resultErr error) {
	group := executor.group
	committing, err := group.ownerStateLocked()
	if err != nil {
		return OwnerSealExecutionResult{}, executor.classifyBeforeCommittingLocked(err)
	}
	record, err := ownerSealUniqueCommittingRecord(committing)
	if err != nil {
		if errors.Is(err, ErrOwnerSealDurableContradiction) {
			return OwnerSealExecutionResult{}, executor.ownerSealFailureLocked(
				err, false, false, true, true)
		}
		return OwnerSealExecutionResult{}, err
	}
	recovery, err := LoadCommittingOwnerSealRecoveryPlanFromMedia(
		ctx, committing, record.AllocationRecordID, executor.source)
	if err != nil {
		return OwnerSealExecutionResult{}, executor.classifyAfterCommittingLocked(err, true)
	}
	plan := recovery.Plan()

	guard, err := executor.openCopier()
	if err != nil {
		return OwnerSealExecutionResult{}, executor.ownerSealFailureLocked(
			err, true, false, false, true)
	}
	defer func() {
		if !guard.closed {
			resultErr = guard.close(resultErr)
			if resultErr != nil {
				result = OwnerSealExecutionResult{}
			}
		}
	}()

	seal, err := runOwnerSealRereadTranscriptPass(
		ctx, plan, executor.source, guard.copier, nil)
	if err != nil {
		return OwnerSealExecutionResult{}, executor.classifyAfterCommittingLocked(err, true)
	}
	if err := recovery.VerifyRecomputedSeal(seal); err != nil {
		return OwnerSealExecutionResult{}, executor.ownerSealFailureLocked(
			ownerSealQuarantinef("recovery pass 1 differs from durable H: %v", err),
			true, true, false, true)
	}
	committed, err := PlanCommittingOwnerSealCompletion(committing, plan, seal)
	if err != nil {
		return OwnerSealExecutionResult{}, executor.ownerSealFailureLocked(
			ownerSealDurableContradictionf("plan COMMITTED completion: %v", err),
			false, false, true, true)
	}
	sink, err := group.newOwnerSealDescriptorSinkLocked(
		plan, ownerSealDescriptorRecoveryReservedOrTarget)
	if err != nil {
		return OwnerSealExecutionResult{}, executor.classifyAfterCommittingLocked(err, true)
	}
	if _, err := executor.runDescriptorMaterializationLocked(
		ctx, plan, seal, guard.copier, sink); err != nil {
		return OwnerSealExecutionResult{}, executor.classifyAfterCommittingLocked(err, true)
	}
	if err := executor.runPostSyncTerminalPassLocked(
		ctx, committing, plan, seal, guard); err != nil {
		return OwnerSealExecutionResult{}, err
	}
	if err := group.commitExactOwnerSealStateLocked(committing, committed); err != nil {
		return OwnerSealExecutionResult{}, executor.ownerSealFailureLocked(
			err, true, false, false, true)
	}
	selected, err := group.refreshAndRequireOwnerSealStateLocked(committed)
	if err != nil {
		return OwnerSealExecutionResult{}, executor.classifyAfterCommittingLocked(err, false)
	}
	selectedRecord, found := producerScatterRecordByID(
		selected.Records(), plan.AllocationRecordID())
	if !found {
		return OwnerSealExecutionResult{}, executor.ownerSealFailureLocked(
			ownerSealDurableContradictionf("final recovered COMMITTED record disappeared"),
			false, false, true, true)
	}
	return ownerSealExecutionResult(selectedRecord, false, true, false), nil
}

func (executor *OwnerSealExecutor) replayCommittedLocked(
	ctx context.Context,
	allocationRecordID uint64,
) (result OwnerSealExecutionResult, resultErr error) {
	group := executor.group
	committed, err := group.ownerStateLocked()
	if err != nil {
		return OwnerSealExecutionResult{}, executor.classifyBeforeCommittingLocked(err)
	}
	replay, err := LoadCommittedOwnerSealReplayPlanFromMedia(
		ctx, committed, allocationRecordID, executor.source)
	if err != nil {
		return OwnerSealExecutionResult{}, executor.classifyCommittedReplayLocked(err)
	}
	plan := replay.Plan()
	verifier, err := group.newOwnerSealReadOnlyDescriptorVerifierLocked(plan)
	if err != nil {
		return OwnerSealExecutionResult{}, executor.classifyCommittedReplayLocked(err)
	}

	guard, err := executor.openCopier()
	if err != nil {
		return OwnerSealExecutionResult{}, err
	}
	defer func() {
		if !guard.closed {
			resultErr = guard.close(resultErr)
			if resultErr != nil {
				result = OwnerSealExecutionResult{}
			}
		}
	}()
	seal, err := runOwnerSealRereadTranscriptPass(
		ctx, plan, executor.source, guard.copier, verifier.Append)
	if err != nil {
		return OwnerSealExecutionResult{}, executor.classifyCommittedReplayLocked(err)
	}
	if err := replay.VerifyRecomputedSeal(seal); err != nil {
		return OwnerSealExecutionResult{}, executor.ownerSealFailureLocked(
			ownerSealQuarantinef("COMMITTED replay differs from durable H: %v", err),
			false, true, false, true)
	}
	if err := verifier.Finish(); err != nil {
		return OwnerSealExecutionResult{}, executor.classifyCommittedReplayLocked(err)
	}
	if err := guard.close(nil); err != nil {
		return OwnerSealExecutionResult{}, executor.ownerSealFailureLocked(
			err, false, false, false, true)
	}
	selected, err := group.refreshAndRequireOwnerSealStateLocked(committed)
	if err != nil {
		return OwnerSealExecutionResult{}, executor.classifyCommittedReplayLocked(err)
	}
	record, found := producerScatterRecordByID(
		selected.Records(), allocationRecordID)
	if !found {
		return OwnerSealExecutionResult{}, executor.ownerSealFailureLocked(
			ownerSealDurableContradictionf("replayed COMMITTED record disappeared"),
			false, false, true, true)
	}
	return ownerSealExecutionResult(record, false, false, true), nil
}

func (executor *OwnerSealExecutor) runDescriptorMaterializationLocked(
	ctx context.Context,
	plan OwnerSealPlan,
	expected OwnerVerifiedSeal,
	copier trcxl007dml.Copier,
	sink *ownerSealDescriptorSink,
) (OwnerVerifiedSeal, error) {
	seal, err := runOwnerSealRereadTranscriptPass(
		ctx, plan, executor.source, copier, sink.Append)
	if err != nil {
		return OwnerVerifiedSeal{}, sink.FailAndSync(err)
	}
	if seal.SHA256() != expected.SHA256() {
		mismatch := ownerSealQuarantinef(
			"descriptor pass H2 differs from the authoritative pass-1 H")
		return OwnerVerifiedSeal{}, sink.FailAndSync(mismatch)
	}
	if err := sink.Finish(); err != nil {
		return OwnerVerifiedSeal{}, sink.FailAndSync(err)
	}
	return seal, nil
}

func (executor *OwnerSealExecutor) runPostSyncTerminalPassLocked(
	ctx context.Context,
	expectedCommitting OwnerStateSnapshot,
	plan OwnerSealPlan,
	expected OwnerVerifiedSeal,
	guard *ownerSealCopierGuard,
) error {
	group := executor.group
	verifier, err := group.prepareOwnerSealPostSyncVerifierLocked(
		expectedCommitting, plan)
	if err != nil {
		return executor.classifyAfterCommittingLocked(err, true)
	}
	seal, err := runOwnerSealRereadTranscriptPass(
		ctx, plan, executor.source, guard.copier, verifier.Append)
	if err != nil {
		return executor.classifyAfterCommittingLocked(err, true)
	}
	if seal.SHA256() != expected.SHA256() {
		return executor.ownerSealFailureLocked(
			ownerSealQuarantinef("terminal pass H3 differs from authoritative H"),
			true, true, false, true)
	}
	if err := verifier.Finish(); err != nil {
		return executor.classifyAfterCommittingLocked(err, true)
	}
	if err := guard.close(nil); err != nil {
		return executor.ownerSealFailureLocked(
			err, true, false, false, true)
	}
	if err := group.completeOwnerSealPostSyncVerificationLocked(verifier); err != nil {
		return executor.classifyAfterCommittingLocked(err, true)
	}
	return nil
}

func (executor *OwnerSealExecutor) validateCall(ctx context.Context) error {
	if executor == nil || executor.self != executor || executor.group == nil ||
		!executor.group.ownerDeviceGroupHandleValid() || interfaceIsNil(executor.source) ||
		executor.copierFactory == nil {
		return ownerSealExecutorInvalidf("executor handle is nil, copied, or incomplete")
	}
	if interfaceIsNil(ctx) {
		return ownerSealExecutorInvalidf("context is nil")
	}
	return nil
}

func (executor *OwnerSealExecutor) validateLockedEntry(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	group := executor.group
	if !group.ownerDeviceGroupHandleValid() || executor.self != executor {
		return ownerSealExecutorInvalidf("executor or Owner device-group handle changed")
	}
	if group.ownerDeviceGroupOfflineRequiredLocked() {
		return ErrOwnerDeviceGroupOfflineRequired
	}
	if group.ownerDeviceGroupReopenRequiredLocked() {
		return ErrOwnerDeviceGroupReopenRequired
	}
	return nil
}

func (executor *OwnerSealExecutor) openCopier() (*ownerSealCopierGuard, error) {
	copier, err := executor.copierFactory()
	if err != nil {
		if !interfaceIsNil(copier) {
			err = ownerSealCombineErrors(err, copier.Close())
		}
		return nil, fmt.Errorf("open hardware-only Owner seal Copier: %w", err)
	}
	if interfaceIsNil(copier) {
		return nil, ownerSealExecutorInvalidf(
			"hardware Copier factory returned a nil Copier")
	}
	return &ownerSealCopierGuard{copier: copier}, nil
}

type ownerSealCopierGuard struct {
	copier   trcxl007dml.Copier
	closed   bool
	closeErr error
}

func (guard *ownerSealCopierGuard) close(primary error) error {
	if guard == nil {
		return ownerSealCombineErrors(primary, errors.New("Owner seal Copier guard is nil"))
	}
	if !guard.closed {
		guard.closed = true
		if interfaceIsNil(guard.copier) {
			guard.closeErr = errors.New("Owner seal Copier is nil")
		} else {
			guard.closeErr = guard.copier.Close()
		}
	}
	return ownerSealCombineErrors(primary, guard.closeErr)
}

type ownerSealCombinedError struct {
	primary   error
	secondary error
}

func (combined *ownerSealCombinedError) Error() string {
	if combined == nil {
		return "<nil>"
	}
	return fmt.Sprintf("%v; additionally: %v", combined.primary, combined.secondary)
}

func (combined *ownerSealCombinedError) Unwrap() error {
	if combined == nil {
		return nil
	}
	return combined.primary
}

func (combined *ownerSealCombinedError) Is(target error) bool {
	return combined != nil &&
		(errors.Is(combined.primary, target) || errors.Is(combined.secondary, target))
}

func ownerSealCombineErrors(primary, secondary error) error {
	switch {
	case primary == nil:
		return secondary
	case secondary == nil || errors.Is(primary, secondary):
		return primary
	case errors.Is(secondary, primary):
		return secondary
	default:
		return &ownerSealCombinedError{primary: primary, secondary: secondary}
	}
}

type ownerSealExecutionError struct {
	cause              error
	recoveryRequired   bool
	quarantineRequired bool
	reopenRequired     bool
	offlineRequired    bool
}

func (executionError *ownerSealExecutionError) Error() string {
	if executionError == nil {
		return "TRCXL007 Owner seal execution failed"
	}
	qualifier := "TRCXL007 Owner seal execution failed"
	if executionError.offlineRequired {
		qualifier = "TRCXL007 Owner seal requires the Owner group to be taken offline"
	} else if executionError.quarantineRequired {
		qualifier = "TRCXL007 Owner seal requires checkpoint quarantine"
	} else if executionError.recoveryRequired {
		qualifier = "TRCXL007 Owner seal requires forward recovery"
	}
	if executionError.reopenRequired && !executionError.offlineRequired {
		qualifier += " after reopening the Owner device group"
	}
	return fmt.Sprintf("%s: %v", qualifier, executionError.cause)
}

func (executionError *ownerSealExecutionError) Unwrap() error {
	if executionError == nil {
		return nil
	}
	return executionError.cause
}

func (executionError *ownerSealExecutionError) Is(target error) bool {
	return executionError != nil && ((target == ErrOwnerSealRecoveryRequired && executionError.recoveryRequired) ||
		(target == ErrOwnerSealQuarantineRequired && executionError.quarantineRequired) ||
		(target == ErrOwnerDeviceGroupReopenRequired && executionError.reopenRequired) ||
		(target == ErrOwnerDeviceGroupOfflineRequired && executionError.offlineRequired) ||
		(target == ErrOwnerSealDurableContradiction && executionError.offlineRequired))
}

func (executor *OwnerSealExecutor) ownerSealFailureLocked(
	cause error,
	recoveryRequired bool,
	quarantineRequired bool,
	offlineRequired bool,
	reopenRequired bool,
) error {
	if cause == nil {
		cause = errors.New("unspecified Owner seal execution failure")
	}
	group := executor.group
	if ownerSealFailureRequiresOffline(cause) {
		offlineRequired = true
	}
	if offlineRequired {
		group.executionState.offlineRequired = true
		group.executionState.reopenRequired = true
		recoveryRequired = false
		reopenRequired = true
	} else if reopenRequired {
		group.executionState.reopenRequired = true
	}
	if !recoveryRequired && !quarantineRequired && !offlineRequired && !reopenRequired {
		return cause
	}
	return &ownerSealExecutionError{
		cause:              cause,
		recoveryRequired:   recoveryRequired,
		quarantineRequired: quarantineRequired,
		reopenRequired:     reopenRequired,
		offlineRequired:    offlineRequired,
	}
}

func (executor *OwnerSealExecutor) classifyBeforeCommittingLocked(err error) error {
	if ownerSealFailureRequiresOffline(err) {
		return executor.ownerSealFailureLocked(err, false, false, true, true)
	}
	if errors.Is(err, ErrOwnerSealDescriptorMediaConflict) ||
		errors.Is(err, ErrOwnerSealDescriptorDispositionChanged) {
		return executor.ownerSealFailureLocked(err, false, true, false, false)
	}
	if errors.Is(err, ErrOwnerSealDescriptorStorage) ||
		errors.Is(err, ErrDeviceMetadataStorage) {
		return executor.ownerSealFailureLocked(err, false, false, false, true)
	}
	return err
}

func (executor *OwnerSealExecutor) classifyAfterCommittingLocked(
	err error,
	stableDescriptorOrMedia bool,
) error {
	if ownerSealFailureRequiresOffline(err) {
		return executor.ownerSealFailureLocked(err, false, false, true, true)
	}
	stable := errors.Is(err, ErrOwnerSealQuarantineRequired) ||
		errors.Is(err, ErrInvalidOwnerSealTranscript) ||
		errors.Is(err, ErrOwnerSealDescriptorMediaConflict) ||
		errors.Is(err, ErrOwnerSealDescriptorDispositionChanged) ||
		errors.Is(err, ErrInvalidOwnerSealMedia)
	if stableDescriptorOrMedia && errors.Is(err, ErrInvalidOwnerSealRecoveryPlan) {
		stable = true
	}
	return executor.ownerSealFailureLocked(err, true, stable, false, true)
}

func (executor *OwnerSealExecutor) classifyCommittedReplayLocked(err error) error {
	if ownerSealFailureRequiresOffline(err) {
		return executor.ownerSealFailureLocked(err, false, false, true, true)
	}
	stable := errors.Is(err, ErrOwnerSealQuarantineRequired) ||
		errors.Is(err, ErrInvalidOwnerSealTranscript) ||
		errors.Is(err, ErrOwnerSealDescriptorMediaConflict) ||
		errors.Is(err, ErrOwnerSealDescriptorDispositionChanged) ||
		errors.Is(err, ErrInvalidOwnerSealMedia) ||
		errors.Is(err, ErrInvalidOwnerSealRecoveryPlan)
	return executor.ownerSealFailureLocked(err, false, stable, false, true)
}

// ownerSealFailureRequiresOffline distinguishes durable authority/media-root
// contradictions from operational read, configured-limit, and reopen errors.
// Once an already-opened Owner group observes any of these categories, merely
// retrying the same authority after reopen is not sufficient: the complete
// group must remain sticky OFFLINE for operator reconciliation.
func ownerSealFailureRequiresOffline(err error) bool {
	for _, category := range []error{
		ErrOwnerSealDescriptorAllocatorContradiction,
		ErrOwnerSealPostSyncAuthorityContradiction,
		ErrOwnerSealDurableContradiction,
		ErrOwnerDeviceGroupMismatch,
		ErrDeviceMetadataSequence,
		ErrDeviceMetadataSizeMismatch,
		ErrDeviceMetadataGeometryMismatch,
		ErrDeviceMetadataRoleMismatch,
		ErrOwnerStateBootstrapMismatch,
		ErrOwnerStateSplitBrain,
		ErrSuperblockSplitBrain,
		ErrNoValidSuperblock,
		ErrNoValidOwnerState,
		ErrSuperblockSnapshotMismatch,
		ErrAllocatorSnapshotMismatch,
		ErrInvalidSuperblock,
		ErrWrongSuperblockFormat,
		ErrCorruptSuperblock,
		ErrInvalidAllocatorSnapshot,
		ErrWrongAllocatorSnapshotFormat,
		ErrCorruptAllocatorSnapshot,
		ErrInvalidOwnerState,
		ErrWrongOwnerStateFormat,
		ErrCorruptOwnerState,
	} {
		if errors.Is(err, category) {
			return true
		}
	}
	return false
}

func (group *OwnerDeviceGroup) commitExactOwnerSealStateLocked(
	current OwnerStateSnapshot,
	next OwnerStateSnapshot,
) error {
	if group == nil || group.anchor == nil {
		return ErrOwnerDeviceGroupInput
	}
	currentSlot, selected, present := group.anchor.ActiveOwnerState()
	if !present || !ownerStateSnapshotsCanonicalEqual(
		selected, current, group.anchor.geometry) {
		return ownerSealDurableContradictionf(
			"cached ANCHOR Owner state differs from exact transition source")
	}
	if err := group.preflightOwnerStateTransitionLocked(
		selected, next, currentSlot); err != nil {
		return err
	}
	return group.anchor.commitOwnerState(next)
}

func (group *OwnerDeviceGroup) refreshAndRequireOwnerSealStateLocked(
	expected OwnerStateSnapshot,
) (OwnerStateSnapshot, error) {
	if err := group.refreshOwnerDeviceGroupMetadataLocked(); err != nil {
		group.executionState.reopenRequired = true
		return OwnerStateSnapshot{}, err
	}
	selected, err := group.ownerStateLocked()
	if err != nil {
		group.executionState.reopenRequired = true
		return OwnerStateSnapshot{}, err
	}
	if !ownerStateSnapshotsCanonicalEqual(selected, expected, group.anchor.geometry) {
		group.executionState.reopenRequired = true
		return OwnerStateSnapshot{}, ownerSealDurableContradictionf(
			"freshly selected Owner state differs from the exact expected phase")
	}
	return selected, nil
}

type ownerSealProducerCRCAdvisory struct {
	vector  ProducerScatterCRCVector
	matched bool
}

func (advisory *ownerSealProducerCRCAdvisory) append(
	verification OwnerSealPageVerification,
) error {
	if advisory == nil {
		return ownerSealExecutorInvalidf("Producer CRC advisory is nil")
	}
	want, err := advisory.vector.CRC32C(verification.Target().LogicalPage())
	if err != nil {
		return ownerSealExecutorInvalidf("Producer CRC advisory: %v", err)
	}
	if want != verification.Descriptor().PaddedPageCRC32C {
		advisory.matched = false
	}
	return nil
}

func ownerSealUniqueCommittingRecord(
	owner OwnerStateSnapshot,
) (OwnerStateAllocationRecord, error) {
	if err := owner.Validate(); err != nil {
		return OwnerStateAllocationRecord{}, ownerSealDurableContradictionf(
			"Owner state: %v", err)
	}
	var selected OwnerStateAllocationRecord
	count := 0
	for _, record := range owner.Records() {
		switch record.State {
		case OwnerAllocationCommitting:
			selected = record
			count++
		case OwnerAllocationPreparing,
			OwnerAllocationAborting,
			OwnerAllocationReclaiming,
			OwnerAllocationCanceling:
			return OwnerStateAllocationRecord{}, ownerSealDurableContradictionf(
				"allocation %d remains in state %d beside COMMITTING recovery",
				record.AllocationRecordID,
				record.State)
		}
	}
	if count == 0 {
		return OwnerStateAllocationRecord{}, ErrOwnerSealNoCommitting
	}
	if count != 1 {
		return OwnerStateAllocationRecord{}, ownerSealDurableContradictionf(
			"Owner state contains %d COMMITTING allocations", count)
	}
	return cloneOwnerStateRecord(selected), nil
}

func ownerSealOtherTransitionalRecord(
	owner OwnerStateSnapshot,
	exceptAllocationRecordID uint64,
) (OwnerStateAllocationRecord, bool) {
	for _, record := range owner.Records() {
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

func ownerSealExecutionResult(
	record OwnerStateAllocationRecord,
	producerCRCMatch bool,
	forwardRecovered bool,
	replayed bool,
) OwnerSealExecutionResult {
	return OwnerSealExecutionResult{
		Record:           cloneOwnerStateRecord(record),
		ProducerCRCMatch: producerCRCMatch,
		ForwardRecovered: forwardRecovered,
		Replayed:         replayed,
	}
}

func ownerSealExecutorInvalidf(format string, arguments ...interface{}) error {
	return fmt.Errorf(
		"%w: %s", ErrInvalidOwnerSealExecutor, fmt.Sprintf(format, arguments...))
}

func ownerSealQuarantinef(format string, arguments ...interface{}) error {
	return fmt.Errorf(
		"%w: %s", ErrOwnerSealQuarantineRequired, fmt.Sprintf(format, arguments...))
}

func ownerSealDurableContradictionf(format string, arguments ...interface{}) error {
	return fmt.Errorf(
		"%w: %s", ErrOwnerSealDurableContradiction, fmt.Sprintf(format, arguments...))
}

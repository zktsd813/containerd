package trcxl007

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
)

var (
	// ErrInvalidOwnerSealPostSyncVerification identifies an invalid verifier
	// lifecycle, a caller-supplied verification that is not the next exact plan
	// page, or an attempt to clear the group latch without one complete
	// post-Sync reread. It never authorizes media repair.
	ErrInvalidOwnerSealPostSyncVerification = errors.New(
		"invalid TRCXL007 Owner seal post-Sync verification")

	// ErrOwnerSealPostSyncAuthorityContradiction identifies a refreshed Owner
	// state, group binding, or metadata handle that no longer equals the exact
	// COMMITTING authority captured by the seal executor. This is an
	// architecture-level sticky-OFFLINE input for that executor. The helper
	// reports the contradiction but does not itself perform an OFFLINE
	// transition.
	ErrOwnerSealPostSyncAuthorityContradiction = errors.New(
		"TRCXL007 Owner seal post-Sync authority contradiction")
)

// ownerSealPostSyncVerificationError retains one stable operation label and
// one underlying category/cause while remaining compatible with Go 1.17
// errors.Is traversal.
type ownerSealPostSyncVerificationError struct {
	category  error
	operation string
	detail    string
	cause     error
}

func (verificationError *ownerSealPostSyncVerificationError) Error() string {
	if verificationError == nil {
		return "<nil>"
	}
	message := verificationError.category.Error()
	if verificationError.operation != "" {
		message += ": " + verificationError.operation
	}
	if verificationError.detail != "" {
		message += ": " + verificationError.detail
	}
	if verificationError.cause != nil {
		message += ": " + verificationError.cause.Error()
	}
	return message
}

func (verificationError *ownerSealPostSyncVerificationError) Unwrap() error {
	if verificationError == nil {
		return nil
	}
	return verificationError.cause
}

func (verificationError *ownerSealPostSyncVerificationError) Is(target error) bool {
	return verificationError != nil && target == verificationError.category
}

// Operation returns a stable phase label for operator diagnostics.
func (verificationError *ownerSealPostSyncVerificationError) Operation() string {
	if verificationError == nil {
		return ""
	}
	return verificationError.operation
}

// ownerSealReadOnlyDescriptorVerifier binds one complete hardware-DML reread
// to the exact target descriptor bytes already present on media. It retains a
// detached compact plan plus one handle per affected device, never a page
// table, page payload, CRC vector, or bitmap copy.
//
// In normal mode it supports mutation-free COMMITTED replay. In post-Sync mode
// it is also the unforgeable package-private capability required to clear the
// group reopen latch after descriptor persistence and metadata refresh.
type ownerSealReadOnlyDescriptorVerifier struct {
	self     *ownerSealReadOnlyDescriptorVerifier
	group    *OwnerDeviceGroup
	plan     OwnerSealPlan
	iterator OwnerSealPageIterator
	devices  []ownerSealDescriptorDevice

	postSync                    bool
	expectedCommittingSHA256    [sha256.Size]byte
	expectedCommittingLength    uint64
	pagesAppended               uint64
	finished                    bool
	postSyncCompletionAttempted bool
	terminalErr                 error
}

// newOwnerSealReadOnlyDescriptorVerifierLocked constructs the normal-latch,
// read-only verifier used by COMMITTED replay. Construction performs a full
// allocator and exact target-only descriptor preflight but no write or Sync.
func (group *OwnerDeviceGroup) newOwnerSealReadOnlyDescriptorVerifierLocked(
	plan OwnerSealPlan,
) (*ownerSealReadOnlyDescriptorVerifier, error) {
	preparedPlan, devices, err := group.prepareOwnerSealDescriptorPersistenceLocked(plan)
	if err != nil {
		return nil, err
	}
	if err := preflightPreparedOwnerSealDescriptorsLocked(
		preparedPlan,
		devices,
		ownerSealDescriptorTerminalTargetOnly); err != nil {
		return nil, err
	}
	return newPreparedOwnerSealReadOnlyDescriptorVerifier(
		group,
		preparedPlan,
		devices,
		false,
		[sha256.Size]byte{},
		0,
	)
}

// prepareOwnerSealPostSyncVerifierLocked establishes a fresh metadata view
// after descriptor Sync and constructs the read-only verifier for the third
// hardware-DML pass. The caller must hold the group execution lock and the
// external distributed writer fence. The group latch is set before refresh
// and stays set on every failure.
func (group *OwnerDeviceGroup) prepareOwnerSealPostSyncVerifierLocked(
	expectedCommitting OwnerStateSnapshot,
	plan OwnerSealPlan,
) (*ownerSealReadOnlyDescriptorVerifier, error) {
	if !group.ownerDeviceGroupHandleValid() || group.anchor == nil || len(group.devices) == 0 {
		return nil, ownerSealPostSyncError(
			ErrInvalidOwnerSealPostSyncVerification,
			"prepare",
			ErrOwnerDeviceGroupInput,
			"Owner device-group handle is invalid")
	}

	// This is the fail-closed barrier. Neither a successful descriptor Sync nor
	// a successful metadata refresh may clear it. Only the exact verifier
	// capability returned below can reach the final completion gate.
	group.executionState.reopenRequired = true
	if group.ownerDeviceGroupOfflineRequiredLocked() {
		return nil, ownerSealPostSyncError(
			ErrOwnerSealPostSyncAuthorityContradiction,
			"prepare",
			ErrOwnerDeviceGroupOfflineRequired,
			"Owner device group is offline")
	}
	if err := plan.Validate(); err != nil {
		return nil, ownerSealPostSyncError(
			ErrInvalidOwnerSealPostSyncVerification,
			"prepare-plan",
			err,
			"Owner seal plan")
	}
	if err := ownerSealValidateExpectedCommitting(expectedCommitting, plan); err != nil {
		return nil, err
	}
	expectedStorage, err := EncodeOwnerStateForStorage(
		expectedCommitting,
		group.anchor.geometry)
	if err != nil {
		return nil, ownerSealPostSyncError(
			ErrInvalidOwnerSealPostSyncVerification,
			"prepare-expected-owner",
			err,
			"encode expected COMMITTING Owner state")
	}

	if err := group.refreshOwnerDeviceGroupMetadataLocked(); err != nil {
		return nil, ownerSealPostSyncError(
			ErrInvalidOwnerSealPostSyncVerification,
			"refresh-metadata",
			err,
			"reopen every Owner-group metadata view")
	}
	selectedOwner, err := group.ownerStateLocked()
	if err != nil {
		return nil, ownerSealPostSyncError(
			ErrOwnerSealPostSyncAuthorityContradiction,
			"refresh-owner",
			err,
			"select refreshed Owner state")
	}
	selectedStorage, err := EncodeOwnerStateForStorage(
		selectedOwner,
		group.anchor.geometry)
	if err != nil {
		return nil, ownerSealPostSyncError(
			ErrOwnerSealPostSyncAuthorityContradiction,
			"refresh-owner",
			err,
			"encode refreshed Owner state")
	}
	if selectedStorage.SHA256() != expectedStorage.SHA256() ||
		selectedStorage.ExactLength() != expectedStorage.ExactLength() {
		return nil, ownerSealPostSyncError(
			ErrOwnerSealPostSyncAuthorityContradiction,
			"refresh-owner",
			nil,
			"refreshed Owner state differs from exact expected COMMITTING state")
	}

	preparedPlan, devices, err := group.prepareOwnerSealDescriptorPostRefreshLocked(plan)
	if err != nil {
		return nil, err
	}
	if err := preflightPreparedOwnerSealDescriptorsLocked(
		preparedPlan,
		devices,
		ownerSealDescriptorTerminalTargetOnly); err != nil {
		return nil, err
	}
	return newPreparedOwnerSealReadOnlyDescriptorVerifier(
		group,
		preparedPlan,
		devices,
		true,
		expectedStorage.SHA256(),
		expectedStorage.ExactLength(),
	)
}

func newPreparedOwnerSealReadOnlyDescriptorVerifier(
	group *OwnerDeviceGroup,
	plan OwnerSealPlan,
	devices []ownerSealDescriptorDevice,
	postSync bool,
	expectedCommittingSHA256 [sha256.Size]byte,
	expectedCommittingLength uint64,
) (*ownerSealReadOnlyDescriptorVerifier, error) {
	iterator, err := plan.PageIterator()
	if err != nil {
		return nil, ownerSealPostSyncError(
			ErrInvalidOwnerSealPostSyncVerification,
			"new-verifier",
			err,
			"create page iterator")
	}
	verifier := &ownerSealReadOnlyDescriptorVerifier{
		group:                       group,
		plan:                        cloneOwnerSealPlan(plan),
		iterator:                    iterator,
		devices:                     append([]ownerSealDescriptorDevice(nil), devices...),
		postSync:                    postSync,
		expectedCommittingSHA256:    expectedCommittingSHA256,
		expectedCommittingLength:    expectedCommittingLength,
		postSyncCompletionAttempted: false,
	}
	verifier.self = verifier
	return verifier, nil
}

// Append consumes the next successful hardware-DML page verification. It
// rebuilds the target descriptor from the CRC recomputed from that payload
// and compares the complete canonical 64-byte wire image with DAX media. It
// never writes a descriptor or calls Sync.
func (verifier *ownerSealReadOnlyDescriptorVerifier) Append(
	verification OwnerSealPageVerification,
) error {
	if err := verifier.validateUse("append"); err != nil {
		return err
	}
	if verifier.finished {
		return verifier.fail(ownerSealPostSyncError(
			ErrInvalidOwnerSealPostSyncVerification,
			"append",
			nil,
			"verifier is already finished"))
	}
	if err := verifier.validateBoundGroup("append"); err != nil {
		return verifier.fail(err)
	}

	expectedTarget, err := verifier.iterator.Next()
	if errors.Is(err, io.EOF) {
		return verifier.fail(ownerSealPostSyncError(
			ErrInvalidOwnerSealPostSyncVerification,
			"append-order",
			nil,
			"extra verification after %d pages",
			verifier.pagesAppended))
	}
	if err != nil {
		return verifier.fail(ownerSealPostSyncError(
			ErrInvalidOwnerSealPostSyncVerification,
			"append-order",
			err,
			"select logical page %d",
			verifier.pagesAppended))
	}
	if verification.Target() != expectedTarget {
		return verifier.fail(ownerSealPostSyncError(
			ErrInvalidOwnerSealPostSyncVerification,
			"append-verification",
			nil,
			"verification target differs at logical page %d",
			expectedTarget.LogicalPage()))
	}
	expectedDescriptor, err := expectedTarget.TargetDescriptor(
		verification.Descriptor().PaddedPageCRC32C)
	if err != nil {
		return verifier.fail(ownerSealPostSyncError(
			ErrInvalidOwnerSealPostSyncVerification,
			"append-verification",
			err,
			"derive logical page %d target descriptor",
			expectedTarget.LogicalPage()))
	}
	if verification.Descriptor() != expectedDescriptor {
		return verifier.fail(ownerSealPostSyncError(
			ErrInvalidOwnerSealPostSyncVerification,
			"append-verification",
			nil,
			"verification descriptor differs at logical page %d",
			expectedTarget.LogicalPage()))
	}
	targetWire, err := expectedDescriptor.MarshalBinary()
	if err != nil {
		return verifier.fail(ownerSealPostSyncError(
			ErrInvalidOwnerSealPostSyncVerification,
			"append-verification",
			err,
			"marshal logical page %d target descriptor",
			expectedTarget.LogicalPage()))
	}

	device, err := ownerSealDescriptorDeviceForTarget(verifier.devices, expectedTarget)
	if err != nil {
		return verifier.fail(err)
	}
	if !ownerSealReadOnlyVerifierDeviceStillBound(verifier.group, device) {
		return verifier.fail(ownerSealPostSyncError(
			ErrOwnerSealPostSyncAuthorityContradiction,
			"append-binding",
			nil,
			"device %q binding or refreshed metadata handle changed",
			device.binding.DeviceUUID))
	}
	if err := ownerSealDescriptorPageUnavailable(
		device,
		expectedTarget,
		"verify-allocator"); err != nil {
		return verifier.fail(err)
	}
	raw, err := ownerSealReadRawDescriptor(device.metadata, expectedTarget)
	if err != nil {
		return verifier.fail(ownerSealDescriptorError(
			ErrOwnerSealDescriptorStorage,
			"verify-read",
			err,
			"device %q data page %d",
			device.binding.DeviceUUID,
			expectedTarget.DataPageIndex()))
	}
	if !bytes.Equal(raw[:], targetWire) {
		return verifier.fail(ownerSealDescriptorError(
			ErrOwnerSealDescriptorDispositionChanged,
			"verify-target",
			nil,
			"device %q data page %d logical page %d differs from the DML-recomputed target",
			device.binding.DeviceUUID,
			expectedTarget.DataPageIndex(),
			expectedTarget.LogicalPage()))
	}

	verifier.pagesAppended++
	return nil
}

// Finish requires exact page-stream completion. It performs no storage write,
// Sync, state transition, or latch change.
func (verifier *ownerSealReadOnlyDescriptorVerifier) Finish() error {
	if err := verifier.validateUse("finish"); err != nil {
		return err
	}
	if verifier.finished {
		return verifier.fail(ownerSealPostSyncError(
			ErrInvalidOwnerSealPostSyncVerification,
			"finish",
			nil,
			"verifier is already finished"))
	}
	if err := verifier.validateBoundGroup("finish"); err != nil {
		return verifier.fail(err)
	}
	if verifier.pagesAppended != verifier.plan.TotalPages() {
		return verifier.fail(ownerSealPostSyncError(
			ErrInvalidOwnerSealPostSyncVerification,
			"finish-completion",
			nil,
			"stream has %d of %d pages",
			verifier.pagesAppended,
			verifier.plan.TotalPages()))
	}
	if _, err := verifier.iterator.Next(); !errors.Is(err, io.EOF) {
		if err == nil {
			err = errors.New("page iterator contains an extra target")
		}
		return verifier.fail(ownerSealPostSyncError(
			ErrInvalidOwnerSealPostSyncVerification,
			"finish-completion",
			err,
			"page iterator did not end at exact EOF"))
	}
	verifier.finished = true
	return nil
}

// completeOwnerSealPostSyncVerificationLocked is the only path that clears
// the group-level reopen latch after descriptor persistence. The caller must
// still hold the same lock and external writer fence, and must call this only
// after the third DML transcript, H comparison, verifier Finish, and Copier
// Close all succeed. Clearing the latch is deliberately the last state change.
func (group *OwnerDeviceGroup) completeOwnerSealPostSyncVerificationLocked(
	verifier *ownerSealReadOnlyDescriptorVerifier,
) error {
	if verifier == nil || verifier.self != verifier || verifier.group != group {
		return ownerSealPostSyncError(
			ErrInvalidOwnerSealPostSyncVerification,
			"complete",
			nil,
			"verifier capability is nil, copied, or belongs to another group")
	}
	if verifier.terminalErr != nil {
		return verifier.terminalErr
	}
	if !verifier.postSync || !verifier.finished ||
		verifier.postSyncCompletionAttempted {
		return verifier.fail(ownerSealPostSyncError(
			ErrInvalidOwnerSealPostSyncVerification,
			"complete",
			nil,
			"verifier is not one fresh, finished post-Sync capability"))
	}
	verifier.postSyncCompletionAttempted = true
	if err := verifier.validateBoundGroup("complete"); err != nil {
		return verifier.fail(err)
	}
	if !group.executionState.reopenRequired {
		return verifier.fail(ownerSealPostSyncError(
			ErrOwnerSealPostSyncAuthorityContradiction,
			"complete-latch",
			nil,
			"group reopen latch was cleared before the final gate"))
	}
	selectedOwner, err := group.ownerStateLocked()
	if err != nil {
		return verifier.fail(ownerSealPostSyncError(
			ErrOwnerSealPostSyncAuthorityContradiction,
			"complete-owner",
			err,
			"select refreshed Owner state"))
	}
	selectedStorage, err := EncodeOwnerStateForStorage(
		selectedOwner,
		group.anchor.geometry)
	if err != nil {
		return verifier.fail(ownerSealPostSyncError(
			ErrOwnerSealPostSyncAuthorityContradiction,
			"complete-owner",
			err,
			"encode refreshed Owner state"))
	}
	if verifier.expectedCommittingSHA256 == ([sha256.Size]byte{}) ||
		verifier.expectedCommittingLength == 0 ||
		selectedStorage.SHA256() != verifier.expectedCommittingSHA256 ||
		selectedStorage.ExactLength() != verifier.expectedCommittingLength {
		return verifier.fail(ownerSealPostSyncError(
			ErrOwnerSealPostSyncAuthorityContradiction,
			"complete-owner",
			nil,
			"Owner state changed after post-Sync preparation"))
	}
	if err := verifier.plan.Validate(); err != nil {
		return verifier.fail(ownerSealPostSyncError(
			ErrOwnerSealPostSyncAuthorityContradiction,
			"complete-plan",
			err,
			"retained compact plan changed"))
	}

	// The one-shot capability was consumed before the final rechecks above. No
	// fallible operation may follow this point; the latch clear is the literal
	// final state change of the gate.
	group.executionState.reopenRequired = false
	return nil
}

func (verifier *ownerSealReadOnlyDescriptorVerifier) validateUse(
	operation string,
) error {
	if verifier == nil || verifier.self != verifier || verifier.group == nil {
		return ownerSealPostSyncError(
			ErrInvalidOwnerSealPostSyncVerification,
			operation,
			nil,
			"verifier is nil, copied, or unbound")
	}
	if verifier.terminalErr != nil {
		return verifier.terminalErr
	}
	return nil
}

func (verifier *ownerSealReadOnlyDescriptorVerifier) validateBoundGroup(
	operation string,
) error {
	group := verifier.group
	if !group.ownerDeviceGroupHandleValid() || group.anchor == nil || len(group.devices) == 0 {
		return ownerSealPostSyncError(
			ErrOwnerSealPostSyncAuthorityContradiction,
			operation+"-group",
			ErrOwnerDeviceGroupInput,
			"Owner device-group handle is invalid")
	}
	if group.ownerDeviceGroupOfflineRequiredLocked() {
		return ownerSealPostSyncError(
			ErrOwnerSealPostSyncAuthorityContradiction,
			operation+"-group",
			ErrOwnerDeviceGroupOfflineRequired,
			"Owner device group is offline")
	}
	if verifier.postSync {
		if !group.executionState.reopenRequired {
			return ownerSealPostSyncError(
				ErrOwnerSealPostSyncAuthorityContradiction,
				operation+"-latch",
				nil,
				"post-Sync group reopen latch is not set")
		}
	} else if group.ownerDeviceGroupReopenRequiredLocked() {
		return ownerSealPostSyncError(
			ErrOwnerSealPostSyncAuthorityContradiction,
			operation+"-latch",
			ErrOwnerDeviceGroupReopenRequired,
			"Owner device group requires reopen")
	}
	for index := range verifier.devices {
		device := &verifier.devices[index]
		if !ownerSealReadOnlyVerifierDeviceStillBound(group, device) ||
			device.metadata.reopenRequired {
			return ownerSealPostSyncError(
				ErrOwnerSealPostSyncAuthorityContradiction,
				operation+"-binding",
				ErrDeviceMetadataReopenRequired,
				"device %q binding changed or metadata requires reopen",
				device.binding.DeviceUUID)
		}
	}
	return nil
}

func ownerSealReadOnlyVerifierDeviceStillBound(
	group *OwnerDeviceGroup,
	device *ownerSealDescriptorDevice,
) bool {
	return group != nil && device != nil && device.groupIndex >= 0 &&
		device.groupIndex < len(group.devices) &&
		group.devices[device.groupIndex].deviceUUID == device.binding.DeviceUUID &&
		group.devices[device.groupIndex].metadata == device.metadata &&
		device.metadata != nil && device.metadata.storage != nil
}

func ownerSealValidateExpectedCommitting(
	expected OwnerStateSnapshot,
	plan OwnerSealPlan,
) error {
	record, found := producerScatterRecordByID(
		expected.Records(),
		plan.AllocationRecordID())
	if !found {
		return ownerSealPostSyncError(
			ErrOwnerSealPostSyncAuthorityContradiction,
			"prepare-expected-owner",
			nil,
			"allocation record %d is absent",
			plan.AllocationRecordID())
	}
	if _, _, err := ownerSealCrossCheckStatePhaseDigest(
		expected,
		plan,
		OwnerAllocationCommitting,
		plan.CommittingOwnerSnapshotSequence(),
		plan.TerminalTransactionSequence(),
		plan.SealTransactionSequence(),
		record.OwnerVerifiedSealSHA256,
	); err != nil {
		return ownerSealPostSyncError(
			ErrOwnerSealPostSyncAuthorityContradiction,
			"prepare-expected-owner",
			err,
			"expected Owner state is not the exact planned COMMITTING phase")
	}
	return nil
}

func ownerSealPostSyncError(
	category error,
	operation string,
	cause error,
	format string,
	arguments ...interface{},
) error {
	detail := ""
	if format != "" {
		detail = fmt.Sprintf(format, arguments...)
	}
	return &ownerSealPostSyncVerificationError{
		category:  category,
		operation: operation,
		detail:    detail,
		cause:     cause,
	}
}

func (verifier *ownerSealReadOnlyDescriptorVerifier) fail(err error) error {
	if verifier != nil && verifier.terminalErr == nil {
		verifier.terminalErr = err
	}
	if verifier == nil {
		return err
	}
	return verifier.terminalErr
}

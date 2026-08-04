package trcxl007

import (
	"bytes"
	"errors"
	"fmt"
	"io"
)

var (
	// ErrInvalidOwnerSealDescriptorPersistence identifies an invalid mode,
	// compact-plan/group mismatch, out-of-order verification, duplicate page,
	// incomplete stream, or use after a terminal sink result. These failures do
	// not grant permission to repair media.
	ErrInvalidOwnerSealDescriptorPersistence = errors.New(
		"invalid TRCXL007 Owner seal descriptor persistence")

	// ErrOwnerSealDescriptorMediaConflict identifies a read-only preflight
	// observation outside the exact descriptor set allowed by the selected
	// fresh, recovery, or terminal mode. The complete preflight precedes every
	// descriptor mutation performed by its caller.
	ErrOwnerSealDescriptorMediaConflict = errors.New(
		"TRCXL007 Owner seal descriptor media conflict")

	// ErrOwnerSealDescriptorAllocatorContradiction means that a page selected
	// by the exact Owner seal plan is FREE in the already-selected allocator
	// snapshot. Unlike an ordinary descriptor conflict, this contradicts the
	// durable allocation authority and is an architecture-level sticky-OFFLINE
	// input for the enclosing executor. This primitive reports but does not
	// itself authorize or perform the OFFLINE transition.
	ErrOwnerSealDescriptorAllocatorContradiction = errors.New(
		"TRCXL007 Owner seal descriptor contradicts selected allocator")

	// ErrOwnerSealDescriptorDispositionChanged means that allocator or
	// descriptor state no longer equals the observation required by the
	// streaming sink. A prefix may already contain exact target descriptors;
	// recovery must reopen and rescan rather than continuing this sink.
	ErrOwnerSealDescriptorDispositionChanged = errors.New(
		"TRCXL007 Owner seal descriptor disposition changed")

	// ErrOwnerSealDescriptorStorage distinguishes descriptor read/write I/O
	// from semantic conflicts. It also matches ErrDeviceMetadataStorage.
	ErrOwnerSealDescriptorStorage = errors.New(
		"TRCXL007 Owner seal descriptor storage failure")

	// ErrOwnerSealDescriptorSync identifies failure of the final persistence
	// boundary. It is separate from descriptor read/write storage failures and
	// also matches ErrDeviceMetadataStorage.
	ErrOwnerSealDescriptorSync = errors.New(
		"TRCXL007 Owner seal descriptor sync failure")
)

// ownerSealDescriptorMode selects the exact media set accepted by the global,
// read-only preflight. It is deliberately package-private: the Owner executor
// must derive the legal mode from its durable allocation transition.
type ownerSealDescriptorMode uint8

const (
	ownerSealDescriptorFreshReservedOnly ownerSealDescriptorMode = iota + 1
	ownerSealDescriptorRecoveryReservedOrTarget
	ownerSealDescriptorTerminalTargetOnly
)

type ownerSealDescriptorClass uint8

const (
	ownerSealDescriptorReserved ownerSealDescriptorClass = iota + 1
	ownerSealDescriptorTarget
	ownerSealDescriptorConflict
)

// ownerSealDescriptorPersistenceError retains one stable operation label and
// one underlying cause while supporting Go 1.17 errors.Is semantics. Storage
// and Sync categories additionally match the existing device-storage error.
type ownerSealDescriptorPersistenceError struct {
	category  error
	operation string
	detail    string
	cause     error
}

// ownerSealDescriptorFailureBarrierError preserves the executor's primary
// failure and the first failed failure-barrier Sync under Go 1.17. Unwrap
// follows the primary failure for errors.As diagnostics; Is explicitly walks
// both branches because errors.Join is unavailable in the supported toolchain.
type ownerSealDescriptorFailureBarrierError struct {
	primary error
	syncErr error
}

// ownerSealDescriptorPrimaryError retains an executor-supplied outer failure
// together with an already-terminal sink failure when neither wraps the other.
// The executor failure remains the unwrap path so its location/context stays
// primary, while Is exposes both causes on Go 1.17.
type ownerSealDescriptorPrimaryError struct {
	primary error
	sinkErr error
}

func (primaryError *ownerSealDescriptorPrimaryError) Error() string {
	if primaryError == nil {
		return "<nil>"
	}
	return fmt.Sprintf("%v; descriptor sink failure: %v",
		primaryError.primary, primaryError.sinkErr)
}

func (primaryError *ownerSealDescriptorPrimaryError) Unwrap() error {
	if primaryError == nil {
		return nil
	}
	return primaryError.primary
}

func (primaryError *ownerSealDescriptorPrimaryError) Is(target error) bool {
	return primaryError != nil &&
		(errors.Is(primaryError.primary, target) ||
			errors.Is(primaryError.sinkErr, target))
}

func (barrierError *ownerSealDescriptorFailureBarrierError) Error() string {
	if barrierError == nil {
		return "<nil>"
	}
	return fmt.Sprintf("%v; descriptor failure-barrier Sync: %v",
		barrierError.primary, barrierError.syncErr)
}

func (barrierError *ownerSealDescriptorFailureBarrierError) Unwrap() error {
	if barrierError == nil {
		return nil
	}
	return barrierError.primary
}

func (barrierError *ownerSealDescriptorFailureBarrierError) Is(target error) bool {
	return barrierError != nil &&
		(errors.Is(barrierError.primary, target) ||
			errors.Is(barrierError.syncErr, target))
}

func (persistenceError *ownerSealDescriptorPersistenceError) Error() string {
	if persistenceError == nil {
		return "<nil>"
	}
	message := persistenceError.category.Error()
	if persistenceError.operation != "" {
		message += ": " + persistenceError.operation
	}
	if persistenceError.detail != "" {
		message += ": " + persistenceError.detail
	}
	if persistenceError.cause != nil {
		message += ": " + persistenceError.cause.Error()
	}
	return message
}

func (persistenceError *ownerSealDescriptorPersistenceError) Unwrap() error {
	if persistenceError == nil {
		return nil
	}
	return persistenceError.cause
}

func (persistenceError *ownerSealDescriptorPersistenceError) Is(target error) bool {
	if persistenceError == nil {
		return false
	}
	if target == persistenceError.category {
		return true
	}
	return target == ErrDeviceMetadataStorage &&
		(persistenceError.category == ErrOwnerSealDescriptorStorage ||
			persistenceError.category == ErrOwnerSealDescriptorSync)
}

// Operation returns a stable phase label for operator diagnostics.
func (persistenceError *ownerSealDescriptorPersistenceError) Operation() string {
	if persistenceError == nil {
		return ""
	}
	return persistenceError.operation
}

type ownerSealDescriptorDevice struct {
	binding    ProducerScatterDeviceBinding
	groupIndex int
	metadata   *DeviceMetadata
}

// ownerSealDescriptorSink consumes successful Owner reread verifications in
// exact checkpoint-logical order. Retained memory is one detached compact
// plan/iterator plus one entry per affected device; there is no page table,
// missing-page bitmap, or CRC vector.
type ownerSealDescriptorSink struct {
	group    *OwnerDeviceGroup
	plan     OwnerSealPlan
	mode     ownerSealDescriptorMode
	iterator OwnerSealPageIterator
	devices  []ownerSealDescriptorDevice

	pagesAppended      uint64
	writeAttempted     bool
	failureBarrierDone bool
	finished           bool
	terminalErr        error
}

// preflightOwnerSealDescriptorsLocked scans every selected allocator bit and
// descriptor before the first mutation. The caller must hold the group's
// execution lock and keep the Owner writer fenced for the entire subsequent
// transition. This low-level primitive intentionally does not inspect or
// authorize a GRANTED/COMMITTING/COMMITTED Owner-state phase; the executor must
// establish that durable authority before choosing a mode or constructing a
// sink.
func (group *OwnerDeviceGroup) preflightOwnerSealDescriptorsLocked(
	plan OwnerSealPlan,
	mode ownerSealDescriptorMode,
) error {
	if !mode.valid() {
		return ownerSealDescriptorError(
			ErrInvalidOwnerSealDescriptorPersistence,
			"preflight",
			nil,
			"unsupported descriptor mode %d",
			mode)
	}
	preparedPlan, devices, err := group.prepareOwnerSealDescriptorPersistenceLocked(plan)
	if err != nil {
		return err
	}
	return preflightPreparedOwnerSealDescriptorsLocked(preparedPlan, devices, mode)
}

// preflightPreparedOwnerSealDescriptorsLocked scans the exact detached plan
// and opened-device set that a sink will retain. Keeping this helper below the
// preparing boundary lets sink construction perform one indivisible
// prepare/preflight/bind operation: a caller cannot preflight one plan and
// then construct a writable sink for another plan.
func preflightPreparedOwnerSealDescriptorsLocked(
	preparedPlan OwnerSealPlan,
	devices []ownerSealDescriptorDevice,
	mode ownerSealDescriptorMode,
) error {
	if !mode.valid() {
		return ownerSealDescriptorError(
			ErrInvalidOwnerSealDescriptorPersistence,
			"preflight",
			nil,
			"unsupported descriptor mode %d",
			mode)
	}
	iterator, err := preparedPlan.PageIterator()
	if err != nil {
		return ownerSealDescriptorError(
			ErrInvalidOwnerSealDescriptorPersistence,
			"preflight",
			err,
			"create page iterator")
	}

	var pages uint64
	for {
		target, nextErr := iterator.Next()
		if errors.Is(nextErr, io.EOF) {
			break
		}
		if nextErr != nil {
			return ownerSealDescriptorError(
				ErrInvalidOwnerSealDescriptorPersistence,
				"preflight",
				nextErr,
				"select logical page %d",
				pages)
		}
		device, resolveErr := ownerSealDescriptorDeviceForTarget(devices, target)
		if resolveErr != nil {
			return resolveErr
		}
		if err := ownerSealDescriptorPageUnavailable(device, target, "preflight"); err != nil {
			return err
		}
		raw, readErr := ownerSealReadRawDescriptor(device.metadata, target)
		if readErr != nil {
			return ownerSealDescriptorError(
				ErrOwnerSealDescriptorStorage,
				"preflight-read",
				readErr,
				"device %q data page %d",
				device.binding.DeviceUUID,
				target.DataPageIndex())
		}
		class, classifyErr := classifyOwnerSealDescriptor(raw[:], target)
		if classifyErr != nil {
			return ownerSealDescriptorError(
				ErrOwnerSealDescriptorMediaConflict,
				"preflight-classify",
				classifyErr,
				"device %q data page %d logical page %d",
				device.binding.DeviceUUID,
				target.DataPageIndex(),
				target.LogicalPage())
		}
		if !mode.accepts(class) {
			return ownerSealDescriptorError(
				ErrOwnerSealDescriptorMediaConflict,
				"preflight-mode",
				nil,
				"device %q data page %d logical page %d has class %d in mode %d",
				device.binding.DeviceUUID,
				target.DataPageIndex(),
				target.LogicalPage(),
				class,
				mode)
		}
		pages++
	}
	if pages != preparedPlan.TotalPages() {
		return ownerSealDescriptorError(
			ErrInvalidOwnerSealDescriptorPersistence,
			"preflight",
			nil,
			"iterator covered %d pages, want %d",
			pages,
			preparedPlan.TotalPages())
	}
	return nil
}

// newOwnerSealDescriptorSinkLocked constructs a streaming sink only after it
// has performed the selected global descriptor preflight itself. The sink is
// bound to the exact detached plan, opened-device set, and mode that were
// preflighted in this call. Construction performs no descriptor write or Sync.
func (group *OwnerDeviceGroup) newOwnerSealDescriptorSinkLocked(
	plan OwnerSealPlan,
	mode ownerSealDescriptorMode,
) (*ownerSealDescriptorSink, error) {
	if !mode.valid() {
		return nil, ownerSealDescriptorError(
			ErrInvalidOwnerSealDescriptorPersistence,
			"new-sink",
			nil,
			"unsupported descriptor mode %d",
			mode)
	}
	preparedPlan, devices, err := group.prepareOwnerSealDescriptorPersistenceLocked(plan)
	if err != nil {
		return nil, err
	}
	if err := preflightPreparedOwnerSealDescriptorsLocked(
		preparedPlan, devices, mode); err != nil {
		return nil, err
	}
	iterator, err := preparedPlan.PageIterator()
	if err != nil {
		return nil, ownerSealDescriptorError(
			ErrInvalidOwnerSealDescriptorPersistence,
			"new-sink",
			err,
			"create page iterator")
	}
	return &ownerSealDescriptorSink{
		group:    group,
		plan:     preparedPlan,
		mode:     mode,
		iterator: iterator,
		devices:  devices,
	}, nil
}

// Append consumes exactly one successful transcript verification. Exact
// RESERVED is changed to the supplied exact target; an already exact target
// is a replay. Any allocator or descriptor change terminates this sink. Once
// the first write is attempted, the group poison is intentionally ignored by
// later Append calls so the same lock holder can finish the remaining pages.
func (sink *ownerSealDescriptorSink) Append(
	verification OwnerSealPageVerification,
) error {
	if sink == nil {
		return ownerSealDescriptorError(
			ErrInvalidOwnerSealDescriptorPersistence,
			"append",
			nil,
			"sink is nil")
	}
	if sink.terminalErr != nil {
		return sink.terminalErr
	}
	if sink.finished {
		return ownerSealDescriptorError(
			ErrInvalidOwnerSealDescriptorPersistence,
			"append",
			nil,
			"sink is already finished")
	}
	if !sink.mode.valid() {
		return sink.fail(ownerSealDescriptorError(
			ErrInvalidOwnerSealDescriptorPersistence,
			"append-mode",
			nil,
			"sink has unsupported descriptor mode %d",
			sink.mode))
	}
	if !sink.group.ownerDeviceGroupHandleValid() ||
		sink.group.ownerDeviceGroupOfflineRequiredLocked() {
		return sink.fail(ownerSealDescriptorError(
			ErrInvalidOwnerSealDescriptorPersistence,
			"append",
			ErrOwnerDeviceGroupOfflineRequired,
			"Owner device-group handle is invalid or offline"))
	}

	expectedTarget, err := sink.iterator.Next()
	if errors.Is(err, io.EOF) {
		return sink.fail(ownerSealDescriptorError(
			ErrInvalidOwnerSealDescriptorPersistence,
			"append-order",
			nil,
			"extra verification after %d pages",
			sink.pagesAppended))
	}
	if err != nil {
		return sink.fail(ownerSealDescriptorError(
			ErrInvalidOwnerSealDescriptorPersistence,
			"append-order",
			err,
			"select logical page %d",
			sink.pagesAppended))
	}
	if verification.target != expectedTarget {
		return sink.fail(ownerSealDescriptorError(
			ErrInvalidOwnerSealDescriptorPersistence,
			"append-verification",
			nil,
			"verification target differs at logical page %d",
			expectedTarget.LogicalPage()))
	}
	expectedDescriptor, err := expectedTarget.TargetDescriptor(
		verification.descriptor.PaddedPageCRC32C)
	if err != nil {
		return sink.fail(ownerSealDescriptorError(
			ErrInvalidOwnerSealDescriptorPersistence,
			"append-verification",
			err,
			"derive logical page %d target descriptor",
			expectedTarget.LogicalPage()))
	}
	if verification.descriptor != expectedDescriptor {
		return sink.fail(ownerSealDescriptorError(
			ErrInvalidOwnerSealDescriptorPersistence,
			"append-verification",
			nil,
			"descriptor differs at logical page %d",
			expectedTarget.LogicalPage()))
	}
	targetWire, err := expectedDescriptor.MarshalBinary()
	if err != nil {
		return sink.fail(ownerSealDescriptorError(
			ErrInvalidOwnerSealDescriptorPersistence,
			"append-verification",
			err,
			"marshal logical page %d target descriptor",
			expectedTarget.LogicalPage()))
	}

	device, err := ownerSealDescriptorDeviceForTarget(sink.devices, expectedTarget)
	if err != nil {
		return sink.fail(err)
	}
	if !sink.deviceStillBound(device) {
		return sink.fail(ownerSealDescriptorError(
			ErrOwnerSealDescriptorDispositionChanged,
			"append-binding",
			nil,
			"device %q binding changed",
			device.binding.DeviceUUID))
	}
	if err := ownerSealDescriptorPageUnavailable(
		device, expectedTarget, "append-allocator"); err != nil {
		return sink.fail(ownerSealDescriptorChanged(err,
			device.binding.DeviceUUID,
			expectedTarget))
	}

	raw, err := ownerSealReadRawDescriptor(device.metadata, expectedTarget)
	if err != nil {
		return sink.fail(ownerSealDescriptorError(
			ErrOwnerSealDescriptorStorage,
			"append-read",
			err,
			"device %q data page %d",
			device.binding.DeviceUUID,
			expectedTarget.DataPageIndex()))
	}
	class, classifyErr := classifyOwnerSealDescriptor(raw[:], expectedTarget)
	if classifyErr != nil {
		return sink.fail(ownerSealDescriptorError(
			ErrOwnerSealDescriptorDispositionChanged,
			"append-classify",
			classifyErr,
			"device %q data page %d logical page %d",
			device.binding.DeviceUUID,
			expectedTarget.DataPageIndex(),
			expectedTarget.LogicalPage()))
	}
	if !sink.mode.accepts(class) {
		return sink.fail(ownerSealDescriptorError(
			ErrOwnerSealDescriptorDispositionChanged,
			"append-mode",
			nil,
			"device %q data page %d logical page %d has class %d in mode %d",
			device.binding.DeviceUUID,
			expectedTarget.DataPageIndex(),
			expectedTarget.LogicalPage(),
			class,
			sink.mode))
	}
	switch class {
	case ownerSealDescriptorReserved:
		offset, offsetErr := device.metadata.geometry.DescriptorOffset(
			expectedTarget.DataPageIndex())
		if offsetErr != nil {
			return sink.fail(ownerSealDescriptorError(
				ErrInvalidOwnerSealDescriptorPersistence,
				"append-write",
				offsetErr,
				"device %q data page %d descriptor offset",
				device.binding.DeviceUUID,
				expectedTarget.DataPageIndex()))
		}
		// Latch immediately before the first byte can be attempted. The latch
		// remains set after successful Sync because only a later explicit
		// refresh/reopen may establish a new validated metadata view.
		sink.writeAttempted = true
		device.metadata.reopenRequired = true
		sink.group.executionState.reopenRequired = true
		if writeErr := writeMetadataExactAt(
			device.metadata.storage,
			device.metadata.geometry.DeviceBytes,
			targetWire,
			offset); writeErr != nil {
			return sink.fail(ownerSealDescriptorError(
				ErrOwnerSealDescriptorStorage,
				"append-write",
				writeErr,
				"device %q data page %d",
				device.binding.DeviceUUID,
				expectedTarget.DataPageIndex()))
		}
	case ownerSealDescriptorTarget:
		if !bytes.Equal(raw[:], targetWire) {
			return sink.fail(ownerSealDescriptorError(
				ErrOwnerSealDescriptorDispositionChanged,
				"append-replay",
				nil,
				"device %q data page %d target CRC32C differs from verification",
				device.binding.DeviceUUID,
				expectedTarget.DataPageIndex()))
		}
	default:
		return sink.fail(ownerSealDescriptorError(
			ErrOwnerSealDescriptorDispositionChanged,
			"append-classify",
			nil,
			"device %q data page %d has unknown class %d",
			device.binding.DeviceUUID,
			expectedTarget.DataPageIndex(),
			class))
	}

	sink.pagesAppended++
	return nil
}

// Finish requires exact iterator completion, then calls Sync on every affected
// device in canonical plan DeviceUUID order. Every Sync is attempted even if
// an earlier one fails and even if replay required no descriptor write. A
// successful result is only a persistence boundary: it neither clears poison,
// refreshes metadata, nor claims a terminal Owner state.
func (sink *ownerSealDescriptorSink) Finish() error {
	if sink == nil {
		return ownerSealDescriptorError(
			ErrInvalidOwnerSealDescriptorPersistence,
			"finish",
			nil,
			"sink is nil")
	}
	if sink.terminalErr != nil {
		return sink.terminalErr
	}
	if sink.finished {
		return ownerSealDescriptorError(
			ErrInvalidOwnerSealDescriptorPersistence,
			"finish",
			nil,
			"sink is already finished")
	}
	if sink.pagesAppended != sink.plan.TotalPages() {
		return sink.fail(ownerSealDescriptorError(
			ErrInvalidOwnerSealDescriptorPersistence,
			"finish-completion",
			nil,
			"stream has %d of %d pages",
			sink.pagesAppended,
			sink.plan.TotalPages()))
	}
	if _, err := sink.iterator.Next(); !errors.Is(err, io.EOF) {
		if err == nil {
			err = errors.New("page iterator contains an extra target")
		}
		return sink.fail(ownerSealDescriptorError(
			ErrInvalidOwnerSealDescriptorPersistence,
			"finish-completion",
			err,
			"page iterator did not end at exact EOF"))
	}

	sink.failureBarrierDone = true
	firstSyncError := sink.syncEveryAffectedDevice("finish-sync")
	if firstSyncError != nil {
		return sink.fail(firstSyncError)
	}
	sink.finished = true
	return nil
}

// FailAndSync terminates an incomplete sink while preserving the executor's
// first failure. If any descriptor write was attempted, it establishes one
// best-effort persistence boundary across every affected DAX in canonical
// DeviceUUID order. Every Sync is attempted, the first Sync error is retained
// together with the primary error, and repeated calls return the exact same
// result without issuing another Sync. With no write attempt it performs no
// unnecessary Sync but still makes the sink terminal.
func (sink *ownerSealDescriptorSink) FailAndSync(primary error) error {
	if sink == nil {
		return ownerSealDescriptorError(
			ErrInvalidOwnerSealDescriptorPersistence,
			"failure-barrier",
			primary,
			"sink is nil")
	}
	if sink.failureBarrierDone {
		if sink.terminalErr != nil {
			return sink.terminalErr
		}
		return ownerSealDescriptorError(
			ErrInvalidOwnerSealDescriptorPersistence,
			"failure-barrier",
			primary,
			"sink already completed its persistence boundary")
	}
	if sink.finished {
		return ownerSealDescriptorError(
			ErrInvalidOwnerSealDescriptorPersistence,
			"failure-barrier",
			primary,
			"sink is already finished")
	}
	if sink.terminalErr == nil {
		if primary == nil {
			primary = ownerSealDescriptorError(
				ErrInvalidOwnerSealDescriptorPersistence,
				"failure-barrier",
				nil,
				"primary failure is nil")
		}
		sink.fail(primary)
	} else if primary != nil {
		sink.terminalErr = ownerSealDescriptorPreservePrimary(
			primary, sink.terminalErr)
	}
	primary = sink.terminalErr
	// Latch before the first Sync call. The execution lock prevents concurrent
	// use, and this ordering also makes accidental reentry one-shot.
	sink.failureBarrierDone = true
	if !sink.writeAttempted {
		return primary
	}

	syncErr := sink.syncEveryAffectedDevice("failure-sync")
	if syncErr == nil {
		return primary
	}
	combined := &ownerSealDescriptorFailureBarrierError{
		primary: primary,
		syncErr: syncErr,
	}
	sink.terminalErr = combined
	return combined
}

func ownerSealDescriptorPreservePrimary(primary, sinkErr error) error {
	switch {
	case primary == nil:
		return sinkErr
	case sinkErr == nil:
		return primary
	case errors.Is(primary, sinkErr):
		// The executor supplied a location-bearing outer wrapper around the
		// sink failure. Retain it verbatim.
		return primary
	case errors.Is(sinkErr, primary):
		return sinkErr
	default:
		return &ownerSealDescriptorPrimaryError{
			primary: primary,
			sinkErr: sinkErr,
		}
	}
}

func (sink *ownerSealDescriptorSink) syncEveryAffectedDevice(
	operation string,
) error {
	var firstSyncError error
	for index := range sink.devices {
		device := &sink.devices[index]
		syncErr := device.metadata.storage.Sync()
		if syncErr == nil {
			continue
		}
		device.metadata.reopenRequired = true
		sink.group.executionState.reopenRequired = true
		if firstSyncError == nil {
			firstSyncError = ownerSealDescriptorError(
				ErrOwnerSealDescriptorSync,
				operation,
				syncErr,
				"device %q",
				device.binding.DeviceUUID)
		}
	}
	return firstSyncError
}

func (group *OwnerDeviceGroup) prepareOwnerSealDescriptorPersistenceLocked(
	plan OwnerSealPlan,
) (OwnerSealPlan, []ownerSealDescriptorDevice, error) {
	if !group.ownerDeviceGroupHandleValid() || group.anchor == nil || len(group.devices) == 0 {
		return OwnerSealPlan{}, nil, ownerSealDescriptorError(
			ErrInvalidOwnerSealDescriptorPersistence,
			"prepare",
			ErrOwnerDeviceGroupInput,
			"Owner device-group handle is invalid")
	}
	if group.ownerDeviceGroupOfflineRequiredLocked() {
		return OwnerSealPlan{}, nil, ownerSealDescriptorError(
			ErrInvalidOwnerSealDescriptorPersistence,
			"prepare",
			ErrOwnerDeviceGroupOfflineRequired,
			"Owner device group is offline")
	}
	if group.ownerDeviceGroupReopenRequiredLocked() {
		return OwnerSealPlan{}, nil, ownerSealDescriptorError(
			ErrInvalidOwnerSealDescriptorPersistence,
			"prepare",
			ErrOwnerDeviceGroupReopenRequired,
			"Owner device group requires reopen")
	}
	if err := plan.Validate(); err != nil {
		return OwnerSealPlan{}, nil, ownerSealDescriptorError(
			ErrInvalidOwnerSealDescriptorPersistence,
			"prepare-plan",
			err,
			"Owner seal plan")
	}
	if plan.ClusterID() != group.bootstrap.ClusterID ||
		plan.OwnerGroupID() != group.bootstrap.OwnerGroupID ||
		plan.AnchorDeviceUUID() != group.bootstrap.AnchorDeviceUUID ||
		plan.StorageCompatibilityID() != group.bootstrap.StorageCompatibilityID ||
		plan.OwnerID() != group.bootstrap.CurrentOwnerID ||
		plan.OwnerEpoch() != group.bootstrap.OwnerEpoch ||
		plan.GroupConfigurationSequence() != group.bootstrap.GroupConfigurationSequence ||
		plan.MembershipSHA256() != group.bootstrap.MembershipSHA256 {
		return OwnerSealPlan{}, nil, ownerSealDescriptorError(
			ErrInvalidOwnerSealDescriptorPersistence,
			"prepare-plan-binding",
			ErrInvalidOwnerSealPlan,
			"Owner seal plan static group identity differs from opened group")
	}

	planDevices := plan.Devices()
	devices := make([]ownerSealDescriptorDevice, len(planDevices))
	groupCursor := 0
	memberCursor := 0
	for index, binding := range planDevices {
		for groupCursor < len(group.devices) &&
			group.devices[groupCursor].deviceUUID < binding.DeviceUUID {
			groupCursor++
		}
		for memberCursor < len(group.bootstrap.Devices) &&
			group.bootstrap.Devices[memberCursor].DeviceUUID < binding.DeviceUUID {
			memberCursor++
		}
		if memberCursor >= len(group.bootstrap.Devices) ||
			group.bootstrap.Devices[memberCursor].DeviceUUID != binding.DeviceUUID {
			return OwnerSealPlan{}, nil, ownerSealDescriptorError(
				ErrInvalidOwnerSealDescriptorPersistence,
				"prepare-plan-binding",
				ErrInvalidOwnerSealPlan,
				"plan device %q is absent from trusted group membership",
				binding.DeviceUUID)
		}
		member := group.bootstrap.Devices[memberCursor]
		if member.DeviceOwnerEpoch != binding.DeviceOwnerEpoch ||
			member.DataPageCount != binding.DataPageCount ||
			member.DeviceBindingSHA256 != binding.DeviceBindingSHA256 {
			return OwnerSealPlan{}, nil, ownerSealDescriptorError(
				ErrInvalidOwnerSealDescriptorPersistence,
				"prepare-plan-binding",
				ErrInvalidOwnerSealPlan,
				"plan device %q binding differs from trusted group membership",
				binding.DeviceUUID)
		}
		if groupCursor >= len(group.devices) ||
			group.devices[groupCursor].deviceUUID != binding.DeviceUUID {
			return OwnerSealPlan{}, nil, ownerSealDescriptorError(
				ErrInvalidOwnerSealDescriptorPersistence,
				"prepare-opened-binding",
				ErrOwnerDeviceGroupMismatch,
				"trusted member %q is absent from opened group",
				binding.DeviceUUID)
		}
		opened := group.devices[groupCursor]
		if opened.metadata == nil || opened.metadata.storage == nil {
			return OwnerSealPlan{}, nil, ownerSealDescriptorError(
				ErrOwnerSealDescriptorStorage,
				"prepare-opened-storage",
				nil,
				"device %q has no opened storage",
				binding.DeviceUUID)
		}
		metadata := opened.metadata
		if opened.geometry != metadata.geometry ||
			metadata.superblock.Geometry != metadata.geometry ||
			metadata.superblock.DeviceUUID != binding.DeviceUUID ||
			metadata.superblock.OwnerEpoch != binding.DeviceOwnerEpoch ||
			metadata.geometry.DataPageCount != binding.DataPageCount ||
			metadata.superblock.DeviceBindingSHA256() != binding.DeviceBindingSHA256 {
			return OwnerSealPlan{}, nil, ownerSealDescriptorError(
				ErrInvalidOwnerSealDescriptorPersistence,
				"prepare-opened-binding",
				ErrOwnerDeviceGroupMismatch,
				"plan device %q binding differs from opened group",
				binding.DeviceUUID)
		}
		if err := validateMetadataStorageSize(metadata.storage, metadata.geometry); err != nil {
			return OwnerSealPlan{}, nil, ownerSealDescriptorError(
				ErrOwnerSealDescriptorStorage,
				"prepare-storage",
				err,
				"device %q",
				binding.DeviceUUID)
		}
		if err := validateSuperblockBootstrap(metadata.superblock, group.bootstrap); err != nil {
			return OwnerSealPlan{}, nil, ownerSealDescriptorError(
				ErrInvalidOwnerSealDescriptorPersistence,
				"prepare-opened-binding",
				err,
				"device %q superblock/bootstrap",
				binding.DeviceUUID)
		}
		if err := ownerSealDescriptorValidateAllocatorEnvelope(metadata); err != nil {
			return OwnerSealPlan{}, nil, err
		}
		devices[index] = ownerSealDescriptorDevice{
			binding:    binding,
			groupIndex: groupCursor,
			metadata:   metadata,
		}
		groupCursor++
		memberCursor++
	}

	detached := cloneOwnerSealPlan(plan)
	iterator, err := detached.PageIterator()
	if err != nil {
		return OwnerSealPlan{}, nil, ownerSealDescriptorError(
			ErrInvalidOwnerSealDescriptorPersistence,
			"prepare-allocator",
			err,
			"create allocator-check iterator")
	}
	var pages uint64
	for {
		target, nextErr := iterator.Next()
		if errors.Is(nextErr, io.EOF) {
			break
		}
		if nextErr != nil {
			return OwnerSealPlan{}, nil, ownerSealDescriptorError(
				ErrInvalidOwnerSealDescriptorPersistence,
				"prepare-allocator",
				nextErr,
				"select logical page %d",
				pages)
		}
		device, resolveErr := ownerSealDescriptorDeviceForTarget(devices, target)
		if resolveErr != nil {
			return OwnerSealPlan{}, nil, resolveErr
		}
		if err := ownerSealDescriptorPageUnavailable(
			device, target, "prepare-allocator"); err != nil {
			return OwnerSealPlan{}, nil, err
		}
		pages++
	}
	if pages != detached.TotalPages() {
		return OwnerSealPlan{}, nil, ownerSealDescriptorError(
			ErrInvalidOwnerSealDescriptorPersistence,
			"prepare-allocator",
			nil,
			"iterator covered %d pages, want %d",
			pages,
			detached.TotalPages())
	}
	return detached, devices, nil
}

func ownerSealDescriptorValidateAllocatorEnvelope(metadata *DeviceMetadata) error {
	expectedBitmapBytes, err := metadata.geometry.AllocationBitmapBytes()
	if err != nil {
		return ownerSealDescriptorError(
			ErrInvalidOwnerSealDescriptorPersistence,
			"prepare-allocator",
			err,
			"device %q allocation bitmap geometry",
			metadata.superblock.DeviceUUID)
	}
	allocator := &metadata.allocator
	if allocator.DeviceBindingSHA256 != metadata.superblock.DeviceBindingSHA256() ||
		allocator.OwnerGroupIdentitySHA256 != metadata.superblock.OwnerGroupIdentitySHA256() ||
		allocator.OwnerEpoch != metadata.superblock.OwnerEpoch {
		return ownerSealDescriptorError(
			ErrInvalidOwnerSealDescriptorPersistence,
			"prepare-opened-allocator-binding",
			ErrOwnerDeviceGroupMismatch,
			"device %q cached allocator binding/epoch differs from selected superblock",
			metadata.superblock.DeviceUUID)
	}
	if allocator.DataPageCount != metadata.geometry.DataPageCount ||
		allocator.AllocatedPageCount > allocator.DataPageCount ||
		allocator.BitmapByteLength != expectedBitmapBytes ||
		uint64(len(allocator.allocationBitmap)) != expectedBitmapBytes {
		return ownerSealDescriptorError(
			ErrInvalidOwnerSealDescriptorPersistence,
			"prepare-allocator",
			nil,
			"device %q cached allocator envelope differs from opened metadata",
			metadata.superblock.DeviceUUID)
	}
	if err := allocatorSnapshotValidateUnusedHighBits(
		allocator.allocationBitmap,
		allocator.DataPageCount); err != nil {
		return ownerSealDescriptorError(
			ErrInvalidOwnerSealDescriptorPersistence,
			"prepare-allocator",
			err,
			"device %q cached allocator final bitmap byte",
			metadata.superblock.DeviceUUID)
	}
	allocatorLength, lengthOK := checkedAdd(
		AllocatorSnapshotFixedBytes,
		allocator.BitmapByteLength)
	if !lengthOK ||
		allocator.SnapshotSequence != metadata.superblock.ActiveAllocatorSnapshotSequence ||
		allocatorLength != metadata.superblock.ActiveAllocatorSnapshotLength {
		return ownerSealDescriptorError(
			ErrInvalidOwnerSealDescriptorPersistence,
			"prepare-allocator",
			nil,
			"device %q active allocator sequence/length differs from selected superblock",
			metadata.superblock.DeviceUUID)
	}
	return nil
}

func ownerSealDescriptorPageUnavailable(
	device *ownerSealDescriptorDevice,
	target OwnerSealPageTarget,
	operation string,
) error {
	unavailable, err := device.metadata.allocator.PageUnavailable(target.DataPageIndex())
	if err != nil {
		return ownerSealDescriptorError(
			ErrInvalidOwnerSealDescriptorPersistence,
			operation,
			err,
			"device %q data page %d allocator",
			device.binding.DeviceUUID,
			target.DataPageIndex())
	}
	if !unavailable {
		return ownerSealDescriptorError(
			ErrOwnerSealDescriptorAllocatorContradiction,
			operation,
			nil,
			"device %q data page %d is allocator-free",
			device.binding.DeviceUUID,
			target.DataPageIndex())
	}
	return nil
}

func ownerSealDescriptorDeviceForTarget(
	devices []ownerSealDescriptorDevice,
	target OwnerSealPageTarget,
) (*ownerSealDescriptorDevice, error) {
	index := uint64(target.DeviceIndex())
	if index >= uint64(len(devices)) {
		return nil, ownerSealDescriptorError(
			ErrInvalidOwnerSealDescriptorPersistence,
			"target-binding",
			nil,
			"logical page %d device index %d is outside %d devices",
			target.LogicalPage(),
			index,
			len(devices))
	}
	device := &devices[index]
	if target.Device() != device.binding ||
		target.DataPageIndex() >= device.binding.DataPageCount {
		return nil, ownerSealDescriptorError(
			ErrInvalidOwnerSealDescriptorPersistence,
			"target-binding",
			nil,
			"logical page %d target differs from device binding %q",
			target.LogicalPage(),
			device.binding.DeviceUUID)
	}
	return device, nil
}

func (sink *ownerSealDescriptorSink) deviceStillBound(
	device *ownerSealDescriptorDevice,
) bool {
	return sink != nil && sink.group != nil && device != nil &&
		device.groupIndex >= 0 && device.groupIndex < len(sink.group.devices) &&
		sink.group.devices[device.groupIndex].deviceUUID == device.binding.DeviceUUID &&
		sink.group.devices[device.groupIndex].metadata == device.metadata &&
		device.metadata != nil && device.metadata.storage != nil
}

func ownerSealReadRawDescriptor(
	metadata *DeviceMetadata,
	target OwnerSealPageTarget,
) ([PageDescriptorBytes]byte, error) {
	var raw [PageDescriptorBytes]byte
	offset, err := metadata.geometry.DescriptorOffset(target.DataPageIndex())
	if err != nil {
		return raw, err
	}
	if err := readMetadataExactAt(
		metadata.storage,
		metadata.geometry.DeviceBytes,
		raw[:],
		offset); err != nil {
		return raw, err
	}
	return raw, nil
}

// classifyOwnerSealDescriptor accepts only byte-exact RESERVED or a canonical
// target reconstructed from the CRC stored in the raw descriptor itself. The
// parse/rebuild/compare sequence rejects torn, foreign, and noncanonical wire
// bytes without trusting any other target field from media.
func classifyOwnerSealDescriptor(
	raw []byte,
	target OwnerSealPageTarget,
) (ownerSealDescriptorClass, error) {
	reserved, err := target.ExpectedReservedDescriptor()
	if err != nil {
		return ownerSealDescriptorConflict, err
	}
	reservedWire, err := reserved.MarshalBinary()
	if err != nil {
		return ownerSealDescriptorConflict, err
	}
	if bytes.Equal(raw, reservedWire) {
		return ownerSealDescriptorReserved, nil
	}

	parsed, err := ParseDescriptor(raw)
	if err != nil {
		return ownerSealDescriptorConflict, err
	}
	canonicalTarget, err := target.TargetDescriptor(parsed.PaddedPageCRC32C)
	if err != nil {
		return ownerSealDescriptorConflict, err
	}
	canonicalWire, err := canonicalTarget.MarshalBinary()
	if err != nil {
		return ownerSealDescriptorConflict, err
	}
	if !bytes.Equal(raw, canonicalWire) {
		return ownerSealDescriptorConflict, fmt.Errorf(
			"raw descriptor is neither exact RESERVED nor canonical target")
	}
	return ownerSealDescriptorTarget, nil
}

func (mode ownerSealDescriptorMode) valid() bool {
	return mode >= ownerSealDescriptorFreshReservedOnly &&
		mode <= ownerSealDescriptorTerminalTargetOnly
}

func (mode ownerSealDescriptorMode) accepts(class ownerSealDescriptorClass) bool {
	switch mode {
	case ownerSealDescriptorFreshReservedOnly:
		return class == ownerSealDescriptorReserved
	case ownerSealDescriptorRecoveryReservedOrTarget:
		return class == ownerSealDescriptorReserved || class == ownerSealDescriptorTarget
	case ownerSealDescriptorTerminalTargetOnly:
		return class == ownerSealDescriptorTarget
	default:
		return false
	}
}

func ownerSealDescriptorChanged(
	cause error,
	deviceUUID string,
	target OwnerSealPageTarget,
) error {
	return ownerSealDescriptorError(
		ErrOwnerSealDescriptorDispositionChanged,
		"append-allocator",
		cause,
		"device %q data page %d logical page %d",
		deviceUUID,
		target.DataPageIndex(),
		target.LogicalPage())
}

func ownerSealDescriptorError(
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
	return &ownerSealDescriptorPersistenceError{
		category:  category,
		operation: operation,
		detail:    detail,
		cause:     cause,
	}
}

func (sink *ownerSealDescriptorSink) fail(err error) error {
	if sink.terminalErr == nil {
		sink.terminalErr = err
		// A disposition change invalidates the preflight observation even when
		// no byte was attempted. Require a group reopen/rescan before another
		// sink can be constructed; write and Sync paths retain their stronger
		// per-device poison rules above.
		if errors.Is(err, ErrOwnerSealDescriptorDispositionChanged) &&
			sink.group != nil && sink.group.executionState != nil {
			sink.group.executionState.reopenRequired = true
		}
	}
	return sink.terminalErr
}

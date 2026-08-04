package trcxl007

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"reflect"

	"github.com/containerd/containerd/third_party/trenv-containerd/cmd/cxld/internal/trcxl007dml"
)

var errOwnerSealRereadPass = errors.New("TRCXL007 Owner seal reread pass failed")

type ownerSealRereadOperation string

const (
	ownerSealRereadValidateOperation   ownerSealRereadOperation = "validate"
	ownerSealRereadContextOperation    ownerSealRereadOperation = "context"
	ownerSealRereadOpenOperation       ownerSealRereadOperation = "open-read-pass"
	ownerSealRereadViewOperation       ownerSealRereadOperation = "readable-extent"
	ownerSealRereadDMLOperation        ownerSealRereadOperation = "dml-copy-crc"
	ownerSealRereadTranscriptOperation ownerSealRereadOperation = "transcript"
	ownerSealRereadSinkOperation       ownerSealRereadOperation = "verification-sink"
	ownerSealRereadFinishOperation     ownerSealRereadOperation = "finish"
	ownerSealRereadCloseOperation      ownerSealRereadOperation = "close-read-pass"
)

// ownerSealPageVerificationSink is deliberately package-private. A later
// descriptor-materialization pass may consume each successful verification,
// but no public caller may inject descriptor targets into this reread pass.
type ownerSealPageVerificationSink func(OwnerSealPageVerification) error

type ownerSealRereadLocation struct {
	runIndex       int
	logicalPage    uint64
	hasLogicalPage bool
	deviceUUID     string
}

// ownerSealRereadError preserves the exact failed operation and compact media
// location. If Close also fails, closeErr retains a second typed close failure
// while primary and errors.Is continue to expose the original cause.
type ownerSealRereadError struct {
	operation ownerSealRereadOperation
	location  ownerSealRereadLocation
	primary   error
	closeErr  error
}

func (failure *ownerSealRereadError) Error() string {
	if failure == nil {
		return "<nil>"
	}
	message := fmt.Sprintf("%s: %s", errOwnerSealRereadPass, failure.operation)
	if failure.location.runIndex >= 0 {
		message += fmt.Sprintf(" run=%d", failure.location.runIndex)
	}
	if failure.location.hasLogicalPage {
		message += fmt.Sprintf(" logical-page=%d", failure.location.logicalPage)
	}
	if failure.location.deviceUUID != "" {
		message += fmt.Sprintf(" device=%q", failure.location.deviceUUID)
	}
	if failure.primary != nil {
		message += ": " + failure.primary.Error()
	}
	if failure.closeErr != nil {
		message += "; additionally " + failure.closeErr.Error()
	}
	return message
}

func (failure *ownerSealRereadError) Unwrap() error {
	if failure == nil {
		return nil
	}
	return failure.primary
}

func (failure *ownerSealRereadError) Is(target error) bool {
	if failure == nil {
		return false
	}
	if target == errOwnerSealRereadPass {
		return true
	}
	return errors.Is(failure.primary, target) || errors.Is(failure.closeErr, target)
}

type ownerSealPreparedReadableExtent struct {
	run          ProducerScatterExtentRun
	view         OwnerSealReadableExtent
	addressStart uintptr
	addressEnd   uintptr
}

type ownerSealRereadBackingOrigin struct {
	initialized bool
	backingID   [sha256.Size]byte
	byteOffset  uint64
}

// runOwnerSealRereadTranscriptPass performs one read-only, hardware-copy/CRC
// transcript pass over an already reconstructed compact plan. It opens no DML
// hardware itself and never closes copier; the future authenticated Owner
// executor owns hardware construction and lifecycle.
//
// Every direct-DAX extent view is requested and cross-checked before the first
// COPY_CRC or sink call. The pass retains one view per compact extent and one
// Owner-owned 4 KiB scratch page, never a per-page view, CRC, descriptor, or
// verification table. It performs no CPU content copy or CRC fallback.
func runOwnerSealRereadTranscriptPass(
	ctx context.Context,
	suppliedPlan OwnerSealPlan,
	source OwnerSealContentSource,
	copier trcxl007dml.Copier,
	sink ownerSealPageVerificationSink,
) (seal OwnerVerifiedSeal, resultErr error) {
	if ownerSealRereadInterfaceNil(ctx) {
		return OwnerVerifiedSeal{}, ownerSealRereadFailure(
			ownerSealRereadContextOperation,
			ownerSealRereadNoLocation(),
			errors.New("context is nil"))
	}
	if err := ctx.Err(); err != nil {
		return OwnerVerifiedSeal{}, ownerSealRereadFailure(
			ownerSealRereadContextOperation, ownerSealRereadNoLocation(), err)
	}
	plan := cloneOwnerSealPlan(suppliedPlan)
	if err := plan.Validate(); err != nil {
		return OwnerVerifiedSeal{}, ownerSealRereadFailure(
			ownerSealRereadValidateOperation,
			ownerSealRereadNoLocation(),
			fmt.Errorf("compact plan: %w", err))
	}
	if ownerSealRereadInterfaceNil(source) {
		return OwnerVerifiedSeal{}, ownerSealRereadFailure(
			ownerSealRereadOpenOperation,
			ownerSealRereadNoLocation(),
			errors.New("content source is nil"))
	}
	if ownerSealRereadInterfaceNil(copier) {
		return OwnerVerifiedSeal{}, ownerSealRereadFailure(
			ownerSealRereadDMLOperation,
			ownerSealRereadNoLocation(),
			errors.New("DML copier is nil"))
	}

	readPass, err := source.OpenReadPass(ctx, plan.Devices())
	if err != nil {
		primary := ownerSealRereadFailure(
			ownerSealRereadOpenOperation, ownerSealRereadNoLocation(), err)
		if ownerSealRereadInterfaceNil(readPass) {
			return OwnerVerifiedSeal{}, primary
		}
		if closeErr := readPass.Close(); closeErr != nil {
			closeFailure := ownerSealRereadFailure(
				ownerSealRereadCloseOperation, ownerSealRereadNoLocation(), closeErr)
			primary = ownerSealRereadAttachClose(primary, closeFailure)
		}
		return OwnerVerifiedSeal{}, primary
	}
	if ownerSealRereadInterfaceNil(readPass) {
		return OwnerVerifiedSeal{}, ownerSealRereadFailure(
			ownerSealRereadOpenOperation,
			ownerSealRereadNoLocation(),
			errors.New("content source returned a nil read pass"))
	}
	defer func() {
		closeErr := readPass.Close()
		if closeErr == nil {
			return
		}
		seal = OwnerVerifiedSeal{}
		closeFailure := ownerSealRereadFailure(
			ownerSealRereadCloseOperation, ownerSealRereadNoLocation(), closeErr)
		resultErr = ownerSealRereadAttachClose(resultErr, closeFailure)
	}()

	scratch := make([]byte, ContentPageBytes)
	scratchStart, scratchEnd, err := producerScatterSliceAddressRange(scratch)
	if err != nil {
		return OwnerVerifiedSeal{}, ownerSealRereadFailure(
			ownerSealRereadValidateOperation,
			ownerSealRereadNoLocation(),
			fmt.Errorf("Owner scratch page: %w", err))
	}
	devices := plan.Devices()
	runs := plan.ExtentRuns()
	prepared := make([]ownerSealPreparedReadableExtent, 0, len(runs))
	origins := make([]ownerSealRereadBackingOrigin, len(devices))
	backingOwners := make(map[[sha256.Size]byte]uint32, len(devices))
	for runIndex, run := range runs {
		if uint64(run.DeviceIndex) >= uint64(len(devices)) {
			return OwnerVerifiedSeal{}, ownerSealRereadFailure(
				ownerSealRereadValidateOperation,
				ownerSealRereadRunLocation(runIndex, run, ""),
				errors.New("extent run device index is outside compact device table"))
		}
		binding := devices[run.DeviceIndex]
		location := ownerSealRereadRunLocation(runIndex, run, binding.DeviceUUID)
		if err := ctx.Err(); err != nil {
			return OwnerVerifiedSeal{}, ownerSealRereadFailure(
				ownerSealRereadContextOperation, location, err)
		}
		view, err := readPass.ReadableExtent(
			binding, run.StartDataPageIndex, run.PageCount)
		if err != nil {
			return OwnerVerifiedSeal{}, ownerSealRereadFailure(
				ownerSealRereadViewOperation, location, err)
		}
		if err := ctx.Err(); err != nil {
			return OwnerVerifiedSeal{}, ownerSealRereadFailure(
				ownerSealRereadContextOperation, location, err)
		}
		candidate, err := ownerSealPrepareReadableExtent(
			runIndex,
			run,
			binding,
			view,
			scratchStart,
			scratchEnd,
			origins,
			backingOwners,
			prepared,
		)
		if err != nil {
			return OwnerVerifiedSeal{}, ownerSealRereadFailure(
				ownerSealRereadViewOperation, location, err)
		}
		prepared = append(prepared, candidate)
	}
	if err := ctx.Err(); err != nil {
		return OwnerVerifiedSeal{}, ownerSealRereadFailure(
			ownerSealRereadContextOperation, ownerSealRereadNoLocation(), err)
	}

	transcript, err := NewOwnerSealTranscript(plan)
	if err != nil {
		return OwnerVerifiedSeal{}, ownerSealRereadFailure(
			ownerSealRereadTranscriptOperation,
			ownerSealRereadNoLocation(),
			fmt.Errorf("create transcript: %w", err))
	}
	logicalPage := uint64(0)
	for runIndex := range prepared {
		extent := prepared[runIndex]
		binding := extent.view.Binding
		for runPage := uint64(0); runPage < extent.run.PageCount; runPage++ {
			location := ownerSealRereadPageLocation(
				runIndex, logicalPage, binding.DeviceUUID)
			if err := ctx.Err(); err != nil {
				return OwnerVerifiedSeal{}, ownerSealRereadFailure(
					ownerSealRereadContextOperation, location, err)
			}
			target, err := transcript.NextPageTarget()
			if err != nil {
				return OwnerVerifiedSeal{}, ownerSealRereadFailure(
					ownerSealRereadTranscriptOperation,
					location,
					fmt.Errorf("select target: %w", err))
			}
			dataPageIndex, dataPageOK := checkedAdd(extent.run.StartDataPageIndex, runPage)
			if !dataPageOK || target.LogicalPage() != logicalPage ||
				target.DeviceIndex() != extent.run.DeviceIndex ||
				target.Device() != binding || target.DataPageIndex() != dataPageIndex {
				return OwnerVerifiedSeal{}, ownerSealRereadFailure(
					ownerSealRereadTranscriptOperation,
					location,
					errors.New("transcript target differs from compact extent cursor"))
			}
			byteOffset, offsetOK := checkedMul(runPage, uint64(ContentPageBytes))
			byteEnd, endOK := checkedAdd(byteOffset, uint64(ContentPageBytes))
			if !offsetOK || !endOK || byteEnd > uint64(len(extent.view.Bytes)) {
				return OwnerVerifiedSeal{}, ownerSealRereadFailure(
					ownerSealRereadViewOperation,
					location,
					errors.New("page slice exceeds readable extent view"))
			}
			sourcePage := extent.view.Bytes[int(byteOffset):int(byteEnd)]
			ownerCRC32C, err := copier.CopyPage(scratch, sourcePage)
			if err != nil {
				return OwnerVerifiedSeal{}, ownerSealRereadFailure(
					ownerSealRereadDMLOperation, location, err)
			}
			if err := ctx.Err(); err != nil {
				return OwnerVerifiedSeal{}, ownerSealRereadFailure(
					ownerSealRereadContextOperation, location, err)
			}
			verification, err := transcript.AppendOwnerRereadPage(scratch, ownerCRC32C)
			if err != nil {
				return OwnerVerifiedSeal{}, ownerSealRereadFailure(
					ownerSealRereadTranscriptOperation, location, err)
			}
			if verification.Target() != target {
				return OwnerVerifiedSeal{}, ownerSealRereadFailure(
					ownerSealRereadTranscriptOperation,
					location,
					errors.New("successful verification returned a substituted target"))
			}
			if sink != nil {
				if err := ctx.Err(); err != nil {
					return OwnerVerifiedSeal{}, ownerSealRereadFailure(
						ownerSealRereadContextOperation, location, err)
				}
				if err := sink(verification); err != nil {
					return OwnerVerifiedSeal{}, ownerSealRereadFailure(
						ownerSealRereadSinkOperation, location, err)
				}
			}
			logicalPage++
		}
	}
	if logicalPage != plan.TotalPages() {
		return OwnerVerifiedSeal{}, ownerSealRereadFailure(
			ownerSealRereadTranscriptOperation,
			ownerSealRereadNoLocation(),
			fmt.Errorf("extent cursor covered %d pages, want %d",
				logicalPage, plan.TotalPages()))
	}
	if err := ctx.Err(); err != nil {
		return OwnerVerifiedSeal{}, ownerSealRereadFailure(
			ownerSealRereadContextOperation, ownerSealRereadNoLocation(), err)
	}
	seal, err = transcript.Finish()
	if err != nil {
		return OwnerVerifiedSeal{}, ownerSealRereadFailure(
			ownerSealRereadFinishOperation, ownerSealRereadNoLocation(), err)
	}
	return seal, nil
}

func ownerSealPrepareReadableExtent(
	runIndex int,
	run ProducerScatterExtentRun,
	binding ProducerScatterDeviceBinding,
	view OwnerSealReadableExtent,
	scratchStart uintptr,
	scratchEnd uintptr,
	origins []ownerSealRereadBackingOrigin,
	backingOwners map[[sha256.Size]byte]uint32,
	prepared []ownerSealPreparedReadableExtent,
) (ownerSealPreparedReadableExtent, error) {
	if view.Binding != binding ||
		view.StartDataPageIndex != run.StartDataPageIndex ||
		view.PageCount != run.PageCount {
		return ownerSealPreparedReadableExtent{}, errors.New(
			"readable extent binding, start, or page count differs from request")
	}
	exactByteLength, multiplyOK := checkedMul(run.PageCount, uint64(ContentPageBytes))
	if !multiplyOK || exactByteLength > uint64(^uint(0)>>1) {
		return ownerSealPreparedReadableExtent{}, errors.New(
			"readable extent byte length overflows host int")
	}
	if uint64(len(view.Bytes)) != exactByteLength {
		return ownerSealPreparedReadableExtent{}, fmt.Errorf(
			"readable extent byte length %d, want %d",
			len(view.Bytes), exactByteLength)
	}
	name := fmt.Sprintf("device %q run %d", binding.DeviceUUID, runIndex)
	if err := validateProducerScatterBackingRange(name, view.Backing, exactByteLength); err != nil {
		return ownerSealPreparedReadableExtent{}, err
	}
	addressStart, addressEnd, err := producerScatterSliceAddressRange(view.Bytes)
	if err != nil {
		return ownerSealPreparedReadableExtent{}, fmt.Errorf("%s: %w", name, err)
	}
	if addressStart < scratchEnd && scratchStart < addressEnd {
		return ownerSealPreparedReadableExtent{}, errors.New(
			"readable extent aliases Owner scratch page")
	}
	candidate := ownerSealPreparedReadableExtent{
		run:          run,
		view:         view,
		addressStart: addressStart,
		addressEnd:   addressEnd,
	}
	for previousIndex, previous := range prepared {
		physicalOverlap, rangeErr := producerScatterBackingRangesOverlap(
			previous.view.Backing, candidate.view.Backing)
		if rangeErr != nil {
			return ownerSealPreparedReadableExtent{}, rangeErr
		}
		virtualOverlap := previous.addressStart < candidate.addressEnd &&
			candidate.addressStart < previous.addressEnd
		if physicalOverlap || virtualOverlap {
			return ownerSealPreparedReadableExtent{}, fmt.Errorf(
				"readable extent runs %d and %d alias", previousIndex, runIndex)
		}
	}
	physicalByteOffset, physicalOK := checkedMul(
		run.StartDataPageIndex, uint64(ContentPageBytes))
	if !physicalOK || view.Backing.ByteOffset < physicalByteOffset {
		return ownerSealPreparedReadableExtent{}, errors.New(
			"readable extent backing offset cannot represent its data-page index")
	}
	origin := ownerSealRereadBackingOrigin{
		initialized: true,
		backingID:   view.Backing.BackingID,
		byteOffset:  view.Backing.ByteOffset - physicalByteOffset,
	}
	if uint64(run.DeviceIndex) >= uint64(len(origins)) {
		return ownerSealPreparedReadableExtent{}, errors.New(
			"readable extent device index is outside backing-origin table")
	}
	if previous := origins[run.DeviceIndex]; previous.initialized {
		if previous != origin {
			return ownerSealPreparedReadableExtent{}, errors.New(
				"same-device readable extents have different backing origins")
		}
	} else {
		if previousDevice, found := backingOwners[origin.backingID]; found &&
			previousDevice != run.DeviceIndex {
			return ownerSealPreparedReadableExtent{}, errors.New(
				"different devices share one physical backing ID")
		}
		origins[run.DeviceIndex] = origin
		backingOwners[origin.backingID] = run.DeviceIndex
	}
	return candidate, nil
}

func ownerSealRereadNoLocation() ownerSealRereadLocation {
	return ownerSealRereadLocation{runIndex: -1}
}

func ownerSealRereadRunLocation(
	runIndex int,
	run ProducerScatterExtentRun,
	deviceUUID string,
) ownerSealRereadLocation {
	return ownerSealRereadLocation{
		runIndex:       runIndex,
		logicalPage:    run.LogicalPageStart,
		hasLogicalPage: true,
		deviceUUID:     deviceUUID,
	}
}

func ownerSealRereadPageLocation(
	runIndex int,
	logicalPage uint64,
	deviceUUID string,
) ownerSealRereadLocation {
	return ownerSealRereadLocation{
		runIndex:       runIndex,
		logicalPage:    logicalPage,
		hasLogicalPage: true,
		deviceUUID:     deviceUUID,
	}
}

func ownerSealRereadFailure(
	operation ownerSealRereadOperation,
	location ownerSealRereadLocation,
	primary error,
) error {
	return &ownerSealRereadError{
		operation: operation,
		location:  location,
		primary:   primary,
	}
}

func ownerSealRereadAttachClose(primary error, closeFailure error) error {
	if primary == nil {
		return closeFailure
	}
	var typed *ownerSealRereadError
	if errors.As(primary, &typed) {
		result := *typed
		result.closeErr = closeFailure
		return &result
	}
	return &ownerSealRereadError{
		operation: ownerSealRereadCloseOperation,
		location:  ownerSealRereadNoLocation(),
		primary:   primary,
		closeErr:  closeFailure,
	}
}

func ownerSealRereadInterfaceNil(value interface{}) bool {
	if value == nil {
		return true
	}
	reflected := reflect.ValueOf(value)
	switch reflected.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map,
		reflect.Ptr, reflect.Slice:
		return reflected.IsNil()
	default:
		return false
	}
}

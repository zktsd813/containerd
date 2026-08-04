package trcxl007

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"sort"

	"github.com/containerd/containerd/third_party/trenv-containerd/pkg/cxlcheckpoint"
)

var (
	// ErrInvalidOwnerSealMedia identifies an invalid COMMITTING Owner shape or
	// invalid bytes recovered from the two bootstrap control objects. It is not
	// an operational content-source error and this read-only operation performs
	// no descriptor, allocator, Owner-state, payload, or Sync mutation.
	ErrInvalidOwnerSealMedia = errors.New(
		"invalid TRCXL007 Owner seal recovery media")

	// ErrOwnerSealContentSource identifies an operational context, pass-open,
	// direct-view, or pass-close failure. It is deliberately separate from
	// invalid durable media so a later executor can choose reopen/retry rather
	// than misclassifying an incomplete observation as quarantine evidence.
	ErrOwnerSealContentSource = errors.New(
		"TRCXL007 Owner seal direct content source failure")
)

// OwnerSealReadableExtent is one exact read-only direct-DAX view. Binding,
// StartDataPageIndex, and PageCount echo the request and are checked by the
// loader before the first control byte is copied. Bytes must directly map the
// requested DAX capacity; a CPU snapshot, buffered ReaderAt result, or generic
// file read is not eligible. The slice must remain stable and unmodified until
// its OwnerSealContentReadPass is closed.
//
// Backing uses the same global physical-backing namespace as Producer scatter.
// Every view of one device must report one stable BackingID and one stable
// device-relative backing origin. The loader rejects both physical-backing and
// virtual-memory aliasing before reading either envelope.
type OwnerSealReadableExtent struct {
	Binding            ProducerScatterDeviceBinding
	StartDataPageIndex uint64
	PageCount          uint64
	Bytes              []byte
	Backing            ProducerScatterBackingRange
}

// OwnerSealContentReadPass supplies stable direct-DAX views for one bounded
// recovery observation. Implementations must be capability-bound to the exact
// opened Owner group represented by the bindings passed to OpenReadPass. This
// interface provides no ReaderAt fallback and no software DML path.
type OwnerSealContentReadPass interface {
	ReadableExtent(
		binding ProducerScatterDeviceBinding,
		startDataPageIndex uint64,
		pageCount uint64,
	) (OwnerSealReadableExtent, error)
	Close() error
}

// OwnerSealContentSource opens a fresh platform visibility/mapping pass for a
// detached exact device-binding table. A later hardware reread executor must
// open a new pass after its all-DAX descriptor Sync and metadata refresh; it
// must never reuse the bootstrap pass opened here.
type OwnerSealContentSource interface {
	OpenReadPass(
		ctx context.Context,
		devices []ProducerScatterDeviceBinding,
	) (OwnerSealContentReadPass, error)
}

// OwnerSealMediaReadError retains a stable non-secret operation and optional
// device identity. errors.Is distinguishes invalid durable media from an
// operational content-source failure. If cleanup also failed, CloseError
// exposes that secondary failure without hiding the primary cause; this is
// compatible with Go 1.17, which has no errors.Join.
type OwnerSealMediaReadError struct {
	operation     string
	deviceUUID    string
	cause         error
	closeError    error
	invalidMedia  bool
	contentSource bool
}

func (readError *OwnerSealMediaReadError) Error() string {
	if readError == nil {
		return "TRCXL007 Owner seal media read failed"
	}
	location := ""
	if readError.deviceUUID != "" {
		location = fmt.Sprintf(" on device %q", readError.deviceUUID)
	}
	message := fmt.Sprintf(
		"TRCXL007 Owner seal media read failed during %s%s: %v",
		readError.operation,
		location,
		readError.cause)
	if readError.closeError != nil && readError.closeError != readError.cause {
		message += fmt.Sprintf("; closing the direct content pass also failed: %v",
			readError.closeError)
	}
	return message
}

func (readError *OwnerSealMediaReadError) Unwrap() error {
	if readError == nil {
		return nil
	}
	return readError.cause
}

func (readError *OwnerSealMediaReadError) Is(target error) bool {
	if readError == nil {
		return false
	}
	if target == ErrInvalidOwnerSealMedia && readError.invalidMedia {
		return true
	}
	if target == ErrOwnerSealContentSource && readError.contentSource {
		return true
	}
	if errors.Is(readError.cause, target) {
		return true
	}
	return readError.closeError != nil && readError.closeError != readError.cause &&
		errors.Is(readError.closeError, target)
}

// Operation returns the stable step that first failed.
func (readError *OwnerSealMediaReadError) Operation() string {
	if readError == nil {
		return ""
	}
	return readError.operation
}

// DeviceUUID returns the affected persistent device identity when one exact
// view was involved. It never returns a host-local path.
func (readError *OwnerSealMediaReadError) DeviceUUID() string {
	if readError == nil {
		return ""
	}
	return readError.deviceUUID
}

// CloseError returns the secondary pass-close failure, if any. The primary
// cause remains available through errors.Unwrap.
func (readError *OwnerSealMediaReadError) CloseError() error {
	if readError == nil {
		return nil
	}
	return readError.closeError
}

const (
	ownerSealMediaPublicationObject = iota
	ownerSealMediaInitialPlacementObject
	ownerSealMediaObjectCount
)

type ownerSealMediaObject struct {
	kind             cxlcheckpoint.ContentKindV7
	objectID         uint64
	logicalPageStart uint64
	capacityPages    uint64
	capacityBytes    uint64
}

type ownerSealMediaRun struct {
	objectIndex        int
	objectPageStart    uint64
	binding            ProducerScatterDeviceBinding
	startDataPageIndex uint64
	pageCount          uint64
}

// ownerSealRecordMediaPlan is bounded by two objects, the allocation's compact
// extent count, and its selected device count. It contains no page table, CRC
// vector, descriptor array, Producer plan, publication bytes, or source view.
type ownerSealRecordMediaPlan struct {
	devices []ProducerScatterDeviceBinding
	objects [ownerSealMediaObjectCount]ownerSealMediaObject
	runs    []ownerSealMediaRun
}

type ownerSealPreparedMediaRun struct {
	ownerSealMediaRun
	bytes        []byte
	backing      ProducerScatterBackingRange
	addressStart uintptr
	addressEnd   uintptr
}

type ownerSealMediaBackingOrigin struct {
	backingID [sha256.Size]byte
	offset    uint64
}

// LoadCommittingOwnerSealRecoveryPlanFromMedia reads only the Publication and
// initial slot-A capacities needed to bootstrap one exact COMMITTING recovery.
// It first maps and validates every clipped direct-DAX extent, copies exactly a
// fixed 64-byte header for each envelope, bounds the declared exact length by
// that object's exact capacity, then copies exactly the complete declared
// envelope and invokes BuildCommittingOwnerSealRecoveryPlan for full decoding,
// canonical validation, and the exact Owner/publication/map join.
//
// These bounded CPU copies are bootstrap parsing only. They are not Owner
// payload verification, do not produce an OwnerVerifiedSeal, and do not replace
// the required three hardware-only DML traversals. The function retains no
// pass, direct view, source, or envelope bytes in its detached result. After a
// successful OpenReadPass, Close is called exactly once on every return prefix.
func LoadCommittingOwnerSealRecoveryPlanFromMedia(
	ctx context.Context,
	committingState OwnerStateSnapshot,
	allocationRecordID uint64,
	source OwnerSealContentSource,
) (
	result CommittingOwnerSealRecoveryPlan,
	resultErr error,
) {
	if interfaceIsNil(ctx) {
		return CommittingOwnerSealRecoveryPlan{}, ownerSealMediaSourceError(
			"validate context", "", errors.New("nil context"))
	}
	if err := ctx.Err(); err != nil {
		return CommittingOwnerSealRecoveryPlan{}, ownerSealMediaSourceError(
			"check context before media planning", "", err)
	}

	mediaPlan, err := buildOwnerSealRecordMediaPlan(
		committingState, allocationRecordID)
	if err != nil {
		return CommittingOwnerSealRecoveryPlan{}, err
	}
	if interfaceIsNil(source) {
		return CommittingOwnerSealRecoveryPlan{}, ownerSealMediaSourceError(
			"validate direct content source", "", errors.New("nil content source"))
	}
	if err := ctx.Err(); err != nil {
		return CommittingOwnerSealRecoveryPlan{}, ownerSealMediaSourceError(
			"check context before opening direct content pass", "", err)
	}

	pass, openErr := source.OpenReadPass(
		ctx, append([]ProducerScatterDeviceBinding(nil), mediaPlan.devices...))
	if openErr != nil {
		primary := ownerSealMediaSourceError(
			"open direct content pass", "", openErr)
		if interfaceIsNil(pass) {
			return CommittingOwnerSealRecoveryPlan{}, primary
		}
		return CommittingOwnerSealRecoveryPlan{}, ownerSealMediaAddCloseFailure(
			primary, pass.Close())
	}
	if interfaceIsNil(pass) {
		return CommittingOwnerSealRecoveryPlan{}, ownerSealMediaSourceError(
			"open direct content pass", "", errors.New("source returned a nil pass"))
	}

	closed := false
	defer func() {
		if closed {
			return
		}
		closed = true
		if closeErr := pass.Close(); closeErr != nil {
			result = CommittingOwnerSealRecoveryPlan{}
			resultErr = ownerSealMediaAddCloseFailure(resultErr, closeErr)
		}
	}()

	prepared, err := prepareOwnerSealMediaRuns(ctx, pass, mediaPlan)
	if err != nil {
		return CommittingOwnerSealRecoveryPlan{}, err
	}
	publicationBytes, err := readOwnerSealMediaEnvelope(
		ctx,
		mediaPlan.objects[ownerSealMediaPublicationObject],
		prepared,
		"TRPUB007 Publication",
		cxlcheckpoint.PublicationV7EnvelopeHeaderBytes,
		cxlcheckpoint.PublicationV7EnvelopeExactLengthFromHeader)
	if err != nil {
		return CommittingOwnerSealRecoveryPlan{}, err
	}
	if err := ctx.Err(); err != nil {
		return CommittingOwnerSealRecoveryPlan{}, ownerSealMediaSourceError(
			"check context between recovery envelopes", "", err)
	}
	initialPlacementBytes, err := readOwnerSealMediaEnvelope(
		ctx,
		mediaPlan.objects[ownerSealMediaInitialPlacementObject],
		prepared,
		"initial slot-A TRCPM007",
		cxlcheckpoint.ContentMappingEnvelopeHeaderBytes,
		cxlcheckpoint.ContentPlacementMapEnvelopeExactLengthFromHeader)
	if err != nil {
		return CommittingOwnerSealRecoveryPlan{}, err
	}
	if err := ctx.Err(); err != nil {
		return CommittingOwnerSealRecoveryPlan{}, ownerSealMediaSourceError(
			"check context before recovery-plan decode", "", err)
	}

	recovery, err := BuildCommittingOwnerSealRecoveryPlan(
		committingState,
		allocationRecordID,
		publicationBytes,
		initialPlacementBytes)
	if err != nil {
		return CommittingOwnerSealRecoveryPlan{}, ownerSealMediaInvalidError(
			"decode and join recovery envelopes", err)
	}
	if err := ctx.Err(); err != nil {
		return CommittingOwnerSealRecoveryPlan{}, ownerSealMediaSourceError(
			"check context after recovery-plan decode", "", err)
	}

	closeErr := pass.Close()
	closed = true
	if closeErr != nil {
		return CommittingOwnerSealRecoveryPlan{}, ownerSealMediaAddCloseFailure(
			nil, closeErr)
	}
	if err := ctx.Err(); err != nil {
		return CommittingOwnerSealRecoveryPlan{}, ownerSealMediaSourceError(
			"check context after closing direct content pass", "", err)
	}
	return recovery, nil
}

func buildOwnerSealRecordMediaPlan(
	committingState OwnerStateSnapshot,
	allocationRecordID uint64,
) (ownerSealRecordMediaPlan, error) {
	owner := committingState.Clone()
	if err := owner.Validate(); err != nil {
		return ownerSealRecordMediaPlan{}, ownerSealMediaInvalidError(
			"validate COMMITTING Owner state", err)
	}
	if allocationRecordID == 0 || allocationRecordID > cxlcheckpoint.MaxSignedLong {
		return ownerSealRecordMediaPlan{}, ownerSealMediaInvalidError(
			"select COMMITTING allocation",
			fmt.Errorf("allocation record ID %d is outside 1..%d",
				allocationRecordID, cxlcheckpoint.MaxSignedLong))
	}
	record, found := producerScatterRecordByID(owner.Records(), allocationRecordID)
	if !found || record.State != OwnerAllocationCommitting {
		state := OwnerAllocationState(0)
		if found {
			state = record.State
		}
		return ownerSealRecordMediaPlan{}, ownerSealMediaInvalidError(
			"select COMMITTING allocation",
			fmt.Errorf("allocation %d is absent or in state %d",
				allocationRecordID, state))
	}

	var objects [ownerSealMediaObjectCount]ownerSealMediaObject
	var foundObject [ownerSealMediaObjectCount]bool
	for _, demand := range record.ContentDemands {
		objectIndex := -1
		maximumPages := uint64(0)
		switch demand.Kind {
		case cxlcheckpoint.ContentPublicationV7:
			objectIndex = ownerSealMediaPublicationObject
			maximumPages = cxlcheckpoint.MaxPublicationV7SlotPages
		case cxlcheckpoint.ContentPlacementSlotAV7:
			objectIndex = ownerSealMediaInitialPlacementObject
			maximumPages = cxlcheckpoint.MaxPlacementSlotV7Pages
		default:
			continue
		}
		if foundObject[objectIndex] {
			return ownerSealRecordMediaPlan{}, ownerSealMediaInvalidError(
				"locate recovery control objects",
				fmt.Errorf("content kind %d occurs more than once", demand.Kind))
		}
		if demand.CapacityPages == 0 || demand.CapacityPages > maximumPages {
			return ownerSealRecordMediaPlan{}, ownerSealMediaInvalidError(
				"bound recovery control-object capacity",
				fmt.Errorf("content kind %d capacity %d is outside 1..%d pages",
					demand.Kind, demand.CapacityPages, maximumPages))
		}
		capacityBytes, ok := checkedMul(
			demand.CapacityPages, uint64(ContentPageBytes))
		if !ok || capacityBytes > uint64(maxIntValue()) {
			return ownerSealRecordMediaPlan{}, ownerSealMediaInvalidError(
				"bound recovery control-object capacity",
				fmt.Errorf("content kind %d capacity byte length overflows host int",
					demand.Kind))
		}
		objects[objectIndex] = ownerSealMediaObject{
			kind:             demand.Kind,
			objectID:         demand.ObjectID,
			logicalPageStart: demand.LogicalPageStart,
			capacityPages:    demand.CapacityPages,
			capacityBytes:    capacityBytes,
		}
		foundObject[objectIndex] = true
	}
	for index, found := range foundObject {
		if !found {
			return ownerSealRecordMediaPlan{}, ownerSealMediaInvalidError(
				"locate recovery control objects",
				fmt.Errorf("required recovery object index %d is absent", index))
		}
	}

	members := owner.Devices()
	memberByUUID := make(map[string]OwnerStateDevice, len(members))
	for _, member := range members {
		memberByUUID[member.DeviceUUID] = member
	}
	runs := make([]ownerSealMediaRun, 0, 2*len(record.Fragments))
	selectedBindings := make(map[string]ProducerScatterDeviceBinding)
	for _, fragment := range record.Fragments {
		member, exists := memberByUUID[fragment.DeviceUUID]
		if !exists || member.DeviceOwnerEpoch != fragment.DeviceOwnerEpoch {
			return ownerSealRecordMediaPlan{}, ownerSealMediaInvalidError(
				"bind recovery extent devices",
				fmt.Errorf("fragment device %q is absent or has a different Owner epoch",
					fragment.DeviceUUID))
		}
		binding := ProducerScatterDeviceBinding{
			DeviceUUID:          member.DeviceUUID,
			DeviceOwnerEpoch:    member.DeviceOwnerEpoch,
			DataPageCount:       member.DataPageCount,
			DeviceBindingSHA256: member.DeviceBindingSHA256,
		}
		for _, extent := range fragment.Extents {
			extentEnd, ok := checkedAdd(extent.LogicalPageStart, extent.PageCount)
			if !ok {
				return ownerSealRecordMediaPlan{}, ownerSealMediaInvalidError(
					"clip recovery control extents",
					errors.New("extent logical range overflows"))
			}
			for objectIndex := range objects {
				object := objects[objectIndex]
				objectEnd, addOK := checkedAdd(
					object.logicalPageStart, object.capacityPages)
				if !addOK {
					return ownerSealRecordMediaPlan{}, ownerSealMediaInvalidError(
						"clip recovery control extents",
						errors.New("control-object logical range overflows"))
				}
				intersectionStart := extent.LogicalPageStart
				if object.logicalPageStart > intersectionStart {
					intersectionStart = object.logicalPageStart
				}
				intersectionEnd := extentEnd
				if objectEnd < intersectionEnd {
					intersectionEnd = objectEnd
				}
				if intersectionStart >= intersectionEnd {
					continue
				}
				delta := intersectionStart - extent.LogicalPageStart
				physicalStart, physicalOK := checkedAdd(
					extent.StartDataPageIndex, delta)
				if !physicalOK {
					return ownerSealRecordMediaPlan{}, ownerSealMediaInvalidError(
						"clip recovery control extents",
						errors.New("clipped physical start overflows"))
				}
				runs = append(runs, ownerSealMediaRun{
					objectIndex:        objectIndex,
					objectPageStart:    intersectionStart - object.logicalPageStart,
					binding:            binding,
					startDataPageIndex: physicalStart,
					pageCount:          intersectionEnd - intersectionStart,
				})
				selectedBindings[binding.DeviceUUID] = binding
			}
		}
	}

	sort.Slice(runs, func(left, right int) bool {
		if runs[left].objectIndex != runs[right].objectIndex {
			return runs[left].objectIndex < runs[right].objectIndex
		}
		return runs[left].objectPageStart < runs[right].objectPageStart
	})
	for objectIndex := range objects {
		expectedPage := uint64(0)
		for _, run := range runs {
			if run.objectIndex != objectIndex {
				continue
			}
			if run.objectPageStart != expectedPage {
				return ownerSealRecordMediaPlan{}, ownerSealMediaInvalidError(
					"validate clipped recovery coverage",
					fmt.Errorf("object %d has a gap or overlap at page %d",
						objects[objectIndex].objectID, expectedPage))
			}
			next, ok := checkedAdd(expectedPage, run.pageCount)
			if !ok || next > objects[objectIndex].capacityPages {
				return ownerSealRecordMediaPlan{}, ownerSealMediaInvalidError(
					"validate clipped recovery coverage",
					fmt.Errorf("object %d clipped coverage overflows",
						objects[objectIndex].objectID))
			}
			expectedPage = next
		}
		if expectedPage != objects[objectIndex].capacityPages {
			return ownerSealRecordMediaPlan{}, ownerSealMediaInvalidError(
				"validate clipped recovery coverage",
				fmt.Errorf("object %d covers %d of %d capacity pages",
					objects[objectIndex].objectID,
					expectedPage,
					objects[objectIndex].capacityPages))
		}
	}

	devices := make([]ProducerScatterDeviceBinding, 0, len(selectedBindings))
	for _, binding := range selectedBindings {
		devices = append(devices, binding)
	}
	sort.Slice(devices, func(left, right int) bool {
		return devices[left].DeviceUUID < devices[right].DeviceUUID
	})
	if len(devices) == 0 || len(runs) == 0 {
		return ownerSealRecordMediaPlan{}, ownerSealMediaInvalidError(
			"validate clipped recovery coverage",
			errors.New("recovery control objects selected no direct extents"))
	}
	return ownerSealRecordMediaPlan{
		devices: append([]ProducerScatterDeviceBinding(nil), devices...),
		objects: objects,
		runs:    append([]ownerSealMediaRun(nil), runs...),
	}, nil
}

func prepareOwnerSealMediaRuns(
	ctx context.Context,
	pass OwnerSealContentReadPass,
	mediaPlan ownerSealRecordMediaPlan,
) ([]ownerSealPreparedMediaRun, error) {
	prepared := make([]ownerSealPreparedMediaRun, 0, len(mediaPlan.runs))
	origins := make(map[string]ownerSealMediaBackingOrigin, len(mediaPlan.devices))
	deviceByBackingID := make(map[[sha256.Size]byte]string, len(mediaPlan.devices))
	for runIndex, run := range mediaPlan.runs {
		if err := ctx.Err(); err != nil {
			return nil, ownerSealMediaSourceError(
				"check context before direct extent view", run.binding.DeviceUUID, err)
		}
		view, err := pass.ReadableExtent(
			run.binding, run.startDataPageIndex, run.pageCount)
		if err != nil {
			return nil, ownerSealMediaSourceError(
				fmt.Sprintf("open direct extent view %d", runIndex),
				run.binding.DeviceUUID,
				err)
		}
		if err := ctx.Err(); err != nil {
			return nil, ownerSealMediaSourceError(
				"check context after direct extent view", run.binding.DeviceUUID, err)
		}
		if view.Binding != run.binding ||
			view.StartDataPageIndex != run.startDataPageIndex ||
			view.PageCount != run.pageCount {
			return nil, ownerSealMediaSourceError(
				fmt.Sprintf("validate direct extent view %d identity", runIndex),
				run.binding.DeviceUUID,
				errors.New("returned binding or extent coordinates are stale"))
		}
		exactBytes, multiplyOK := checkedMul(
			run.pageCount, uint64(ContentPageBytes))
		if !multiplyOK || exactBytes == 0 || exactBytes > uint64(maxIntValue()) {
			return nil, ownerSealMediaInvalidError(
				"size clipped recovery extent",
				fmt.Errorf("device %q extent byte length overflows",
					run.binding.DeviceUUID))
		}
		if uint64(len(view.Bytes)) != exactBytes {
			return nil, ownerSealMediaSourceError(
				fmt.Sprintf("validate direct extent view %d length", runIndex),
				run.binding.DeviceUUID,
				fmt.Errorf("view length %d, want %d", len(view.Bytes), exactBytes))
		}
		if err := validateProducerScatterBackingRange(
			fmt.Sprintf("Owner seal device %q run %d",
				run.binding.DeviceUUID, runIndex),
			view.Backing,
			exactBytes); err != nil {
			return nil, ownerSealMediaSourceError(
				fmt.Sprintf("validate direct extent view %d backing", runIndex),
				run.binding.DeviceUUID,
				err)
		}
		physicalBytes, physicalOK := checkedMul(
			run.startDataPageIndex, uint64(ContentPageBytes))
		if !physicalOK || view.Backing.ByteOffset < physicalBytes {
			return nil, ownerSealMediaSourceError(
				fmt.Sprintf("validate direct extent view %d backing origin", runIndex),
				run.binding.DeviceUUID,
				errors.New("backing offset cannot represent the requested physical page"))
		}
		origin := ownerSealMediaBackingOrigin{
			backingID: view.Backing.BackingID,
			offset:    view.Backing.ByteOffset - physicalBytes,
		}
		if previousDevice, found := deviceByBackingID[origin.backingID]; found &&
			previousDevice != run.binding.DeviceUUID {
			return nil, ownerSealMediaSourceError(
				fmt.Sprintf("validate direct extent view %d backing identity", runIndex),
				run.binding.DeviceUUID,
				errors.New("different devices report the same physical backing identity"))
		}
		deviceByBackingID[origin.backingID] = run.binding.DeviceUUID
		if previous, found := origins[run.binding.DeviceUUID]; found {
			if previous != origin {
				return nil, ownerSealMediaSourceError(
					fmt.Sprintf("validate direct extent view %d backing origin", runIndex),
					run.binding.DeviceUUID,
					errors.New("same-device direct views have different backing origins"))
			}
		} else {
			origins[run.binding.DeviceUUID] = origin
		}
		addressStart, addressEnd, err := producerScatterSliceAddressRange(view.Bytes)
		if err != nil {
			return nil, ownerSealMediaSourceError(
				fmt.Sprintf("validate direct extent view %d address", runIndex),
				run.binding.DeviceUUID,
				err)
		}
		candidate := ownerSealPreparedMediaRun{
			ownerSealMediaRun: run,
			bytes:             view.Bytes,
			backing:           view.Backing,
			addressStart:      addressStart,
			addressEnd:        addressEnd,
		}
		for previousIndex, previous := range prepared {
			overlap, overlapErr := producerScatterBackingRangesOverlap(
				previous.backing, candidate.backing)
			if overlapErr != nil {
				return nil, ownerSealMediaSourceError(
					fmt.Sprintf("compare direct extent views %d and %d",
						previousIndex, runIndex),
					run.binding.DeviceUUID,
					overlapErr)
			}
			if overlap || (previous.addressStart < candidate.addressEnd &&
				candidate.addressStart < previous.addressEnd) {
				return nil, ownerSealMediaSourceError(
					fmt.Sprintf("compare direct extent views %d and %d",
						previousIndex, runIndex),
					run.binding.DeviceUUID,
					errors.New("direct extent views physically or virtually alias"))
			}
		}
		prepared = append(prepared, candidate)
	}
	return prepared, nil
}

type ownerSealMediaEnvelopeLength func([]byte, uint64) (uint64, error)

func readOwnerSealMediaEnvelope(
	ctx context.Context,
	object ownerSealMediaObject,
	prepared []ownerSealPreparedMediaRun,
	name string,
	headerBytes uint64,
	exactLength ownerSealMediaEnvelopeLength,
) ([]byte, error) {
	if headerBytes == 0 || headerBytes > object.capacityBytes ||
		headerBytes > uint64(maxIntValue()) {
		return nil, ownerSealMediaInvalidError(
			"bound "+name+" header",
			fmt.Errorf("header length %d exceeds object capacity %d",
				headerBytes, object.capacityBytes))
	}
	header := make([]byte, int(headerBytes))
	if err := copyOwnerSealMediaObjectBytes(
		ctx, object, prepared, 0, header); err != nil {
		return nil, err
	}
	declared, err := exactLength(header, object.capacityBytes)
	if err != nil {
		return nil, ownerSealMediaInvalidError(
			"validate "+name+" header", err)
	}
	if declared < headerBytes || declared > object.capacityBytes ||
		declared > uint64(maxIntValue()) {
		return nil, ownerSealMediaInvalidError(
			"bound "+name+" envelope",
			fmt.Errorf("declared length %d is outside %d..%d",
				declared, headerBytes, object.capacityBytes))
	}
	if err := ctx.Err(); err != nil {
		return nil, ownerSealMediaSourceError(
			"check context before copying "+name+" envelope", "", err)
	}
	envelope := make([]byte, int(declared))
	if err := copyOwnerSealMediaObjectBytes(
		ctx, object, prepared, 0, envelope); err != nil {
		return nil, err
	}
	if !bytes.Equal(header, envelope[:int(headerBytes)]) {
		return nil, ownerSealMediaSourceError(
			"confirm "+name+" discovery header",
			"",
			errors.New("header changed between bounded discovery and exact copy"))
	}
	return envelope, nil
}

func copyOwnerSealMediaObjectBytes(
	ctx context.Context,
	object ownerSealMediaObject,
	prepared []ownerSealPreparedMediaRun,
	objectByteOffset uint64,
	destination []byte,
) error {
	end, ok := checkedAdd(objectByteOffset, uint64(len(destination)))
	if !ok || end > object.capacityBytes {
		return ownerSealMediaInvalidError(
			"copy bounded recovery object",
			fmt.Errorf("object %d byte range %d..%d exceeds capacity %d",
				object.objectID, objectByteOffset, end, object.capacityBytes))
	}
	remainingOffset := objectByteOffset
	copied := uint64(0)
	for _, run := range prepared {
		if run.objectIndex < 0 || run.objectIndex >= ownerSealMediaObjectCount ||
			run.objectIndex == ownerSealMediaPublicationObject &&
				object.kind != cxlcheckpoint.ContentPublicationV7 ||
			run.objectIndex == ownerSealMediaInitialPlacementObject &&
				object.kind != cxlcheckpoint.ContentPlacementSlotAV7 {
			continue
		}
		runByteStart, multiplyOK := checkedMul(
			run.objectPageStart, uint64(ContentPageBytes))
		runByteLength, lengthOK := checkedMul(
			run.pageCount, uint64(ContentPageBytes))
		runByteEnd, addOK := checkedAdd(runByteStart, runByteLength)
		if !multiplyOK || !lengthOK || !addOK ||
			runByteEnd > object.capacityBytes ||
			uint64(len(run.bytes)) != runByteLength {
			return ownerSealMediaInvalidError(
				"copy bounded recovery object",
				fmt.Errorf("object %d prepared run is inconsistent", object.objectID))
		}
		requestStart := remainingOffset
		requestEnd := end
		if requestStart < runByteStart {
			requestStart = runByteStart
		}
		if requestEnd > runByteEnd {
			requestEnd = runByteEnd
		}
		if requestStart >= requestEnd {
			continue
		}
		if err := ctx.Err(); err != nil {
			return ownerSealMediaSourceError(
				"check context while copying bounded recovery object",
				run.binding.DeviceUUID,
				err)
		}
		runOffset := requestStart - runByteStart
		chunk := requestEnd - requestStart
		destinationOffset := requestStart - objectByteOffset
		copy(
			destination[int(destinationOffset):int(destinationOffset+chunk)],
			run.bytes[int(runOffset):int(runOffset+chunk)])
		copied += chunk
		remainingOffset = requestEnd
		if remainingOffset == end {
			break
		}
	}
	if copied != uint64(len(destination)) || remainingOffset != end {
		return ownerSealMediaInvalidError(
			"copy bounded recovery object",
			fmt.Errorf("object %d copied %d of %d bytes",
				object.objectID, copied, len(destination)))
	}
	return nil
}

func ownerSealMediaInvalidError(operation string, cause error) error {
	if cause == nil {
		cause = errors.New("unspecified invalid Owner seal media")
	}
	return &OwnerSealMediaReadError{
		operation:    operation,
		cause:        cause,
		invalidMedia: true,
	}
}

func ownerSealMediaSourceError(
	operation string,
	deviceUUID string,
	cause error,
) error {
	if cause == nil {
		cause = errors.New("unspecified direct content source failure")
	}
	return &OwnerSealMediaReadError{
		operation:     operation,
		deviceUUID:    deviceUUID,
		cause:         cause,
		contentSource: true,
	}
}

func ownerSealMediaAddCloseFailure(primary error, closeErr error) error {
	if closeErr == nil {
		return primary
	}
	if primary == nil {
		return &OwnerSealMediaReadError{
			operation:     "close direct content pass",
			cause:         closeErr,
			closeError:    closeErr,
			contentSource: true,
		}
	}
	operation := "close direct content pass after an earlier failure"
	deviceUUID := ""
	if readError, ok := primary.(*OwnerSealMediaReadError); ok && readError != nil {
		operation = readError.operation
		deviceUUID = readError.deviceUUID
	}
	return &OwnerSealMediaReadError{
		operation:     operation,
		deviceUUID:    deviceUUID,
		cause:         primary,
		closeError:    closeErr,
		invalidMedia:  errors.Is(primary, ErrInvalidOwnerSealMedia),
		contentSource: true,
	}
}

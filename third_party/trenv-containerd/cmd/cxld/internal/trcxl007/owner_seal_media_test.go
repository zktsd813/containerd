package trcxl007

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"reflect"
	"testing"

	"github.com/containerd/containerd/third_party/trenv-containerd/pkg/cxlcheckpoint"
)

type ownerSealMediaTestRequest struct {
	binding            ProducerScatterDeviceBinding
	startDataPageIndex uint64
	pageCount          uint64
}

type ownerSealMediaTestSource struct {
	expectedBindings map[string]ProducerScatterDeviceBinding
	deviceBytes      map[string][]byte
	backingIDs       map[string][sha256.Size]byte
	backingOrigin    uint64

	openCalls         int
	openDevices       [][]ProducerScatterDeviceBinding
	openError         error
	returnPassOnError bool
	returnTypedNil    bool
	mutateOpenInput   bool
	pass              *ownerSealMediaTestPass
}

type ownerSealMediaTestPass struct {
	source           *ownerSealMediaTestSource
	requests         []ownerSealMediaTestRequest
	viewCalls        int
	viewErrorCall    int
	viewError        error
	mutateView       func(int, *OwnerSealReadableExtent)
	sharedViewBytes  []byte
	cancel           context.CancelFunc
	cancelOnViewCall int
	closeCalls       int
	closeError       error
	overwriteOnClose bool
}

func (source *ownerSealMediaTestSource) OpenReadPass(
	_ context.Context,
	devices []ProducerScatterDeviceBinding,
) (OwnerSealContentReadPass, error) {
	if source == nil {
		panic("typed-nil media source was invoked")
	}
	source.openCalls++
	source.openDevices = append(source.openDevices,
		append([]ProducerScatterDeviceBinding(nil), devices...))
	for _, binding := range devices {
		if want, found := source.expectedBindings[binding.DeviceUUID]; !found || want != binding {
			return nil, fmt.Errorf("unexpected open binding %#v", binding)
		}
	}
	if source.mutateOpenInput && len(devices) != 0 {
		devices[0].DeviceUUID = "mutated-open-input"
	}
	if source.returnTypedNil {
		var pass *ownerSealMediaTestPass
		return pass, source.openError
	}
	if source.pass == nil {
		source.pass = &ownerSealMediaTestPass{source: source}
	}
	if source.openError != nil && !source.returnPassOnError {
		return nil, source.openError
	}
	return source.pass, source.openError
}

func (pass *ownerSealMediaTestPass) ReadableExtent(
	binding ProducerScatterDeviceBinding,
	startDataPageIndex uint64,
	pageCount uint64,
) (OwnerSealReadableExtent, error) {
	if pass == nil {
		panic("typed-nil media pass was invoked")
	}
	pass.viewCalls++
	pass.requests = append(pass.requests, ownerSealMediaTestRequest{
		binding: binding, startDataPageIndex: startDataPageIndex, pageCount: pageCount,
	})
	if pass.viewErrorCall == pass.viewCalls {
		if pass.viewError == nil {
			pass.viewError = errors.New("injected direct-view failure")
		}
		return OwnerSealReadableExtent{}, pass.viewError
	}
	want, found := pass.source.expectedBindings[binding.DeviceUUID]
	if !found || want != binding {
		return OwnerSealReadableExtent{}, errors.New("unexpected view binding")
	}
	end, ok := checkedAdd(startDataPageIndex, pageCount)
	if !ok || pageCount == 0 || end > binding.DataPageCount {
		return OwnerSealReadableExtent{}, errors.New("view is outside the bound device")
	}
	startByte := startDataPageIndex * uint64(ContentPageBytes)
	endByte := end * uint64(ContentPageBytes)
	device := pass.source.deviceBytes[binding.DeviceUUID]
	if endByte > uint64(len(device)) {
		return OwnerSealReadableExtent{}, errors.New("test device image is too short")
	}
	value := device[int(startByte):int(endByte)]
	if pass.sharedViewBytes != nil {
		if len(pass.sharedViewBytes) < len(value) {
			return OwnerSealReadableExtent{}, errors.New("shared alias view is too short")
		}
		copy(pass.sharedViewBytes[:len(value)], value)
		value = pass.sharedViewBytes[:len(value)]
	}
	view := OwnerSealReadableExtent{
		Binding:            binding,
		StartDataPageIndex: startDataPageIndex,
		PageCount:          pageCount,
		Bytes:              value,
		Backing: ProducerScatterBackingRange{
			BackingID:  pass.source.backingIDs[binding.DeviceUUID],
			ByteOffset: pass.source.backingOrigin + startByte,
			ByteLength: uint64(len(value)),
		},
	}
	if pass.mutateView != nil {
		pass.mutateView(pass.viewCalls, &view)
	}
	if pass.cancelOnViewCall == pass.viewCalls && pass.cancel != nil {
		pass.cancel()
	}
	return view, nil
}

func (pass *ownerSealMediaTestPass) Close() error {
	if pass == nil {
		panic("typed-nil media pass Close was invoked")
	}
	pass.closeCalls++
	if pass.overwriteOnClose {
		for _, data := range pass.source.deviceBytes {
			for index := range data {
				data[index] = 0xa5
			}
		}
	}
	return pass.closeError
}

func TestOwnerSealMediaLoadsExactFragmentedTwoDAXControlObjects(t *testing.T) {
	fixture := newOwnerSealRecoveryTestFixture(t)
	source := ownerSealMediaTestSourceForFixture(t, fixture)
	source.mutateOpenInput = true
	source.pass.overwriteOnClose = true

	recovery, err := LoadCommittingOwnerSealRecoveryPlanFromMedia(
		context.Background(), fixture.committing, 29, source)
	if err != nil {
		t.Fatalf("LoadCommittingOwnerSealRecoveryPlanFromMedia: %v", err)
	}
	if !reflect.DeepEqual(recovery.Plan(), fixture.freshPlan) ||
		recovery.ExpectedOwnerVerifiedSealSHA256() != fixture.freshSeal.SHA256() {
		t.Fatal("media recovery differs from the fresh compact plan or durable H")
	}
	if source.openCalls != 1 || source.pass.closeCalls != 1 {
		t.Fatalf("open/close calls = %d/%d, want 1/1",
			source.openCalls, source.pass.closeCalls)
	}
	wantOpen := []string{"device-a", "device-b"}
	if got := ownerSealMediaTestDeviceUUIDs(source.openDevices[0]); !reflect.DeepEqual(got, wantOpen) {
		t.Fatalf("opened devices = %v, want %v", got, wantOpen)
	}
	wantRequests := []ownerSealMediaTestRequest{
		{binding: source.expectedBindings["device-b"], startDataPageIndex: 50, pageCount: 4},
		{binding: source.expectedBindings["device-b"], startDataPageIndex: 40, pageCount: 1},
		{binding: source.expectedBindings["device-a"], startDataPageIndex: 40, pageCount: 1},
	}
	if !reflect.DeepEqual(source.pass.requests, wantRequests) {
		t.Fatalf("direct-view requests = %#v, want %#v", source.pass.requests, wantRequests)
	}
	// Close overwrote every direct view. The detached recovery result must still
	// be complete and usable, and no payload/non-bootstrap capacity was opened.
	if !reflect.DeepEqual(recovery.Plan(), fixture.freshPlan) {
		t.Fatal("closing and overwriting direct views changed the detached result")
	}
	mediaPlan, err := buildOwnerSealRecordMediaPlan(fixture.committing, 29)
	if err != nil {
		t.Fatalf("build compact media plan: %v", err)
	}
	if len(mediaPlan.devices) != 2 || len(mediaPlan.objects) != 2 || len(mediaPlan.runs) != 3 {
		t.Fatalf("compact media plan devices/objects/runs = %d/%d/%d, want 2/2/3",
			len(mediaPlan.devices), len(mediaPlan.objects), len(mediaPlan.runs))
	}
}

func TestOwnerSealMediaCrossesPageAndDeviceBoundaries(t *testing.T) {
	fixture := ownerSealMediaTestLargeFragmentedFixture(t)
	if len(fixture.initialMapBytes) <= ContentPageBytes {
		t.Fatalf("large initial map length = %d, want more than one page",
			len(fixture.initialMapBytes))
	}
	source := ownerSealMediaTestSourceForFixture(t, fixture)

	recovery, err := LoadCommittingOwnerSealRecoveryPlanFromMedia(
		context.Background(), fixture.committing, 29, source)
	if err != nil {
		t.Fatalf("large fragmented media recovery: %v", err)
	}
	if !reflect.DeepEqual(recovery.Plan(), fixture.freshPlan) {
		t.Fatal("large fragmented recovery differs from fresh plan")
	}
	seenSlotDevices := make(map[string]bool)
	for _, request := range source.pass.requests {
		if request.startDataPageIndex == 154 || request.startDataPageIndex == 155 {
			seenSlotDevices[request.binding.DeviceUUID] = true
		}
	}
	if len(seenSlotDevices) < 2 {
		t.Fatalf("slot-A views did not span both devices: %#v", source.pass.requests)
	}
}

func TestOwnerSealMediaDoesNotOpenUnallocatedAnchorDevice(t *testing.T) {
	fixture := ownerSealMediaTestUnallocatedAnchorFixture(t)
	source := ownerSealMediaTestSourceForFixture(t, fixture)

	recovery, err := LoadCommittingOwnerSealRecoveryPlanFromMedia(
		context.Background(), fixture.committing, 29, source)
	if err != nil {
		t.Fatalf("media recovery with unallocated anchor: %v", err)
	}
	if !reflect.DeepEqual(recovery.Plan(), fixture.freshPlan) {
		t.Fatal("media recovery with unallocated anchor differs from fresh plan")
	}
	if got := ownerSealMediaTestDeviceUUIDs(source.openDevices[0]); !reflect.DeepEqual(got, []string{"device-a", "device-b"}) {
		t.Fatalf("opened devices = %v, want only allocated device-a/device-b", got)
	}
	if recovery.Plan().AnchorDeviceUUID() != "device-c" {
		t.Fatalf("recovered anchor = %q, want unallocated device-c",
			recovery.Plan().AnchorDeviceUUID())
	}
}

func TestOwnerSealMediaSelectsOnlyRequestedCommittingRecord(t *testing.T) {
	fixture := newOwnerSealRecoveryTestFixture(t)
	target := fixture.committing.Records()[0]
	left := ownerSealRecoveryTestRejectedRecord(target, 28, 80, "media-left")
	right := ownerSealRecoveryTestRejectedRecord(target, 30, 90, "media-right")
	fixture.committing = ownerSealRecoveryTestRebuildOwner(
		t,
		fixture.committing,
		nil,
		[]OwnerStateAllocationRecord{left, target, right},
		fixture.committing.SnapshotSequence,
		31,
		fixture.committing.NextOwnerTransactionSequence,
	)
	source := ownerSealMediaTestSourceForFixture(t, fixture)

	recovery, err := LoadCommittingOwnerSealRecoveryPlanFromMedia(
		context.Background(), fixture.committing, 29, source)
	if err != nil {
		t.Fatalf("middle-record media recovery: %v", err)
	}
	if !reflect.DeepEqual(recovery.Plan(), fixture.freshPlan) ||
		recovery.ExpectedOwnerVerifiedSealSHA256() != fixture.freshSeal.SHA256() {
		t.Fatal("neighbor records changed the requested media recovery")
	}
	if source.openCalls != 1 || len(source.pass.requests) != 3 {
		t.Fatalf("open/view calls = %d/%d, want 1/3",
			source.openCalls, len(source.pass.requests))
	}
}

func TestOwnerSealMediaSourceFailuresAreTypedAndAlwaysClose(t *testing.T) {
	viewFailure := errors.New("view unavailable")
	closeFailure := errors.New("unmap failed")
	tests := []struct {
		name      string
		configure func(*ownerSealMediaTestSource)
	}{
		{
			name: "view error",
			configure: func(source *ownerSealMediaTestSource) {
				source.pass.viewErrorCall = 2
				source.pass.viewError = viewFailure
			},
		},
		{
			name: "stale binding echo",
			configure: func(source *ownerSealMediaTestSource) {
				source.pass.mutateView = func(_ int, view *OwnerSealReadableExtent) {
					view.Binding.DeviceOwnerEpoch++
				}
			},
		},
		{
			name: "stale extent echo",
			configure: func(source *ownerSealMediaTestSource) {
				source.pass.mutateView = func(_ int, view *OwnerSealReadableExtent) {
					view.StartDataPageIndex++
				}
			},
		},
		{
			name: "short view",
			configure: func(source *ownerSealMediaTestSource) {
				source.pass.mutateView = func(_ int, view *OwnerSealReadableExtent) {
					view.Bytes = view.Bytes[:len(view.Bytes)-1]
				}
			},
		},
		{
			name: "long view",
			configure: func(source *ownerSealMediaTestSource) {
				source.pass.mutateView = func(_ int, view *OwnerSealReadableExtent) {
					view.Bytes = append(view.Bytes, 0)
				}
			},
		},
		{
			name: "zero backing",
			configure: func(source *ownerSealMediaTestSource) {
				source.pass.mutateView = func(_ int, view *OwnerSealReadableExtent) {
					view.Backing.BackingID = [sha256.Size]byte{}
				}
			},
		},
		{
			name: "backing length mismatch",
			configure: func(source *ownerSealMediaTestSource) {
				source.pass.mutateView = func(_ int, view *OwnerSealReadableExtent) {
					view.Backing.ByteLength--
				}
			},
		},
		{
			name: "backing overflow",
			configure: func(source *ownerSealMediaTestSource) {
				source.pass.mutateView = func(_ int, view *OwnerSealReadableExtent) {
					view.Backing.ByteOffset = ^uint64(0)
				}
			},
		},
		{
			name: "backing before physical page",
			configure: func(source *ownerSealMediaTestSource) {
				source.pass.mutateView = func(_ int, view *OwnerSealReadableExtent) {
					view.Backing.ByteOffset = 1
				}
			},
		},
		{
			name: "same device changes backing origin",
			configure: func(source *ownerSealMediaTestSource) {
				source.pass.mutateView = func(call int, view *OwnerSealReadableExtent) {
					if call == 2 {
						view.Backing.ByteOffset++
					}
				}
			},
		},
		{
			name: "different devices share backing identity",
			configure: func(source *ownerSealMediaTestSource) {
				source.pass.mutateView = func(call int, view *OwnerSealReadableExtent) {
					if call == 3 {
						view.Backing.BackingID = source.backingIDs["device-b"]
						view.Backing.ByteOffset += 32 * uint64(ContentPageBytes)
					}
				}
			},
		},
		{
			name: "virtual alias",
			configure: func(source *ownerSealMediaTestSource) {
				source.pass.sharedViewBytes = make([]byte, 4*ContentPageBytes)
			},
		},
		{
			name: "successful parse but close fails",
			configure: func(source *ownerSealMediaTestSource) {
				source.pass.closeError = closeFailure
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newOwnerSealRecoveryTestFixture(t)
			source := ownerSealMediaTestSourceForFixture(t, fixture)
			test.configure(source)
			recovery, err := LoadCommittingOwnerSealRecoveryPlanFromMedia(
				context.Background(), fixture.committing, 29, source)
			if !errors.Is(err, ErrOwnerSealContentSource) {
				t.Fatalf("error = %v, want ErrOwnerSealContentSource", err)
			}
			if !reflect.DeepEqual(recovery, CommittingOwnerSealRecoveryPlan{}) {
				t.Fatal("operational failure returned a nonzero recovery result")
			}
			if source.pass.closeCalls != 1 {
				t.Fatalf("close calls = %d, want 1", source.pass.closeCalls)
			}
		})
	}
}

func TestOwnerSealMediaErrorPrecedenceRetainsPrimaryAndCloseFailure(t *testing.T) {
	fixture := newOwnerSealRecoveryTestFixture(t)
	source := ownerSealMediaTestSourceForFixture(t, fixture)
	primary := errors.New("view mapping failed")
	secondary := errors.New("pass cleanup failed")
	source.pass.viewErrorCall = 1
	source.pass.viewError = primary
	source.pass.closeError = secondary

	_, err := LoadCommittingOwnerSealRecoveryPlanFromMedia(
		context.Background(), fixture.committing, 29, source)
	var readError *OwnerSealMediaReadError
	if !errors.As(err, &readError) || !errors.Is(err, primary) || !errors.Is(err, secondary) ||
		!errors.Is(err, ErrOwnerSealContentSource) {
		t.Fatalf("combined source/close error = %#v (%v)", readError, err)
	}
	if readError.Operation() != "open direct extent view 0" ||
		readError.DeviceUUID() != "device-b" || readError.CloseError() != secondary {
		t.Fatalf("combined error operation/device/close = %q/%q/%v",
			readError.Operation(), readError.DeviceUUID(), readError.CloseError())
	}
	if source.pass.closeCalls != 1 {
		t.Fatalf("close calls = %d, want 1", source.pass.closeCalls)
	}

	t.Run("invalid media remains primary", func(t *testing.T) {
		fixture := newOwnerSealRecoveryTestFixture(t)
		source := ownerSealMediaTestSourceForFixture(t, fixture)
		ownerSealMediaTestFlipObjectByte(
			t, source, fixture.freshPlan, cxlcheckpoint.ContentPublicationV7, 0)
		source.pass.closeError = secondary
		_, err := LoadCommittingOwnerSealRecoveryPlanFromMedia(
			context.Background(), fixture.committing, 29, source)
		var readError *OwnerSealMediaReadError
		if !errors.As(err, &readError) || !errors.Is(err, ErrInvalidOwnerSealMedia) ||
			!errors.Is(err, ErrOwnerSealContentSource) || !errors.Is(err, secondary) {
			t.Fatalf("invalid-media/close classification = %v", err)
		}
		if readError.Operation() != "validate TRPUB007 Publication header" ||
			readError.CloseError() != secondary || source.pass.closeCalls != 1 {
			t.Fatalf("invalid-media operation/close/calls = %q/%v/%d",
				readError.Operation(), readError.CloseError(), source.pass.closeCalls)
		}
	})
}

func TestOwnerSealMediaPreflightsEveryViewBeforeReadingFirstHeader(t *testing.T) {
	fixture := newOwnerSealRecoveryTestFixture(t)
	source := ownerSealMediaTestSourceForFixture(t, fixture)
	ownerSealMediaTestFlipObjectByte(
		t, source, fixture.freshPlan, cxlcheckpoint.ContentPublicationV7, 0)
	source.pass.viewErrorCall = 3
	source.pass.viewError = errors.New("late slot-A view failed")

	_, err := LoadCommittingOwnerSealRecoveryPlanFromMedia(
		context.Background(), fixture.committing, 29, source)
	if !errors.Is(err, ErrOwnerSealContentSource) ||
		errors.Is(err, ErrInvalidOwnerSealMedia) {
		t.Fatalf("late preflight failure was hidden by first-object bytes: %v", err)
	}
	if source.pass.viewCalls != 3 || source.pass.closeCalls != 1 {
		t.Fatalf("view/close calls = %d/%d, want 3/1",
			source.pass.viewCalls, source.pass.closeCalls)
	}
}

func TestOwnerSealMediaOpenNilAndCancellationPrefixes(t *testing.T) {
	fixture := newOwnerSealRecoveryTestFixture(t)
	openFailure := errors.New("visibility pass unavailable")
	closeFailure := errors.New("failed to close partial pass")
	t.Run("pre-canceled", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		source := ownerSealMediaTestSourceForFixture(t, fixture)
		_, err := LoadCommittingOwnerSealRecoveryPlanFromMedia(
			ctx, fixture.committing, 29, source)
		if !errors.Is(err, ErrOwnerSealContentSource) || !errors.Is(err, context.Canceled) ||
			source.openCalls != 0 {
			t.Fatalf("pre-canceled error/open calls = %v/%d", err, source.openCalls)
		}
	})
	t.Run("cancel after view", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		source := ownerSealMediaTestSourceForFixture(t, fixture)
		source.pass.cancel = cancel
		source.pass.cancelOnViewCall = 1
		_, err := LoadCommittingOwnerSealRecoveryPlanFromMedia(
			ctx, fixture.committing, 29, source)
		if !errors.Is(err, context.Canceled) || !errors.Is(err, ErrOwnerSealContentSource) ||
			source.pass.closeCalls != 1 {
			t.Fatalf("cancel-after-view error/close calls = %v/%d", err, source.pass.closeCalls)
		}
	})
	t.Run("open error without pass", func(t *testing.T) {
		source := ownerSealMediaTestSourceForFixture(t, fixture)
		source.openError = openFailure
		_, err := LoadCommittingOwnerSealRecoveryPlanFromMedia(
			context.Background(), fixture.committing, 29, source)
		if !errors.Is(err, openFailure) || !errors.Is(err, ErrOwnerSealContentSource) ||
			source.pass.closeCalls != 0 {
			t.Fatalf("open error/close calls = %v/%d", err, source.pass.closeCalls)
		}
	})
	t.Run("open error with partial pass", func(t *testing.T) {
		source := ownerSealMediaTestSourceForFixture(t, fixture)
		source.openError = openFailure
		source.returnPassOnError = true
		source.pass.closeError = closeFailure
		_, err := LoadCommittingOwnerSealRecoveryPlanFromMedia(
			context.Background(), fixture.committing, 29, source)
		var readError *OwnerSealMediaReadError
		if !errors.As(err, &readError) || !errors.Is(err, openFailure) ||
			!errors.Is(err, closeFailure) || readError.CloseError() != closeFailure ||
			source.pass.closeCalls != 1 {
			t.Fatalf("partial-open error/close calls = %v/%d", err, source.pass.closeCalls)
		}
	})
	t.Run("typed nil source", func(t *testing.T) {
		var source *ownerSealMediaTestSource
		_, err := LoadCommittingOwnerSealRecoveryPlanFromMedia(
			context.Background(), fixture.committing, 29, source)
		if !errors.Is(err, ErrOwnerSealContentSource) {
			t.Fatalf("typed-nil source error = %v", err)
		}
	})
	t.Run("typed nil pass", func(t *testing.T) {
		source := ownerSealMediaTestSourceForFixture(t, fixture)
		source.returnTypedNil = true
		_, err := LoadCommittingOwnerSealRecoveryPlanFromMedia(
			context.Background(), fixture.committing, 29, source)
		if !errors.Is(err, ErrOwnerSealContentSource) {
			t.Fatalf("typed-nil pass error = %v", err)
		}
	})
}

func TestOwnerSealMediaInvalidBytesAreNotOperationalSourceFailures(t *testing.T) {
	tests := []struct {
		name   string
		kind   cxlcheckpoint.ContentKindV7
		offset uint64
	}{
		{name: "publication header", kind: cxlcheckpoint.ContentPublicationV7, offset: 0},
		{name: "publication payload", kind: cxlcheckpoint.ContentPublicationV7,
			offset: cxlcheckpoint.PublicationV7EnvelopeHeaderBytes},
		{name: "slot A header", kind: cxlcheckpoint.ContentPlacementSlotAV7, offset: 0},
		{name: "slot A payload", kind: cxlcheckpoint.ContentPlacementSlotAV7,
			offset: cxlcheckpoint.ContentMappingEnvelopeHeaderBytes},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newOwnerSealRecoveryTestFixture(t)
			source := ownerSealMediaTestSourceForFixture(t, fixture)
			ownerSealMediaTestFlipObjectByte(t, source, fixture.freshPlan, test.kind, test.offset)
			_, err := LoadCommittingOwnerSealRecoveryPlanFromMedia(
				context.Background(), fixture.committing, 29, source)
			if !errors.Is(err, ErrInvalidOwnerSealMedia) ||
				errors.Is(err, ErrOwnerSealContentSource) {
				t.Fatalf("invalid-media classification = %v", err)
			}
			if source.pass.closeCalls != 1 {
				t.Fatalf("close calls = %d, want 1", source.pass.closeCalls)
			}
		})
	}
}

func TestOwnerSealMediaHeaderDiscoveryIsCapacityBoundAndStable(t *testing.T) {
	fixture := newOwnerSealRecoveryTestFixture(t)
	source := ownerSealMediaTestSourceForFixture(t, fixture)
	mediaPlan, err := buildOwnerSealRecordMediaPlan(fixture.committing, 29)
	if err != nil {
		t.Fatalf("build compact media plan: %v", err)
	}
	prepared, err := prepareOwnerSealMediaRuns(context.Background(), source.pass, mediaPlan)
	if err != nil {
		t.Fatalf("prepare direct views: %v", err)
	}
	publication := mediaPlan.objects[ownerSealMediaPublicationObject]
	_, err = readOwnerSealMediaEnvelope(
		context.Background(), publication, prepared, "test publication",
		cxlcheckpoint.PublicationV7EnvelopeHeaderBytes,
		func(_ []byte, capacity uint64) (uint64, error) { return capacity + 1, nil })
	if !errors.Is(err, ErrInvalidOwnerSealMedia) || errors.Is(err, ErrOwnerSealContentSource) {
		t.Fatalf("over-capacity discovery error = %v", err)
	}
	_, err = readOwnerSealMediaEnvelope(
		context.Background(), publication, prepared, "test publication",
		cxlcheckpoint.PublicationV7EnvelopeHeaderBytes,
		func(_ []byte, _ uint64) (uint64, error) {
			prepared[0].bytes[0] ^= 0xff
			return uint64(len(fixture.publicationBytes)), nil
		})
	if !errors.Is(err, ErrOwnerSealContentSource) || errors.Is(err, ErrInvalidOwnerSealMedia) {
		t.Fatalf("changed-header discovery error = %v", err)
	}
}

func TestOwnerSealMediaInvalidOwnerFailsBeforeSourceOpen(t *testing.T) {
	fixture := newOwnerSealRecoveryTestFixture(t)
	tests := []struct {
		name       string
		owner      OwnerStateSnapshot
		allocation uint64
	}{
		{name: "absent record", owner: fixture.committing, allocation: 30},
		{name: "zero record", owner: fixture.committing, allocation: 0},
		{name: "invalid Owner snapshot", owner: func() OwnerStateSnapshot {
			owner := fixture.committing.Clone()
			owner.records[0].ContentDemands[0].CapacityPages = 0
			return owner
		}(), allocation: 29},
		{name: "publication capacity exceeds media bound", owner: func() OwnerStateSnapshot {
			owner := fixture.committing.Clone()
			devices := owner.Devices()
			record := owner.Records()[0]
			publicationIndex := len(record.ContentDemands) - 1
			oldPages := record.ContentDemands[publicationIndex].CapacityPages
			newPages := uint64(cxlcheckpoint.MaxPublicationV7SlotPages) + 1
			delta := newPages - oldPages
			record.ContentDemands[publicationIndex].CapacityPages = newPages
			record.TotalDemandPages += delta
			for fragmentIndex := range record.Fragments {
				fragment := &record.Fragments[fragmentIndex]
				for extentIndex := range fragment.Extents {
					extent := &fragment.Extents[extentIndex]
					if extent.LogicalPageStart == record.ContentDemands[publicationIndex].LogicalPageStart {
						extent.PageCount = newPages
						for deviceIndex := range devices {
							if devices[deviceIndex].DeviceUUID == fragment.DeviceUUID {
								devices[deviceIndex].DataPageCount = extent.StartDataPageIndex + newPages
							}
						}
					}
				}
			}
			return ownerSealRecoveryTestRebuildOwner(
				t, owner, devices, []OwnerStateAllocationRecord{record},
				owner.SnapshotSequence, owner.NextAllocationRecordID,
				owner.NextOwnerTransactionSequence)
		}(), allocation: 29},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			source := ownerSealMediaTestSourceForFixture(t, fixture)
			_, err := LoadCommittingOwnerSealRecoveryPlanFromMedia(
				context.Background(), test.owner, test.allocation, source)
			if !errors.Is(err, ErrInvalidOwnerSealMedia) ||
				errors.Is(err, ErrOwnerSealContentSource) || source.openCalls != 0 {
				t.Fatalf("invalid Owner error/open calls = %v/%d", err, source.openCalls)
			}
		})
	}
}

func ownerSealMediaTestSourceForFixture(
	t *testing.T,
	fixture ownerSealRecoveryTestFixture,
) *ownerSealMediaTestSource {
	t.Helper()
	pages := ownerSealTranscriptTestPages(t, fixture.producer, fixture.freshPlan)
	bindings := fixture.freshPlan.Devices()
	expected := make(map[string]ProducerScatterDeviceBinding, len(bindings))
	deviceBytes := make(map[string][]byte, len(bindings))
	backingIDs := make(map[string][sha256.Size]byte, len(bindings))
	for _, binding := range bindings {
		expected[binding.DeviceUUID] = binding
		deviceBytes[binding.DeviceUUID] = make(
			[]byte, int(binding.DataPageCount)*ContentPageBytes)
		backingIDs[binding.DeviceUUID] = sha256.Sum256(
			[]byte("Owner-seal-media-" + binding.DeviceUUID))
	}
	for _, run := range fixture.freshPlan.ExtentRuns() {
		if int(run.DeviceIndex) >= len(bindings) {
			t.Fatalf("run device index %d exceeds %d bindings", run.DeviceIndex, len(bindings))
		}
		binding := bindings[run.DeviceIndex]
		for page := uint64(0); page < run.PageCount; page++ {
			logical := run.LogicalPageStart + page
			physical := run.StartDataPageIndex + page
			start := int(physical) * ContentPageBytes
			copy(deviceBytes[binding.DeviceUUID][start:start+ContentPageBytes], pages[logical])
		}
	}
	source := &ownerSealMediaTestSource{
		expectedBindings: expected,
		deviceBytes:      deviceBytes,
		backingIDs:       backingIDs,
		backingOrigin:    uint64(ContentPageBytes),
	}
	source.pass = &ownerSealMediaTestPass{source: source}
	return source
}

func ownerSealMediaTestDeviceUUIDs(bindings []ProducerScatterDeviceBinding) []string {
	result := make([]string, len(bindings))
	for index := range bindings {
		result[index] = bindings[index].DeviceUUID
	}
	return result
}

func ownerSealMediaTestFlipObjectByte(
	t *testing.T,
	source *ownerSealMediaTestSource,
	plan OwnerSealPlan,
	kind cxlcheckpoint.ContentKindV7,
	objectByteOffset uint64,
) {
	t.Helper()
	var object OwnerSealObject
	found := false
	for _, candidate := range plan.Objects() {
		if candidate.Kind == kind {
			object = candidate
			found = true
			break
		}
	}
	if !found || objectByteOffset >= object.CapacityPages*uint64(ContentPageBytes) {
		t.Fatalf("object kind %d byte %d is unavailable", kind, objectByteOffset)
	}
	logical := object.LogicalPageStart + objectByteOffset/uint64(ContentPageBytes)
	pageOffset := objectByteOffset % uint64(ContentPageBytes)
	bindings := plan.Devices()
	for _, run := range plan.ExtentRuns() {
		if logical < run.LogicalPageStart || logical >= run.LogicalPageStart+run.PageCount {
			continue
		}
		binding := bindings[run.DeviceIndex]
		physical := run.StartDataPageIndex + logical - run.LogicalPageStart
		byteOffset := physical*uint64(ContentPageBytes) + pageOffset
		source.deviceBytes[binding.DeviceUUID][int(byteOffset)] ^= 0xff
		return
	}
	t.Fatalf("logical object page %d has no physical extent", logical)
}

func ownerSealMediaTestUnallocatedAnchorFixture(t *testing.T) ownerSealRecoveryTestFixture {
	t.Helper()
	producer := newProducerScatterTestFixture(t)
	devices := append(producer.owner.Devices(), OwnerStateDevice{
		DeviceUUID:          "device-c",
		DeviceOwnerEpoch:    producer.owner.OwnerEpoch,
		DataPageCount:       128,
		DeviceBindingSHA256: sha256.Sum256([]byte("binding-device-c")),
	})
	membership, err := OwnerGroupMembershipSHA256(devices)
	if err != nil {
		t.Fatalf("three-device membership: %v", err)
	}
	owner, err := NewOwnerStateSnapshot(OwnerStateConfig{
		ClusterID:                    producer.owner.ClusterID,
		OwnerGroupID:                 producer.owner.OwnerGroupID,
		CurrentOwnerID:               producer.owner.CurrentOwnerID,
		AnchorDeviceUUID:             "device-c",
		StorageCompatibilityID:       producer.owner.StorageCompatibilityID,
		OwnerEpoch:                   producer.owner.OwnerEpoch,
		GroupConfigurationSequence:   producer.owner.GroupConfigurationSequence,
		MembershipSHA256:             membership,
		SnapshotSequence:             producer.owner.SnapshotSequence,
		NextAllocationRecordID:       producer.owner.NextAllocationRecordID,
		NextOwnerTransactionSequence: producer.owner.NextOwnerTransactionSequence,
		Devices:                      devices,
		Records:                      producer.owner.Records(),
	})
	if err != nil {
		t.Fatalf("Owner with unallocated anchor: %v", err)
	}
	producer.owner = owner
	producer.plan, err = BuildProducerScatterPlan(owner, 29, producer.initial)
	if err != nil {
		t.Fatalf("Producer plan with unallocated anchor: %v", err)
	}
	freshPlan := ownerSealPlanTestBuild(t, producer)
	pages := ownerSealTranscriptTestPages(t, producer, freshPlan)
	freshSeal := ownerSealTranscriptTestComplete(t, freshPlan, pages, nil)
	transitions, err := PlanFreshOwnerSealStateTransitions(owner, freshPlan, freshSeal)
	if err != nil {
		t.Fatalf("fresh transitions with unallocated anchor: %v", err)
	}
	publicationBytes := ownerSealRecoveryTestPublicationBytes(
		t, producer.initial.Publication)
	publicationObjects, err := producer.initial.Publication.MappingContentObjects()
	if err != nil {
		t.Fatalf("mapping objects with unallocated anchor: %v", err)
	}
	initialMapBytes := ownerSealRecoveryTestMappingBytes(
		t, producer.initial.InitialContentPlacementMap, publicationObjects)
	return ownerSealRecoveryTestFixture{
		producer: producer, freshPlan: freshPlan, freshSeal: freshSeal,
		committing: transitions.Committing(), committed: transitions.Committed(),
		publicationBytes: publicationBytes, initialMapBytes: initialMapBytes,
		initialMapping: producer.initial.InitialContentPlacementMap,
		publication:    producer.initial.Publication, publicationObject: publicationObjects,
	}
}

func ownerSealMediaTestLargeFragmentedFixture(t *testing.T) ownerSealRecoveryTestFixture {
	t.Helper()
	const restorePages = uint64(100)
	initialBase := producerScatterTestInitialPlan(t)
	publication := ownerSealRecoveryTestClonePublication(initialBase.Publication)
	publication.InitialAllocation.TotalPages = 116
	publication.InitialAllocation.Devices = []cxlcheckpoint.AllocationDeviceV7{
		{DeviceUUID: "device-a", DataPageCount: 1000},
		{DeviceUUID: "device-b", DataPageCount: 1000},
	}
	publication.InitialAllocation.Extents = make(
		[]cxlcheckpoint.AllocationExtentV7, publication.InitialAllocation.TotalPages)
	for index := range publication.InitialAllocation.Extents {
		publication.InitialAllocation.Extents[index] = cxlcheckpoint.AllocationExtentV7{
			DeviceIndex:        uint32(index % 2),
			StartDataPageIndex: 100 + uint64(index/2),
			PageCount:          1,
			LogicalPageStart:   uint64(index),
		}
	}
	publication.Objects[2].ImmutableByteLength = restorePages * uint64(ContentPageBytes)
	publication.Objects[2].CapacityPages = restorePages
	logicalStarts := []uint64{0, 3, 5, 105, 106, 107, 108, 110, 112}
	for index := range publication.Objects {
		publication.Objects[index].LogicalPageStart = logicalStarts[index]
	}
	mappingObjects := []cxlcheckpoint.ContentObject{
		{ObjectID: 1, Kind: cxlcheckpoint.ContentMemory,
			ByteLength: 3 * uint64(ContentPageBytes), LogicalPageStart: 0, PageCount: 3},
		{ObjectID: 2, Kind: cxlcheckpoint.ContentArtifact,
			ByteLength: 5000, LogicalPageStart: 3, PageCount: 2},
		{ObjectID: 3, Kind: cxlcheckpoint.ContentRestoreBlob,
			ByteLength:       restorePages * uint64(ContentPageBytes),
			LogicalPageStart: 5, PageCount: restorePages},
	}
	templateBytes, err := cxlcheckpoint.CanonicalMMTemplateV7Bytes(initialBase.MMTemplate)
	if err != nil {
		t.Fatalf("large fixture MMTemplate bytes: %v", err)
	}
	virtualBytes, err := cxlcheckpoint.CanonicalVirtualPageMapBytes(
		initialBase.VirtualPageMap, mappingObjects)
	if err != nil {
		t.Fatalf("large fixture virtual map bytes: %v", err)
	}
	manifestBytes, err := cxlcheckpoint.CanonicalArtifactManifestV7Bytes(
		initialBase.ArtifactManifest)
	if err != nil {
		t.Fatalf("large fixture artifact manifest bytes: %v", err)
	}
	publication.MMTemplate.SHA256 = sha256.Sum256(templateBytes)
	publication.VirtualPageMap.SHA256 = sha256.Sum256(virtualBytes)
	publication.ArtifactManifest.SHA256 = sha256.Sum256(manifestBytes)
	publication.Objects[3].ImmutableByteLength = uint64(len(templateBytes))
	publication.Objects[4].ImmutableByteLength = uint64(len(virtualBytes))
	publication.Objects[5].ImmutableByteLength = uint64(len(manifestBytes))
	initial, err := cxlcheckpoint.BuildInitialPublicationV7Plan(
		cxlcheckpoint.InitialPublicationV7Input{
			Publication:                  publication,
			MMTemplate:                   initialBase.MMTemplate,
			VirtualPageMap:               initialBase.VirtualPageMap,
			ArtifactManifest:             initialBase.ArtifactManifest,
			InitialContentPlacementMapID: "large-initial-placement-v7",
			InitialActivePlacementRootID: "large-active-root-v7",
		})
	if err != nil {
		t.Fatalf("large initial publication plan: %v", err)
	}
	devices := []OwnerStateDevice{
		{DeviceUUID: "device-a", DeviceOwnerEpoch: 11, DataPageCount: 1000,
			DeviceBindingSHA256: sha256.Sum256([]byte("binding-device-a"))},
		{DeviceUUID: "device-b", DeviceOwnerEpoch: 11, DataPageCount: 1000,
			DeviceBindingSHA256: sha256.Sum256([]byte("binding-device-b"))},
	}
	membership, err := OwnerGroupMembershipSHA256(devices)
	if err != nil {
		t.Fatalf("large fixture membership: %v", err)
	}
	demands := make([]OwnerStateContentDemand, len(publication.Objects))
	for index, object := range publication.Objects {
		demands[index] = OwnerStateContentDemand{
			Kind: object.Kind, ObjectID: object.ObjectID,
			ByteLength: object.ImmutableByteLength, CapacityPages: object.CapacityPages,
			LogicalPageStart: object.LogicalPageStart,
		}
	}
	fragments := []OwnerStateDeviceFragment{
		{DeviceUUID: "device-a", DeviceOwnerEpoch: 11, TargetAllocatorSnapshotSequence: 7},
		{DeviceUUID: "device-b", DeviceOwnerEpoch: 11, TargetAllocatorSnapshotSequence: 9},
	}
	for logical := uint64(0); logical < publication.InitialAllocation.TotalPages; logical++ {
		deviceIndex := int(logical % 2)
		fragments[deviceIndex].Extents = append(fragments[deviceIndex].Extents,
			OwnerStateExtent{
				StartDataPageIndex: 100 + logical/2,
				LogicalPageStart:   logical,
				PageCount:          1,
			})
	}
	record := OwnerStateAllocationRecord{
		AllocationRecordID: 29, ReservationTransactionSequence: 101,
		OwnerTransactionSequence: 102, State: OwnerAllocationGranted,
		RequestID: "request-7", CheckpointID: "checkpoint-7", ProducerID: "producer-7",
		DedupDomainID: "dedup-domain-7", SharingPolicyID: "same-tenant-verified-content-v1",
		RequestSHA256:    sha256.Sum256([]byte("request-7")),
		TotalDemandPages: publication.InitialAllocation.TotalPages,
		MaxExtents:       MaxOwnerStateExtents,
		ContentDemands:   demands,
		Fragments:        fragments,
		AuthorityEvidence: OwnerStateAuthorityEvidence{
			SchedulerReserveSHA256:     sha256.Sum256([]byte("scheduler-reserve")),
			ProducerCapabilitySHA256:   sha256.Sum256([]byte("producer-capability")),
			PublicationAuthoritySHA256: sha256.Sum256([]byte("publication-authority")),
			ReclaimAuthoritySHA256:     sha256.Sum256([]byte("reclaim-authority")),
		},
	}
	owner, err := NewOwnerStateSnapshot(OwnerStateConfig{
		ClusterID: "cluster-7", OwnerGroupID: "owner-group-7", CurrentOwnerID: "owner-a",
		AnchorDeviceUUID: "device-a", StorageCompatibilityID: cxlcheckpoint.V7StorageCompatibilityID,
		OwnerEpoch: 11, GroupConfigurationSequence: 1, MembershipSHA256: membership,
		SnapshotSequence: 8, NextAllocationRecordID: 30, NextOwnerTransactionSequence: 103,
		Devices: devices, Records: []OwnerStateAllocationRecord{record},
	})
	if err != nil {
		t.Fatalf("large GRANTED Owner: %v", err)
	}
	producerPlan, err := BuildProducerScatterPlan(owner, 29, initial)
	if err != nil {
		t.Fatalf("large Producer plan: %v", err)
	}
	producer := producerScatterTestFixture{
		owner: owner, initial: initial, plan: producerPlan,
		memory:      producerScatterTestBytes(3*ContentPageBytes, 0x11),
		artifact:    producerScatterTestBytes(5000, 0x47),
		restoreBlob: producerScatterTestBytes(int(restorePages)*ContentPageBytes, 0x83),
	}
	freshPlan := ownerSealPlanTestBuild(t, producer)
	pages := ownerSealTranscriptTestPages(t, producer, freshPlan)
	freshSeal := ownerSealTranscriptTestComplete(t, freshPlan, pages, nil)
	transitions, err := PlanFreshOwnerSealStateTransitions(owner, freshPlan, freshSeal)
	if err != nil {
		t.Fatalf("large fresh transitions: %v", err)
	}
	publicationBytes := ownerSealRecoveryTestPublicationBytes(t, publication)
	publicationObjects, err := publication.MappingContentObjects()
	if err != nil {
		t.Fatalf("large mapping objects: %v", err)
	}
	initialMapBytes := ownerSealRecoveryTestMappingBytes(
		t, initial.InitialContentPlacementMap, publicationObjects)
	return ownerSealRecoveryTestFixture{
		producer: producer, freshPlan: freshPlan, freshSeal: freshSeal,
		committing: transitions.Committing(), committed: transitions.Committed(),
		publicationBytes: publicationBytes, initialMapBytes: initialMapBytes,
		initialMapping: initial.InitialContentPlacementMap, publication: publication,
		publicationObject: publicationObjects,
	}
}

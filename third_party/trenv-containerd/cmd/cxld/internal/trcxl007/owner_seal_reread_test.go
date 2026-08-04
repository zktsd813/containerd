package trcxl007

import (
	"context"
	"crypto/sha256"
	"errors"
	"hash/crc32"
	"reflect"
	"strings"
	"testing"

	"github.com/containerd/containerd/third_party/trenv-containerd/cmd/cxld/internal/trcxl007dml"
)

type ownerSealRereadTestEventLog struct {
	values []string
}

func (log *ownerSealRereadTestEventLog) add(value string) {
	log.values = append(log.values, value)
}

type ownerSealRereadTestRequest struct {
	binding            ProducerScatterDeviceBinding
	startDataPageIndex uint64
	pageCount          uint64
}

type ownerSealRereadTestSource struct {
	log         *ownerSealRereadTestEventLog
	pass        *ownerSealRereadTestPass
	openErr     error
	openCalls   int
	openDevices []ProducerScatterDeviceBinding
	passOnError bool
}

func (source *ownerSealRereadTestSource) OpenReadPass(
	_ context.Context,
	devices []ProducerScatterDeviceBinding,
) (OwnerSealContentReadPass, error) {
	source.openCalls++
	source.openDevices = append([]ProducerScatterDeviceBinding(nil), devices...)
	source.log.add("open")
	if source.openErr != nil {
		if source.passOnError {
			return source.pass, source.openErr
		}
		return nil, source.openErr
	}
	return source.pass, nil
}

type ownerSealRereadTestPass struct {
	log               *ownerSealRereadTestEventLog
	views             map[ownerSealRereadTestRequest]OwnerSealReadableExtent
	requests          []ownerSealRereadTestRequest
	viewFailureCall   int
	viewErr           error
	cancelViewCall    int
	cancel            context.CancelFunc
	closeErr          error
	closeCalls        int
	readableViewCalls int
}

func (pass *ownerSealRereadTestPass) ReadableExtent(
	binding ProducerScatterDeviceBinding,
	startDataPageIndex uint64,
	pageCount uint64,
) (OwnerSealReadableExtent, error) {
	pass.readableViewCalls++
	request := ownerSealRereadTestRequest{
		binding: binding, startDataPageIndex: startDataPageIndex, pageCount: pageCount,
	}
	pass.requests = append(pass.requests, request)
	pass.log.add("view")
	if pass.cancelViewCall > 0 && pass.readableViewCalls == pass.cancelViewCall && pass.cancel != nil {
		pass.cancel()
	}
	if pass.viewFailureCall > 0 && pass.readableViewCalls == pass.viewFailureCall {
		return OwnerSealReadableExtent{}, pass.viewErr
	}
	view, found := pass.views[request]
	if !found {
		return OwnerSealReadableExtent{}, errors.New("unexpected readable extent request")
	}
	return view, nil
}

func (pass *ownerSealRereadTestPass) Close() error {
	pass.closeCalls++
	pass.log.add("close")
	return pass.closeErr
}

type ownerSealRereadTestCopier struct {
	log        *ownerSealRereadTestEventLog
	failCall   int
	failErr    error
	cancelCall int
	cancel     context.CancelFunc
	calls      int
	closeCalls int
}

func (copier *ownerSealRereadTestCopier) CopyPage(dst, src []byte) (uint32, error) {
	copier.calls++
	copier.log.add("dml")
	if copier.failCall > 0 && copier.calls == copier.failCall {
		return 0, copier.failErr
	}
	if len(dst) != trcxl007dml.PageSize || len(src) != trcxl007dml.PageSize {
		return 0, trcxl007dml.ErrInvalidPage
	}
	copy(dst, src)
	checksum := crc32.Checksum(dst, crc32.MakeTable(crc32.Castagnoli))
	if copier.cancelCall > 0 && copier.calls == copier.cancelCall && copier.cancel != nil {
		copier.cancel()
	}
	return checksum, nil
}

func (copier *ownerSealRereadTestCopier) Close() error {
	copier.closeCalls++
	return errors.New("test copier must not be closed by reread pass")
}

type ownerSealRereadTestFixture struct {
	producer producerScatterTestFixture
	plan     OwnerSealPlan
	pages    [][]byte
	wantSeal OwnerVerifiedSeal
	log      *ownerSealRereadTestEventLog
	requests []ownerSealRereadTestRequest
	pass     *ownerSealRereadTestPass
	source   *ownerSealRereadTestSource
	copier   *ownerSealRereadTestCopier
}

func TestOwnerSealRereadPassFragmentedTwoDAXCanonicalOrderKnownSeal(t *testing.T) {
	fixture := newOwnerSealRereadTestFixture(t)
	verifications := make([]OwnerSealPageVerification, 0, fixture.plan.TotalPages())
	sink := func(verification OwnerSealPageVerification) error {
		fixture.log.add("sink")
		verifications = append(verifications, verification)
		return nil
	}

	seal, err := runOwnerSealRereadTranscriptPass(
		context.Background(), fixture.plan, fixture.source, fixture.copier, sink)
	if err != nil {
		t.Fatalf("runOwnerSealRereadTranscriptPass: %v", err)
	}
	if seal != fixture.wantSeal {
		t.Fatalf("reread seal = %#v, want %#v", seal, fixture.wantSeal)
	}
	const knownSHA256 = "609da5bc6a04366dd5fa2c1dd7969ca1cb90c8011b52621801bcf6937ac8f018"
	if got := ownerSealTranscriptTestHex(seal.SHA256()); got != knownSHA256 {
		t.Fatalf("reread known seal = %s, want %s", got, knownSHA256)
	}
	if fixture.source.openCalls != 1 ||
		!reflect.DeepEqual(fixture.source.openDevices, fixture.plan.Devices()) ||
		!reflect.DeepEqual(fixture.pass.requests, fixture.requests) {
		t.Fatalf("open/devices/requests = %d/%#v/%#v, want 1/%#v/%#v",
			fixture.source.openCalls, fixture.source.openDevices, fixture.pass.requests,
			fixture.plan.Devices(), fixture.requests)
	}
	if fixture.pass.closeCalls != 1 || fixture.copier.closeCalls != 0 ||
		fixture.copier.calls != int(fixture.plan.TotalPages()) ||
		len(verifications) != int(fixture.plan.TotalPages()) {
		t.Fatalf("close/copier/calls/verifications = %d/%d/%d/%d",
			fixture.pass.closeCalls, fixture.copier.closeCalls,
			fixture.copier.calls, len(verifications))
	}
	wantTargets := ownerSealTranscriptTestTargets(t, fixture.plan)
	for logical := range verifications {
		if verifications[logical].Target() != wantTargets[logical] ||
			verifications[logical].Target().LogicalPage() != uint64(logical) {
			t.Fatalf("verification %d target = %#v, want %#v",
				logical, verifications[logical].Target(), wantTargets[logical])
		}
	}
	firstDML := ownerSealRereadTestFirstEvent(fixture.log.values, "dml")
	if firstDML != 1+len(fixture.requests) {
		t.Fatalf("first DML event index = %d, want %d; events=%#v",
			firstDML, 1+len(fixture.requests), fixture.log.values)
	}
	if ownerSealRereadTestFirstEvent(fixture.log.values, "sink") <= firstDML {
		t.Fatalf("sink ran before successful first DML: %#v", fixture.log.values)
	}
	if fixture.log.values[len(fixture.log.values)-1] != "close" {
		t.Fatalf("last event = %q, want close", fixture.log.values[len(fixture.log.values)-1])
	}
}

func TestOwnerSealRereadPassPreflightsEveryViewBeforeDMLOrSink(t *testing.T) {
	fixture := newOwnerSealRereadTestFixture(t)
	viewErr := errors.New("injected final view failure")
	fixture.pass.viewFailureCall = len(fixture.requests)
	fixture.pass.viewErr = viewErr
	sinkCalls := 0
	seal, err := runOwnerSealRereadTranscriptPass(
		context.Background(), fixture.plan, fixture.source, fixture.copier,
		func(OwnerSealPageVerification) error {
			sinkCalls++
			return nil
		})
	failure := ownerSealRereadTestRequireFailure(
		t, err, ownerSealRereadViewOperation)
	if seal != (OwnerVerifiedSeal{}) || !errors.Is(err, viewErr) ||
		failure.location.runIndex != len(fixture.requests)-1 ||
		fixture.pass.readableViewCalls != len(fixture.requests) ||
		fixture.copier.calls != 0 || sinkCalls != 0 || fixture.pass.closeCalls != 1 ||
		fixture.copier.closeCalls != 0 {
		t.Fatalf("preflight failure = seal %#v error %#v views %d DML %d sink %d close %d copier-close %d",
			seal, failure, fixture.pass.readableViewCalls, fixture.copier.calls,
			sinkCalls, fixture.pass.closeCalls, fixture.copier.closeCalls)
	}
	if !reflect.DeepEqual(fixture.pass.requests, fixture.requests) {
		t.Fatalf("preflight requested unrelated or reordered range: %#v want %#v",
			fixture.pass.requests, fixture.requests)
	}
}

func TestOwnerSealRereadPassRejectsViewShapeBackingAndAliasesBeforeDML(t *testing.T) {
	tests := []struct {
		name        string
		wantMessage string
		mutate      func(*ownerSealRereadTestFixture)
	}{
		{
			name: "binding",
			mutate: func(fixture *ownerSealRereadTestFixture) {
				request := fixture.requests[0]
				view := fixture.pass.views[request]
				view.Binding.DeviceUUID = "substituted-device"
				fixture.pass.views[request] = view
			},
		},
		{
			name: "start",
			mutate: func(fixture *ownerSealRereadTestFixture) {
				request := fixture.requests[0]
				view := fixture.pass.views[request]
				view.StartDataPageIndex++
				fixture.pass.views[request] = view
			},
		},
		{
			name: "page-count",
			mutate: func(fixture *ownerSealRereadTestFixture) {
				request := fixture.requests[0]
				view := fixture.pass.views[request]
				view.PageCount++
				fixture.pass.views[request] = view
			},
		},
		{
			name: "short-bytes",
			mutate: func(fixture *ownerSealRereadTestFixture) {
				request := fixture.requests[0]
				view := fixture.pass.views[request]
				view.Bytes = view.Bytes[:len(view.Bytes)-1]
				fixture.pass.views[request] = view
			},
		},
		{
			name: "long-bytes",
			mutate: func(fixture *ownerSealRereadTestFixture) {
				request := fixture.requests[0]
				view := fixture.pass.views[request]
				view.Bytes = append(view.Bytes, 0)
				fixture.pass.views[request] = view
			},
		},
		{
			name: "zero-backing-ID",
			mutate: func(fixture *ownerSealRereadTestFixture) {
				request := fixture.requests[0]
				view := fixture.pass.views[request]
				view.Backing.BackingID = [sha256.Size]byte{}
				fixture.pass.views[request] = view
			},
		},
		{
			name: "backing-length",
			mutate: func(fixture *ownerSealRereadTestFixture) {
				request := fixture.requests[0]
				view := fixture.pass.views[request]
				view.Backing.ByteLength--
				fixture.pass.views[request] = view
			},
		},
		{
			name: "backing-overflow",
			mutate: func(fixture *ownerSealRereadTestFixture) {
				request := fixture.requests[0]
				view := fixture.pass.views[request]
				view.Backing.ByteOffset = ^uint64(0) - view.Backing.ByteLength + 1
				fixture.pass.views[request] = view
			},
		},
		{
			name:        "backing-origin-underflow",
			wantMessage: "cannot represent its data-page index",
			mutate: func(fixture *ownerSealRereadTestFixture) {
				request := fixture.requests[0]
				view := fixture.pass.views[request]
				view.Backing.ByteOffset = 0
				fixture.pass.views[request] = view
			},
		},
		{
			name:        "backing-origin-page-offset-overflow",
			wantMessage: "cannot represent its data-page index",
			mutate: func(fixture *ownerSealRereadTestFixture) {
				oldRequest := fixture.requests[0]
				view := fixture.pass.views[oldRequest]
				delete(fixture.pass.views, oldRequest)

				overflowPage := ^uint64(0)/uint64(ContentPageBytes) + 1
				fixture.plan.runs[0].StartDataPageIndex = overflowPage
				fixture.plan.devices[0].DataPageCount = overflowPage + oldRequest.pageCount
				fixture.plan.integritySHA256 = ownerSealPlanSHA256(fixture.plan)
				binding := fixture.plan.devices[0]
				request := ownerSealRereadTestRequest{
					binding: binding, startDataPageIndex: overflowPage,
					pageCount: oldRequest.pageCount,
				}
				view.Binding = binding
				view.StartDataPageIndex = overflowPage
				view.Backing.ByteOffset = 0
				fixture.pass.views[request] = view
			},
		},
		{
			name:        "same-device-changed-backing-ID",
			wantMessage: "same-device readable extents have different backing origins",
			mutate: func(fixture *ownerSealRereadTestFixture) {
				request := fixture.requests[2]
				view := fixture.pass.views[request]
				view.Backing.BackingID = sha256.Sum256([]byte("substituted-backing"))
				fixture.pass.views[request] = view
			},
		},
		{
			name:        "same-device-shifted-backing-origin",
			wantMessage: "same-device readable extents have different backing origins",
			mutate: func(fixture *ownerSealRereadTestFixture) {
				request := fixture.requests[2]
				view := fixture.pass.views[request]
				view.Backing.ByteOffset += uint64(ContentPageBytes)
				fixture.pass.views[request] = view
			},
		},
		{
			name:        "different-device-shared-backing-ID",
			wantMessage: "different devices share one physical backing ID",
			mutate: func(fixture *ownerSealRereadTestFixture) {
				firstRequest, secondRequest := fixture.requests[0], fixture.requests[1]
				first := fixture.pass.views[firstRequest]
				second := fixture.pass.views[secondRequest]
				second.Backing.BackingID = first.Backing.BackingID
				fixture.pass.views[secondRequest] = second
			},
		},
		{
			name:        "physical-alias",
			wantMessage: "alias",
			mutate: func(fixture *ownerSealRereadTestFixture) {
				firstRequest, secondRequest := fixture.requests[0], fixture.requests[1]
				first := fixture.pass.views[firstRequest]
				second := fixture.pass.views[secondRequest]
				second.Backing.BackingID = first.Backing.BackingID
				second.Backing.ByteOffset = first.Backing.ByteOffset
				fixture.pass.views[secondRequest] = second
			},
		},
		{
			name:        "virtual-alias",
			wantMessage: "alias",
			mutate: func(fixture *ownerSealRereadTestFixture) {
				firstRequest, secondRequest := fixture.requests[0], fixture.requests[1]
				first := fixture.pass.views[firstRequest]
				second := fixture.pass.views[secondRequest]
				length := len(first.Bytes)
				if 1+len(second.Bytes) > length {
					length = 1 + len(second.Bytes)
				}
				alias := make([]byte, length)
				first.Bytes = alias[:len(first.Bytes)]
				second.Bytes = alias[1 : 1+len(second.Bytes)]
				fixture.pass.views[firstRequest] = first
				fixture.pass.views[secondRequest] = second
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newOwnerSealRereadTestFixture(t)
			test.mutate(&fixture)
			seal, err := runOwnerSealRereadTranscriptPass(
				context.Background(), fixture.plan, fixture.source, fixture.copier, nil)
			ownerSealRereadTestRequireFailure(t, err, ownerSealRereadViewOperation)
			if test.wantMessage != "" && !strings.Contains(err.Error(), test.wantMessage) {
				t.Fatalf("view rejection error = %v, want text %q", err, test.wantMessage)
			}
			if seal != (OwnerVerifiedSeal{}) || fixture.copier.calls != 0 ||
				fixture.pass.closeCalls != 1 || fixture.copier.closeCalls != 0 {
				t.Fatalf("view rejection = seal %#v DML %d close %d copier-close %d",
					seal, fixture.copier.calls, fixture.pass.closeCalls,
					fixture.copier.closeCalls)
			}
		})
	}
}

func TestOwnerSealPrepareReadableExtentRejectsOwnerScratchAlias(t *testing.T) {
	fixture := newOwnerSealRereadTestFixture(t)
	devices := fixture.plan.Devices()
	runs := fixture.plan.ExtentRuns()
	if len(devices) == 0 || len(runs) == 0 {
		t.Fatal("reread fixture has no device or extent run")
	}
	run := runs[0]
	run.PageCount = 1
	binding := devices[run.DeviceIndex]
	scratch := make([]byte, ContentPageBytes)
	scratchStart, scratchEnd, err := producerScatterSliceAddressRange(scratch)
	if err != nil {
		t.Fatalf("scratch address range: %v", err)
	}
	view := OwnerSealReadableExtent{
		Binding:            binding,
		StartDataPageIndex: run.StartDataPageIndex,
		PageCount:          run.PageCount,
		Bytes:              scratch,
		Backing: ProducerScatterBackingRange{
			BackingID:  sha256.Sum256([]byte("scratch-alias-backing")),
			ByteOffset: run.StartDataPageIndex * uint64(ContentPageBytes),
			ByteLength: uint64(ContentPageBytes),
		},
	}
	_, err = ownerSealPrepareReadableExtent(
		0,
		run,
		binding,
		view,
		scratchStart,
		scratchEnd,
		make([]ownerSealRereadBackingOrigin, len(devices)),
		make(map[[sha256.Size]byte]uint32),
		nil,
	)
	if err == nil || !strings.Contains(err.Error(), "aliases Owner scratch page") {
		t.Fatalf("scratch-alias rejection = %v", err)
	}
}

func TestOwnerSealRereadPassRejectsTypedNilDependencies(t *testing.T) {
	t.Run("source", func(t *testing.T) {
		fixture := newOwnerSealRereadTestFixture(t)
		var source *ownerSealRereadTestSource
		seal, err := runOwnerSealRereadTranscriptPass(
			context.Background(), fixture.plan, source, fixture.copier, nil)
		ownerSealRereadTestRequireFailure(t, err, ownerSealRereadOpenOperation)
		if seal != (OwnerVerifiedSeal{}) || fixture.pass.closeCalls != 0 ||
			fixture.copier.calls != 0 || fixture.copier.closeCalls != 0 {
			t.Fatalf("typed-nil source = seal %#v close %d DML %d copier-close %d",
				seal, fixture.pass.closeCalls, fixture.copier.calls,
				fixture.copier.closeCalls)
		}
	})

	t.Run("read-pass", func(t *testing.T) {
		fixture := newOwnerSealRereadTestFixture(t)
		fixture.source.pass = nil
		seal, err := runOwnerSealRereadTranscriptPass(
			context.Background(), fixture.plan, fixture.source, fixture.copier, nil)
		ownerSealRereadTestRequireFailure(t, err, ownerSealRereadOpenOperation)
		if seal != (OwnerVerifiedSeal{}) || fixture.source.openCalls != 1 ||
			fixture.pass.closeCalls != 0 || fixture.copier.calls != 0 ||
			fixture.copier.closeCalls != 0 {
			t.Fatalf("typed-nil pass = seal %#v open %d close %d DML %d copier-close %d",
				seal, fixture.source.openCalls, fixture.pass.closeCalls,
				fixture.copier.calls, fixture.copier.closeCalls)
		}
	})

	t.Run("copier", func(t *testing.T) {
		fixture := newOwnerSealRereadTestFixture(t)
		var copier *ownerSealRereadTestCopier
		seal, err := runOwnerSealRereadTranscriptPass(
			context.Background(), fixture.plan, fixture.source, copier, nil)
		ownerSealRereadTestRequireFailure(t, err, ownerSealRereadDMLOperation)
		if seal != (OwnerVerifiedSeal{}) || fixture.source.openCalls != 0 ||
			fixture.pass.closeCalls != 0 || fixture.copier.closeCalls != 0 {
			t.Fatalf("typed-nil copier = seal %#v open %d close %d copier-close %d",
				seal, fixture.source.openCalls, fixture.pass.closeCalls,
				fixture.copier.closeCalls)
		}
	})
}

func TestOwnerSealRereadPassClassifiesZeroPaddingAndTypedSHAFailures(t *testing.T) {
	tests := []struct {
		name      string
		predicate func(OwnerSealPageTarget) bool
	}{
		{
			name: "zero-padding",
			predicate: func(target OwnerSealPageTarget) bool {
				return target.TargetState() == DescriptorZeroPadding
			},
		},
		{
			name: "typed-control-SHA",
			predicate: func(target OwnerSealPageTarget) bool {
				return target.Object().ExactSHA256Required &&
					target.MeaningfulByteLength() > 0 &&
					target.Object().Kind != 0
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newOwnerSealRereadTestFixture(t)
			targets := ownerSealTranscriptTestTargets(t, fixture.plan)
			logical := ownerSealTranscriptTestFindTarget(t, targets, test.predicate)
			ownerSealRereadTestMutateLogicalPage(t, &fixture, logical, func(page []byte) {
				page[0] ^= 0x80
			})
			seal, err := runOwnerSealRereadTranscriptPass(
				context.Background(), fixture.plan, fixture.source, fixture.copier, nil)
			failure := ownerSealRereadTestRequireFailure(
				t, err, ownerSealRereadTranscriptOperation)
			if seal != (OwnerVerifiedSeal{}) ||
				!errors.Is(err, ErrInvalidOwnerSealTranscript) ||
				!failure.location.hasLogicalPage ||
				failure.location.logicalPage != logical ||
				fixture.pass.closeCalls != 1 || fixture.copier.closeCalls != 0 {
				t.Fatalf("content rejection = seal %#v failure %#v close %d copier-close %d",
					seal, failure, fixture.pass.closeCalls, fixture.copier.closeCalls)
			}
		})
	}
}

func TestOwnerSealRereadPassClassifiesDMLAndSinkFailures(t *testing.T) {
	t.Run("DML", func(t *testing.T) {
		fixture := newOwnerSealRereadTestFixture(t)
		dmlErr := errors.New("injected DML failure")
		fixture.copier.failCall = 3
		fixture.copier.failErr = dmlErr
		sinkCalls := 0
		seal, err := runOwnerSealRereadTranscriptPass(
			context.Background(), fixture.plan, fixture.source, fixture.copier,
			func(OwnerSealPageVerification) error {
				sinkCalls++
				return nil
			})
		failure := ownerSealRereadTestRequireFailure(t, err, ownerSealRereadDMLOperation)
		if seal != (OwnerVerifiedSeal{}) || !errors.Is(err, dmlErr) ||
			failure.location.logicalPage != 2 || sinkCalls != 2 ||
			fixture.copier.calls != 3 || fixture.pass.closeCalls != 1 ||
			fixture.copier.closeCalls != 0 {
			t.Fatalf("DML failure = seal %#v failure %#v sink %d DML %d close %d/%d",
				seal, failure, sinkCalls, fixture.copier.calls,
				fixture.pass.closeCalls, fixture.copier.closeCalls)
		}
	})

	t.Run("sink", func(t *testing.T) {
		fixture := newOwnerSealRereadTestFixture(t)
		sinkErr := errors.New("injected sink failure")
		sinkCalls := 0
		seal, err := runOwnerSealRereadTranscriptPass(
			context.Background(), fixture.plan, fixture.source, fixture.copier,
			func(verification OwnerSealPageVerification) error {
				fixture.log.add("sink")
				sinkCalls++
				if verification.Target().LogicalPage() == 2 {
					return sinkErr
				}
				return nil
			})
		failure := ownerSealRereadTestRequireFailure(t, err, ownerSealRereadSinkOperation)
		if seal != (OwnerVerifiedSeal{}) || !errors.Is(err, sinkErr) ||
			failure.location.logicalPage != 2 || sinkCalls != 3 ||
			fixture.copier.calls != 3 || fixture.pass.closeCalls != 1 ||
			fixture.copier.closeCalls != 0 {
			t.Fatalf("sink failure = seal %#v failure %#v sink %d DML %d close %d/%d",
				seal, failure, sinkCalls, fixture.copier.calls,
				fixture.pass.closeCalls, fixture.copier.closeCalls)
		}
	})
}

func TestOwnerSealRereadPassContextCancellationBeforeOpenViewAndAfterDML(t *testing.T) {
	t.Run("before-open", func(t *testing.T) {
		fixture := newOwnerSealRereadTestFixture(t)
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		seal, err := runOwnerSealRereadTranscriptPass(
			ctx, fixture.plan, fixture.source, fixture.copier, nil)
		ownerSealRereadTestRequireFailure(t, err, ownerSealRereadContextOperation)
		if seal != (OwnerVerifiedSeal{}) || !errors.Is(err, context.Canceled) ||
			fixture.source.openCalls != 0 || fixture.pass.closeCalls != 0 ||
			fixture.copier.calls != 0 || fixture.copier.closeCalls != 0 {
			t.Fatalf("pre-open cancellation = seal %#v open %d close %d DML %d copier-close %d error %v",
				seal, fixture.source.openCalls, fixture.pass.closeCalls,
				fixture.copier.calls, fixture.copier.closeCalls, err)
		}
	})

	t.Run("during-final-view", func(t *testing.T) {
		fixture := newOwnerSealRereadTestFixture(t)
		ctx, cancel := context.WithCancel(context.Background())
		fixture.pass.cancelViewCall = len(fixture.requests)
		fixture.pass.cancel = cancel
		seal, err := runOwnerSealRereadTranscriptPass(
			ctx, fixture.plan, fixture.source, fixture.copier, nil)
		failure := ownerSealRereadTestRequireFailure(
			t, err, ownerSealRereadContextOperation)
		if seal != (OwnerVerifiedSeal{}) || !errors.Is(err, context.Canceled) ||
			failure.location.runIndex != len(fixture.requests)-1 ||
			fixture.pass.readableViewCalls != len(fixture.requests) ||
			fixture.copier.calls != 0 || fixture.pass.closeCalls != 1 ||
			fixture.copier.closeCalls != 0 {
			t.Fatalf("view cancellation = seal %#v failure %#v views %d DML %d close %d/%d",
				seal, failure, fixture.pass.readableViewCalls, fixture.copier.calls,
				fixture.pass.closeCalls, fixture.copier.closeCalls)
		}
	})

	t.Run("after-DML", func(t *testing.T) {
		fixture := newOwnerSealRereadTestFixture(t)
		ctx, cancel := context.WithCancel(context.Background())
		fixture.copier.cancelCall = 3
		fixture.copier.cancel = cancel
		sinkCalls := 0
		seal, err := runOwnerSealRereadTranscriptPass(
			ctx, fixture.plan, fixture.source, fixture.copier,
			func(OwnerSealPageVerification) error {
				sinkCalls++
				return nil
			})
		failure := ownerSealRereadTestRequireFailure(
			t, err, ownerSealRereadContextOperation)
		if seal != (OwnerVerifiedSeal{}) || !errors.Is(err, context.Canceled) ||
			failure.location.logicalPage != 2 || fixture.copier.calls != 3 ||
			sinkCalls != 2 || fixture.pass.closeCalls != 1 || fixture.copier.closeCalls != 0 {
			t.Fatalf("DML cancellation = seal %#v failure %#v DML %d sink %d close %d/%d",
				seal, failure, fixture.copier.calls, sinkCalls,
				fixture.pass.closeCalls, fixture.copier.closeCalls)
		}
	})
}

func TestOwnerSealRereadPassClosesEveryOpenedPrefixAndPreservesCloseErrors(t *testing.T) {
	t.Run("open-failure-does-not-close", func(t *testing.T) {
		fixture := newOwnerSealRereadTestFixture(t)
		openErr := errors.New("injected open failure")
		fixture.source.openErr = openErr
		_, err := runOwnerSealRereadTranscriptPass(
			context.Background(), fixture.plan, fixture.source, fixture.copier, nil)
		ownerSealRereadTestRequireFailure(t, err, ownerSealRereadOpenOperation)
		if !errors.Is(err, openErr) || fixture.pass.closeCalls != 0 ||
			fixture.copier.closeCalls != 0 {
			t.Fatalf("open failure = %v close %d copier-close %d",
				err, fixture.pass.closeCalls, fixture.copier.closeCalls)
		}
	})

	t.Run("open-failure-closes-returned-pass", func(t *testing.T) {
		fixture := newOwnerSealRereadTestFixture(t)
		openErr := errors.New("injected open failure with a pass")
		closeErr := errors.New("injected cleanup failure after open failure")
		fixture.source.openErr = openErr
		fixture.source.passOnError = true
		fixture.pass.closeErr = closeErr
		seal, err := runOwnerSealRereadTranscriptPass(
			context.Background(), fixture.plan, fixture.source, fixture.copier, nil)
		failure := ownerSealRereadTestRequireFailure(
			t, err, ownerSealRereadOpenOperation)
		var closeFailure *ownerSealRereadError
		if seal != (OwnerVerifiedSeal{}) || !errors.Is(err, openErr) ||
			!errors.Is(err, closeErr) || failure.closeErr == nil ||
			!errors.As(failure.closeErr, &closeFailure) ||
			closeFailure.operation != ownerSealRereadCloseOperation ||
			fixture.pass.closeCalls != 1 || fixture.copier.closeCalls != 0 {
			t.Fatalf("open/close failure = seal %#v failure %#v nested close %#v close %d copier-close %d",
				seal, failure, closeFailure, fixture.pass.closeCalls,
				fixture.copier.closeCalls)
		}
	})

	tests := []struct {
		name      string
		configure func(*ownerSealRereadTestFixture) ownerSealPageVerificationSink
		operation ownerSealRereadOperation
	}{
		{
			name: "view",
			configure: func(fixture *ownerSealRereadTestFixture) ownerSealPageVerificationSink {
				fixture.pass.viewFailureCall = 1
				fixture.pass.viewErr = errors.New("view")
				return nil
			},
			operation: ownerSealRereadViewOperation,
		},
		{
			name: "DML",
			configure: func(fixture *ownerSealRereadTestFixture) ownerSealPageVerificationSink {
				fixture.copier.failCall = 1
				fixture.copier.failErr = errors.New("DML")
				return nil
			},
			operation: ownerSealRereadDMLOperation,
		},
		{
			name: "sink",
			configure: func(*ownerSealRereadTestFixture) ownerSealPageVerificationSink {
				return func(OwnerSealPageVerification) error { return errors.New("sink") }
			},
			operation: ownerSealRereadSinkOperation,
		},
		{
			name: "transcript",
			configure: func(fixture *ownerSealRereadTestFixture) ownerSealPageVerificationSink {
				targets := ownerSealTranscriptTestTargets(t, fixture.plan)
				logical := ownerSealTranscriptTestFindTarget(t, targets, func(target OwnerSealPageTarget) bool {
					return target.TargetState() == DescriptorZeroPadding
				})
				ownerSealRereadTestMutateLogicalPage(t, fixture, logical, func(page []byte) {
					page[0] = 1
				})
				return nil
			},
			operation: ownerSealRereadTranscriptOperation,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newOwnerSealRereadTestFixture(t)
			sink := test.configure(&fixture)
			_, err := runOwnerSealRereadTranscriptPass(
				context.Background(), fixture.plan, fixture.source, fixture.copier, sink)
			ownerSealRereadTestRequireFailure(t, err, test.operation)
			if fixture.pass.closeCalls != 1 || fixture.copier.closeCalls != 0 {
				t.Fatalf("failure prefix close = %d copier-close = %d",
					fixture.pass.closeCalls, fixture.copier.closeCalls)
			}
		})
	}

	t.Run("close-only", func(t *testing.T) {
		fixture := newOwnerSealRereadTestFixture(t)
		closeErr := errors.New("injected close failure")
		fixture.pass.closeErr = closeErr
		seal, err := runOwnerSealRereadTranscriptPass(
			context.Background(), fixture.plan, fixture.source, fixture.copier, nil)
		failure := ownerSealRereadTestRequireFailure(
			t, err, ownerSealRereadCloseOperation)
		if seal != (OwnerVerifiedSeal{}) || !errors.Is(err, closeErr) ||
			failure.closeErr != nil || fixture.pass.closeCalls != 1 ||
			fixture.copier.closeCalls != 0 {
			t.Fatalf("close-only = seal %#v failure %#v close %d copier-close %d",
				seal, failure, fixture.pass.closeCalls, fixture.copier.closeCalls)
		}
	})

	t.Run("primary-and-close", func(t *testing.T) {
		fixture := newOwnerSealRereadTestFixture(t)
		primaryErr := errors.New("injected primary DML failure")
		closeErr := errors.New("injected secondary close failure")
		fixture.copier.failCall = 1
		fixture.copier.failErr = primaryErr
		fixture.pass.closeErr = closeErr
		seal, err := runOwnerSealRereadTranscriptPass(
			context.Background(), fixture.plan, fixture.source, fixture.copier, nil)
		failure := ownerSealRereadTestRequireFailure(t, err, ownerSealRereadDMLOperation)
		var closeFailure *ownerSealRereadError
		if seal != (OwnerVerifiedSeal{}) || !errors.Is(err, primaryErr) ||
			!errors.Is(err, closeErr) || failure.closeErr == nil ||
			!errors.As(failure.closeErr, &closeFailure) ||
			closeFailure.operation != ownerSealRereadCloseOperation ||
			fixture.pass.closeCalls != 1 || fixture.copier.closeCalls != 0 {
			t.Fatalf("combined failure = seal %#v failure %#v nested close %#v close %d copier-close %d",
				seal, failure, closeFailure, fixture.pass.closeCalls,
				fixture.copier.closeCalls)
		}
		if !strings.Contains(err.Error(), "additionally") {
			t.Fatalf("combined error does not preserve close text: %v", err)
		}
	})
}

func TestOwnerSealRereadPassRetainsNoViewsOrPerPageResultAndNeverOwnsCopier(t *testing.T) {
	functionType := reflect.TypeOf(runOwnerSealRereadTranscriptPass)
	if functionType.NumOut() != 2 || functionType.Out(0) != reflect.TypeOf(OwnerVerifiedSeal{}) ||
		functionType.Out(1) != reflect.TypeOf((*error)(nil)).Elem() {
		t.Fatalf("reread function outputs = %s", functionType)
	}
	preparedType := reflect.TypeOf(ownerSealPreparedReadableExtent{})
	for fieldIndex := 0; fieldIndex < preparedType.NumField(); fieldIndex++ {
		field := preparedType.Field(fieldIndex)
		lower := strings.ToLower(field.Name)
		if strings.Contains(lower, "pages") || strings.Contains(lower, "crc") ||
			strings.Contains(lower, "descriptor") || strings.Contains(lower, "verification") {
			t.Fatalf("prepared extent retains per-page-looking field %q", field.Name)
		}
		if field.Type.Kind() == reflect.Slice {
			t.Fatalf("prepared extent has direct slice field %q; only one nested run view is allowed",
				field.Name)
		}
	}
	errorType := reflect.TypeOf(ownerSealRereadError{})
	for fieldIndex := 0; fieldIndex < errorType.NumField(); fieldIndex++ {
		kind := errorType.Field(fieldIndex).Type.Kind()
		if kind == reflect.Slice || kind == reflect.Map {
			t.Fatalf("typed error retains collection field %q", errorType.Field(fieldIndex).Name)
		}
	}

	fixture := newOwnerSealRereadTestFixture(t)
	if _, err := runOwnerSealRereadTranscriptPass(
		context.Background(), fixture.plan, fixture.source, fixture.copier, nil,
	); err != nil {
		t.Fatalf("reread without sink: %v", err)
	}
	if fixture.copier.closeCalls != 0 || fixture.pass.closeCalls != 1 {
		t.Fatalf("copier/read-pass close counts = %d/%d, want 0/1",
			fixture.copier.closeCalls, fixture.pass.closeCalls)
	}
}

func newOwnerSealRereadTestFixture(t *testing.T) ownerSealRereadTestFixture {
	t.Helper()
	producer := newProducerScatterTestFixture(t)
	plan := ownerSealPlanTestBuild(t, producer)
	pages := ownerSealTranscriptTestPages(t, producer, plan)
	log := &ownerSealRereadTestEventLog{}
	views := make(map[ownerSealRereadTestRequest]OwnerSealReadableExtent)
	devices := plan.Devices()
	requests := make([]ownerSealRereadTestRequest, len(plan.ExtentRuns()))
	for runIndex, run := range plan.ExtentRuns() {
		binding := devices[run.DeviceIndex]
		request := ownerSealRereadTestRequest{
			binding: binding, startDataPageIndex: run.StartDataPageIndex,
			pageCount: run.PageCount,
		}
		requests[runIndex] = request
		bytes := make([]byte, int(run.PageCount)*ContentPageBytes)
		for page := uint64(0); page < run.PageCount; page++ {
			logical := run.LogicalPageStart + page
			start := int(page) * ContentPageBytes
			copy(bytes[start:start+ContentPageBytes], pages[logical])
		}
		views[request] = OwnerSealReadableExtent{
			Binding:            binding,
			StartDataPageIndex: run.StartDataPageIndex,
			PageCount:          run.PageCount,
			Bytes:              bytes,
			Backing: ProducerScatterBackingRange{
				BackingID:  sha256.Sum256([]byte("reread-" + binding.DeviceUUID)),
				ByteOffset: run.StartDataPageIndex * uint64(ContentPageBytes),
				ByteLength: uint64(len(bytes)),
			},
		}
	}
	pass := &ownerSealRereadTestPass{log: log, views: views}
	source := &ownerSealRereadTestSource{log: log, pass: pass}
	copier := &ownerSealRereadTestCopier{log: log}
	return ownerSealRereadTestFixture{
		producer: producer,
		plan:     plan,
		pages:    pages,
		wantSeal: ownerSealTranscriptTestComplete(t, plan, pages, nil),
		log:      log,
		requests: requests,
		pass:     pass,
		source:   source,
		copier:   copier,
	}
}

func ownerSealRereadTestMutateLogicalPage(
	t *testing.T,
	fixture *ownerSealRereadTestFixture,
	logicalPage uint64,
	mutate func([]byte),
) {
	t.Helper()
	devices := fixture.plan.Devices()
	for _, run := range fixture.plan.ExtentRuns() {
		end := run.LogicalPageStart + run.PageCount
		if logicalPage < run.LogicalPageStart || logicalPage >= end {
			continue
		}
		request := ownerSealRereadTestRequest{
			binding: devices[run.DeviceIndex], startDataPageIndex: run.StartDataPageIndex,
			pageCount: run.PageCount,
		}
		view := fixture.pass.views[request]
		page := logicalPage - run.LogicalPageStart
		start := int(page) * ContentPageBytes
		mutate(view.Bytes[start : start+ContentPageBytes])
		fixture.pass.views[request] = view
		return
	}
	t.Fatalf("logical page %d is absent from compact extents", logicalPage)
}

func ownerSealRereadTestRequireFailure(
	t *testing.T,
	err error,
	wantOperation ownerSealRereadOperation,
) *ownerSealRereadError {
	t.Helper()
	if !errors.Is(err, errOwnerSealRereadPass) {
		t.Fatalf("error = %v, want errOwnerSealRereadPass", err)
	}
	var failure *ownerSealRereadError
	if !errors.As(err, &failure) {
		t.Fatalf("error %T = %v, want *ownerSealRereadError", err, err)
	}
	if failure.operation != wantOperation {
		t.Fatalf("error operation = %q, want %q: %v",
			failure.operation, wantOperation, err)
	}
	return failure
}

func ownerSealRereadTestFirstEvent(events []string, want string) int {
	for index, event := range events {
		if event == want {
			return index
		}
	}
	return -1
}

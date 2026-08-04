package trcxl007

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"hash/crc32"
	"reflect"
	"runtime"
	"strings"
	"testing"

	"github.com/containerd/containerd/third_party/trenv-containerd/cmd/cxld/internal/trcxl007dml"
)

type ownerSealExecutorTestSource struct {
	bindings map[string]ProducerScatterDeviceBinding
	images   map[string][]byte
	backings map[string][sha256.Size]byte
	trace    *[]string

	openCalls       int
	openFailureCall int
	openFailure     error
	returnTypedNil  bool
	mutateOpenCall  int
	mutateDevice    string
	mutatePage      uint64
	closeFailure    error
	passes          []*ownerSealExecutorTestPass
}

type ownerSealExecutorTestPass struct {
	source     *ownerSealExecutorTestSource
	openCall   int
	closeCalls int
}

func (source *ownerSealExecutorTestSource) OpenReadPass(
	_ context.Context,
	devices []ProducerScatterDeviceBinding,
) (OwnerSealContentReadPass, error) {
	if source == nil {
		panic("typed-nil Owner seal test source was invoked")
	}
	source.openCalls++
	call := source.openCalls
	*source.trace = append(*source.trace, fmt.Sprintf("source-open:%d", call))
	for _, binding := range devices {
		if want, found := source.bindings[binding.DeviceUUID]; !found || want != binding {
			return nil, fmt.Errorf("unexpected source binding %#v", binding)
		}
	}
	if source.returnTypedNil {
		var pass *ownerSealExecutorTestPass
		return pass, source.openFailure
	}
	pass := &ownerSealExecutorTestPass{source: source, openCall: call}
	source.passes = append(source.passes, pass)
	if source.openFailureCall == call {
		return nil, source.openFailure
	}
	return pass, nil
}

func (pass *ownerSealExecutorTestPass) ReadableExtent(
	binding ProducerScatterDeviceBinding,
	startDataPageIndex uint64,
	pageCount uint64,
) (OwnerSealReadableExtent, error) {
	if pass == nil || pass.source == nil {
		panic("typed-nil Owner seal test pass was invoked")
	}
	*pass.source.trace = append(*pass.source.trace,
		fmt.Sprintf("source-view:%d", pass.openCall))
	want, found := pass.source.bindings[binding.DeviceUUID]
	if !found || want != binding || pageCount == 0 {
		return OwnerSealReadableExtent{}, errors.New("invalid test source extent binding")
	}
	endPage, ok := checkedAdd(startDataPageIndex, pageCount)
	if !ok || endPage > binding.DataPageCount {
		return OwnerSealReadableExtent{}, errors.New("test source extent is out of bounds")
	}
	startByte := startDataPageIndex * uint64(ContentPageBytes)
	endByte := endPage * uint64(ContentPageBytes)
	image := pass.source.images[binding.DeviceUUID]
	if endByte > uint64(len(image)) {
		return OwnerSealReadableExtent{}, errors.New("test source image is too short")
	}
	viewBytes := image[int(startByte):int(endByte)]
	if pass.openCall == pass.source.mutateOpenCall &&
		binding.DeviceUUID == pass.source.mutateDevice &&
		pass.source.mutatePage >= startDataPageIndex &&
		pass.source.mutatePage < endPage {
		viewBytes = append([]byte(nil), viewBytes...)
		offset := (pass.source.mutatePage - startDataPageIndex) * uint64(ContentPageBytes)
		viewBytes[int(offset)] ^= 0x80
	}
	return OwnerSealReadableExtent{
		Binding:            binding,
		StartDataPageIndex: startDataPageIndex,
		PageCount:          pageCount,
		Bytes:              viewBytes,
		Backing: ProducerScatterBackingRange{
			BackingID:  pass.source.backings[binding.DeviceUUID],
			ByteOffset: startByte,
			ByteLength: uint64(len(viewBytes)),
		},
	}, nil
}

func (pass *ownerSealExecutorTestPass) Close() error {
	if pass == nil || pass.source == nil {
		panic("typed-nil Owner seal test pass Close was invoked")
	}
	pass.closeCalls++
	*pass.source.trace = append(*pass.source.trace,
		fmt.Sprintf("source-close:%d", pass.openCall))
	return pass.source.closeFailure
}

type ownerSealExecutorTestCopier struct {
	trace      *[]string
	calls      int
	failCall   int
	failErr    error
	onCall     func(int)
	closeCalls int
	closeErr   error
}

func (copier *ownerSealExecutorTestCopier) CopyPage(dst, src []byte) (uint32, error) {
	copier.calls++
	*copier.trace = append(*copier.trace, fmt.Sprintf("dml:%d", copier.calls))
	if copier.onCall != nil {
		copier.onCall(copier.calls)
	}
	if copier.failCall == copier.calls {
		return 0, copier.failErr
	}
	if len(dst) != trcxl007dml.PageSize || len(src) != trcxl007dml.PageSize {
		return 0, trcxl007dml.ErrInvalidPage
	}
	copy(dst, src)
	return crc32.Checksum(dst, crc32.MakeTable(crc32.Castagnoli)), nil
}

func (copier *ownerSealExecutorTestCopier) Close() error {
	copier.closeCalls++
	*copier.trace = append(*copier.trace, "copier-close")
	return copier.closeErr
}

type ownerSealExecutorTestFixture struct {
	*ownerSealDescriptorPersistenceTestFixture
	trace  *[]string
	source *ownerSealExecutorTestSource
}

func newPersistedOwnerSealExecutorTestFixture(
	t *testing.T,
) *ownerSealExecutorTestFixture {
	t.Helper()
	descriptorFixture := newOwnerSealDescriptorPersistenceTestFixture(t)
	trace := make([]string, 0, 256)
	descriptorFixture.syncTrace = &trace
	for _, storage := range descriptorFixture.storages {
		storage.syncTrace = &trace
	}

	// The descriptor-persistence fixture deliberately uses cached metadata.
	// Materialize that exact selected view into real A slots so this executor
	// fixture exercises every required full reopen instead of bypassing it.
	for index := range descriptorFixture.group.devices {
		opened := descriptorFixture.group.devices[index]
		metadata := opened.metadata
		allocatorWire, err := CanonicalAllocatorSnapshotBytes(
			metadata.allocator,
			metadata.geometry)
		if err != nil {
			t.Fatalf("canonical allocator %q: %v", opened.deviceUUID, err)
		}
		if err := writeMetadataEnvelopeHeaderLast(
			metadata.storage,
			metadata.geometry.DeviceBytes,
			metadata.geometry.AllocatorSnapshotAOffset,
			metadata.geometry.AllocatorSnapshotSlotBytes,
			allocatorWire,
			AllocatorSnapshotEnvelopeHeaderBytes); err != nil {
			t.Fatalf("persist allocator %q: %v", opened.deviceUUID, err)
		}
		if opened.deviceUUID == descriptorFixture.group.bootstrap.AnchorDeviceUUID {
			ownerWire, err := CanonicalOwnerStateBytes(
				descriptorFixture.owner,
				metadata.geometry)
			if err != nil {
				t.Fatalf("canonical Owner state: %v", err)
			}
			if err := writeMetadataEnvelopeHeaderLast(
				metadata.storage,
				metadata.geometry.DeviceBytes,
				metadata.geometry.OwnerStateSnapshotAOffset,
				metadata.geometry.OwnerStateSnapshotSlotBytes,
				ownerWire,
				OwnerStateEnvelopeHeaderBytes); err != nil {
				t.Fatalf("persist Owner state: %v", err)
			}
		}
		superblockWire, err := CanonicalSuperblockBytes(metadata.superblock)
		if err != nil {
			t.Fatalf("canonical superblock %q: %v", opened.deviceUUID, err)
		}
		if err := writeMetadataEnvelopeHeaderLast(
			metadata.storage,
			metadata.geometry.DeviceBytes,
			metadata.geometry.SuperblockAOffset,
			SuperblockSlotBytes,
			superblockWire,
			SuperblockEnvelopeHeaderBytes); err != nil {
			t.Fatalf("persist superblock %q: %v", opened.deviceUUID, err)
		}
	}

	entries := make([]OwnerDeviceGroupDeviceInput, len(descriptorFixture.group.devices))
	for index, opened := range descriptorFixture.group.devices {
		entries[index] = OwnerDeviceGroupDeviceInput{
			ExpectedDeviceUUID:       opened.deviceUUID,
			Storage:                  opened.metadata.storage,
			Geometry:                 opened.geometry,
			OwnerStateReadLimitBytes: opened.geometry.OwnerStateSnapshotSlotBytes,
		}
	}
	group, err := OpenOwnerDeviceGroup(OwnerDeviceGroupInput{
		Devices:             entries,
		OwnerStateBootstrap: descriptorFixture.group.bootstrap,
	})
	if err != nil {
		t.Fatalf("open persisted Owner seal fixture: %v", err)
	}
	descriptorFixture.group = group
	descriptorFixture.resetTracking()

	bindings := make(map[string]ProducerScatterDeviceBinding)
	images := make(map[string][]byte)
	backings := make(map[string][sha256.Size]byte)
	for _, binding := range descriptorFixture.plan.Devices() {
		bindings[binding.DeviceUUID] = binding
		images[binding.DeviceUUID] = make(
			[]byte,
			int(binding.DataPageCount)*ContentPageBytes)
		backings[binding.DeviceUUID] = sha256.Sum256(
			[]byte("owner-seal-executor-" + binding.DeviceUUID))
	}
	for logical, target := range descriptorFixture.targets {
		image := images[target.Device().DeviceUUID]
		start := int(target.DataPageIndex()) * ContentPageBytes
		copy(image[start:start+ContentPageBytes], descriptorFixture.pages[logical])
	}
	source := &ownerSealExecutorTestSource{
		bindings: bindings,
		images:   images,
		backings: backings,
		trace:    &trace,
	}
	return &ownerSealExecutorTestFixture{
		ownerSealDescriptorPersistenceTestFixture: descriptorFixture,
		trace:  &trace,
		source: source,
	}
}

func (fixture *ownerSealExecutorTestFixture) producerResult(
	t *testing.T,
) ProducerScatterResult {
	t.Helper()
	destination := newProducerScatterTestDestination(fixture.producer.plan)
	copier := &producerScatterTestCPUCopier{destination: destination}
	result, err := ExecuteProducerScatter(
		context.Background(),
		ProducerScatterExecutionRequest{
			Plan:        fixture.producer.plan,
			Sources:     fixture.producer.sources(nil),
			Destination: destination,
			Copier:      copier,
		})
	if err != nil {
		t.Fatalf("construct opaque Producer result: %v", err)
	}
	return result
}

func (fixture *ownerSealExecutorTestFixture) input(
	t *testing.T,
) OwnerGrantedSealInput {
	t.Helper()
	return OwnerGrantedSealInput{
		AllocationRecordID: fixture.plan.AllocationRecordID(),
		PublicationPlan:    fixture.producer.initial,
		ProducerPlan:       fixture.producer.plan,
		ProducerResult:     fixture.producerResult(t),
	}
}

func (fixture *ownerSealExecutorTestFixture) executor(
	t *testing.T,
	copier *ownerSealExecutorTestCopier,
) *OwnerSealExecutor {
	t.Helper()
	executor, err := newOwnerSealExecutor(
		fixture.group,
		fixture.source,
		func() (trcxl007dml.Copier, error) { return copier, nil })
	if err != nil {
		t.Fatalf("newOwnerSealExecutor: %v", err)
	}
	return executor
}

func (fixture *ownerSealExecutorTestFixture) record(
	t *testing.T,
) OwnerStateAllocationRecord {
	t.Helper()
	owner, _, err := fixture.group.PlannerInputs()
	if err != nil {
		t.Fatalf("PlannerInputs: %v", err)
	}
	record, found := producerScatterRecordByID(
		owner.Records(),
		fixture.plan.AllocationRecordID())
	if !found {
		t.Fatalf("allocation %d disappeared", fixture.plan.AllocationRecordID())
	}
	return record
}

func (fixture *ownerSealExecutorTestFixture) reopen(
	t *testing.T,
) *OwnerDeviceGroup {
	t.Helper()
	entries := make([]OwnerDeviceGroupDeviceInput, len(fixture.group.devices))
	for index, opened := range fixture.group.devices {
		entries[index] = OwnerDeviceGroupDeviceInput{
			ExpectedDeviceUUID:       opened.deviceUUID,
			Storage:                  opened.metadata.storage,
			Geometry:                 opened.geometry,
			OwnerStateReadLimitBytes: opened.geometry.OwnerStateSnapshotSlotBytes,
		}
	}
	group, err := OpenOwnerDeviceGroup(OwnerDeviceGroupInput{
		Devices:             entries,
		OwnerStateBootstrap: fixture.group.bootstrap,
	})
	if err != nil {
		t.Fatalf("reopen Owner seal fixture: %v", err)
	}
	fixture.group = group
	return group
}

func ownerSealExecutorTestIndex(events []string, value string) int {
	for index, event := range events {
		if event == value {
			return index
		}
	}
	return -1
}

func ownerSealExecutorTestLastIndex(events []string, value string) int {
	for index := len(events) - 1; index >= 0; index-- {
		if events[index] == value {
			return index
		}
	}
	return -1
}

func ownerSealExecutorTestIndexAfter(events []string, value string, after int) int {
	for index := after + 1; index < len(events); index++ {
		if events[index] == value {
			return index
		}
	}
	return -1
}

func TestOwnerSealExecutorFreshFragmentedTwoDAXAndReadOnlyReplay(t *testing.T) {
	fixture := newPersistedOwnerSealExecutorTestFixture(t)
	if got := len(fixture.plan.ExtentRuns()); got != 6 || len(fixture.plan.Devices()) != 2 {
		t.Fatalf("fixture placement = %d runs/%d devices, want fragmented 6/2",
			got, len(fixture.plan.Devices()))
	}
	copier := &ownerSealExecutorTestCopier{trace: fixture.trace}
	executor := fixture.executor(t, copier)

	result, err := executor.ExecuteGrantedCheckpointSeal(
		context.Background(),
		fixture.input(t))
	if err != nil {
		t.Fatalf("ExecuteGrantedCheckpointSeal: %v", err)
	}
	if result.Record.State != OwnerAllocationCommitted ||
		!result.ProducerCRCMatch || result.ForwardRecovered || result.Replayed {
		t.Fatalf("fresh result = %#v", result)
	}
	if fixture.source.openCalls != 3 ||
		copier.calls != 3*int(fixture.plan.TotalPages()) || copier.closeCalls != 1 {
		t.Fatalf("fresh open/DML/close = %d/%d/%d, want 3/%d/1",
			fixture.source.openCalls,
			copier.calls,
			copier.closeCalls,
			3*int(fixture.plan.TotalPages()))
	}
	if fixture.group.executionState.reopenRequired {
		t.Fatal("successful post-Sync verification did not clear the group latch")
	}
	fixture.requireAllExactTargets(t)
	closeIndex := ownerSealExecutorTestIndex(*fixture.trace, "copier-close")
	lastAnchorSync := ownerSealExecutorTestLastIndex(*fixture.trace, "device-a")
	if closeIndex < 0 || lastAnchorSync <= closeIndex {
		t.Fatalf("Copier Close must precede terminal Owner commit: close=%d last anchor Sync=%d trace=%#v",
			closeIndex, lastAnchorSync, *fixture.trace)
	}

	beforeOwner, _, err := fixture.group.PlannerInputs()
	if err != nil {
		t.Fatalf("PlannerInputs before replay: %v", err)
	}
	beforeWire, err := CanonicalOwnerStateBytes(beforeOwner, fixture.geometry)
	if err != nil {
		t.Fatalf("canonical pre-replay Owner: %v", err)
	}
	fixture.resetTracking()
	*fixture.trace = nil
	replayCopier := &ownerSealExecutorTestCopier{trace: fixture.trace}
	replayExecutor := fixture.executor(t, replayCopier)
	replay, err := replayExecutor.ReplayCommittedCheckpointSeal(
		context.Background(),
		fixture.plan.AllocationRecordID())
	if err != nil {
		t.Fatalf("ReplayCommittedCheckpointSeal: %v", err)
	}
	if replay.Record.State != OwnerAllocationCommitted || !replay.Replayed ||
		replay.ForwardRecovered || replay.ProducerCRCMatch {
		t.Fatalf("replay result = %#v", replay)
	}
	if replayCopier.calls != int(fixture.plan.TotalPages()) || replayCopier.closeCalls != 1 {
		t.Fatalf("replay DML/Close = %d/%d", replayCopier.calls, replayCopier.closeCalls)
	}
	if fixture.totalWrites() != 0 || fixture.totalSyncs() != 0 ||
		fixture.totalMutations() != 0 {
		t.Fatalf("read-only replay writes/Syncs/mutations = %d/%d/%d",
			fixture.totalWrites(), fixture.totalSyncs(), fixture.totalMutations())
	}
	afterOwner, _, err := fixture.group.PlannerInputs()
	if err != nil {
		t.Fatalf("PlannerInputs after replay: %v", err)
	}
	afterWire, err := CanonicalOwnerStateBytes(afterOwner, fixture.geometry)
	if err != nil || !reflect.DeepEqual(afterWire, beforeWire) {
		t.Fatalf("replay changed durable Owner state: equal=%t err=%v",
			reflect.DeepEqual(afterWire, beforeWire), err)
	}
}

func TestOwnerSealExecutorRecoversUniqueDurableCommitting(t *testing.T) {
	fixture := newPersistedOwnerSealExecutorTestFixture(t)
	seal := ownerSealTranscriptTestComplete(t, fixture.plan, fixture.pages, nil)
	transitions, err := PlanFreshOwnerSealStateTransitions(
		fixture.owner,
		fixture.plan,
		seal)
	if err != nil {
		t.Fatalf("PlanFreshOwnerSealStateTransitions: %v", err)
	}
	if err := fixture.group.anchor.commitOwnerState(transitions.Committing()); err != nil {
		t.Fatalf("persist COMMITTING: %v", err)
	}
	fixture.resetTracking()
	*fixture.trace = nil
	copier := &ownerSealExecutorTestCopier{trace: fixture.trace}
	executor := fixture.executor(t, copier)

	result, err := executor.RecoverCommittingCheckpointSeal(context.Background())
	if err != nil {
		t.Fatalf("RecoverCommittingCheckpointSeal: %v", err)
	}
	if result.Record.State != OwnerAllocationCommitted || !result.ForwardRecovered ||
		result.Replayed || result.ProducerCRCMatch {
		t.Fatalf("recovery result = %#v", result)
	}
	// Media reconstruction plus the three authoritative rereads each owns one
	// bounded read pass. Only the three transcript passes use DML.
	if fixture.source.openCalls != 4 ||
		copier.calls != 3*int(fixture.plan.TotalPages()) || copier.closeCalls != 1 {
		t.Fatalf("recovery open/DML/Close = %d/%d/%d",
			fixture.source.openCalls, copier.calls, copier.closeCalls)
	}
	if fixture.group.executionState.reopenRequired {
		t.Fatal("successful recovery left the group reopen latch set")
	}
	fixture.requireAllExactTargets(t)
}

func TestOwnerSealExecutorProducerCRCIsAdvisory(t *testing.T) {
	fixture := newPersistedOwnerSealExecutorTestFixture(t)
	input := fixture.input(t)
	input.ProducerResult.crcVector.raw[0] ^= 0xff
	copier := &ownerSealExecutorTestCopier{trace: fixture.trace}
	result, err := fixture.executor(t, copier).ExecuteGrantedCheckpointSeal(
		context.Background(),
		input)
	if err != nil {
		t.Fatalf("advisory CRC mismatch: %v", err)
	}
	if result.ProducerCRCMatch || result.Record.State != OwnerAllocationCommitted {
		t.Fatalf("advisory mismatch result = %#v", result)
	}
	fixture.requireAllExactTargets(t)
}

func TestOwnerSealExecutorPublicBoundaryAndInvalidHandles(t *testing.T) {
	constructor := reflect.TypeOf(NewOwnerSealExecutor)
	if constructor.NumIn() != 2 ||
		constructor.In(0) != reflect.TypeOf((*OwnerDeviceGroup)(nil)) ||
		constructor.In(1) != reflect.TypeOf((*OwnerSealContentSource)(nil)).Elem() {
		t.Fatalf("public constructor unexpectedly exposes Copier/factory input: %s", constructor)
	}

	fixture := newPersistedOwnerSealExecutorTestFixture(t)
	production, err := NewOwnerSealExecutor(fixture.group, fixture.source)
	if err != nil {
		t.Fatalf("public production constructor: %v", err)
	}
	factoryName := runtime.FuncForPC(
		reflect.ValueOf(production.copierFactory).Pointer()).Name()
	if !strings.HasSuffix(factoryName, "trcxl007dml.OpenHardware") {
		t.Fatalf("production Copier factory = %q, want fixed OpenHardware", factoryName)
	}
	var nilSource *ownerSealExecutorTestSource
	if _, err := NewOwnerSealExecutor(fixture.group, nilSource); !errors.Is(
		err,
		ErrInvalidOwnerSealExecutor) {
		t.Fatalf("typed-nil source constructor error = %v", err)
	}
	if _, err := newOwnerSealExecutor(
		fixture.group,
		fixture.source,
		nil); !errors.Is(err, ErrInvalidOwnerSealExecutor) {
		t.Fatalf("nil factory constructor error = %v", err)
	}

	copier := &ownerSealExecutorTestCopier{trace: fixture.trace}
	executor := fixture.executor(t, copier)
	copiedValue := *executor
	copied := &copiedValue
	fixture.resetTracking()
	*fixture.trace = nil
	if _, err := copied.ExecuteGrantedCheckpointSeal(
		context.Background(),
		fixture.input(t)); !errors.Is(err, ErrInvalidOwnerSealExecutor) {
		t.Fatalf("copied executor error = %v", err)
	}
	if fixture.totalWrites() != 0 || fixture.totalSyncs() != 0 ||
		fixture.source.openCalls != 0 || copier.calls != 0 {
		t.Fatalf("copied executor performed I/O: writes=%d Syncs=%d opens=%d DML=%d",
			fixture.totalWrites(), fixture.totalSyncs(), fixture.source.openCalls, copier.calls)
	}

	var typedNilCopier *ownerSealExecutorTestCopier
	typedNilExecutor, err := newOwnerSealExecutor(
		fixture.group,
		fixture.source,
		func() (trcxl007dml.Copier, error) { return typedNilCopier, nil })
	if err != nil {
		t.Fatalf("construct typed-nil factory executor: %v", err)
	}
	_, err = typedNilExecutor.ExecuteGrantedCheckpointSeal(
		context.Background(),
		fixture.input(t))
	if !errors.Is(err, ErrInvalidOwnerSealExecutor) ||
		!strings.Contains(err.Error(), "nil Copier") {
		t.Fatalf("typed-nil Copier result = %v", err)
	}
	if fixture.source.openCalls != 0 || fixture.totalWrites() != 0 ||
		fixture.totalSyncs() != 0 {
		t.Fatal("typed-nil Copier factory fell back or performed persistent I/O")
	}
}

func TestOwnerSealExecutorDescriptorPassFailurePrefixesUseOneBarrier(t *testing.T) {
	failure := errors.New("injected descriptor-pass DML failure")
	for _, test := range []struct {
		name          string
		passTwoOffset int
		wantBarrier   bool
	}{
		{name: "before-first-write", passTwoOffset: 1, wantBarrier: false},
		{name: "after-one-write", passTwoOffset: 2, wantBarrier: true},
		{name: "late-prefix", passTwoOffset: 17, wantBarrier: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := newPersistedOwnerSealExecutorTestFixture(t)
			copier := &ownerSealExecutorTestCopier{
				trace:    fixture.trace,
				failCall: int(fixture.plan.TotalPages()) + test.passTwoOffset,
				failErr:  failure,
			}
			_, err := fixture.executor(t, copier).ExecuteGrantedCheckpointSeal(
				context.Background(),
				fixture.input(t))
			if !errors.Is(err, failure) ||
				!errors.Is(err, ErrOwnerSealRecoveryRequired) ||
				!errors.Is(err, ErrOwnerDeviceGroupReopenRequired) {
				t.Fatalf("prefix failure = %v", err)
			}
			if copier.closeCalls != 1 {
				t.Fatalf("Copier Close calls = %d, want 1", copier.closeCalls)
			}
			passClose := ownerSealExecutorTestIndex(*fixture.trace, "source-close:2")
			copierClose := ownerSealExecutorTestIndexAfter(
				*fixture.trace,
				"copier-close",
				passClose)
			barrierA := ownerSealExecutorTestIndexAfter(
				*fixture.trace,
				"device-a",
				passClose)
			barrierB := ownerSealExecutorTestIndexAfter(
				*fixture.trace,
				"device-b",
				passClose)
			if test.wantBarrier {
				if passClose < 0 || barrierA <= passClose || barrierB <= barrierA ||
					copierClose <= barrierB {
					t.Fatalf("failure barrier/Close order = pass %d A %d B %d Close %d trace=%#v",
						passClose, barrierA, barrierB, copierClose, *fixture.trace)
				}
			} else if barrierA >= 0 || barrierB >= 0 || copierClose <= passClose {
				t.Fatalf("pre-write failure issued an unnecessary barrier: trace=%#v",
					*fixture.trace)
			}

			// A new validated handle must select the one durable COMMITTING
			// allocation; the failed handle itself remains unusable.
			if _, _, err := fixture.group.PlannerInputs(); !errors.Is(
				err,
				ErrOwnerDeviceGroupReopenRequired) {
				t.Fatalf("failed handle PlannerInputs = %v", err)
			}
			fixture.reopen(t)
			if record := fixture.record(t); record.State != OwnerAllocationCommitting {
				t.Fatalf("durable failure state = %d, want COMMITTING", record.State)
			}
		})
	}
}

func TestOwnerSealExecutorFreshRejectsTargetAppearingAfterReservedPreflight(t *testing.T) {
	fixture := newPersistedOwnerSealExecutorTestFixture(t)
	copier := &ownerSealExecutorTestCopier{trace: fixture.trace}
	copier.onCall = func(call int) {
		if call == 1 {
			// Model an unauthorized writer appearing after the executor's exact
			// RESERVED-only preflight. The process-local lock and required external
			// fence make this impossible in correct production wiring; accepting it
			// here would silently turn the fresh path into recovery authority.
			fixture.writeTarget(t, 0, fixture.verifications[0].Descriptor())
		}
	}

	_, err := fixture.executor(t, copier).ExecuteGrantedCheckpointSeal(
		context.Background(),
		fixture.input(t))
	if !errors.Is(err, ErrOwnerSealDescriptorMediaConflict) ||
		!errors.Is(err, ErrOwnerSealQuarantineRequired) ||
		!errors.Is(err, ErrOwnerSealRecoveryRequired) ||
		!errors.Is(err, ErrOwnerDeviceGroupReopenRequired) {
		t.Fatalf("post-preflight target conflict = %v", err)
	}
	var descriptorWrites int
	for _, storage := range fixture.storages {
		for _, event := range storage.events {
			if event.kind == "write" &&
				event.offset >= fixture.geometry.DescriptorRegionBase &&
				event.offset < fixture.geometry.ContentRegionBase {
				descriptorWrites++
			}
		}
	}
	if descriptorWrites != 0 || fixture.storages["device-b"].syncCalls != 0 {
		t.Fatalf("fresh target conflict performed descriptor writes/barrier Sync: %d/%d",
			descriptorWrites,
			fixture.storages["device-b"].syncCalls)
	}
	if copier.calls != int(fixture.plan.TotalPages()) || copier.closeCalls != 1 {
		t.Fatalf("conflict pass-1 DML/Close = %d/%d", copier.calls, copier.closeCalls)
	}
	fixture.reopen(t)
	if record := fixture.record(t); record.State != OwnerAllocationCommitting {
		t.Fatalf("fresh target conflict durable state = %d, want COMMITTING", record.State)
	}
}

func TestOwnerSealExecutorFreshInitialDescriptorPreflightClassification(t *testing.T) {
	t.Run("stable-media-conflict-quarantines-before-DML", func(t *testing.T) {
		fixture := newPersistedOwnerSealExecutorTestFixture(t)
		fixture.writeRawDescriptor(t, 0, make([]byte, PageDescriptorBytes))
		fixture.resetTracking()
		copier := &ownerSealExecutorTestCopier{trace: fixture.trace}

		_, err := fixture.executor(t, copier).ExecuteGrantedCheckpointSeal(
			context.Background(),
			fixture.input(t))
		if !errors.Is(err, ErrOwnerSealDescriptorMediaConflict) ||
			!errors.Is(err, ErrOwnerSealQuarantineRequired) ||
			errors.Is(err, ErrOwnerSealRecoveryRequired) ||
			errors.Is(err, ErrOwnerDeviceGroupReopenRequired) {
			t.Fatalf("initial descriptor conflict classification = %v", err)
		}
		if fixture.totalWrites() != 0 || fixture.totalSyncs() != 0 ||
			fixture.totalMutations() != 0 || fixture.source.openCalls != 0 ||
			copier.calls != 0 || copier.closeCalls != 0 {
			t.Fatalf("initial conflict I/O = writes %d Syncs %d mutations %d opens %d DML %d Close %d",
				fixture.totalWrites(), fixture.totalSyncs(), fixture.totalMutations(),
				fixture.source.openCalls, copier.calls, copier.closeCalls)
		}
		if record := fixture.record(t); record.State != OwnerAllocationGranted {
			t.Fatalf("initial conflict state = %d, want GRANTED", record.State)
		}
	})

	t.Run("operational-read-failure-requires-reopen-before-DML", func(t *testing.T) {
		fixture := newPersistedOwnerSealExecutorTestFixture(t)
		target := fixture.targets[0]
		offset, err := fixture.geometry.DescriptorOffset(target.DataPageIndex())
		if err != nil {
			t.Fatalf("DescriptorOffset: %v", err)
		}
		storage := fixture.storages[target.Device().DeviceUUID]
		fixture.resetTracking()
		storage.failReadOffset = &offset
		copier := &ownerSealExecutorTestCopier{trace: fixture.trace}

		_, err = fixture.executor(t, copier).ExecuteGrantedCheckpointSeal(
			context.Background(),
			fixture.input(t))
		if !errors.Is(err, ErrOwnerSealDescriptorStorage) ||
			!errors.Is(err, ErrDeviceMetadataStorage) ||
			!errors.Is(err, ErrOwnerDeviceGroupReopenRequired) ||
			errors.Is(err, ErrOwnerSealRecoveryRequired) ||
			errors.Is(err, ErrOwnerSealQuarantineRequired) ||
			errors.Is(err, ErrOwnerDeviceGroupOfflineRequired) {
			t.Fatalf("initial descriptor read classification = %v", err)
		}
		if !fixture.group.executionState.reopenRequired ||
			fixture.group.executionState.offlineRequired ||
			fixture.totalWrites() != 0 || fixture.totalSyncs() != 0 ||
			fixture.totalMutations() != 0 || fixture.source.openCalls != 0 ||
			copier.calls != 0 || copier.closeCalls != 0 {
			t.Fatalf("initial read failure state/I-O = reopen %t offline %t writes %d Syncs %d mutations %d opens %d DML %d Close %d",
				fixture.group.executionState.reopenRequired,
				fixture.group.executionState.offlineRequired,
				fixture.totalWrites(), fixture.totalSyncs(), fixture.totalMutations(),
				fixture.source.openCalls, copier.calls, copier.closeCalls)
		}
		storage.failReadOffset = nil
		fixture.reopen(t)
		if record := fixture.record(t); record.State != OwnerAllocationGranted {
			t.Fatalf("initial read failure state = %d, want GRANTED", record.State)
		}
	})
}

func TestOwnerSealExecutorPassTwoSealMismatchMarksQuarantine(t *testing.T) {
	fixture := newPersistedOwnerSealExecutorTestFixture(t)
	target := fixture.targets[0]
	fixture.source.mutateOpenCall = 2
	fixture.source.mutateDevice = target.Device().DeviceUUID
	fixture.source.mutatePage = target.DataPageIndex()
	copier := &ownerSealExecutorTestCopier{trace: fixture.trace}

	_, err := fixture.executor(t, copier).ExecuteGrantedCheckpointSeal(
		context.Background(),
		fixture.input(t))
	if !errors.Is(err, ErrOwnerSealQuarantineRequired) ||
		!errors.Is(err, ErrOwnerSealRecoveryRequired) ||
		!errors.Is(err, ErrOwnerDeviceGroupReopenRequired) {
		t.Fatalf("H2 mismatch error = %v", err)
	}
	if copier.closeCalls != 1 {
		t.Fatalf("H2 mismatch Copier Close calls = %d", copier.closeCalls)
	}
	fixture.reopen(t)
	if record := fixture.record(t); record.State != OwnerAllocationCommitting {
		t.Fatalf("H2 mismatch durable state = %d, want COMMITTING", record.State)
	}
}

func TestOwnerSealExecutorPostSyncMismatchKeepsLatchAndCommitting(t *testing.T) {
	fixture := newPersistedOwnerSealExecutorTestFixture(t)
	target := fixture.targets[0]
	fixture.source.mutateOpenCall = 3
	fixture.source.mutateDevice = target.Device().DeviceUUID
	fixture.source.mutatePage = target.DataPageIndex()
	copier := &ownerSealExecutorTestCopier{trace: fixture.trace}

	_, err := fixture.executor(t, copier).ExecuteGrantedCheckpointSeal(
		context.Background(),
		fixture.input(t))
	if !errors.Is(err, ErrOwnerSealDescriptorDispositionChanged) ||
		!errors.Is(err, ErrOwnerSealQuarantineRequired) ||
		!errors.Is(err, ErrOwnerSealRecoveryRequired) ||
		!errors.Is(err, ErrOwnerDeviceGroupReopenRequired) {
		t.Fatalf("post-Sync mismatch error = %v", err)
	}
	if !fixture.group.executionState.reopenRequired {
		t.Fatal("post-Sync mismatch cleared the fail-closed latch")
	}
	if copier.closeCalls != 1 {
		t.Fatalf("post-Sync mismatch Copier Close calls = %d", copier.closeCalls)
	}
	fixture.reopen(t)
	if record := fixture.record(t); record.State != OwnerAllocationCommitting {
		t.Fatalf("post-Sync mismatch durable state = %d, want COMMITTING", record.State)
	}
}

func TestOwnerSealExecutorCopierCloseIsGateAndPreservesMultipleCauses(t *testing.T) {
	t.Run("terminal-gate", func(t *testing.T) {
		fixture := newPersistedOwnerSealExecutorTestFixture(t)
		closeFailure := errors.New("injected Copier Close failure")
		copier := &ownerSealExecutorTestCopier{
			trace:    fixture.trace,
			closeErr: closeFailure,
		}
		_, err := fixture.executor(t, copier).ExecuteGrantedCheckpointSeal(
			context.Background(),
			fixture.input(t))
		if !errors.Is(err, closeFailure) ||
			!errors.Is(err, ErrOwnerSealRecoveryRequired) ||
			!errors.Is(err, ErrOwnerDeviceGroupReopenRequired) {
			t.Fatalf("terminal Close failure = %v", err)
		}
		if copier.closeCalls != 1 || !fixture.group.executionState.reopenRequired ||
			(*fixture.trace)[len(*fixture.trace)-1] != "copier-close" {
			t.Fatalf("terminal Close gate state = calls %d latch %t trace tail %q",
				copier.closeCalls,
				fixture.group.executionState.reopenRequired,
				(*fixture.trace)[len(*fixture.trace)-1])
		}
		fixture.reopen(t)
		if record := fixture.record(t); record.State != OwnerAllocationCommitting {
			t.Fatalf("Close failure durable state = %d, want COMMITTING", record.State)
		}
	})

	t.Run("Go-1.17-multiple-cause", func(t *testing.T) {
		fixture := newPersistedOwnerSealExecutorTestFixture(t)
		primary := errors.New("injected primary DML failure")
		secondary := errors.New("injected secondary Close failure")
		copier := &ownerSealExecutorTestCopier{
			trace:    fixture.trace,
			failCall: int(fixture.plan.TotalPages()) + 2,
			failErr:  primary,
			closeErr: secondary,
		}
		_, err := fixture.executor(t, copier).ExecuteGrantedCheckpointSeal(
			context.Background(),
			fixture.input(t))
		if !errors.Is(err, primary) || !errors.Is(err, secondary) ||
			!errors.Is(err, ErrOwnerSealRecoveryRequired) || copier.closeCalls != 1 {
			t.Fatalf("combined failure = %v; Close calls=%d", err, copier.closeCalls)
		}
	})
}

func TestOwnerSealExecutorDurableAllocatorContradictionSticksOffline(t *testing.T) {
	fixture := newPersistedOwnerSealExecutorTestFixture(t)
	target := fixture.targets[0]
	for index := range fixture.group.devices {
		device := &fixture.group.devices[index]
		if device.deviceUUID != target.Device().DeviceUUID {
			continue
		}
		page := target.DataPageIndex()
		device.metadata.allocator.allocationBitmap[page/8] &^=
			byte(1) << uint(page%8)
		device.metadata.allocator.AllocatedPageCount--
	}
	copier := &ownerSealExecutorTestCopier{trace: fixture.trace}
	_, err := fixture.executor(t, copier).ExecuteGrantedCheckpointSeal(
		context.Background(),
		fixture.input(t))
	if !errors.Is(err, ErrOwnerSealDescriptorAllocatorContradiction) ||
		!errors.Is(err, ErrOwnerSealDurableContradiction) ||
		!errors.Is(err, ErrOwnerDeviceGroupOfflineRequired) {
		t.Fatalf("allocator contradiction = %v", err)
	}
	if !fixture.group.executionState.offlineRequired || copier.calls != 0 ||
		fixture.source.openCalls != 0 {
		t.Fatalf("offline/calls/opens = %t/%d/%d",
			fixture.group.executionState.offlineRequired,
			copier.calls,
			fixture.source.openCalls)
	}
	if _, _, err := fixture.group.PlannerInputs(); !errors.Is(
		err,
		ErrOwnerDeviceGroupOfflineRequired) {
		t.Fatalf("sticky OFFLINE PlannerInputs = %v", err)
	}
}

func TestOwnerSealExecutorDurableMetadataAuthoritySticksOffline(t *testing.T) {
	t.Run("post-sync-owner-split-brain", func(t *testing.T) {
		fixture := newPersistedOwnerSealExecutorTestFixture(t)
		copier := &ownerSealExecutorTestCopier{trace: fixture.trace}
		copier.onCall = func(call int) {
			if call != int(fixture.plan.TotalPages())+1 {
				return
			}
			current, err := fixture.group.ownerStateLocked()
			if err != nil {
				t.Fatalf("select COMMITTING for split-brain injection: %v", err)
			}
			records := current.Records()
			records[0].SharingPolicyID = "sharing-split-brain"
			conflict := ownerReserveExecutorSnapshotWithRecords(t, current, records)
			wire, err := CanonicalOwnerStateBytes(conflict, fixture.geometry)
			if err != nil {
				t.Fatalf("canonical split-brain Owner state: %v", err)
			}
			activeSlot, _, present := fixture.group.anchor.ActiveOwnerState()
			if !present {
				t.Fatal("ANCHOR has no active COMMITTING state")
			}
			conflictOffset, err := ownerStateSlotOffset(
				fixture.geometry,
				otherOwnerStateSlot(activeSlot))
			if err != nil {
				t.Fatalf("split-brain Owner slot offset: %v", err)
			}
			fixture.storages[fixture.group.bootstrap.AnchorDeviceUUID].rawWrite(
				conflictOffset,
				wire)
		}

		_, err := fixture.executor(t, copier).ExecuteGrantedCheckpointSeal(
			context.Background(),
			fixture.input(t))
		if !errors.Is(err, ErrOwnerStateSplitBrain) ||
			!errors.Is(err, ErrOwnerSealDurableContradiction) ||
			!errors.Is(err, ErrOwnerDeviceGroupOfflineRequired) ||
			errors.Is(err, ErrOwnerSealRecoveryRequired) {
			t.Fatalf("post-Sync split-brain classification = %v", err)
		}
		if !fixture.group.executionState.offlineRequired ||
			!fixture.group.executionState.reopenRequired || copier.closeCalls != 1 {
			t.Fatalf("split-brain offline/reopen/Close = %t/%t/%d",
				fixture.group.executionState.offlineRequired,
				fixture.group.executionState.reopenRequired,
				copier.closeCalls)
		}
	})

	t.Run("entry-cached-owner-bootstrap-mismatch", func(t *testing.T) {
		fixture := newPersistedOwnerSealExecutorTestFixture(t)
		fixture.group.anchor.ownerState.CurrentOwnerID = "foreign-owner"
		fixture.resetTracking()
		copier := &ownerSealExecutorTestCopier{trace: fixture.trace}

		_, err := fixture.executor(t, copier).ExecuteGrantedCheckpointSeal(
			context.Background(),
			fixture.input(t))
		if !errors.Is(err, ErrOwnerDeviceGroupMismatch) ||
			!errors.Is(err, ErrOwnerSealDurableContradiction) ||
			!errors.Is(err, ErrOwnerDeviceGroupOfflineRequired) {
			t.Fatalf("entry Owner/bootstrap mismatch classification = %v", err)
		}
		if !fixture.group.executionState.offlineRequired ||
			fixture.source.openCalls != 0 || copier.calls != 0 ||
			fixture.totalWrites() != 0 || fixture.totalSyncs() != 0 {
			t.Fatal("entry Owner/bootstrap mismatch did not fail before I/O")
		}
	})

	t.Run("durable-category-table", func(t *testing.T) {
		for _, category := range []error{
			ErrOwnerStateSplitBrain,
			ErrSuperblockSplitBrain,
			ErrDeviceMetadataGeometryMismatch,
			ErrDeviceMetadataRoleMismatch,
			ErrDeviceMetadataSizeMismatch,
			ErrOwnerStateBootstrapMismatch,
			ErrNoValidSuperblock,
			ErrNoValidOwnerState,
			ErrSuperblockSnapshotMismatch,
			ErrAllocatorSnapshotMismatch,
		} {
			if !ownerSealFailureRequiresOffline(fmt.Errorf("wrapped: %w", category)) {
				t.Fatalf("durable category %v does not require OFFLINE", category)
			}
		}
		for _, operational := range []error{
			ErrDeviceMetadataStorage,
			ErrDeviceMetadataOwnerStateReadLimit,
			ErrDeviceMetadataReopenRequired,
			ErrOwnerDeviceGroupReopenRequired,
		} {
			if ownerSealFailureRequiresOffline(fmt.Errorf("wrapped: %w", operational)) {
				t.Fatalf("operational category %v unexpectedly requires OFFLINE", operational)
			}
		}
	})
}

func TestOwnerSealExecutorExactOwnerIdentityContradictionSticksOffline(t *testing.T) {
	fixture := newPersistedOwnerSealExecutorTestFixture(t)
	copier := &ownerSealExecutorTestCopier{trace: fixture.trace}
	copier.onCall = func(call int) {
		if call == 1 {
			// Simulate an in-process authority bypass after planning. The exact
			// source snapshot check before the first durable transition must detect
			// this even though the media copy pass itself completes.
			fixture.group.anchor.ownerState.CurrentOwnerID = "substituted-owner"
		}
	}
	_, err := fixture.executor(t, copier).ExecuteGrantedCheckpointSeal(
		context.Background(),
		fixture.input(t))
	if !errors.Is(err, ErrOwnerSealDurableContradiction) ||
		!errors.Is(err, ErrOwnerDeviceGroupOfflineRequired) {
		t.Fatalf("exact Owner identity contradiction = %v", err)
	}
	if !fixture.group.executionState.offlineRequired || copier.closeCalls != 1 {
		t.Fatalf("identity contradiction offline/Close = %t/%d",
			fixture.group.executionState.offlineRequired,
			copier.closeCalls)
	}
	for _, storage := range fixture.storages {
		if storage.writeCalls != 0 || storage.syncCalls != 0 {
			t.Fatalf("identity contradiction mutated %q: writes=%d Syncs=%d",
				storage.deviceUUID, storage.writeCalls, storage.syncCalls)
		}
	}
}

func TestOwnerSealExecutorRecoverWithoutCommittingIsReadOnly(t *testing.T) {
	fixture := newPersistedOwnerSealExecutorTestFixture(t)
	copier := &ownerSealExecutorTestCopier{trace: fixture.trace}
	fixture.resetTracking()
	*fixture.trace = nil
	_, err := fixture.executor(t, copier).RecoverCommittingCheckpointSeal(
		context.Background())
	if !errors.Is(err, ErrOwnerSealNoCommitting) {
		t.Fatalf("recovery without COMMITTING = %v", err)
	}
	if fixture.totalWrites() != 0 || fixture.totalSyncs() != 0 ||
		fixture.source.openCalls != 0 || copier.calls != 0 || copier.closeCalls != 0 {
		t.Fatalf("empty recovery I/O = writes %d Syncs %d opens %d DML %d Close %d",
			fixture.totalWrites(),
			fixture.totalSyncs(),
			fixture.source.openCalls,
			copier.calls,
			copier.closeCalls)
	}
}

func TestOwnerSealExecutorRetainsOnlyBoundCompactDependencies(t *testing.T) {
	typeOfExecutor := reflect.TypeOf(OwnerSealExecutor{})
	for index := 0; index < typeOfExecutor.NumField(); index++ {
		field := typeOfExecutor.Field(index)
		if field.Type.Kind() == reflect.Slice || field.Type.Kind() == reflect.Map {
			t.Fatalf("executor retains per-page-capable field %q of type %s",
				field.Name, field.Type)
		}
		lower := strings.ToLower(field.Name)
		if strings.Contains(lower, "crc") || strings.Contains(lower, "page") ||
			strings.Contains(lower, "descriptor") || strings.Contains(lower, "view") {
			t.Fatalf("executor retains unexpected data-plane field %q", field.Name)
		}
	}
}

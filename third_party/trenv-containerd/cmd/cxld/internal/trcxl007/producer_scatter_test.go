package trcxl007

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/containerd/containerd/third_party/trenv-containerd/cmd/cxld/internal/trcxl007dml"
	"github.com/containerd/containerd/third_party/trenv-containerd/pkg/cxlcheckpoint"
)

var _ ProducerScatterPageCopier = trcxl007dml.Copier(nil)

type producerScatterTestFixture struct {
	owner       OwnerStateSnapshot
	initial     cxlcheckpoint.InitialPublicationV7Plan
	plan        ProducerScatterPlan
	memory      []byte
	artifact    []byte
	restoreBlob []byte
}

type producerScatterTestPageRequest struct {
	deviceUUID string
	pageIndex  uint64
}

type producerScatterTestDestination struct {
	expectedBindings    map[string]ProducerScatterDeviceBinding
	pages               map[string]map[uint64][]byte
	events              []string
	pageRequests        []producerScatterTestPageRequest
	prepareFailure      string
	extentFailureCall   int
	wrongLengthCall     int
	actualAlias         bool
	declaredAlias       bool
	zeroBackingCall     int
	overflowBackingCall int
	aliasBytes          []byte
	syncFailure         string
	extentCalls         int
}

func (destination *producerScatterTestDestination) PrepareDevice(
	binding ProducerScatterDeviceBinding,
) error {
	destination.events = append(destination.events, "prepare:"+binding.DeviceUUID)
	want, found := destination.expectedBindings[binding.DeviceUUID]
	if !found || want != binding {
		return fmt.Errorf("unexpected binding %#v", binding)
	}
	if destination.prepareFailure == binding.DeviceUUID {
		return errors.New("injected prepare failure")
	}
	return nil
}

func (destination *producerScatterTestDestination) WritableExtent(
	binding ProducerScatterDeviceBinding,
	startDataPageIndex uint64,
	pageCount uint64,
) (ProducerScatterWritableExtent, error) {
	destination.extentCalls++
	destination.events = append(destination.events,
		fmt.Sprintf("extent:%s:%d:%d", binding.DeviceUUID, startDataPageIndex, pageCount))
	if destination.extentFailureCall > 0 && destination.extentCalls == destination.extentFailureCall {
		return ProducerScatterWritableExtent{}, errors.New("injected extent failure")
	}
	end, ok := checkedAdd(startDataPageIndex, pageCount)
	if !ok || end > binding.DataPageCount {
		return ProducerScatterWritableExtent{}, errors.New("extent exceeds binding")
	}
	length := int(pageCount * uint64(ContentPageBytes))
	var extent []byte
	if destination.actualAlias {
		if len(destination.aliasBytes) < length {
			destination.aliasBytes = make([]byte, 4*ContentPageBytes)
		}
		extent = destination.aliasBytes[:length]
	} else {
		extent = make([]byte, length)
	}
	if destination.wrongLengthCall > 0 && destination.extentCalls == destination.wrongLengthCall {
		extent = extent[:len(extent)-1]
	}
	device := destination.pages[binding.DeviceUUID]
	if device == nil {
		device = make(map[uint64][]byte)
		destination.pages[binding.DeviceUUID] = device
	}
	if len(extent) == length {
		for page := uint64(0); page < pageCount; page++ {
			pageIndex := startDataPageIndex + page
			start := int(page) * ContentPageBytes
			device[pageIndex] = extent[start : start+ContentPageBytes]
			destination.pageRequests = append(destination.pageRequests,
				producerScatterTestPageRequest{deviceUUID: binding.DeviceUUID, pageIndex: pageIndex})
		}
	}
	backingID := sha256.Sum256([]byte("destination-" + binding.DeviceUUID))
	backingOffset := startDataPageIndex * uint64(ContentPageBytes)
	if destination.declaredAlias {
		backingID = sha256.Sum256([]byte("declared-shared-backing"))
		backingOffset = 0
	}
	if destination.zeroBackingCall > 0 && destination.extentCalls == destination.zeroBackingCall {
		backingID = [sha256.Size]byte{}
	}
	if destination.overflowBackingCall > 0 && destination.extentCalls == destination.overflowBackingCall {
		backingOffset = ^uint64(0)
	}
	return ProducerScatterWritableExtent{
		Bytes: extent,
		Backing: ProducerScatterBackingRange{
			BackingID:  backingID,
			ByteOffset: backingOffset,
			ByteLength: uint64(length),
		},
	}, nil
}

func (destination *producerScatterTestDestination) SyncDevice(
	binding ProducerScatterDeviceBinding,
) error {
	destination.events = append(destination.events, "sync:"+binding.DeviceUUID)
	if destination.syncFailure == binding.DeviceUUID {
		return errors.New("injected sync failure")
	}
	return nil
}

type producerScatterTestCPUCopier struct {
	destination *producerScatterTestDestination
	calls       int
	failCall    int
	zeroCall    int
	cancel      context.CancelFunc
	closeCalls  int
}

func (copier *producerScatterTestCPUCopier) CopyPage(dst, src []byte) (uint32, error) {
	copier.calls++
	if copier.destination != nil {
		copier.destination.events = append(copier.destination.events,
			fmt.Sprintf("copy:%d", copier.calls))
	}
	copy(dst, src)
	if copier.cancel != nil {
		copier.cancel()
		copier.cancel = nil
	}
	if copier.failCall > 0 && copier.calls == copier.failCall {
		return 0, errors.New("injected COPY_CRC failure after destination mutation")
	}
	if copier.zeroCall > 0 && copier.calls == copier.zeroCall {
		return 0, nil
	}
	return crc32.Checksum(src, crc32.MakeTable(crc32.Castagnoli)), nil
}

func (copier *producerScatterTestCPUCopier) Close() error {
	copier.closeCalls++
	return nil
}

type producerScatterTestReaderAt struct {
	data       []byte
	fullEOF    bool
	shortFirst bool
	backing    ProducerScatterBackingRange
	requests   []struct {
		offset int64
		length int
	}
}

type producerScatterTestNilContext struct{}

func (*producerScatterTestNilContext) Deadline() (time.Time, bool)   { return time.Time{}, false }
func (*producerScatterTestNilContext) Done() <-chan struct{}         { return nil }
func (*producerScatterTestNilContext) Err() error                    { return nil }
func (*producerScatterTestNilContext) Value(interface{}) interface{} { return nil }

func (reader *producerScatterTestReaderAt) ProducerScatterBackingRange() ProducerScatterBackingRange {
	if reader == nil {
		return ProducerScatterBackingRange{}
	}
	return reader.backing
}

func (reader *producerScatterTestReaderAt) ReadAt(buffer []byte, offset int64) (int, error) {
	reader.requests = append(reader.requests, struct {
		offset int64
		length int
	}{offset: offset, length: len(buffer)})
	if offset < 0 || uint64(offset) > uint64(len(reader.data)) ||
		uint64(len(buffer)) > uint64(len(reader.data))-uint64(offset) {
		return 0, io.EOF
	}
	if reader.shortFirst && len(buffer) > 0 {
		reader.shortFirst = false
		n := len(buffer) - 1
		copy(buffer[:n], reader.data[int(offset):int(offset)+n])
		return n, io.EOF
	}
	copy(buffer, reader.data[int(offset):int(offset)+len(buffer)])
	if reader.fullEOF && int(offset)+len(buffer) == len(reader.data) {
		return len(buffer), io.EOF
	}
	return len(buffer), nil
}

func TestProducerScatterPlanExactFragmentedTwoDAXJoinAndDefensiveCopies(t *testing.T) {
	fixture := newProducerScatterTestFixture(t)
	if err := fixture.plan.Validate(); err != nil {
		t.Fatalf("plan.Validate: %v", err)
	}
	if fixture.plan.CheckpointID() != "checkpoint-7" ||
		fixture.plan.AllocationRecordID() != 29 || fixture.plan.OwnerID() != "owner-a" ||
		fixture.plan.ClusterID() != "cluster-7" || fixture.plan.OwnerGroupID() != "owner-group-7" ||
		fixture.plan.AnchorDeviceUUID() != "device-a" ||
		fixture.plan.OwnerEpoch() != 11 || fixture.plan.TotalPages() != 17 {
		t.Fatalf("plan identity = checkpoint=%q allocation=%d cluster/group=%q/%q Owner=%q/%d pages=%d",
			fixture.plan.CheckpointID(), fixture.plan.AllocationRecordID(),
			fixture.plan.ClusterID(), fixture.plan.OwnerGroupID(), fixture.plan.OwnerID(),
			fixture.plan.OwnerEpoch(), fixture.plan.TotalPages())
	}
	devices := fixture.plan.Devices()
	if len(devices) != 2 || devices[0].DeviceUUID != "device-a" ||
		devices[1].DeviceUUID != "device-b" {
		t.Fatalf("devices = %#v", devices)
	}
	runs := fixture.plan.ExtentRuns()
	wantRuns := []ProducerScatterExtentRun{
		{DeviceIndex: 0, StartDataPageIndex: 10, LogicalPageStart: 0, PageCount: 2},
		{DeviceIndex: 1, StartDataPageIndex: 20, LogicalPageStart: 2, PageCount: 3},
		{DeviceIndex: 0, StartDataPageIndex: 30, LogicalPageStart: 5, PageCount: 4},
		{DeviceIndex: 1, StartDataPageIndex: 40, LogicalPageStart: 9, PageCount: 1},
		{DeviceIndex: 0, StartDataPageIndex: 40, LogicalPageStart: 10, PageCount: 3},
		{DeviceIndex: 1, StartDataPageIndex: 50, LogicalPageStart: 13, PageCount: 4},
	}
	if !reflect.DeepEqual(runs, wantRuns) {
		t.Fatalf("extent runs = %#v, want %#v", runs, wantRuns)
	}
	objects := fixture.plan.Objects()
	if len(objects) != 9 || objects[0].Kind != cxlcheckpoint.ContentMemoryPayloadV7 ||
		objects[8].Kind != cxlcheckpoint.ContentPublicationV7 {
		t.Fatalf("objects = %#v", objects)
	}

	devices[0].DeviceUUID = "mutated"
	runs[0].PageCount = 999
	objects[0].CapacityPages = 999
	fixture.initial.ObjectWrites[0].CapacityPages = 999
	fixture.initial.Publication.InitialAllocation.Extents[0].PageCount = 999
	fixture.owner.CurrentOwnerID = "mutated-owner-copy"
	if err := fixture.plan.Validate(); err != nil {
		t.Fatalf("caller/accessor mutation reached detached plan: %v", err)
	}
	if fixture.plan.Devices()[0].DeviceUUID != "device-a" ||
		fixture.plan.ExtentRuns()[0].PageCount != 2 || fixture.plan.Objects()[0].CapacityPages != 3 {
		t.Fatal("plan accessors did not return defensive copies")
	}
}

func TestProducerScatterPlanCommitsOwnerGroupAnchor(t *testing.T) {
	fixture := newProducerScatterTestFixture(t)
	changedOwner := fixture.owner.Clone()
	changedOwner.AnchorDeviceUUID = "device-b"
	if err := changedOwner.Validate(); err != nil {
		t.Fatalf("changed anchor Owner state: %v", err)
	}
	changed, err := BuildProducerScatterPlan(changedOwner, 29, fixture.initial)
	if err != nil {
		t.Fatalf("BuildProducerScatterPlan changed anchor: %v", err)
	}
	if changed.AnchorDeviceUUID() != "device-b" ||
		fixture.plan.integritySHA256 == changed.integritySHA256 {
		t.Fatal("different valid Owner-group anchor yielded an indistinguishable plan")
	}
}

func TestProducerScatterPlanCommitsCompleteGrantedProducerIdentity(t *testing.T) {
	fixture := newProducerScatterTestFixture(t)
	changedOwner := fixture.owner.Clone()
	changedOwner.records[0].ProducerID = "different-producer"
	changedOwner.records[0].AuthorityEvidence.ProducerCapabilitySHA256 =
		sha256.Sum256([]byte("different-producer-capability"))
	if err := changedOwner.Validate(); err != nil {
		t.Fatalf("changed Owner state: %v", err)
	}
	changed, err := BuildProducerScatterPlan(changedOwner, 29, fixture.initial)
	if err != nil {
		t.Fatalf("BuildProducerScatterPlan changed grant: %v", err)
	}
	if fixture.plan.GrantRecordSHA256() == ([sha256.Size]byte{}) ||
		fixture.plan.GrantRecordSHA256() == changed.GrantRecordSHA256() ||
		fixture.plan.integritySHA256 == changed.integritySHA256 {
		t.Fatal("different Producer/capability yielded an indistinguishable scatter grant")
	}
}

func TestProducerScatterPlanRejectsEveryOwnerPublicationSubstitution(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*OwnerStateSnapshot, *cxlcheckpoint.InitialPublicationV7Plan)
	}{
		{"state", func(owner *OwnerStateSnapshot, _ *cxlcheckpoint.InitialPublicationV7Plan) {
			owner.records[0].State = OwnerAllocationCommitted
		}},
		{"checkpoint", func(owner *OwnerStateSnapshot, _ *cxlcheckpoint.InitialPublicationV7Plan) {
			owner.records[0].CheckpointID = "substituted"
		}},
		{"dedup", func(owner *OwnerStateSnapshot, _ *cxlcheckpoint.InitialPublicationV7Plan) {
			owner.records[0].DedupDomainID = "substituted"
		}},
		{"sharing", func(owner *OwnerStateSnapshot, _ *cxlcheckpoint.InitialPublicationV7Plan) {
			owner.records[0].SharingPolicyID = "substituted"
		}},
		{"Owner", func(owner *OwnerStateSnapshot, _ *cxlcheckpoint.InitialPublicationV7Plan) {
			owner.CurrentOwnerID = "owner-substituted"
		}},
		{"allocation", func(_ *OwnerStateSnapshot, plan *cxlcheckpoint.InitialPublicationV7Plan) {
			plan.Publication.InitialAllocation.AllocationRecordID++
		}},
		{"object-demand", func(owner *OwnerStateSnapshot, _ *cxlcheckpoint.InitialPublicationV7Plan) {
			owner.records[0].ContentDemands[0].ByteLength--
		}},
		{"extent", func(owner *OwnerStateSnapshot, _ *cxlcheckpoint.InitialPublicationV7Plan) {
			owner.records[0].Fragments[0].Extents[0].StartDataPageIndex++
		}},
		{"device-count", func(_ *OwnerStateSnapshot, plan *cxlcheckpoint.InitialPublicationV7Plan) {
			plan.Publication.InitialAllocation.Devices[0].DataPageCount++
		}},
		{"zero-producer-capability", func(owner *OwnerStateSnapshot, _ *cxlcheckpoint.InitialPublicationV7Plan) {
			owner.records[0].AuthorityEvidence.ProducerCapabilitySHA256 = [sha256.Size]byte{}
		}},
		{"zero-publication-authority", func(owner *OwnerStateSnapshot, _ *cxlcheckpoint.InitialPublicationV7Plan) {
			owner.records[0].AuthorityEvidence.PublicationAuthoritySHA256 = [sha256.Size]byte{}
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newProducerScatterTestFixture(t)
			owner := fixture.owner.Clone()
			plan := fixture.initial
			test.mutate(&owner, &plan)
			_, err := BuildProducerScatterPlan(owner, 29, plan)
			if !errors.Is(err, ErrInvalidProducerScatterPlan) {
				t.Fatalf("BuildProducerScatterPlan error = %v", err)
			}
		})
	}
}

func TestProducerScatterRejectsMutatedDetachedPlanBeforeAnyDestinationCall(t *testing.T) {
	fixture := newProducerScatterTestFixture(t)
	fixture.plan.runs[0].PageCount++
	destination := newProducerScatterTestDestination(fixture.plan)
	copier := &producerScatterTestCPUCopier{destination: destination}
	result, err := ExecuteProducerScatter(context.Background(), ProducerScatterExecutionRequest{
		Plan: fixture.plan, Sources: fixture.sources(nil), Destination: destination, Copier: copier,
	})
	if !errors.Is(err, ErrInvalidProducerScatterPlan) ||
		errors.Is(err, ErrProducerScatterCancellationRequired) {
		t.Fatalf("mutated plan error = %v", err)
	}
	if len(destination.events) != 0 || copier.calls != 0 || len(result.CRCVector().Bytes()) != 0 {
		t.Fatalf("mutated plan reached destination/copy/result: events=%#v copies=%d", destination.events, copier.calls)
	}
}

func TestProducerScatterExecutesAllCapacityPagesThenCanonicalSync(t *testing.T) {
	fixture := newProducerScatterTestFixture(t)
	destination := newProducerScatterTestDestination(fixture.plan)
	copier := &producerScatterTestCPUCopier{destination: destination}
	result, err := ExecuteProducerScatter(context.Background(), ProducerScatterExecutionRequest{
		Plan:        fixture.plan,
		Sources:     fixture.sources(nil),
		Destination: destination,
		Copier:      copier,
	})
	if err != nil {
		t.Fatalf("ExecuteProducerScatter: %v", err)
	}
	if result.CheckpointID() != "checkpoint-7" || result.AllocationRecordID() != 29 {
		t.Fatalf("result identity = %q/%d", result.CheckpointID(), result.AllocationRecordID())
	}
	if copier.calls != 17 || destination.extentCalls != 6 {
		t.Fatalf("copy/extent calls = %d/%d, want 17/6", copier.calls, destination.extentCalls)
	}
	if copier.closeCalls != 0 {
		t.Fatalf("executor closed caller-owned copier %d times", copier.closeCalls)
	}
	wantRequests := producerScatterTestExpectedPageRequests(fixture.plan)
	if !reflect.DeepEqual(destination.pageRequests, wantRequests) {
		t.Fatalf("page requests = %#v, want %#v", destination.pageRequests, wantRequests)
	}
	if got := destination.events[:2]; !reflect.DeepEqual(got, []string{"prepare:device-a", "prepare:device-b"}) {
		t.Fatalf("initial prepare barrier = %#v", got)
	}
	firstSync := -1
	firstCopy := -1
	lastExtent := -1
	lastCopy := -1
	for index, event := range destination.events {
		if strings.HasPrefix(event, "copy:") {
			if firstCopy == -1 {
				firstCopy = index
			}
			lastCopy = index
		}
		if strings.HasPrefix(event, "extent:") {
			lastExtent = index
		}
		if firstSync == -1 && strings.HasPrefix(event, "sync:") {
			firstSync = index
		}
	}
	if firstCopy <= lastExtent || lastCopy < 0 || firstSync <= lastCopy ||
		!reflect.DeepEqual(destination.events[len(destination.events)-2:],
			[]string{"sync:device-a", "sync:device-b"}) {
		t.Fatalf("copy/sync barrier events = %#v", destination.events)
	}

	expectedLogical := fixture.expectedLogicalPages(t)
	vector := result.CRCVector()
	if vector.TotalPages() != 17 || len(vector.Bytes()) != 17*ProducerScatterCRCBytesPerPage {
		t.Fatalf("CRC vector shape = pages %d bytes %d", vector.TotalPages(), len(vector.Bytes()))
	}
	for logicalPage, request := range wantRequests {
		gotPage := destination.pages[request.deviceUUID][request.pageIndex]
		wantPage := expectedLogical[logicalPage]
		if !bytes.Equal(gotPage, wantPage) {
			t.Fatalf("logical page %d at %s/%d differs", logicalPage, request.deviceUUID, request.pageIndex)
		}
		wantCRC := crc32.Checksum(wantPage, crc32.MakeTable(crc32.Castagnoli))
		gotCRC, crcErr := vector.CRC32C(uint64(logicalPage))
		if crcErr != nil || gotCRC != wantCRC {
			t.Fatalf("CRC[%d] = %#08x, %v, want %#08x", logicalPage, gotCRC, crcErr, wantCRC)
		}
		wire := vector.Bytes()[logicalPage*4 : logicalPage*4+4]
		if binary.LittleEndian.Uint32(wire) != wantCRC {
			t.Fatalf("raw CRC[%d] is not little-endian", logicalPage)
		}
	}
	zeroCRC := crc32.Checksum(make([]byte, ContentPageBytes), crc32.MakeTable(crc32.Castagnoli))
	if zeroCRC != 0x98f94189 {
		t.Fatalf("zero-page CRC32C = %#08x, want DML known answer", zeroCRC)
	}
	// Slot B occupies logical pages 11 and 12 and must be wholly zero.
	for _, page := range []uint64{11, 12} {
		got, _ := vector.CRC32C(page)
		if got != zeroCRC {
			t.Fatalf("zero slot CRC[%d] = %#08x, want %#08x", page, got, zeroCRC)
		}
	}

	firstVectorBytes := append([]byte(nil), vector.Bytes()...)
	mutated := vector.Bytes()
	mutated[0] ^= 0xff
	if bytes.Equal(mutated, result.CRCVector().Bytes()) || !bytes.Equal(firstVectorBytes, result.CRCVector().Bytes()) {
		t.Fatal("CRC vector accessor aliases result state")
	}
}

func TestProducerScatterAcceptsZeroChecksumAndKeepsReadsBounded(t *testing.T) {
	fixture := newProducerScatterTestFixture(t)
	readers := map[uint64]*producerScatterTestReaderAt{
		1: producerScatterTestSourceReader(1, fixture.memory),
		2: producerScatterTestSourceReader(2, fixture.artifact),
		3: producerScatterTestSourceReader(3, fixture.restoreBlob),
	}
	destination := newProducerScatterTestDestination(fixture.plan)
	copier := &producerScatterTestCPUCopier{destination: destination, zeroCall: 1}
	result, err := ExecuteProducerScatter(context.Background(), ProducerScatterExecutionRequest{
		Plan: fixture.plan,
		Sources: fixture.sources(func(objectID uint64, _ []byte) ProducerScatterSourceReaderAt {
			return readers[objectID]
		}),
		Destination: destination,
		Copier:      copier,
	})
	if err != nil {
		t.Fatalf("ExecuteProducerScatter: %v", err)
	}
	got, err := result.CRCVector().CRC32C(0)
	if err != nil || got != 0 {
		t.Fatalf("valid zero CRC = %#08x, %v", got, err)
	}
	for objectID, reader := range readers {
		if len(reader.requests) == 0 {
			t.Fatalf("object %d was not read", objectID)
		}
		for _, request := range reader.requests {
			if request.length <= 0 || request.length > ContentPageBytes || request.offset < 0 ||
				uint64(request.offset)+uint64(request.length) > uint64(len(reader.data)) {
				t.Fatalf("object %d unbounded request = %#v", objectID, request)
			}
		}
	}
}

func TestProducerScatterPreflightsEveryExtentAndRejectsBackingAliasing(t *testing.T) {
	fixture := newProducerScatterTestFixture(t)
	tests := []struct {
		name    string
		prepare func(*producerScatterTestDestination, []ProducerScatterSource)
		sources func() []ProducerScatterSource
	}{
		{
			name: "late-device-prepare-failure",
			prepare: func(destination *producerScatterTestDestination, _ []ProducerScatterSource) {
				destination.prepareFailure = "device-b"
			},
		},
		{
			name: "late-extent-failure",
			prepare: func(destination *producerScatterTestDestination, _ []ProducerScatterSource) {
				destination.extentFailureCall = 6
			},
		},
		{
			name: "wrong-extent-length",
			prepare: func(destination *producerScatterTestDestination, _ []ProducerScatterSource) {
				destination.wrongLengthCall = 4
			},
		},
		{
			name: "zero-destination-backing-ID",
			prepare: func(destination *producerScatterTestDestination, _ []ProducerScatterSource) {
				destination.zeroBackingCall = 2
			},
		},
		{
			name: "overflow-destination-backing-range",
			prepare: func(destination *producerScatterTestDestination, _ []ProducerScatterSource) {
				destination.overflowBackingCall = 2
			},
		},
		{
			name: "actual-destination-alias",
			prepare: func(destination *producerScatterTestDestination, _ []ProducerScatterSource) {
				destination.actualAlias = true
			},
		},
		{
			name: "declared-destination-alias-with-distinct-views",
			prepare: func(destination *producerScatterTestDestination, _ []ProducerScatterSource) {
				destination.declaredAlias = true
			},
		},
		{
			name: "source-destination-alias",
			sources: func() []ProducerScatterSource {
				sources := fixture.sources(nil)
				reader := producerScatterTestSourceReader(1, fixture.memory)
				reader.backing = ProducerScatterBackingRange{
					BackingID:  sha256.Sum256([]byte("destination-device-a")),
					ByteOffset: 10 * uint64(ContentPageBytes),
					ByteLength: uint64(len(fixture.memory)),
				}
				sources[0].Reader = reader
				return sources
			},
		},
		{
			name: "zero-source-backing-ID",
			sources: func() []ProducerScatterSource {
				sources := fixture.sources(nil)
				reader := producerScatterTestSourceReader(1, fixture.memory)
				reader.backing.BackingID = [sha256.Size]byte{}
				sources[0].Reader = reader
				return sources
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			destination := newProducerScatterTestDestination(fixture.plan)
			copier := &producerScatterTestCPUCopier{destination: destination}
			sources := fixture.sources(nil)
			if test.sources != nil {
				sources = test.sources()
			}
			if test.prepare != nil {
				test.prepare(destination, sources)
			}
			result, err := ExecuteProducerScatter(context.Background(), ProducerScatterExecutionRequest{
				Plan: fixture.plan, Sources: sources, Destination: destination, Copier: copier,
			})
			if !errors.Is(err, ErrProducerScatterCancellationRequired) {
				t.Fatalf("error = %v", err)
			}
			if copier.calls != 0 || len(result.CRCVector().Bytes()) != 0 {
				t.Fatalf("preflight failure copied %d pages or exposed a vector", copier.calls)
			}
		})
	}
}

func TestProducerScatterFailuresRequireCancellationAndExposeNoVector(t *testing.T) {
	fixture := newProducerScatterTestFixture(t)
	tests := []struct {
		name         string
		run          func(*producerScatterTestDestination, *producerScatterTestCPUCopier) (ProducerScatterResult, error)
		copiesAtMost int
	}{
		{
			name: "short-ReaderAt-before-copy",
			run: func(destination *producerScatterTestDestination, copier *producerScatterTestCPUCopier) (ProducerScatterResult, error) {
				short := producerScatterTestSourceReader(1, fixture.memory)
				short.shortFirst = true
				return ExecuteProducerScatter(context.Background(), ProducerScatterExecutionRequest{
					Plan: fixture.plan,
					Sources: fixture.sources(func(objectID uint64, data []byte) ProducerScatterSourceReaderAt {
						if objectID == 1 {
							return short
						}
						return producerScatterTestSourceReader(objectID, data)
					}),
					Destination: destination, Copier: copier,
				})
			},
			copiesAtMost: 0,
		},
		{
			name: "ReaderAt-full-count-with-error",
			run: func(destination *producerScatterTestDestination, copier *producerScatterTestCPUCopier) (ProducerScatterResult, error) {
				fullError := producerScatterTestSourceReader(1, fixture.memory)
				fullError.fullEOF = true
				return ExecuteProducerScatter(context.Background(), ProducerScatterExecutionRequest{
					Plan: fixture.plan,
					Sources: fixture.sources(func(objectID uint64, data []byte) ProducerScatterSourceReaderAt {
						if objectID == 1 {
							return fullError
						}
						return producerScatterTestSourceReader(objectID, data)
					}),
					Destination: destination, Copier: copier,
				})
			},
			copiesAtMost: 2,
		},
		{
			name: "writable-extent-preflight",
			run: func(destination *producerScatterTestDestination, copier *producerScatterTestCPUCopier) (ProducerScatterResult, error) {
				destination.extentFailureCall = 3
				return ExecuteProducerScatter(context.Background(), ProducerScatterExecutionRequest{
					Plan: fixture.plan, Sources: fixture.sources(nil), Destination: destination, Copier: copier,
				})
			},
			copiesAtMost: 0,
		},
		{
			name: "COPY-CRC-after-mutation",
			run: func(destination *producerScatterTestDestination, copier *producerScatterTestCPUCopier) (ProducerScatterResult, error) {
				copier.failCall = 2
				return ExecuteProducerScatter(context.Background(), ProducerScatterExecutionRequest{
					Plan: fixture.plan, Sources: fixture.sources(nil), Destination: destination, Copier: copier,
				})
			},
			copiesAtMost: 2,
		},
		{
			name: "sync",
			run: func(destination *producerScatterTestDestination, copier *producerScatterTestCPUCopier) (ProducerScatterResult, error) {
				destination.syncFailure = "device-a"
				return ExecuteProducerScatter(context.Background(), ProducerScatterExecutionRequest{
					Plan: fixture.plan, Sources: fixture.sources(nil), Destination: destination, Copier: copier,
				})
			},
			copiesAtMost: 17,
		},
		{
			name: "context-after-first-copy",
			run: func(destination *producerScatterTestDestination, copier *producerScatterTestCPUCopier) (ProducerScatterResult, error) {
				ctx, cancel := context.WithCancel(context.Background())
				copier.cancel = cancel
				return ExecuteProducerScatter(ctx, ProducerScatterExecutionRequest{
					Plan: fixture.plan, Sources: fixture.sources(nil), Destination: destination, Copier: copier,
				})
			},
			copiesAtMost: 1,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			destination := newProducerScatterTestDestination(fixture.plan)
			copier := &producerScatterTestCPUCopier{destination: destination}
			result, err := test.run(destination, copier)
			if !errors.Is(err, ErrProducerScatterCancellationRequired) {
				t.Fatalf("error = %v, want cancellation required", err)
			}
			var detailed *ProducerScatterCancellationError
			if !errors.As(err, &detailed) || detailed.Operation() == "" {
				t.Fatalf("error is not inspectable: %T %v", err, err)
			}
			if result.CheckpointID() != "" || result.AllocationRecordID() != 0 ||
				result.CRCVector().TotalPages() != 0 || len(result.CRCVector().Bytes()) != 0 {
				t.Fatalf("failure exposed partial result %#v", result)
			}
			if copier.calls > test.copiesAtMost {
				t.Fatalf("copy calls = %d, want <= %d", copier.calls, test.copiesAtMost)
			}
		})
	}
}

func TestProducerScatterRejectsSourceAndTypedNilSeamsBeforeCopy(t *testing.T) {
	fixture := newProducerScatterTestFixture(t)
	var nilReader *producerScatterTestReaderAt
	var nilDestination *producerScatterTestDestination
	var nilCopier *producerScatterTestCPUCopier
	tests := []struct {
		name    string
		request func(*producerScatterTestDestination, *producerScatterTestCPUCopier) ProducerScatterExecutionRequest
	}{
		{
			"wrong-source-length",
			func(destination *producerScatterTestDestination, copier *producerScatterTestCPUCopier) ProducerScatterExecutionRequest {
				sources := fixture.sources(nil)
				sources[0].ExactByteLength--
				return ProducerScatterExecutionRequest{Plan: fixture.plan, Sources: sources, Destination: destination, Copier: copier}
			},
		},
		{
			"duplicate-source",
			func(destination *producerScatterTestDestination, copier *producerScatterTestCPUCopier) ProducerScatterExecutionRequest {
				sources := fixture.sources(nil)
				sources[1].ObjectID = sources[0].ObjectID
				return ProducerScatterExecutionRequest{Plan: fixture.plan, Sources: sources, Destination: destination, Copier: copier}
			},
		},
		{
			"canonical-object-source",
			func(destination *producerScatterTestDestination, copier *producerScatterTestCPUCopier) ProducerScatterExecutionRequest {
				sources := fixture.sources(nil)
				sources[2].ObjectID = 4
				return ProducerScatterExecutionRequest{Plan: fixture.plan, Sources: sources, Destination: destination, Copier: copier}
			},
		},
		{
			"typed-nil-reader",
			func(destination *producerScatterTestDestination, copier *producerScatterTestCPUCopier) ProducerScatterExecutionRequest {
				sources := fixture.sources(nil)
				sources[0].Reader = nilReader
				return ProducerScatterExecutionRequest{Plan: fixture.plan, Sources: sources, Destination: destination, Copier: copier}
			},
		},
		{
			"typed-nil-destination",
			func(_ *producerScatterTestDestination, copier *producerScatterTestCPUCopier) ProducerScatterExecutionRequest {
				return ProducerScatterExecutionRequest{Plan: fixture.plan, Sources: fixture.sources(nil), Destination: nilDestination, Copier: copier}
			},
		},
		{
			"typed-nil-copier",
			func(destination *producerScatterTestDestination, _ *producerScatterTestCPUCopier) ProducerScatterExecutionRequest {
				return ProducerScatterExecutionRequest{Plan: fixture.plan, Sources: fixture.sources(nil), Destination: destination, Copier: nilCopier}
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			destination := newProducerScatterTestDestination(fixture.plan)
			copier := &producerScatterTestCPUCopier{destination: destination}
			result, err := ExecuteProducerScatter(context.Background(), test.request(destination, copier))
			if !errors.Is(err, ErrProducerScatterCancellationRequired) {
				t.Fatalf("error = %v", err)
			}
			if copier.calls != 0 || len(result.CRCVector().Bytes()) != 0 {
				t.Fatalf("rejected input copied %d pages or returned vector", copier.calls)
			}
		})
	}
	var nilContext *producerScatterTestNilContext
	destination := newProducerScatterTestDestination(fixture.plan)
	copier := &producerScatterTestCPUCopier{destination: destination}
	result, err := ExecuteProducerScatter(nilContext, ProducerScatterExecutionRequest{
		Plan: fixture.plan, Sources: fixture.sources(nil), Destination: destination, Copier: copier,
	})
	if !errors.Is(err, ErrProducerScatterCancellationRequired) ||
		copier.calls != 0 || len(result.CRCVector().Bytes()) != 0 {
		t.Fatalf("typed-nil context result/error = %#v / %v", result, err)
	}
}

func TestProducerScatterPlanHasNoPerPageTargetTable(t *testing.T) {
	typeOfPlan := reflect.TypeOf(ProducerScatterPlan{})
	wantSlices := map[string]bool{
		"devices": true,
		"objects": true,
		"runs":    true,
	}
	for index := 0; index < typeOfPlan.NumField(); index++ {
		field := typeOfPlan.Field(index)
		if field.Type.Kind() == reflect.Slice {
			if !wantSlices[field.Name] {
				t.Fatalf("unexpected slice field %q (%s) may be a per-page table", field.Name, field.Type)
			}
			delete(wantSlices, field.Name)
		}
		if strings.Contains(strings.ToLower(field.Name), "pagetarget") {
			t.Fatalf("plan contains per-page target field %q", field.Name)
		}
	}
	if len(wantSlices) != 0 {
		t.Fatalf("compact plan slice fields changed: missing %#v", wantSlices)
	}
}

func newProducerScatterTestFixture(t *testing.T) producerScatterTestFixture {
	t.Helper()
	initial := producerScatterTestInitialPlan(t)
	devices := []OwnerStateDevice{
		{DeviceUUID: "device-a", DeviceOwnerEpoch: 11, DataPageCount: 128,
			DeviceBindingSHA256: sha256.Sum256([]byte("binding-device-a"))},
		{DeviceUUID: "device-b", DeviceOwnerEpoch: 11, DataPageCount: 128,
			DeviceBindingSHA256: sha256.Sum256([]byte("binding-device-b"))},
	}
	membership, err := OwnerGroupMembershipSHA256(devices)
	if err != nil {
		t.Fatalf("OwnerGroupMembershipSHA256: %v", err)
	}
	demands := make([]OwnerStateContentDemand, len(initial.Publication.Objects))
	for index, object := range initial.Publication.Objects {
		demands[index] = OwnerStateContentDemand{
			Kind: object.Kind, ObjectID: object.ObjectID,
			ByteLength: object.ImmutableByteLength, CapacityPages: object.CapacityPages,
			LogicalPageStart: object.LogicalPageStart,
		}
	}
	record := OwnerStateAllocationRecord{
		AllocationRecordID: 29, ReservationTransactionSequence: 101,
		OwnerTransactionSequence: 102, State: OwnerAllocationGranted,
		RequestID: "request-7", CheckpointID: "checkpoint-7", ProducerID: "producer-7",
		DedupDomainID: "dedup-domain-7", SharingPolicyID: "same-tenant-verified-content-v1",
		RequestSHA256: sha256.Sum256([]byte("request-7")), TotalDemandPages: 17,
		MaxExtents: 16, ContentDemands: demands,
		Fragments: []OwnerStateDeviceFragment{
			{
				DeviceUUID: "device-a", DeviceOwnerEpoch: 11, TargetAllocatorSnapshotSequence: 7,
				Extents: []OwnerStateExtent{
					{StartDataPageIndex: 10, LogicalPageStart: 0, PageCount: 2},
					{StartDataPageIndex: 30, LogicalPageStart: 5, PageCount: 4},
					{StartDataPageIndex: 40, LogicalPageStart: 10, PageCount: 3},
				},
			},
			{
				DeviceUUID: "device-b", DeviceOwnerEpoch: 11, TargetAllocatorSnapshotSequence: 9,
				Extents: []OwnerStateExtent{
					{StartDataPageIndex: 20, LogicalPageStart: 2, PageCount: 3},
					{StartDataPageIndex: 40, LogicalPageStart: 9, PageCount: 1},
					{StartDataPageIndex: 50, LogicalPageStart: 13, PageCount: 4},
				},
			},
		},
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
		t.Fatalf("NewOwnerStateSnapshot: %v", err)
	}
	plan, err := BuildProducerScatterPlan(owner, 29, initial)
	if err != nil {
		t.Fatalf("BuildProducerScatterPlan: %v", err)
	}
	return producerScatterTestFixture{
		owner: owner, initial: initial, plan: plan,
		memory:      producerScatterTestBytes(3*ContentPageBytes, 0x11),
		artifact:    producerScatterTestBytes(5000, 0x47),
		restoreBlob: producerScatterTestBytes(1000, 0x83),
	}
}

func producerScatterTestInitialPlan(t *testing.T) cxlcheckpoint.InitialPublicationV7Plan {
	t.Helper()
	template := cxlcheckpoint.MMTemplateV7{
		MMTemplateID: "mm-template-7", Version: 1,
		RuntimeCompatibilityID: "runtime-compatible-fixture-only", PageSize: cxlcheckpoint.PageSize,
		VMAs: []cxlcheckpoint.VMAV7{{
			PagesImageID: 1, StartVAddr: 0x1000, EndVAddr: 0x6000,
			ProtectionFlags:        cxlcheckpoint.ProtectionRead | cxlcheckpoint.ProtectionWrite,
			MappingFlags:           cxlcheckpoint.MappingPrivate | cxlcheckpoint.MappingAnonymous,
			BackingKind:            cxlcheckpoint.BackingAnonymous,
			VirtualPageMapRunStart: 0, VirtualPageMapRunCount: 2,
		}},
	}
	virtual := cxlcheckpoint.VirtualPageMap{
		VirtualPageMapID: "virtual-map-7", Version: 1, PageSize: cxlcheckpoint.PageSize,
		Runs: []cxlcheckpoint.VirtualPageMapRun{
			{PagesImageID: 1, StartVAddr: 0x1000, PageCount: 2, ContentObjectID: 1, ObjectPageIndex: 0},
			{PagesImageID: 1, StartVAddr: 0x5000, PageCount: 1, ContentObjectID: 1, ObjectPageIndex: 2},
		},
	}
	manifest := cxlcheckpoint.ArtifactManifestV7{
		ArtifactManifestID: "artifact-manifest-7", Version: 1,
		Entries: []cxlcheckpoint.ArtifactEntryV7{
			{Path: "a.bin", Type: cxlcheckpoint.ArtifactRegular, Mode: 0o644, UID: 1000, GID: 1000,
				ByteLength: 2000, ContentObjectID: 2, ContentOffset: 0},
			{Path: "b.bin", Type: cxlcheckpoint.ArtifactRegular, Mode: 0o600, UID: 1000, GID: 1000,
				ByteLength: 3000, ContentObjectID: 2, ContentOffset: 2000},
			{Path: "dir", Type: cxlcheckpoint.ArtifactDirectory, Mode: 0o755},
		},
	}
	templateBytes, err := cxlcheckpoint.CanonicalMMTemplateV7Bytes(template)
	if err != nil {
		t.Fatalf("CanonicalMMTemplateV7Bytes: %v", err)
	}
	mappingObjects := []cxlcheckpoint.ContentObject{
		{ObjectID: 1, Kind: cxlcheckpoint.ContentMemory, ByteLength: 3 * cxlcheckpoint.PageSize, LogicalPageStart: 0, PageCount: 3},
		{ObjectID: 2, Kind: cxlcheckpoint.ContentArtifact, ByteLength: 5000, LogicalPageStart: 3, PageCount: 2},
		{ObjectID: 3, Kind: cxlcheckpoint.ContentRestoreBlob, ByteLength: 1000, LogicalPageStart: 5, PageCount: 1},
	}
	virtualBytes, err := cxlcheckpoint.CanonicalVirtualPageMapBytes(virtual, mappingObjects)
	if err != nil {
		t.Fatalf("CanonicalVirtualPageMapBytes: %v", err)
	}
	manifestBytes, err := cxlcheckpoint.CanonicalArtifactManifestV7Bytes(manifest)
	if err != nil {
		t.Fatalf("CanonicalArtifactManifestV7Bytes: %v", err)
	}
	publication := cxlcheckpoint.PublicationV7{
		CheckpointID: "checkpoint-7", ImmutableGraphID: "immutable-graph-7",
		DedupDomainID: "dedup-domain-7", SharingPolicyID: "same-tenant-verified-content-v1",
		InitialAllocation: cxlcheckpoint.InitialAllocationV7{
			OwnerID: "owner-a", OwnerEpoch: 11, AllocationRecordID: 29, TotalPages: 17,
			Devices: []cxlcheckpoint.AllocationDeviceV7{
				{DeviceUUID: "device-a", DataPageCount: 128},
				{DeviceUUID: "device-b", DataPageCount: 128},
			},
			Extents: []cxlcheckpoint.AllocationExtentV7{
				{DeviceIndex: 0, StartDataPageIndex: 10, PageCount: 2, LogicalPageStart: 0},
				{DeviceIndex: 1, StartDataPageIndex: 20, PageCount: 3, LogicalPageStart: 2},
				{DeviceIndex: 0, StartDataPageIndex: 30, PageCount: 4, LogicalPageStart: 5},
				{DeviceIndex: 1, StartDataPageIndex: 40, PageCount: 1, LogicalPageStart: 9},
				{DeviceIndex: 0, StartDataPageIndex: 40, PageCount: 3, LogicalPageStart: 10},
				{DeviceIndex: 1, StartDataPageIndex: 50, PageCount: 4, LogicalPageStart: 13},
			},
		},
		Objects: []cxlcheckpoint.ContentObjectV7{
			{ObjectID: 1, Kind: cxlcheckpoint.ContentMemoryPayloadV7, ImmutableByteLength: 3 * cxlcheckpoint.PageSize, LogicalPageStart: 0, CapacityPages: 3},
			{ObjectID: 2, Kind: cxlcheckpoint.ContentArtifactPayloadV7, ImmutableByteLength: 5000, LogicalPageStart: 3, CapacityPages: 2},
			{ObjectID: 3, Kind: cxlcheckpoint.ContentRestoreBlobPayloadV7, ImmutableByteLength: 1000, LogicalPageStart: 5, CapacityPages: 1},
			{ObjectID: 4, Kind: cxlcheckpoint.ContentMMTemplateMetadataV7, ImmutableByteLength: uint64(len(templateBytes)), LogicalPageStart: 6, CapacityPages: 1},
			{ObjectID: 5, Kind: cxlcheckpoint.ContentVirtualPageMapMetadataV7, ImmutableByteLength: uint64(len(virtualBytes)), LogicalPageStart: 7, CapacityPages: 1},
			{ObjectID: 6, Kind: cxlcheckpoint.ContentArtifactManifestMetadataV7, ImmutableByteLength: uint64(len(manifestBytes)), LogicalPageStart: 8, CapacityPages: 1},
			{ObjectID: 7, Kind: cxlcheckpoint.ContentPlacementSlotAV7, LogicalPageStart: 9, CapacityPages: 2},
			{ObjectID: 8, Kind: cxlcheckpoint.ContentPlacementSlotBV7, LogicalPageStart: 11, CapacityPages: 2},
			{ObjectID: 9, Kind: cxlcheckpoint.ContentPublicationV7, LogicalPageStart: 13, CapacityPages: 4},
		},
		MMTemplate: cxlcheckpoint.MMTemplateRefV7{
			ObjectID: 4, MMTemplateID: template.MMTemplateID, Version: template.Version,
			SHA256: sha256.Sum256(templateBytes),
		},
		VirtualPageMap: cxlcheckpoint.VirtualPageMapRefV7{
			ObjectID: 5, VirtualPageMapID: virtual.VirtualPageMapID, Version: virtual.Version,
			SHA256: sha256.Sum256(virtualBytes),
		},
		ArtifactManifest: cxlcheckpoint.ArtifactManifestRefV7{
			ObjectID: 6, ArtifactManifestID: manifest.ArtifactManifestID, Version: manifest.Version,
			SHA256: sha256.Sum256(manifestBytes),
		},
		PlacementSlots: cxlcheckpoint.PlacementSlotsV7{AObjectID: 7, BObjectID: 8},
	}
	plan, err := cxlcheckpoint.BuildInitialPublicationV7Plan(cxlcheckpoint.InitialPublicationV7Input{
		Publication: publication, MMTemplate: template, VirtualPageMap: virtual, ArtifactManifest: manifest,
		InitialContentPlacementMapID: "initial-placement-v7",
		InitialActivePlacementRootID: "active-root-v7",
	})
	if err != nil {
		t.Fatalf("BuildInitialPublicationV7Plan: %v", err)
	}
	return plan
}

func newProducerScatterTestDestination(plan ProducerScatterPlan) *producerScatterTestDestination {
	bindings := make(map[string]ProducerScatterDeviceBinding)
	for _, binding := range plan.Devices() {
		bindings[binding.DeviceUUID] = binding
	}
	return &producerScatterTestDestination{
		expectedBindings: bindings,
		pages:            make(map[string]map[uint64][]byte),
	}
}

func (fixture producerScatterTestFixture) sources(
	replace func(uint64, []byte) ProducerScatterSourceReaderAt,
) []ProducerScatterSource {
	values := []struct {
		objectID uint64
		data     []byte
	}{
		{1, fixture.memory},
		{2, fixture.artifact},
		{3, fixture.restoreBlob},
	}
	result := make([]ProducerScatterSource, len(values))
	for index, value := range values {
		reader := ProducerScatterSourceReaderAt(producerScatterTestSourceReader(value.objectID, value.data))
		if replace != nil {
			reader = replace(value.objectID, value.data)
		}
		result[index] = ProducerScatterSource{
			ObjectID: value.objectID, ExactByteLength: uint64(len(value.data)), Reader: reader,
		}
	}
	return result
}

func producerScatterTestSourceReader(objectID uint64, data []byte) *producerScatterTestReaderAt {
	return &producerScatterTestReaderAt{
		data: data,
		backing: ProducerScatterBackingRange{
			BackingID:  sha256.Sum256([]byte(fmt.Sprintf("source-object-%d", objectID))),
			ByteLength: uint64(len(data)),
		},
	}
}

func (fixture producerScatterTestFixture) expectedLogicalPages(t *testing.T) [][]byte {
	t.Helper()
	sourceByID := map[uint64][]byte{1: fixture.memory, 2: fixture.artifact, 3: fixture.restoreBlob}
	result := make([][]byte, fixture.plan.totalPages)
	for _, object := range fixture.plan.objects {
		for page := uint64(0); page < object.CapacityPages; page++ {
			value := make([]byte, ContentPageBytes)
			offset := page * uint64(ContentPageBytes)
			if offset < object.ExactByteLength {
				remaining := object.ExactByteLength - offset
				length := uint64(ContentPageBytes)
				if remaining < length {
					length = remaining
				}
				switch object.writeSource {
				case producerScatterExternal:
					copy(value[:int(length)], sourceByID[object.ObjectID][int(offset):int(offset+length)])
				case producerScatterCanonical:
					copy(value[:int(length)], object.canonicalBytes[int(offset):int(offset+length)])
				default:
					t.Fatalf("object %d has meaningful bytes with source %d", object.ObjectID, object.writeSource)
				}
			}
			result[int(object.LogicalPageStart+page)] = value
		}
	}
	return result
}

func producerScatterTestExpectedPageRequests(plan ProducerScatterPlan) []producerScatterTestPageRequest {
	result := make([]producerScatterTestPageRequest, 0, plan.totalPages)
	for _, run := range plan.runs {
		binding := plan.devices[run.DeviceIndex]
		for page := uint64(0); page < run.PageCount; page++ {
			result = append(result, producerScatterTestPageRequest{
				deviceUUID: binding.DeviceUUID, pageIndex: run.StartDataPageIndex + page,
			})
		}
	}
	return result
}

func producerScatterTestBytes(length int, seed byte) []byte {
	result := make([]byte, length)
	for index := range result {
		result[index] = byte((index*31 + int(seed)) & 0xff)
	}
	return result
}

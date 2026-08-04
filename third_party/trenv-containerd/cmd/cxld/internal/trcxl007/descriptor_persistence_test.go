package trcxl007

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"reflect"
	"testing"

	"github.com/containerd/containerd/third_party/trenv-containerd/pkg/cxlcheckpoint"
)

type reservedDescriptorTestFixture struct {
	formatFixture metadataTestFixture
	storage       *metadataTestStorage
	device        *DeviceMetadata
	record        OwnerStateAllocationRecord
	runs          []OwnerReservedDescriptorRun
	update        OwnerAllocatorSnapshotUpdate
}

// reservedDescriptorTornWriteStorage makes one genuinely torn descriptor:
// unlike metadataTestStorage's len-1 short write, it stops inside the
// descriptor's nonzero identity fields rather than omitting a canonical-zero
// tail byte.
type reservedDescriptorTornWriteStorage struct {
	*metadataTestStorage
	tearNextWrite bool
}

func (storage *reservedDescriptorTornWriteStorage) WriteAt(
	source []byte,
	offset int64,
) (int, error) {
	if !storage.tearNextWrite {
		return storage.metadataTestStorage.WriteAt(source, offset)
	}
	storage.tearNextWrite = false
	storage.writeCalls++
	if len(source) > storage.maxWrite {
		storage.maxWrite = len(source)
	}
	if err := storage.beforeMutation(); err != nil {
		return 0, err
	}
	if offset < 0 || len(source) < 24 {
		return 0, fmt.Errorf("invalid torn-write fixture range")
	}
	const prefix = 24
	start := uint64(offset)
	storage.rawWrite(start, source[:prefix])
	storage.events = append(storage.events, metadataTestEvent{
		kind: "write", offset: start, length: prefix,
	})
	return prefix, nil
}

func TestPersistPreparingReservedDescriptorsFreshAndIdempotent(t *testing.T) {
	demands := []OwnerStateContentDemand{
		{
			Kind:             cxlcheckpoint.ContentMemoryPayloadV7,
			ObjectID:         1,
			ByteLength:       1100 * uint64(ContentPageBytes),
			CapacityPages:    1100,
			LogicalPageStart: 0,
		},
		{
			Kind:             cxlcheckpoint.ContentArtifactPayloadV7,
			ObjectID:         2,
			ByteLength:       200*uint64(ContentPageBytes) - 17,
			CapacityPages:    200,
			LogicalPageStart: 1100,
		},
	}
	fixture := newReservedDescriptorTestFixture(t, demands)
	geometry := fixture.device.geometry
	controlBefore := fixture.storage.rawBytes(0, int(geometry.DescriptorRegionBase))
	contentOffset, err := geometry.ContentOffset(0)
	if err != nil {
		t.Fatalf("ContentOffset: %v", err)
	}
	contentSentinel := []byte("RESERVED-must-not-write-payload")
	fixture.storage.rawWrite(contentOffset, contentSentinel)
	fixture.storage.resetTracking()

	if err := fixture.device.persistPreparingReservedDescriptors(
		fixture.record, fixture.runs); err != nil {
		t.Fatalf("persistPreparingReservedDescriptors: %v", err)
	}
	assertReservedDescriptorPages(t, fixture.storage, fixture.device.geometry, fixture.runs)
	if got := fixture.storage.rawBytes(0, len(controlBefore)); !bytes.Equal(got, controlBefore) {
		t.Fatal("RESERVED persistence changed control/allocator/Owner metadata")
	}
	if got := fixture.storage.rawBytes(contentOffset, len(contentSentinel)); !bytes.Equal(got, contentSentinel) {
		t.Fatalf("content sentinel = %q, want %q", got, contentSentinel)
	}
	assertReservedDescriptorMutationEvents(t, fixture.storage, fixture.device.geometry, fixture.runs)
	if fixture.storage.maxRead > reservedDescriptorIOBatchBytes ||
		fixture.storage.maxWrite > reservedDescriptorIOBatchBytes {
		t.Fatalf("maximum descriptor I/O = read %d/write %d, bound %d",
			fixture.storage.maxRead,
			fixture.storage.maxWrite,
			reservedDescriptorIOBatchBytes)
	}
	if fixture.storage.readCalls < 2 {
		t.Fatalf("1300-page preflight used only %d read", fixture.storage.readCalls)
	}

	fixture.storage.resetTracking()
	if err := fixture.device.persistPreparingReservedDescriptors(
		fixture.record, fixture.runs); err != nil {
		t.Fatalf("idempotent persistence: %v", err)
	}
	if fixture.storage.writeCalls != 0 || fixture.storage.mutationCount != 1 ||
		len(fixture.storage.events) != 1 || fixture.storage.events[0].kind != "sync" {
		t.Fatalf("idempotent retry mutated storage: %#v", fixture.storage.events)
	}
}

func TestPersistPreparingReservedDescriptorsAllExactSyncFailurePoisonsAndRetries(t *testing.T) {
	fixture := newReservedDescriptorMemoryFixture(t, 8)
	if err := fixture.device.persistPreparingReservedDescriptors(
		fixture.record, fixture.runs); err != nil {
		t.Fatalf("initial persistence: %v", err)
	}
	fixture.storage.resetTracking()
	fixture.storage.failMutation = 1
	err := fixture.device.persistPreparingReservedDescriptors(fixture.record, fixture.runs)
	if !errors.Is(err, ErrDeviceMetadataStorage) {
		t.Fatalf("all-exact Sync failure = %v", err)
	}
	if fixture.storage.writeCalls != 0 || fixture.storage.mutationCount != 1 {
		t.Fatalf("all-exact Sync failure writes/mutations = %d/%d",
			fixture.storage.writeCalls, fixture.storage.mutationCount)
	}
	reads, writes, mutations := fixture.storage.readCalls,
		fixture.storage.writeCalls, fixture.storage.mutationCount
	fixture.storage.failMutation = 0
	if err := fixture.device.persistPreparingReservedDescriptors(
		fixture.record, fixture.runs); !errors.Is(err, ErrDeviceMetadataReopenRequired) {
		t.Fatalf("poisoned all-exact retry = %v", err)
	}
	if fixture.storage.readCalls != reads || fixture.storage.writeCalls != writes ||
		fixture.storage.mutationCount != mutations {
		t.Fatal("poisoned all-exact retry performed I/O")
	}

	reopened := openReservedDescriptorTestDevice(t, fixture.storage, fixture.formatFixture)
	if err := reopened.persistPreparingReservedDescriptors(
		fixture.record, fixture.runs); err != nil {
		t.Fatalf("all-exact reopen retry: %v", err)
	}
	if fixture.storage.writeCalls != 0 || fixture.storage.mutationCount != 1 ||
		len(fixture.storage.events) != 1 || fixture.storage.events[0].kind != "sync" {
		t.Fatalf("all-exact reopen retry events = %#v", fixture.storage.events)
	}
}

func TestPersistPreparingReservedDescriptorsFullPreflightRejectsLateConflict(t *testing.T) {
	fixture := newReservedDescriptorMemoryFixture(t, 1500)
	lastRun := fixture.runs[len(fixture.runs)-1]
	lastPage := lastRun.StartDataPageIndex + lastRun.PageCount - 1
	conflict := lastRun.Descriptor
	conflict.OriginObjectID++
	conflictWire, err := conflict.MarshalBinary()
	if err != nil {
		t.Fatalf("conflict descriptor: %v", err)
	}
	offset, err := fixture.device.geometry.DescriptorOffset(lastPage)
	if err != nil {
		t.Fatalf("DescriptorOffset: %v", err)
	}
	fixture.storage.rawWrite(offset, conflictWire)
	before := fixture.storage.clone()
	fixture.storage.resetTracking()

	err = fixture.device.persistPreparingReservedDescriptors(fixture.record, fixture.runs)
	if !errors.Is(err, ErrDeviceMetadataDescriptorConflict) {
		t.Fatalf("late conflict error = %v", err)
	}
	if fixture.storage.writeCalls != 0 || fixture.storage.mutationCount != 0 ||
		len(fixture.storage.events) != 0 {
		t.Fatalf("late conflict mutated storage: %#v", fixture.storage.events)
	}
	if !reflect.DeepEqual(fixture.storage.bytes, before.bytes) {
		t.Fatal("late conflict changed sparse storage bytes")
	}
	if fixture.storage.readCalls < 2 || fixture.storage.maxRead > reservedDescriptorIOBatchBytes {
		t.Fatalf("late preflight reads = %d, max = %d",
			fixture.storage.readCalls, fixture.storage.maxRead)
	}
}

func TestPersistPreparingReservedDescriptorsRejectsTornDescriptorWithoutMutation(t *testing.T) {
	fixture := newReservedDescriptorMemoryFixture(t, 3)
	offset, err := fixture.device.geometry.DescriptorOffset(
		fixture.runs[0].StartDataPageIndex + 1)
	if err != nil {
		t.Fatalf("DescriptorOffset: %v", err)
	}
	fixture.storage.rawWrite(offset, []byte{0x7f})
	before := fixture.storage.clone()
	fixture.storage.resetTracking()

	err = fixture.device.persistPreparingReservedDescriptors(fixture.record, fixture.runs)
	if !errors.Is(err, ErrDeviceMetadataDescriptorConflict) {
		t.Fatalf("torn descriptor error = %v", err)
	}
	if fixture.storage.mutationCount != 0 || fixture.storage.writeCalls != 0 ||
		!reflect.DeepEqual(fixture.storage.bytes, before.bytes) {
		t.Fatal("torn descriptor rejection mutated storage")
	}
}

func TestPersistPreparingReservedDescriptorsReadFailureIsRetryableWithoutReopen(t *testing.T) {
	fixture := newReservedDescriptorMemoryFixture(t, 8)
	offset, err := fixture.device.geometry.DescriptorOffset(
		fixture.runs[0].StartDataPageIndex)
	if err != nil {
		t.Fatalf("DescriptorOffset: %v", err)
	}
	fixture.storage.failReadOffset = &offset
	err = fixture.device.persistPreparingReservedDescriptors(fixture.record, fixture.runs)
	if !errors.Is(err, ErrDeviceMetadataStorage) {
		t.Fatalf("read failure error = %v", err)
	}
	if fixture.storage.writeCalls != 0 || fixture.storage.mutationCount != 0 {
		t.Fatal("read failure mutated storage")
	}
	fixture.storage.failReadOffset = nil
	fixture.storage.resetTracking()
	if err := fixture.device.persistPreparingReservedDescriptors(
		fixture.record, fixture.runs); err != nil {
		t.Fatalf("same-handle retry after read failure: %v", err)
	}
	assertReservedDescriptorPages(t, fixture.storage, fixture.device.geometry, fixture.runs)
}

func TestPersistPreparingReservedDescriptorsWritesOnlyPreflightFreePages(t *testing.T) {
	fixture := newReservedDescriptorMemoryFixture(t, 6)
	wire, err := fixture.runs[0].Descriptor.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary: %v", err)
	}
	alreadyReserved := map[uint64]bool{1: true, 3: true}
	for page := range alreadyReserved {
		offset, err := fixture.device.geometry.DescriptorOffset(
			fixture.runs[0].StartDataPageIndex + page)
		if err != nil {
			t.Fatalf("DescriptorOffset: %v", err)
		}
		fixture.storage.rawWrite(offset, wire)
	}
	fixture.storage.resetTracking()
	if err := fixture.device.persistPreparingReservedDescriptors(
		fixture.record, fixture.runs); err != nil {
		t.Fatalf("mixed FREE/RESERVED persistence: %v", err)
	}
	for _, event := range fixture.storage.events {
		if event.kind != "write" {
			continue
		}
		start := (event.offset - fixture.device.geometry.DescriptorRegionBase) /
			uint64(PageDescriptorBytes)
		for page := uint64(0); page < uint64(event.length/PageDescriptorBytes); page++ {
			if alreadyReserved[start+page-fixture.runs[0].StartDataPageIndex] {
				t.Fatalf("write touched already exact RESERVED page %d", start+page)
			}
		}
	}
	assertReservedDescriptorPages(t, fixture.storage, fixture.device.geometry, fixture.runs)
}

func TestPersistPreparingReservedDescriptorsEveryMutationFailurePoisonsAndRecovers(t *testing.T) {
	fixture := newReservedDescriptorMemoryFixture(t, 2050)
	probeStorage := fixture.storage.clone()
	probeDevice := openReservedDescriptorTestDevice(t, probeStorage, fixture.formatFixture)
	if err := probeDevice.persistPreparingReservedDescriptors(
		fixture.record, fixture.runs); err != nil {
		t.Fatalf("complete probe: %v", err)
	}
	operationCount := probeStorage.mutationCount
	if operationCount != 4 {
		t.Fatalf("2050-page operation mutations = %d, want 3 writes + 1 Sync", operationCount)
	}

	for failure := 1; failure <= operationCount; failure++ {
		t.Run(fmt.Sprintf("mutation-%d", failure), func(t *testing.T) {
			storage := fixture.storage.clone()
			device := openReservedDescriptorTestDevice(t, storage, fixture.formatFixture)
			storage.failMutation = failure
			err := device.persistPreparingReservedDescriptors(fixture.record, fixture.runs)
			if !errors.Is(err, ErrDeviceMetadataStorage) {
				t.Fatalf("failure %d error = %v", failure, err)
			}
			reads, writes, mutations := storage.readCalls, storage.writeCalls, storage.mutationCount
			storage.failMutation = 0
			if err := device.persistPreparingReservedDescriptors(
				fixture.record, fixture.runs); !errors.Is(err, ErrDeviceMetadataReopenRequired) {
				t.Fatalf("poisoned retry error = %v", err)
			}
			if storage.readCalls != reads || storage.writeCalls != writes ||
				storage.mutationCount != mutations {
				t.Fatal("poisoned retry performed I/O")
			}

			reopened := openReservedDescriptorTestDevice(t, storage, fixture.formatFixture)
			if err := reopened.persistPreparingReservedDescriptors(
				fixture.record, fixture.runs); err != nil {
				t.Fatalf("reopen recovery: %v", err)
			}
			assertReservedDescriptorPages(t, storage, reopened.geometry, fixture.runs)
		})
	}
}

func TestPersistPreparingReservedDescriptorsShortWritePoisonsAndReopens(t *testing.T) {
	fixture := newReservedDescriptorMemoryFixture(t, 1100)
	// metadataTestStorage's short write omits only the last byte. That byte is
	// zero in canonical RESERVED, so the first batch is nevertheless byte-exact;
	// the short return still must poison the handle, and reopen may safely finish
	// the untouched later batch.
	fixture.storage.shortWriteCall = 1
	err := fixture.device.persistPreparingReservedDescriptors(fixture.record, fixture.runs)
	if !errors.Is(err, ErrDeviceMetadataStorage) {
		t.Fatalf("short write error = %v", err)
	}
	reads, writes, mutations := fixture.storage.readCalls,
		fixture.storage.writeCalls, fixture.storage.mutationCount
	fixture.storage.shortWriteCall = 0
	if err := fixture.device.persistPreparingReservedDescriptors(
		fixture.record, fixture.runs); !errors.Is(err, ErrDeviceMetadataReopenRequired) {
		t.Fatalf("poisoned short-write retry = %v", err)
	}
	if fixture.storage.readCalls != reads || fixture.storage.writeCalls != writes ||
		fixture.storage.mutationCount != mutations {
		t.Fatal("poisoned short-write retry performed I/O")
	}

	reopened := openReservedDescriptorTestDevice(
		t, fixture.storage, fixture.formatFixture)
	err = reopened.persistPreparingReservedDescriptors(fixture.record, fixture.runs)
	if err != nil {
		t.Fatalf("reopened short-write recovery = %v", err)
	}
	assertReservedDescriptorPages(t, fixture.storage, reopened.geometry, fixture.runs)
}

func TestPersistPreparingReservedDescriptorsTornMutationFailsClosedAfterReopen(t *testing.T) {
	fixture := newReservedDescriptorMemoryFixture(t, 4)
	base := fixture.storage.clone()
	storage := &reservedDescriptorTornWriteStorage{metadataTestStorage: base}
	device, err := OpenDeviceMetadata(storage, metadataTestOpenInput(fixture.formatFixture))
	if err != nil {
		t.Fatalf("open torn-write fixture: %v", err)
	}
	base.resetTracking()
	storage.tearNextWrite = true
	err = device.persistPreparingReservedDescriptors(fixture.record, fixture.runs)
	if !errors.Is(err, ErrDeviceMetadataStorage) {
		t.Fatalf("torn short-write error = %v", err)
	}
	if base.writeCalls != 1 || base.mutationCount != 1 ||
		len(base.events) != 1 || base.events[0].length != 24 {
		t.Fatalf("torn mutation evidence = %#v", base.events)
	}
	reads, writes, mutations := base.readCalls, base.writeCalls, base.mutationCount
	if err := device.persistPreparingReservedDescriptors(
		fixture.record, fixture.runs); !errors.Is(err, ErrDeviceMetadataReopenRequired) {
		t.Fatalf("poisoned torn retry = %v", err)
	}
	if base.readCalls != reads || base.writeCalls != writes ||
		base.mutationCount != mutations {
		t.Fatal("poisoned torn retry performed I/O")
	}

	reopened, err := OpenDeviceMetadata(storage, metadataTestOpenInput(fixture.formatFixture))
	if err != nil {
		t.Fatalf("reopen after torn descriptor: %v", err)
	}
	base.resetTracking()
	err = reopened.persistPreparingReservedDescriptors(fixture.record, fixture.runs)
	if !errors.Is(err, ErrDeviceMetadataDescriptorConflict) {
		t.Fatalf("reopened torn descriptor error = %v", err)
	}
	if base.writeCalls != 0 || base.mutationCount != 0 || len(base.events) != 0 {
		t.Fatalf("torn recovery blindly repaired media: %#v", base.events)
	}
}

func TestPersistPreparingReservedDescriptorsRejectsTamperingBeforeIO(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*testing.T, *DeviceMetadata, *OwnerStateAllocationRecord, []OwnerReservedDescriptorRun)
	}{
		{"record-state", func(_ *testing.T, _ *DeviceMetadata, record *OwnerStateAllocationRecord, _ []OwnerReservedDescriptorRun) {
			record.State = OwnerAllocationGranted
		}},
		{"record-device", func(_ *testing.T, _ *DeviceMetadata, record *OwnerStateAllocationRecord, _ []OwnerReservedDescriptorRun) {
			record.Fragments[0].DeviceUUID = "device-other"
		}},
		{"record-epoch", func(_ *testing.T, _ *DeviceMetadata, record *OwnerStateAllocationRecord, _ []OwnerReservedDescriptorRun) {
			record.Fragments[0].DeviceOwnerEpoch++
		}},
		{"record-target-sequence", func(_ *testing.T, _ *DeviceMetadata, record *OwnerStateAllocationRecord, _ []OwnerReservedDescriptorRun) {
			record.Fragments[0].TargetAllocatorSnapshotSequence++
		}},
		{"record-demand", func(_ *testing.T, _ *DeviceMetadata, record *OwnerStateAllocationRecord, _ []OwnerReservedDescriptorRun) {
			record.ContentDemands[0].ObjectID++
		}},
		{"run-start", func(_ *testing.T, _ *DeviceMetadata, _ *OwnerStateAllocationRecord, runs []OwnerReservedDescriptorRun) {
			runs[0].StartDataPageIndex++
		}},
		{"run-descriptor", func(_ *testing.T, _ *DeviceMetadata, _ *OwnerStateAllocationRecord, runs []OwnerReservedDescriptorRun) {
			runs[0].Descriptor.OriginObjectID++
		}},
		{"allocator-sequence", func(t *testing.T, device *DeviceMetadata, _ *OwnerStateAllocationRecord, _ []OwnerReservedDescriptorRun) {
			retargetReservedDescriptorCachedAllocator(
				t, device, device.allocator.SnapshotSequence+2,
				device.allocator.AppliedOwnerTransactionSequence, false)
		}},
		{"allocator-bitmap", func(t *testing.T, device *DeviceMetadata, _ *OwnerStateAllocationRecord, _ []OwnerReservedDescriptorRun) {
			retargetReservedDescriptorCachedAllocator(
				t, device, device.allocator.SnapshotSequence,
				device.allocator.AppliedOwnerTransactionSequence, true)
		}},
		{"allocator-binding", func(_ *testing.T, device *DeviceMetadata, _ *OwnerStateAllocationRecord, _ []OwnerReservedDescriptorRun) {
			device.allocator.DeviceBindingSHA256[0] ^= 1
		}},
		{"allocator-bitmap-length", func(_ *testing.T, device *DeviceMetadata, _ *OwnerStateAllocationRecord, _ []OwnerReservedDescriptorRun) {
			device.allocator.BitmapByteLength--
		}},
	}

	base := newReservedDescriptorMemoryFixture(t, 4)
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			storage := base.storage.clone()
			device := openReservedDescriptorTestDevice(t, storage, base.formatFixture)
			record := cloneOwnerStateRecord(base.record)
			runs := append([]OwnerReservedDescriptorRun(nil), base.runs...)
			test.mutate(t, device, &record, runs)
			before := storage.clone()
			storage.resetTracking()

			if err := device.persistPreparingReservedDescriptors(record, runs); err == nil {
				t.Fatal("tampered input was accepted")
			}
			if storage.readCalls != 0 || storage.writeCalls != 0 ||
				storage.mutationCount != 0 || !reflect.DeepEqual(storage.bytes, before.bytes) {
				t.Fatalf("tampering performed I/O or mutation: reads=%d events=%#v",
					storage.readCalls, storage.events)
			}
		})
	}
}

func TestPersistPreparingReservedDescriptorsAnchorRequiresExactActiveRecord(t *testing.T) {
	fixture := newReservedDescriptorMemoryFixture(t, 2)
	fixture.device.ownerState = fixture.formatFixture.input.OwnerState.Clone()
	fixture.storage.resetTracking()
	err := fixture.device.persistPreparingReservedDescriptors(fixture.record, fixture.runs)
	if !errors.Is(err, ErrOwnerAllocatorInputMismatch) {
		t.Fatalf("missing active PREPARING record error = %v", err)
	}
	if fixture.storage.readCalls != 0 || fixture.storage.mutationCount != 0 {
		t.Fatal("missing active record reached descriptor I/O")
	}
}

func TestPersistPreparingReservedDescriptorsSupportsPostAllocatorRecovery(t *testing.T) {
	fixture := newReservedDescriptorMemoryFixture(t, 12)
	if err := fixture.device.commitAllocatorSnapshot(
		fixture.update.DesiredSnapshot); err != nil {
		t.Fatalf("commit target allocator first: %v", err)
	}
	fixture.storage.resetTracking()
	if err := fixture.device.persistPreparingReservedDescriptors(
		fixture.record, fixture.runs); err != nil {
		t.Fatalf("post-allocator descriptor recovery: %v", err)
	}
	assertReservedDescriptorPages(t, fixture.storage, fixture.device.geometry, fixture.runs)
	_, allocator := fixture.device.ActiveAllocatorSnapshot()
	if allocator.SnapshotSequence != fixture.record.Fragments[0].TargetAllocatorSnapshotSequence ||
		allocator.AppliedOwnerTransactionSequence != fixture.record.OwnerTransactionSequence {
		t.Fatalf("allocator changed during descriptor recovery: %#v", allocator)
	}
}

func TestPersistPreparingReservedDescriptorsDoesNotAliasInputs(t *testing.T) {
	fixture := newReservedDescriptorMemoryFixture(t, 5)
	recordBefore := cloneOwnerStateRecord(fixture.record)
	runsBefore := append([]OwnerReservedDescriptorRun(nil), fixture.runs...)
	if err := fixture.device.persistPreparingReservedDescriptors(
		fixture.record, fixture.runs); err != nil {
		t.Fatalf("persist: %v", err)
	}
	if !reflect.DeepEqual(fixture.record, recordBefore) ||
		!reflect.DeepEqual(fixture.runs, runsBefore) {
		t.Fatal("persistence mutated caller-owned record or run slices")
	}
	firstOffset, err := fixture.device.geometry.DescriptorOffset(
		fixture.runs[0].StartDataPageIndex)
	if err != nil {
		t.Fatalf("DescriptorOffset: %v", err)
	}
	persisted := fixture.storage.rawBytes(firstOffset, PageDescriptorBytes)
	fixture.record.ContentDemands[0].ObjectID++
	fixture.record.Fragments[0].Extents[0].StartDataPageIndex++
	fixture.runs[0].Descriptor.OriginObjectID++
	if got := fixture.storage.rawBytes(firstOffset, PageDescriptorBytes); !bytes.Equal(got, persisted) {
		t.Fatal("post-return input mutation changed persisted bytes")
	}
}

func TestPersistPreparingReservedDescriptorsMemberUsesSuppliedGroupAuthority(t *testing.T) {
	geometry := metadataTestGeometry(t, 8<<20, 16<<10)
	formatFixture := metadataTestFixtureForRole(t, geometry, OwnerGroupRoleMember)
	storage := metadataTestFormat(t, formatFixture)
	device := metadataTestOpen(t, storage, formatFixture)
	demand := OwnerStateContentDemand{
		Kind:             cxlcheckpoint.ContentMemoryPayloadV7,
		ObjectID:         9,
		ByteLength:       3 * uint64(ContentPageBytes),
		CapacityPages:    3,
		LogicalPageStart: 0,
	}
	record := OwnerStateAllocationRecord{
		AllocationRecordID:       7,
		OwnerTransactionSequence: 5,
		State:                    OwnerAllocationPreparing,
		RequestID:                "member-reserve-request",
		CheckpointID:             "member-checkpoint",
		ProducerID:               "member-producer",
		DedupDomainID:            "member-dedup-domain",
		SharingPolicyID:          "member-sharing-policy",
		RequestSHA256:            sha256.Sum256([]byte("member-request")),
		TotalDemandPages:         3,
		MaxExtents:               1,
		ContentDemands:           []OwnerStateContentDemand{demand},
		Fragments: []OwnerStateDeviceFragment{{
			DeviceUUID:                      formatFixture.input.Superblock.DeviceUUID,
			DeviceOwnerEpoch:                formatFixture.input.Superblock.OwnerEpoch,
			TargetAllocatorSnapshotSequence: 2,
			Extents: []OwnerStateExtent{{
				StartDataPageIndex: 0,
				LogicalPageStart:   0,
				PageCount:          3,
			}},
		}},
	}
	runs, err := ownerReserveDescriptorRuns(
		record.ContentDemands,
		[]ownerAllocatorPlacedRun{{
			DeviceUUID:         formatFixture.input.Superblock.DeviceUUID,
			StartDataPageIndex: 0,
			LogicalPageStart:   0,
			PageCount:          3,
		}},
		record.AllocationRecordID,
		record.OwnerTransactionSequence)
	if err != nil {
		t.Fatalf("derive member runs: %v", err)
	}
	storage.resetTracking()
	if err := device.persistPreparingReservedDescriptors(record, runs); err != nil {
		t.Fatalf("MEMBER descriptor persistence: %v", err)
	}
	assertReservedDescriptorPages(t, storage, geometry, runs)
}

func newReservedDescriptorMemoryFixture(
	t *testing.T,
	pages uint64,
) *reservedDescriptorTestFixture {
	t.Helper()
	return newReservedDescriptorTestFixture(t, []OwnerStateContentDemand{{
		Kind:             cxlcheckpoint.ContentMemoryPayloadV7,
		ObjectID:         1,
		ByteLength:       pages * uint64(ContentPageBytes),
		CapacityPages:    pages,
		LogicalPageStart: 0,
	}})
}

func newReservedDescriptorTestFixture(
	t *testing.T,
	demands []OwnerStateContentDemand,
) *reservedDescriptorTestFixture {
	t.Helper()
	geometry := metadataTestGeometry(t, 16<<20, 16<<10)
	formatFixture := metadataTestFixtureForRole(t, geometry, OwnerGroupRoleAnchor)
	storage := metadataTestFormat(t, formatFixture)
	device := metadataTestOpen(t, storage, formatFixture)
	_, owner, present := device.ActiveOwnerState()
	if !present {
		t.Fatal("anchor fixture has no Owner state")
	}
	_, allocator := device.ActiveAllocatorSnapshot()
	request := ownerAllocatorTestRequest(owner, demands, MaxOwnerStateExtents)
	request.RequestID = "descriptor-reserve-request"
	request.CheckpointID = "descriptor-checkpoint"
	plan, err := PlanOwnerCheckpointReserve(owner, []OwnerAllocatorDeviceSnapshot{{
		DeviceUUID: device.superblock.DeviceUUID,
		Geometry:   geometry,
		Snapshot:   allocator,
	}}, request)
	if err != nil {
		t.Fatalf("PlanOwnerCheckpointReserve: %v", err)
	}
	if plan.Outcome != OwnerReservePlanned || len(plan.AllocatorUpdates) != 1 {
		t.Fatalf("descriptor fixture plan = outcome %d, updates %d",
			plan.Outcome, len(plan.AllocatorUpdates))
	}
	record := ownerAllocatorLastRecord(t, plan.PreparingOwnerState)
	if err := device.commitOwnerState(plan.PreparingOwnerState); err != nil {
		t.Fatalf("commit PREPARING Owner state: %v", err)
	}
	runs := make([]OwnerReservedDescriptorRun, 0, len(plan.ReservedDescriptors))
	for _, run := range plan.ReservedDescriptors {
		if run.DeviceUUID == device.superblock.DeviceUUID {
			runs = append(runs, run)
		}
	}
	storage.resetTracking()
	return &reservedDescriptorTestFixture{
		formatFixture: formatFixture,
		storage:       storage,
		device:        device,
		record:        record,
		runs:          runs,
		update:        plan.AllocatorUpdates[0],
	}
}

func openReservedDescriptorTestDevice(
	t *testing.T,
	storage *metadataTestStorage,
	fixture metadataTestFixture,
) *DeviceMetadata {
	t.Helper()
	device := metadataTestOpen(t, storage, fixture)
	storage.resetTracking()
	return device
}

func assertReservedDescriptorPages(
	t *testing.T,
	storage *metadataTestStorage,
	geometry DeviceGeometry,
	runs []OwnerReservedDescriptorRun,
) {
	t.Helper()
	for _, run := range runs {
		wire, err := run.Descriptor.MarshalBinary()
		if err != nil {
			t.Fatalf("MarshalBinary: %v", err)
		}
		for page := uint64(0); page < run.PageCount; page++ {
			offset, err := geometry.DescriptorOffset(run.StartDataPageIndex + page)
			if err != nil {
				t.Fatalf("DescriptorOffset: %v", err)
			}
			if got := storage.rawBytes(offset, PageDescriptorBytes); !bytes.Equal(got, wire) {
				t.Fatalf("descriptor page %d = %x, want %x",
					run.StartDataPageIndex+page, got, wire)
			}
		}
	}
}

func assertReservedDescriptorMutationEvents(
	t *testing.T,
	storage *metadataTestStorage,
	geometry DeviceGeometry,
	runs []OwnerReservedDescriptorRun,
) {
	t.Helper()
	selected := make(map[uint64]bool)
	for _, run := range runs {
		for page := uint64(0); page < run.PageCount; page++ {
			selected[run.StartDataPageIndex+page] = true
		}
	}
	syncs := 0
	writes := 0
	for _, event := range storage.events {
		if event.kind == "sync" {
			syncs++
			continue
		}
		if event.kind != "write" {
			t.Fatalf("unexpected event %#v", event)
		}
		writes++
		if event.length == 0 || event.length > reservedDescriptorIOBatchBytes ||
			event.length%PageDescriptorBytes != 0 ||
			event.offset < geometry.DescriptorRegionBase {
			t.Fatalf("invalid descriptor write %#v", event)
		}
		start := (event.offset - geometry.DescriptorRegionBase) / uint64(PageDescriptorBytes)
		if geometry.DescriptorRegionBase+start*uint64(PageDescriptorBytes) != event.offset {
			t.Fatalf("unaligned descriptor write %#v", event)
		}
		for page := uint64(0); page < uint64(event.length/PageDescriptorBytes); page++ {
			if !selected[start+page] {
				t.Fatalf("write touched unselected descriptor page %d", start+page)
			}
		}
	}
	if writes == 0 || syncs != 1 {
		t.Fatalf("descriptor events contain %d writes/%d Syncs: %#v",
			writes, syncs, storage.events)
	}
}

func retargetReservedDescriptorCachedAllocator(
	t *testing.T,
	device *DeviceMetadata,
	sequence,
	applied uint64,
	setFirstPage bool,
) {
	t.Helper()
	bitmap := device.allocator.BitmapBytes()
	if setFirstPage {
		ownerAllocatorSetBitmap(bitmap, 0)
	}
	allocator, err := NewAllocatorSnapshot(AllocatorSnapshotConfig{
		DeviceBindingSHA256:             device.allocator.DeviceBindingSHA256,
		OwnerGroupIdentitySHA256:        device.allocator.OwnerGroupIdentitySHA256,
		OwnerEpoch:                      device.allocator.OwnerEpoch,
		SnapshotSequence:                sequence,
		AppliedOwnerTransactionSequence: applied,
		DataPageCount:                   device.allocator.DataPageCount,
	}, bitmap)
	if err != nil {
		t.Fatalf("tampered allocator: %v", err)
	}
	exact, err := CanonicalAllocatorSnapshotBytes(allocator, device.geometry)
	if err != nil {
		t.Fatalf("canonical tampered allocator: %v", err)
	}
	device.allocator = allocator
	device.superblock.ActiveAllocatorSnapshotSequence = sequence
	device.superblock.ActiveAllocatorSnapshotLength = uint64(len(exact))
	device.superblock.ActiveAllocatorSnapshotSHA256 = sha256.Sum256(exact)
}

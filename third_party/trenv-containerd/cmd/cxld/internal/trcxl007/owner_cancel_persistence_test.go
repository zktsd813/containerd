package trcxl007

import (
	"bytes"
	"errors"
	"testing"

	"github.com/containerd/containerd/third_party/trenv-containerd/pkg/cxlcheckpoint"
)

func ownerCancelPersistenceTestRun(
	t *testing.T,
	fixture *ownerReserveExecutorTestFixture,
	record OwnerStateAllocationRecord,
) OwnerReservedDescriptorRun {
	t.Helper()
	runs, err := ownerReserveDescriptorsFromRecord(record)
	if err != nil {
		t.Fatalf("ownerReserveDescriptorsFromRecord: %v", err)
	}
	if len(runs) != 1 {
		t.Fatalf("descriptor runs = %d, want 1", len(runs))
	}
	return runs[0]
}

func ownerCancelPersistenceTestWire(
	t *testing.T,
	descriptor Descriptor,
) []byte {
	t.Helper()
	wire, err := descriptor.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary(%d): %v", descriptor.State, err)
	}
	return wire
}

func ownerCancelPersistenceTestDescriptorOffset(
	t *testing.T,
	fixture *ownerReserveExecutorTestFixture,
	run OwnerReservedDescriptorRun,
	page uint64,
) uint64 {
	t.Helper()
	if page >= run.PageCount {
		t.Fatalf("descriptor page %d outside run of %d", page, run.PageCount)
	}
	offset, err := fixture.geometry.DescriptorOffset(
		run.StartDataPageIndex + page)
	if err != nil {
		t.Fatalf("DescriptorOffset: %v", err)
	}
	return offset
}

func TestOwnerCancelDescriptorClassifierIsExactWireClassification(t *testing.T) {
	fixture := newOwnerReserveExecutorTestFixture(
		t, []string{"device-a"}, "device-a", 2<<20)
	_, granted := ownerCancelTestGrant(t, fixture, "classes", 1)
	run := ownerCancelPersistenceTestRun(t, fixture, granted)
	ownerState, _, err := fixture.group.PlannerInputs()
	if err != nil {
		t.Fatalf("PlannerInputs: %v", err)
	}
	c := ownerState.NextOwnerTransactionSequence
	reserved := ownerCancelPersistenceTestWire(t, run.Descriptor)
	quarantinedDescriptor := run.Descriptor
	quarantinedDescriptor.State = DescriptorQuarantined
	quarantinedDescriptor.OwnerTransactionSeq = c
	quarantined := ownerCancelPersistenceTestWire(t, quarantinedDescriptor)

	sealedDescriptor, err := BuildImmutableContentPageDescriptor(
		granted.AllocationRecordID,
		run.Descriptor.OriginObjectID,
		1,
		c,
		cxlcheckpoint.ContentMemoryPayloadV7,
		make([]byte, ContentPageBytes))
	if err != nil {
		t.Fatalf("BuildImmutableContentPageDescriptor: %v", err)
	}
	sealed := ownerCancelPersistenceTestWire(t, sealedDescriptor)
	publishedDescriptor, err := BuildPublishedSlotPageDescriptor(
		granted.AllocationRecordID,
		run.Descriptor.OriginObjectID,
		1,
		c,
		cxlcheckpoint.ContentPlacementSlotAV7,
		[]byte("published"))
	if err != nil {
		t.Fatalf("BuildPublishedSlotPageDescriptor: %v", err)
	}
	published := ownerCancelPersistenceTestWire(t, publishedDescriptor)
	foreignDescriptor := run.Descriptor
	foreignDescriptor.AllocationRecordID++
	foreign := ownerCancelPersistenceTestWire(t, foreignDescriptor)
	torn := make([]byte, PageDescriptorBytes)
	copy(torn, []byte{1, 2, 3, 4, 5})
	corrupt := append([]byte(nil), reserved...)
	corrupt[len(corrupt)-1] ^= 0xff

	tests := []struct {
		name string
		wire []byte
		want ownerCancelDescriptorClass
	}{
		{"free", make([]byte, PageDescriptorBytes), ownerCancelDescriptorFree},
		{"exact-reserved-R", reserved, ownerCancelDescriptorReserved},
		{"exact-quarantined-C", quarantined, ownerCancelDescriptorQuarantined},
		{"sealed", sealed, ownerCancelDescriptorConflict},
		{"published", published, ownerCancelDescriptorConflict},
		{"foreign", foreign, ownerCancelDescriptorConflict},
		{"torn", torn, ownerCancelDescriptorConflict},
		{"corrupt", corrupt, ownerCancelDescriptorConflict},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := classifyOwnerCancelDescriptor(
				test.wire, reserved, quarantined); got != test.want {
				t.Fatalf("class = %d, want %d", got, test.want)
			}
		})
	}
}

func TestOwnerCancelContentPersistenceCoversCapacityAndBoundsIO(t *testing.T) {
	fixture := newOwnerReserveExecutorTestFixture(
		t, []string{"device-a"}, "device-a", 4<<20)
	_, granted := ownerCancelTestGrant(t, fixture, "content-bound", 35)
	plan := ownerCancelTestDurableCanceling(t, fixture, granted)
	device := ownerCancelTestDevice(t, fixture, "device-a")
	storage := fixture.storages["device-a"]

	if err := device.persistCancelingContentZeroes(plan.cancelingRecord); err != nil {
		t.Fatalf("persistCancelingContentZeroes: %v", err)
	}
	if storage.maxWrite > ownerCancelIOBatchBytes {
		t.Fatalf("maximum content write = %d, bound %d",
			storage.maxWrite, ownerCancelIOBatchBytes)
	}
	var contentBytes uint64
	contentSyncs := 0
	for _, event := range *fixture.trace {
		if event.region != "content" {
			continue
		}
		if event.kind == "write" {
			contentBytes += uint64(event.length)
		}
		if event.kind == "sync" {
			contentSyncs++
		}
	}
	if contentBytes != 35*uint64(ContentPageBytes) || contentSyncs != 1 {
		t.Fatalf("content persistence bytes/Syncs = %d/%d", contentBytes, contentSyncs)
	}
	storage.maxRead = 0
	if err := device.verifyCancelingContentZeroes(plan.cancelingRecord); err != nil {
		t.Fatalf("verifyCancelingContentZeroes: %v", err)
	}
	if storage.maxRead > ownerCancelIOBatchBytes {
		t.Fatalf("maximum content read = %d, bound %d",
			storage.maxRead, ownerCancelIOBatchBytes)
	}
	ownerCancelTestAssertSelectedContentZero(t, fixture, granted)
}

func TestOwnerCancelContentVerificationScansAllAndReadErrorWins(t *testing.T) {
	t.Run("nonzero-scans-entire-capacity", func(t *testing.T) {
		fixture := newOwnerReserveExecutorTestFixture(
			t, []string{"device-a"}, "device-a", 4<<20)
		_, granted := ownerCancelTestGrant(t, fixture, "scan-nonzero", 35)
		plan := ownerCancelTestDurableCanceling(t, fixture, granted)
		storage := fixture.storages["device-a"]
		err := ownerCancelTestDevice(t, fixture, "device-a").
			verifyCancelingContentZeroes(plan.cancelingRecord)
		if !errors.Is(err, ErrOwnerCancelContentNotZero) {
			t.Fatalf("nonzero verification = %v", err)
		}
		if storage.readCalls != 3 {
			t.Fatalf("35-page verification reads = %d, want 3", storage.readCalls)
		}
	})

	t.Run("later-read-error-wins-and-latches-reopen", func(t *testing.T) {
		fixture := newOwnerReserveExecutorTestFixture(
			t, []string{"device-a"}, "device-a", 4<<20)
		_, granted := ownerCancelTestGrant(t, fixture, "scan-error", 35)
		plan := ownerCancelTestDurableCanceling(t, fixture, granted)
		first := granted.Fragments[0].Extents[0].StartDataPageIndex
		secondBatchOffset, err := fixture.geometry.ContentOffset(first + 16)
		if err != nil {
			t.Fatalf("ContentOffset: %v", err)
		}
		storage := fixture.storages["device-a"]
		storage.failReadOffset = &secondBatchOffset
		device := ownerCancelTestDevice(t, fixture, "device-a")
		err = device.verifyCancelingContentZeroes(plan.cancelingRecord)
		if !errors.Is(err, ErrDeviceMetadataStorage) ||
			errors.Is(err, ErrOwnerCancelContentNotZero) {
			t.Fatalf("later read error = %v", err)
		}
		if storage.readCalls != 2 || !device.reopenRequired {
			t.Fatalf("later read failure calls/reopen = %d/%v",
				storage.readCalls, device.reopenRequired)
		}
	})
}

func TestOwnerCancelDescriptorPersistenceCleanAndQuarantine(t *testing.T) {
	t.Run("clean-accepts-only-free-or-exact-reserved", func(t *testing.T) {
		fixture := newOwnerReserveExecutorTestFixture(
			t, []string{"device-a"}, "device-a", 2<<20)
		_, granted := ownerCancelTestGrant(t, fixture, "descriptor-clean", 3)
		plan := ownerCancelTestDurableCanceling(t, fixture, granted)
		run := ownerCancelPersistenceTestRun(t, fixture, granted)
		storage := fixture.storages["device-a"]
		firstOffset := ownerCancelPersistenceTestDescriptorOffset(t, fixture, run, 0)
		storage.rawWrite(firstOffset, make([]byte, PageDescriptorBytes))
		fixture.resetTracking()
		device := ownerCancelTestDevice(t, fixture, "device-a")
		if err := device.persistCancelingDescriptorDisposition(
			plan.cancelingRecord, OwnerCancelClean, false); err != nil {
			t.Fatalf("clean descriptor persistence: %v", err)
		}
		for page := uint64(0); page < run.PageCount; page++ {
			offset := ownerCancelPersistenceTestDescriptorOffset(t, fixture, run, page)
			if got := storage.rawBytes(offset, PageDescriptorBytes); !allZero(got) {
				t.Fatalf("clean descriptor page %d = %x", page, got)
			}
		}
	})

	t.Run("quarantine-rewrites-safe-pages-and-preserves-conflict", func(t *testing.T) {
		fixture := newOwnerReserveExecutorTestFixture(
			t, []string{"device-a"}, "device-a", 2<<20)
		_, granted := ownerCancelTestGrant(t, fixture, "descriptor-q", 3)
		plan := ownerCancelTestDurableCanceling(t, fixture, granted)
		run := ownerCancelPersistenceTestRun(t, fixture, granted)
		storage := fixture.storages["device-a"]
		freeOffset := ownerCancelPersistenceTestDescriptorOffset(t, fixture, run, 0)
		conflictOffset := ownerCancelPersistenceTestDescriptorOffset(t, fixture, run, 2)
		storage.rawWrite(freeOffset, make([]byte, PageDescriptorBytes))
		conflict := make([]byte, PageDescriptorBytes)
		copy(conflict, []byte("sealed-or-foreign-raw-conflict"))
		storage.rawWrite(conflictOffset, conflict)
		wantContent := ownerCancelTestSelectedContent(t, fixture, granted)
		fixture.resetTracking()

		device := ownerCancelTestDevice(t, fixture, "device-a")
		if err := device.persistCancelingDescriptorDisposition(
			plan.cancelingRecord, OwnerCancelQuarantine, false); err != nil {
			t.Fatalf("Quarantine descriptor persistence: %v", err)
		}
		q := run.Descriptor
		q.State = DescriptorQuarantined
		q.OwnerTransactionSeq = plan.cancelingRecord.OwnerTransactionSequence
		qWire := ownerCancelPersistenceTestWire(t, q)
		for _, page := range []uint64{0, 1} {
			offset := ownerCancelPersistenceTestDescriptorOffset(t, fixture, run, page)
			if got := storage.rawBytes(offset, PageDescriptorBytes); !bytes.Equal(got, qWire) {
				t.Fatalf("Quarantine descriptor page %d = %x, want %x",
					page, got, qWire)
			}
		}
		if got := storage.rawBytes(
			conflictOffset, PageDescriptorBytes); !bytes.Equal(got, conflict) {
			t.Fatalf("conflict bytes changed: %x", got)
		}
		ownerCancelTestAssertSelectedContentEqual(t, fixture, granted, wantContent)
		for _, event := range *fixture.trace {
			if event.region == "content" {
				t.Fatalf("descriptor-only Quarantine touched content: %#v", event)
			}
		}
	})
}

func TestOwnerCancelBatchLimits(t *testing.T) {
	if got := ownerCancelBatchPages(1000); got !=
		uint64(ownerCancelIOBatchBytes/ContentPageBytes) {
		t.Fatalf("content batch pages = %d", got)
	}
	if got := ownerCancelDescriptorBatchPages(100000); got !=
		uint64(ownerCancelIOBatchBytes/PageDescriptorBytes) {
		t.Fatalf("descriptor batch pages = %d", got)
	}
}

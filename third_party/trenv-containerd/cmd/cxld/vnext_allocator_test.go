package main

import (
	"errors"
	"fmt"
	"math/rand"
	"os"
	"sync"
	"testing"
)

func newTestVNextAllocator(t *testing.T, deviceBytes, slotBytes uint64) *vnextCheckpointAllocator {
	t.Helper()
	geometry, err := calculateVNextDeviceGeometry(deviceBytes, slotBytes)
	if err != nil {
		t.Fatalf("calculate test geometry: %v", err)
	}
	allocator, err := newVNextCheckpointAllocator(vnextDeviceSuperblock{
		DeviceUUID: "test-device",
		OwnerID:    "owner-0",
		OwnerEpoch: 7,
		Sequence:   2,
		Geometry:   geometry,
	})
	if err != nil {
		t.Fatalf("create allocator: %v", err)
	}
	return allocator
}

func testVNextRequest(id string, pages uint64) vnextCheckpointAllocationRequest {
	return vnextCheckpointAllocationRequest{
		RequestID:    "request-" + id,
		CheckpointID: "checkpoint-" + id,
		ProducerID:   "producer-" + id,
		OwnerID:      "owner-0",
		OwnerEpoch:   7,
		Contents: []vnextContentRequest{{
			Kind:       vnextContentMemory,
			ObjectID:   uint64(len(id)) + uint64(id[0]) + 1,
			ByteLength: pages * vnextContentPageSize,
		}},
		MaxExtents: 64,
	}
}

func commitVNextAllocation(t *testing.T, allocator *vnextCheckpointAllocator, grant vnextWriteGrant) vnextAllocationRecord {
	t.Helper()
	if err := allocator.commit(grant); err != nil {
		t.Fatalf("commit allocation %d: %v", grant.AllocationRecordID, err)
	}
	record, ok := allocator.lookup(grant.CheckpointID)
	if !ok {
		t.Fatalf("lookup committed allocation %d", grant.AllocationRecordID)
	}
	return record
}

func reclaimVNextAllocation(t *testing.T, allocator *vnextCheckpointAllocator, record vnextAllocationRecord) {
	t.Helper()
	err := allocator.reclaimCheckpoint(vnextReclaimRequest{
		Authority: vnextOwnerAuthority{
			DeviceUUID: "test-device",
			OwnerID:    "owner-0",
			OwnerEpoch: 7,
		},
		CheckpointID:           record.CheckpointID,
		AllocationRecordID:     record.AllocationRecordID,
		ExpectedCommitSequence: record.OwnerTransaction,
	})
	if err != nil {
		t.Fatalf("reclaim allocation %d: %v", record.AllocationRecordID, err)
	}
}

func TestVNextAllocatorUsesOnePoolForMemoryAndArtifacts(t *testing.T) {
	allocator := newTestVNextAllocator(t, 8<<20, 128<<10)
	request := vnextCheckpointAllocationRequest{
		RequestID:    "request-unified",
		CheckpointID: "checkpoint-unified",
		ProducerID:   "producer-a",
		OwnerID:      "owner-0",
		OwnerEpoch:   7,
		MaxExtents:   8,
		Contents: []vnextContentRequest{
			{Kind: vnextContentMemory, ObjectID: 1, ByteLength: 4096},
			{Kind: vnextContentArtifact, ObjectID: 2, ByteLength: 4097},
			{Kind: vnextContentMMTemplate, ObjectID: 3, ByteLength: 1},
		},
	}
	before := allocator.freePages()
	grant, err := allocator.reserve(request)
	if err != nil {
		t.Fatalf("reserve unified content: %v", err)
	}
	if len(grant.Extents) != 1 || grant.Extents[0].PageCount != 4 {
		t.Fatalf("unified content did not use one ordinary run: %#v", grant.Extents)
	}
	if before-allocator.freePages() != 4 {
		t.Fatalf("unified request consumed %d pages, expected 4", before-allocator.freePages())
	}
	wantLengths := []uint32{4096, 4096, 1, 1}
	wantKinds := []vnextContentKind{
		vnextContentMemory,
		vnextContentArtifact,
		vnextContentArtifact,
		vnextContentMMTemplate,
	}
	for logicalPage := uint64(0); logicalPage < 4; logicalPage++ {
		authorization, err := allocator.authorizePageWrite(grant, logicalPage)
		if err != nil {
			t.Fatalf("authorize logical page %d: %v", logicalPage, err)
		}
		if authorization.ExpectedPayloadLength != wantLengths[logicalPage] ||
			authorization.ContentKind != wantKinds[logicalPage] {
			t.Fatalf("logical page %d authorization: %#v", logicalPage, authorization)
		}
	}
	repeated, err := allocator.reserve(request)
	if err != nil {
		t.Fatalf("idempotent reserve: %v", err)
	}
	if repeated.WriteToken != grant.WriteToken ||
		repeated.AllocationRecordID != grant.AllocationRecordID {
		t.Fatal("idempotent reserve issued a new writer identity")
	}
	conflicting := request
	conflicting.Contents[1].ByteLength++
	if _, err := allocator.reserve(conflicting); !errors.Is(err, errVNextAlreadyExists) {
		t.Fatalf("conflicting request reuse returned %v", err)
	}
}

func TestVNextAllocatorEnforcesOwnerAndSingleWriter(t *testing.T) {
	allocator := newTestVNextAllocator(t, 8<<20, 128<<10)
	request := testVNextRequest("authority", 2)
	wrongOwner := request
	wrongOwner.OwnerEpoch++
	if _, err := allocator.reserve(wrongOwner); !errors.Is(err, errVNextAuthority) {
		t.Fatalf("wrong owner epoch returned %v", err)
	}
	grant, err := allocator.reserve(request)
	if err != nil {
		t.Fatalf("reserve: %v", err)
	}
	tampered := grant
	tampered.ProducerID = "other-producer"
	if _, err := allocator.authorizePageWrite(tampered, 0); !errors.Is(err, errVNextAuthority) {
		t.Fatalf("wrong producer returned %v", err)
	}
	tampered = grant
	tampered.WriteToken[0] ^= 0xff
	if err := allocator.commit(tampered); !errors.Is(err, errVNextAuthority) {
		t.Fatalf("wrong token returned %v", err)
	}
	if _, err := allocator.authorizePageWrite(grant, 2); err == nil {
		t.Fatal("out-of-range logical page was authorized")
	}
	if err := allocator.commit(grant); err != nil {
		t.Fatalf("commit: %v", err)
	}
	if _, err := allocator.authorizePageWrite(grant, 0); err == nil {
		t.Fatal("committed allocation still accepted producer writes")
	}
}

func TestVNextAllocatorFragmentsCheckpointAndFailsAtomicallyAtExtentBudget(t *testing.T) {
	allocator := newTestVNextAllocator(t, 2<<20, 64<<10)
	grants := make([]vnextWriteGrant, 4)
	records := make([]vnextAllocationRecord, 4)
	for index := range grants {
		request := testVNextRequest(fmt.Sprintf("fragment-%d", index), 2)
		grant, err := allocator.reserve(request)
		if err != nil {
			t.Fatalf("reserve %d: %v", index, err)
		}
		grants[index] = grant
		records[index] = commitVNextAllocation(t, allocator, grant)
	}
	reclaimVNextAllocation(t, allocator, records[1])
	reclaimVNextAllocation(t, allocator, records[3])

	request := testVNextRequest("fragment-target", 5)
	request.MaxExtents = 1
	beforeFree := allocator.freePages()
	allocator.mu.Lock()
	beforeID := allocator.nextAllocationRecordID
	allocator.mu.Unlock()
	if _, err := allocator.reserve(request); !errors.Is(err, errVNextNoSpace) {
		t.Fatalf("one-extent fragmented request returned %v", err)
	}
	if allocator.freePages() != beforeFree {
		t.Fatal("failed extent plan consumed bitmap capacity")
	}
	allocator.mu.Lock()
	afterID := allocator.nextAllocationRecordID
	allocator.mu.Unlock()
	if afterID != beforeID {
		t.Fatal("failed extent plan consumed an allocation record ID")
	}
	request.MaxExtents = 2
	grant, err := allocator.reserve(request)
	if err != nil {
		t.Fatalf("fragmented reserve: %v", err)
	}
	if len(grant.Extents) != 2 ||
		grant.Extents[0].StartDataPageIndex != 2 ||
		grant.Extents[0].PageCount != 2 {
		t.Fatalf("unexpected fragmented extents: %#v", grant.Extents)
	}
	if err := allocator.validate(); err != nil {
		t.Fatalf("allocator invariant after fragmented reserve: %v", err)
	}
}

func TestVNextAllocatorAbortAndReclaimNeverReuseAllocationID(t *testing.T) {
	allocator := newTestVNextAllocator(t, 2<<20, 64<<10)
	first, err := allocator.reserve(testVNextRequest("abort-a", 3))
	if err != nil {
		t.Fatalf("reserve first: %v", err)
	}
	firstStart := first.Extents[0].StartDataPageIndex
	if err := allocator.abort(first); err != nil {
		t.Fatalf("abort first: %v", err)
	}
	second, err := allocator.reserve(testVNextRequest("abort-b", 3))
	if err != nil {
		t.Fatalf("reserve second: %v", err)
	}
	if second.AllocationRecordID <= first.AllocationRecordID {
		t.Fatal("aborted allocation record ID was reused")
	}
	if second.Extents[0].StartDataPageIndex != firstStart {
		t.Fatal("aborted physical hole was not reusable")
	}
	secondRecord := commitVNextAllocation(t, allocator, second)
	reclaimVNextAllocation(t, allocator, secondRecord)
	third, err := allocator.reserve(testVNextRequest("abort-c", 3))
	if err != nil {
		t.Fatalf("reserve third: %v", err)
	}
	if third.AllocationRecordID <= second.AllocationRecordID {
		t.Fatal("reclaimed allocation record ID was reused")
	}
	if third.Extents[0].StartDataPageIndex != firstStart {
		t.Fatal("reclaimed physical hole was not reusable")
	}
}

func TestVNextAllocatorSnapshotRoundTripAndFaultRejection(t *testing.T) {
	allocator := newTestVNextAllocator(t, 4<<20, 128<<10)
	first, err := allocator.reserve(testVNextRequest("snapshot-a", 3))
	if err != nil {
		t.Fatalf("reserve first: %v", err)
	}
	commitVNextAllocation(t, allocator, first)
	second, err := allocator.reserve(testVNextRequest("snapshot-b", 2))
	if err != nil {
		t.Fatalf("reserve second: %v", err)
	}
	if err := allocator.abort(second); err != nil {
		t.Fatalf("abort second: %v", err)
	}
	data, _, err := allocator.marshalNextSnapshot()
	if err != nil {
		t.Fatalf("marshal snapshot: %v", err)
	}
	path := t.TempDir() + "/allocator.bin"
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("write file-backed snapshot: %v", err)
	}
	fromFile, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read file-backed snapshot: %v", err)
	}
	restored, err := parseVNextAllocatorSnapshot(fromFile, allocator.superblock)
	if err != nil {
		t.Fatalf("parse snapshot: %v", err)
	}
	if err := restored.validate(); err != nil {
		t.Fatalf("restored allocator invariant: %v", err)
	}
	if restored.freePages() != allocator.freePages() {
		t.Fatalf("free pages changed across restart: got %d want %d", restored.freePages(), allocator.freePages())
	}
	restoredRecord, ok := restored.lookup(first.CheckpointID)
	if !ok || restoredRecord.State != vnextAllocationCommitted {
		t.Fatalf("committed record was not restored: %#v", restoredRecord)
	}
	legacy := append([]byte(nil), data...)
	copy(legacy[:8], []byte("TRALC005"))
	if _, err := parseVNextAllocatorSnapshot(legacy, allocator.superblock); !errors.Is(err, errVNextWrongFormat) {
		t.Fatalf("legacy allocator snapshot returned %v", err)
	}
	corrupt := append([]byte(nil), data...)
	corrupt[len(corrupt)-1] ^= 0x80
	if _, err := parseVNextAllocatorSnapshot(corrupt, allocator.superblock); !errors.Is(err, errVNextCorrupt) {
		t.Fatalf("corrupt allocator snapshot returned %v", err)
	}
	for length := 0; length < len(data); length += 37 {
		if _, err := parseVNextAllocatorSnapshot(data[:length], allocator.superblock); err == nil {
			t.Fatalf("truncated allocator snapshot at %d bytes was accepted", length)
		}
	}
}

func TestVNextAllocatorMetadataCapacityFailsBeforeBitmapReservation(t *testing.T) {
	allocator := newTestVNextAllocator(t, 2<<20, 4<<10)
	for index := 0; index < 1000; index++ {
		request := testVNextRequest(fmt.Sprintf("metadata-%d", index), 1)
		beforeFree := allocator.freePages()
		allocator.mu.Lock()
		beforeID := allocator.nextAllocationRecordID
		allocator.mu.Unlock()
		grant, err := allocator.reserve(request)
		if errors.Is(err, errVNextMetadataFull) {
			if allocator.freePages() != beforeFree {
				t.Fatal("metadata-full request consumed a payload page")
			}
			allocator.mu.Lock()
			afterID := allocator.nextAllocationRecordID
			allocator.mu.Unlock()
			if afterID != beforeID {
				t.Fatal("metadata-full request consumed an allocation ID")
			}
			return
		}
		if err != nil {
			t.Fatalf("reserve before metadata full at %d: %v", index, err)
		}
		if err := allocator.abort(grant); err != nil {
			t.Fatalf("abort at %d: %v", index, err)
		}
	}
	t.Fatal("4 KiB allocator record slot did not reach an explicit metadata limit")
}

func TestVNextAllocatorRandomTracePreservesInvariants(t *testing.T) {
	allocator := newTestVNextAllocator(t, 16<<20, 512<<10)
	random := rand.New(rand.NewSource(0x5eed))
	for index := 0; index < 500; index++ {
		pages := uint64(random.Intn(8) + 1)
		request := testVNextRequest(fmt.Sprintf("random-%d", index), pages)
		request.MaxExtents = 16
		grant, err := allocator.reserve(request)
		if err != nil {
			t.Fatalf("random reserve %d: %v", index, err)
		}
		if random.Intn(3) == 0 {
			if err := allocator.abort(grant); err != nil {
				t.Fatalf("random abort %d: %v", index, err)
			}
		} else {
			record := commitVNextAllocation(t, allocator, grant)
			reclaimVNextAllocation(t, allocator, record)
		}
		if err := allocator.validate(); err != nil {
			t.Fatalf("random trace invariant at operation %d: %v", index, err)
		}
	}
}

func TestVNextAllocatorConcurrentReservationsDoNotOverlap(t *testing.T) {
	allocator := newTestVNextAllocator(t, 8<<20, 256<<10)
	const workers = 64
	grants := make(chan vnextWriteGrant, workers)
	errs := make(chan error, workers)
	var wait sync.WaitGroup
	for worker := 0; worker < workers; worker++ {
		wait.Add(1)
		go func(worker int) {
			defer wait.Done()
			request := testVNextRequest(fmt.Sprintf("concurrent-%d", worker), 1)
			request.MaxExtents = 1
			grant, err := allocator.reserve(request)
			if err != nil {
				errs <- err
				return
			}
			grants <- grant
		}(worker)
	}
	wait.Wait()
	close(grants)
	close(errs)
	for err := range errs {
		t.Fatalf("concurrent reserve: %v", err)
	}
	seen := make(map[uint64]uint64)
	for grant := range grants {
		page := grant.Extents[0].StartDataPageIndex
		if previous, exists := seen[page]; exists {
			t.Fatalf("page %d granted to allocations %d and %d", page, previous, grant.AllocationRecordID)
		}
		seen[page] = grant.AllocationRecordID
	}
	if len(seen) != workers {
		t.Fatalf("got %d grants, want %d", len(seen), workers)
	}
	if err := allocator.validate(); err != nil {
		t.Fatalf("concurrent allocator invariant: %v", err)
	}
}

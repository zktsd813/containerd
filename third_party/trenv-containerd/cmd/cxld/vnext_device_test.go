package main

import (
	"bytes"
	"errors"
	"os"
	"testing"
)

func newTestVNextPersistentDevice(
	t *testing.T,
	deviceBytes int64,
	slotBytes uint64,
) (*os.File, *vnextPersistentDevice) {
	t.Helper()
	path := t.TempDir() + "/dax.img"
	file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR|os.O_EXCL, 0o600)
	if err != nil {
		t.Fatalf("create file-backed DAX: %v", err)
	}
	t.Cleanup(func() {
		_ = file.Close()
	})
	if err := file.Truncate(deviceBytes); err != nil {
		t.Fatalf("truncate file-backed DAX: %v", err)
	}
	device, err := formatVNextFileDevice(file, "test-device", "owner-0", 7, slotBytes)
	if err != nil {
		t.Fatalf("format file-backed VNext device: %v", err)
	}
	return file, device
}

func writeAllVNextGrantPages(
	t *testing.T,
	device *vnextPersistentDevice,
	grant vnextWriteGrant,
) [][]byte {
	t.Helper()
	record, ok := device.allocator.lookup(grant.CheckpointID)
	if !ok {
		t.Fatal("lookup reserved allocation")
	}
	contents := make([][]byte, record.TotalPages)
	for logicalPage := uint64(0); logicalPage < record.TotalPages; logicalPage++ {
		authorization, err := device.allocator.authorizePageWrite(grant, logicalPage)
		if err != nil {
			t.Fatalf("authorize page %d: %v", logicalPage, err)
		}
		content := bytes.Repeat(
			[]byte{byte(logicalPage + 1)},
			int(authorization.ExpectedPayloadLength))
		contents[logicalPage] = content
		if err := device.writePage(grant, logicalPage, content); err != nil {
			t.Fatalf("write page %d: %v", logicalPage, err)
		}
	}
	return contents
}

func TestVNextPersistentDeviceUnifiedLifecycleAndRestart(t *testing.T) {
	file, device := newTestVNextPersistentDevice(t, 8<<20, 128<<10)
	request := vnextCheckpointAllocationRequest{
		RequestID:    "request-file-lifecycle",
		CheckpointID: "checkpoint-file-lifecycle",
		ProducerID:   "producer-file",
		OwnerID:      "owner-0",
		OwnerEpoch:   7,
		MaxExtents:   8,
		Contents: []vnextContentRequest{
			{Kind: vnextContentMemory, ObjectID: 101, ByteLength: 4096, PageCount: 1},
			{Kind: vnextContentArtifact, ObjectID: 102, ByteLength: 4100, PageCount: 2},
		},
	}
	initialFree := device.allocator.freePages()
	grant, err := device.reserve(request)
	if err != nil {
		t.Fatalf("reserve: %v", err)
	}
	if initialFree-device.allocator.freePages() != 3 {
		t.Fatalf("reservation consumed %d pages, want 3", initialFree-device.allocator.freePages())
	}
	for logicalPage := uint64(0); logicalPage < 3; logicalPage++ {
		authorization, err := device.allocator.authorizePageWrite(grant, logicalPage)
		if err != nil {
			t.Fatalf("authorize reserved page %d: %v", logicalPage, err)
		}
		descriptor, err := device.readDescriptorLocked(authorization.DataPageIndex)
		if err != nil {
			t.Fatalf("read reserved descriptor: %v", err)
		}
		if descriptor.State != vnextDescriptorReserved ||
			descriptor.AllocationRecordID != grant.AllocationRecordID {
			t.Fatalf("unexpected reserved descriptor: %#v", descriptor)
		}
	}
	contents := writeAllVNextGrantPages(t, device, grant)
	if err := device.writePage(grant, 2, contents[2]); err != nil {
		t.Fatalf("idempotent producer page retry: %v", err)
	}
	different := append([]byte(nil), contents[2]...)
	different[0] ^= 0xff
	if err := device.writePage(grant, 2, different); !errors.Is(err, errVNextAuthority) {
		t.Fatalf("different sealed-page retry returned %v", err)
	}
	if err := device.commit(grant); err != nil {
		t.Fatalf("commit: %v", err)
	}
	committed, ok := device.allocator.lookup(request.CheckpointID)
	if !ok || committed.State != vnextAllocationCommitted {
		t.Fatalf("unexpected committed record: %#v", committed)
	}
	if _, err := device.allocator.authorizePageWrite(grant, 0); err == nil {
		t.Fatal("commit did not revoke producer write grant")
	}

	reopened, err := openVNextFileDevice(file)
	if err != nil {
		t.Fatalf("reopen committed device: %v", err)
	}
	restartedRecord, ok := reopened.allocator.lookup(request.CheckpointID)
	if !ok || restartedRecord.State != vnextAllocationCommitted ||
		restartedRecord.AllocationRecordID != grant.AllocationRecordID {
		t.Fatalf("committed allocation did not survive restart: %#v", restartedRecord)
	}
	for logicalPage := uint64(0); logicalPage < restartedRecord.TotalPages; logicalPage++ {
		dataPage, err := vnextRecordPhysicalPage(&restartedRecord, logicalPage)
		if err != nil {
			t.Fatalf("physical page %d: %v", logicalPage, err)
		}
		page, err := reopened.readContentPageLocked(dataPage)
		if err != nil {
			t.Fatalf("read content page %d: %v", logicalPage, err)
		}
		if !bytes.Equal(page[:len(contents[logicalPage])], contents[logicalPage]) {
			t.Fatalf("content page %d changed across restart", logicalPage)
		}
	}

	firstPhysical := restartedRecord.Extents[0].StartDataPageIndex
	if err := reopened.reclaimCheckpoint(vnextReclaimRequest{
		Authority: vnextOwnerAuthority{
			DeviceUUID: "test-device",
			OwnerID:    "owner-0",
			OwnerEpoch: 7,
		},
		CheckpointID:           restartedRecord.CheckpointID,
		AllocationRecordID:     restartedRecord.AllocationRecordID,
		ExpectedCommitSequence: restartedRecord.OwnerTransaction,
	}); err != nil {
		t.Fatalf("whole-checkpoint reclaim: %v", err)
	}
	if reopened.allocator.freePages() != initialFree {
		t.Fatalf("reclaim left %d of %d pages free", reopened.allocator.freePages(), initialFree)
	}
	for _, extent := range restartedRecord.Extents {
		for page := uint64(0); page < extent.PageCount; page++ {
			descriptor, err := reopened.readDescriptorLocked(extent.StartDataPageIndex + page)
			if err != nil {
				t.Fatalf("read reclaimed descriptor: %v", err)
			}
			if descriptor.State != vnextDescriptorFree {
				t.Fatalf("reclaimed descriptor is state %d", descriptor.State)
			}
		}
	}
	reopenedAgain, err := openVNextFileDevice(file)
	if err != nil {
		t.Fatalf("reopen reclaimed device: %v", err)
	}
	nextRequest := testVNextRequest("file-reuse", 3)
	nextGrant, err := reopenedAgain.reserve(nextRequest)
	if err != nil {
		t.Fatalf("reserve reclaimed hole: %v", err)
	}
	if nextGrant.AllocationRecordID <= grant.AllocationRecordID {
		t.Fatal("reclaimed page reused an allocation record ID")
	}
	if nextGrant.Extents[0].StartDataPageIndex != firstPhysical {
		t.Fatal("allocator did not reuse the reclaimed physical hole")
	}
}

func TestVNextPersistentDeviceRequiresZeroFilledCapacityPadding(t *testing.T) {
	_, device := newTestVNextPersistentDevice(t, 8<<20, 128<<10)
	request := vnextCheckpointAllocationRequest{
		RequestID:    "request-zero-capacity-padding",
		CheckpointID: "checkpoint-zero-capacity-padding",
		ProducerID:   "producer-zero-capacity-padding",
		OwnerID:      "owner-0",
		OwnerEpoch:   7,
		MaxExtents:   1,
		Contents: []vnextContentRequest{{
			Kind:       vnextContentPageMap,
			ObjectID:   501,
			ByteLength: 3,
			PageCount:  2,
		}},
	}
	grant, err := device.reserve(request)
	if err != nil {
		t.Fatalf("reserve padded PageMap slot: %v", err)
	}
	if err := device.writePage(grant, 0, []byte{1, 2, 3}); err != nil {
		t.Fatalf("write meaningful PageMap bytes: %v", err)
	}
	nonZero := bytes.Repeat([]byte{1}, int(vnextContentPageSize))
	if err := device.writePage(grant, 1, nonZero); !errors.Is(err, errVNextAuthority) {
		t.Fatalf("non-zero capacity padding returned %v", err)
	}
	if err := device.writePage(grant, 1, make([]byte, vnextContentPageSize)); err != nil {
		t.Fatalf("seal zero capacity padding: %v", err)
	}
	if err := device.commit(grant); err != nil {
		t.Fatalf("commit capacity-aware PageMap slot: %v", err)
	}
}

func TestVNextPersistentDeviceAbortClearsPartialProducerWrites(t *testing.T) {
	file, device := newTestVNextPersistentDevice(t, 4<<20, 64<<10)
	request := testVNextRequest("file-abort", 2)
	initialFree := device.allocator.freePages()
	grant, err := device.reserve(request)
	if err != nil {
		t.Fatalf("reserve: %v", err)
	}
	authorization, err := device.allocator.authorizePageWrite(grant, 0)
	if err != nil {
		t.Fatalf("authorize first page: %v", err)
	}
	if err := device.writePage(
		grant,
		0,
		bytes.Repeat([]byte{0xa5}, int(authorization.ExpectedPayloadLength))); err != nil {
		t.Fatalf("write first page: %v", err)
	}
	if err := device.abort(grant); err != nil {
		t.Fatalf("abort: %v", err)
	}
	if device.allocator.freePages() != initialFree {
		t.Fatal("abort did not return the whole checkpoint allocation")
	}
	record, ok := device.allocator.lookup(request.CheckpointID)
	if !ok || record.State != vnextAllocationAborted {
		t.Fatalf("unexpected aborted record: %#v", record)
	}
	for _, extent := range record.Extents {
		for page := uint64(0); page < extent.PageCount; page++ {
			descriptor, err := device.readDescriptorLocked(extent.StartDataPageIndex + page)
			if err != nil {
				t.Fatalf("read aborted descriptor: %v", err)
			}
			if descriptor.State != vnextDescriptorFree {
				t.Fatalf("abort left descriptor state %d", descriptor.State)
			}
		}
	}
	if _, err := openVNextFileDevice(file); err != nil {
		t.Fatalf("reopen aborted device: %v", err)
	}
}

func TestVNextPersistentDeviceReserveRetryRepairsTornDescriptorInitialization(t *testing.T) {
	file, device := newTestVNextPersistentDevice(t, 4<<20, 64<<10)
	request := testVNextRequest("descriptor-retry", 2)
	grant, err := device.reserve(request)
	if err != nil {
		t.Fatalf("reserve: %v", err)
	}
	firstAuthorization, err := device.allocator.authorizePageWrite(grant, 0)
	if err != nil {
		t.Fatalf("authorize first page: %v", err)
	}
	if err := device.writePage(
		grant,
		0,
		bytes.Repeat([]byte{0x33}, int(firstAuthorization.ExpectedPayloadLength))); err != nil {
		t.Fatalf("seal first page: %v", err)
	}
	secondAuthorization, err := device.allocator.authorizePageWrite(grant, 1)
	if err != nil {
		t.Fatalf("authorize second page: %v", err)
	}
	if err := vnextWriteAtFull(
		file,
		make([]byte, vnextPageDescriptorSize),
		secondAuthorization.DescriptorOffset); err != nil {
		t.Fatalf("simulate torn descriptor initialization: %v", err)
	}
	if err := file.Sync(); err != nil {
		t.Fatalf("sync torn descriptor simulation: %v", err)
	}
	reopened, err := openVNextFileDevice(file)
	if err != nil {
		t.Fatalf("reopen partially initialized reservation: %v", err)
	}
	retriedGrant, err := reopened.reserve(request)
	if err != nil {
		t.Fatalf("idempotent reserve retry: %v", err)
	}
	if retriedGrant.AllocationRecordID != grant.AllocationRecordID ||
		retriedGrant.WriteToken != grant.WriteToken {
		t.Fatal("reserve retry changed allocation or writer identity")
	}
	firstDescriptor, err := reopened.readDescriptorLocked(firstAuthorization.DataPageIndex)
	if err != nil {
		t.Fatalf("read sealed retry descriptor: %v", err)
	}
	secondDescriptor, err := reopened.readDescriptorLocked(secondAuthorization.DataPageIndex)
	if err != nil {
		t.Fatalf("read repaired retry descriptor: %v", err)
	}
	if firstDescriptor.State != vnextDescriptorSealed ||
		secondDescriptor.State != vnextDescriptorReserved {
		t.Fatalf("retry states are sealed=%d reserved=%d", firstDescriptor.State, secondDescriptor.State)
	}
}

func TestVNextPersistentDeviceABRecovery(t *testing.T) {
	t.Run("corrupt newest superblock", func(t *testing.T) {
		file, _ := newTestVNextPersistentDevice(t, 4<<20, 64<<10)
		if err := vnextWriteAtFull(file, make([]byte, vnextFormatHeaderSize), vnextSuperblockSlotBytes); err != nil {
			t.Fatalf("corrupt superblock B: %v", err)
		}
		if err := file.Sync(); err != nil {
			t.Fatalf("sync corruption: %v", err)
		}
		device, err := openVNextFileDevice(file)
		if err != nil {
			t.Fatalf("fallback to superblock A: %v", err)
		}
		if device.superblock.Sequence != 1 {
			t.Fatalf("selected superblock sequence %d, want 1", device.superblock.Sequence)
		}
	})

	t.Run("torn newest allocator snapshot", func(t *testing.T) {
		file, device := newTestVNextPersistentDevice(t, 4<<20, 64<<10)
		offset := device.superblock.Geometry.AllocatorSlotBOffset
		if err := vnextWriteAtFull(file, make([]byte, vnextFormatHeaderSize), offset); err != nil {
			t.Fatalf("tear allocator B header: %v", err)
		}
		if err := file.Sync(); err != nil {
			t.Fatalf("sync torn allocator: %v", err)
		}
		reopened, err := openVNextFileDevice(file)
		if err != nil {
			t.Fatalf("fallback to allocator A: %v", err)
		}
		reopened.allocator.mu.Lock()
		sequence := reopened.allocator.snapshotSequence
		reopened.allocator.mu.Unlock()
		if sequence != 1 {
			t.Fatalf("selected allocator sequence %d, want 1", sequence)
		}
	})

	t.Run("corrupt newest allocator payload", func(t *testing.T) {
		file, device := newTestVNextPersistentDevice(t, 4<<20, 64<<10)
		offset := device.superblock.Geometry.AllocatorSlotBOffset + uint64(vnextFormatHeaderSize)
		one := []byte{0}
		if err := vnextReadAtFull(file, one, offset); err != nil {
			t.Fatalf("read allocator B payload: %v", err)
		}
		one[0] ^= 0xff
		if err := vnextWriteAtFull(file, one, offset); err != nil {
			t.Fatalf("corrupt allocator B payload: %v", err)
		}
		if err := file.Sync(); err != nil {
			t.Fatalf("sync corruption: %v", err)
		}
		reopened, err := openVNextFileDevice(file)
		if err != nil {
			t.Fatalf("fallback after payload corruption: %v", err)
		}
		reopened.allocator.mu.Lock()
		sequence := reopened.allocator.snapshotSequence
		reopened.allocator.mu.Unlock()
		if sequence != 1 {
			t.Fatalf("selected allocator sequence %d, want 1", sequence)
		}
	})

	t.Run("stale descriptor prevents unsafe fallback", func(t *testing.T) {
		file, device := newTestVNextPersistentDevice(t, 4<<20, 64<<10)
		if _, err := device.reserve(testVNextRequest("unsafe-fallback", 1)); err != nil {
			t.Fatalf("reserve: %v", err)
		}
		// Reservation sequence 3 is in A. Destroying it exposes sequence 2,
		// whose bitmap says FREE while the descriptor still names a writer.
		offset := device.superblock.Geometry.AllocatorSlotAOffset
		if err := vnextWriteAtFull(file, make([]byte, vnextFormatHeaderSize), offset); err != nil {
			t.Fatalf("tear latest reservation: %v", err)
		}
		if err := file.Sync(); err != nil {
			t.Fatalf("sync tear: %v", err)
		}
		if _, err := openVNextFileDevice(file); !errors.Is(err, errVNextCorrupt) {
			t.Fatalf("unsafe stale-descriptor fallback returned %v", err)
		}
	})
}

func TestVNextPersistentDeviceRecoversReclaimAfterDescriptorClear(t *testing.T) {
	file, device := newTestVNextPersistentDevice(t, 4<<20, 64<<10)
	request := testVNextRequest("pending-reclaim", 2)
	grant, err := device.reserve(request)
	if err != nil {
		t.Fatalf("reserve: %v", err)
	}
	writeAllVNextGrantPages(t, device, grant)
	if err := device.commit(grant); err != nil {
		t.Fatalf("commit: %v", err)
	}
	record, _ := device.allocator.lookup(request.CheckpointID)
	reclaim := vnextReclaimRequest{
		Authority: vnextOwnerAuthority{
			DeviceUUID: "test-device",
			OwnerID:    "owner-0",
			OwnerEpoch: 7,
		},
		CheckpointID:           record.CheckpointID,
		AllocationRecordID:     record.AllocationRecordID,
		ExpectedCommitSequence: record.OwnerTransaction,
	}
	if err := device.allocator.beginReclaim(reclaim); err != nil {
		t.Fatalf("begin reclaim: %v", err)
	}
	if err := device.persistAllocatorLocked(); err != nil {
		t.Fatalf("persist reclaim decision: %v", err)
	}
	if err := device.clearRecordDescriptorsLocked(record, false, false); err != nil {
		t.Fatalf("clear descriptors: %v", err)
	}
	// Simulate a crash before finishReclaim/persisting the free bitmap.
	reopened, err := openVNextFileDevice(file)
	if err != nil {
		t.Fatalf("recover pending reclaim: %v", err)
	}
	recovered, ok := reopened.allocator.lookup(request.CheckpointID)
	if !ok || recovered.State != vnextAllocationReclaimed {
		t.Fatalf("pending reclaim recovered as %#v", recovered)
	}
	if reopened.allocator.freePages() != reopened.superblock.Geometry.DataPageCount {
		t.Fatal("pending reclaim recovery did not return bitmap capacity")
	}
}

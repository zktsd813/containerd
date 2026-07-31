package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"hash/crc32"
	"sort"
	"strings"
	"testing"

	"github.com/containerd/containerd/third_party/trenv-containerd/pkg/cxlcheckpoint"
)

func newVNextOwnerServiceForFixture(
	t *testing.T,
	fixture *vnextOwnerTestFixture,
) *vnextOwnerService {
	t.Helper()
	bindings := make([]vnextLocalDAXBinding, len(fixture.devices))
	for index, device := range fixture.devices {
		binding, err := vnextLocalDAXBindingFromDevice(device, fixture.deviceFiles[index].Name())
		if err != nil {
			t.Fatalf("build Owner-service DAX binding %d: %v", index, err)
		}
		bindings[index] = binding
	}
	directory, err := newVNextLocalDAXDirectory(bindings)
	if err != nil {
		t.Fatalf("build Owner-service DAX directory: %v", err)
	}
	service, err := newVNextOwnerService(fixture.group, directory)
	if err != nil {
		t.Fatalf("build VNext Owner service: %v", err)
	}
	return service
}

func vnextOwnerServiceIdentity(grant vnextOwnerWriteGrant) vnextOwnerOperationIdentity {
	return vnextOwnerOperationIdentity{
		RequestID:          grant.RequestID,
		CheckpointID:       grant.CheckpointID,
		ProducerID:         grant.ProducerID,
		OwnerID:            grant.OwnerID,
		OwnerEpoch:         grant.OwnerEpoch,
		AllocationRecordID: grant.AllocationRecordID,
	}
}

func requireVNextOwnerServiceCode(
	t *testing.T,
	err error,
	want vnextOwnerServiceErrorCode,
) *vnextOwnerServiceError {
	t.Helper()
	if err == nil {
		t.Fatalf("operation succeeded, expected service code %q", want)
	}
	var serviceError *vnextOwnerServiceError
	if !errors.As(err, &serviceError) {
		t.Fatalf("error %T %v is not a VNext Owner service error", err, err)
	}
	if serviceError.Code != want {
		t.Fatalf("service error code is %q, expected %q: %v", serviceError.Code, want, err)
	}
	return serviceError
}

func TestVNextOwnerServiceInventoryEchoesIdentityWithoutAdvancingJournal(t *testing.T) {
	fixture := newVNextOwnerTestFixture(t, []vnextOwnerTestDeviceSpec{
		{UUID: "service-inventory-z", Size: 256 << 10},
		{UUID: "service-inventory-a", Size: 384 << 10},
	})
	service := newVNextOwnerServiceForFixture(t, fixture)
	request := vnextOwnerInventoryRequest{
		RequestID:  "service-inventory-request",
		OwnerID:    "owner-0",
		OwnerEpoch: 7,
	}
	first, err := service.inventory(request)
	if err != nil {
		t.Fatalf("read service inventory: %v", err)
	}
	if first.RequestID != request.RequestID || first.OwnerID != request.OwnerID ||
		first.OwnerEpoch != request.OwnerEpoch || first.SnapshotSequence == 0 ||
		len(first.Devices) != 2 || first.Devices[0].DeviceUUID != "service-inventory-a" ||
		first.Devices[1].DeviceUUID != "service-inventory-z" {
		t.Fatalf("service inventory does not echo a stable Owner identity: %#v", first)
	}
	second, err := service.inventory(request)
	if err != nil {
		t.Fatalf("retry service inventory: %v", err)
	}
	if !bytes.Equal(mustMarshalJSON(t, first), mustMarshalJSON(t, second)) {
		t.Fatalf("read-only service inventory advanced or changed state: %#v != %#v",
			first, second)
	}
}

func TestVNextOwnerServiceInventoryRejectsStaleOrPoisonedOwner(t *testing.T) {
	fixture := newVNextOwnerTestFixture(t, []vnextOwnerTestDeviceSpec{{
		UUID: "service-inventory-authority", Size: 256 << 10,
	}})
	service := newVNextOwnerServiceForFixture(t, fixture)
	base := vnextOwnerInventoryRequest{
		RequestID:  "service-inventory-authority-request",
		OwnerID:    "owner-0",
		OwnerEpoch: 7,
	}

	wrongOwner := base
	wrongOwner.OwnerID = "owner-stale"
	response, err := service.inventory(wrongOwner)
	requireVNextOwnerServiceCode(t, err, vnextOwnerServiceIdentityMismatch)
	if response.RequestID != "" || response.OwnerID != "" ||
		response.OwnerEpoch != 0 || response.SnapshotSequence != 0 ||
		len(response.Devices) != 0 {
		t.Fatalf("wrong Owner identity returned inventory: %#v", response)
	}
	wrongEpoch := base
	wrongEpoch.OwnerEpoch++
	response, err = service.inventory(wrongEpoch)
	requireVNextOwnerServiceCode(t, err, vnextOwnerServiceIdentityMismatch)
	if response.RequestID != "" || response.OwnerID != "" ||
		response.OwnerEpoch != 0 || response.SnapshotSequence != 0 ||
		len(response.Devices) != 0 {
		t.Fatalf("stale Owner epoch returned inventory: %#v", response)
	}

	fixture.group.mu.Lock()
	fixture.group.poisoned = errors.New("test poisoned Owner")
	fixture.group.mu.Unlock()
	response, err = service.inventory(base)
	requireVNextOwnerServiceCode(t, err, vnextOwnerServiceUnavailable)
	if response.RequestID != "" || response.OwnerID != "" ||
		response.OwnerEpoch != 0 || response.SnapshotSequence != 0 ||
		len(response.Devices) != 0 {
		t.Fatalf("poisoned Owner returned inventory: %#v", response)
	}
}

func TestVNextOwnerServiceMultiDAXReserveResponseIsPortable(t *testing.T) {
	fixture := newVNextOwnerTestFixture(t, []vnextOwnerTestDeviceSpec{
		{UUID: "owner-service-device-b", Size: 256 << 10},
		{UUID: "owner-service-device-a", Size: 256 << 10},
	})
	service := newVNextOwnerServiceForFixture(t, fixture)
	firstCapacity := fixture.devices[0].superblock.Geometry.DataPageCount
	pages := firstCapacity + 3
	request := vnextOwnerReserveRequest{
		RequestID:    "owner-service-reserve-request",
		CheckpointID: "owner-service-reserve-checkpoint",
		ProducerID:   "owner-service-reserve-producer",
		OwnerID:      "owner-0",
		OwnerEpoch:   7,
		Contents: []vnextOwnerReserveContent{
			{
				Kind:          vnextOwnerServiceContentMemory,
				ObjectID:      11,
				ByteLength:    pages * vnextContentPageSize,
				CapacityPages: pages,
			},
			{
				Kind:          vnextOwnerServiceContentPublication,
				ObjectID:      12,
				ByteLength:    vnextContentPageSize,
				CapacityPages: 1,
			},
		},
		MaxExtents: 2,
	}
	response, err := service.reserve(request)
	if err != nil {
		t.Fatalf("reserve checkpoint through Owner service: %v", err)
	}
	if response.Operation != (vnextOwnerOperationIdentity{
		RequestID:          request.RequestID,
		CheckpointID:       request.CheckpointID,
		ProducerID:         request.ProducerID,
		OwnerID:            request.OwnerID,
		OwnerEpoch:         request.OwnerEpoch,
		AllocationRecordID: 1,
	}) {
		t.Fatalf("unexpected portable operation identity: %#v", response.Operation)
	}
	if response.TotalPages != pages+1 || len(response.Contents) != 2 {
		t.Fatalf("unexpected content segmentation: total=%d contents=%#v",
			response.TotalPages, response.Contents)
	}
	segment := response.Contents[0]
	if segment.Kind != vnextOwnerServiceContentMemory || segment.ObjectID != 11 ||
		segment.ByteLength != pages*vnextContentPageSize ||
		segment.LogicalPageStart != 0 || segment.PageCount != pages {
		t.Fatalf("portable content segment differs from request: %#v", segment)
	}
	if len(response.Extents) != 2 || len(response.Devices) != 2 {
		t.Fatalf("multi-DAX placement returned extents/devices %d/%d: %#v %#v",
			len(response.Extents), len(response.Devices), response.Extents, response.Devices)
	}
	var logical uint64
	used := make(map[string]struct{})
	for _, extent := range response.Extents {
		if extent.LogicalPageStart != logical || extent.PageCount == 0 {
			t.Fatalf("extent order is not canonical at %#v after page %d", extent, logical)
		}
		logical += extent.PageCount
		used[extent.DeviceUUID] = struct{}{}
	}
	if logical != pages+1 || len(used) != 2 {
		t.Fatalf("multi-DAX extents cover %d pages on %d devices", logical, len(used))
	}
	if !sort.SliceIsSorted(response.Devices, func(i, j int) bool {
		return response.Devices[i].DeviceUUID < response.Devices[j].DeviceUUID
	}) {
		t.Fatalf("portable device table is not UUID ordered: %#v", response.Devices)
	}
	for _, portable := range response.Devices {
		device := fixture.group.devices[portable.DeviceUUID]
		if device == nil ||
			portable.DataPageCount != device.superblock.Geometry.DataPageCount ||
			portable.ContentRegionBase != device.superblock.Geometry.ContentRegionBase {
			t.Fatalf("portable geometry does not match %q: %#v", portable.DeviceUUID, portable)
		}
	}

	// Marshaling is used only as a negative portability inspection here; the
	// service intentionally defines no JSON wire decoder in this slice.
	encoded, err := json.Marshal(response)
	if err != nil {
		t.Fatalf("inspect portable reserve response: %v", err)
	}
	for _, deviceFile := range fixture.deviceFiles {
		if bytes.Contains(encoded, []byte(deviceFile.Name())) {
			t.Fatalf("portable reserve response leaked local path %q: %s", deviceFile.Name(), encoded)
		}
	}
	for _, forbidden := range [][]byte{
		[]byte("WriteToken"), []byte("DevicePath"), []byte("fragmentGrants"),
	} {
		if bytes.Contains(encoded, forbidden) {
			t.Fatalf("portable reserve response leaked internal field %q: %s", forbidden, encoded)
		}
	}

	// A retry is resolved by the durable request identity and must reproduce
	// the same placement without allocating another checkpoint.
	retried, err := service.reserve(request)
	if err != nil {
		t.Fatalf("retry portable reserve: %v", err)
	}
	if !bytes.Equal(mustMarshalJSON(t, response), mustMarshalJSON(t, retried)) {
		t.Fatalf("reserve retry changed response:\nfirst=%#v\nretry=%#v", response, retried)
	}
}

func mustMarshalJSON(t *testing.T, value interface{}) []byte {
	t.Helper()
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("marshal test value: %v", err)
	}
	return encoded
}

func vnextOwnerStatusTestRequest(id string, pages uint64) vnextOwnerReserveRequest {
	return vnextOwnerReserveRequest{
		RequestID:    "status-request-" + id,
		CheckpointID: "status-checkpoint-" + id,
		ProducerID:   "status-producer-" + id,
		OwnerID:      "owner-0",
		OwnerEpoch:   7,
		Contents: []vnextOwnerReserveContent{
			{
				Kind:          vnextOwnerServiceContentMemory,
				ObjectID:      uint64(id[0]) + 100,
				ByteLength:    pages * vnextContentPageSize,
				CapacityPages: pages,
			},
			{
				Kind:          vnextOwnerServiceContentPublication,
				ObjectID:      uint64(id[0]) + 200,
				ByteLength:    vnextContentPageSize,
				CapacityPages: 1,
			},
		},
		MaxExtents: 2,
	}
}

func vnextOwnerStatusRequestFromTransaction(
	t *testing.T,
	transaction *vnextOwnerTransaction,
	ownerID string,
	ownerEpoch uint64,
) vnextOwnerReserveRequest {
	t.Helper()
	request := vnextOwnerReserveRequest{
		RequestID:    transaction.RequestID,
		CheckpointID: transaction.CheckpointID,
		ProducerID:   transaction.ProducerID,
		OwnerID:      ownerID,
		OwnerEpoch:   ownerEpoch,
		Contents:     make([]vnextOwnerReserveContent, len(transaction.Contents)),
		MaxExtents:   transaction.MaxExtents,
	}
	for index, content := range transaction.Contents {
		kind, ok := vnextOwnerServiceKindFromInternal(content.Kind)
		if !ok {
			t.Fatalf("convert status content kind %d", content.Kind)
		}
		request.Contents[index] = vnextOwnerReserveContent{
			Kind:          kind,
			ObjectID:      content.ObjectID,
			ByteLength:    content.ByteLength,
			CapacityPages: content.PageCount,
		}
	}
	return request
}

func vnextOwnerStatusTestFreePages(group *vnextOwnerGroup) uint64 {
	group.mu.Lock()
	defer group.mu.Unlock()
	var free uint64
	for _, deviceUUID := range group.deviceOrder {
		free += group.devices[deviceUUID].allocator.freePages()
	}
	return free
}

func vnextOwnerStatusTestPersistentImage(
	t *testing.T,
	group *vnextOwnerGroup,
) []byte {
	t.Helper()
	group.mu.Lock()
	defer group.mu.Unlock()
	journal, err := group.journal.marshalAtSequence(
		group.journal.SnapshotSequence, group.devices)
	if err != nil {
		t.Fatalf("marshal status-test Owner journal: %v", err)
	}
	image := append([]byte(nil), journal...)
	for _, deviceUUID := range group.deviceOrder {
		allocator := group.devices[deviceUUID].allocator
		allocator.mu.Lock()
		snapshot, err := allocator.marshalSnapshotLocked(
			nil,
			allocator.bitmap,
			allocator.nextAllocationRecordID,
			allocator.nextOwnerTransaction,
			allocator.snapshotSequence)
		allocator.mu.Unlock()
		if err != nil {
			t.Fatalf("marshal status-test allocator %q: %v", deviceUUID, err)
		}
		image = append(image, snapshot...)
	}
	return image
}

func TestVNextOwnerReservationStatusNotFoundIsReadOnly(t *testing.T) {
	fixture := newVNextOwnerTestFixture(t, []vnextOwnerTestDeviceSpec{{
		UUID: "status-not-found", Size: 256 << 10,
	}})
	service := newVNextOwnerServiceForFixture(t, fixture)
	request := vnextOwnerStatusTestRequest("missing", 1)
	beforeSequence := fixture.group.journal.SnapshotSequence
	beforeHighWater := fixture.group.journal.NextAllocationRecordID
	beforeFree := vnextOwnerStatusTestFreePages(fixture.group)
	beforeImage := vnextOwnerStatusTestPersistentImage(t, fixture.group)
	for attempt := 0; attempt < 3; attempt++ {
		response, err := service.reservationStatus(request)
		if err != nil {
			t.Fatalf("read missing reservation status: %v", err)
		}
		if response.State != vnextOwnerReservationNotFound ||
			response.Identity.RequestID != request.RequestID ||
			response.Identity.CheckpointID != request.CheckpointID ||
			response.Identity.ProducerID != request.ProducerID ||
			response.Identity.OwnerID != request.OwnerID ||
			response.Identity.OwnerEpoch != request.OwnerEpoch ||
			response.Identity.AllocationRecordID != 0 || response.Grant != nil {
			t.Fatalf("unexpected NOT_FOUND status: %#v", response)
		}
	}
	if fixture.group.journal.SnapshotSequence != beforeSequence ||
		fixture.group.journal.NextAllocationRecordID != beforeHighWater ||
		len(fixture.group.journal.Transactions) != 0 ||
		vnextOwnerStatusTestFreePages(fixture.group) != beforeFree {
		t.Fatal("NOT_FOUND status mutated Owner state")
	}
	if afterImage := vnextOwnerStatusTestPersistentImage(t, fixture.group); !bytes.Equal(afterImage, beforeImage) {
		t.Fatal("NOT_FOUND status changed journal, bitmap, records, or sequence")
	}
}

func TestVNextOwnerReservationStatusReplaysExactLostGrantWithoutMutation(t *testing.T) {
	fixture := newVNextOwnerTestFixture(t, []vnextOwnerTestDeviceSpec{
		{UUID: "status-grant-b", Size: 256 << 10},
		{UUID: "status-grant-a", Size: 256 << 10},
	})
	service := newVNextOwnerServiceForFixture(t, fixture)
	firstCapacity := fixture.devices[0].superblock.Geometry.DataPageCount
	request := vnextOwnerStatusTestRequest("lost-grant", firstCapacity+1)
	reserved, err := service.reserve(request)
	if err != nil {
		t.Fatalf("reserve before lost response: %v", err)
	}
	beforeSequence := fixture.group.journal.SnapshotSequence
	beforeHighWater := fixture.group.journal.NextAllocationRecordID
	beforeFree := vnextOwnerStatusTestFreePages(fixture.group)
	beforeImage := vnextOwnerStatusTestPersistentImage(t, fixture.group)
	status, err := service.reservationStatus(request)
	if err != nil {
		t.Fatalf("recover lost Reserve response: %v", err)
	}
	if status.State != vnextOwnerReservationGranted || status.Grant == nil ||
		!bytes.Equal(mustMarshalJSON(t, *status.Grant), mustMarshalJSON(t, reserved)) {
		t.Fatalf("status did not replay exact grant: %#v / %#v", status, reserved)
	}
	if fixture.group.journal.SnapshotSequence != beforeSequence ||
		fixture.group.journal.NextAllocationRecordID != beforeHighWater ||
		vnextOwnerStatusTestFreePages(fixture.group) != beforeFree {
		t.Fatal("GRANTED status mutated Owner state")
	}
	if afterImage := vnextOwnerStatusTestPersistentImage(t, fixture.group); !bytes.Equal(afterImage, beforeImage) {
		t.Fatal("GRANTED status changed journal, bitmap, records, or sequence")
	}

	mismatch := request
	mismatch.Contents = append([]vnextOwnerReserveContent(nil), request.Contents...)
	mismatch.Contents[0].ObjectID++
	_, err = service.reservationStatus(mismatch)
	requireVNextOwnerServiceCode(t, err, vnextOwnerServiceConflict)
}

func TestVNextOwnerReservationStatusReportsDurableNoSpaceExactlyAndReadOnly(t *testing.T) {
	fixture := newVNextOwnerTestFixture(t, []vnextOwnerTestDeviceSpec{{
		UUID: "status-no-space", Size: 256 << 10,
	}})
	service := newVNextOwnerServiceForFixture(t, fixture)
	capacity := fixture.devices[0].superblock.Geometry.DataPageCount
	request := vnextOwnerStatusTestRequest("no-space", capacity)
	_, err := service.reserve(request)
	requireVNextOwnerServiceCode(t, err, vnextOwnerServiceNoSpace)
	allocationID := fixture.group.journal.RequestIndex[request.RequestID]
	if allocationID == 0 {
		t.Fatal("service no-space result has no durable allocation ID")
	}
	beforeSequence := fixture.group.journal.SnapshotSequence
	beforeHighWater := fixture.group.journal.NextAllocationRecordID
	_, err = service.reserve(request)
	requireVNextOwnerServiceCode(t, err, vnextOwnerServiceNoSpace)
	if fixture.group.journal.SnapshotSequence != beforeSequence ||
		fixture.group.journal.NextAllocationRecordID != beforeHighWater ||
		fixture.group.journal.RequestIndex[request.RequestID] != allocationID {
		t.Fatal("service duplicate no-space replay mutated or replaced its tombstone")
	}
	beforeFree := vnextOwnerStatusTestFreePages(fixture.group)
	beforeImage := vnextOwnerStatusTestPersistentImage(t, fixture.group)
	for attempt := 0; attempt < 3; attempt++ {
		status, err := service.reservationStatus(request)
		if err != nil {
			t.Fatalf("read REJECTED_NO_SPACE status: %v", err)
		}
		if status.State != vnextOwnerReservationRejectedNoSpace || status.Grant != nil ||
			status.Identity.RequestID != request.RequestID ||
			status.Identity.CheckpointID != request.CheckpointID ||
			status.Identity.ProducerID != request.ProducerID ||
			status.Identity.OwnerID != request.OwnerID ||
			status.Identity.OwnerEpoch != request.OwnerEpoch ||
			status.Identity.AllocationRecordID != allocationID {
			t.Fatalf("unexpected REJECTED_NO_SPACE status: %#v", status)
		}
	}
	if fixture.group.journal.SnapshotSequence != beforeSequence ||
		fixture.group.journal.NextAllocationRecordID != beforeHighWater ||
		vnextOwnerStatusTestFreePages(fixture.group) != beforeFree {
		t.Fatal("REJECTED_NO_SPACE status mutated Owner state")
	}
	if afterImage := vnextOwnerStatusTestPersistentImage(t, fixture.group); !bytes.Equal(afterImage, beforeImage) {
		t.Fatal("REJECTED_NO_SPACE status changed journal, bitmap, records, or sequence")
	}

	mismatch := request
	mismatch.Contents = append([]vnextOwnerReserveContent(nil), request.Contents...)
	mismatch.Contents[0].ObjectID++
	_, err = service.reservationStatus(mismatch)
	requireVNextOwnerServiceCode(t, err, vnextOwnerServiceConflict)

	fixture.reopen(t)
	restarted := newVNextOwnerServiceForFixture(t, fixture)
	status, err := restarted.reservationStatus(request)
	if err != nil || status.State != vnextOwnerReservationRejectedNoSpace ||
		status.Grant != nil || status.Identity.AllocationRecordID != allocationID {
		t.Fatalf("REJECTED_NO_SPACE status after restart: %#v / %v", status, err)
	}
}

func TestVNextOwnerServiceNoSpaceMetadataFailureIsUnavailable(t *testing.T) {
	fixture := newVNextOwnerTestFixture(t, []vnextOwnerTestDeviceSpec{{
		UUID: "service-no-space-persist-failure", Size: 256 << 10,
	}})
	service := newVNextOwnerServiceForFixture(t, fixture)
	capacity := fixture.devices[0].superblock.Geometry.DataPageCount
	fixture.group.controlSlotBytes = 1
	_, err := service.reserve(vnextOwnerStatusTestRequest("metadata-failure", capacity))
	requireVNextOwnerServiceCode(t, err, vnextOwnerServiceUnavailable)
	if errors.Is(err, errVNextNoSpace) || !errors.Is(err, errVNextMetadataFull) {
		t.Fatalf("metadata persistence failure was misclassified: %v", err)
	}
}

func TestVNextOwnerReservationStatusConcurrentRepeatedReadsRemainPure(t *testing.T) {
	fixture := newVNextOwnerTestFixture(t, []vnextOwnerTestDeviceSpec{
		{UUID: "status-race-b", Size: 256 << 10},
		{UUID: "status-race-a", Size: 256 << 10},
	})
	service := newVNextOwnerServiceForFixture(t, fixture)
	firstCapacity := fixture.devices[0].superblock.Geometry.DataPageCount
	request := vnextOwnerStatusTestRequest("race", firstCapacity+1)
	reserved, err := service.reserve(request)
	if err != nil {
		t.Fatalf("reserve before concurrent status: %v", err)
	}
	wantGrant, err := json.Marshal(reserved)
	if err != nil {
		t.Fatal(err)
	}
	beforeImage := vnextOwnerStatusTestPersistentImage(t, fixture.group)

	const workers = 8
	const readsPerWorker = 25
	results := make(chan error, workers)
	for worker := 0; worker < workers; worker++ {
		go func() {
			for read := 0; read < readsPerWorker; read++ {
				status, err := service.reservationStatus(request)
				if err != nil {
					results <- err
					return
				}
				if status.State != vnextOwnerReservationGranted || status.Grant == nil {
					results <- errors.New("concurrent status did not return GRANTED with a grant")
					return
				}
				gotGrant, err := json.Marshal(status.Grant)
				if err != nil {
					results <- err
					return
				}
				if !bytes.Equal(gotGrant, wantGrant) {
					results <- errors.New("concurrent status changed immutable grant geometry")
					return
				}
			}
			results <- nil
		}()
	}
	for worker := 0; worker < workers; worker++ {
		if err := <-results; err != nil {
			t.Fatal(err)
		}
	}
	if afterImage := vnextOwnerStatusTestPersistentImage(t, fixture.group); !bytes.Equal(afterImage, beforeImage) {
		t.Fatal("concurrent status changed journal, bitmap, records, or sequence")
	}
}

func TestVNextOwnerReservationStatusPreparingRecoversToDurableFreedAborted(t *testing.T) {
	fixture := newVNextOwnerTestFixture(t, []vnextOwnerTestDeviceSpec{
		{UUID: "status-prepare-a", Size: 256 << 10},
		{UUID: "status-prepare-b", Size: 256 << 10},
	})
	service := newVNextOwnerServiceForFixture(t, fixture)
	firstCapacity := fixture.devices[0].superblock.Geometry.DataPageCount
	request := vnextOwnerStatusTestRequest("prepare-crash", firstCapacity+1)
	internal, err := request.internal()
	if err != nil {
		t.Fatal(err)
	}
	initialFree := vnextOwnerStatusTestFreePages(fixture.group)
	calls := 0
	fixture.group.faultHook = func(stage, _ string) error {
		if stage == vnextOwnerFailAfterPrepare {
			calls++
			if calls == 1 {
				return errVNextOwnerCrashInjected
			}
		}
		return nil
	}
	if _, err := fixture.group.reserve(internal); !errors.Is(err, errVNextOwnerCrashInjected) {
		t.Fatalf("inject partial prepare crash: %v", err)
	}
	preparingSequence := fixture.group.journal.SnapshotSequence
	preparingImage := vnextOwnerStatusTestPersistentImage(t, fixture.group)
	preparing, err := service.reservationStatus(request)
	if err != nil {
		t.Fatalf("read PREPARING status: %v", err)
	}
	if preparing.State != vnextOwnerReservationPreparing || preparing.Grant != nil ||
		preparing.Identity.AllocationRecordID == 0 {
		t.Fatalf("unexpected ambiguous PREPARING status: %#v", preparing)
	}
	if fixture.group.journal.SnapshotSequence != preparingSequence {
		t.Fatal("PREPARING status advanced Owner journal")
	}
	if afterImage := vnextOwnerStatusTestPersistentImage(t, fixture.group); !bytes.Equal(afterImage, preparingImage) {
		t.Fatal("PREPARING status changed journal, bitmap, records, or sequence")
	}

	fixture.reopen(t)
	restarted := newVNextOwnerServiceForFixture(t, fixture)
	abortedImage := vnextOwnerStatusTestPersistentImage(t, fixture.group)
	aborted, err := restarted.reservationStatus(request)
	if err != nil {
		t.Fatalf("read recovered ABORTED status: %v", err)
	}
	if aborted.State != vnextOwnerReservationAborted || aborted.Grant != nil ||
		aborted.Identity.AllocationRecordID != preparing.Identity.AllocationRecordID {
		t.Fatalf("unexpected recovered ABORTED status: %#v", aborted)
	}
	if got := vnextOwnerStatusTestFreePages(fixture.group); got != initialFree {
		t.Fatalf("ABORTED free pages = %d, want %d", got, initialFree)
	}
	if afterImage := vnextOwnerStatusTestPersistentImage(t, fixture.group); !bytes.Equal(afterImage, abortedImage) {
		t.Fatal("ABORTED status changed journal, bitmap, records, or sequence")
	}
	for _, device := range fixture.devices {
		record, exists := device.allocator.lookup(request.CheckpointID)
		if exists && record.State != vnextAllocationAborted {
			t.Fatalf("ABORTED device record still owns pages: %#v", record)
		}
	}
	fixture.reopen(t)
	restartedAgain := newVNextOwnerServiceForFixture(t, fixture)
	again, err := restartedAgain.reservationStatus(request)
	if err != nil || again.State != vnextOwnerReservationAborted || again.Grant != nil {
		t.Fatalf("ABORTED status did not survive another restart: %#v / %v", again, err)
	}
}

func TestVNextOwnerReservationStatusDistinguishesSealedAndCommitted(t *testing.T) {
	fixture := newVNextExternalSealTestFixture(t, vnextCRCCopyEngineCPU)
	service := newVNextOwnerServiceForFixture(t, fixture.owner)
	transaction := fixture.owner.group.journal.Transactions[fixture.grant.AllocationRecordID]
	request := vnextOwnerStatusRequestFromTransaction(
		t, transaction, fixture.grant.OwnerID, fixture.grant.OwnerEpoch)

	granted, err := service.reservationStatus(request)
	if err != nil || granted.State != vnextOwnerReservationGranted || granted.Grant == nil {
		t.Fatalf("initial GRANTED status: %#v / %v", granted, err)
	}
	if err := fixture.owner.group.sealExternalCRIUOutput(
		fixture.grant, fixture.publication, fixture.directory, fixture.cloneSidecars()); err != nil {
		t.Fatalf("seal status memory content: %v", err)
	}
	fixture.sealControlPages(t)
	sealedImage := vnextOwnerStatusTestPersistentImage(t, fixture.owner.group)
	sealed, err := service.reservationStatus(request)
	if err != nil || sealed.State != vnextOwnerReservationSealed || sealed.Grant == nil {
		t.Fatalf("SEALED status: %#v / %v", sealed, err)
	}
	if !bytes.Equal(mustMarshalJSON(t, sealed.Grant), mustMarshalJSON(t, granted.Grant)) {
		t.Fatal("SEALED status changed immutable grant geometry")
	}
	if afterImage := vnextOwnerStatusTestPersistentImage(t, fixture.owner.group); !bytes.Equal(afterImage, sealedImage) {
		t.Fatal("SEALED status changed journal, bitmap, records, or sequence")
	}
	if err := fixture.owner.group.commit(fixture.grant); err != nil {
		t.Fatalf("commit status checkpoint: %v", err)
	}
	committedImage := vnextOwnerStatusTestPersistentImage(t, fixture.owner.group)
	committed, err := service.reservationStatus(request)
	if err != nil || committed.State != vnextOwnerReservationCommitted || committed.Grant == nil {
		t.Fatalf("COMMITTED status: %#v / %v", committed, err)
	}
	if !bytes.Equal(mustMarshalJSON(t, committed.Grant), mustMarshalJSON(t, granted.Grant)) {
		t.Fatal("COMMITTED status changed immutable grant geometry")
	}
	if afterImage := vnextOwnerStatusTestPersistentImage(t, fixture.owner.group); !bytes.Equal(afterImage, committedImage) {
		t.Fatal("COMMITTED status changed journal, bitmap, records, or sequence")
	}
}

func TestVNextOwnerServiceRestartResolvesSameIdentityForAbort(t *testing.T) {
	fixture := newVNextOwnerTestFixture(t, []vnextOwnerTestDeviceSpec{
		{UUID: "owner-service-abort-device", Size: 256 << 10},
	})
	service := newVNextOwnerServiceForFixture(t, fixture)
	response, err := service.reserve(vnextOwnerReserveRequest{
		RequestID:    "owner-service-abort-request",
		CheckpointID: "owner-service-abort-checkpoint",
		ProducerID:   "owner-service-abort-producer",
		OwnerID:      "owner-0",
		OwnerEpoch:   7,
		Contents: []vnextOwnerReserveContent{
			{
				Kind:          vnextOwnerServiceContentMemory,
				ObjectID:      12,
				ByteLength:    2 * vnextContentPageSize,
				CapacityPages: 2,
			},
			{
				Kind:          vnextOwnerServiceContentPublication,
				ObjectID:      13,
				ByteLength:    vnextContentPageSize,
				CapacityPages: 1,
			},
		},
		MaxExtents: 1,
	})
	if err != nil {
		t.Fatalf("reserve restart-abort checkpoint: %v", err)
	}

	fixture.reopen(t)
	restarted := newVNextOwnerServiceForFixture(t, fixture)
	if err := restarted.abort(response.Operation); err != nil {
		t.Fatalf("abort by the same operation identity after restart: %v", err)
	}
	if err := restarted.abort(response.Operation); err != nil {
		t.Fatalf("idempotent abort after restart: %v", err)
	}
	transaction := fixture.group.journal.Transactions[response.Operation.AllocationRecordID]
	if transaction == nil || transaction.State != vnextOwnerAborted {
		t.Fatalf("restart-aborted transaction is %#v", transaction)
	}
	for _, fragment := range transaction.Fragments {
		device := fixture.group.devices[fragment.DeviceUUID]
		for _, extent := range fragment.Extents {
			for page := uint64(0); page < extent.PageCount; page++ {
				device.mu.Lock()
				descriptor, readErr := device.readDescriptorLocked(extent.StartDataPageIndex + page)
				device.mu.Unlock()
				if readErr != nil || descriptor.State != vnextDescriptorFree {
					t.Fatalf("aborted descriptor %s/%d is %#v, err=%v",
						fragment.DeviceUUID, extent.StartDataPageIndex+page, descriptor, readErr)
				}
			}
		}
	}
}

func TestVNextOwnerServiceReserveRequiresOneBoundedPublicationSlot(t *testing.T) {
	base := vnextOwnerReserveRequest{
		RequestID:    "owner-service-publication-request",
		CheckpointID: "owner-service-publication-checkpoint",
		ProducerID:   "owner-service-publication-producer",
		OwnerID:      "owner-0",
		OwnerEpoch:   7,
		Contents: []vnextOwnerReserveContent{{
			Kind:          vnextOwnerServiceContentMemory,
			ObjectID:      1,
			ByteLength:    vnextContentPageSize,
			CapacityPages: 1,
		}},
		MaxExtents: 2,
	}
	t.Run("missing", func(t *testing.T) {
		if _, err := base.internal(); err == nil {
			t.Fatal("reserve without a publication slot was accepted")
		}
	})
	t.Run("duplicate", func(t *testing.T) {
		request := base
		request.Contents = append(append([]vnextOwnerReserveContent(nil), base.Contents...),
			vnextOwnerReserveContent{
				Kind:          vnextOwnerServiceContentPublication,
				ObjectID:      2,
				ByteLength:    vnextContentPageSize,
				CapacityPages: 1,
			},
			vnextOwnerReserveContent{
				Kind:          vnextOwnerServiceContentPublication,
				ObjectID:      3,
				ByteLength:    vnextContentPageSize,
				CapacityPages: 1,
			})
		if _, err := request.internal(); err == nil {
			t.Fatal("reserve with duplicate publication slots was accepted")
		}
	})
	t.Run("over maximum", func(t *testing.T) {
		request := base
		pages := cxlcheckpoint.MaxPublicationSlotPages + 1
		request.Contents = append(append([]vnextOwnerReserveContent(nil), base.Contents...),
			vnextOwnerReserveContent{
				Kind:          vnextOwnerServiceContentPublication,
				ObjectID:      2,
				ByteLength:    pages * vnextContentPageSize,
				CapacityPages: pages,
			})
		if _, err := request.internal(); err == nil {
			t.Fatal("oversized publication slot was accepted")
		}
	})
}

func TestVNextOwnerServiceMultiPagePublicationCrossesDevicesAndRetriesAfterRestart(t *testing.T) {
	fixture := newVNextOwnerTestFixture(t, []vnextOwnerTestDeviceSpec{
		// With the test control-slot size these devices contain exactly one
		// and five content pages. The two-page publication slot is first in
		// logical order, so it necessarily crosses the device boundary.
		{UUID: "publication-device-a", Size: 48 << 10},
		{UUID: "publication-device-b", Size: 64 << 10},
	})
	if fixture.devices[0].superblock.Geometry.DataPageCount != 1 ||
		fixture.devices[1].superblock.Geometry.DataPageCount != 5 {
		t.Fatalf("unexpected test capacities: %d/%d",
			fixture.devices[0].superblock.Geometry.DataPageCount,
			fixture.devices[1].superblock.Geometry.DataPageCount)
	}
	service := newVNextOwnerServiceForFixture(t, fixture)

	// CheckpointID appears in both the publication and its committed root.
	// A long but valid identity makes the canonical envelope require two
	// pages without adding unrelated payload content.
	checkpointID := "multi-page-publication-" + strings.Repeat("x", 3000)
	mmTemplate := cxlcheckpoint.MMTemplate{
		TemplateID:             "multi-page-mm-template",
		ContentObjectID:        3,
		RuntimeCompatibilityID: "trenv-v6-multi-page-publication-test",
		PageSize:               cxlcheckpoint.PageSize,
		VMAs: []cxlcheckpoint.VMA{{
			PagesImageID:    7,
			StartVAddr:      0x1000,
			EndVAddr:        0x2000,
			ProtectionFlags: cxlcheckpoint.ProtectionRead | cxlcheckpoint.ProtectionWrite,
			MappingFlags:    cxlcheckpoint.MappingPrivate | cxlcheckpoint.MappingAnonymous,
			BackingKind:     cxlcheckpoint.BackingAnonymous,
			PageMapRunStart: 0,
			PageMapRunCount: 1,
		}},
	}
	pageMap := cxlcheckpoint.PageMap{
		PageMapID:       "multi-page-page-map",
		Version:         1,
		ContentObjectID: 4,
		PageSize:        cxlcheckpoint.PageSize,
		Runs: []cxlcheckpoint.PageMapRun{{
			PagesImageID: 7,
			StartVAddr:   0x1000,
			PageCount:    1,
			FirstPage: cxlcheckpoint.PageID{
				OwnerID:            "owner-0",
				DeviceUUID:         "publication-device-a",
				AllocationRecordID: 1,
				DataPageIndex:      0,
			},
		}},
	}
	mmSize, err := cxlcheckpoint.CanonicalMMTemplateSize(mmTemplate)
	if err != nil {
		t.Fatalf("measure MMTemplate: %v", err)
	}
	pageMapSize, err := cxlcheckpoint.CanonicalPageMapSize(pageMap)
	if err != nil {
		t.Fatalf("measure PageMap: %v", err)
	}
	reserved, err := service.reserve(vnextOwnerReserveRequest{
		RequestID:    "multi-page-publication-request",
		CheckpointID: checkpointID,
		ProducerID:   "multi-page-publication-producer",
		OwnerID:      "owner-0",
		OwnerEpoch:   7,
		Contents: []vnextOwnerReserveContent{
			{
				Kind:          vnextOwnerServiceContentPublication,
				ObjectID:      1,
				ByteLength:    2 * vnextContentPageSize,
				CapacityPages: 2,
			},
			{
				Kind:          vnextOwnerServiceContentMemory,
				ObjectID:      2,
				ByteLength:    vnextContentPageSize,
				CapacityPages: 1,
			},
			{
				Kind:          vnextOwnerServiceContentMMTemplate,
				ObjectID:      3,
				ByteLength:    mmSize,
				CapacityPages: 1,
			},
			{
				Kind:          vnextOwnerServiceContentPageMap,
				ObjectID:      4,
				ByteLength:    pageMapSize,
				CapacityPages: 1,
			},
			{
				Kind:          vnextOwnerServiceContentPageMap,
				ObjectID:      5,
				ByteLength:    pageMapSize,
				CapacityPages: 1,
			},
		},
		MaxExtents: 2,
	})
	if err != nil {
		t.Fatalf("reserve cross-device publication: %v", err)
	}
	if len(reserved.Extents) != 2 ||
		reserved.Extents[0].LogicalPageStart != 0 ||
		reserved.Extents[0].PageCount != 1 ||
		reserved.Extents[1].LogicalPageStart != 1 {
		t.Fatalf("publication slot does not cross the expected boundary: %#v", reserved.Extents)
	}
	memoryPage := cxlcheckpoint.PageID{}
	for _, extent := range reserved.Extents {
		end := extent.LogicalPageStart + extent.PageCount
		if 2 < extent.LogicalPageStart || 2 >= end {
			continue
		}
		memoryPage = cxlcheckpoint.PageID{
			OwnerID:            reserved.Operation.OwnerID,
			DeviceUUID:         extent.DeviceUUID,
			AllocationRecordID: reserved.Operation.AllocationRecordID,
			DataPageIndex:      extent.StartDataPageIndex + (2 - extent.LogicalPageStart),
		}
	}
	if memoryPage.DeviceUUID == "" {
		t.Fatal("memory page is outside the portable reserve response")
	}
	pageMap.Runs[0].FirstPage = memoryPage
	finalPageMapSize, err := cxlcheckpoint.CanonicalPageMapSize(pageMap)
	if err != nil {
		t.Fatalf("measure located PageMap: %v", err)
	}
	if finalPageMapSize != pageMapSize {
		t.Fatalf("located PageMap size changed from %d to %d", pageMapSize, finalPageMapSize)
	}

	extents := make([]cxlcheckpoint.AllocationExtent, len(reserved.Extents))
	for index, extent := range reserved.Extents {
		extents[index] = cxlcheckpoint.AllocationExtent{
			DeviceUUID:         extent.DeviceUUID,
			StartDataPageIndex: extent.StartDataPageIndex,
			PageCount:          extent.PageCount,
			LogicalPageStart:   extent.LogicalPageStart,
		}
	}
	devices := make([]cxlcheckpoint.Device, len(fixture.devices))
	for index, device := range fixture.devices {
		devices[index] = cxlcheckpoint.Device{
			DeviceUUID:    device.superblock.DeviceUUID,
			OwnerID:       device.superblock.OwnerID,
			OwnerEpoch:    device.superblock.OwnerEpoch,
			DataPageCount: device.superblock.Geometry.DataPageCount,
		}
	}
	publication := cxlcheckpoint.Publication{
		CheckpointID: checkpointID,
		Devices:      devices,
		ContentObjects: []cxlcheckpoint.ContentObject{
			{
				ObjectID:         1,
				Kind:             cxlcheckpoint.ContentPublication,
				ByteLength:       2 * cxlcheckpoint.PageSize,
				LogicalPageStart: 0,
				PageCount:        2,
			},
			{
				ObjectID:         2,
				Kind:             cxlcheckpoint.ContentMemory,
				ByteLength:       cxlcheckpoint.PageSize,
				LogicalPageStart: 2,
				PageCount:        1,
			},
			{
				ObjectID:         3,
				Kind:             cxlcheckpoint.ContentMMTemplate,
				ByteLength:       mmSize,
				LogicalPageStart: 3,
				PageCount:        1,
			},
			{
				ObjectID:         4,
				Kind:             cxlcheckpoint.ContentPageMap,
				ByteLength:       pageMapSize,
				LogicalPageStart: 4,
				PageCount:        1,
			},
			{
				ObjectID:         5,
				Kind:             cxlcheckpoint.ContentPageMap,
				ByteLength:       pageMapSize,
				LogicalPageStart: 5,
				PageCount:        1,
			},
		},
		Allocation: cxlcheckpoint.InitialAllocation{
			OwnerID:            reserved.Operation.OwnerID,
			OwnerEpoch:         reserved.Operation.OwnerEpoch,
			AllocationRecordID: reserved.Operation.AllocationRecordID,
			TotalPages:         reserved.TotalPages,
			Extents:            extents,
		},
		MMTemplate: mmTemplate,
		PageMap:    pageMap,
		Artifacts: cxlcheckpoint.ArtifactManifest{
			ManifestID: "multi-page-artifacts",
		},
		MappingSlots: cxlcheckpoint.MappingSlots{
			A: cxlcheckpoint.MappingSlot{
				Name:            cxlcheckpoint.MappingSlotA,
				ContentObjectID: 4,
				CapacityPages:   1,
			},
			B: cxlcheckpoint.MappingSlot{
				Name:            cxlcheckpoint.MappingSlotB,
				ContentObjectID: 5,
				CapacityPages:   1,
			},
		},
		Root: cxlcheckpoint.CommittedRoot{
			State:               cxlcheckpoint.RootCommitted,
			RootID:              "multi-page-publication-root",
			CheckpointID:        checkpointID,
			OwnerID:             reserved.Operation.OwnerID,
			AllocationRecordID:  reserved.Operation.AllocationRecordID,
			MMTemplateID:        mmTemplate.TemplateID,
			PageMapID:           pageMap.PageMapID,
			PageMapVersion:      pageMap.Version,
			ArtifactManifestID:  "multi-page-artifacts",
			ActiveMappingSlot:   cxlcheckpoint.MappingSlotA,
			PublicationSequence: 1,
		},
	}
	digest, err := cxlcheckpoint.DeviceTableDigest(publication.Devices)
	if err != nil {
		t.Fatalf("digest device table: %v", err)
	}
	publication.Root.DeviceTableDigest = digest
	storage, err := cxlcheckpoint.EncodeForStorage(publication)
	if err != nil {
		t.Fatalf("encode multi-page publication: %v", err)
	}
	if len(storage.ExactBytes) <= int(cxlcheckpoint.PageSize) ||
		len(storage.ExactBytes) > 2*int(cxlcheckpoint.PageSize) ||
		len(storage.PageRuns) != 2 ||
		storage.PageRuns[0].FirstPage.DeviceUUID == storage.PageRuns[1].FirstPage.DeviceUUID {
		t.Fatalf("publication did not produce two cross-device exact runs: bytes=%d runs=%#v",
			len(storage.ExactBytes), storage.PageRuns)
	}
	memoryPayload := bytes.Repeat([]byte{0x5a}, int(vnextContentPageSize))
	memoryDevice := fixture.group.devices[memoryPage.DeviceUUID]
	memoryOffset, err := memoryDevice.superblock.Geometry.contentOffset(memoryPage.DataPageIndex)
	if err != nil {
		t.Fatalf("resolve memory payload offset: %v", err)
	}
	if err := vnextWriteAtFull(memoryDevice.file, memoryPayload, memoryOffset); err != nil {
		t.Fatalf("write memory payload: %v", err)
	}
	if err := memoryDevice.file.Sync(); err != nil {
		t.Fatalf("sync memory payload: %v", err)
	}
	sidecars := vnextTestCRCPageSidecars(t, publication, service.directory)
	binary.LittleEndian.PutUint32(sidecars[7][28:32], uint32(vnextCRCCopyEngineCPU))
	binary.LittleEndian.PutUint32(
		sidecars[7][vnextCRCPageSidecarHeaderSize+28:vnextCRCPageSidecarHeaderSize+32],
		crc32.Checksum(memoryPayload, vnextCRCTable))
	grant, _, err := service.resolveOperation(
		"test-seal", reserved.Operation, vnextOwnerGranted, true)
	if err != nil {
		t.Fatalf("resolve multi-page external grant: %v", err)
	}
	mmBytes, err := cxlcheckpoint.CanonicalMMTemplateBytes(mmTemplate)
	if err != nil {
		t.Fatalf("encode multi-page MMTemplate: %v", err)
	}
	pageMapBytes, err := cxlcheckpoint.CanonicalPageMapBytes(pageMap)
	if err != nil {
		t.Fatalf("encode multi-page PageMap: %v", err)
	}
	externalRecords := []vnextExternalContentPageCRC{
		{
			LogicalPage: 3,
			ContentCRC32C: vnextWriteExternalGrantLogicalPage(
				t, fixture.group, grant, 3, mmBytes),
			CopyEngine: vnextCRCCopyEngineCPU,
		},
		{
			LogicalPage: 4,
			ContentCRC32C: vnextWriteExternalGrantLogicalPage(
				t, fixture.group, grant, 4, pageMapBytes),
			CopyEngine: vnextCRCCopyEngineCPU,
		},
		{
			LogicalPage: 5,
			ContentCRC32C: vnextWriteExternalGrantLogicalPage(
				t,
				fixture.group,
				grant,
				5,
				bytes.Repeat([]byte{0x63}, int(pageMapSize))),
			CopyEngine: vnextCRCCopyEngineCPU,
		},
	}

	sealed, err := service.sealExternal(vnextOwnerExternalSealRequest{
		Operation:               reserved.Operation,
		PublicationEnvelope:     storage.ExactBytes,
		CRCPageSidecars:         sidecars,
		ExternalContentPageCRCs: externalRecords,
	})
	if err != nil {
		t.Fatalf("seal multi-page publication: %v", err)
	}
	if sealed.Root.Locator.PublicationByteLength != uint64(len(storage.ExactBytes)) ||
		sealed.Root.Locator.PublicationSHA256 != storage.SHA256 ||
		len(sealed.Root.Locator.PageRuns) != len(storage.PageRuns) {
		t.Fatalf("seal returned a different root locator: %#v", sealed)
	}
	for index, run := range sealed.Root.Locator.PageRuns {
		if run.FirstPage != storage.PageRuns[index].FirstPage ||
			run.PageCount != storage.PageRuns[index].PageCount {
			t.Fatalf("seal run %d = %#v, want %#v", index, run, storage.PageRuns[index])
		}
		device := fixture.group.devices[run.FirstPage.DeviceUUID]
		device.mu.Lock()
		page, readErr := device.readContentPageLocked(run.FirstPage.DataPageIndex)
		device.mu.Unlock()
		if readErr != nil {
			t.Fatalf("read stored publication run %d: %v", index, readErr)
		}
		start := index * int(cxlcheckpoint.PageSize)
		end := start + int(cxlcheckpoint.PageSize)
		if !bytes.Equal(page, storage.PaddedBytes[start:end]) {
			t.Fatalf("stored publication page %d differs from canonical padding", index)
		}
	}

	fixture.reopen(t)
	restarted := newVNextOwnerServiceForFixture(t, fixture)
	retried, err := restarted.sealExternal(vnextOwnerExternalSealRequest{
		Operation:               reserved.Operation,
		PublicationEnvelope:     storage.ExactBytes,
		CRCPageSidecars:         sidecars,
		ExternalContentPageCRCs: externalRecords,
	})
	if err != nil {
		t.Fatalf("retry multi-page publication seal after restart: %v", err)
	}
	if !bytes.Equal(mustMarshalJSON(t, sealed), mustMarshalJSON(t, retried)) {
		t.Fatalf("restart retry changed publication locator:\nfirst=%#v\nretry=%#v",
			sealed, retried)
	}
}

func TestVNextOwnerServiceRestartResolvesSameIdentityForCommit(t *testing.T) {
	fixture := newVNextExternalSealTestFixture(t, vnextCRCCopyEngineCPU)
	service, err := newVNextOwnerService(fixture.owner.group, fixture.directory)
	if err != nil {
		t.Fatalf("build external Owner service: %v", err)
	}
	externalRecords := vnextPrepareCompleteExternalContent(t, fixture)
	envelope, err := cxlcheckpoint.Encode(fixture.publication)
	if err != nil {
		t.Fatalf("encode strict external publication: %v", err)
	}
	identity := vnextOwnerServiceIdentity(fixture.grant)
	sealed, err := service.sealExternal(vnextOwnerExternalSealRequest{
		Operation:               identity,
		PublicationEnvelope:     envelope,
		CRCPageSidecars:         fixture.cloneSidecars(),
		ExternalContentPageCRCs: externalRecords,
	})
	if err != nil {
		t.Fatalf("seal external pages through Owner service: %v", err)
	}
	if sealed.Root.Locator.PublicationByteLength != uint64(len(envelope)) ||
		sealed.Root.Locator.PublicationSHA256 != sha256.Sum256(envelope) ||
		len(sealed.Root.Locator.PageRuns) != 1 ||
		sealed.Root.Locator.PageRuns[0].PageCount != 1 {
		t.Fatalf("unexpected portable publication root locator: %#v", sealed)
	}
	publicationStorage, err := cxlcheckpoint.EncodeForStorage(fixture.publication)
	if err != nil {
		t.Fatalf("prepare expected publication storage: %v", err)
	}
	if sealed.Root.Locator.PageRuns[0].FirstPage != publicationStorage.PageRuns[0].FirstPage {
		t.Fatalf("seal response PageID = %#v, want %#v",
			sealed.Root.Locator.PageRuns[0].FirstPage, publicationStorage.PageRuns[0].FirstPage)
	}
	publicationDevice := fixture.owner.group.devices[sealed.Root.Locator.PageRuns[0].FirstPage.DeviceUUID]
	publicationDevice.mu.Lock()
	storedPublicationPage, readErr := publicationDevice.readContentPageLocked(
		sealed.Root.Locator.PageRuns[0].FirstPage.DataPageIndex)
	publicationDescriptor, descriptorErr := publicationDevice.readDescriptorLocked(
		sealed.Root.Locator.PageRuns[0].FirstPage.DataPageIndex)
	publicationDevice.mu.Unlock()
	if readErr != nil || descriptorErr != nil {
		t.Fatalf("read Owner-written publication page/descriptor: %v / %v",
			readErr, descriptorErr)
	}
	if publicationDescriptor.State != vnextDescriptorSealed ||
		!bytes.Equal(storedPublicationPage, publicationStorage.PaddedBytes[:vnextContentPageSize]) {
		t.Fatalf("Owner did not atomically store the zero-padded publication slot")
	}
	fixture.owner.reopen(t)
	restarted := newVNextOwnerServiceForFixture(t, fixture.owner)
	if err := restarted.commit(identity); err != nil {
		t.Fatalf("commit by the same operation identity after restart: %v", err)
	}
	if err := restarted.commit(identity); err != nil {
		t.Fatalf("idempotent commit after restart: %v", err)
	}
	transaction := fixture.owner.group.journal.Transactions[identity.AllocationRecordID]
	if transaction == nil || transaction.State != vnextOwnerCommitted {
		t.Fatalf("restart-committed transaction is %#v", transaction)
	}
}

func TestVNextOwnerServiceSealAndCommitFailClosedCodes(t *testing.T) {
	t.Run("legacy-publication", func(t *testing.T) {
		fixture := newVNextExternalSealTestFixture(t, vnextCRCCopyEngineCPU)
		service, err := newVNextOwnerService(fixture.owner.group, fixture.directory)
		if err != nil {
			t.Fatalf("build Owner service: %v", err)
		}
		_, err = service.sealExternal(vnextOwnerExternalSealRequest{
			Operation:           vnextOwnerServiceIdentity(fixture.grant),
			PublicationEnvelope: []byte("TRPUB005"),
			CRCPageSidecars:     fixture.cloneSidecars(),
		})
		requireVNextOwnerServiceCode(t, err, vnextOwnerServicePublicationIncompatible)
		fixture.assertAllocationDescriptorState(t, vnextDescriptorReserved)
	})

	t.Run("missing-sidecar", func(t *testing.T) {
		fixture := newVNextExternalSealTestFixture(t, vnextCRCCopyEngineCPU)
		service, err := newVNextOwnerService(fixture.owner.group, fixture.directory)
		if err != nil {
			t.Fatalf("build Owner service: %v", err)
		}
		envelope, err := cxlcheckpoint.Encode(fixture.publication)
		if err != nil {
			t.Fatalf("encode publication: %v", err)
		}
		sidecars := fixture.cloneSidecars()
		delete(sidecars, 8)
		_, err = service.sealExternal(vnextOwnerExternalSealRequest{
			Operation:           vnextOwnerServiceIdentity(fixture.grant),
			PublicationEnvelope: envelope,
			CRCPageSidecars:     sidecars,
		})
		requireVNextOwnerServiceCode(t, err, vnextOwnerServiceSidecarMissing)
		fixture.assertAllocationDescriptorState(t, vnextDescriptorReserved)
	})

	t.Run("payload-crc-mismatch", func(t *testing.T) {
		fixture := newVNextExternalSealTestFixture(t, vnextCRCCopyEngineCPU)
		service, err := newVNextOwnerService(fixture.owner.group, fixture.directory)
		if err != nil {
			t.Fatalf("build Owner service: %v", err)
		}
		envelope, err := cxlcheckpoint.Encode(fixture.publication)
		if err != nil {
			t.Fatalf("encode publication: %v", err)
		}
		sidecars := fixture.cloneSidecars()
		externalRecords := vnextPrepareCompleteExternalContent(t, fixture)
		offset := vnextCRCPageSidecarHeaderSize + vnextCRCPageSidecarRecordSize
		crc := binary.LittleEndian.Uint32(sidecars[8][offset+28 : offset+32])
		binary.LittleEndian.PutUint32(sidecars[8][offset+28:offset+32], crc^1)
		_, err = service.sealExternal(vnextOwnerExternalSealRequest{
			Operation:               vnextOwnerServiceIdentity(fixture.grant),
			PublicationEnvelope:     envelope,
			CRCPageSidecars:         sidecars,
			ExternalContentPageCRCs: externalRecords,
		})
		requireVNextOwnerServiceCode(t, err, vnextOwnerServicePayloadMismatch)
		fixture.assertAllocationDescriptorState(t, vnextDescriptorReserved)
	})

	t.Run("identity-mismatch", func(t *testing.T) {
		fixture := newVNextExternalSealTestFixture(t, vnextCRCCopyEngineCPU)
		service, err := newVNextOwnerService(fixture.owner.group, fixture.directory)
		if err != nil {
			t.Fatalf("build Owner service: %v", err)
		}
		identity := vnextOwnerServiceIdentity(fixture.grant)
		identity.ProducerID = "different-producer"
		_, err = service.sealExternal(vnextOwnerExternalSealRequest{Operation: identity})
		requireVNextOwnerServiceCode(t, err, vnextOwnerServiceIdentityMismatch)
		fixture.assertAllocationDescriptorState(t, vnextDescriptorReserved)
	})

	t.Run("complete-evidence-seals-control-descriptors", func(t *testing.T) {
		fixture := newVNextExternalSealTestFixture(t, vnextCRCCopyEngineCPU)
		service, err := newVNextOwnerService(fixture.owner.group, fixture.directory)
		if err != nil {
			t.Fatalf("build Owner service: %v", err)
		}
		envelope, err := cxlcheckpoint.Encode(fixture.publication)
		if err != nil {
			t.Fatalf("encode publication: %v", err)
		}
		identity := vnextOwnerServiceIdentity(fixture.grant)
		externalRecords := vnextPrepareCompleteExternalContent(t, fixture)
		if _, err := service.sealExternal(vnextOwnerExternalSealRequest{
			Operation:               identity,
			PublicationEnvelope:     envelope,
			CRCPageSidecars:         fixture.cloneSidecars(),
			ExternalContentPageCRCs: externalRecords,
		}); err != nil {
			t.Fatalf("seal strict Owner service request: %v", err)
		}
		if err := service.commit(identity); err != nil {
			t.Fatalf("commit after unified seal covered all control descriptors: %v", err)
		}
	})
}

func TestVNextOwnerServiceUsesExactTRCRC006Bytes(t *testing.T) {
	fixture := newVNextExternalSealTestFixture(t, vnextCRCCopyEngineCPU)
	service, err := newVNextOwnerService(fixture.owner.group, fixture.directory)
	if err != nil {
		t.Fatalf("build Owner service: %v", err)
	}
	envelope, err := cxlcheckpoint.Encode(fixture.publication)
	if err != nil {
		t.Fatalf("encode publication: %v", err)
	}
	sidecars := fixture.cloneSidecars()

	// Append one byte. The sidecar parser must reject it instead of accepting
	// a prefix or silently choosing an older contiguous format.
	sidecars[7] = append(sidecars[7], 0)
	_, err = service.sealExternal(vnextOwnerExternalSealRequest{
		Operation:           vnextOwnerServiceIdentity(fixture.grant),
		PublicationEnvelope: envelope,
		CRCPageSidecars:     sidecars,
	})
	requireVNextOwnerServiceCode(t, err, vnextOwnerServiceSidecarInvalid)
	fixture.assertAllocationDescriptorState(t, vnextDescriptorReserved)

	// Restore an exact sidecar and prove the payload CRCs used by the test are
	// the same CRC-32C values that the external-seal bridge consumes.
	sidecars = fixture.cloneSidecars()
	for index, page := range fixture.pages {
		run := fixture.publication.PageMap.Runs[index]
		imageRecord := 0
		for previous := 0; previous < index; previous++ {
			if fixture.publication.PageMap.Runs[previous].PagesImageID == run.PagesImageID {
				imageRecord++
			}
		}
		offset := vnextCRCPageSidecarHeaderSize + imageRecord*vnextCRCPageSidecarRecordSize
		got := binary.LittleEndian.Uint32(sidecars[run.PagesImageID][offset+28 : offset+32])
		want := crc32.Checksum(page.payload, vnextCRCTable)
		if got != want {
			t.Fatalf("sidecar CRC for logical page %d is %#x, expected %#x", page.logicalPage, got, want)
		}
	}
}

func vnextWriteExternalLogicalPage(
	t *testing.T,
	fixture *vnextExternalSealTestFixture,
	logicalPage uint64,
	exactPayload []byte,
) uint32 {
	t.Helper()
	return vnextWriteExternalGrantLogicalPage(
		t, fixture.owner.group, fixture.grant, logicalPage, exactPayload)
}

func vnextWriteExternalGrantLogicalPage(
	t *testing.T,
	group *vnextOwnerGroup,
	grant vnextOwnerWriteGrant,
	logicalPage uint64,
	exactPayload []byte,
) uint32 {
	t.Helper()
	if len(exactPayload) > int(vnextContentPageSize) {
		t.Fatalf("external logical page %d payload is %d bytes", logicalPage, len(exactPayload))
	}
	page := make([]byte, int(vnextContentPageSize))
	copy(page, exactPayload)
	pageID := vnextExternalSealTestPageID(t, grant, logicalPage)
	device := group.devices[pageID.DeviceUUID]
	if device == nil {
		t.Fatalf("external logical page %d references unknown device %q",
			logicalPage, pageID.DeviceUUID)
	}
	contentOffset, err := device.superblock.Geometry.contentOffset(pageID.DataPageIndex)
	if err != nil {
		t.Fatalf("resolve external logical page %d: %v", logicalPage, err)
	}
	if err := vnextWriteAtFull(device.file, page, contentOffset); err != nil {
		t.Fatalf("write external logical page %d: %v", logicalPage, err)
	}
	if err := device.file.Sync(); err != nil {
		t.Fatalf("sync external logical page %d: %v", logicalPage, err)
	}
	return crc32.Checksum(page, vnextCRCTable)
}

func vnextPrepareCompleteExternalContent(
	t *testing.T,
	fixture *vnextExternalSealTestFixture,
) []vnextExternalContentPageCRC {
	t.Helper()
	mmBytes, err := cxlcheckpoint.CanonicalMMTemplateBytes(fixture.publication.MMTemplate)
	if err != nil {
		t.Fatalf("encode fixture MMTemplate: %v", err)
	}
	pageMapBytes, err := cxlcheckpoint.CanonicalPageMapBytes(fixture.publication.PageMap)
	if err != nil {
		t.Fatalf("encode fixture active PageMap: %v", err)
	}
	// A non-empty inactive slot has no semantic representation in the current
	// publication. Arbitrary older bytes are therefore valid when their exact
	// grant length, zero tail, and CRC are all correct.
	inactiveBytes := bytes.Repeat([]byte{0x6d}, fixture.controlSize[2])
	payloads := map[uint64][]byte{
		4: mmBytes,
		5: pageMapBytes,
		6: inactiveBytes,
	}
	records := make([]vnextExternalContentPageCRC, 0, len(payloads))
	for logicalPage := uint64(4); logicalPage <= 6; logicalPage++ {
		payload := payloads[logicalPage]
		content := fixture.grant.Contents[logicalPage-4+1]
		if content.LogicalPageStart != logicalPage ||
			content.ByteLength != uint64(len(payload)) {
			t.Fatalf("fixture content at logical page %d is %#v for %d bytes",
				logicalPage, content, len(payload))
		}
		records = append(records, vnextExternalContentPageCRC{
			LogicalPage:   logicalPage,
			ContentCRC32C: vnextWriteExternalLogicalPage(t, fixture, logicalPage, payload),
			CopyEngine:    vnextCRCCopyEngineCPU,
		})
	}
	return records
}

func vnextCloneExternalContentCRCs(
	records []vnextExternalContentPageCRC,
) []vnextExternalContentPageCRC {
	return append([]vnextExternalContentPageCRC(nil), records...)
}

func vnextSetExternalContentRecordCRC(
	t *testing.T,
	records []vnextExternalContentPageCRC,
	logicalPage uint64,
	crc uint32,
) {
	t.Helper()
	for index := range records {
		if records[index].LogicalPage == logicalPage {
			records[index].ContentCRC32C = crc
			return
		}
	}
	t.Fatalf("external CRC record for logical page %d is missing", logicalPage)
}

func TestVNextOwnerServiceCompleteExternalSealAndCommit(t *testing.T) {
	fixture := newVNextExternalSealTestFixture(t, vnextCRCCopyEngineCPU)
	// Keep PageMapVersion at 1 but make the committed-root sequence distinct,
	// so this test catches accidentally sourcing RootVersion from PageMap.
	fixture.publication.Root.PublicationSequence = 11
	service, err := newVNextOwnerService(fixture.owner.group, fixture.directory)
	if err != nil {
		t.Fatalf("build complete external Owner service: %v", err)
	}
	records := vnextPrepareCompleteExternalContent(t, fixture)
	envelope, err := cxlcheckpoint.Encode(fixture.publication)
	if err != nil {
		t.Fatalf("encode complete external publication: %v", err)
	}
	identity := vnextOwnerServiceIdentity(fixture.grant)
	sealed, err := service.sealExternal(vnextOwnerExternalSealRequest{
		Operation:               identity,
		PublicationEnvelope:     envelope,
		CRCPageSidecars:         fixture.cloneSidecars(),
		ExternalContentPageCRCs: records,
	})
	if err != nil {
		t.Fatalf("seal complete external checkpoint: %v", err)
	}
	if sealed.Root.Locator.PublicationByteLength != uint64(len(envelope)) ||
		sealed.Root.Locator.PublicationSHA256 != sha256.Sum256(envelope) ||
		len(sealed.Root.Locator.PageRuns) != 1 {
		t.Fatalf("unexpected complete external seal response: %#v", sealed)
	}
	publicationRoot := fixture.publication.Root
	if sealed.Root.RootID != publicationRoot.RootID ||
		sealed.Root.RootVersion != publicationRoot.PublicationSequence ||
		sealed.Root.MMTemplateID != publicationRoot.MMTemplateID ||
		sealed.Root.PageMapID != publicationRoot.PageMapID ||
		sealed.Root.PageMapVersion != publicationRoot.PageMapVersion ||
		sealed.Root.DeviceTableDigest != publicationRoot.DeviceTableDigest ||
		sealed.Root.ContractID != cxlcheckpoint.V6CompatibilityID {
		t.Fatalf("seal returned a root that differs from TRPUB006: %#v", sealed.Root)
	}
	fixture.assertAllocationDescriptorState(t, vnextDescriptorSealed)
	transaction := fixture.owner.group.journal.Transactions[identity.AllocationRecordID]
	if transaction == nil || transaction.State != vnextOwnerGranted {
		t.Fatalf("seal changed lifecycle state before commit: %#v", transaction)
	}
	if err := service.commit(identity); err != nil {
		t.Fatalf("commit complete external checkpoint: %v", err)
	}
}

func TestVNextOwnerServiceCompleteExternalSealFailsBeforeAnyDescriptorWrite(t *testing.T) {
	tests := []struct {
		name   string
		code   vnextOwnerServiceErrorCode
		mutate func(*testing.T, *vnextExternalSealTestFixture, []vnextExternalContentPageCRC) []vnextExternalContentPageCRC
	}{
		{
			name: "wrong-crc",
			code: vnextOwnerServicePayloadMismatch,
			mutate: func(_ *testing.T, _ *vnextExternalSealTestFixture, records []vnextExternalContentPageCRC) []vnextExternalContentPageCRC {
				records[0].ContentCRC32C ^= 1
				return records
			},
		},
		{
			name: "missing-record",
			code: vnextOwnerServiceSidecarInvalid,
			mutate: func(_ *testing.T, _ *vnextExternalSealTestFixture, records []vnextExternalContentPageCRC) []vnextExternalContentPageCRC {
				return records[:len(records)-1]
			},
		},
		{
			name: "duplicate-record",
			code: vnextOwnerServiceSidecarInvalid,
			mutate: func(_ *testing.T, _ *vnextExternalSealTestFixture, records []vnextExternalContentPageCRC) []vnextExternalContentPageCRC {
				return append(records, records[0])
			},
		},
		{
			name: "extra-record",
			code: vnextOwnerServiceSidecarInvalid,
			mutate: func(_ *testing.T, _ *vnextExternalSealTestFixture, records []vnextExternalContentPageCRC) []vnextExternalContentPageCRC {
				return append(records, vnextExternalContentPageCRC{
					LogicalPage:   99,
					ContentCRC32C: 1,
					CopyEngine:    vnextCRCCopyEngineCPU,
				})
			},
		},
		{
			name: "memory-record",
			code: vnextOwnerServiceSidecarInvalid,
			mutate: func(_ *testing.T, _ *vnextExternalSealTestFixture, records []vnextExternalContentPageCRC) []vnextExternalContentPageCRC {
				return append(records, vnextExternalContentPageCRC{
					LogicalPage:   0,
					ContentCRC32C: 1,
					CopyEngine:    vnextCRCCopyEngineCPU,
				})
			},
		},
		{
			name: "publication-record",
			code: vnextOwnerServiceSidecarInvalid,
			mutate: func(_ *testing.T, _ *vnextExternalSealTestFixture, records []vnextExternalContentPageCRC) []vnextExternalContentPageCRC {
				return append(records, vnextExternalContentPageCRC{
					LogicalPage:   7,
					ContentCRC32C: 1,
					CopyEngine:    vnextCRCCopyEngineCPU,
				})
			},
		},
		{
			name: "mm-template-canonical-mismatch",
			code: vnextOwnerServicePayloadMismatch,
			mutate: func(t *testing.T, fixture *vnextExternalSealTestFixture, records []vnextExternalContentPageCRC) []vnextExternalContentPageCRC {
				payload, err := cxlcheckpoint.CanonicalMMTemplateBytes(fixture.publication.MMTemplate)
				if err != nil {
					t.Fatalf("encode MMTemplate for corruption: %v", err)
				}
				payload[0] ^= 1
				crc := vnextWriteExternalLogicalPage(t, fixture, 4, payload)
				vnextSetExternalContentRecordCRC(t, records, 4, crc)
				return records
			},
		},
		{
			name: "page-map-canonical-mismatch",
			code: vnextOwnerServicePayloadMismatch,
			mutate: func(t *testing.T, fixture *vnextExternalSealTestFixture, records []vnextExternalContentPageCRC) []vnextExternalContentPageCRC {
				payload, err := cxlcheckpoint.CanonicalPageMapBytes(fixture.publication.PageMap)
				if err != nil {
					t.Fatalf("encode PageMap for corruption: %v", err)
				}
				payload[0] ^= 1
				crc := vnextWriteExternalLogicalPage(t, fixture, 5, payload)
				vnextSetExternalContentRecordCRC(t, records, 5, crc)
				return records
			},
		},
		{
			name: "non-zero-tail",
			code: vnextOwnerServicePayloadMismatch,
			mutate: func(t *testing.T, fixture *vnextExternalSealTestFixture, records []vnextExternalContentPageCRC) []vnextExternalContentPageCRC {
				payload, err := cxlcheckpoint.CanonicalMMTemplateBytes(fixture.publication.MMTemplate)
				if err != nil {
					t.Fatalf("encode MMTemplate for tail corruption: %v", err)
				}
				payload = append(payload, 0x7f)
				crc := vnextWriteExternalLogicalPage(t, fixture, 4, payload)
				vnextSetExternalContentRecordCRC(t, records, 4, crc)
				return records
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newVNextExternalSealTestFixture(t, vnextCRCCopyEngineCPU)
			service, err := newVNextOwnerService(fixture.owner.group, fixture.directory)
			if err != nil {
				t.Fatalf("build complete external Owner service: %v", err)
			}
			records := vnextCloneExternalContentCRCs(
				vnextPrepareCompleteExternalContent(t, fixture))
			records = test.mutate(t, fixture, records)
			envelope, err := cxlcheckpoint.Encode(fixture.publication)
			if err != nil {
				t.Fatalf("encode complete external publication: %v", err)
			}
			_, err = service.sealExternal(vnextOwnerExternalSealRequest{
				Operation:               vnextOwnerServiceIdentity(fixture.grant),
				PublicationEnvelope:     envelope,
				CRCPageSidecars:         fixture.cloneSidecars(),
				ExternalContentPageCRCs: records,
			})
			requireVNextOwnerServiceCode(t, err, test.code)
			// This assertion includes every memory descriptor. The unified
			// phase-one validation must therefore never partially seal memory
			// before discovering a later external-content failure.
			fixture.assertAllocationDescriptorState(t, vnextDescriptorReserved)
		})
	}
}

func TestVNextExternalSealRejectsNonZeroZeroLengthCapacityPage(t *testing.T) {
	owner := newVNextOwnerTestFixture(t, []vnextOwnerTestDeviceSpec{{
		UUID: "zero-length-capacity-device",
		Size: 256 << 10,
	}})
	grant, err := owner.group.reserve(vnextCheckpointAllocationRequest{
		RequestID:    "zero-length-capacity-request",
		CheckpointID: "zero-length-capacity-checkpoint",
		ProducerID:   "zero-length-capacity-producer",
		OwnerID:      "owner-0",
		OwnerEpoch:   7,
		Contents: []vnextContentRequest{
			{Kind: vnextContentPageMap, ObjectID: 1, ByteLength: 0, PageCount: 1},
			{
				Kind:       vnextContentPublication,
				ObjectID:   2,
				ByteLength: vnextContentPageSize,
				PageCount:  1,
			},
		},
		MaxExtents: 1,
	})
	if err != nil {
		t.Fatalf("reserve zero-length capacity page: %v", err)
	}
	pageID := vnextExternalSealTestPageID(t, grant, 0)
	device := owner.group.devices[pageID.DeviceUUID]
	contentOffset, err := device.superblock.Geometry.contentOffset(pageID.DataPageIndex)
	if err != nil {
		t.Fatalf("resolve zero-length capacity page: %v", err)
	}
	nonZero := bytes.Repeat([]byte{0x9e}, int(vnextContentPageSize))
	if err := vnextWriteAtFull(device.file, nonZero, contentOffset); err != nil {
		t.Fatalf("write zero-length capacity page: %v", err)
	}
	if err := device.file.Sync(); err != nil {
		t.Fatalf("sync zero-length capacity page: %v", err)
	}
	fragmentGrant := grant.fragmentGrants[pageID.DeviceUUID]
	device.mu.Lock()
	_, err = device.prepareExternallyWrittenPageLocked(
		fragmentGrant,
		0,
		0,
		pageID.DataPageIndex,
		crc32.Checksum(nonZero, vnextCRCTable),
		vnextCRCCopyEngineCPU)
	device.mu.Unlock()
	if !errors.Is(err, errVNextCorrupt) {
		t.Fatalf("prepare non-zero zero-length capacity page error = %v, want corruption", err)
	}
	for _, extent := range grant.Extents {
		attached := owner.group.devices[extent.DeviceUUID]
		attached.mu.Lock()
		for page := uint64(0); page < extent.PageCount; page++ {
			descriptor, readErr := attached.readDescriptorLocked(extent.StartDataPageIndex + page)
			if readErr != nil || descriptor.State != vnextDescriptorReserved {
				attached.mu.Unlock()
				t.Fatalf("descriptor %s/%d = %#v, err=%v; want RESERVED",
					extent.DeviceUUID, extent.StartDataPageIndex+page, descriptor, readErr)
			}
		}
		attached.mu.Unlock()
	}
}

func TestVNextExternalContentCoverageIsDerivedFromGrantKinds(t *testing.T) {
	grant := vnextOwnerWriteGrant{Contents: []vnextContentSegment{
		{Kind: vnextContentMemory, ObjectID: 1, ByteLength: 2 * vnextContentPageSize, LogicalPageStart: 0, PageCount: 2},
		{Kind: vnextContentArtifact, ObjectID: 2, ByteLength: vnextContentPageSize + 7, LogicalPageStart: 2, PageCount: 2},
		{Kind: vnextContentMMTemplate, ObjectID: 3, ByteLength: 100, LogicalPageStart: 4, PageCount: 1},
		{Kind: vnextContentPageMap, ObjectID: 4, ByteLength: 0, LogicalPageStart: 5, PageCount: 1},
		{Kind: vnextContentRestoreBlob, ObjectID: 5, ByteLength: 17, LogicalPageStart: 6, PageCount: 1},
		{Kind: vnextContentPublication, ObjectID: 6, ByteLength: vnextContentPageSize, LogicalPageStart: 7, PageCount: 1},
	}}
	expected, err := vnextExpectedExternalContentPages(grant)
	if err != nil {
		t.Fatalf("derive complete external content coverage: %v", err)
	}
	want := []vnextExpectedExternalContentPage{
		{LogicalPage: 2, ContentObjectID: 2, ContentKind: vnextContentArtifact, PayloadLength: uint32(vnextContentPageSize)},
		{LogicalPage: 3, ContentObjectID: 2, ContentKind: vnextContentArtifact, PayloadLength: 7},
		{LogicalPage: 4, ContentObjectID: 3, ContentKind: vnextContentMMTemplate, PayloadLength: 100},
		{LogicalPage: 5, ContentObjectID: 4, ContentKind: vnextContentPageMap, PayloadLength: uint32(vnextContentPageSize)},
		{LogicalPage: 6, ContentObjectID: 5, ContentKind: vnextContentRestoreBlob, PayloadLength: 17},
	}
	if !bytes.Equal(mustMarshalJSON(t, expected), mustMarshalJSON(t, want)) {
		t.Fatalf("derived external coverage = %#v, want %#v", expected, want)
	}
}

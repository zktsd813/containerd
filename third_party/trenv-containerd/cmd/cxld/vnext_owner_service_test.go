package main

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"hash/crc32"
	"sort"
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
				Kind:       vnextOwnerServiceContentMemory,
				ObjectID:   11,
				ByteLength: pages * vnextContentPageSize,
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
	if response.TotalPages != pages || len(response.Contents) != 1 {
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
	if logical != pages || len(used) != 2 {
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
			{Kind: vnextOwnerServiceContentMemory, ObjectID: 12, ByteLength: 2 * vnextContentPageSize},
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

func TestVNextOwnerServiceRestartResolvesSameIdentityForCommit(t *testing.T) {
	fixture := newVNextExternalSealTestFixture(t, vnextCRCCopyEngineCPU)
	service, err := newVNextOwnerService(fixture.owner.group, fixture.directory)
	if err != nil {
		t.Fatalf("build external Owner service: %v", err)
	}
	envelope, err := cxlcheckpoint.Encode(fixture.publication)
	if err != nil {
		t.Fatalf("encode strict external publication: %v", err)
	}
	identity := vnextOwnerServiceIdentity(fixture.grant)
	if err := service.seal(vnextOwnerSealRequest{
		Operation:           identity,
		PublicationEnvelope: envelope,
		CRCPageSidecars:     fixture.cloneSidecars(),
	}); err != nil {
		t.Fatalf("seal external pages through Owner service: %v", err)
	}
	fixture.sealControlPages(t)

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
		err = service.seal(vnextOwnerSealRequest{
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
		err = service.seal(vnextOwnerSealRequest{
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
		offset := vnextCRCPageSidecarHeaderSize + vnextCRCPageSidecarRecordSize
		crc := binary.LittleEndian.Uint32(sidecars[8][offset+28 : offset+32])
		binary.LittleEndian.PutUint32(sidecars[8][offset+28:offset+32], crc^1)
		err = service.seal(vnextOwnerSealRequest{
			Operation:           vnextOwnerServiceIdentity(fixture.grant),
			PublicationEnvelope: envelope,
			CRCPageSidecars:     sidecars,
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
		err = service.seal(vnextOwnerSealRequest{Operation: identity})
		requireVNextOwnerServiceCode(t, err, vnextOwnerServiceIdentityMismatch)
		fixture.assertAllocationDescriptorState(t, vnextDescriptorReserved)
	})

	t.Run("control-descriptors-required", func(t *testing.T) {
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
		if err := service.seal(vnextOwnerSealRequest{
			Operation:           identity,
			PublicationEnvelope: envelope,
			CRCPageSidecars:     fixture.cloneSidecars(),
		}); err != nil {
			t.Fatalf("seal strict Owner service request: %v", err)
		}
		requireVNextOwnerServiceCode(t, service.commit(identity), vnextOwnerServiceTransactionState)
		fixture.sealControlPages(t)
		if err := service.commit(identity); err != nil {
			t.Fatalf("commit after all control descriptors were sealed: %v", err)
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
	err = service.seal(vnextOwnerSealRequest{
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

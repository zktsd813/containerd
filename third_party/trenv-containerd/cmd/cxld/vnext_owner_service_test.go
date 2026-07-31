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

	sealed, err := service.seal(vnextOwnerSealRequest{
		Operation:           reserved.Operation,
		PublicationEnvelope: storage.ExactBytes,
		CRCPageSidecars:     sidecars,
	})
	if err != nil {
		t.Fatalf("seal multi-page publication: %v", err)
	}
	if sealed.PublicationByteLength != uint64(len(storage.ExactBytes)) ||
		sealed.PublicationSHA256 != storage.SHA256 ||
		len(sealed.PageRuns) != len(storage.PageRuns) {
		t.Fatalf("seal returned a different root locator: %#v", sealed)
	}
	for index, run := range sealed.PageRuns {
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
	retried, err := restarted.seal(vnextOwnerSealRequest{
		Operation:           reserved.Operation,
		PublicationEnvelope: storage.ExactBytes,
		CRCPageSidecars:     sidecars,
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
	envelope, err := cxlcheckpoint.Encode(fixture.publication)
	if err != nil {
		t.Fatalf("encode strict external publication: %v", err)
	}
	identity := vnextOwnerServiceIdentity(fixture.grant)
	sealed, err := service.seal(vnextOwnerSealRequest{
		Operation:           identity,
		PublicationEnvelope: envelope,
		CRCPageSidecars:     fixture.cloneSidecars(),
	})
	if err != nil {
		t.Fatalf("seal external pages through Owner service: %v", err)
	}
	if sealed.PublicationByteLength != uint64(len(envelope)) ||
		sealed.PublicationSHA256 != sha256.Sum256(envelope) ||
		len(sealed.PageRuns) != 1 ||
		sealed.PageRuns[0].PageCount != 1 {
		t.Fatalf("unexpected portable publication root locator: %#v", sealed)
	}
	publicationStorage, err := cxlcheckpoint.EncodeForStorage(fixture.publication)
	if err != nil {
		t.Fatalf("prepare expected publication storage: %v", err)
	}
	if sealed.PageRuns[0].FirstPage != publicationStorage.PageRuns[0].FirstPage {
		t.Fatalf("seal response PageID = %#v, want %#v",
			sealed.PageRuns[0].FirstPage, publicationStorage.PageRuns[0].FirstPage)
	}
	publicationDevice := fixture.owner.group.devices[sealed.PageRuns[0].FirstPage.DeviceUUID]
	publicationDevice.mu.Lock()
	storedPublicationPage, readErr := publicationDevice.readContentPageLocked(
		sealed.PageRuns[0].FirstPage.DataPageIndex)
	publicationDescriptor, descriptorErr := publicationDevice.readDescriptorLocked(
		sealed.PageRuns[0].FirstPage.DataPageIndex)
	publicationDevice.mu.Unlock()
	if readErr != nil || descriptorErr != nil {
		t.Fatalf("read Owner-written publication page/descriptor: %v / %v",
			readErr, descriptorErr)
	}
	if publicationDescriptor.State != vnextDescriptorSealed ||
		!bytes.Equal(storedPublicationPage, publicationStorage.PaddedBytes[:vnextContentPageSize]) {
		t.Fatalf("Owner did not atomically store the zero-padded publication slot")
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
		_, err = service.seal(vnextOwnerSealRequest{
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
		_, err = service.seal(vnextOwnerSealRequest{
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
		_, err = service.seal(vnextOwnerSealRequest{
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
		_, err = service.seal(vnextOwnerSealRequest{Operation: identity})
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
		if _, err := service.seal(vnextOwnerSealRequest{
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
	_, err = service.seal(vnextOwnerSealRequest{
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

package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"hash/crc32"
	"io"
	"strings"
	"testing"

	"github.com/containerd/containerd/third_party/trenv-containerd/pkg/cxlcheckpoint"
)

type vnextProducerCountingOwnerClient struct {
	delegate vnextProducerOwnerClient

	sealCalls  int
	abortCalls int
}

func (client *vnextProducerCountingOwnerClient) SealVNextCheckpoint(
	ctx context.Context,
	request vnextOwnerExternalSealRequest,
) (vnextOwnerSealResponse, error) {
	client.sealCalls++
	return client.delegate.SealVNextCheckpoint(ctx, request)
}

func (client *vnextProducerCountingOwnerClient) ProducerAbortVNextCheckpoint(
	ctx context.Context,
	identity vnextOwnerOperationIdentity,
	capability vnextProducerCapabilityProof,
) error {
	client.abortCalls++
	return client.delegate.ProducerAbortVNextCheckpoint(ctx, identity, capability)
}

type vnextProducerTestEnvironment struct {
	ownerFixture *vnextOwnerTestFixture
	service      *vnextOwnerService
	client       *vnextProducerCountingOwnerClient
	producer     *vnextFileBackedProducer
	reserve      vnextOwnerReserveResponse
	publication  cxlcheckpoint.Publication
	payloads     map[uint64][]byte
	sidecars     map[uint32][]byte
	capability   vnextProducerCapabilityProof
}

func newVNextProducerTestEnvironment(t *testing.T) *vnextProducerTestEnvironment {
	t.Helper()
	ownerFixture := newVNextOwnerTestFixture(t, []vnextOwnerTestDeviceSpec{
		{UUID: "producer-device-a", Size: 256 << 10},
		{UUID: "producer-device-b", Size: 256 << 10},
	})
	service := newVNextOwnerServiceForFixture(t, ownerFixture)
	deviceCapacity := ownerFixture.devices[0].superblock.Geometry.DataPageCount
	memoryPages := deviceCapacity + 2
	memoryBytes := memoryPages * cxlcheckpoint.PageSize

	const (
		memoryObject      = uint64(101)
		artifactObject    = uint64(102)
		mmTemplateObject  = uint64(103)
		activeMapObject   = uint64(104)
		inactiveMapObject = uint64(105)
		restoreObject     = uint64(106)
		publicationObject = uint64(107)
		pagesImageID      = uint32(17)
		memoryStartVAddr  = uint64(0x400000)
	)

	mmTemplate := cxlcheckpoint.MMTemplate{
		TemplateID:             "producer-mm-template",
		ContentObjectID:        mmTemplateObject,
		RuntimeCompatibilityID: "producer-runtime-v6",
		PageSize:               cxlcheckpoint.PageSize,
		VMAs: []cxlcheckpoint.VMA{{
			PagesImageID:    pagesImageID,
			StartVAddr:      memoryStartVAddr,
			EndVAddr:        memoryStartVAddr + memoryBytes,
			ProtectionFlags: cxlcheckpoint.ProtectionRead | cxlcheckpoint.ProtectionWrite,
			MappingFlags:    cxlcheckpoint.MappingPrivate | cxlcheckpoint.MappingAnonymous,
			BackingKind:     cxlcheckpoint.BackingAnonymous,
			PageMapRunStart: 0,
			PageMapRunCount: 2,
		}},
	}
	// Numeric PageID values do not affect the canonical PageMap size. This
	// provisional two-run shape lets reserve include the exact active slot
	// ByteLength before the Owner chooses physical extents.
	pageMap := cxlcheckpoint.PageMap{
		PageMapID:       "producer-page-map",
		Version:         3,
		ContentObjectID: activeMapObject,
		PageSize:        cxlcheckpoint.PageSize,
		Runs: []cxlcheckpoint.PageMapRun{
			{
				PagesImageID: pagesImageID,
				StartVAddr:   memoryStartVAddr,
				PageCount:    deviceCapacity,
				FirstPage: cxlcheckpoint.PageID{
					OwnerID:            "owner-0",
					DeviceUUID:         "producer-device-a",
					AllocationRecordID: 1,
					DataPageIndex:      0,
				},
			},
			{
				PagesImageID: pagesImageID,
				StartVAddr:   memoryStartVAddr + deviceCapacity*cxlcheckpoint.PageSize,
				PageCount:    2,
				FirstPage: cxlcheckpoint.PageID{
					OwnerID:            "owner-0",
					DeviceUUID:         "producer-device-b",
					AllocationRecordID: 1,
					DataPageIndex:      0,
				},
			},
		},
	}
	mmSize, err := cxlcheckpoint.CanonicalMMTemplateSize(mmTemplate)
	if err != nil {
		t.Fatalf("measure producer MMTemplate: %v", err)
	}
	pageMapSize, err := cxlcheckpoint.CanonicalPageMapSize(pageMap)
	if err != nil {
		t.Fatalf("measure producer PageMap: %v", err)
	}

	payloads := map[uint64][]byte{
		memoryObject:      vnextProducerTestPattern(int(memoryBytes), 0x11),
		artifactObject:    vnextProducerTestPattern(5000, 0x41),
		inactiveMapObject: []byte("previous-inactive-page-map-version"),
		restoreObject:     vnextProducerTestPattern(311, 0x71),
	}
	reserved, err := service.reserve(vnextOwnerReserveRequest{
		RequestID:    "producer-reserve-request",
		CheckpointID: "producer-checkpoint",
		ProducerID:   "producer-node-7",
		OwnerID:      "owner-0",
		OwnerEpoch:   7,
		Contents: []vnextOwnerReserveContent{
			{
				Kind:          vnextOwnerServiceContentMemory,
				ObjectID:      memoryObject,
				ByteLength:    memoryBytes,
				CapacityPages: memoryPages,
			},
			{
				Kind:          vnextOwnerServiceContentArtifact,
				ObjectID:      artifactObject,
				ByteLength:    uint64(len(payloads[artifactObject])),
				CapacityPages: 2,
			},
			{
				Kind:          vnextOwnerServiceContentMMTemplate,
				ObjectID:      mmTemplateObject,
				ByteLength:    mmSize,
				CapacityPages: 1,
			},
			{
				Kind:          vnextOwnerServiceContentPageMap,
				ObjectID:      activeMapObject,
				ByteLength:    pageMapSize,
				CapacityPages: 1,
			},
			{
				Kind:          vnextOwnerServiceContentPageMap,
				ObjectID:      inactiveMapObject,
				ByteLength:    uint64(len(payloads[inactiveMapObject])),
				CapacityPages: 1,
			},
			{
				Kind:          vnextOwnerServiceContentRestoreBlob,
				ObjectID:      restoreObject,
				ByteLength:    uint64(len(payloads[restoreObject])),
				CapacityPages: 1,
			},
			{
				Kind:          vnextOwnerServiceContentPublication,
				ObjectID:      publicationObject,
				ByteLength:    2 * cxlcheckpoint.PageSize,
				CapacityPages: 2,
			},
		},
		MaxExtents: 2,
	})
	if err != nil {
		t.Fatalf("reserve producer checkpoint: %v", err)
	}
	if len(reserved.Extents) != 2 ||
		reserved.Extents[0].DeviceUUID == reserved.Extents[1].DeviceUUID {
		t.Fatalf("producer fixture is not a two-DAX fragmented placement: %#v", reserved.Extents)
	}

	pageMap.Runs = vnextProducerMemoryRuns(t, reserved, memoryPages, pagesImageID, memoryStartVAddr)
	if len(pageMap.Runs) != 2 {
		t.Fatalf("memory pages did not cross both reserve extents: %#v", pageMap.Runs)
	}
	actualPageMapSize, err := cxlcheckpoint.CanonicalPageMapSize(pageMap)
	if err != nil || actualPageMapSize != pageMapSize {
		t.Fatalf("located PageMap size = %d/%v, reserved %d", actualPageMapSize, err, pageMapSize)
	}

	publication := cxlcheckpoint.Publication{
		CheckpointID: reserved.Operation.CheckpointID,
		MMTemplate:   mmTemplate,
		PageMap:      pageMap,
		Artifacts: cxlcheckpoint.ArtifactManifest{
			ManifestID: "producer-artifacts",
			Entries: []cxlcheckpoint.ArtifactEntry{{
				Path:            "action/handler.bin",
				Type:            cxlcheckpoint.ArtifactRegular,
				Mode:            0o755,
				ByteLength:      uint64(len(payloads[artifactObject])),
				ContentObjectID: artifactObject,
			}},
		},
		MappingSlots: cxlcheckpoint.MappingSlots{
			A: cxlcheckpoint.MappingSlot{
				Name:            cxlcheckpoint.MappingSlotA,
				ContentObjectID: activeMapObject,
				CapacityPages:   1,
			},
			B: cxlcheckpoint.MappingSlot{
				Name:            cxlcheckpoint.MappingSlotB,
				ContentObjectID: inactiveMapObject,
				CapacityPages:   1,
			},
		},
		Root: cxlcheckpoint.CommittedRoot{
			State:               cxlcheckpoint.RootCommitted,
			RootID:              "producer-root",
			CheckpointID:        reserved.Operation.CheckpointID,
			OwnerID:             reserved.Operation.OwnerID,
			AllocationRecordID:  reserved.Operation.AllocationRecordID,
			MMTemplateID:        mmTemplate.TemplateID,
			PageMapID:           pageMap.PageMapID,
			PageMapVersion:      pageMap.Version,
			ArtifactManifestID:  "producer-artifacts",
			ActiveMappingSlot:   cxlcheckpoint.MappingSlotA,
			PublicationSequence: 9,
		},
	}
	for _, portable := range reserved.Devices {
		publication.Devices = append(publication.Devices, cxlcheckpoint.Device{
			DeviceUUID:    portable.DeviceUUID,
			OwnerID:       reserved.Operation.OwnerID,
			OwnerEpoch:    reserved.Operation.OwnerEpoch,
			DataPageCount: portable.DataPageCount,
		})
	}
	for _, portable := range reserved.Contents {
		kind, ok := vnextProducerTestPortableKind(portable.Kind)
		if !ok {
			t.Fatalf("unknown reserve content kind %d", portable.Kind)
		}
		publication.ContentObjects = append(publication.ContentObjects, cxlcheckpoint.ContentObject{
			ObjectID:         portable.ObjectID,
			Kind:             kind,
			ByteLength:       portable.ByteLength,
			LogicalPageStart: portable.LogicalPageStart,
			PageCount:        portable.PageCount,
		})
	}
	publication.Allocation = cxlcheckpoint.InitialAllocation{
		OwnerID:            reserved.Operation.OwnerID,
		OwnerEpoch:         reserved.Operation.OwnerEpoch,
		AllocationRecordID: reserved.Operation.AllocationRecordID,
		TotalPages:         reserved.TotalPages,
	}
	for _, extent := range reserved.Extents {
		publication.Allocation.Extents = append(
			publication.Allocation.Extents,
			cxlcheckpoint.AllocationExtent{
				DeviceUUID:         extent.DeviceUUID,
				StartDataPageIndex: extent.StartDataPageIndex,
				PageCount:          extent.PageCount,
				LogicalPageStart:   extent.LogicalPageStart,
			})
	}
	digest, err := cxlcheckpoint.DeviceTableDigest(publication.Devices)
	if err != nil {
		t.Fatalf("digest producer device table: %v", err)
	}
	publication.Root.DeviceTableDigest = digest
	if err := publication.Validate(); err != nil {
		t.Fatalf("validate producer publication: %v", err)
	}

	sidecars := vnextTestCRCPageSidecars(t, publication, service.directory)
	data := sidecars[pagesImageID]
	for page := uint64(0); page < memoryPages; page++ {
		offset := vnextCRCPageSidecarHeaderSize + int(page)*vnextCRCPageSidecarRecordSize
		start := page * cxlcheckpoint.PageSize
		checksum := crc32.Checksum(
			payloads[memoryObject][int(start):int(start+cxlcheckpoint.PageSize)],
			vnextCRCTable)
		binary.LittleEndian.PutUint32(data[offset+28:offset+32], checksum)
	}

	capability := issueVNextOwnerTestCapability(
		t, service, reserved.Operation, vnextProducerCapabilityAll)
	client := &vnextProducerCountingOwnerClient{
		delegate: vnextOwnerServiceProducerClient{
			service: service,
			caller:  vnextOwnerTestProducerCaller,
		},
	}
	producer, err := newVNextFileBackedProducer(service.directory, client)
	if err != nil {
		t.Fatalf("create file-backed VNext producer: %v", err)
	}
	return &vnextProducerTestEnvironment{
		ownerFixture: ownerFixture,
		service:      service,
		client:       client,
		producer:     producer,
		reserve:      reserved,
		publication:  publication,
		payloads:     payloads,
		sidecars:     sidecars,
		capability:   capability,
	}
}

func (environment *vnextProducerTestEnvironment) request() vnextProducerSealRequest {
	return vnextProducerSealRequest{
		Reserve:            cloneVNextProducerReserve(environment.reserve),
		Capability:         environment.capability,
		Publication:        environment.publication,
		CRCPageSidecars:    cloneVNextProducerSidecars(environment.sidecars),
		ExternalCopyEngine: vnextCRCCopyEngineCPU,
		Sources: []vnextProducerContentSource{
			{ObjectID: 101, Reader: bytes.NewReader(environment.payloads[101])},
			{ObjectID: 102, Reader: bytes.NewReader(environment.payloads[102])},
			{ObjectID: 105, Reader: bytes.NewReader(environment.payloads[105])},
			{ObjectID: 106, Reader: bytes.NewReader(environment.payloads[106])},
		},
	}
}

func TestVNextFileBackedProducerTwoDAXSealThenSeparateCommit(t *testing.T) {
	environment := newVNextProducerTestEnvironment(t)
	sealed, err := environment.producer.Seal(context.Background(), environment.request())
	if err != nil {
		t.Fatalf("seal two-DAX producer checkpoint: %v", err)
	}
	if environment.client.sealCalls != 1 ||
		environment.client.abortCalls != 0 {
		t.Fatalf("unexpected lifecycle calls after seal: %#v", environment.client)
	}
	transaction := environment.ownerFixture.group.journal.Transactions[environment.reserve.Operation.AllocationRecordID]
	if transaction == nil || transaction.State != vnextOwnerGranted {
		t.Fatalf("seal changed transaction before commit: %#v", transaction)
	}
	if sealed.Operation != environment.reserve.Operation ||
		sealed.Root.RootID != environment.publication.Root.RootID ||
		sealed.Root.RootVersion != environment.publication.Root.PublicationSequence ||
		sealed.Root.ContractID != cxlcheckpoint.V6CompatibilityID {
		t.Fatalf("unexpected sealed candidate root: %#v", sealed)
	}

	// The memory allocation crosses both devices, while artifact/control
	// objects continue in the fragmented second extent. Verify exact payload
	// and zero padding through portable logical placement.
	memoryLast := environment.publication.ContentObjects[0]
	memoryPage := vnextProducerReadLogicalPage(
		t, environment, memoryLast.LogicalPageStart+memoryLast.PageCount-1)
	wantMemoryStart := (memoryLast.PageCount - 1) * cxlcheckpoint.PageSize
	if !bytes.Equal(memoryPage, environment.payloads[101][int(wantMemoryStart):]) {
		t.Fatal("last cross-device memory page differs from producer source")
	}
	artifact := environment.publication.ContentObjects[1]
	artifactLast := vnextProducerReadLogicalPage(t, environment, artifact.LogicalPageStart+1)
	if !bytes.Equal(artifactLast[:904], environment.payloads[102][4096:]) ||
		!vnextProducerAllZero(artifactLast[904:]) {
		t.Fatal("artifact final page was not written with exact zero padding")
	}

	if err := environment.service.commit(sealed.Operation); err != nil {
		t.Fatalf("Scheduler commit of separately sealed checkpoint: %v", err)
	}
	transaction = environment.ownerFixture.group.journal.Transactions[environment.reserve.Operation.AllocationRecordID]
	if transaction == nil || transaction.State != vnextOwnerCommitted {
		t.Fatalf("commit did not make Owner transaction COMMITTED: %#v", transaction)
	}
}

func TestVNextFileBackedProducerSourceFailuresNeverCommitAndRemainAbortable(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*testing.T, *vnextProducerTestEnvironment, *vnextProducerSealRequest)
		want   string
	}{
		{
			name: "missing-content-source",
			mutate: func(_ *testing.T, _ *vnextProducerTestEnvironment, request *vnextProducerSealRequest) {
				request.Sources = request.Sources[:len(request.Sources)-1]
			},
			want: "no exact source",
		},
		{
			name: "short-content-source",
			mutate: func(_ *testing.T, environment *vnextProducerTestEnvironment, request *vnextProducerSealRequest) {
				request.Sources[1].Reader = bytes.NewReader(environment.payloads[102][:4999])
			},
			want: "is short",
		},
		{
			name: "extra-content-source",
			mutate: func(_ *testing.T, environment *vnextProducerTestEnvironment, request *vnextProducerSealRequest) {
				request.Sources[3].Reader = io.MultiReader(
					bytes.NewReader(environment.payloads[106]), strings.NewReader("x"))
			},
			want: "extra bytes",
		},
		{
			name: "publication-write-attempt",
			mutate: func(_ *testing.T, _ *vnextProducerTestEnvironment, request *vnextProducerSealRequest) {
				request.Sources = append(request.Sources, vnextProducerContentSource{
					ObjectID: 107,
					Reader:   strings.NewReader("forbidden"),
				})
			},
			want: "must not supply or write publication",
		},
		{
			name: "memory-sidecar-crc-mismatch",
			mutate: func(_ *testing.T, _ *vnextProducerTestEnvironment, request *vnextProducerSealRequest) {
				data := request.CRCPageSidecars[17]
				offset := vnextCRCPageSidecarHeaderSize + 28
				binary.LittleEndian.PutUint32(
					data[offset:offset+4], binary.LittleEndian.Uint32(data[offset:offset+4])^1)
			},
			want: "does not match producer bytes",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			environment := newVNextProducerTestEnvironment(t)
			request := environment.request()
			test.mutate(t, environment, &request)
			if _, err := environment.producer.Seal(context.Background(), request); err == nil ||
				!strings.Contains(err.Error(), test.want) {
				t.Fatalf("seal error is %v, want text %q", err, test.want)
			}
			if environment.client.sealCalls != 0 {
				t.Fatalf("failed producer called Owner seal: %d",
					environment.client.sealCalls)
			}
			if err := environment.producer.Abort(
				context.Background(), environment.reserve.Operation,
				environment.capability); err != nil {
				t.Fatalf("abort failed producer reserve: %v", err)
			}
			if environment.client.abortCalls != 1 {
				t.Fatalf("Producer abort calls are %d, want 1",
					environment.client.abortCalls)
			}
			transaction := environment.ownerFixture.group.journal.Transactions[environment.reserve.Operation.AllocationRecordID]
			if transaction == nil || transaction.State != vnextOwnerAborted {
				t.Fatalf("failed producer transaction is not ABORTED: %#v", transaction)
			}
		})
	}
}

func TestVNextFileBackedProducerRejectsUntrustedPlacementBeforeOwnerSeal(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*vnextProducerTestEnvironment, *vnextProducerSealRequest)
	}{
		{
			name: "wrong-owner",
			mutate: func(_ *vnextProducerTestEnvironment, request *vnextProducerSealRequest) {
				request.Reserve.Operation.OwnerID = "other-owner"
			},
		},
		{
			name: "wrong-owner-epoch",
			mutate: func(_ *vnextProducerTestEnvironment, request *vnextProducerSealRequest) {
				request.Reserve.Operation.OwnerEpoch++
			},
		},
		{
			name: "wrong-device",
			mutate: func(_ *vnextProducerTestEnvironment, request *vnextProducerSealRequest) {
				request.Reserve.Extents[0].DeviceUUID = "unknown-device"
			},
		},
		{
			name: "capacity-exceeds-device",
			mutate: func(_ *vnextProducerTestEnvironment, request *vnextProducerSealRequest) {
				request.Reserve.Devices[0].DataPageCount--
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			environment := newVNextProducerTestEnvironment(t)
			request := environment.request()
			test.mutate(environment, &request)
			if _, err := environment.producer.Seal(context.Background(), request); err == nil {
				t.Fatal("untrusted producer placement was accepted")
			}
			if environment.client.sealCalls != 0 {
				t.Fatalf("untrusted placement reached Owner seal: %d",
					environment.client.sealCalls)
			}
			if err := environment.producer.Abort(
				context.Background(), environment.reserve.Operation,
				environment.capability); err != nil {
				t.Fatalf("abort original reserve identity: %v", err)
			}
		})
	}

	t.Run("wrong-local-path", func(t *testing.T) {
		environment := newVNextProducerTestEnvironment(t)
		bindings := make([]vnextLocalDAXBinding, 0, len(environment.service.directory.byUUID))
		for _, portable := range environment.reserve.Devices {
			binding := environment.service.directory.byUUID[portable.DeviceUUID]
			if portable.DeviceUUID == environment.reserve.Devices[0].DeviceUUID {
				binding.DevicePath = binding.DevicePath + ".missing"
			}
			bindings = append(bindings, binding)
		}
		directory, err := newVNextLocalDAXDirectory(bindings)
		if err != nil {
			t.Fatalf("create missing-path producer directory: %v", err)
		}
		producer, err := newVNextFileBackedProducer(directory, environment.client)
		if err != nil {
			t.Fatalf("create missing-path producer: %v", err)
		}
		if _, err := producer.Seal(context.Background(), environment.request()); err == nil ||
			!strings.Contains(err.Error(), "inspect VNext producer") {
			t.Fatalf("missing local path returned %v", err)
		}
		if environment.client.sealCalls != 0 {
			t.Fatal("missing local path reached Owner lifecycle")
		}
		if err := environment.producer.Abort(
			context.Background(), environment.reserve.Operation,
			environment.capability); err != nil {
			t.Fatalf("abort missing-path producer reserve: %v", err)
		}
	})
}

func vnextProducerMemoryRuns(
	t *testing.T,
	reserve vnextOwnerReserveResponse,
	memoryPages uint64,
	pagesImageID uint32,
	startVAddr uint64,
) []cxlcheckpoint.PageMapRun {
	t.Helper()
	var runs []cxlcheckpoint.PageMapRun
	for _, extent := range reserve.Extents {
		extentEnd := extent.LogicalPageStart + extent.PageCount
		start := extent.LogicalPageStart
		if start >= memoryPages {
			continue
		}
		end := extentEnd
		if end > memoryPages {
			end = memoryPages
		}
		if start >= end {
			continue
		}
		runs = append(runs, cxlcheckpoint.PageMapRun{
			PagesImageID: pagesImageID,
			StartVAddr:   startVAddr + start*cxlcheckpoint.PageSize,
			PageCount:    end - start,
			FirstPage: cxlcheckpoint.PageID{
				OwnerID:            reserve.Operation.OwnerID,
				DeviceUUID:         extent.DeviceUUID,
				AllocationRecordID: reserve.Operation.AllocationRecordID,
				DataPageIndex:      extent.StartDataPageIndex,
			},
		})
	}
	var covered uint64
	for _, run := range runs {
		covered += run.PageCount
	}
	if covered != memoryPages {
		t.Fatalf("PageMap runs cover %d memory pages, want %d", covered, memoryPages)
	}
	return runs
}

func vnextProducerTestPortableKind(
	kind vnextOwnerServiceContentKind,
) (cxlcheckpoint.ContentKind, bool) {
	switch kind {
	case vnextOwnerServiceContentMemory:
		return cxlcheckpoint.ContentMemory, true
	case vnextOwnerServiceContentArtifact:
		return cxlcheckpoint.ContentArtifact, true
	case vnextOwnerServiceContentMMTemplate:
		return cxlcheckpoint.ContentMMTemplate, true
	case vnextOwnerServiceContentPageMap:
		return cxlcheckpoint.ContentPageMap, true
	case vnextOwnerServiceContentRestoreBlob:
		return cxlcheckpoint.ContentRestoreBlob, true
	case vnextOwnerServiceContentPublication:
		return cxlcheckpoint.ContentPublication, true
	default:
		return 0, false
	}
}

func vnextProducerTestPattern(length int, seed byte) []byte {
	data := make([]byte, length)
	for index := range data {
		data[index] = seed + byte(index%23)
	}
	return data
}

func vnextProducerAllZero(data []byte) bool {
	for _, value := range data {
		if value != 0 {
			return false
		}
	}
	return true
}

func vnextProducerReadLogicalPage(
	t *testing.T,
	environment *vnextProducerTestEnvironment,
	logicalPage uint64,
) []byte {
	t.Helper()
	extent, dataPageIndex, err := locateVNextProducerLogicalPage(environment.reserve, logicalPage)
	if err != nil {
		t.Fatalf("locate producer logical page %d: %v", logicalPage, err)
	}
	device := environment.ownerFixture.group.devices[extent.DeviceUUID]
	if device == nil {
		t.Fatalf("producer device %q is missing", extent.DeviceUUID)
	}
	offset, err := device.superblock.Geometry.contentOffset(dataPageIndex)
	if err != nil {
		t.Fatalf("resolve producer page offset: %v", err)
	}
	page := make([]byte, cxlcheckpoint.PageSize)
	if err := vnextReadAtFull(device.file, page, offset); err != nil {
		t.Fatalf("read producer logical page %d: %v", logicalPage, err)
	}
	return page
}

func (client *vnextProducerCountingOwnerClient) String() string {
	return fmt.Sprintf("seal=%d abort=%d", client.sealCalls, client.abortCalls)
}

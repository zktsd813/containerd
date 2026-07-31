package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"hash/crc32"
	"os"
	"testing"

	"github.com/containerd/containerd/third_party/trenv-containerd/pkg/cxlcheckpoint"
)

type vnextExternalSealTestPage struct {
	logicalPage uint64
	pageID      cxlcheckpoint.PageID
	payload     []byte
}

type vnextExternalSealTestFixture struct {
	owner       *vnextOwnerTestFixture
	grant       vnextOwnerWriteGrant
	publication cxlcheckpoint.Publication
	directory   *vnextLocalDAXDirectory
	pages       []vnextExternalSealTestPage
	sidecars    map[uint32][]byte
	controlSize []int
}

func newVNextExternalSealTestFixture(
	t *testing.T,
	engine vnextCRCCopyEngine,
) *vnextExternalSealTestFixture {
	t.Helper()
	// These capacities are deliberately three and four content pages. The
	// seven-page checkpoint must therefore span both devices, and its fourth
	// memory page crosses the device boundary.
	owner := newVNextOwnerTestFixture(t, []vnextOwnerTestDeviceSpec{
		{UUID: "external-seal-device-a", Size: 56 << 10},
		{UUID: "external-seal-device-b", Size: 60 << 10},
	})
	device := owner.devices[0]

	pageMap := cxlcheckpoint.PageMap{
		PageMapID:       "external-seal-page-map",
		Version:         1,
		ContentObjectID: 3,
		PageSize:        cxlcheckpoint.PageSize,
		Runs: []cxlcheckpoint.PageMapRun{
			{
				PagesImageID: 7,
				StartVAddr:   0x1000,
				PageCount:    1,
				FirstPage: cxlcheckpoint.PageID{
					OwnerID:            device.superblock.OwnerID,
					DeviceUUID:         device.superblock.DeviceUUID,
					AllocationRecordID: 1,
					DataPageIndex:      0,
				},
			},
			{
				// Preserve one absent page so the sidecar exercises the
				// strict scatter contract rather than a contiguous shortcut.
				PagesImageID: 7,
				StartVAddr:   0x3000,
				PageCount:    1,
				FirstPage: cxlcheckpoint.PageID{
					OwnerID:            device.superblock.OwnerID,
					DeviceUUID:         device.superblock.DeviceUUID,
					AllocationRecordID: 1,
					DataPageIndex:      1,
				},
			},
			{
				PagesImageID: 8,
				StartVAddr:   0x1000,
				PageCount:    1,
				FirstPage: cxlcheckpoint.PageID{
					OwnerID:            device.superblock.OwnerID,
					DeviceUUID:         device.superblock.DeviceUUID,
					AllocationRecordID: 1,
					DataPageIndex:      2,
				},
			},
			{
				PagesImageID: 8,
				StartVAddr:   0x2000,
				PageCount:    1,
				FirstPage: cxlcheckpoint.PageID{
					OwnerID:            device.superblock.OwnerID,
					DeviceUUID:         device.superblock.DeviceUUID,
					AllocationRecordID: 1,
					DataPageIndex:      3,
				},
			},
		},
	}
	mmTemplate := cxlcheckpoint.MMTemplate{
		TemplateID:             "external-seal-mm-template",
		ContentObjectID:        2,
		RuntimeCompatibilityID: "trenv-v6-external-seal-test",
		PageSize:               cxlcheckpoint.PageSize,
		VMAs: []cxlcheckpoint.VMA{
			{
				PagesImageID:    7,
				StartVAddr:      0x1000,
				EndVAddr:        0x4000,
				ProtectionFlags: cxlcheckpoint.ProtectionRead | cxlcheckpoint.ProtectionWrite,
				MappingFlags:    cxlcheckpoint.MappingPrivate | cxlcheckpoint.MappingAnonymous,
				BackingKind:     cxlcheckpoint.BackingAnonymous,
				PageMapRunStart: 0,
				PageMapRunCount: 2,
			},
			{
				PagesImageID:    8,
				StartVAddr:      0x1000,
				EndVAddr:        0x3000,
				ProtectionFlags: cxlcheckpoint.ProtectionRead | cxlcheckpoint.ProtectionWrite,
				MappingFlags:    cxlcheckpoint.MappingPrivate | cxlcheckpoint.MappingAnonymous,
				BackingKind:     cxlcheckpoint.BackingAnonymous,
				PageMapRunStart: 2,
				PageMapRunCount: 2,
			},
		},
	}
	mmSize, err := cxlcheckpoint.CanonicalMMTemplateSize(mmTemplate)
	if err != nil {
		t.Fatalf("measure external-seal MMTemplate: %v", err)
	}
	pageMapSize, err := cxlcheckpoint.CanonicalPageMapSize(pageMap)
	if err != nil {
		t.Fatalf("measure external-seal PageMap: %v", err)
	}
	if mmSize == 0 || mmSize > cxlcheckpoint.PageSize ||
		pageMapSize == 0 || pageMapSize > cxlcheckpoint.PageSize {
		t.Fatalf("test control objects do not fit one page: mm=%d page-map=%d", mmSize, pageMapSize)
	}

	request := vnextCheckpointAllocationRequest{
		RequestID:    "external-seal-request",
		CheckpointID: "external-seal-checkpoint",
		ProducerID:   "external-seal-producer",
		OwnerID:      device.superblock.OwnerID,
		OwnerEpoch:   device.superblock.OwnerEpoch,
		Contents: []vnextContentRequest{
			{Kind: vnextContentMemory, ObjectID: 1, ByteLength: 4 * vnextContentPageSize},
			{Kind: vnextContentMMTemplate, ObjectID: 2, ByteLength: mmSize},
			{Kind: vnextContentPageMap, ObjectID: 3, ByteLength: pageMapSize},
			{Kind: vnextContentPageMap, ObjectID: 4, ByteLength: pageMapSize},
		},
		MaxExtents: 4,
	}
	grant, err := owner.group.reserve(request)
	if err != nil {
		t.Fatalf("reserve external-seal allocation: %v", err)
	}

	firstPage := vnextExternalSealTestPageID(t, grant, 0)
	secondPage := vnextExternalSealTestPageID(t, grant, 1)
	thirdPage := vnextExternalSealTestPageID(t, grant, 2)
	fourthPage := vnextExternalSealTestPageID(t, grant, 3)
	pageMap.Runs[0].FirstPage = firstPage
	pageMap.Runs[1].FirstPage = secondPage
	pageMap.Runs[2].FirstPage = thirdPage
	pageMap.Runs[3].FirstPage = fourthPage
	if thirdPage.DeviceUUID == fourthPage.DeviceUUID {
		t.Fatalf("test memory pages did not cross a DAX device boundary: %#v %#v",
			thirdPage, fourthPage)
	}
	finalPageMapSize, err := cxlcheckpoint.CanonicalPageMapSize(pageMap)
	if err != nil {
		t.Fatalf("measure granted external-seal PageMap: %v", err)
	}
	if finalPageMapSize != pageMapSize {
		t.Fatalf("grant-dependent PageMap size changed from %d to %d", pageMapSize, finalPageMapSize)
	}

	extents := make([]cxlcheckpoint.AllocationExtent, len(grant.Extents))
	var totalPages uint64
	for index, extent := range grant.Extents {
		extents[index] = cxlcheckpoint.AllocationExtent{
			DeviceUUID:         extent.DeviceUUID,
			StartDataPageIndex: extent.StartDataPageIndex,
			PageCount:          extent.PageCount,
			LogicalPageStart:   extent.GlobalLogicalStart,
		}
		totalPages += extent.PageCount
	}
	devices := make([]cxlcheckpoint.Device, len(owner.devices))
	for index, attached := range owner.devices {
		devices[index] = cxlcheckpoint.Device{
			DeviceUUID:    attached.superblock.DeviceUUID,
			OwnerID:       attached.superblock.OwnerID,
			OwnerEpoch:    attached.superblock.OwnerEpoch,
			DataPageCount: attached.superblock.Geometry.DataPageCount,
		}
	}
	publication := cxlcheckpoint.Publication{
		CheckpointID: request.CheckpointID,
		Devices:      devices,
		ContentObjects: []cxlcheckpoint.ContentObject{
			{
				ObjectID:         1,
				Kind:             cxlcheckpoint.ContentMemory,
				ByteLength:       4 * cxlcheckpoint.PageSize,
				LogicalPageStart: 0,
				PageCount:        4,
			},
			{
				ObjectID:         2,
				Kind:             cxlcheckpoint.ContentMMTemplate,
				ByteLength:       mmSize,
				LogicalPageStart: 4,
				PageCount:        1,
			},
			{
				ObjectID:         3,
				Kind:             cxlcheckpoint.ContentPageMap,
				ByteLength:       pageMapSize,
				LogicalPageStart: 5,
				PageCount:        1,
			},
			{
				ObjectID:         4,
				Kind:             cxlcheckpoint.ContentPageMap,
				ByteLength:       pageMapSize,
				LogicalPageStart: 6,
				PageCount:        1,
			},
		},
		Allocation: cxlcheckpoint.InitialAllocation{
			OwnerID:            grant.OwnerID,
			OwnerEpoch:         grant.OwnerEpoch,
			AllocationRecordID: grant.AllocationRecordID,
			TotalPages:         totalPages,
			Extents:            extents,
		},
		MMTemplate: mmTemplate,
		PageMap:    pageMap,
		Artifacts: cxlcheckpoint.ArtifactManifest{
			ManifestID: "external-seal-artifacts",
		},
		MappingSlots: cxlcheckpoint.MappingSlots{
			A: cxlcheckpoint.MappingSlot{
				Name:            cxlcheckpoint.MappingSlotA,
				ContentObjectID: 3,
				CapacityPages:   1,
			},
			B: cxlcheckpoint.MappingSlot{
				Name:            cxlcheckpoint.MappingSlotB,
				ContentObjectID: 4,
				CapacityPages:   1,
			},
		},
		Root: cxlcheckpoint.CommittedRoot{
			State:               cxlcheckpoint.RootCommitted,
			RootID:              "external-seal-root",
			CheckpointID:        request.CheckpointID,
			OwnerID:             grant.OwnerID,
			AllocationRecordID:  grant.AllocationRecordID,
			MMTemplateID:        mmTemplate.TemplateID,
			PageMapID:           pageMap.PageMapID,
			PageMapVersion:      pageMap.Version,
			ArtifactManifestID:  "external-seal-artifacts",
			ActiveMappingSlot:   cxlcheckpoint.MappingSlotA,
			PublicationSequence: 1,
		},
	}
	digest, err := cxlcheckpoint.DeviceTableDigest(publication.Devices)
	if err != nil {
		t.Fatalf("digest external-seal device table: %v", err)
	}
	publication.Root.DeviceTableDigest = digest
	if err := publication.Validate(); err != nil {
		t.Fatalf("external-seal publication is invalid: %v", err)
	}

	bindings := make([]vnextLocalDAXBinding, len(owner.devices))
	for index, attached := range owner.devices {
		binding, err := vnextLocalDAXBindingFromDevice(
			attached, owner.deviceFiles[index].Name())
		if err != nil {
			t.Fatalf("build external-seal local DAX binding for %q: %v",
				attached.superblock.DeviceUUID, err)
		}
		bindings[index] = binding
	}
	directory, err := newVNextLocalDAXDirectory(bindings)
	if err != nil {
		t.Fatalf("build external-seal local DAX directory: %v", err)
	}
	pages := []vnextExternalSealTestPage{
		{
			logicalPage: 0,
			pageID:      firstPage,
			payload:     bytes.Repeat([]byte{0x31}, int(vnextContentPageSize)),
		},
		{
			logicalPage: 1,
			pageID:      secondPage,
			payload:     bytes.Repeat([]byte{0x92}, int(vnextContentPageSize)),
		},
		{
			logicalPage: 2,
			pageID:      thirdPage,
			payload:     bytes.Repeat([]byte{0x47}, int(vnextContentPageSize)),
		},
		{
			logicalPage: 3,
			pageID:      fourthPage,
			payload:     bytes.Repeat([]byte{0xe1}, int(vnextContentPageSize)),
		},
	}
	for _, page := range pages {
		pageDevice := owner.group.devices[page.pageID.DeviceUUID]
		if pageDevice == nil {
			t.Fatalf("external page references unknown device %q", page.pageID.DeviceUUID)
		}
		contentOffset, err := pageDevice.superblock.Geometry.contentOffset(page.pageID.DataPageIndex)
		if err != nil {
			t.Fatalf("resolve external page %d content offset: %v", page.logicalPage, err)
		}
		if err := vnextWriteAtFull(pageDevice.file, page.payload, contentOffset); err != nil {
			t.Fatalf("write external page %d: %v", page.logicalPage, err)
		}
	}
	for _, attached := range owner.devices {
		if err := attached.file.Sync(); err != nil {
			t.Fatalf("sync externally written payload pages on %q: %v",
				attached.superblock.DeviceUUID, err)
		}
	}

	sidecars := vnextTestCRCPageSidecars(t, publication, directory)
	for _, sidecar := range sidecars {
		binary.LittleEndian.PutUint32(sidecar[28:32], uint32(engine))
	}
	nextRecord := make(map[uint32]int)
	for index, run := range publication.PageMap.Runs {
		sidecar := sidecars[run.PagesImageID]
		recordIndex := nextRecord[run.PagesImageID]
		nextRecord[run.PagesImageID]++
		offset := vnextCRCPageSidecarHeaderSize +
			recordIndex*vnextCRCPageSidecarRecordSize
		binary.LittleEndian.PutUint32(
			sidecar[offset+28:offset+32],
			crc32.Checksum(pages[index].payload, vnextCRCTable))
	}

	return &vnextExternalSealTestFixture{
		owner:       owner,
		grant:       grant,
		publication: publication,
		directory:   directory,
		pages:       pages,
		sidecars:    sidecars,
		controlSize: []int{int(mmSize), int(pageMapSize), int(pageMapSize)},
	}
}

func vnextExternalSealTestPageID(
	t *testing.T,
	grant vnextOwnerWriteGrant,
	logicalPage uint64,
) cxlcheckpoint.PageID {
	t.Helper()
	for _, extent := range grant.Extents {
		end := extent.GlobalLogicalStart + extent.PageCount
		if logicalPage < extent.GlobalLogicalStart || logicalPage >= end {
			continue
		}
		return cxlcheckpoint.PageID{
			OwnerID:            grant.OwnerID,
			DeviceUUID:         extent.DeviceUUID,
			AllocationRecordID: grant.AllocationRecordID,
			DataPageIndex: extent.StartDataPageIndex +
				(logicalPage - extent.GlobalLogicalStart),
		}
	}
	t.Fatalf("logical page %d is outside external-seal grant", logicalPage)
	return cxlcheckpoint.PageID{}
}

func (fixture *vnextExternalSealTestFixture) cloneSidecars() map[uint32][]byte {
	cloned := make(map[uint32][]byte, len(fixture.sidecars))
	for pagesImageID, data := range fixture.sidecars {
		cloned[pagesImageID] = append([]byte(nil), data...)
	}
	return cloned
}

func (fixture *vnextExternalSealTestFixture) assertAllocationDescriptorState(
	t *testing.T,
	want vnextPageDescriptorState,
) {
	t.Helper()
	for _, extent := range fixture.grant.Extents {
		device := fixture.owner.group.devices[extent.DeviceUUID]
		if device == nil {
			t.Fatalf("grant extent references unknown device %q", extent.DeviceUUID)
		}
		device.mu.Lock()
		for page := uint64(0); page < extent.PageCount; page++ {
			descriptor, err := device.readDescriptorLocked(extent.StartDataPageIndex + page)
			if err != nil {
				device.mu.Unlock()
				t.Fatalf("read allocation descriptor %d: %v", extent.StartDataPageIndex+page, err)
			}
			if descriptor.State != want {
				device.mu.Unlock()
				t.Fatalf(
					"descriptor %s/%d is state %d, expected %d",
					extent.DeviceUUID, extent.StartDataPageIndex+page, descriptor.State, want)
			}
		}
		device.mu.Unlock()
	}
}

func (fixture *vnextExternalSealTestFixture) assertMemoryDescriptorState(
	t *testing.T,
	want vnextPageDescriptorState,
) {
	t.Helper()
	for _, page := range fixture.pages {
		device := fixture.owner.group.devices[page.pageID.DeviceUUID]
		device.mu.Lock()
		descriptor, err := device.readDescriptorLocked(page.pageID.DataPageIndex)
		device.mu.Unlock()
		if err != nil {
			t.Fatalf("read memory descriptor %d: %v", page.logicalPage, err)
		}
		if descriptor.State != want {
			t.Fatalf("memory descriptor %d is state %d, expected %d", page.logicalPage, descriptor.State, want)
		}
	}
}

func (fixture *vnextExternalSealTestFixture) sealControlPages(t *testing.T) {
	t.Helper()
	for index, size := range fixture.controlSize {
		payload := bytes.Repeat([]byte{byte(0xa0 + index)}, size)
		if err := fixture.owner.group.writePage(
			fixture.grant, uint64(index+4), payload); err != nil {
			t.Fatalf("seal control logical page %d: %v", index+4, err)
		}
	}
}

func TestVNextExternalCRIUSealCommitsAndSurvivesRestart(t *testing.T) {
	fixture := newVNextExternalSealTestFixture(t, vnextCRCCopyEngineCPU)
	if err := fixture.owner.group.sealExternalCRIUOutput(
		fixture.grant, fixture.publication, fixture.directory, fixture.cloneSidecars()); err != nil {
		t.Fatalf("seal external CRIU output: %v", err)
	}
	fixture.assertMemoryDescriptorState(t, vnextDescriptorSealed)

	// Retrying the exact producer request must be harmless. In particular, it
	// must accept the already-sealed descriptors without changing authority.
	if err := fixture.owner.group.sealExternalCRIUOutput(
		fixture.grant, fixture.publication, fixture.directory, fixture.cloneSidecars()); err != nil {
		t.Fatalf("retry external CRIU seal: %v", err)
	}
	fixture.sealControlPages(t)
	if err := fixture.owner.group.commit(fixture.grant); err != nil {
		t.Fatalf("commit externally sealed checkpoint: %v", err)
	}

	reopened := fixture.owner.reopen(t)
	transaction := reopened.journal.Transactions[fixture.grant.AllocationRecordID]
	if transaction == nil || transaction.State != vnextOwnerCommitted {
		t.Fatalf("external checkpoint did not survive restart as COMMITTED: %#v", transaction)
	}
	fixture.assertAllocationDescriptorState(t, vnextDescriptorSealed)
	for _, page := range fixture.pages {
		device := reopened.devices[page.pageID.DeviceUUID]
		device.mu.Lock()
		payload, err := device.readContentPageLocked(page.pageID.DataPageIndex)
		device.mu.Unlock()
		if err != nil {
			t.Fatalf("read restarted external payload %d: %v", page.logicalPage, err)
		}
		if !bytes.Equal(payload, page.payload) {
			t.Fatalf("external payload %d changed across restart", page.logicalPage)
		}
	}
}

func TestVNextExternalCRIUSealCRCFailureLeavesEveryDescriptorReserved(t *testing.T) {
	fixture := newVNextExternalSealTestFixture(t, vnextCRCCopyEngineCPU)
	sidecars := fixture.cloneSidecars()
	// Corrupt the final memory page, which is on the second DAX device. The
	// first device's three pages have already passed phase-one validation
	// when this mismatch is found, but none of their descriptors may be
	// published.
	secondRecord := vnextCRCPageSidecarHeaderSize + vnextCRCPageSidecarRecordSize
	recorded := binary.LittleEndian.Uint32(sidecars[8][secondRecord+28 : secondRecord+32])
	binary.LittleEndian.PutUint32(sidecars[8][secondRecord+28:secondRecord+32], recorded^1)

	err := fixture.owner.group.sealExternalCRIUOutput(
		fixture.grant, fixture.publication, fixture.directory, sidecars)
	if !errors.Is(err, errVNextCorrupt) {
		t.Fatalf("later-page CRC mismatch returned %v", err)
	}
	fixture.assertAllocationDescriptorState(t, vnextDescriptorReserved)
}

func TestVNextExternalCRIUSealRejectsIncompleteOrAlteredSidecarBeforeSeal(t *testing.T) {
	t.Run("missing", func(t *testing.T) {
		fixture := newVNextExternalSealTestFixture(t, vnextCRCCopyEngineCPU)
		sidecars := fixture.cloneSidecars()
		delete(sidecars, 7)
		err := fixture.owner.group.sealExternalCRIUOutput(
			fixture.grant, fixture.publication, fixture.directory, sidecars)
		if !errors.Is(err, errVNextCRCSidecar) {
			t.Fatalf("missing sidecar returned %v", err)
		}
		fixture.assertAllocationDescriptorState(t, vnextDescriptorReserved)
	})

	t.Run("altered-record", func(t *testing.T) {
		fixture := newVNextExternalSealTestFixture(t, vnextCRCCopyEngineCPU)
		sidecars := fixture.cloneSidecars()
		secondRecord := vnextCRCPageSidecarHeaderSize + vnextCRCPageSidecarRecordSize
		binary.LittleEndian.PutUint64(
			sidecars[7][secondRecord+8:secondRecord+16], 0x5000)
		err := fixture.owner.group.sealExternalCRIUOutput(
			fixture.grant, fixture.publication, fixture.directory, sidecars)
		if !errors.Is(err, errVNextCRCSidecar) {
			t.Fatalf("altered sidecar returned %v", err)
		}
		fixture.assertAllocationDescriptorState(t, vnextDescriptorReserved)
	})
}

func TestVNextExternalCRIUSealVisibilityFailureLeavesAbortableCheckpoint(t *testing.T) {
	fixture := newVNextExternalSealTestFixture(t, vnextCRCCopyEngineCPU)
	visibilityFailure := errors.New("test visibility barrier failed")
	original := vnextExternalPayloadVisibilityHook
	vnextExternalPayloadVisibilityHook = func(
		[]byte,
		func([]byte) error,
		func([]byte) error,
		vnextCRCCopyEngine,
	) error {
		return visibilityFailure
	}
	t.Cleanup(func() { vnextExternalPayloadVisibilityHook = original })

	err := fixture.owner.group.sealExternalCRIUOutput(
		fixture.grant, fixture.publication, fixture.directory, fixture.cloneSidecars())
	if !errors.Is(err, visibilityFailure) {
		t.Fatalf("visibility failure returned %v", err)
	}
	fixture.assertAllocationDescriptorState(t, vnextDescriptorReserved)
	if err := fixture.owner.group.abort(fixture.grant); err != nil {
		t.Fatalf("abort after visibility failure: %v", err)
	}
	fixture.assertAllocationDescriptorState(t, vnextDescriptorFree)
	transaction := fixture.owner.group.journal.Transactions[fixture.grant.AllocationRecordID]
	if transaction == nil || transaction.State != vnextOwnerAborted {
		t.Fatalf("visibility-failed checkpoint is not ABORTED: %#v", transaction)
	}
}

func TestVNextExternalCRIUSealRoutesCPUAndDMLHardwareVisibility(t *testing.T) {
	originalFlush := directDaxFlushHook
	originalInvalidate := directDaxInvalidateHook
	var flushCalls, invalidateCalls int
	directDaxFlushHook = func(*os.File, []byte) error {
		flushCalls++
		return nil
	}
	directDaxInvalidateHook = func([]byte) error {
		invalidateCalls++
		return nil
	}
	t.Cleanup(func() {
		directDaxFlushHook = originalFlush
		directDaxInvalidateHook = originalInvalidate
	})

	cpu := newVNextExternalSealTestFixture(t, vnextCRCCopyEngineCPU)
	if err := cpu.owner.group.sealExternalCRIUOutput(
		cpu.grant, cpu.publication, cpu.directory, cpu.cloneSidecars()); err != nil {
		t.Fatalf("seal CPU external pages: %v", err)
	}
	if flushCalls != len(cpu.pages) || invalidateCalls != 0 {
		t.Fatalf("CPU route called flush/invalidate %d/%d, expected %d/0",
			flushCalls, invalidateCalls, len(cpu.pages))
	}
	if err := cpu.owner.group.abort(cpu.grant); err != nil {
		t.Fatalf("abort CPU routing fixture: %v", err)
	}

	flushCalls, invalidateCalls = 0, 0
	hardware := newVNextExternalSealTestFixture(t, vnextCRCCopyEngineDMLHardware)
	if err := hardware.owner.group.sealExternalCRIUOutput(
		hardware.grant, hardware.publication, hardware.directory, hardware.cloneSidecars()); err != nil {
		t.Fatalf("seal DML hardware external pages: %v", err)
	}
	if flushCalls != 0 || invalidateCalls != len(hardware.pages) {
		t.Fatalf("DML hardware route called flush/invalidate %d/%d, expected 0/%d",
			flushCalls, invalidateCalls, len(hardware.pages))
	}
	if err := hardware.owner.group.abort(hardware.grant); err != nil {
		t.Fatalf("abort DML hardware routing fixture: %v", err)
	}
}

package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/containerd/containerd/third_party/trenv-containerd/pkg/cxlcheckpoint"
)

type vnextReaderTestFixture struct {
	directory     *vnextLocalDAXDirectory
	devices       map[string]*vnextPersistentDevice
	publication   cxlcheckpoint.Publication
	storage       cxlcheckpoint.PublicationStorage
	request       vnextReaderRequest
	authorization vnextReaderAuthorization
}

func newVNextReaderTestFixture(t *testing.T) *vnextReaderTestFixture {
	t.Helper()
	fixture := &vnextReaderTestFixture{
		devices: make(map[string]*vnextPersistentDevice),
	}
	bindings := make([]vnextLocalDAXBinding, 0, 2)
	for _, deviceUUID := range []string{"reader-device-a", "reader-device-b"} {
		path := filepath.Join(t.TempDir(), deviceUUID+".img")
		file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0o600)
		if err != nil {
			t.Fatalf("create reader device %q: %v", deviceUUID, err)
		}
		t.Cleanup(func() { _ = file.Close() })
		if err := file.Truncate(2 << 20); err != nil {
			t.Fatalf("size reader device %q: %v", deviceUUID, err)
		}
		device, err := formatVNextFileDevice(
			file, deviceUUID, "reader-owner", 7, 16<<10)
		if err != nil {
			t.Fatalf("format reader device %q: %v", deviceUUID, err)
		}
		fixture.devices[deviceUUID] = device
		binding, err := vnextLocalDAXBindingFromDevice(device, path)
		if err != nil {
			t.Fatalf("bind reader device %q: %v", deviceUUID, err)
		}
		bindings = append(bindings, binding)
	}
	directory, err := newVNextLocalDAXDirectory(bindings)
	if err != nil {
		t.Fatalf("build reader local DAX directory: %v", err)
	}
	fixture.directory = directory
	fixture.publication = vnextReaderTestPublication(t, fixture.devices)
	fixture.storage, err = cxlcheckpoint.EncodeForStorage(fixture.publication)
	if err != nil {
		t.Fatalf("encode reader publication: %v", err)
	}
	if len(fixture.storage.ExactBytes) <= int(cxlcheckpoint.PageSize) ||
		len(fixture.storage.ExactBytes) >= 2*int(cxlcheckpoint.PageSize) ||
		fixture.storage.CapacityPages != 3 ||
		len(fixture.storage.PageRuns) != 2 ||
		fixture.storage.PageRuns[0].FirstPage.DeviceUUID ==
			fixture.storage.PageRuns[1].FirstPage.DeviceUUID {
		t.Fatalf(
			"reader publication is not an exact two-page/cross-device/three-page-slot fixture: bytes=%d storage=%#v",
			len(fixture.storage.ExactBytes), fixture.storage)
	}
	fixture.writePublicationPages(t)
	fixture.request = vnextReaderRequest{
		RestoreAuthorizationID: "reader-restore-authorization",
		CheckpointID:           fixture.publication.CheckpointID,
		ExecutorID:             "reader-executor",
		CxldLogicalID:          "reader-cxld",
		TargetContainerID:      "reader-container",
	}
	fixture.authorization = vnextReaderAuthorization{
		RestoreAuthorizationID: fixture.request.RestoreAuthorizationID,
		CheckpointID:           fixture.request.CheckpointID,
		ExecutorID:             fixture.request.ExecutorID,
		CxldLogicalID:          fixture.request.CxldLogicalID,
		TargetContainerID:      fixture.request.TargetContainerID,
		Root: vnextReaderTrustedRoot{
			RootID:            fixture.publication.Root.RootID,
			RootVersion:       fixture.publication.Root.PublicationSequence,
			MMTemplateID:      fixture.publication.MMTemplate.TemplateID,
			PageMapID:         fixture.publication.PageMap.PageMapID,
			PageMapVersion:    fixture.publication.PageMap.Version,
			DeviceTableDigest: fixture.publication.Root.DeviceTableDigest,
			ContractID:        cxlcheckpoint.V6CompatibilityID,
			PublicationLocator: vnextReaderPublicationLocator{
				PublicationByteLength: uint64(len(fixture.storage.ExactBytes)),
				PublicationSHA256:     fixture.storage.SHA256,
				PageRuns: append(
					[]cxlcheckpoint.PublicationPageRun(nil),
					fixture.storage.PageRuns...),
			},
		},
	}
	return fixture
}

func vnextReaderTestPublication(
	t *testing.T,
	devices map[string]*vnextPersistentDevice,
) cxlcheckpoint.Publication {
	t.Helper()
	checkpointID := "reader-checkpoint-" + strings.Repeat("x", 2600)
	mmTemplate := cxlcheckpoint.MMTemplate{
		TemplateID:             "reader-mm-template",
		ContentObjectID:        3,
		RuntimeCompatibilityID: "reader-runtime-v6",
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
		PageMapID:       "reader-page-map",
		Version:         3,
		ContentObjectID: 4,
		PageSize:        cxlcheckpoint.PageSize,
		Runs: []cxlcheckpoint.PageMapRun{{
			PagesImageID: 7,
			StartVAddr:   0x1000,
			PageCount:    1,
			FirstPage: cxlcheckpoint.PageID{
				OwnerID:            "reader-owner",
				DeviceUUID:         "reader-device-b",
				AllocationRecordID: 42,
				DataPageIndex:      22,
			},
		}},
	}
	mmBytes, err := cxlcheckpoint.CanonicalMMTemplateSize(mmTemplate)
	if err != nil {
		t.Fatalf("measure reader MMTemplate: %v", err)
	}
	pageMapBytes, err := cxlcheckpoint.CanonicalPageMapSize(pageMap)
	if err != nil {
		t.Fatalf("measure reader PageMap: %v", err)
	}
	publication := cxlcheckpoint.Publication{
		CheckpointID: checkpointID,
		Devices: []cxlcheckpoint.Device{
			{
				DeviceUUID:    "reader-device-a",
				OwnerID:       "reader-owner",
				OwnerEpoch:    7,
				DataPageCount: devices["reader-device-a"].superblock.Geometry.DataPageCount,
			},
			{
				DeviceUUID:    "reader-device-b",
				OwnerID:       "reader-owner",
				OwnerEpoch:    7,
				DataPageCount: devices["reader-device-b"].superblock.Geometry.DataPageCount,
			},
		},
		ContentObjects: []cxlcheckpoint.ContentObject{
			{
				ObjectID:         1,
				Kind:             cxlcheckpoint.ContentPublication,
				ByteLength:       3 * cxlcheckpoint.PageSize,
				LogicalPageStart: 0,
				PageCount:        3,
			},
			{
				ObjectID:         2,
				Kind:             cxlcheckpoint.ContentMemory,
				ByteLength:       cxlcheckpoint.PageSize,
				LogicalPageStart: 3,
				PageCount:        1,
			},
			{
				ObjectID:         3,
				Kind:             cxlcheckpoint.ContentMMTemplate,
				ByteLength:       mmBytes,
				LogicalPageStart: 4,
				PageCount:        1,
			},
			{
				ObjectID:         4,
				Kind:             cxlcheckpoint.ContentPageMap,
				ByteLength:       pageMapBytes,
				LogicalPageStart: 5,
				PageCount:        1,
			},
			{
				ObjectID:         5,
				Kind:             cxlcheckpoint.ContentPageMap,
				ByteLength:       pageMapBytes,
				LogicalPageStart: 6,
				PageCount:        1,
			},
		},
		Allocation: cxlcheckpoint.InitialAllocation{
			OwnerID:            "reader-owner",
			OwnerEpoch:         7,
			AllocationRecordID: 42,
			TotalPages:         7,
			Extents: []cxlcheckpoint.AllocationExtent{
				{
					DeviceUUID:         "reader-device-a",
					StartDataPageIndex: 10,
					PageCount:          1,
					LogicalPageStart:   0,
				},
				{
					DeviceUUID:         "reader-device-b",
					StartDataPageIndex: 20,
					PageCount:          6,
					LogicalPageStart:   1,
				},
			},
		},
		MMTemplate: mmTemplate,
		PageMap:    pageMap,
		Artifacts: cxlcheckpoint.ArtifactManifest{
			ManifestID: "reader-artifacts",
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
			RootID:              "reader-root",
			CheckpointID:        checkpointID,
			OwnerID:             "reader-owner",
			AllocationRecordID:  42,
			MMTemplateID:        mmTemplate.TemplateID,
			PageMapID:           pageMap.PageMapID,
			PageMapVersion:      pageMap.Version,
			ArtifactManifestID:  "reader-artifacts",
			ActiveMappingSlot:   cxlcheckpoint.MappingSlotA,
			PublicationSequence: 5,
		},
	}
	digest, err := cxlcheckpoint.DeviceTableDigest(publication.Devices)
	if err != nil {
		t.Fatalf("digest reader device table: %v", err)
	}
	publication.Root.DeviceTableDigest = digest
	if err := publication.Validate(); err != nil {
		t.Fatalf("reader publication is invalid: %v", err)
	}
	return publication
}

func (fixture *vnextReaderTestFixture) writePublicationPages(t *testing.T) {
	t.Helper()
	byteOffset := 0
	for _, run := range fixture.storage.PageRuns {
		for page := uint64(0); page < run.PageCount; page++ {
			pageID := run.FirstPage
			pageID.DataPageIndex += page
			payload := fixture.storage.PaddedBytes[byteOffset : byteOffset+int(cxlcheckpoint.PageSize)]
			byteOffset += int(cxlcheckpoint.PageSize)
			content, descriptor, err := buildVNextContentPage(
				vnextContentPublication,
				payload,
				pageID.AllocationRecordID,
				fixture.storage.ContentObjectID,
				1)
			if err != nil {
				t.Fatalf("build reader publication page: %v", err)
			}
			device := fixture.devices[pageID.DeviceUUID]
			contentOffset, err := device.superblock.Geometry.contentOffset(pageID.DataPageIndex)
			if err != nil {
				t.Fatalf("locate reader publication content: %v", err)
			}
			descriptorOffset, err := device.superblock.Geometry.descriptorOffset(pageID.DataPageIndex)
			if err != nil {
				t.Fatalf("locate reader publication descriptor: %v", err)
			}
			descriptorBytes, err := descriptor.marshalBinary()
			if err != nil {
				t.Fatalf("marshal reader publication descriptor: %v", err)
			}
			if err := vnextWriteAtFull(device.storage, content[:], contentOffset); err != nil {
				t.Fatalf("write reader publication content: %v", err)
			}
			if err := device.storage.Sync(); err != nil {
				t.Fatalf("sync reader publication content: %v", err)
			}
			if err := vnextWriteAtFull(device.storage, descriptorBytes, descriptorOffset); err != nil {
				t.Fatalf("write reader publication descriptor: %v", err)
			}
			if err := device.storage.Sync(); err != nil {
				t.Fatalf("sync reader publication descriptor: %v", err)
			}
		}
	}
}

func (fixture *vnextReaderTestFixture) rewriteFirstDescriptor(
	t *testing.T,
	mutate func(*vnextPageDescriptor),
) {
	t.Helper()
	pageID := fixture.storage.PageRuns[0].FirstPage
	device := fixture.devices[pageID.DeviceUUID]
	device.mu.Lock()
	defer device.mu.Unlock()
	descriptor, err := device.readDescriptorLocked(pageID.DataPageIndex)
	if err != nil {
		t.Fatalf("read descriptor for mutation: %v", err)
	}
	mutate(&descriptor)
	encoded, err := descriptor.marshalBinary()
	if err != nil {
		t.Fatalf("marshal mutated descriptor: %v", err)
	}
	offset, err := device.superblock.Geometry.descriptorOffset(pageID.DataPageIndex)
	if err != nil {
		t.Fatalf("locate mutated descriptor: %v", err)
	}
	if err := vnextWriteAtFull(device.storage, encoded, offset); err != nil {
		t.Fatalf("write mutated descriptor: %v", err)
	}
	if err := device.storage.Sync(); err != nil {
		t.Fatalf("sync mutated descriptor: %v", err)
	}
}

func vnextReaderArmTestRestore(
	t *testing.T,
	fixture *vnextReaderTestFixture,
) (*vnextReaderActivationStore, vnextReaderActivatedRestoreRequest) {
	t.Helper()
	process := vnextReaderProcessIncarnation(
		sha256.Sum256([]byte("reader-first-read-test-process")))
	authorization := cloneVNextReaderAuthorization(fixture.authorization)
	authorization.CxldProcessIncarnationID = process
	authorization.ReaderInitialRegistrationCatalogRevision = 23
	acquired := vnextReaderAcquiredAuthorization{
		Authorization:          authorization,
		SchedulerID:            "reader-first-read-test-scheduler",
		SchedulerFenceRevision: 19,
		IssuedAtEpochMillis:    100,
		ExpiresAtEpochMillis:   200,
		CatalogState:           vnextReaderCatalogAuthorizationAcquired,
		LastMutationID:         authorization.RestoreAuthorizationID,
	}
	prepared, err := newVNextReaderAuthorizationStore(
		vnextReaderAuthorizationStoreTestConfig(4))
	if err != nil {
		t.Fatalf("construct VNext Reader PREPARED test store: %v", err)
	}
	if _, _, err := prepared.Prepare(acquired, 150); err != nil {
		t.Fatalf("prepare VNext Reader test authorization: %v", err)
	}
	activationStore, err := newVNextReaderActivationStore(
		vnextReaderActivationStoreTestConfig(4),
		authorization.ExecutorID,
		authorization.CxldLogicalID,
		process,
		prepared)
	if err != nil {
		t.Fatalf("construct VNext Reader activation test store: %v", err)
	}
	activationRequest := vnextReaderActivationRequestIdentity{
		Acquired:            acquired,
		ActivationRequestID: "reader-first-read-activation-request",
	}
	proposal, _, err := activationStore.Propose(activationRequest, 150)
	if err != nil {
		t.Fatalf("propose VNext Reader test activation: %v", err)
	}
	active := cloneVNextReaderAcquiredAuthorization(acquired)
	active.CatalogState = vnextReaderCatalogAuthorizationActive
	active.LastMutationID = activationRequest.ActivationRequestID
	armed, _, err := activationStore.Commit(active, proposal)
	if err != nil {
		t.Fatalf("arm VNext Reader test activation: %v", err)
	}
	return activationStore, vnextReaderActivatedRestoreRequest{
		Request:    fixture.request,
		Activation: armed,
	}
}

type vnextReaderCountingSource struct {
	delegate        vnextReaderDAXSource
	mu              sync.Mutex
	descriptorReads []cxlcheckpoint.PageID
	contentReads    []cxlcheckpoint.PageID
	events          *[]string
}

func (source *vnextReaderCountingSource) ReadVNextDescriptor(
	ctx context.Context,
	binding vnextLocalDAXBinding,
	dataPageIndex uint64,
) (vnextPageDescriptor, error) {
	source.mu.Lock()
	source.descriptorReads = append(source.descriptorReads, cxlcheckpoint.PageID{
		OwnerID:       binding.OwnerID,
		DeviceUUID:    binding.DeviceUUID,
		DataPageIndex: dataPageIndex,
	})
	if source.events != nil {
		*source.events = append(*source.events, "descriptor")
	}
	source.mu.Unlock()
	return source.delegate.ReadVNextDescriptor(ctx, binding, dataPageIndex)
}

func (source *vnextReaderCountingSource) ReadVNextContentPage(
	ctx context.Context,
	binding vnextLocalDAXBinding,
	dataPageIndex uint64,
) ([]byte, error) {
	source.mu.Lock()
	source.contentReads = append(source.contentReads, cxlcheckpoint.PageID{
		OwnerID:       binding.OwnerID,
		DeviceUUID:    binding.DeviceUUID,
		DataPageIndex: dataPageIndex,
	})
	if source.events != nil {
		*source.events = append(*source.events, "content")
	}
	source.mu.Unlock()
	return source.delegate.ReadVNextContentPage(ctx, binding, dataPageIndex)
}

func (source *vnextReaderCountingSource) counts() (int, int) {
	source.mu.Lock()
	defer source.mu.Unlock()
	return len(source.descriptorReads), len(source.contentReads)
}

type vnextReaderTestRunner struct {
	mu      sync.Mutex
	calls   int
	targets []vnextReaderExecutionTarget
	events  *[]string
	err     error
}

func (runner *vnextReaderTestRunner) RunAuthorizedVNextPublication(
	_ context.Context,
	target vnextReaderExecutionTarget,
	_ *vnextLocalDAXDirectory,
	_ vnextReaderVerifiedPublication,
) error {
	runner.mu.Lock()
	defer runner.mu.Unlock()
	runner.calls++
	runner.targets = append(runner.targets, target)
	if runner.events != nil {
		*runner.events = append(*runner.events, "runner")
	}
	return runner.err
}

func TestVNextReaderPassesExactValidatedExecutionTargetToRunner(t *testing.T) {
	fixture := newVNextReaderTestFixture(t)
	activationStore, request := vnextReaderArmTestRestore(t, fixture)
	source := &vnextReaderCountingSource{
		delegate: vnextRegularFileReaderDAXSource{},
	}
	runner := &vnextReaderTestRunner{}
	reader, err := newVNextAuthorizedReader(
		fixture.directory, activationStore, source, runner)
	if err != nil {
		t.Fatalf("construct authorized VNext reader: %v", err)
	}
	if _, err := reader.Restore(context.Background(), request); err != nil {
		t.Fatalf("restore with exact execution target: %v", err)
	}
	runner.mu.Lock()
	defer runner.mu.Unlock()
	if runner.calls != 1 || len(runner.targets) != 1 {
		t.Fatalf("runner calls/targets=%d/%d, want 1/1",
			runner.calls, len(runner.targets))
	}
	if got := runner.targets[0].TargetContainerID(); got != fixture.request.TargetContainerID {
		t.Fatalf("runner target=%q, want exact validated target %q",
			got, fixture.request.TargetContainerID)
	}
}

func TestVNextReaderRequiresActiveArmedBeforeCrossDeviceExactReadAndMaterializesRemap(t *testing.T) {
	fixture := newVNextReaderTestFixture(t)
	events := make([]string, 0)
	activationStore, request := vnextReaderArmTestRestore(t, fixture)
	source := &vnextReaderCountingSource{
		delegate: vnextRegularFileReaderDAXSource{},
		events:   &events,
	}
	workDirectory := t.TempDir()
	var materializedPath string
	var remapBytes []byte
	var invokedTarget vnextReaderExecutionTarget
	runner := vnextReaderCRIURemapRunner{
		WorkDirectory: workDirectory,
		Invoke: func(
			_ context.Context,
			target vnextReaderExecutionTarget,
			path string,
			verified vnextReaderVerifiedPublication,
		) error {
			events = append(events, "runner")
			invokedTarget = target
			materializedPath = path
			if !bytes.Equal(verified.ExactBytes, fixture.storage.ExactBytes) {
				return errors.New("runner received padded or changed publication bytes")
			}
			var err error
			remapBytes, err = os.ReadFile(path)
			return err
		},
	}
	reader, err := newVNextAuthorizedReader(
		fixture.directory, activationStore, source, runner)
	if err != nil {
		t.Fatalf("construct authorized VNext reader: %v", err)
	}
	verified, err := reader.Restore(context.Background(), request)
	if err != nil {
		t.Fatalf("restore exact cross-device publication: %v", err)
	}
	if !bytes.Equal(verified.ExactBytes, fixture.storage.ExactBytes) ||
		len(verified.ExactBytes) != len(fixture.storage.ExactBytes) ||
		len(verified.ExactBytes) == len(fixture.storage.PaddedBytes) {
		t.Fatalf(
			"reader returned slot padding: exact=%d got=%d capacity=%d",
			len(fixture.storage.ExactBytes), len(verified.ExactBytes), len(fixture.storage.PaddedBytes))
	}
	descriptorReads, contentReads := source.counts()
	if descriptorReads != 4 || contentReads != 2 {
		t.Fatalf("reader DAX calls descriptor/content = %d/%d, want 4/2", descriptorReads, contentReads)
	}
	if len(source.contentReads) != 2 ||
		source.contentReads[0].DeviceUUID != "reader-device-a" ||
		source.contentReads[0].DataPageIndex != 10 ||
		source.contentReads[1].DeviceUUID != "reader-device-b" ||
		source.contentReads[1].DataPageIndex != 20 {
		t.Fatalf("reader did not follow ordered exact PageID runs: %#v", source.contentReads)
	}
	if events[0] != "descriptor" || events[len(events)-1] != "runner" {
		t.Fatalf("ACTIVE_ARMED read/runner order is wrong: %#v", events)
	}
	if !bytes.HasPrefix(remapBytes, []byte(vnextCRIURemapMagic+"\n")) ||
		!bytes.Contains(remapBytes, []byte(fixture.directory.byUUID["reader-device-b"].DevicePath)) {
		t.Fatalf("materialized remap is incomplete: %q", remapBytes)
	}
	if materializedPath == "" {
		t.Fatal("CRIU remap runner was not invoked")
	}
	if invokedTarget.TargetContainerID() != fixture.request.TargetContainerID {
		t.Fatalf("CRIU Invoke target=%q, want exact validated target %q",
			invokedTarget.TargetContainerID(), fixture.request.TargetContainerID)
	}
	if _, err := os.Stat(materializedPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("ephemeral CRIU remap was not removed: %v", err)
	}
}

func TestVNextReaderRejectsInactiveOrMismatchedActivationBeforeDAXRead(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(*vnextReaderActivatedRestoreRequest)
	}{
		{
			name: "activation is not ACTIVE_ARMED",
			mutate: func(request *vnextReaderActivatedRestoreRequest) {
				request.Activation.State = vnextReaderActivationPending
			},
		},
		{
			name: "substituted request target identity",
			mutate: func(request *vnextReaderActivatedRestoreRequest) {
				request.Request.TargetContainerID = "different-container"
			},
		},
		{
			name: "substituted authorization target identity",
			mutate: func(request *vnextReaderActivatedRestoreRequest) {
				request.Activation = cloneVNextReaderActivationIntent(
					request.Activation)
				request.Activation.Request.Acquired.Authorization.
					TargetContainerID = "different-container"
			},
		},
		{
			name: "wrong locator Owner identity",
			mutate: func(request *vnextReaderActivatedRestoreRequest) {
				request.Activation.Request.Acquired.Authorization.Root.PublicationLocator.PageRuns = append(
					[]cxlcheckpoint.PublicationPageRun(nil),
					request.Activation.Request.Acquired.Authorization.Root.PublicationLocator.PageRuns...)
				request.Activation.Request.Acquired.Authorization.Root.PublicationLocator.PageRuns[0].FirstPage.OwnerID =
					"different-owner"
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := newVNextReaderTestFixture(t)
			activationStore, request := vnextReaderArmTestRestore(t, fixture)
			test.mutate(&request)
			source := &vnextReaderCountingSource{delegate: vnextRegularFileReaderDAXSource{}}
			runner := &vnextReaderTestRunner{}
			reader, err := newVNextAuthorizedReader(
				fixture.directory, activationStore, source, runner)
			if err != nil {
				t.Fatalf("construct authorized reader: %v", err)
			}
			if _, err := reader.Restore(context.Background(), request); err == nil {
				t.Fatal("reader accepted missing or mismatched authorization")
			}
			descriptorReads, contentReads := source.counts()
			if descriptorReads != 0 || contentReads != 0 || runner.calls != 0 {
				t.Fatalf(
					"authorization failure reached DAX/runner: descriptor=%d content=%d runner=%d",
					descriptorReads, contentReads, runner.calls)
			}
		})
	}
}

func TestVNextReaderLocatorRunLimitAccepts256(t *testing.T) {
	fixture := newVNextReaderTestFixture(t)
	authorization := vnextReaderAuthorizationWithLocatorRuns(
		fixture.authorization, vnextReaderMaxLocatorRuns)
	reader := &vnextAuthorizedReader{directory: fixture.directory}

	pages, target, err := reader.validateAuthorization(
		fixture.request, authorization)
	if err != nil {
		t.Fatalf("validate %d locator runs: %v", vnextReaderMaxLocatorRuns, err)
	}
	if len(pages) != vnextReaderMaxLocatorRuns {
		t.Fatalf("resolved locator pages = %d, want %d", len(pages), vnextReaderMaxLocatorRuns)
	}
	if target.TargetContainerID() != fixture.request.TargetContainerID {
		t.Fatalf("resolved execution target=%q, want %q",
			target.TargetContainerID(), fixture.request.TargetContainerID)
	}
}

func TestVNextReaderLocatorRunLimitRejects257(t *testing.T) {
	fixture := newVNextReaderTestFixture(t)
	authorization := vnextReaderAuthorizationWithLocatorRuns(
		fixture.authorization, vnextReaderMaxLocatorRuns+1)
	reader := &vnextAuthorizedReader{directory: fixture.directory}

	_, target, err := reader.validateAuthorization(
		fixture.request, authorization)
	if err == nil || !strings.Contains(err.Error(), "outside 1..256") {
		t.Fatalf("validate %d locator runs = %v, want run-count rejection", vnextReaderMaxLocatorRuns+1, err)
	}
	if target != (vnextReaderExecutionTarget{}) {
		t.Fatalf("failed authorization minted execution target %#v", target)
	}
}

func vnextReaderAuthorizationWithLocatorRuns(
	authorization vnextReaderAuthorization,
	runCount int,
) vnextReaderAuthorization {
	authorization.Root.PublicationLocator.PublicationByteLength =
		uint64(runCount) * cxlcheckpoint.PageSize
	authorization.Root.PublicationLocator.PageRuns = make(
		[]cxlcheckpoint.PublicationPageRun, runCount)
	for index := range authorization.Root.PublicationLocator.PageRuns {
		deviceUUID := "reader-device-a"
		if index%2 != 0 {
			deviceUUID = "reader-device-b"
		}
		authorization.Root.PublicationLocator.PageRuns[index] =
			cxlcheckpoint.PublicationPageRun{
				FirstPage: cxlcheckpoint.PageID{
					OwnerID:            "reader-owner",
					DeviceUUID:         deviceUUID,
					AllocationRecordID: 42,
					DataPageIndex:      uint64(10 + index/2),
				},
				PageCount: 1,
			}
	}
	return authorization
}

func TestVNextReaderRejectsChangedExactRootOrDescriptor(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*testing.T, *vnextReaderTestFixture)
	}{
		{
			name: "wrong exact length",
			mutate: func(t *testing.T, fixture *vnextReaderTestFixture) {
				length := len(fixture.storage.ExactBytes) + 1
				fixture.authorization.Root.PublicationLocator.PublicationByteLength = uint64(length)
				fixture.authorization.Root.PublicationLocator.PublicationSHA256 =
					sha256.Sum256(fixture.storage.PaddedBytes[:length])
			},
		},
		{
			name: "wrong exact SHA",
			mutate: func(_ *testing.T, fixture *vnextReaderTestFixture) {
				fixture.authorization.Root.PublicationLocator.PublicationSHA256[0] ^= 0xff
			},
		},
		{
			name: "wrong authorized root",
			mutate: func(_ *testing.T, fixture *vnextReaderTestFixture) {
				fixture.authorization.Root.RootID = "different-reader-root"
			},
		},
		{
			name: "wrong MM template",
			mutate: func(_ *testing.T, fixture *vnextReaderTestFixture) {
				fixture.authorization.Root.MMTemplateID = "different-reader-template"
			},
		},
		{
			name: "wrong PageMap version",
			mutate: func(_ *testing.T, fixture *vnextReaderTestFixture) {
				fixture.authorization.Root.PageMapVersion++
			},
		},
		{
			name: "wrong device-table digest",
			mutate: func(_ *testing.T, fixture *vnextReaderTestFixture) {
				fixture.authorization.Root.DeviceTableDigest[0] ^= 0xff
			},
		},
		{
			name: "wrong checkpoint binding",
			mutate: func(_ *testing.T, fixture *vnextReaderTestFixture) {
				fixture.request.CheckpointID = "different-checkpoint"
				fixture.authorization.CheckpointID = fixture.request.CheckpointID
			},
		},
		{
			name: "descriptor is not SEALED",
			mutate: func(t *testing.T, fixture *vnextReaderTestFixture) {
				fixture.rewriteFirstDescriptor(t, func(descriptor *vnextPageDescriptor) {
					descriptor.State = vnextDescriptorReserved
				})
			},
		},
		{
			name: "descriptor allocation differs",
			mutate: func(t *testing.T, fixture *vnextReaderTestFixture) {
				fixture.rewriteFirstDescriptor(t, func(descriptor *vnextPageDescriptor) {
					descriptor.AllocationRecordID++
				})
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newVNextReaderTestFixture(t)
			test.mutate(t, fixture)
			activationStore, request := vnextReaderArmTestRestore(t, fixture)
			source := &vnextReaderCountingSource{delegate: vnextRegularFileReaderDAXSource{}}
			runner := &vnextReaderTestRunner{}
			reader, err := newVNextAuthorizedReader(
				fixture.directory, activationStore, source, runner)
			if err != nil {
				t.Fatalf("construct authorized reader: %v", err)
			}
			if _, err := reader.Restore(context.Background(), request); err == nil {
				t.Fatalf("reader accepted %s", test.name)
			}
			if runner.calls != 0 {
				t.Fatalf("rejected publication reached restore runner %d times", runner.calls)
			}
		})
	}
}

func TestVNextReaderRegularFileSourceRejectsBindingChange(t *testing.T) {
	fixture := newVNextReaderTestFixture(t)
	binding := fixture.directory.byUUID["reader-device-a"]
	binding.OwnerEpoch++
	source := vnextRegularFileReaderDAXSource{}
	if _, err := source.ReadVNextDescriptor(
		context.Background(), binding, 10); err == nil ||
		!strings.Contains(err.Error(), "does not match") {
		t.Fatalf("read-only source accepted a changed local binding: %v", err)
	}
}

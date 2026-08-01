package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"math"
	"os"
	"reflect"
	"sort"

	"github.com/containerd/containerd/third_party/trenv-containerd/pkg/cxlcheckpoint"
)

// vnextProducerOwnerClient is the narrow Owner lifecycle contract needed by
// a checkpoint producer. Seal returns a candidate root but deliberately does
// not commit the allocation. Commit remains outside this Producer interface
// and is a separate Scheduler-only transition. Producer Abort is capability
// gated and remains available after producer-side failure.
//
// A network adapter can implement this interface with the strict VNext Owner
// RPC. The in-process adapter below is used by the file-backed integration
// gate without creating a second lifecycle implementation.
type vnextProducerOwnerClient interface {
	SealVNextCheckpoint(
		context.Context,
		vnextOwnerExternalSealRequest,
	) (vnextOwnerSealResponse, error)
	ProducerAbortVNextCheckpoint(
		context.Context,
		vnextOwnerOperationIdentity,
		vnextProducerCapabilityProof,
	) error
}

type vnextOwnerServiceProducerClient struct {
	service *vnextOwnerService
	caller  vnextOwnerCallerContext
}

func (client vnextOwnerServiceProducerClient) SealVNextCheckpoint(
	ctx context.Context,
	request vnextOwnerExternalSealRequest,
) (vnextOwnerSealResponse, error) {
	if err := ctx.Err(); err != nil {
		return vnextOwnerSealResponse{}, err
	}
	if client.service == nil {
		return vnextOwnerSealResponse{}, errors.New("VNext producer Owner service is unavailable")
	}
	return client.service.sealExternal(request, client.caller)
}

func (client vnextOwnerServiceProducerClient) ProducerAbortVNextCheckpoint(
	ctx context.Context,
	identity vnextOwnerOperationIdentity,
	capability vnextProducerCapabilityProof,
) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if client.service == nil {
		return errors.New("VNext producer Owner service is unavailable")
	}
	return client.service.producerAbort(identity, capability, client.caller)
}

// vnextProducerContentSource supplies the exact meaningful bytes for one
// reserved content object. A source is mandatory for memory, artifact,
// restore-blob, inactive PageMap, and any non-active MMTemplate object, even
// when ByteLength is zero. The active MMTemplate and active PageMap are always
// generated from their canonical TRPUB006 representation and must not be
// supplied by the caller. ContentPublication is Owner-written and accepting a
// source for it is an error.
type vnextProducerContentSource struct {
	ObjectID uint64
	Reader   io.Reader
}

type vnextProducerSealRequest struct {
	Reserve vnextOwnerReserveResponse
	// Capability is issued by the exact Owner for this immutable Reserve scope
	// and must authorize Seal for the authenticated Producer principal.
	Capability vnextProducerCapabilityProof

	// Publication must already contain the exact portable allocation returned
	// by Reserve. Seal re-encodes it canonically; a caller cannot provide raw
	// publication bytes or write the publication slot directly.
	Publication cxlcheckpoint.Publication
	Sources     []vnextProducerContentSource

	// Memory CRC evidence is owned by the CRIU dump boundary. This producer
	// does not synthesize evidence for a dump it did not perform: it parses the
	// strict TRCRC006 sidecars and compares every record with the exact 4 KiB
	// memory page it wrote before forwarding the bytes to the Owner.
	CRCPageSidecars map[uint32][]byte

	// ExternalCopyEngine labels producer-written non-memory pages. The
	// file-backed implementation normally uses CPU; the numeric contract also
	// admits the two Intel DML modes used by the real producer boundary.
	ExternalCopyEngine vnextCRCCopyEngine
}

// vnextProducerSealedCheckpoint is a candidate Scheduler root. It is not
// AVAILABLE and the durable Owner transaction remains GRANTED until Commit is
// called successfully.
type vnextProducerSealedCheckpoint struct {
	Operation vnextOwnerOperationIdentity
	Root      vnextOwnerCheckpointRoot
}

// vnextFileBackedProducer is the regular-file/QEMU implementation of the
// producer data plane. It opens local bindings O_RDWR, verifies existing
// TRCXL006 superblocks without running allocator recovery, writes only content
// payload pages, fsyncs them, and then asks the Owner to seal descriptors and
// write the canonical publication slot.
//
// Physical devdax requires the explicit mmap/cache-writeback backend and is
// intentionally not disguised as regular-file support here.
type vnextFileBackedProducer struct {
	directory *vnextLocalDAXDirectory
	owner     vnextProducerOwnerClient
}

func newVNextFileBackedProducer(
	directory *vnextLocalDAXDirectory,
	owner vnextProducerOwnerClient,
) (*vnextFileBackedProducer, error) {
	if directory == nil || len(directory.byUUID) == 0 {
		return nil, errors.New("VNext producer local DAX directory is unavailable")
	}
	if owner == nil || vnextProducerInterfaceIsNil(owner) {
		return nil, errors.New("VNext producer Owner client is unavailable")
	}
	return &vnextFileBackedProducer{directory: directory, owner: owner}, nil
}

type vnextPreparedProducerSeal struct {
	reserve        vnextOwnerReserveResponse
	publication    cxlcheckpoint.Publication
	storage        cxlcheckpoint.PublicationStorage
	sources        map[uint64]io.Reader
	sidecars       map[uint32][]byte
	externalEngine vnextCRCCopyEngine
}

type vnextProducerWrittenPage struct {
	logicalPage uint64
	crc32c      uint32
}

type vnextProducerOpenedRegularFile struct {
	binding    vnextLocalDAXBinding
	file       *os.File
	storage    *vnextRegularFileStorage
	superblock vnextDeviceSuperblock
	stat       os.FileInfo
	touched    bool
}

// Seal writes every non-publication content page and invokes Owner seal. It
// never calls commit. On error the reserve identity remains available to
// Abort; payload pages may contain partial producer data, but their Owner
// descriptors remain RESERVED unless Owner seal itself reached its descriptor
// publication phase.
func (producer *vnextFileBackedProducer) Seal(
	ctx context.Context,
	request vnextProducerSealRequest,
) (vnextProducerSealedCheckpoint, error) {
	if producer == nil || producer.directory == nil || producer.owner == nil {
		return vnextProducerSealedCheckpoint{}, errors.New("VNext producer is unavailable")
	}
	if err := ctx.Err(); err != nil {
		return vnextProducerSealedCheckpoint{}, err
	}
	prepared, err := producer.prepare(request)
	if err != nil {
		return vnextProducerSealedCheckpoint{}, err
	}

	memoryPages, externalCRCs, err := producer.writeContent(ctx, prepared)
	if err != nil {
		return vnextProducerSealedCheckpoint{}, err
	}
	if err := producer.validateMemorySidecars(
		prepared.reserve,
		prepared.publication,
		prepared.sidecars,
		memoryPages,
	); err != nil {
		return vnextProducerSealedCheckpoint{}, err
	}
	if err := ctx.Err(); err != nil {
		return vnextProducerSealedCheckpoint{}, err
	}

	response, err := producer.owner.SealVNextCheckpoint(
		ctx,
		vnextOwnerExternalSealRequest{
			Operation:               prepared.reserve.Operation,
			Capability:              request.Capability,
			PublicationEnvelope:     append([]byte(nil), prepared.storage.ExactBytes...),
			CRCPageSidecars:         cloneVNextProducerSidecars(prepared.sidecars),
			ExternalContentPageCRCs: externalCRCs,
		})
	if err != nil {
		return vnextProducerSealedCheckpoint{}, err
	}
	if err := validateVNextProducerSealResponse(
		prepared.reserve,
		prepared.publication,
		prepared.storage,
		response,
	); err != nil {
		return vnextProducerSealedCheckpoint{}, fmt.Errorf(
			"Owner returned an invalid VNext candidate root: %w", err)
	}
	return vnextProducerSealedCheckpoint{
		Operation: prepared.reserve.Operation,
		Root:      cloneVNextProducerRoot(response.Root),
	}, nil
}

// Abort is valid for the reserve identity even when producer validation,
// source streaming, sidecar validation, or Owner seal failed. It never implies
// that Commit was attempted.
func (producer *vnextFileBackedProducer) Abort(
	ctx context.Context,
	identity vnextOwnerOperationIdentity,
	capability vnextProducerCapabilityProof,
) error {
	if producer == nil || producer.owner == nil {
		return errors.New("VNext producer is unavailable")
	}
	if err := validateVNextProducerOperationIdentity(identity); err != nil {
		return err
	}
	if err := validateVNextProducerCapabilityProof(capability); err != nil {
		return err
	}
	return producer.owner.ProducerAbortVNextCheckpoint(ctx, identity, capability)
}

func (producer *vnextFileBackedProducer) prepare(
	request vnextProducerSealRequest,
) (vnextPreparedProducerSeal, error) {
	if err := validateVNextProducerCapabilityProof(request.Capability); err != nil {
		return vnextPreparedProducerSeal{}, err
	}
	if !request.ExternalCopyEngine.valid() {
		return vnextPreparedProducerSeal{}, fmt.Errorf(
			"VNext producer external copy engine %d is invalid", request.ExternalCopyEngine)
	}
	if err := validateVNextProducerReserve(request.Reserve, producer.directory); err != nil {
		return vnextPreparedProducerSeal{}, err
	}
	if err := validateVNextProducerPublication(request.Reserve, request.Publication); err != nil {
		return vnextPreparedProducerSeal{}, err
	}
	storage, err := cxlcheckpoint.EncodeForStorage(request.Publication)
	if err != nil {
		return vnextPreparedProducerSeal{}, fmt.Errorf(
			"encode canonical VNext publication: %w", err)
	}
	sources, err := validateVNextProducerSources(request.Publication, request.Sources)
	if err != nil {
		return vnextPreparedProducerSeal{}, err
	}
	if len(request.CRCPageSidecars) == 0 {
		return vnextPreparedProducerSeal{}, errors.New(
			"VNext producer requires strict TRCRC006 memory sidecars")
	}
	return vnextPreparedProducerSeal{
		reserve:        cloneVNextProducerReserve(request.Reserve),
		publication:    request.Publication,
		storage:        storage,
		sources:        sources,
		sidecars:       cloneVNextProducerSidecars(request.CRCPageSidecars),
		externalEngine: request.ExternalCopyEngine,
	}, nil
}

func (producer *vnextFileBackedProducer) writeContent(
	ctx context.Context,
	prepared vnextPreparedProducerSeal,
) (map[uint64]uint32, []vnextExternalContentPageCRC, error) {
	opened, err := producer.openRegularFiles(prepared.reserve)
	if err != nil {
		return nil, nil, err
	}
	closeOpened := func() error {
		var combined error
		for _, device := range opened {
			if err := device.file.Close(); err != nil {
				current := fmt.Errorf(
					"close producer device %q: %w", device.binding.DeviceUUID, err)
				if combined == nil {
					combined = current
				} else {
					combined = fmt.Errorf("%v; additional close failure: %w", combined, current)
				}
			}
		}
		return combined
	}

	memoryPages := make(map[uint64]uint32)
	external := make([]vnextExternalContentPageCRC, 0)
	writeErr := producer.writeAllObjects(ctx, prepared, opened, memoryPages, &external)
	if writeErr == nil {
		for _, device := range opened {
			if !device.touched {
				continue
			}
			if err := device.storage.Sync(); err != nil {
				writeErr = fmt.Errorf(
					"sync VNext producer device %q: %w", device.binding.DeviceUUID, err)
				break
			}
		}
	}
	closeErr := closeOpened()
	if writeErr != nil {
		if closeErr != nil {
			return nil, nil, fmt.Errorf(
				"%v; additionally failed to close producer devices: %w", writeErr, closeErr)
		}
		return nil, nil, writeErr
	}
	if closeErr != nil {
		return nil, nil, closeErr
	}
	return memoryPages, external, nil
}

func (producer *vnextFileBackedProducer) writeAllObjects(
	ctx context.Context,
	prepared vnextPreparedProducerSeal,
	opened map[string]*vnextProducerOpenedRegularFile,
	memoryPages map[uint64]uint32,
	external *[]vnextExternalContentPageCRC,
) error {
	mmBytes, err := cxlcheckpoint.CanonicalMMTemplateBytes(prepared.publication.MMTemplate)
	if err != nil {
		return fmt.Errorf("encode canonical MMTemplate: %w", err)
	}
	pageMapBytes, err := cxlcheckpoint.CanonicalPageMapBytes(prepared.publication.PageMap)
	if err != nil {
		return fmt.Errorf("encode canonical PageMap: %w", err)
	}

	for _, content := range prepared.publication.ContentObjects {
		if err := ctx.Err(); err != nil {
			return err
		}
		if content.Kind == cxlcheckpoint.ContentPublication {
			// The Owner is the only writer of the canonical publication slot.
			continue
		}
		var reader io.Reader
		switch {
		case content.Kind == cxlcheckpoint.ContentMMTemplate &&
			content.ObjectID == prepared.publication.MMTemplate.ContentObjectID:
			reader = bytes.NewReader(mmBytes)
		case content.Kind == cxlcheckpoint.ContentPageMap &&
			content.ObjectID == prepared.publication.PageMap.ContentObjectID:
			reader = bytes.NewReader(pageMapBytes)
		default:
			reader = prepared.sources[content.ObjectID]
		}
		if reader == nil || vnextProducerInterfaceIsNil(reader) {
			return fmt.Errorf(
				"VNext producer content object %d has no exact source", content.ObjectID)
		}
		if err := producer.writeObject(
			ctx, prepared.reserve, content, reader, opened, memoryPages, external,
			prepared.externalEngine,
		); err != nil {
			return err
		}
	}
	return nil
}

func (producer *vnextFileBackedProducer) writeObject(
	ctx context.Context,
	reserve vnextOwnerReserveResponse,
	content cxlcheckpoint.ContentObject,
	reader io.Reader,
	opened map[string]*vnextProducerOpenedRegularFile,
	memoryPages map[uint64]uint32,
	external *[]vnextExternalContentPageCRC,
	externalEngine vnextCRCCopyEngine,
) error {
	remaining := content.ByteLength
	for pageWithinObject := uint64(0); pageWithinObject < content.PageCount; pageWithinObject++ {
		if err := ctx.Err(); err != nil {
			return err
		}
		logicalPage, ok := vnextAdd(content.LogicalPageStart, pageWithinObject)
		if !ok {
			return fmt.Errorf("content object %d logical page overflows", content.ObjectID)
		}
		payloadLength := remaining
		if payloadLength > cxlcheckpoint.PageSize {
			payloadLength = cxlcheckpoint.PageSize
		}
		page := make([]byte, cxlcheckpoint.PageSize)
		if payloadLength > 0 {
			if _, err := io.ReadFull(reader, page[:int(payloadLength)]); err != nil {
				return fmt.Errorf(
					"content object %d is short at logical page %d: %w",
					content.ObjectID, logicalPage, err)
			}
			remaining -= payloadLength
		}

		extent, dataPageIndex, err := locateVNextProducerLogicalPage(reserve, logicalPage)
		if err != nil {
			return err
		}
		device := opened[extent.DeviceUUID]
		if device == nil {
			return fmt.Errorf("VNext producer device %q was not opened", extent.DeviceUUID)
		}
		offset, err := device.superblock.Geometry.contentOffset(dataPageIndex)
		if err != nil {
			return fmt.Errorf(
				"resolve content object %d logical page %d: %w",
				content.ObjectID, logicalPage, err)
		}
		if err := vnextWriteAtFull(device.storage, page, offset); err != nil {
			return fmt.Errorf(
				"write content object %d logical page %d: %w",
				content.ObjectID, logicalPage, err)
		}
		device.touched = true
		checksum := crc32.Checksum(page, vnextCRCTable)
		if content.Kind == cxlcheckpoint.ContentMemory {
			memoryPages[logicalPage] = checksum
		} else {
			*external = append(*external, vnextExternalContentPageCRC{
				LogicalPage:   logicalPage,
				ContentCRC32C: checksum,
				CopyEngine:    externalEngine,
			})
		}
	}
	if remaining != 0 {
		return fmt.Errorf(
			"content object %d has %d unwritten bytes after its capacity",
			content.ObjectID, remaining)
	}
	var trailing [1]byte
	count, err := reader.Read(trailing[:])
	if count != 0 {
		return fmt.Errorf("content object %d source contains extra bytes", content.ObjectID)
	}
	if err != nil && !errors.Is(err, io.EOF) {
		return fmt.Errorf("read content object %d trailer: %w", content.ObjectID, err)
	}
	if err == nil {
		return fmt.Errorf("content object %d source made no progress at EOF", content.ObjectID)
	}
	return nil
}

func (producer *vnextFileBackedProducer) openRegularFiles(
	reserve vnextOwnerReserveResponse,
) (map[string]*vnextProducerOpenedRegularFile, error) {
	opened := make(map[string]*vnextProducerOpenedRegularFile, len(reserve.Devices))
	closeAll := func() {
		for _, device := range opened {
			_ = device.file.Close()
		}
	}
	for _, portable := range reserve.Devices {
		binding := producer.directory.byUUID[portable.DeviceUUID]
		device, err := openVNextProducerRegularFile(binding)
		if err != nil {
			closeAll()
			return nil, err
		}
		for previousUUID, previous := range opened {
			if os.SameFile(previous.stat, device.stat) {
				_ = device.file.Close()
				closeAll()
				return nil, fmt.Errorf(
					"VNext producer paths for devices %q and %q alias one file",
					previousUUID, portable.DeviceUUID)
			}
		}
		opened[portable.DeviceUUID] = device
	}
	return opened, nil
}

func openVNextProducerRegularFile(
	binding vnextLocalDAXBinding,
) (*vnextProducerOpenedRegularFile, error) {
	if err := validateVNextLocalDAXPath(binding.DevicePath); err != nil {
		return nil, err
	}
	pathStat, err := os.Lstat(binding.DevicePath)
	if err != nil {
		return nil, fmt.Errorf(
			"inspect VNext producer regular-file DAX %q: %w", binding.DevicePath, err)
	}
	if pathStat.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf(
			"VNext producer regular-file DAX %q is a symbolic link", binding.DevicePath)
	}
	file, err := os.OpenFile(binding.DevicePath, os.O_RDWR, 0)
	if err != nil {
		return nil, fmt.Errorf(
			"open VNext producer regular-file DAX %q read-write: %w", binding.DevicePath, err)
	}
	fail := func(cause error) (*vnextProducerOpenedRegularFile, error) {
		if closeErr := file.Close(); closeErr != nil {
			return nil, fmt.Errorf("%v; close producer file: %w", cause, closeErr)
		}
		return nil, cause
	}
	fileStat, err := file.Stat()
	if err != nil {
		return fail(fmt.Errorf("stat opened VNext producer file: %w", err))
	}
	if !os.SameFile(pathStat, fileStat) {
		return fail(errors.New("VNext producer device path changed while it was opened"))
	}
	storage, err := newVNextRegularFileStorage(file)
	if err != nil {
		return fail(err)
	}
	first, firstErr := vnextReadSuperblockSlot(storage, 0)
	second, secondErr := vnextReadSuperblockSlot(storage, vnextSuperblockSlotBytes)
	superblock, err := vnextSelectSuperblock(first, firstErr, second, secondErr)
	if err != nil {
		return fail(err)
	}
	if storage.Size() != superblock.Geometry.DeviceBytes ||
		superblock.DeviceUUID != binding.DeviceUUID ||
		superblock.OwnerID != binding.OwnerID ||
		superblock.OwnerEpoch != binding.OwnerEpoch ||
		superblock.Geometry.DataPageCount != binding.DataPageCount ||
		superblock.Geometry.ContentRegionBase != binding.ContentRegionBase {
		return fail(errors.New(
			"read-write TRCXL006 superblock does not match the local producer binding"))
	}
	return &vnextProducerOpenedRegularFile{
		binding:    binding,
		file:       file,
		storage:    storage,
		superblock: superblock,
		stat:       fileStat,
	}, nil
}

func (producer *vnextFileBackedProducer) validateMemorySidecars(
	reserve vnextOwnerReserveResponse,
	publication cxlcheckpoint.Publication,
	sidecars map[uint32][]byte,
	written map[uint64]uint32,
) error {
	validated, err := producer.directory.validateVNextCRCPageSidecars(publication, sidecars)
	if err != nil {
		return fmt.Errorf("validate producer TRCRC006 sidecars: %w", err)
	}
	if len(validated) != len(written) {
		return fmt.Errorf(
			"TRCRC006 contains %d memory pages, producer wrote %d",
			len(validated), len(written))
	}
	seen := make(map[uint64]struct{}, len(validated))
	for _, record := range validated {
		logicalPage, err := locateVNextProducerPageID(reserve, record.PageID)
		if err != nil {
			return err
		}
		checksum, exists := written[logicalPage]
		if !exists || checksum != record.ContentCRC32C {
			return fmt.Errorf(
				"TRCRC006 CRC for memory logical page %d does not match producer bytes",
				logicalPage)
		}
		if _, duplicate := seen[logicalPage]; duplicate {
			return fmt.Errorf("TRCRC006 repeats memory logical page %d", logicalPage)
		}
		seen[logicalPage] = struct{}{}
	}
	return nil
}

func validateVNextProducerReserve(
	reserve vnextOwnerReserveResponse,
	directory *vnextLocalDAXDirectory,
) error {
	if directory == nil || len(directory.byUUID) == 0 {
		return errors.New("VNext producer local DAX directory is unavailable")
	}
	if err := validateVNextProducerOperationIdentity(reserve.Operation); err != nil {
		return err
	}
	if reserve.TotalPages == 0 || reserve.TotalPages > uint64(math.MaxInt64) {
		return errors.New("VNext producer reserve has an invalid total page count")
	}
	if len(reserve.Contents) == 0 || len(reserve.Extents) == 0 || len(reserve.Devices) == 0 {
		return errors.New("VNext producer reserve has incomplete placement")
	}

	objectIDs := make(map[uint64]struct{}, len(reserve.Contents))
	expectedLogical := uint64(0)
	publicationSlots := 0
	for index, content := range reserve.Contents {
		if _, ok := content.Kind.internal(); !ok || content.ObjectID == 0 ||
			content.PageCount == 0 || content.LogicalPageStart != expectedLogical {
			return fmt.Errorf("VNext producer reserve content %d is invalid", index)
		}
		if _, duplicate := objectIDs[content.ObjectID]; duplicate {
			return fmt.Errorf("VNext producer reserve repeats object ID %d", content.ObjectID)
		}
		objectIDs[content.ObjectID] = struct{}{}
		capacity, ok := vnextMul(content.PageCount, cxlcheckpoint.PageSize)
		if !ok || content.ByteLength > capacity {
			return fmt.Errorf("VNext producer content %d exceeds its capacity", content.ObjectID)
		}
		if content.Kind == vnextOwnerServiceContentMemory && content.ByteLength != capacity {
			return fmt.Errorf("VNext producer memory object %d is not page-complete", content.ObjectID)
		}
		if content.Kind == vnextOwnerServiceContentPublication {
			publicationSlots++
			if content.ByteLength != capacity ||
				content.PageCount > cxlcheckpoint.MaxPublicationSlotPages {
				return fmt.Errorf("VNext producer publication object %d has invalid capacity", content.ObjectID)
			}
		}
		expectedLogical, ok = vnextAdd(expectedLogical, content.PageCount)
		if !ok || expectedLogical > uint64(math.MaxInt64) {
			return errors.New("VNext producer content coverage overflows")
		}
	}
	if expectedLogical != reserve.TotalPages || publicationSlots != 1 {
		return errors.New("VNext producer content coverage or publication slot is invalid")
	}

	portableDevices := make(map[string]vnextOwnerPortableDevice, len(reserve.Devices))
	previousUUID := ""
	for index, portable := range reserve.Devices {
		if portable.DeviceUUID == "" || portable.DataPageCount == 0 ||
			portable.ContentRegionBase == 0 ||
			portable.ContentRegionBase%cxlcheckpoint.PageSize != 0 ||
			(index > 0 && previousUUID >= portable.DeviceUUID) {
			return fmt.Errorf("VNext producer portable device %d is invalid or unordered", index)
		}
		binding, exists := directory.byUUID[portable.DeviceUUID]
		if !exists || binding.OwnerID != reserve.Operation.OwnerID ||
			binding.OwnerEpoch != reserve.Operation.OwnerEpoch ||
			binding.DataPageCount != portable.DataPageCount ||
			binding.ContentRegionBase != portable.ContentRegionBase {
			return fmt.Errorf(
				"VNext producer local binding for device %q does not match reserve Owner/epoch/geometry",
				portable.DeviceUUID)
		}
		portableDevices[portable.DeviceUUID] = portable
		previousUUID = portable.DeviceUUID
	}

	expectedLogical = 0
	physical := make(map[string][]vnextOwnerPortableExtent)
	used := make(map[string]struct{})
	for index, extent := range reserve.Extents {
		if extent.PageCount == 0 || extent.LogicalPageStart != expectedLogical {
			return fmt.Errorf("VNext producer extent %d has a gap, overlap, or zero size", index)
		}
		portable, exists := portableDevices[extent.DeviceUUID]
		end, ok := vnextAdd(extent.StartDataPageIndex, extent.PageCount)
		if !exists || !ok || end > portable.DataPageCount {
			return fmt.Errorf("VNext producer extent %d exceeds device geometry", index)
		}
		expectedLogical, ok = vnextAdd(expectedLogical, extent.PageCount)
		if !ok {
			return errors.New("VNext producer extent coverage overflows")
		}
		physical[extent.DeviceUUID] = append(physical[extent.DeviceUUID], extent)
		used[extent.DeviceUUID] = struct{}{}
	}
	if expectedLogical != reserve.TotalPages || len(used) != len(portableDevices) {
		return errors.New("VNext producer extents do not exactly cover reserve devices/pages")
	}
	for deviceUUID, extents := range physical {
		sort.Slice(extents, func(i, j int) bool {
			return extents[i].StartDataPageIndex < extents[j].StartDataPageIndex
		})
		for index := 1; index < len(extents); index++ {
			previousEnd, _ := vnextAdd(
				extents[index-1].StartDataPageIndex, extents[index-1].PageCount)
			if previousEnd > extents[index].StartDataPageIndex {
				return fmt.Errorf("VNext producer extents overlap on device %q", deviceUUID)
			}
		}
	}
	return nil
}

func validateVNextProducerPublication(
	reserve vnextOwnerReserveResponse,
	publication cxlcheckpoint.Publication,
) error {
	if err := publication.Validate(); err != nil {
		return fmt.Errorf("validate VNext producer publication: %w", err)
	}
	if publication.CheckpointID != reserve.Operation.CheckpointID ||
		publication.Root.CheckpointID != reserve.Operation.CheckpointID ||
		publication.Allocation.OwnerID != reserve.Operation.OwnerID ||
		publication.Allocation.OwnerEpoch != reserve.Operation.OwnerEpoch ||
		publication.Allocation.AllocationRecordID != reserve.Operation.AllocationRecordID ||
		publication.Allocation.TotalPages != reserve.TotalPages {
		return errors.New("VNext producer publication does not match reserve identity")
	}
	if len(publication.ContentObjects) != len(reserve.Contents) ||
		len(publication.Allocation.Extents) != len(reserve.Extents) ||
		len(publication.Devices) != len(reserve.Devices) {
		return errors.New("VNext producer publication does not match reserve placement cardinality")
	}
	for index, content := range publication.ContentObjects {
		portable := reserve.Contents[index]
		kind, ok := vnextProducerPortableContentKind(content.Kind)
		if !ok || portable.Kind != kind || portable.ObjectID != content.ObjectID ||
			portable.ByteLength != content.ByteLength ||
			portable.LogicalPageStart != content.LogicalPageStart ||
			portable.PageCount != content.PageCount {
			return fmt.Errorf("VNext producer publication content %d differs from reserve", index)
		}
	}
	for index, extent := range publication.Allocation.Extents {
		portable := reserve.Extents[index]
		if portable.DeviceUUID != extent.DeviceUUID ||
			portable.StartDataPageIndex != extent.StartDataPageIndex ||
			portable.PageCount != extent.PageCount ||
			portable.LogicalPageStart != extent.LogicalPageStart {
			return fmt.Errorf("VNext producer publication extent %d differs from reserve", index)
		}
	}
	for index, device := range publication.Devices {
		portable := reserve.Devices[index]
		if device.DeviceUUID != portable.DeviceUUID ||
			device.OwnerID != reserve.Operation.OwnerID ||
			device.OwnerEpoch != reserve.Operation.OwnerEpoch ||
			device.DataPageCount != portable.DataPageCount {
			return fmt.Errorf("VNext producer publication device %d differs from reserve", index)
		}
	}
	return nil
}

func validateVNextProducerSources(
	publication cxlcheckpoint.Publication,
	sources []vnextProducerContentSource,
) (map[uint64]io.Reader, error) {
	provided := make(map[uint64]io.Reader, len(sources))
	for index, source := range sources {
		if source.ObjectID == 0 || source.Reader == nil ||
			vnextProducerInterfaceIsNil(source.Reader) {
			return nil, fmt.Errorf("VNext producer source %d is incomplete", index)
		}
		if _, duplicate := provided[source.ObjectID]; duplicate {
			return nil, fmt.Errorf("VNext producer repeats source object ID %d", source.ObjectID)
		}
		provided[source.ObjectID] = source.Reader
	}

	required := make(map[uint64]struct{})
	for _, content := range publication.ContentObjects {
		automatic := (content.Kind == cxlcheckpoint.ContentMMTemplate &&
			content.ObjectID == publication.MMTemplate.ContentObjectID) ||
			(content.Kind == cxlcheckpoint.ContentPageMap &&
				content.ObjectID == publication.PageMap.ContentObjectID)
		if content.Kind == cxlcheckpoint.ContentPublication {
			if _, attempted := provided[content.ObjectID]; attempted {
				return nil, fmt.Errorf(
					"producer must not supply or write publication object %d", content.ObjectID)
			}
			continue
		}
		if automatic {
			if _, attempted := provided[content.ObjectID]; attempted {
				return nil, fmt.Errorf(
					"producer must use canonical bytes for content object %d", content.ObjectID)
			}
			continue
		}
		required[content.ObjectID] = struct{}{}
		if _, exists := provided[content.ObjectID]; !exists {
			return nil, fmt.Errorf(
				"VNext producer content object %d has no exact source", content.ObjectID)
		}
	}
	if len(provided) != len(required) {
		for objectID := range provided {
			if _, expected := required[objectID]; !expected {
				return nil, fmt.Errorf("VNext producer source object %d is not reserved", objectID)
			}
		}
	}
	return provided, nil
}

func validateVNextProducerSealResponse(
	reserve vnextOwnerReserveResponse,
	publication cxlcheckpoint.Publication,
	storage cxlcheckpoint.PublicationStorage,
	response vnextOwnerSealResponse,
) error {
	root := response.Root
	want := publication.Root
	if root.RootID != want.RootID ||
		root.RootVersion != want.PublicationSequence ||
		root.MMTemplateID != want.MMTemplateID ||
		root.PageMapID != want.PageMapID ||
		root.PageMapVersion != want.PageMapVersion ||
		root.DeviceTableDigest != want.DeviceTableDigest ||
		root.ContractID != cxlcheckpoint.V6CompatibilityID ||
		root.Locator.PublicationByteLength != uint64(len(storage.ExactBytes)) ||
		root.Locator.PublicationSHA256 != storage.SHA256 ||
		len(root.Locator.PageRuns) != len(storage.PageRuns) {
		return errors.New("candidate root identity or publication locator differs from canonical publication")
	}
	for index, run := range root.Locator.PageRuns {
		wantRun := storage.PageRuns[index]
		if run.FirstPage != wantRun.FirstPage || run.PageCount != wantRun.PageCount ||
			run.FirstPage.OwnerID != reserve.Operation.OwnerID ||
			run.FirstPage.AllocationRecordID != reserve.Operation.AllocationRecordID {
			return fmt.Errorf("candidate root publication run %d differs from canonical placement", index)
		}
	}
	return nil
}

func validateVNextProducerOperationIdentity(identity vnextOwnerOperationIdentity) error {
	if identity.RequestID == "" || len(identity.RequestID) > vnextMaxIdentityBytes ||
		identity.CheckpointID == "" || len(identity.CheckpointID) > vnextMaxIdentityBytes ||
		identity.ProducerID == "" || len(identity.ProducerID) > vnextMaxIdentityBytes ||
		identity.OwnerID == "" || len(identity.OwnerID) > vnextMaxIdentityBytes ||
		identity.OwnerEpoch == 0 || identity.OwnerEpoch > uint64(math.MaxInt64) ||
		identity.AllocationRecordID == 0 || identity.AllocationRecordID > uint64(math.MaxInt64) {
		return errors.New("VNext producer operation identity is incomplete")
	}
	return nil
}

func locateVNextProducerLogicalPage(
	reserve vnextOwnerReserveResponse,
	logicalPage uint64,
) (vnextOwnerPortableExtent, uint64, error) {
	if logicalPage >= reserve.TotalPages {
		return vnextOwnerPortableExtent{}, 0, fmt.Errorf(
			"VNext producer logical page %d exceeds reserve", logicalPage)
	}
	for _, extent := range reserve.Extents {
		end := extent.LogicalPageStart + extent.PageCount
		if logicalPage < extent.LogicalPageStart || logicalPage >= end {
			continue
		}
		dataPageIndex := extent.StartDataPageIndex + (logicalPage - extent.LogicalPageStart)
		return extent, dataPageIndex, nil
	}
	return vnextOwnerPortableExtent{}, 0, fmt.Errorf(
		"VNext producer logical page %d is not placed", logicalPage)
}

func locateVNextProducerPageID(
	reserve vnextOwnerReserveResponse,
	pageID cxlcheckpoint.PageID,
) (uint64, error) {
	if pageID.OwnerID != reserve.Operation.OwnerID ||
		pageID.AllocationRecordID != reserve.Operation.AllocationRecordID {
		return 0, errors.New("TRCRC006 PageID does not belong to producer reserve")
	}
	for _, extent := range reserve.Extents {
		if extent.DeviceUUID != pageID.DeviceUUID {
			continue
		}
		end := extent.StartDataPageIndex + extent.PageCount
		if pageID.DataPageIndex < extent.StartDataPageIndex || pageID.DataPageIndex >= end {
			continue
		}
		return extent.LogicalPageStart +
			(pageID.DataPageIndex - extent.StartDataPageIndex), nil
	}
	return 0, errors.New("TRCRC006 PageID is outside producer reserve extents")
}

func vnextProducerPortableContentKind(
	kind cxlcheckpoint.ContentKind,
) (vnextOwnerServiceContentKind, bool) {
	switch kind {
	case cxlcheckpoint.ContentMemory:
		return vnextOwnerServiceContentMemory, true
	case cxlcheckpoint.ContentArtifact:
		return vnextOwnerServiceContentArtifact, true
	case cxlcheckpoint.ContentMMTemplate:
		return vnextOwnerServiceContentMMTemplate, true
	case cxlcheckpoint.ContentPageMap:
		return vnextOwnerServiceContentPageMap, true
	case cxlcheckpoint.ContentRestoreBlob:
		return vnextOwnerServiceContentRestoreBlob, true
	case cxlcheckpoint.ContentPublication:
		return vnextOwnerServiceContentPublication, true
	default:
		return 0, false
	}
}

func cloneVNextProducerSidecars(input map[uint32][]byte) map[uint32][]byte {
	cloned := make(map[uint32][]byte, len(input))
	for pagesImageID, data := range input {
		cloned[pagesImageID] = append([]byte(nil), data...)
	}
	return cloned
}

func cloneVNextProducerRoot(root vnextOwnerCheckpointRoot) vnextOwnerCheckpointRoot {
	cloned := root
	cloned.Locator.PageRuns = append(
		[]vnextOwnerPublicationPageRun(nil), root.Locator.PageRuns...)
	return cloned
}

func cloneVNextProducerReserve(
	reserve vnextOwnerReserveResponse,
) vnextOwnerReserveResponse {
	cloned := reserve
	cloned.Contents = append([]vnextOwnerPortableContentSegment(nil), reserve.Contents...)
	cloned.Extents = append([]vnextOwnerPortableExtent(nil), reserve.Extents...)
	cloned.Devices = append([]vnextOwnerPortableDevice(nil), reserve.Devices...)
	return cloned
}

func vnextProducerInterfaceIsNil(value interface{}) bool {
	if value == nil {
		return true
	}
	reflected := reflect.ValueOf(value)
	switch reflected.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map,
		reflect.Ptr, reflect.Slice:
		return reflected.IsNil()
	default:
		return false
	}
}

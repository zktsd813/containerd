package main

import (
	"bytes"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"math"
	"sort"
	"sync"
)

const (
	vnextMaxAllocationRecords = 1 << 20
	vnextMaxExtentsPerRecord  = 1 << 20
	vnextMaxContentsPerRecord = 1 << 20
)

var (
	errVNextNoSpace       = errors.New("VNext content space exhausted")
	errVNextMetadataFull  = errors.New("VNext allocator metadata slots exhausted")
	errVNextAuthority     = errors.New("VNext owner or writer authority mismatch")
	errVNextInvalidState  = errors.New("invalid VNext allocation state transition")
	errVNextAlreadyExists = errors.New("VNext allocation identity already exists")
)

type vnextAllocationState uint8

const (
	vnextAllocationReserved vnextAllocationState = iota + 1
	vnextAllocationCommitted
	vnextAllocationAbortPending
	vnextAllocationAborted
	vnextAllocationReclaimPending
	vnextAllocationReclaimed
)

func (s vnextAllocationState) valid() bool {
	return s >= vnextAllocationReserved && s <= vnextAllocationReclaimed
}

func (s vnextAllocationState) ownsPages() bool {
	return s == vnextAllocationReserved ||
		s == vnextAllocationCommitted ||
		s == vnextAllocationAbortPending ||
		s == vnextAllocationReclaimPending
}

type vnextContentRequest struct {
	Kind       vnextContentKind
	ObjectID   uint64
	ByteLength uint64
}

type vnextCheckpointAllocationRequest struct {
	RequestID    string
	CheckpointID string
	ProducerID   string
	OwnerID      string
	OwnerEpoch   uint64
	Contents     []vnextContentRequest
	MaxExtents   uint32
}

type vnextContentSegment struct {
	Kind             vnextContentKind
	ObjectID         uint64
	ByteLength       uint64
	LogicalPageStart uint64
	PageCount        uint64
}

type vnextPageExtent struct {
	StartDataPageIndex uint64
	PageCount          uint64
	LogicalPageStart   uint64
}

type vnextFreeRun struct {
	StartDataPageIndex uint64
	PageCount          uint64
}

func (e vnextPageExtent) end() (uint64, bool) {
	return vnextAdd(e.StartDataPageIndex, e.PageCount)
}

type vnextAllocationRecord struct {
	AllocationRecordID uint64
	RequestID          string
	CheckpointID       string
	ProducerID         string
	OwnerID            string
	OwnerEpoch         uint64
	State              vnextAllocationState
	OwnerTransaction   uint64
	TotalPages         uint64
	MaxExtents         uint32
	WriteToken         [16]byte
	Contents           []vnextContentSegment
	Extents            []vnextPageExtent
}

type vnextWriteGrant struct {
	DeviceUUID         string
	AllocationRecordID uint64
	RequestID          string
	CheckpointID       string
	ProducerID         string
	OwnerID            string
	OwnerEpoch         uint64
	WriteToken         [16]byte
	Contents           []vnextContentSegment
	Extents            []vnextPageExtent
}

type vnextOwnerAuthority struct {
	DeviceUUID string
	OwnerID    string
	OwnerEpoch uint64
}

type vnextReclaimRequest struct {
	Authority              vnextOwnerAuthority
	CheckpointID           string
	AllocationRecordID     uint64
	ExpectedCommitSequence uint64
}

type vnextPageWriteAuthorization struct {
	DeviceUUID            string
	DataPageIndex         uint64
	DescriptorOffset      uint64
	ContentOffset         uint64
	AllocationRecordID    uint64
	ContentObjectID       uint64
	ContentKind           vnextContentKind
	ExpectedPayloadLength uint32
	OwnerTransaction      uint64
}

type vnextCheckpointAllocator struct {
	mu sync.Mutex

	superblock             vnextDeviceSuperblock
	bitmap                 []uint64
	nextAllocationRecordID uint64
	nextOwnerTransaction   uint64
	snapshotSequence       uint64
	records                map[uint64]*vnextAllocationRecord
	requestIndex           map[string]uint64
	checkpointIndex        map[string]uint64
	tokenReader            io.Reader
}

func newVNextCheckpointAllocator(superblock vnextDeviceSuperblock) (*vnextCheckpointAllocator, error) {
	if err := superblock.validate(); err != nil {
		return nil, err
	}
	bitmapBytes, ok := vnextBitmapByteCount(superblock.Geometry.DataPageCount)
	if !ok ||
		bitmapBytes > superblock.Geometry.AllocatorSlotBytes ||
		bitmapBytes > vnextMaxEnvelopePayload {
		return nil, fmt.Errorf(
			"bitmap needs %d bytes but allocator slot/envelope capacity is %d/%d: %w",
			bitmapBytes,
			superblock.Geometry.AllocatorSlotBytes,
			vnextMaxEnvelopePayload,
			errVNextMetadataFull)
	}
	wordCount, ok := vnextBitmapWordCount(superblock.Geometry.DataPageCount)
	if !ok {
		return nil, fmt.Errorf("bitmap word count overflows host address space: %w", errVNextWrongFormat)
	}
	allocator := &vnextCheckpointAllocator{
		superblock:             superblock,
		bitmap:                 make([]uint64, wordCount),
		nextAllocationRecordID: 1,
		nextOwnerTransaction:   1,
		snapshotSequence:       0,
		records:                make(map[uint64]*vnextAllocationRecord),
		requestIndex:           make(map[string]uint64),
		checkpointIndex:        make(map[string]uint64),
		tokenReader:            rand.Reader,
	}
	if err := allocator.validateLocked(); err != nil {
		return nil, err
	}
	return allocator, nil
}

func (a *vnextCheckpointAllocator) reserve(request vnextCheckpointAllocationRequest) (vnextWriteGrant, error) {
	return a.reserveInternal(request, 0, nil, false)
}

// reserveAtIDWithExtents is the Owner-group primitive. It permits an Owner to
// use one global allocation identity across several device-local fragments.
// A device may skip IDs allocated on sibling devices, but may never allocate
// below its recovered high-water.
func (a *vnextCheckpointAllocator) reserveAtIDWithExtents(
	request vnextCheckpointAllocationRequest,
	allocationRecordID uint64,
	plannedExtents []vnextPageExtent,
) (vnextWriteGrant, error) {
	return a.reserveInternal(request, allocationRecordID, plannedExtents, true)
}

func (a *vnextCheckpointAllocator) reserveInternal(
	request vnextCheckpointAllocationRequest,
	requestedAllocationRecordID uint64,
	plannedExtents []vnextPageExtent,
	fixedIdentity bool,
) (vnextWriteGrant, error) {
	a.mu.Lock()
	defer a.mu.Unlock()

	segments, totalPages, err := a.validateRequestLocked(request)
	if err != nil {
		return vnextWriteGrant{}, err
	}
	if recordID, ok := a.requestIndex[request.RequestID]; ok {
		record := a.records[recordID]
		if record != nil && record.State == vnextAllocationReserved && vnextRequestMatchesRecord(request, segments, record) {
			if fixedIdentity && record.AllocationRecordID != requestedAllocationRecordID {
				return vnextWriteGrant{}, fmt.Errorf(
					"idempotent fragment request names allocation %d, not requested Owner ID %d: %w",
					record.AllocationRecordID, requestedAllocationRecordID, errVNextAlreadyExists)
			}
			if len(plannedExtents) > 0 && !vnextPageExtentsEqual(record.Extents, plannedExtents) {
				return vnextWriteGrant{}, fmt.Errorf(
					"idempotent fragment request has a different physical plan: %w",
					errVNextAlreadyExists)
			}
			return a.grantFromRecordLocked(record), nil
		}
		return vnextWriteGrant{}, fmt.Errorf(
			"request ID %q already names allocation %d: %w",
			request.RequestID, recordID, errVNextAlreadyExists)
	}
	if recordID, ok := a.checkpointIndex[request.CheckpointID]; ok {
		return vnextWriteGrant{}, fmt.Errorf(
			"checkpoint %q already names allocation %d: %w",
			request.CheckpointID, recordID, errVNextAlreadyExists)
	}
	allocationRecordID := a.nextAllocationRecordID
	if fixedIdentity {
		if requestedAllocationRecordID == 0 || requestedAllocationRecordID >= uint64(math.MaxInt64) {
			return vnextWriteGrant{}, errors.New("requested allocation record ID is outside the positive signed 64-bit ABI")
		}
		if requestedAllocationRecordID < a.nextAllocationRecordID {
			return vnextWriteGrant{}, fmt.Errorf(
				"requested allocation ID %d is below device high-water %d: %w",
				requestedAllocationRecordID, a.nextAllocationRecordID, errVNextAlreadyExists)
		}
		allocationRecordID = requestedAllocationRecordID
	}
	if allocationRecordID == 0 || allocationRecordID >= uint64(math.MaxInt64) {
		return vnextWriteGrant{}, errors.New("allocation record ID high-water reached the signed 64-bit ABI limit")
	}
	if a.nextOwnerTransaction == 0 || a.nextOwnerTransaction == math.MaxUint64 {
		return vnextWriteGrant{}, errors.New("owner transaction high-water is exhausted")
	}
	if len(a.records) >= vnextMaxAllocationRecords {
		return vnextWriteGrant{}, fmt.Errorf(
			"allocation record count reached %d: %w",
			vnextMaxAllocationRecords, errVNextMetadataFull)
	}

	extents := append([]vnextPageExtent(nil), plannedExtents...)
	if len(extents) == 0 {
		extents, err = a.planExtentsLocked(totalPages, request.MaxExtents)
		if err != nil {
			return vnextWriteGrant{}, err
		}
	} else if err := a.validatePlannedExtentsLocked(extents, totalPages, request.MaxExtents); err != nil {
		return vnextWriteGrant{}, err
	}
	var token [16]byte
	if _, err := io.ReadFull(a.tokenReader, token[:]); err != nil {
		return vnextWriteGrant{}, fmt.Errorf("generate write grant token: %w", err)
	}
	if vnextAllZero(token[:]) {
		return vnextWriteGrant{}, errors.New("write grant token source returned the reserved all-zero token")
	}
	record := &vnextAllocationRecord{
		AllocationRecordID: allocationRecordID,
		RequestID:          request.RequestID,
		CheckpointID:       request.CheckpointID,
		ProducerID:         request.ProducerID,
		OwnerID:            a.superblock.OwnerID,
		OwnerEpoch:         a.superblock.OwnerEpoch,
		State:              vnextAllocationReserved,
		OwnerTransaction:   a.nextOwnerTransaction,
		TotalPages:         totalPages,
		MaxExtents:         request.MaxExtents,
		WriteToken:         token,
		Contents:           segments,
		Extents:            extents,
	}
	if err := a.validateRecordLocked(record); err != nil {
		return vnextWriteGrant{}, err
	}

	candidateBitmap := append([]uint64(nil), a.bitmap...)
	for _, extent := range extents {
		for page := uint64(0); page < extent.PageCount; page++ {
			index := extent.StartDataPageIndex + page
			if vnextBitmapGet(candidateBitmap, index) {
				return vnextWriteGrant{}, fmt.Errorf("allocator plan overlaps page %d: %w", index, errVNextCorrupt)
			}
			vnextBitmapSet(candidateBitmap, index, true)
		}
	}
	nextAllocationID := allocationRecordID + 1
	nextTransaction := a.nextOwnerTransaction + 1
	size, err := a.snapshotEncodedSizeLocked(
		record, candidateBitmap, nextAllocationID, nextTransaction, a.snapshotSequence+1)
	if err != nil {
		return vnextWriteGrant{}, err
	}
	if uint64(size) > a.superblock.Geometry.AllocatorSlotBytes {
		return vnextWriteGrant{}, fmt.Errorf(
			"post-reservation allocator snapshot needs %d bytes, slot capacity is %d: %w",
			size, a.superblock.Geometry.AllocatorSlotBytes, errVNextMetadataFull)
	}

	// The bounded metadata check above happens before these bitmap bits become
	// reserved. A failed request therefore cannot consume payload capacity.
	a.bitmap = candidateBitmap
	a.records[record.AllocationRecordID] = record
	a.requestIndex[record.RequestID] = record.AllocationRecordID
	a.checkpointIndex[record.CheckpointID] = record.AllocationRecordID
	a.nextAllocationRecordID = nextAllocationID
	a.nextOwnerTransaction = nextTransaction
	return a.grantFromRecordLocked(record), nil
}

func (a *vnextCheckpointAllocator) commit(grant vnextWriteGrant) error {
	a.mu.Lock()
	defer a.mu.Unlock()

	record, err := a.validateGrantLocked(grant)
	if err != nil {
		return err
	}
	return a.commitRecordLocked(record)
}

func (a *vnextCheckpointAllocator) commitByOwner(
	allocationRecordID uint64,
	checkpointID string,
) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	record, ok := a.records[allocationRecordID]
	if !ok || record.CheckpointID != checkpointID {
		return fmt.Errorf("checkpoint %q allocation %d does not exist", checkpointID, allocationRecordID)
	}
	return a.commitRecordLocked(record)
}

func (a *vnextCheckpointAllocator) commitRecordLocked(record *vnextAllocationRecord) error {
	if record.State != vnextAllocationReserved {
		return fmt.Errorf(
			"allocation %d is in state %d, expected RESERVED: %w",
			record.AllocationRecordID, record.State, errVNextInvalidState)
	}
	transaction, err := a.takeOwnerTransactionLocked()
	if err != nil {
		return err
	}
	record.State = vnextAllocationCommitted
	record.OwnerTransaction = transaction
	record.WriteToken = [16]byte{}
	return nil
}

func (a *vnextCheckpointAllocator) abort(grant vnextWriteGrant) error {
	if err := a.beginAbort(grant); err != nil {
		return err
	}
	return a.finishAbort(grant.AllocationRecordID)
}

func (a *vnextCheckpointAllocator) beginAbort(grant vnextWriteGrant) error {
	a.mu.Lock()
	defer a.mu.Unlock()

	record, err := a.validateGrantLocked(grant)
	if err != nil {
		return err
	}
	return a.beginAbortRecordLocked(record)
}

func (a *vnextCheckpointAllocator) beginAbortByOwner(
	allocationRecordID uint64,
	checkpointID string,
) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	record, ok := a.records[allocationRecordID]
	if !ok || record.CheckpointID != checkpointID {
		return fmt.Errorf("checkpoint %q allocation %d does not exist", checkpointID, allocationRecordID)
	}
	return a.beginAbortRecordLocked(record)
}

func (a *vnextCheckpointAllocator) beginAbortRecordLocked(record *vnextAllocationRecord) error {
	if record.State != vnextAllocationReserved {
		return fmt.Errorf(
			"allocation %d is in state %d, expected RESERVED: %w",
			record.AllocationRecordID, record.State, errVNextInvalidState)
	}
	transaction, err := a.takeOwnerTransactionLocked()
	if err != nil {
		return err
	}
	record.State = vnextAllocationAbortPending
	record.OwnerTransaction = transaction
	record.WriteToken = [16]byte{}
	return nil
}

func (a *vnextCheckpointAllocator) finishAbort(allocationRecordID uint64) error {
	a.mu.Lock()
	defer a.mu.Unlock()

	record, ok := a.records[allocationRecordID]
	if !ok {
		return fmt.Errorf("allocation record %d does not exist", allocationRecordID)
	}
	if record.State != vnextAllocationAbortPending {
		return fmt.Errorf(
			"allocation %d is in state %d, expected ABORT_PENDING: %w",
			record.AllocationRecordID, record.State, errVNextInvalidState)
	}
	transaction, err := a.takeOwnerTransactionLocked()
	if err != nil {
		return err
	}
	if err := a.clearRecordPagesLocked(record); err != nil {
		return err
	}
	record.State = vnextAllocationAborted
	record.OwnerTransaction = transaction
	return nil
}

// reclaimCheckpoint is intentionally checkpoint-scoped. There is no
// allocator API that returns an individual page. Dedup/reference-aware page
// reclaim will be layered above this conservative primitive.
func (a *vnextCheckpointAllocator) reclaimCheckpoint(request vnextReclaimRequest) error {
	if err := a.beginReclaim(request); err != nil {
		return err
	}
	return a.finishReclaim(request.AllocationRecordID)
}

func (a *vnextCheckpointAllocator) beginReclaim(request vnextReclaimRequest) error {
	a.mu.Lock()
	defer a.mu.Unlock()

	if err := a.validateAuthorityLocked(request.Authority); err != nil {
		return err
	}
	record, ok := a.records[request.AllocationRecordID]
	if !ok || record.CheckpointID != request.CheckpointID {
		return fmt.Errorf(
			"checkpoint %q allocation %d does not exist",
			request.CheckpointID, request.AllocationRecordID)
	}
	if record.State != vnextAllocationCommitted {
		return fmt.Errorf(
			"allocation %d is in state %d, expected COMMITTED: %w",
			record.AllocationRecordID, record.State, errVNextInvalidState)
	}
	if request.ExpectedCommitSequence == 0 ||
		request.ExpectedCommitSequence != record.OwnerTransaction {
		return fmt.Errorf(
			"commit sequence is %d, expected %d: %w",
			request.ExpectedCommitSequence, record.OwnerTransaction, errVNextAuthority)
	}
	transaction, err := a.takeOwnerTransactionLocked()
	if err != nil {
		return err
	}
	record.State = vnextAllocationReclaimPending
	record.OwnerTransaction = transaction
	record.WriteToken = [16]byte{}
	return nil
}

func (a *vnextCheckpointAllocator) finishReclaim(allocationRecordID uint64) error {
	a.mu.Lock()
	defer a.mu.Unlock()

	record, ok := a.records[allocationRecordID]
	if !ok {
		return fmt.Errorf("allocation record %d does not exist", allocationRecordID)
	}
	if record.State != vnextAllocationReclaimPending {
		return fmt.Errorf(
			"allocation %d is in state %d, expected RECLAIM_PENDING: %w",
			record.AllocationRecordID, record.State, errVNextInvalidState)
	}
	transaction, err := a.takeOwnerTransactionLocked()
	if err != nil {
		return err
	}
	if err := a.clearRecordPagesLocked(record); err != nil {
		return err
	}
	record.State = vnextAllocationReclaimed
	record.OwnerTransaction = transaction
	return nil
}

func (a *vnextCheckpointAllocator) authorizePageWrite(
	grant vnextWriteGrant,
	logicalPage uint64,
) (vnextPageWriteAuthorization, error) {
	a.mu.Lock()
	defer a.mu.Unlock()

	record, err := a.validateGrantLocked(grant)
	if err != nil {
		return vnextPageWriteAuthorization{}, err
	}
	if record.State != vnextAllocationReserved {
		return vnextPageWriteAuthorization{}, fmt.Errorf(
			"allocation %d no longer accepts producer writes: %w",
			record.AllocationRecordID, errVNextInvalidState)
	}
	if logicalPage >= record.TotalPages {
		return vnextPageWriteAuthorization{}, fmt.Errorf(
			"logical page %d is outside allocation size %d",
			logicalPage, record.TotalPages)
	}
	dataPage, err := vnextRecordPhysicalPage(record, logicalPage)
	if err != nil {
		return vnextPageWriteAuthorization{}, err
	}
	segment, err := vnextRecordContentSegment(record, logicalPage)
	if err != nil {
		return vnextPageWriteAuthorization{}, err
	}
	pageWithinObject := logicalPage - segment.LogicalPageStart
	consumed, ok := vnextMul(pageWithinObject, vnextContentPageSize)
	if !ok || consumed >= segment.ByteLength {
		return vnextPageWriteAuthorization{}, fmt.Errorf("logical content offset overflow: %w", errVNextCorrupt)
	}
	remaining := segment.ByteLength - consumed
	payloadLength := vnextContentPageSize
	if remaining < payloadLength {
		payloadLength = remaining
	}
	descriptorOffset, err := a.superblock.Geometry.descriptorOffset(dataPage)
	if err != nil {
		return vnextPageWriteAuthorization{}, err
	}
	contentOffset, err := a.superblock.Geometry.contentOffset(dataPage)
	if err != nil {
		return vnextPageWriteAuthorization{}, err
	}
	return vnextPageWriteAuthorization{
		DeviceUUID:            a.superblock.DeviceUUID,
		DataPageIndex:         dataPage,
		DescriptorOffset:      descriptorOffset,
		ContentOffset:         contentOffset,
		AllocationRecordID:    record.AllocationRecordID,
		ContentObjectID:       segment.ObjectID,
		ContentKind:           segment.Kind,
		ExpectedPayloadLength: uint32(payloadLength),
		OwnerTransaction:      record.OwnerTransaction,
	}, nil
}

func (a *vnextCheckpointAllocator) lookup(checkpointID string) (vnextAllocationRecord, bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	recordID, ok := a.checkpointIndex[checkpointID]
	if !ok {
		return vnextAllocationRecord{}, false
	}
	record, ok := a.records[recordID]
	if !ok {
		return vnextAllocationRecord{}, false
	}
	return cloneVNextAllocationRecord(record), true
}

func (a *vnextCheckpointAllocator) freePages() uint64 {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.freePagesLocked()
}

func (a *vnextCheckpointAllocator) freeRuns() []vnextFreeRun {
	a.mu.Lock()
	defer a.mu.Unlock()
	runs := make([]vnextFreeRun, 0)
	for index := uint64(0); index < a.superblock.Geometry.DataPageCount; {
		if vnextBitmapGet(a.bitmap, index) {
			index++
			continue
		}
		start := index
		for index < a.superblock.Geometry.DataPageCount && !vnextBitmapGet(a.bitmap, index) {
			index++
		}
		runs = append(runs, vnextFreeRun{
			StartDataPageIndex: start,
			PageCount:          index - start,
		})
	}
	return runs
}

func (a *vnextCheckpointAllocator) allocationIDHighWater() uint64 {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.nextAllocationRecordID
}

func (a *vnextCheckpointAllocator) validate() error {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.validateLocked()
}

func (a *vnextCheckpointAllocator) validateRequestLocked(
	request vnextCheckpointAllocationRequest,
) ([]vnextContentSegment, uint64, error) {
	if request.RequestID == "" || len(request.RequestID) > vnextMaxIdentityBytes {
		return nil, 0, errors.New("allocation request ID is empty or too long")
	}
	if request.CheckpointID == "" || len(request.CheckpointID) > vnextMaxIdentityBytes {
		return nil, 0, errors.New("checkpoint ID is empty or too long")
	}
	if request.ProducerID == "" || len(request.ProducerID) > vnextMaxIdentityBytes {
		return nil, 0, errors.New("producer ID is empty or too long")
	}
	if request.OwnerID != a.superblock.OwnerID ||
		request.OwnerEpoch != a.superblock.OwnerEpoch {
		return nil, 0, fmt.Errorf(
			"request owner %q/%d does not match device owner %q/%d: %w",
			request.OwnerID, request.OwnerEpoch,
			a.superblock.OwnerID, a.superblock.OwnerEpoch,
			errVNextAuthority)
	}
	if request.MaxExtents == 0 || request.MaxExtents > vnextMaxExtentsPerRecord {
		return nil, 0, fmt.Errorf(
			"max extents %d is outside 1..%d",
			request.MaxExtents, vnextMaxExtentsPerRecord)
	}
	if len(request.Contents) == 0 || len(request.Contents) > vnextMaxContentsPerRecord {
		return nil, 0, fmt.Errorf(
			"content count %d is outside 1..%d",
			len(request.Contents), vnextMaxContentsPerRecord)
	}
	segments := make([]vnextContentSegment, 0, len(request.Contents))
	seenObjects := make(map[uint64]struct{}, len(request.Contents))
	var totalPages uint64
	for _, content := range request.Contents {
		if !content.Kind.valid() {
			return nil, 0, fmt.Errorf("content object %d has invalid kind %d", content.ObjectID, content.Kind)
		}
		if content.ObjectID == 0 {
			return nil, 0, errors.New("content object ID must be non-zero")
		}
		if _, exists := seenObjects[content.ObjectID]; exists {
			return nil, 0, fmt.Errorf("content object ID %d is duplicated", content.ObjectID)
		}
		seenObjects[content.ObjectID] = struct{}{}
		if content.ByteLength == 0 {
			return nil, 0, fmt.Errorf("content object %d has zero bytes", content.ObjectID)
		}
		if content.Kind == vnextContentMemory && content.ByteLength%vnextContentPageSize != 0 {
			return nil, 0, fmt.Errorf(
				"memory object %d length %d is not a whole 4 KiB page",
				content.ObjectID, content.ByteLength)
		}
		rounded, ok := vnextAdd(content.ByteLength, vnextContentPageSize-1)
		if !ok {
			return nil, 0, fmt.Errorf("content object %d byte length overflows", content.ObjectID)
		}
		pageCount := rounded / vnextContentPageSize
		nextTotal, ok := vnextAdd(totalPages, pageCount)
		if !ok {
			return nil, 0, errors.New("allocation page count overflows")
		}
		segments = append(segments, vnextContentSegment{
			Kind:             content.Kind,
			ObjectID:         content.ObjectID,
			ByteLength:       content.ByteLength,
			LogicalPageStart: totalPages,
			PageCount:        pageCount,
		})
		totalPages = nextTotal
	}
	if totalPages == 0 || totalPages > a.superblock.Geometry.DataPageCount {
		return nil, 0, fmt.Errorf(
			"allocation needs %d pages, device capacity is %d: %w",
			totalPages, a.superblock.Geometry.DataPageCount, errVNextNoSpace)
	}
	return segments, totalPages, nil
}

func (a *vnextCheckpointAllocator) planExtentsLocked(
	pageCount uint64,
	maxExtents uint32,
) ([]vnextPageExtent, error) {
	if pageCount > a.freePagesLocked() {
		return nil, fmt.Errorf(
			"allocation needs %d pages, only %d are free: %w",
			pageCount, a.freePagesLocked(), errVNextNoSpace)
	}
	extents := make([]vnextPageExtent, 0, maxExtents)
	var allocated uint64
	for index := uint64(0); index < a.superblock.Geometry.DataPageCount && allocated < pageCount; {
		if vnextBitmapGet(a.bitmap, index) {
			index++
			continue
		}
		runStart := index
		for index < a.superblock.Geometry.DataPageCount && !vnextBitmapGet(a.bitmap, index) {
			index++
		}
		runLength := index - runStart
		remaining := pageCount - allocated
		if runLength > remaining {
			runLength = remaining
		}
		if len(extents) == int(maxExtents) {
			return nil, fmt.Errorf(
				"allocation needs more than %d extents despite sufficient free pages: %w",
				maxExtents, errVNextNoSpace)
		}
		extents = append(extents, vnextPageExtent{
			StartDataPageIndex: runStart,
			PageCount:          runLength,
			LogicalPageStart:   allocated,
		})
		allocated += runLength
	}
	if allocated != pageCount {
		return nil, fmt.Errorf(
			"allocator planned %d of %d pages: %w",
			allocated, pageCount, errVNextNoSpace)
	}
	return extents, nil
}

func (a *vnextCheckpointAllocator) validatePlannedExtentsLocked(
	extents []vnextPageExtent,
	totalPages uint64,
	maxExtents uint32,
) error {
	if len(extents) == 0 || len(extents) > int(maxExtents) {
		return fmt.Errorf("planned extent count %d exceeds budget %d", len(extents), maxExtents)
	}
	var logical uint64
	var previousEnd uint64
	for index, extent := range extents {
		if extent.PageCount == 0 || extent.LogicalPageStart != logical {
			return fmt.Errorf("planned extent %d has invalid logical coverage", index)
		}
		end, ok := extent.end()
		if !ok || end > a.superblock.Geometry.DataPageCount {
			return fmt.Errorf("planned extent %d exceeds device capacity", index)
		}
		if index > 0 && extent.StartDataPageIndex <= previousEnd {
			return fmt.Errorf("planned extents overlap, are unordered, or are not coalesced")
		}
		for page := extent.StartDataPageIndex; page < end; page++ {
			if vnextBitmapGet(a.bitmap, page) {
				return fmt.Errorf("planned extent page %d is allocated: %w", page, errVNextNoSpace)
			}
		}
		previousEnd = end
		logical, ok = vnextAdd(logical, extent.PageCount)
		if !ok {
			return errors.New("planned extent page count overflows")
		}
	}
	if logical != totalPages {
		return fmt.Errorf("planned extents cover %d pages, request needs %d", logical, totalPages)
	}
	return nil
}

func (a *vnextCheckpointAllocator) validateAuthorityLocked(authority vnextOwnerAuthority) error {
	if authority.DeviceUUID != a.superblock.DeviceUUID ||
		authority.OwnerID != a.superblock.OwnerID ||
		authority.OwnerEpoch != a.superblock.OwnerEpoch {
		return fmt.Errorf(
			"authority %q/%q/%d does not match device %q owner %q/%d: %w",
			authority.DeviceUUID, authority.OwnerID, authority.OwnerEpoch,
			a.superblock.DeviceUUID, a.superblock.OwnerID, a.superblock.OwnerEpoch,
			errVNextAuthority)
	}
	return nil
}

func (a *vnextCheckpointAllocator) validateGrantLocked(
	grant vnextWriteGrant,
) (*vnextAllocationRecord, error) {
	if err := a.validateAuthorityLocked(vnextOwnerAuthority{
		DeviceUUID: grant.DeviceUUID,
		OwnerID:    grant.OwnerID,
		OwnerEpoch: grant.OwnerEpoch,
	}); err != nil {
		return nil, err
	}
	record, ok := a.records[grant.AllocationRecordID]
	if !ok {
		return nil, fmt.Errorf("allocation record %d does not exist", grant.AllocationRecordID)
	}
	if grant.RequestID != record.RequestID ||
		grant.CheckpointID != record.CheckpointID ||
		grant.ProducerID != record.ProducerID ||
		grant.WriteToken != record.WriteToken ||
		vnextAllZero(grant.WriteToken[:]) {
		return nil, fmt.Errorf(
			"grant does not name the active producer for allocation %d: %w",
			grant.AllocationRecordID, errVNextAuthority)
	}
	return record, nil
}

func (a *vnextCheckpointAllocator) grantFromRecordLocked(record *vnextAllocationRecord) vnextWriteGrant {
	return vnextWriteGrant{
		DeviceUUID:         a.superblock.DeviceUUID,
		AllocationRecordID: record.AllocationRecordID,
		RequestID:          record.RequestID,
		CheckpointID:       record.CheckpointID,
		ProducerID:         record.ProducerID,
		OwnerID:            record.OwnerID,
		OwnerEpoch:         record.OwnerEpoch,
		WriteToken:         record.WriteToken,
		Contents:           append([]vnextContentSegment(nil), record.Contents...),
		Extents:            append([]vnextPageExtent(nil), record.Extents...),
	}
}

func (a *vnextCheckpointAllocator) takeOwnerTransactionLocked() (uint64, error) {
	if a.nextOwnerTransaction == 0 || a.nextOwnerTransaction == math.MaxUint64 {
		return 0, errors.New("owner transaction high-water is exhausted")
	}
	transaction := a.nextOwnerTransaction
	a.nextOwnerTransaction++
	return transaction, nil
}

func (a *vnextCheckpointAllocator) clearRecordPagesLocked(record *vnextAllocationRecord) error {
	for _, extent := range record.Extents {
		for page := uint64(0); page < extent.PageCount; page++ {
			index := extent.StartDataPageIndex + page
			if !vnextBitmapGet(a.bitmap, index) {
				return fmt.Errorf(
					"allocation %d page %d is already free: %w",
					record.AllocationRecordID, index, errVNextCorrupt)
			}
		}
	}
	for _, extent := range record.Extents {
		for page := uint64(0); page < extent.PageCount; page++ {
			vnextBitmapSet(a.bitmap, extent.StartDataPageIndex+page, false)
		}
	}
	return nil
}

func (a *vnextCheckpointAllocator) freePagesLocked() uint64 {
	var used uint64
	for index := uint64(0); index < a.superblock.Geometry.DataPageCount; index++ {
		if vnextBitmapGet(a.bitmap, index) {
			used++
		}
	}
	return a.superblock.Geometry.DataPageCount - used
}

func (a *vnextCheckpointAllocator) validateRecordLocked(record *vnextAllocationRecord) error {
	if record == nil {
		return fmt.Errorf("nil allocation record: %w", errVNextCorrupt)
	}
	if record.AllocationRecordID == 0 ||
		record.AllocationRecordID > uint64(math.MaxInt64) ||
		record.RequestID == "" ||
		record.CheckpointID == "" ||
		record.ProducerID == "" ||
		record.OwnerID != a.superblock.OwnerID ||
		record.OwnerEpoch != a.superblock.OwnerEpoch ||
		record.OwnerTransaction == 0 ||
		record.TotalPages == 0 ||
		!record.State.valid() {
		return fmt.Errorf("allocation record %d has invalid identity or state: %w", record.AllocationRecordID, errVNextCorrupt)
	}
	if len(record.RequestID) > vnextMaxIdentityBytes ||
		len(record.CheckpointID) > vnextMaxIdentityBytes ||
		len(record.ProducerID) > vnextMaxIdentityBytes ||
		len(record.OwnerID) > vnextMaxIdentityBytes {
		return fmt.Errorf("allocation record %d has an overlong identity: %w", record.AllocationRecordID, errVNextCorrupt)
	}
	if record.MaxExtents == 0 ||
		record.MaxExtents > vnextMaxExtentsPerRecord ||
		len(record.Extents) == 0 ||
		len(record.Extents) > int(record.MaxExtents) {
		return fmt.Errorf("allocation record %d has invalid extent bounds: %w", record.AllocationRecordID, errVNextCorrupt)
	}
	if len(record.Contents) == 0 || len(record.Contents) > vnextMaxContentsPerRecord {
		return fmt.Errorf("allocation record %d has invalid content count: %w", record.AllocationRecordID, errVNextCorrupt)
	}
	if record.State == vnextAllocationReserved && vnextAllZero(record.WriteToken[:]) {
		return fmt.Errorf("reserved allocation %d has no writer token: %w", record.AllocationRecordID, errVNextCorrupt)
	}
	if (record.State == vnextAllocationCommitted ||
		record.State == vnextAllocationAbortPending ||
		record.State == vnextAllocationAborted ||
		record.State == vnextAllocationReclaimPending ||
		record.State == vnextAllocationReclaimed) &&
		!vnextAllZero(record.WriteToken[:]) {
		return fmt.Errorf("terminal allocation %d retains writer authority: %w", record.AllocationRecordID, errVNextCorrupt)
	}

	var logical uint64
	for _, segment := range record.Contents {
		if !segment.Kind.valid() ||
			segment.ObjectID == 0 ||
			segment.ByteLength == 0 ||
			segment.PageCount == 0 ||
			segment.LogicalPageStart != logical {
			return fmt.Errorf("allocation %d has invalid content segment: %w", record.AllocationRecordID, errVNextCorrupt)
		}
		rounded, ok := vnextAdd(segment.ByteLength, vnextContentPageSize-1)
		if !ok || rounded/vnextContentPageSize != segment.PageCount {
			return fmt.Errorf("allocation %d content page count mismatch: %w", record.AllocationRecordID, errVNextCorrupt)
		}
		logical, ok = vnextAdd(logical, segment.PageCount)
		if !ok {
			return fmt.Errorf("allocation %d logical content overflow: %w", record.AllocationRecordID, errVNextCorrupt)
		}
	}
	if logical != record.TotalPages {
		return fmt.Errorf("allocation %d content covers %d of %d pages: %w",
			record.AllocationRecordID, logical, record.TotalPages, errVNextCorrupt)
	}

	logical = 0
	var previousEnd uint64
	for index, extent := range record.Extents {
		if extent.PageCount == 0 || extent.LogicalPageStart != logical {
			return fmt.Errorf("allocation %d has invalid extent logical coverage: %w", record.AllocationRecordID, errVNextCorrupt)
		}
		end, ok := extent.end()
		if !ok || end > a.superblock.Geometry.DataPageCount {
			return fmt.Errorf("allocation %d extent exceeds device: %w", record.AllocationRecordID, errVNextCorrupt)
		}
		// Adjacent extents are also rejected: the canonical encoder must
		// coalesce them into one run. This keeps extent count and metadata
		// access deterministic.
		if index > 0 && extent.StartDataPageIndex <= previousEnd {
			return fmt.Errorf("allocation %d extents are not ordered disjoint runs: %w", record.AllocationRecordID, errVNextCorrupt)
		}
		previousEnd = end
		logical, ok = vnextAdd(logical, extent.PageCount)
		if !ok {
			return fmt.Errorf("allocation %d extent page count overflow: %w", record.AllocationRecordID, errVNextCorrupt)
		}
	}
	if logical != record.TotalPages {
		return fmt.Errorf("allocation %d extents cover %d of %d pages: %w",
			record.AllocationRecordID, logical, record.TotalPages, errVNextCorrupt)
	}
	return nil
}

func (a *vnextCheckpointAllocator) validateLocked() error {
	if err := a.superblock.validate(); err != nil {
		return err
	}
	expectedWords, ok := vnextBitmapWordCount(a.superblock.Geometry.DataPageCount)
	if !ok || len(a.bitmap) != expectedWords {
		return fmt.Errorf("bitmap length does not match device capacity: %w", errVNextCorrupt)
	}
	if len(a.records) > vnextMaxAllocationRecords {
		return fmt.Errorf("allocator has too many records: %w", errVNextCorrupt)
	}
	expectedBitmap := make([]uint64, len(a.bitmap))
	requests := make(map[string]uint64, len(a.records))
	checkpoints := make(map[string]uint64, len(a.records))
	var maxRecordID uint64
	var maxTransaction uint64
	for recordID, record := range a.records {
		if record == nil || recordID != record.AllocationRecordID {
			return fmt.Errorf("allocation record map key mismatch: %w", errVNextCorrupt)
		}
		if err := a.validateRecordLocked(record); err != nil {
			return err
		}
		if _, exists := requests[record.RequestID]; exists {
			return fmt.Errorf("duplicate allocation request ID %q: %w", record.RequestID, errVNextCorrupt)
		}
		if _, exists := checkpoints[record.CheckpointID]; exists {
			return fmt.Errorf("duplicate checkpoint ID %q: %w", record.CheckpointID, errVNextCorrupt)
		}
		requests[record.RequestID] = recordID
		checkpoints[record.CheckpointID] = recordID
		if recordID > maxRecordID {
			maxRecordID = recordID
		}
		if record.OwnerTransaction > maxTransaction {
			maxTransaction = record.OwnerTransaction
		}
		if !record.State.ownsPages() {
			continue
		}
		for _, extent := range record.Extents {
			for page := uint64(0); page < extent.PageCount; page++ {
				index := extent.StartDataPageIndex + page
				if vnextBitmapGet(expectedBitmap, index) {
					return fmt.Errorf("active allocation overlap at page %d: %w", index, errVNextCorrupt)
				}
				vnextBitmapSet(expectedBitmap, index, true)
			}
		}
	}
	if !vnextBitmapEqual(a.bitmap, expectedBitmap, a.superblock.Geometry.DataPageCount) {
		return fmt.Errorf("bitmap does not match active allocation records: %w", errVNextCorrupt)
	}
	if len(a.requestIndex) != len(requests) || len(a.checkpointIndex) != len(checkpoints) {
		return fmt.Errorf("allocator identity indexes have wrong size: %w", errVNextCorrupt)
	}
	for identity, recordID := range requests {
		if a.requestIndex[identity] != recordID {
			return fmt.Errorf("request index mismatch for %q: %w", identity, errVNextCorrupt)
		}
	}
	for identity, recordID := range checkpoints {
		if a.checkpointIndex[identity] != recordID {
			return fmt.Errorf("checkpoint index mismatch for %q: %w", identity, errVNextCorrupt)
		}
	}
	if a.nextAllocationRecordID == 0 ||
		a.nextAllocationRecordID > uint64(math.MaxInt64) ||
		a.nextAllocationRecordID <= maxRecordID {
		return fmt.Errorf("allocation ID high-water %d does not exceed %d: %w",
			a.nextAllocationRecordID, maxRecordID, errVNextCorrupt)
	}
	if a.nextOwnerTransaction == 0 || a.nextOwnerTransaction <= maxTransaction {
		return fmt.Errorf("transaction high-water %d does not exceed %d: %w",
			a.nextOwnerTransaction, maxTransaction, errVNextCorrupt)
	}
	if a.snapshotSequence == math.MaxUint64 {
		return fmt.Errorf("snapshot sequence is exhausted: %w", errVNextCorrupt)
	}
	return nil
}

func vnextRecordPhysicalPage(record *vnextAllocationRecord, logicalPage uint64) (uint64, error) {
	for _, extent := range record.Extents {
		end, ok := vnextAdd(extent.LogicalPageStart, extent.PageCount)
		if !ok {
			return 0, fmt.Errorf("extent logical range overflow: %w", errVNextCorrupt)
		}
		if logicalPage >= extent.LogicalPageStart && logicalPage < end {
			delta := logicalPage - extent.LogicalPageStart
			physical, ok := vnextAdd(extent.StartDataPageIndex, delta)
			if !ok {
				return 0, fmt.Errorf("extent physical range overflow: %w", errVNextCorrupt)
			}
			return physical, nil
		}
	}
	return 0, fmt.Errorf("logical page %d is not covered by any extent: %w", logicalPage, errVNextCorrupt)
}

func vnextRecordContentSegment(
	record *vnextAllocationRecord,
	logicalPage uint64,
) (vnextContentSegment, error) {
	for _, segment := range record.Contents {
		end, ok := vnextAdd(segment.LogicalPageStart, segment.PageCount)
		if !ok {
			return vnextContentSegment{}, fmt.Errorf("content logical range overflow: %w", errVNextCorrupt)
		}
		if logicalPage >= segment.LogicalPageStart && logicalPage < end {
			return segment, nil
		}
	}
	return vnextContentSegment{}, fmt.Errorf(
		"logical page %d is not covered by any content object: %w",
		logicalPage, errVNextCorrupt)
}

func vnextRequestMatchesRecord(
	request vnextCheckpointAllocationRequest,
	segments []vnextContentSegment,
	record *vnextAllocationRecord,
) bool {
	if request.RequestID != record.RequestID ||
		request.CheckpointID != record.CheckpointID ||
		request.ProducerID != record.ProducerID ||
		request.OwnerID != record.OwnerID ||
		request.OwnerEpoch != record.OwnerEpoch ||
		request.MaxExtents != record.MaxExtents ||
		len(segments) != len(record.Contents) {
		return false
	}
	for index := range segments {
		if segments[index] != record.Contents[index] {
			return false
		}
	}
	return true
}

func cloneVNextAllocationRecord(record *vnextAllocationRecord) vnextAllocationRecord {
	cloned := *record
	cloned.Contents = append([]vnextContentSegment(nil), record.Contents...)
	cloned.Extents = append([]vnextPageExtent(nil), record.Extents...)
	return cloned
}

func vnextPageExtentsEqual(left, right []vnextPageExtent) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func vnextBitmapWordCount(pageCount uint64) (int, bool) {
	rounded, ok := vnextAdd(pageCount, 63)
	if !ok {
		return 0, false
	}
	words := rounded / 64
	if words > uint64(int(^uint(0)>>1)) {
		return 0, false
	}
	return int(words), true
}

func vnextBitmapGet(bitmap []uint64, index uint64) bool {
	return bitmap[index/64]&(uint64(1)<<(index%64)) != 0
}

func vnextBitmapSet(bitmap []uint64, index uint64, allocated bool) {
	mask := uint64(1) << (index % 64)
	if allocated {
		bitmap[index/64] |= mask
	} else {
		bitmap[index/64] &^= mask
	}
}

func vnextBitmapEqual(left, right []uint64, pageCount uint64) bool {
	if len(left) != len(right) {
		return false
	}
	for index := uint64(0); index < pageCount; index++ {
		if vnextBitmapGet(left, index) != vnextBitmapGet(right, index) {
			return false
		}
	}
	if pageCount%64 != 0 && len(left) > 0 {
		mask := ^uint64(0) << (pageCount % 64)
		if left[len(left)-1]&mask != 0 || right[len(right)-1]&mask != 0 {
			return false
		}
	}
	return true
}

func (a *vnextCheckpointAllocator) snapshotEncodedSizeLocked(
	additionalRecord *vnextAllocationRecord,
	bitmap []uint64,
	nextAllocationRecordID uint64,
	nextOwnerTransaction uint64,
	snapshotSequence uint64,
) (int, error) {
	data, err := a.marshalSnapshotLocked(
		additionalRecord,
		bitmap,
		nextAllocationRecordID,
		nextOwnerTransaction,
		snapshotSequence)
	if err != nil {
		return 0, err
	}
	return len(data), nil
}

func (a *vnextCheckpointAllocator) sortedRecordsLocked(
	additionalRecord *vnextAllocationRecord,
) []*vnextAllocationRecord {
	records := make([]*vnextAllocationRecord, 0, len(a.records)+1)
	for _, record := range a.records {
		records = append(records, record)
	}
	if additionalRecord != nil {
		records = append(records, additionalRecord)
	}
	sort.Slice(records, func(i, j int) bool {
		return records[i].AllocationRecordID < records[j].AllocationRecordID
	})
	return records
}

func vnextWriteToken(buffer *bytes.Buffer, token [16]byte) {
	buffer.Write(token[:])
}

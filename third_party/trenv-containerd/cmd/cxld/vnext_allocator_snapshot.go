package main

import (
	"bytes"
	"crypto/rand"
	"errors"
	"fmt"
	"math"
)

func (a *vnextCheckpointAllocator) marshalNextSnapshot() ([]byte, uint64, error) {
	a.mu.Lock()
	defer a.mu.Unlock()

	if err := a.validateLocked(); err != nil {
		return nil, 0, err
	}
	if a.snapshotSequence == math.MaxUint64 {
		return nil, 0, errors.New("allocator snapshot sequence is exhausted")
	}
	sequence := a.snapshotSequence + 1
	data, err := a.marshalSnapshotLocked(
		nil,
		a.bitmap,
		a.nextAllocationRecordID,
		a.nextOwnerTransaction,
		sequence)
	if err != nil {
		return nil, 0, err
	}
	if uint64(len(data)) > a.superblock.Geometry.AllocatorSlotBytes {
		return nil, 0, fmt.Errorf(
			"allocator snapshot needs %d bytes, slot capacity is %d: %w",
			len(data), a.superblock.Geometry.AllocatorSlotBytes, errVNextMetadataFull)
	}
	return data, sequence, nil
}

func (a *vnextCheckpointAllocator) markSnapshotDurable(sequence uint64) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if sequence != a.snapshotSequence+1 {
		return fmt.Errorf(
			"snapshot sequence %d does not immediately follow %d",
			sequence, a.snapshotSequence)
	}
	a.snapshotSequence = sequence
	return nil
}

func (a *vnextCheckpointAllocator) marshalSnapshotLocked(
	additionalRecord *vnextAllocationRecord,
	bitmap []uint64,
	nextAllocationRecordID uint64,
	nextOwnerTransaction uint64,
	snapshotSequence uint64,
) ([]byte, error) {
	if snapshotSequence == 0 {
		return nil, errors.New("allocator snapshot sequence must be non-zero")
	}
	if nextAllocationRecordID == 0 || nextOwnerTransaction == 0 {
		return nil, errors.New("allocator high-water values must be non-zero")
	}
	if len(bitmap) != len(a.bitmap) {
		return nil, errors.New("candidate bitmap has the wrong length")
	}
	records := a.sortedRecordsLocked(additionalRecord)
	if len(records) > vnextMaxAllocationRecords {
		return nil, fmt.Errorf("allocator record count exceeds %d", vnextMaxAllocationRecords)
	}

	var payload bytes.Buffer
	vnextWriteU64(&payload, snapshotSequence)
	vnextWriteString(&payload, a.superblock.DeviceUUID)
	vnextWriteString(&payload, a.superblock.OwnerID)
	vnextWriteU64(&payload, a.superblock.OwnerEpoch)
	vnextWriteU64(&payload, a.superblock.Geometry.DataPageCount)
	vnextWriteU64(&payload, nextAllocationRecordID)
	vnextWriteU64(&payload, nextOwnerTransaction)
	bitmapBytes := vnextBitmapMarshal(bitmap, a.superblock.Geometry.DataPageCount)
	vnextWriteU32(&payload, uint32(len(bitmapBytes)))
	payload.Write(bitmapBytes)
	vnextWriteU32(&payload, uint32(len(records)))
	for _, record := range records {
		if err := vnextMarshalAllocationRecord(&payload, record); err != nil {
			return nil, err
		}
	}
	return vnextMarshalEnvelope(vnextAllocatorMagic, payload.Bytes())
}

func parseVNextAllocatorSnapshot(
	data []byte,
	superblock vnextDeviceSuperblock,
) (*vnextCheckpointAllocator, error) {
	if err := superblock.validate(); err != nil {
		return nil, err
	}
	if uint64(len(data)) > superblock.Geometry.AllocatorSlotBytes {
		return nil, fmt.Errorf(
			"allocator snapshot is %d bytes, slot is %d: %w",
			len(data), superblock.Geometry.AllocatorSlotBytes, errVNextCorrupt)
	}
	payload, err := vnextParseEnvelope(data, vnextAllocatorMagic, vnextMaxEnvelopePayload)
	if err != nil {
		return nil, err
	}
	decoder := newVNextDecoder(payload)
	sequence, err := decoder.u64()
	if err != nil || sequence == 0 {
		return nil, fmt.Errorf("decode allocator sequence: %w", firstVNextError(err, errVNextCorrupt))
	}
	deviceUUID, err := decoder.string(vnextMaxIdentityBytes)
	if err != nil {
		return nil, fmt.Errorf("decode allocator device UUID: %w", err)
	}
	ownerID, err := decoder.string(vnextMaxIdentityBytes)
	if err != nil {
		return nil, fmt.Errorf("decode allocator owner ID: %w", err)
	}
	ownerEpoch, err := decoder.u64()
	if err != nil {
		return nil, err
	}
	pageCount, err := decoder.u64()
	if err != nil {
		return nil, err
	}
	nextAllocationID, err := decoder.u64()
	if err != nil {
		return nil, err
	}
	if nextAllocationID == 0 || nextAllocationID > uint64(math.MaxInt64) {
		return nil, fmt.Errorf(
			"allocation ID high-water %d exceeds the signed 64-bit ABI: %w",
			nextAllocationID, errVNextWrongFormat)
	}
	nextTransaction, err := decoder.u64()
	if err != nil {
		return nil, err
	}
	if deviceUUID != superblock.DeviceUUID ||
		ownerID != superblock.OwnerID ||
		ownerEpoch != superblock.OwnerEpoch ||
		pageCount != superblock.Geometry.DataPageCount {
		return nil, fmt.Errorf(
			"allocator identity/geometry does not match superblock: %w",
			errVNextWrongFormat)
	}
	bitmapLength, err := decoder.u32()
	if err != nil {
		return nil, err
	}
	expectedBitmapLength, ok := vnextBitmapByteCount(pageCount)
	if !ok || uint64(bitmapLength) != expectedBitmapLength {
		return nil, fmt.Errorf(
			"bitmap length %d does not match page capacity %d: %w",
			bitmapLength, pageCount, errVNextCorrupt)
	}
	rawBitmap, err := decoder.bytes(uint64(bitmapLength))
	if err != nil {
		return nil, err
	}
	bitmap, err := vnextBitmapUnmarshal(rawBitmap, pageCount)
	if err != nil {
		return nil, err
	}
	recordCount, err := decoder.u32()
	if err != nil {
		return nil, err
	}
	if recordCount > vnextMaxAllocationRecords {
		return nil, fmt.Errorf(
			"allocator record count %d exceeds %d: %w",
			recordCount, vnextMaxAllocationRecords, errVNextCorrupt)
	}
	records := make(map[uint64]*vnextAllocationRecord, recordCount)
	requestIndex := make(map[string]uint64, recordCount)
	checkpointIndex := make(map[string]uint64, recordCount)
	for index := uint32(0); index < recordCount; index++ {
		record, err := vnextParseAllocationRecord(decoder)
		if err != nil {
			return nil, fmt.Errorf("decode allocation record %d: %w", index, err)
		}
		if _, exists := records[record.AllocationRecordID]; exists {
			return nil, fmt.Errorf(
				"duplicate allocation record ID %d: %w",
				record.AllocationRecordID, errVNextCorrupt)
		}
		if _, exists := requestIndex[record.RequestID]; exists {
			return nil, fmt.Errorf(
				"duplicate request ID %q: %w",
				record.RequestID, errVNextCorrupt)
		}
		if _, exists := checkpointIndex[record.CheckpointID]; exists {
			return nil, fmt.Errorf(
				"duplicate checkpoint ID %q: %w",
				record.CheckpointID, errVNextCorrupt)
		}
		records[record.AllocationRecordID] = record
		requestIndex[record.RequestID] = record.AllocationRecordID
		checkpointIndex[record.CheckpointID] = record.AllocationRecordID
	}
	if err := decoder.done(); err != nil {
		return nil, err
	}
	allocator := &vnextCheckpointAllocator{
		superblock:             superblock,
		bitmap:                 bitmap,
		nextAllocationRecordID: nextAllocationID,
		nextOwnerTransaction:   nextTransaction,
		snapshotSequence:       sequence,
		records:                records,
		requestIndex:           requestIndex,
		checkpointIndex:        checkpointIndex,
		tokenReader:            rand.Reader,
	}
	if err := allocator.validateLocked(); err != nil {
		return nil, err
	}
	return allocator, nil
}

func vnextMarshalAllocationRecord(buffer *bytes.Buffer, record *vnextAllocationRecord) error {
	if record == nil {
		return errors.New("cannot encode nil allocation record")
	}
	if len(record.Contents) > vnextMaxContentsPerRecord ||
		len(record.Extents) > vnextMaxExtentsPerRecord {
		return errors.New("allocation record exceeds encoding limits")
	}
	vnextWriteU64(buffer, record.AllocationRecordID)
	vnextWriteU64(buffer, record.OwnerTransaction)
	vnextWriteU64(buffer, record.OwnerEpoch)
	vnextWriteU64(buffer, record.TotalPages)
	buffer.WriteByte(byte(record.State))
	buffer.Write(make([]byte, 7))
	vnextWriteU32(buffer, record.MaxExtents)
	buffer.Write(make([]byte, 4))
	vnextWriteString(buffer, record.RequestID)
	vnextWriteString(buffer, record.CheckpointID)
	vnextWriteString(buffer, record.ProducerID)
	vnextWriteString(buffer, record.OwnerID)
	vnextWriteToken(buffer, record.WriteToken)
	vnextWriteU32(buffer, uint32(len(record.Contents)))
	for _, content := range record.Contents {
		buffer.WriteByte(byte(content.Kind))
		buffer.Write(make([]byte, 7))
		vnextWriteU64(buffer, content.ObjectID)
		vnextWriteU64(buffer, content.ByteLength)
		vnextWriteU64(buffer, content.LogicalPageStart)
		vnextWriteU64(buffer, content.PageCount)
	}
	vnextWriteU32(buffer, uint32(len(record.Extents)))
	for _, extent := range record.Extents {
		vnextWriteU64(buffer, extent.StartDataPageIndex)
		vnextWriteU64(buffer, extent.PageCount)
		vnextWriteU64(buffer, extent.LogicalPageStart)
	}
	return nil
}

func vnextParseAllocationRecord(decoder *vnextDecoder) (*vnextAllocationRecord, error) {
	record := &vnextAllocationRecord{}
	var err error
	if record.AllocationRecordID, err = decoder.u64(); err != nil {
		return nil, err
	}
	if record.AllocationRecordID == 0 || record.AllocationRecordID > uint64(math.MaxInt64) {
		return nil, fmt.Errorf(
			"allocation record ID %d exceeds the signed 64-bit ABI: %w",
			record.AllocationRecordID, errVNextWrongFormat)
	}
	if record.OwnerTransaction, err = decoder.u64(); err != nil {
		return nil, err
	}
	if record.OwnerEpoch, err = decoder.u64(); err != nil {
		return nil, err
	}
	if record.TotalPages, err = decoder.u64(); err != nil {
		return nil, err
	}
	state, err := decoder.u8()
	if err != nil {
		return nil, err
	}
	record.State = vnextAllocationState(state)
	reserved, err := decoder.bytes(7)
	if err != nil {
		return nil, err
	}
	if !vnextAllZero(reserved) {
		return nil, fmt.Errorf("allocation state reserved bytes are non-zero: %w", errVNextWrongFormat)
	}
	if record.MaxExtents, err = decoder.u32(); err != nil {
		return nil, err
	}
	reserved, err = decoder.bytes(4)
	if err != nil {
		return nil, err
	}
	if !vnextAllZero(reserved) {
		return nil, fmt.Errorf("allocation bounds reserved bytes are non-zero: %w", errVNextWrongFormat)
	}
	if record.RequestID, err = decoder.string(vnextMaxIdentityBytes); err != nil {
		return nil, err
	}
	if record.CheckpointID, err = decoder.string(vnextMaxIdentityBytes); err != nil {
		return nil, err
	}
	if record.ProducerID, err = decoder.string(vnextMaxIdentityBytes); err != nil {
		return nil, err
	}
	if record.OwnerID, err = decoder.string(vnextMaxIdentityBytes); err != nil {
		return nil, err
	}
	rawToken, err := decoder.bytes(16)
	if err != nil {
		return nil, err
	}
	copy(record.WriteToken[:], rawToken)
	contentCount, err := decoder.u32()
	if err != nil {
		return nil, err
	}
	if contentCount == 0 || contentCount > vnextMaxContentsPerRecord {
		return nil, fmt.Errorf(
			"allocation content count %d is invalid: %w",
			contentCount, errVNextCorrupt)
	}
	record.Contents = make([]vnextContentSegment, 0, contentCount)
	for index := uint32(0); index < contentCount; index++ {
		kind, err := decoder.u8()
		if err != nil {
			return nil, err
		}
		reserved, err := decoder.bytes(7)
		if err != nil {
			return nil, err
		}
		if !vnextAllZero(reserved) {
			return nil, fmt.Errorf("content reserved bytes are non-zero: %w", errVNextWrongFormat)
		}
		content := vnextContentSegment{Kind: vnextContentKind(kind)}
		if content.ObjectID, err = decoder.u64(); err != nil {
			return nil, err
		}
		if content.ByteLength, err = decoder.u64(); err != nil {
			return nil, err
		}
		if content.LogicalPageStart, err = decoder.u64(); err != nil {
			return nil, err
		}
		if content.PageCount, err = decoder.u64(); err != nil {
			return nil, err
		}
		record.Contents = append(record.Contents, content)
	}
	extentCount, err := decoder.u32()
	if err != nil {
		return nil, err
	}
	if extentCount == 0 || extentCount > vnextMaxExtentsPerRecord {
		return nil, fmt.Errorf(
			"allocation extent count %d is invalid: %w",
			extentCount, errVNextCorrupt)
	}
	record.Extents = make([]vnextPageExtent, 0, extentCount)
	for index := uint32(0); index < extentCount; index++ {
		extent := vnextPageExtent{}
		if extent.StartDataPageIndex, err = decoder.u64(); err != nil {
			return nil, err
		}
		if extent.PageCount, err = decoder.u64(); err != nil {
			return nil, err
		}
		if extent.LogicalPageStart, err = decoder.u64(); err != nil {
			return nil, err
		}
		record.Extents = append(record.Extents, extent)
	}
	return record, nil
}

func vnextBitmapByteCount(pageCount uint64) (uint64, bool) {
	rounded, ok := vnextAdd(pageCount, 7)
	if !ok {
		return 0, false
	}
	return rounded / 8, true
}

func vnextBitmapMarshal(bitmap []uint64, pageCount uint64) []byte {
	byteCount, _ := vnextBitmapByteCount(pageCount)
	out := make([]byte, int(byteCount))
	for index := uint64(0); index < pageCount; index++ {
		if vnextBitmapGet(bitmap, index) {
			out[index/8] |= byte(1 << (index % 8))
		}
	}
	return out
}

func vnextBitmapUnmarshal(data []byte, pageCount uint64) ([]uint64, error) {
	expectedBytes, ok := vnextBitmapByteCount(pageCount)
	if !ok || uint64(len(data)) != expectedBytes {
		return nil, fmt.Errorf("bitmap length does not match page count: %w", errVNextCorrupt)
	}
	if pageCount%8 != 0 && len(data) > 0 {
		invalidMask := byte(0xff << (pageCount % 8))
		if data[len(data)-1]&invalidMask != 0 {
			return nil, fmt.Errorf("bitmap sets bits beyond device capacity: %w", errVNextCorrupt)
		}
	}
	wordCount, ok := vnextBitmapWordCount(pageCount)
	if !ok {
		return nil, fmt.Errorf("bitmap word count overflows: %w", errVNextCorrupt)
	}
	bitmap := make([]uint64, wordCount)
	for index := uint64(0); index < pageCount; index++ {
		if data[index/8]&(byte(1)<<(index%8)) != 0 {
			vnextBitmapSet(bitmap, index, true)
		}
	}
	return bitmap, nil
}

func firstVNextError(primary, fallback error) error {
	if primary != nil {
		return primary
	}
	return fallback
}

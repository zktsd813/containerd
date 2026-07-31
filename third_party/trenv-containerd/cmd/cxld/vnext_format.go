package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"
	"math"
)

const (
	vnextFormatVersion             uint32 = 6
	vnextContentPageSize           uint64 = 4096
	vnextPageDescriptorSize        uint64 = 64
	vnextFormatHeaderSize          uint32 = 64
	vnextSuperblockSlotBytes       uint64 = 4096
	vnextSuperblockSlots           uint64 = 2
	vnextAllocatorSlots            uint64 = 2
	vnextMinimumAllocatorSlotBytes        = uint64(4096)

	vnextMaxEnvelopePayload = 64 << 20
	vnextMaxIdentityBytes   = 4096
)

var (
	vnextPublicationMagic = [8]byte{'T', 'R', 'P', 'U', 'B', '0', '0', '6'}
	vnextDeviceMagic      = [8]byte{'T', 'R', 'C', 'X', 'L', '0', '0', '6'}
	vnextAllocatorMagic   = [8]byte{'T', 'R', 'A', 'L', 'C', '0', '0', '6'}

	errVNextWrongFormat = errors.New("not a VNext format")
	errVNextCorrupt     = errors.New("corrupt VNext metadata")
)

// VNext uses the same explicit CPU contract for page fingerprints and small
// metadata integrity checks: CRC-32C (Castagnoli/iSCSI) over exactly the
// supplied bytes. This polynomial matches Intel DML COPY_CRC/CRC operations.
// Content pages are always supplied as 4096 bytes after zero padding. CRC is a
// corruption/candidate fingerprint, not an equality or authenticity proof.
var vnextCRCTable = crc32.MakeTable(crc32.Castagnoli)

type vnextDeviceGeometry struct {
	DeviceBytes           uint64
	SuperblockAOffset     uint64
	SuperblockBOffset     uint64
	AllocatorSlotAOffset  uint64
	AllocatorSlotBOffset  uint64
	AllocatorSlotBytes    uint64
	ControlRegionBytes    uint64
	DescriptorRegionBase  uint64
	DescriptorRegionBytes uint64
	ContentRegionBase     uint64
	ContentRegionBytes    uint64
	DataPageCount         uint64
}

// calculateVNextDeviceGeometry chooses the largest number of content pages
// that fit after two 4 KiB superblocks and two fixed-size allocator snapshot
// slots. Every content page has exactly one 64-byte descriptor. Descriptor
// slots are cache-line aligned and content pages are 4 KiB aligned.
func calculateVNextDeviceGeometry(deviceBytes, allocatorSlotBytes uint64) (vnextDeviceGeometry, error) {
	if deviceBytes > uint64(math.MaxInt64) {
		return vnextDeviceGeometry{}, fmt.Errorf(
			"device size %d exceeds the signed cross-language/file-offset ABI: %w",
			deviceBytes, errVNextWrongFormat)
	}
	if allocatorSlotBytes < vnextMinimumAllocatorSlotBytes {
		return vnextDeviceGeometry{}, fmt.Errorf(
			"allocator slot is %d bytes, need at least %d: %w",
			allocatorSlotBytes, vnextMinimumAllocatorSlotBytes, errVNextWrongFormat)
	}
	if allocatorSlotBytes > uint64(vnextFormatHeaderSize)+vnextMaxEnvelopePayload {
		return vnextDeviceGeometry{}, fmt.Errorf(
			"allocator slot is %d bytes, maximum supported is %d: %w",
			allocatorSlotBytes,
			uint64(vnextFormatHeaderSize)+vnextMaxEnvelopePayload,
			errVNextWrongFormat)
	}
	if allocatorSlotBytes%vnextContentPageSize != 0 {
		return vnextDeviceGeometry{}, fmt.Errorf(
			"allocator slot size %d is not 4 KiB aligned: %w",
			allocatorSlotBytes, errVNextWrongFormat)
	}
	superblockBytes, ok := vnextMul(vnextSuperblockSlotBytes, vnextSuperblockSlots)
	if !ok {
		return vnextDeviceGeometry{}, fmt.Errorf("superblock layout overflow: %w", errVNextWrongFormat)
	}
	allocatorBytes, ok := vnextMul(allocatorSlotBytes, vnextAllocatorSlots)
	if !ok {
		return vnextDeviceGeometry{}, fmt.Errorf("allocator slot layout overflow: %w", errVNextWrongFormat)
	}
	controlRegionBytes, ok := vnextAdd(superblockBytes, allocatorBytes)
	if !ok {
		return vnextDeviceGeometry{}, fmt.Errorf("control region overflow: %w", errVNextWrongFormat)
	}
	if deviceBytes <= controlRegionBytes {
		return vnextDeviceGeometry{}, fmt.Errorf(
			"device size %d does not extend beyond control region %d: %w",
			deviceBytes, controlRegionBytes, errVNextWrongFormat)
	}

	remaining := deviceBytes - controlRegionBytes
	upper := remaining / vnextContentPageSize
	var best uint64
	low, high := uint64(1), upper
	for low <= high {
		mid := low + (high-low)/2
		_, _, end, ok := vnextGeometryEnd(controlRegionBytes, mid)
		if ok && end <= deviceBytes {
			best = mid
			low = mid + 1
		} else {
			if mid == 0 {
				break
			}
			high = mid - 1
		}
	}
	if best == 0 {
		return vnextDeviceGeometry{}, fmt.Errorf(
			"device size %d has no room for a descriptor/content pair: %w",
			deviceBytes, errVNextWrongFormat)
	}

	descriptorBytes, contentBase, end, ok := vnextGeometryEnd(controlRegionBytes, best)
	if !ok {
		return vnextDeviceGeometry{}, fmt.Errorf("geometry overflow: %w", errVNextWrongFormat)
	}
	contentBytes, ok := vnextMul(best, vnextContentPageSize)
	if !ok {
		return vnextDeviceGeometry{}, fmt.Errorf("content geometry overflow: %w", errVNextWrongFormat)
	}
	geometry := vnextDeviceGeometry{
		DeviceBytes:           deviceBytes,
		SuperblockAOffset:     0,
		SuperblockBOffset:     vnextSuperblockSlotBytes,
		AllocatorSlotAOffset:  superblockBytes,
		AllocatorSlotBOffset:  superblockBytes + allocatorSlotBytes,
		AllocatorSlotBytes:    allocatorSlotBytes,
		ControlRegionBytes:    controlRegionBytes,
		DescriptorRegionBase:  controlRegionBytes,
		DescriptorRegionBytes: descriptorBytes,
		ContentRegionBase:     contentBase,
		ContentRegionBytes:    contentBytes,
		DataPageCount:         best,
	}
	if end > deviceBytes {
		return vnextDeviceGeometry{}, fmt.Errorf("computed geometry exceeds device: %w", errVNextWrongFormat)
	}
	if err := geometry.validate(); err != nil {
		return vnextDeviceGeometry{}, err
	}
	return geometry, nil
}

func vnextGeometryEnd(controlRegionBytes, pageCount uint64) (descriptorBytes, contentBase, end uint64, ok bool) {
	descriptorBytes, ok = vnextMul(pageCount, vnextPageDescriptorSize)
	if !ok {
		return 0, 0, 0, false
	}
	descriptorEnd, ok := vnextAdd(controlRegionBytes, descriptorBytes)
	if !ok {
		return 0, 0, 0, false
	}
	contentBase, ok = vnextAlignUp(descriptorEnd, vnextContentPageSize)
	if !ok {
		return 0, 0, 0, false
	}
	contentBytes, ok := vnextMul(pageCount, vnextContentPageSize)
	if !ok {
		return 0, 0, 0, false
	}
	end, ok = vnextAdd(contentBase, contentBytes)
	return descriptorBytes, contentBase, end, ok
}

func (g vnextDeviceGeometry) validate() error {
	if g.DataPageCount == 0 {
		return fmt.Errorf("device has zero data pages: %w", errVNextWrongFormat)
	}
	if g.SuperblockAOffset != 0 ||
		g.SuperblockBOffset != vnextSuperblockSlotBytes ||
		g.AllocatorSlotAOffset != vnextSuperblockSlotBytes*vnextSuperblockSlots ||
		g.AllocatorSlotBytes < vnextMinimumAllocatorSlotBytes ||
		g.AllocatorSlotBytes%vnextContentPageSize != 0 {
		return fmt.Errorf("invalid fixed control-region offsets: %w", errVNextWrongFormat)
	}
	expectedSlotB, ok := vnextAdd(g.AllocatorSlotAOffset, g.AllocatorSlotBytes)
	if !ok || g.AllocatorSlotBOffset != expectedSlotB {
		return fmt.Errorf("allocator A/B slots overlap or have a gap: %w", errVNextWrongFormat)
	}
	expectedControlEnd, ok := vnextAdd(g.AllocatorSlotBOffset, g.AllocatorSlotBytes)
	if !ok || g.ControlRegionBytes != expectedControlEnd {
		return fmt.Errorf("control region does not end after allocator slot B: %w", errVNextWrongFormat)
	}
	if g.DescriptorRegionBase != g.ControlRegionBytes {
		return fmt.Errorf("descriptor region is not adjacent to control region: %w", errVNextWrongFormat)
	}
	expectedDescriptorBytes, ok := vnextMul(g.DataPageCount, vnextPageDescriptorSize)
	if !ok || g.DescriptorRegionBytes != expectedDescriptorBytes {
		return fmt.Errorf("descriptor capacity is not one-to-one with payload capacity: %w", errVNextWrongFormat)
	}
	expectedContentBytes, ok := vnextMul(g.DataPageCount, vnextContentPageSize)
	if !ok || g.ContentRegionBytes != expectedContentBytes {
		return fmt.Errorf("content capacity is not one-to-one with descriptor capacity: %w", errVNextWrongFormat)
	}
	descriptorEnd, ok := vnextAdd(g.DescriptorRegionBase, g.DescriptorRegionBytes)
	if !ok || g.ContentRegionBase < descriptorEnd || g.ContentRegionBase%vnextContentPageSize != 0 {
		return fmt.Errorf("invalid descriptor/content boundary: %w", errVNextWrongFormat)
	}
	contentEnd, ok := vnextAdd(g.ContentRegionBase, g.ContentRegionBytes)
	if !ok || contentEnd > g.DeviceBytes {
		return fmt.Errorf("content region exceeds device: %w", errVNextWrongFormat)
	}
	expected, err := calculateVNextDeviceGeometryUnchecked(g.DeviceBytes, g.AllocatorSlotBytes)
	if err != nil {
		return err
	}
	if g != expected {
		return fmt.Errorf("geometry is not the deterministic maximum-capacity layout: %w", errVNextWrongFormat)
	}
	return nil
}

// calculateVNextDeviceGeometryUnchecked avoids validate's recursive
// deterministic-layout check.
func calculateVNextDeviceGeometryUnchecked(deviceBytes, allocatorSlotBytes uint64) (vnextDeviceGeometry, error) {
	if deviceBytes > uint64(math.MaxInt64) ||
		allocatorSlotBytes < vnextMinimumAllocatorSlotBytes ||
		allocatorSlotBytes%vnextContentPageSize != 0 ||
		allocatorSlotBytes > uint64(vnextFormatHeaderSize)+vnextMaxEnvelopePayload {
		return vnextDeviceGeometry{}, fmt.Errorf("invalid geometry inputs: %w", errVNextWrongFormat)
	}
	superblockBytes, ok := vnextMul(vnextSuperblockSlotBytes, vnextSuperblockSlots)
	if !ok {
		return vnextDeviceGeometry{}, fmt.Errorf("superblock layout overflow: %w", errVNextWrongFormat)
	}
	allocatorBytes, ok := vnextMul(allocatorSlotBytes, vnextAllocatorSlots)
	if !ok {
		return vnextDeviceGeometry{}, fmt.Errorf("allocator layout overflow: %w", errVNextWrongFormat)
	}
	controlRegionBytes, ok := vnextAdd(superblockBytes, allocatorBytes)
	if !ok || deviceBytes <= controlRegionBytes {
		return vnextDeviceGeometry{}, fmt.Errorf("invalid control region: %w", errVNextWrongFormat)
	}
	upper := (deviceBytes - controlRegionBytes) / vnextContentPageSize
	var best uint64
	low, high := uint64(1), upper
	for low <= high {
		mid := low + (high-low)/2
		_, _, end, ok := vnextGeometryEnd(controlRegionBytes, mid)
		if ok && end <= deviceBytes {
			best = mid
			low = mid + 1
		} else {
			high = mid - 1
		}
	}
	if best == 0 {
		return vnextDeviceGeometry{}, fmt.Errorf("no content capacity: %w", errVNextWrongFormat)
	}
	descriptorBytes, contentBase, _, ok := vnextGeometryEnd(controlRegionBytes, best)
	if !ok {
		return vnextDeviceGeometry{}, fmt.Errorf("geometry overflow: %w", errVNextWrongFormat)
	}
	contentBytes, ok := vnextMul(best, vnextContentPageSize)
	if !ok {
		return vnextDeviceGeometry{}, fmt.Errorf("content geometry overflow: %w", errVNextWrongFormat)
	}
	return vnextDeviceGeometry{
		DeviceBytes:           deviceBytes,
		SuperblockAOffset:     0,
		SuperblockBOffset:     vnextSuperblockSlotBytes,
		AllocatorSlotAOffset:  superblockBytes,
		AllocatorSlotBOffset:  superblockBytes + allocatorSlotBytes,
		AllocatorSlotBytes:    allocatorSlotBytes,
		ControlRegionBytes:    controlRegionBytes,
		DescriptorRegionBase:  controlRegionBytes,
		DescriptorRegionBytes: descriptorBytes,
		ContentRegionBase:     contentBase,
		ContentRegionBytes:    contentBytes,
		DataPageCount:         best,
	}, nil
}

func (g vnextDeviceGeometry) descriptorOffset(dataPageIndex uint64) (uint64, error) {
	if dataPageIndex >= g.DataPageCount {
		return 0, fmt.Errorf("data page index %d is outside capacity %d", dataPageIndex, g.DataPageCount)
	}
	delta, ok := vnextMul(dataPageIndex, vnextPageDescriptorSize)
	if !ok {
		return 0, errors.New("descriptor offset overflow")
	}
	offset, ok := vnextAdd(g.DescriptorRegionBase, delta)
	if !ok {
		return 0, errors.New("descriptor offset overflow")
	}
	return offset, nil
}

func (g vnextDeviceGeometry) contentOffset(dataPageIndex uint64) (uint64, error) {
	if dataPageIndex >= g.DataPageCount {
		return 0, fmt.Errorf("data page index %d is outside capacity %d", dataPageIndex, g.DataPageCount)
	}
	delta, ok := vnextMul(dataPageIndex, vnextContentPageSize)
	if !ok {
		return 0, errors.New("content offset overflow")
	}
	offset, ok := vnextAdd(g.ContentRegionBase, delta)
	if !ok {
		return 0, errors.New("content offset overflow")
	}
	return offset, nil
}

func (g vnextDeviceGeometry) dataPageIndex(contentOffset uint64) (uint64, error) {
	if contentOffset < g.ContentRegionBase {
		return 0, fmt.Errorf("content offset %d precedes content region", contentOffset)
	}
	delta := contentOffset - g.ContentRegionBase
	if delta%vnextContentPageSize != 0 {
		return 0, fmt.Errorf("content offset %d is not 4 KiB aligned", contentOffset)
	}
	index := delta / vnextContentPageSize
	if index >= g.DataPageCount {
		return 0, fmt.Errorf("content offset %d exceeds content capacity", contentOffset)
	}
	return index, nil
}

type vnextDeviceSuperblock struct {
	DeviceUUID string
	OwnerID    string
	OwnerEpoch uint64
	Sequence   uint64
	Geometry   vnextDeviceGeometry
}

func (s vnextDeviceSuperblock) marshalBinary() ([]byte, error) {
	if err := s.validate(); err != nil {
		return nil, err
	}
	var payload bytes.Buffer
	vnextWriteString(&payload, s.DeviceUUID)
	vnextWriteString(&payload, s.OwnerID)
	vnextWriteU64(&payload, s.OwnerEpoch)
	vnextWriteU64(&payload, s.Sequence)
	vnextWriteU64(&payload, s.Geometry.DeviceBytes)
	vnextWriteU64(&payload, s.Geometry.SuperblockAOffset)
	vnextWriteU64(&payload, s.Geometry.SuperblockBOffset)
	vnextWriteU64(&payload, s.Geometry.AllocatorSlotAOffset)
	vnextWriteU64(&payload, s.Geometry.AllocatorSlotBOffset)
	vnextWriteU64(&payload, s.Geometry.AllocatorSlotBytes)
	vnextWriteU64(&payload, s.Geometry.ControlRegionBytes)
	vnextWriteU64(&payload, s.Geometry.DescriptorRegionBase)
	vnextWriteU64(&payload, s.Geometry.DescriptorRegionBytes)
	vnextWriteU64(&payload, s.Geometry.ContentRegionBase)
	vnextWriteU64(&payload, s.Geometry.ContentRegionBytes)
	vnextWriteU64(&payload, s.Geometry.DataPageCount)
	return vnextMarshalEnvelope(vnextDeviceMagic, payload.Bytes())
}

func parseVNextDeviceSuperblock(data []byte) (vnextDeviceSuperblock, error) {
	payload, err := vnextParseEnvelope(data, vnextDeviceMagic, vnextMaxEnvelopePayload)
	if err != nil {
		return vnextDeviceSuperblock{}, err
	}
	decoder := newVNextDecoder(payload)
	deviceUUID, err := decoder.string(vnextMaxIdentityBytes)
	if err != nil {
		return vnextDeviceSuperblock{}, fmt.Errorf("decode device UUID: %w", err)
	}
	ownerID, err := decoder.string(vnextMaxIdentityBytes)
	if err != nil {
		return vnextDeviceSuperblock{}, fmt.Errorf("decode owner ID: %w", err)
	}
	superblock := vnextDeviceSuperblock{
		DeviceUUID: deviceUUID,
		OwnerID:    ownerID,
	}
	if superblock.OwnerEpoch, err = decoder.u64(); err != nil {
		return vnextDeviceSuperblock{}, err
	}
	if superblock.Sequence, err = decoder.u64(); err != nil {
		return vnextDeviceSuperblock{}, err
	}
	fields := []*uint64{
		&superblock.Geometry.DeviceBytes,
		&superblock.Geometry.SuperblockAOffset,
		&superblock.Geometry.SuperblockBOffset,
		&superblock.Geometry.AllocatorSlotAOffset,
		&superblock.Geometry.AllocatorSlotBOffset,
		&superblock.Geometry.AllocatorSlotBytes,
		&superblock.Geometry.ControlRegionBytes,
		&superblock.Geometry.DescriptorRegionBase,
		&superblock.Geometry.DescriptorRegionBytes,
		&superblock.Geometry.ContentRegionBase,
		&superblock.Geometry.ContentRegionBytes,
		&superblock.Geometry.DataPageCount,
	}
	for _, field := range fields {
		*field, err = decoder.u64()
		if err != nil {
			return vnextDeviceSuperblock{}, err
		}
	}
	if err := decoder.done(); err != nil {
		return vnextDeviceSuperblock{}, err
	}
	if err := superblock.validate(); err != nil {
		return vnextDeviceSuperblock{}, err
	}
	return superblock, nil
}

func (s vnextDeviceSuperblock) validate() error {
	if s.DeviceUUID == "" || len(s.DeviceUUID) > vnextMaxIdentityBytes {
		return fmt.Errorf("device UUID is empty or too long: %w", errVNextWrongFormat)
	}
	if s.OwnerID == "" || len(s.OwnerID) > vnextMaxIdentityBytes {
		return fmt.Errorf("owner ID is empty or too long: %w", errVNextWrongFormat)
	}
	if s.OwnerEpoch == 0 {
		return fmt.Errorf("owner epoch must be non-zero: %w", errVNextWrongFormat)
	}
	if s.OwnerEpoch > uint64(math.MaxInt64) {
		return fmt.Errorf(
			"owner epoch %d exceeds the signed cross-language ABI: %w",
			s.OwnerEpoch, errVNextWrongFormat)
	}
	if s.Sequence == 0 {
		return fmt.Errorf("superblock sequence must be non-zero: %w", errVNextWrongFormat)
	}
	return s.Geometry.validate()
}

type vnextContentKind uint8

const (
	vnextContentMemory vnextContentKind = iota + 1
	vnextContentArtifact
	vnextContentMMTemplate
	vnextContentPageMap
	vnextContentRestoreBlob
)

func (k vnextContentKind) valid() bool {
	return k >= vnextContentMemory && k <= vnextContentRestoreBlob
}

type vnextPageDescriptorState uint8

const (
	vnextDescriptorFree vnextPageDescriptorState = iota
	vnextDescriptorReserved
	vnextDescriptorSealed
	vnextDescriptorRetiring
	vnextDescriptorQuarantined
)

const vnextKnownDescriptorFlags uint16 = 0

// vnextPageDescriptor is a semantic representation of the exact 64-byte
// on-device descriptor. It deliberately has no per-page generation.
type vnextPageDescriptor struct {
	ContentCRC32            uint32
	AllocationRecordID      uint64
	OriginContentObjectID   uint64
	ContentReferenceCount   uint64
	LastOwnerTransactionSeq uint64
	PayloadLength           uint32
	State                   vnextPageDescriptorState
	ContentKind             vnextContentKind
	Flags                   uint16
}

func (d vnextPageDescriptor) marshalBinary() ([]byte, error) {
	if err := d.validate(); err != nil {
		return nil, err
	}
	out := make([]byte, vnextPageDescriptorSize)
	if d.State == vnextDescriptorFree {
		// The all-zero cache line is the only valid FREE representation. A
		// recovery scan can therefore skip free descriptors without treating
		// the absence of integrity metadata as corruption.
		return out, nil
	}
	binary.LittleEndian.PutUint32(out[0:4], d.ContentCRC32)
	// Bytes 4:8 are descriptor_integrity and remain zero until all other
	// fields have been encoded.
	binary.LittleEndian.PutUint64(out[8:16], d.AllocationRecordID)
	binary.LittleEndian.PutUint64(out[16:24], d.OriginContentObjectID)
	binary.LittleEndian.PutUint64(out[24:32], d.ContentReferenceCount)
	binary.LittleEndian.PutUint64(out[32:40], d.LastOwnerTransactionSeq)
	binary.LittleEndian.PutUint32(out[40:44], d.PayloadLength)
	out[44] = byte(d.State)
	out[45] = byte(d.ContentKind)
	binary.LittleEndian.PutUint16(out[46:48], d.Flags)
	// Bytes 48:64 are reserved and must remain zero.
	integrity := crc32.Checksum(out, vnextCRCTable)
	binary.LittleEndian.PutUint32(out[4:8], integrity)
	return out, nil
}

func parseVNextPageDescriptor(data []byte) (vnextPageDescriptor, error) {
	if len(data) != int(vnextPageDescriptorSize) {
		return vnextPageDescriptor{}, fmt.Errorf(
			"descriptor is %d bytes, expected %d: %w",
			len(data), vnextPageDescriptorSize, errVNextCorrupt)
	}
	if vnextAllZero(data) {
		return vnextPageDescriptor{State: vnextDescriptorFree}, nil
	}
	if !vnextAllZero(data[48:64]) {
		return vnextPageDescriptor{}, fmt.Errorf("descriptor reserved bytes are non-zero: %w", errVNextCorrupt)
	}
	wantIntegrity := binary.LittleEndian.Uint32(data[4:8])
	copyForCRC := append([]byte(nil), data...)
	for i := 4; i < 8; i++ {
		copyForCRC[i] = 0
	}
	if got := crc32.Checksum(copyForCRC, vnextCRCTable); got != wantIntegrity {
		return vnextPageDescriptor{}, fmt.Errorf(
			"descriptor integrity is %#x, expected %#x: %w",
			wantIntegrity, got, errVNextCorrupt)
	}
	descriptor := vnextPageDescriptor{
		ContentCRC32:            binary.LittleEndian.Uint32(data[0:4]),
		AllocationRecordID:      binary.LittleEndian.Uint64(data[8:16]),
		OriginContentObjectID:   binary.LittleEndian.Uint64(data[16:24]),
		ContentReferenceCount:   binary.LittleEndian.Uint64(data[24:32]),
		LastOwnerTransactionSeq: binary.LittleEndian.Uint64(data[32:40]),
		PayloadLength:           binary.LittleEndian.Uint32(data[40:44]),
		State:                   vnextPageDescriptorState(data[44]),
		ContentKind:             vnextContentKind(data[45]),
		Flags:                   binary.LittleEndian.Uint16(data[46:48]),
	}
	if err := descriptor.validate(); err != nil {
		return vnextPageDescriptor{}, err
	}
	return descriptor, nil
}

func (d vnextPageDescriptor) validate() error {
	if d.State == vnextDescriptorFree {
		if d.ContentCRC32 != 0 ||
			d.AllocationRecordID != 0 ||
			d.OriginContentObjectID != 0 ||
			d.ContentReferenceCount != 0 ||
			d.LastOwnerTransactionSeq != 0 ||
			d.PayloadLength != 0 ||
			d.ContentKind != 0 ||
			d.Flags != 0 {
			return fmt.Errorf("FREE descriptor is not the canonical all-zero value: %w", errVNextWrongFormat)
		}
		return nil
	}
	if d.AllocationRecordID == 0 {
		return fmt.Errorf("descriptor allocation record ID is zero: %w", errVNextWrongFormat)
	}
	if d.OriginContentObjectID == 0 {
		return fmt.Errorf("descriptor content object ID is zero: %w", errVNextWrongFormat)
	}
	if !d.ContentKind.valid() {
		return fmt.Errorf("descriptor content kind %d is invalid: %w", d.ContentKind, errVNextWrongFormat)
	}
	if d.State != vnextDescriptorReserved &&
		d.State != vnextDescriptorSealed &&
		d.State != vnextDescriptorRetiring &&
		d.State != vnextDescriptorQuarantined {
		return fmt.Errorf("descriptor state %d is invalid: %w", d.State, errVNextWrongFormat)
	}
	if d.Flags&^vnextKnownDescriptorFlags != 0 {
		return fmt.Errorf("descriptor contains unknown flags %#x: %w", d.Flags, errVNextWrongFormat)
	}
	if d.PayloadLength == 0 || uint64(d.PayloadLength) > vnextContentPageSize {
		return fmt.Errorf("descriptor payload length %d is invalid: %w", d.PayloadLength, errVNextWrongFormat)
	}
	if d.State == vnextDescriptorSealed && d.ContentReferenceCount == 0 {
		return fmt.Errorf("sealed descriptor has zero references: %w", errVNextWrongFormat)
	}
	return nil
}

// buildVNextContentPage converts every logical content kind, including
// artifacts, into the same 4 KiB payload representation. Short final chunks
// are zero-padded before CRC calculation; PayloadLength retains their exact
// byte count.
func buildVNextContentPage(
	kind vnextContentKind,
	content []byte,
	allocationRecordID uint64,
	contentObjectID uint64,
	ownerTransactionSeq uint64,
) ([vnextContentPageSize]byte, vnextPageDescriptor, error) {
	var page [vnextContentPageSize]byte
	if !kind.valid() {
		return page, vnextPageDescriptor{}, fmt.Errorf("invalid content kind %d", kind)
	}
	if len(content) == 0 || uint64(len(content)) > vnextContentPageSize {
		return page, vnextPageDescriptor{}, fmt.Errorf(
			"content length %d is outside 1..%d", len(content), vnextContentPageSize)
	}
	if kind == vnextContentMemory && uint64(len(content)) != vnextContentPageSize {
		return page, vnextPageDescriptor{}, fmt.Errorf(
			"memory content page is %d bytes, expected exactly %d",
			len(content), vnextContentPageSize)
	}
	copy(page[:], content)
	descriptor := vnextPageDescriptor{
		ContentCRC32:            crc32.Checksum(page[:], vnextCRCTable),
		AllocationRecordID:      allocationRecordID,
		OriginContentObjectID:   contentObjectID,
		ContentReferenceCount:   1,
		LastOwnerTransactionSeq: ownerTransactionSeq,
		PayloadLength:           uint32(len(content)),
		State:                   vnextDescriptorSealed,
		ContentKind:             kind,
	}
	if err := descriptor.validate(); err != nil {
		return page, vnextPageDescriptor{}, err
	}
	return page, descriptor, nil
}

func (d vnextPageDescriptor) validateContent(page []byte) error {
	if len(page) != int(vnextContentPageSize) {
		return fmt.Errorf("content page is %d bytes, expected %d", len(page), vnextContentPageSize)
	}
	if got := crc32.Checksum(page, vnextCRCTable); got != d.ContentCRC32 {
		return fmt.Errorf(
			"content CRC is %#x, descriptor records %#x: %w",
			got, d.ContentCRC32, errVNextCorrupt)
	}
	return nil
}

func marshalVNextPublicationEnvelope(payload []byte) ([]byte, error) {
	return vnextMarshalEnvelope(vnextPublicationMagic, payload)
}

func parseVNextPublicationEnvelope(data []byte) ([]byte, error) {
	return vnextParseEnvelope(data, vnextPublicationMagic, vnextMaxEnvelopePayload)
}

// vnextMarshalEnvelope creates a strict, checksummed envelope. Bytes 52:64 are
// reserved so later readers can distinguish optional additions from a format
// change; V6 readers reject any non-zero mandatory flags or reserved bytes.
func vnextMarshalEnvelope(magic [8]byte, payload []byte) ([]byte, error) {
	if len(payload) > vnextMaxEnvelopePayload {
		return nil, fmt.Errorf("VNext payload is %d bytes, limit is %d", len(payload), vnextMaxEnvelopePayload)
	}
	total, ok := vnextAdd(uint64(vnextFormatHeaderSize), uint64(len(payload)))
	if !ok || total > uint64(math.MaxInt) {
		return nil, errors.New("VNext envelope length overflow")
	}
	out := make([]byte, int(total))
	copy(out[0:8], magic[:])
	binary.LittleEndian.PutUint32(out[8:12], vnextFormatVersion)
	binary.LittleEndian.PutUint32(out[12:16], vnextFormatHeaderSize)
	binary.LittleEndian.PutUint64(out[16:24], uint64(len(payload)))
	binary.LittleEndian.PutUint32(out[24:28], crc32.Checksum(payload, vnextCRCTable))
	// 28:32 mandatory feature flags; zero is the only V6 value.
	// 32:36 header integrity.
	copy(out[vnextFormatHeaderSize:], payload)
	binary.LittleEndian.PutUint32(out[32:36], vnextHeaderCRC(out[:vnextFormatHeaderSize]))
	return out, nil
}

func vnextParseEnvelope(data []byte, expectedMagic [8]byte, maxPayload uint64) ([]byte, error) {
	if len(data) < int(vnextFormatHeaderSize) {
		return nil, fmt.Errorf("VNext envelope is truncated: %w", errVNextCorrupt)
	}
	var gotMagic [8]byte
	copy(gotMagic[:], data[0:8])
	if gotMagic != expectedMagic {
		return nil, fmt.Errorf(
			"magic %q does not match %q: %w",
			gotMagic, expectedMagic, errVNextWrongFormat)
	}
	version := binary.LittleEndian.Uint32(data[8:12])
	if version != vnextFormatVersion {
		return nil, fmt.Errorf(
			"format version %d does not match %d: %w",
			version, vnextFormatVersion, errVNextWrongFormat)
	}
	headerSize := binary.LittleEndian.Uint32(data[12:16])
	if headerSize != vnextFormatHeaderSize {
		return nil, fmt.Errorf(
			"header size %d does not match %d: %w",
			headerSize, vnextFormatHeaderSize, errVNextWrongFormat)
	}
	if flags := binary.LittleEndian.Uint32(data[28:32]); flags != 0 {
		return nil, fmt.Errorf("unknown mandatory VNext flags %#x: %w", flags, errVNextWrongFormat)
	}
	if !vnextAllZero(data[36:vnextFormatHeaderSize]) {
		return nil, fmt.Errorf("VNext reserved header bytes are non-zero: %w", errVNextWrongFormat)
	}
	wantHeaderCRC := binary.LittleEndian.Uint32(data[32:36])
	if got := vnextHeaderCRC(data[:vnextFormatHeaderSize]); got != wantHeaderCRC {
		return nil, fmt.Errorf(
			"header integrity is %#x, expected %#x: %w",
			wantHeaderCRC, got, errVNextCorrupt)
	}
	payloadLength := binary.LittleEndian.Uint64(data[16:24])
	if payloadLength > maxPayload {
		return nil, fmt.Errorf("payload length %d exceeds limit %d: %w", payloadLength, maxPayload, errVNextCorrupt)
	}
	total, ok := vnextAdd(uint64(headerSize), payloadLength)
	if !ok || total != uint64(len(data)) {
		return nil, fmt.Errorf(
			"envelope length is %d, header declares %d: %w",
			len(data), total, errVNextCorrupt)
	}
	payload := data[headerSize:]
	wantPayloadCRC := binary.LittleEndian.Uint32(data[24:28])
	if got := crc32.Checksum(payload, vnextCRCTable); got != wantPayloadCRC {
		return nil, fmt.Errorf(
			"payload integrity is %#x, expected %#x: %w",
			wantPayloadCRC, got, errVNextCorrupt)
	}
	return append([]byte(nil), payload...), nil
}

func vnextHeaderCRC(header []byte) uint32 {
	copyForCRC := append([]byte(nil), header...)
	if len(copyForCRC) >= 36 {
		for i := 32; i < 36; i++ {
			copyForCRC[i] = 0
		}
	}
	return crc32.Checksum(copyForCRC, vnextCRCTable)
}

func vnextAdd(a, b uint64) (uint64, bool) {
	if a > math.MaxUint64-b {
		return 0, false
	}
	return a + b, true
}

func vnextMul(a, b uint64) (uint64, bool) {
	if a != 0 && b > math.MaxUint64/a {
		return 0, false
	}
	return a * b, true
}

func vnextAlignUp(value, alignment uint64) (uint64, bool) {
	if alignment == 0 || alignment&(alignment-1) != 0 {
		return 0, false
	}
	mask := alignment - 1
	if value > math.MaxUint64-mask {
		return 0, false
	}
	return (value + mask) &^ mask, true
}

func vnextAllZero(data []byte) bool {
	for _, value := range data {
		if value != 0 {
			return false
		}
	}
	return true
}

func vnextWriteU32(buffer *bytes.Buffer, value uint32) {
	var raw [4]byte
	binary.LittleEndian.PutUint32(raw[:], value)
	buffer.Write(raw[:])
}

func vnextWriteU64(buffer *bytes.Buffer, value uint64) {
	var raw [8]byte
	binary.LittleEndian.PutUint64(raw[:], value)
	buffer.Write(raw[:])
}

func vnextWriteString(buffer *bytes.Buffer, value string) {
	vnextWriteU32(buffer, uint32(len(value)))
	buffer.WriteString(value)
}

type vnextDecoder struct {
	data   []byte
	offset uint64
}

func newVNextDecoder(data []byte) *vnextDecoder {
	return &vnextDecoder{data: data}
}

func (d *vnextDecoder) bytes(length uint64) ([]byte, error) {
	end, ok := vnextAdd(d.offset, length)
	if !ok || end > uint64(len(d.data)) {
		return nil, fmt.Errorf("VNext metadata is truncated at byte %d: %w", d.offset, errVNextCorrupt)
	}
	out := d.data[d.offset:end]
	d.offset = end
	return out, nil
}

func (d *vnextDecoder) u8() (uint8, error) {
	raw, err := d.bytes(1)
	if err != nil {
		return 0, err
	}
	return raw[0], nil
}

func (d *vnextDecoder) u16() (uint16, error) {
	raw, err := d.bytes(2)
	if err != nil {
		return 0, err
	}
	return binary.LittleEndian.Uint16(raw), nil
}

func (d *vnextDecoder) u32() (uint32, error) {
	raw, err := d.bytes(4)
	if err != nil {
		return 0, err
	}
	return binary.LittleEndian.Uint32(raw), nil
}

func (d *vnextDecoder) u64() (uint64, error) {
	raw, err := d.bytes(8)
	if err != nil {
		return 0, err
	}
	return binary.LittleEndian.Uint64(raw), nil
}

func (d *vnextDecoder) string(maxLength uint64) (string, error) {
	length, err := d.u32()
	if err != nil {
		return "", err
	}
	if uint64(length) > maxLength {
		return "", fmt.Errorf("string length %d exceeds limit %d: %w", length, maxLength, errVNextCorrupt)
	}
	raw, err := d.bytes(uint64(length))
	if err != nil {
		return "", err
	}
	if bytes.IndexByte(raw, 0) >= 0 {
		return "", fmt.Errorf("identity contains a NUL byte: %w", errVNextWrongFormat)
	}
	return string(raw), nil
}

func (d *vnextDecoder) done() error {
	if d.offset != uint64(len(d.data)) {
		return fmt.Errorf(
			"VNext metadata has %d trailing bytes: %w",
			uint64(len(d.data))-d.offset, errVNextCorrupt)
	}
	return nil
}

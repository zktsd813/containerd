package trcxl007

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"
	"math/bits"

	"github.com/containerd/containerd/third_party/trenv-containerd/pkg/cxlcheckpoint"
)

const (
	// AllocatorSnapshotMagicString and AllocatorSnapshotDomain identify the
	// clean-slate TRCXL007 allocation-bitmap envelope. The snapshot is pure
	// allocator metadata: it carries no local path, checkpoint record, mutable
	// slot selection, I/O result, or durability claim.
	AllocatorSnapshotMagicString = "TRALC007"
	AllocatorSnapshotVersion     = uint32(7)
	AllocatorSnapshotDomain      = "allocation-bitmap-v1"

	AllocatorSnapshotEnvelopeHeaderBytes uint64 = 64

	allocatorSnapshotDomainFieldBytes = 24

	allocatorSnapshotMagicOffset         = 0
	allocatorSnapshotVersionOffset       = 8
	allocatorSnapshotHeaderSizeOffset    = 12
	allocatorSnapshotDomainOffset        = 16
	allocatorSnapshotPayloadLengthOffset = 40
	allocatorSnapshotPayloadCRCOffset    = 48
	allocatorSnapshotFlagsOffset         = 52
	allocatorSnapshotHeaderCRCOffset     = 56
	allocatorSnapshotReservedOffset      = 60

	allocatorSnapshotDeviceDigestOffset    = 64
	allocatorSnapshotOwnerDigestOffset     = 96
	allocatorSnapshotOwnerEpochOffset      = 128
	allocatorSnapshotSequenceOffset        = 136
	allocatorSnapshotNextAllocationOffset  = 144
	allocatorSnapshotNextTransactionOffset = 152
	allocatorSnapshotOwnerJournalOffset    = 160
	allocatorSnapshotDataPageCountOffset   = 168
	allocatorSnapshotAllocatedCountOffset  = 176
	allocatorSnapshotBitmapLengthOffset    = 184
	allocatorSnapshotBitmapOffset          = 192

	allocatorSnapshotFixedPayloadBytes = AllocatorSnapshotFixedBytes - AllocatorSnapshotEnvelopeHeaderBytes
)

var (
	ErrInvalidAllocatorSnapshot     = errors.New("invalid TRCXL007 allocator snapshot")
	ErrWrongAllocatorSnapshotFormat = errors.New("not a TRALC007 allocator snapshot")
	ErrCorruptAllocatorSnapshot     = errors.New("corrupt TRALC007 allocator snapshot")
	ErrAllocatorSnapshotMismatch    = errors.New("TRALC007 allocator snapshot binding mismatch")
	ErrAllocatorSnapshotBounds      = errors.New("TRALC007 allocator snapshot page index is out of bounds")

	allocatorSnapshotMagic  = [8]byte{'T', 'R', 'A', 'L', 'C', '0', '0', '7'}
	allocatorSnapshotDomain = func() [allocatorSnapshotDomainFieldBytes]byte {
		var domain [allocatorSnapshotDomainFieldBytes]byte
		copy(domain[:], AllocatorSnapshotDomain)
		return domain
	}()
	allocatorSnapshotCRC32CTable  = crc32.MakeTable(crc32.Castagnoli)
	allocatorSnapshotZeroCRCField [4]byte
)

// AllocatorSnapshotConfig supplies the non-derived fields of one allocator
// snapshot. NewAllocatorSnapshot derives the bitmap length and popcount rather
// than trusting caller-provided duplicates.
type AllocatorSnapshotConfig struct {
	DeviceBindingSHA256     [sha256.Size]byte
	OwnerIdentitySHA256     [sha256.Size]byte
	OwnerEpoch              uint64
	SnapshotSequence        uint64
	NextAllocationRecordID  uint64
	NextOwnerTransactionSeq uint64
	OwnerJournalSequence    uint64
	DataPageCount           uint64
}

// AllocatorSnapshot is the logical form of one canonical TRALC007 envelope.
// The bitmap is intentionally private. Copies returned by BitmapBytes and
// Clone never expose the internal slice used by a parsed or constructed value.
type AllocatorSnapshot struct {
	DeviceBindingSHA256     [sha256.Size]byte
	OwnerIdentitySHA256     [sha256.Size]byte
	OwnerEpoch              uint64
	SnapshotSequence        uint64
	NextAllocationRecordID  uint64
	NextOwnerTransactionSeq uint64
	OwnerJournalSequence    uint64
	DataPageCount           uint64
	AllocatedPageCount      uint64
	BitmapByteLength        uint64

	allocationBitmap []byte
}

// AllocatorSnapshotStorage holds immutable copies of the exact canonical
// envelope and its complete zero-padded inactive-slot write image. This type
// does not select A/B, perform I/O, flush caches, or claim durability.
type AllocatorSnapshotStorage struct {
	exactBytes  []byte
	paddedBytes []byte
	sha256      [sha256.Size]byte
}

// NewAllocatorSnapshot clones allocationBitmap, derives its persisted count
// fields, and validates the complete logical snapshot. A set bit means the
// corresponding data page is unavailable/allocated.
func NewAllocatorSnapshot(
	config AllocatorSnapshotConfig,
	allocationBitmap []byte,
) (AllocatorSnapshot, error) {
	expectedBitmapBytes, err := allocatorSnapshotBitmapByteCount(config.DataPageCount)
	if err != nil {
		return AllocatorSnapshot{}, err
	}
	if uint64(len(allocationBitmap)) != expectedBitmapBytes {
		return AllocatorSnapshot{}, allocatorSnapshotInvalidf(
			"bitmap slice length %d does not equal ceil(%d/8)=%d",
			len(allocationBitmap),
			config.DataPageCount,
			expectedBitmapBytes)
	}
	snapshot := AllocatorSnapshot{
		DeviceBindingSHA256:     config.DeviceBindingSHA256,
		OwnerIdentitySHA256:     config.OwnerIdentitySHA256,
		OwnerEpoch:              config.OwnerEpoch,
		SnapshotSequence:        config.SnapshotSequence,
		NextAllocationRecordID:  config.NextAllocationRecordID,
		NextOwnerTransactionSeq: config.NextOwnerTransactionSeq,
		OwnerJournalSequence:    config.OwnerJournalSequence,
		DataPageCount:           config.DataPageCount,
		AllocatedPageCount:      allocatorSnapshotPopcount(allocationBitmap),
		BitmapByteLength:        uint64(len(allocationBitmap)),
		allocationBitmap:        allocationBitmap,
	}
	if err := snapshot.Validate(); err != nil {
		return AllocatorSnapshot{}, err
	}
	snapshot.allocationBitmap = append([]byte(nil), allocationBitmap...)
	return snapshot, nil
}

// Validate checks the snapshot without relying on a particular device slot.
// CrossCheck additionally binds it to one validated DeviceGeometry and to the
// caller's expected device, Owner, and Owner-epoch identities.
func (snapshot AllocatorSnapshot) Validate() error {
	if !allocatorSnapshotCompiledContractValid() {
		return allocatorSnapshotInvalidf("compiled TRALC007 wire contract differs from the required ABI")
	}
	if snapshot.DeviceBindingSHA256 == ([sha256.Size]byte{}) {
		return allocatorSnapshotInvalidf("device-binding SHA-256 is zero")
	}
	if snapshot.OwnerIdentitySHA256 == ([sha256.Size]byte{}) {
		return allocatorSnapshotInvalidf("Owner-identity SHA-256 is zero")
	}
	for _, field := range []struct {
		name  string
		value uint64
	}{
		{"Owner epoch", snapshot.OwnerEpoch},
		{"snapshot sequence", snapshot.SnapshotSequence},
		{"next allocation-record ID", snapshot.NextAllocationRecordID},
		{"next Owner-transaction sequence", snapshot.NextOwnerTransactionSeq},
		{"data-page count", snapshot.DataPageCount},
	} {
		if field.value == 0 || field.value > cxlcheckpoint.MaxSignedLong {
			return allocatorSnapshotInvalidf(
				"%s %d is outside 1..%d", field.name, field.value, cxlcheckpoint.MaxSignedLong)
		}
	}
	if snapshot.OwnerJournalSequence > cxlcheckpoint.MaxSignedLong {
		return allocatorSnapshotInvalidf(
			"Owner-journal sequence %d exceeds %d",
			snapshot.OwnerJournalSequence,
			cxlcheckpoint.MaxSignedLong)
	}
	if snapshot.AllocatedPageCount > snapshot.DataPageCount {
		return allocatorSnapshotInvalidf(
			"allocated-page count %d exceeds data-page count %d",
			snapshot.AllocatedPageCount,
			snapshot.DataPageCount)
	}
	expectedBitmapBytes, err := allocatorSnapshotBitmapByteCount(snapshot.DataPageCount)
	if err != nil {
		return err
	}
	if snapshot.BitmapByteLength != expectedBitmapBytes ||
		uint64(len(snapshot.allocationBitmap)) != expectedBitmapBytes {
		return allocatorSnapshotInvalidf(
			"bitmap length field/slice %d/%d does not equal ceil(%d/8)=%d",
			snapshot.BitmapByteLength,
			len(snapshot.allocationBitmap),
			snapshot.DataPageCount,
			expectedBitmapBytes)
	}
	if err := allocatorSnapshotValidateUnusedHighBits(
		snapshot.allocationBitmap,
		snapshot.DataPageCount); err != nil {
		return err
	}
	actualAllocated := allocatorSnapshotPopcount(snapshot.allocationBitmap)
	if snapshot.AllocatedPageCount != actualAllocated {
		return allocatorSnapshotInvalidf(
			"allocated-page count %d does not equal bitmap popcount %d",
			snapshot.AllocatedPageCount,
			actualAllocated)
	}
	return nil
}

// CrossCheck verifies the snapshot against the already-validated device and
// Owner bindings supplied by the caller. Digests replace path/identity strings
// in this page-local format; they are not authentication by themselves.
func (snapshot AllocatorSnapshot) CrossCheck(
	geometry DeviceGeometry,
	expectedDeviceBindingSHA256 [sha256.Size]byte,
	expectedOwnerIdentitySHA256 [sha256.Size]byte,
	expectedOwnerEpoch uint64,
) error {
	if err := geometry.Validate(); err != nil {
		return err
	}
	if err := snapshot.Validate(); err != nil {
		return err
	}
	if snapshot.DataPageCount != geometry.DataPageCount {
		return allocatorSnapshotMismatchf(
			"data-page count %d does not equal geometry count %d",
			snapshot.DataPageCount,
			geometry.DataPageCount)
	}
	if snapshot.DeviceBindingSHA256 != expectedDeviceBindingSHA256 {
		return allocatorSnapshotMismatchf("device-binding SHA-256 differs")
	}
	if snapshot.OwnerIdentitySHA256 != expectedOwnerIdentitySHA256 {
		return allocatorSnapshotMismatchf("Owner-identity SHA-256 differs")
	}
	if snapshot.OwnerEpoch != expectedOwnerEpoch {
		return allocatorSnapshotMismatchf(
			"Owner epoch %d does not equal expected %d",
			snapshot.OwnerEpoch,
			expectedOwnerEpoch)
	}
	return nil
}

// BitmapBytes returns a detached copy of the one-bit-per-page bitmap.
func (snapshot AllocatorSnapshot) BitmapBytes() []byte {
	return append([]byte(nil), snapshot.allocationBitmap...)
}

// Clone returns a deep copy whose bitmap cannot alias the source value.
func (snapshot AllocatorSnapshot) Clone() AllocatorSnapshot {
	snapshot.allocationBitmap = append([]byte(nil), snapshot.allocationBitmap...)
	return snapshot
}

// PageUnavailable reports whether one data page is unavailable/allocated.
func (snapshot AllocatorSnapshot) PageUnavailable(dataPageIndex uint64) (bool, error) {
	if snapshot.DataPageCount == 0 {
		return false, fmt.Errorf(
			"%w: snapshot has zero data-page capacity",
			ErrAllocatorSnapshotBounds)
	}
	if dataPageIndex >= snapshot.DataPageCount {
		return false, fmt.Errorf(
			"%w: data-page index %d is outside 0..%d",
			ErrAllocatorSnapshotBounds,
			dataPageIndex,
			snapshot.DataPageCount-1)
	}
	byteIndex := dataPageIndex / 8
	if byteIndex >= uint64(len(snapshot.allocationBitmap)) {
		return false, allocatorSnapshotInvalidf("bitmap slice is shorter than its data-page count")
	}
	return snapshot.allocationBitmap[byteIndex]&(byte(1)<<uint(dataPageIndex%8)) != 0, nil
}

// CanonicalAllocatorSnapshotBytes returns one exact canonical TRALC007
// envelope. Its complete length is checked against the configured device slot.
func CanonicalAllocatorSnapshotBytes(
	snapshot AllocatorSnapshot,
	geometry DeviceGeometry,
) ([]byte, error) {
	if err := allocatorSnapshotValidateForGeometry(snapshot, geometry); err != nil {
		return nil, err
	}
	exactLength, ok := checkedAdd(AllocatorSnapshotFixedBytes, snapshot.BitmapByteLength)
	if !ok || exactLength > geometry.AllocatorSnapshotSlotBytes {
		return nil, allocatorSnapshotInvalidf(
			"encoded length %d exceeds allocator snapshot slot %d",
			exactLength,
			geometry.AllocatorSnapshotSlotBytes)
	}
	out := make([]byte, int(exactLength))
	copy(out[allocatorSnapshotMagicOffset:allocatorSnapshotVersionOffset], allocatorSnapshotMagic[:])
	binary.LittleEndian.PutUint32(out[allocatorSnapshotVersionOffset:], AllocatorSnapshotVersion)
	binary.LittleEndian.PutUint32(
		out[allocatorSnapshotHeaderSizeOffset:],
		uint32(AllocatorSnapshotEnvelopeHeaderBytes))
	copy(
		out[allocatorSnapshotDomainOffset:allocatorSnapshotPayloadLengthOffset],
		allocatorSnapshotDomain[:])
	binary.LittleEndian.PutUint64(
		out[allocatorSnapshotPayloadLengthOffset:],
		exactLength-AllocatorSnapshotEnvelopeHeaderBytes)

	copy(
		out[allocatorSnapshotDeviceDigestOffset:allocatorSnapshotOwnerDigestOffset],
		snapshot.DeviceBindingSHA256[:])
	copy(
		out[allocatorSnapshotOwnerDigestOffset:allocatorSnapshotOwnerEpochOffset],
		snapshot.OwnerIdentitySHA256[:])
	binary.LittleEndian.PutUint64(out[allocatorSnapshotOwnerEpochOffset:], snapshot.OwnerEpoch)
	binary.LittleEndian.PutUint64(out[allocatorSnapshotSequenceOffset:], snapshot.SnapshotSequence)
	binary.LittleEndian.PutUint64(
		out[allocatorSnapshotNextAllocationOffset:], snapshot.NextAllocationRecordID)
	binary.LittleEndian.PutUint64(
		out[allocatorSnapshotNextTransactionOffset:], snapshot.NextOwnerTransactionSeq)
	binary.LittleEndian.PutUint64(
		out[allocatorSnapshotOwnerJournalOffset:], snapshot.OwnerJournalSequence)
	binary.LittleEndian.PutUint64(out[allocatorSnapshotDataPageCountOffset:], snapshot.DataPageCount)
	binary.LittleEndian.PutUint64(
		out[allocatorSnapshotAllocatedCountOffset:], snapshot.AllocatedPageCount)
	binary.LittleEndian.PutUint64(out[allocatorSnapshotBitmapLengthOffset:], snapshot.BitmapByteLength)
	copy(out[allocatorSnapshotBitmapOffset:], snapshot.allocationBitmap)

	payload := out[AllocatorSnapshotEnvelopeHeaderBytes:]
	binary.LittleEndian.PutUint32(
		out[allocatorSnapshotPayloadCRCOffset:],
		allocatorSnapshotCRC32C(payload))
	binary.LittleEndian.PutUint32(
		out[allocatorSnapshotHeaderCRCOffset:],
		allocatorSnapshotHeaderCRC32C(out[:AllocatorSnapshotEnvelopeHeaderBytes]))
	return out, nil
}

// ParseAllocatorSnapshot accepts exactly one complete canonical TRALC007
// envelope. The configured 64 MiB maximum slot bound and all declared lengths
// are checked before a bitmap copy or canonical re-encoding allocation occurs.
func ParseAllocatorSnapshot(
	data []byte,
	geometry DeviceGeometry,
) (AllocatorSnapshot, error) {
	if err := geometry.Validate(); err != nil {
		return AllocatorSnapshot{}, err
	}
	if !allocatorSnapshotCompiledContractValid() {
		return AllocatorSnapshot{}, allocatorSnapshotCorruptf("compiled TRALC007 wire contract is invalid")
	}
	if len(data) < int(AllocatorSnapshotEnvelopeHeaderBytes) {
		return AllocatorSnapshot{}, allocatorSnapshotCorruptf(
			"envelope is truncated at %d bytes", len(data))
	}
	if uint64(len(data)) > geometry.AllocatorSnapshotSlotBytes {
		return AllocatorSnapshot{}, allocatorSnapshotCorruptf(
			"envelope is %d bytes, slot capacity is %d",
			len(data),
			geometry.AllocatorSnapshotSlotBytes)
	}
	var magic [8]byte
	copy(magic[:], data[allocatorSnapshotMagicOffset:allocatorSnapshotVersionOffset])
	if magic != allocatorSnapshotMagic {
		return AllocatorSnapshot{}, allocatorSnapshotWrongFormatf(
			"magic %q is not %q", magic, allocatorSnapshotMagic)
	}
	if version := binary.LittleEndian.Uint32(data[allocatorSnapshotVersionOffset:]); version != AllocatorSnapshotVersion {
		return AllocatorSnapshot{}, allocatorSnapshotWrongFormatf(
			"version %d is not %d", version, AllocatorSnapshotVersion)
	}
	if size := binary.LittleEndian.Uint32(data[allocatorSnapshotHeaderSizeOffset:]); size != uint32(AllocatorSnapshotEnvelopeHeaderBytes) {
		return AllocatorSnapshot{}, allocatorSnapshotWrongFormatf(
			"header size %d is not %d", size, AllocatorSnapshotEnvelopeHeaderBytes)
	}
	var domain [allocatorSnapshotDomainFieldBytes]byte
	copy(domain[:], data[allocatorSnapshotDomainOffset:allocatorSnapshotPayloadLengthOffset])
	if domain != allocatorSnapshotDomain {
		return AllocatorSnapshot{}, allocatorSnapshotWrongFormatf(
			"domain does not equal %q", AllocatorSnapshotDomain)
	}
	if flags := binary.LittleEndian.Uint32(data[allocatorSnapshotFlagsOffset:]); flags != 0 {
		return AllocatorSnapshot{}, allocatorSnapshotWrongFormatf(
			"mandatory flags %#x are not zero", flags)
	}
	if !allocatorSnapshotAllZero(
		data[allocatorSnapshotReservedOffset:AllocatorSnapshotEnvelopeHeaderBytes]) {
		return AllocatorSnapshot{}, allocatorSnapshotWrongFormatf("reserved header bytes are nonzero")
	}
	wantHeaderCRC := binary.LittleEndian.Uint32(data[allocatorSnapshotHeaderCRCOffset:])
	if got := allocatorSnapshotHeaderCRC32C(data[:AllocatorSnapshotEnvelopeHeaderBytes]); got != wantHeaderCRC {
		return AllocatorSnapshot{}, allocatorSnapshotCorruptf(
			"header CRC32C %#08x does not equal stored %#08x", got, wantHeaderCRC)
	}
	payloadLength := binary.LittleEndian.Uint64(data[allocatorSnapshotPayloadLengthOffset:])
	if payloadLength > cxlcheckpoint.MaxSignedLong ||
		payloadLength > geometry.AllocatorSnapshotSlotBytes-AllocatorSnapshotEnvelopeHeaderBytes {
		return AllocatorSnapshot{}, allocatorSnapshotCorruptf(
			"payload length %d exceeds its configured bound", payloadLength)
	}
	totalLength, ok := checkedAdd(AllocatorSnapshotEnvelopeHeaderBytes, payloadLength)
	if !ok || totalLength != uint64(len(data)) {
		return AllocatorSnapshot{}, allocatorSnapshotCorruptf(
			"envelope is %d bytes, header declares %d", len(data), totalLength)
	}
	if payloadLength < allocatorSnapshotFixedPayloadBytes {
		return AllocatorSnapshot{}, allocatorSnapshotCorruptf(
			"payload length %d is shorter than fixed payload %d",
			payloadLength,
			allocatorSnapshotFixedPayloadBytes)
	}
	payload := data[AllocatorSnapshotEnvelopeHeaderBytes:]
	wantPayloadCRC := binary.LittleEndian.Uint32(data[allocatorSnapshotPayloadCRCOffset:])
	if got := allocatorSnapshotCRC32C(payload); got != wantPayloadCRC {
		return AllocatorSnapshot{}, allocatorSnapshotCorruptf(
			"payload CRC32C %#08x does not equal stored %#08x", got, wantPayloadCRC)
	}

	snapshot := AllocatorSnapshot{}
	copy(
		snapshot.DeviceBindingSHA256[:],
		data[allocatorSnapshotDeviceDigestOffset:allocatorSnapshotOwnerDigestOffset])
	copy(
		snapshot.OwnerIdentitySHA256[:],
		data[allocatorSnapshotOwnerDigestOffset:allocatorSnapshotOwnerEpochOffset])
	snapshot.OwnerEpoch = binary.LittleEndian.Uint64(data[allocatorSnapshotOwnerEpochOffset:])
	snapshot.SnapshotSequence = binary.LittleEndian.Uint64(data[allocatorSnapshotSequenceOffset:])
	snapshot.NextAllocationRecordID = binary.LittleEndian.Uint64(
		data[allocatorSnapshotNextAllocationOffset:])
	snapshot.NextOwnerTransactionSeq = binary.LittleEndian.Uint64(
		data[allocatorSnapshotNextTransactionOffset:])
	snapshot.OwnerJournalSequence = binary.LittleEndian.Uint64(
		data[allocatorSnapshotOwnerJournalOffset:])
	snapshot.DataPageCount = binary.LittleEndian.Uint64(data[allocatorSnapshotDataPageCountOffset:])
	snapshot.AllocatedPageCount = binary.LittleEndian.Uint64(
		data[allocatorSnapshotAllocatedCountOffset:])
	snapshot.BitmapByteLength = binary.LittleEndian.Uint64(
		data[allocatorSnapshotBitmapLengthOffset:])

	expectedBitmapBytes, err := geometry.AllocationBitmapBytes()
	if err != nil {
		return AllocatorSnapshot{}, err
	}
	if snapshot.BitmapByteLength != expectedBitmapBytes {
		return AllocatorSnapshot{}, allocatorSnapshotCorruptf(
			"bitmap length %d does not equal geometry length %d",
			snapshot.BitmapByteLength,
			expectedBitmapBytes)
	}
	expectedPayloadLength, ok := checkedAdd(
		allocatorSnapshotFixedPayloadBytes,
		snapshot.BitmapByteLength)
	if !ok || expectedPayloadLength != payloadLength {
		return AllocatorSnapshot{}, allocatorSnapshotCorruptf(
			"payload length %d does not equal fixed-plus-bitmap length %d",
			payloadLength,
			expectedPayloadLength)
	}
	snapshot.allocationBitmap = data[allocatorSnapshotBitmapOffset:]
	if err := allocatorSnapshotValidateForGeometry(snapshot, geometry); err != nil {
		return AllocatorSnapshot{}, allocatorSnapshotCorruptf("decoded snapshot is invalid: %v", err)
	}
	canonical, err := CanonicalAllocatorSnapshotBytes(snapshot, geometry)
	if err != nil {
		return AllocatorSnapshot{}, allocatorSnapshotCorruptf("canonical re-encode failed: %v", err)
	}
	if !bytes.Equal(canonical, data) {
		return AllocatorSnapshot{}, allocatorSnapshotCorruptf("envelope is not canonically encoded")
	}
	snapshot.allocationBitmap = append([]byte(nil), snapshot.allocationBitmap...)
	return snapshot, nil
}

// EncodeAllocatorSnapshotForStorage returns detached exact and full-slot
// images. The padded tail is zero; publishing or selecting that slot belongs
// to a later Owner I/O state machine.
func EncodeAllocatorSnapshotForStorage(
	snapshot AllocatorSnapshot,
	geometry DeviceGeometry,
) (AllocatorSnapshotStorage, error) {
	exact, err := CanonicalAllocatorSnapshotBytes(snapshot, geometry)
	if err != nil {
		return AllocatorSnapshotStorage{}, err
	}
	padded := make([]byte, int(geometry.AllocatorSnapshotSlotBytes))
	copy(padded, exact)
	return AllocatorSnapshotStorage{
		exactBytes:  exact,
		paddedBytes: padded,
		sha256:      sha256.Sum256(exact),
	}, nil
}

// ExactBytes returns a detached copy of the canonical envelope.
func (storage AllocatorSnapshotStorage) ExactBytes() []byte {
	return append([]byte(nil), storage.exactBytes...)
}

// PaddedBytes returns a detached copy of the complete zero-padded slot image.
func (storage AllocatorSnapshotStorage) PaddedBytes() []byte {
	return append([]byte(nil), storage.paddedBytes...)
}

func (storage AllocatorSnapshotStorage) ExactLength() uint64 {
	return uint64(len(storage.exactBytes))
}

func (storage AllocatorSnapshotStorage) SlotLength() uint64 {
	return uint64(len(storage.paddedBytes))
}

// SHA256 returns the digest of the exact canonical envelope, excluding slot
// padding. A later superblock may bind this value without copying ExactBytes.
func (storage AllocatorSnapshotStorage) SHA256() [sha256.Size]byte {
	return storage.sha256
}

func allocatorSnapshotValidateForGeometry(
	snapshot AllocatorSnapshot,
	geometry DeviceGeometry,
) error {
	if err := geometry.Validate(); err != nil {
		return err
	}
	if err := snapshot.Validate(); err != nil {
		return err
	}
	if snapshot.DataPageCount != geometry.DataPageCount {
		return allocatorSnapshotInvalidf(
			"data-page count %d does not equal geometry count %d",
			snapshot.DataPageCount,
			geometry.DataPageCount)
	}
	exactLength, ok := checkedAdd(AllocatorSnapshotFixedBytes, snapshot.BitmapByteLength)
	if !ok || exactLength > geometry.AllocatorSnapshotSlotBytes {
		return allocatorSnapshotInvalidf(
			"encoded length %d exceeds allocator snapshot slot %d",
			exactLength,
			geometry.AllocatorSnapshotSlotBytes)
	}
	return nil
}

func allocatorSnapshotBitmapByteCount(dataPageCount uint64) (uint64, error) {
	if dataPageCount == 0 || dataPageCount > cxlcheckpoint.MaxSignedLong {
		return 0, allocatorSnapshotInvalidf(
			"data-page count %d is outside 1..%d",
			dataPageCount,
			cxlcheckpoint.MaxSignedLong)
	}
	plusSeven, ok := checkedAdd(dataPageCount, 7)
	if !ok {
		return 0, allocatorSnapshotInvalidf("bitmap byte count overflows")
	}
	return plusSeven / 8, nil
}

func allocatorSnapshotValidateUnusedHighBits(bitmap []byte, dataPageCount uint64) error {
	remainder := dataPageCount % 8
	if remainder == 0 {
		return nil
	}
	if len(bitmap) == 0 {
		return allocatorSnapshotInvalidf("nonzero data-page count has an empty bitmap")
	}
	validMask := byte((uint16(1) << uint(remainder)) - 1)
	if bitmap[len(bitmap)-1]&^validMask != 0 {
		return allocatorSnapshotInvalidf("unused high bits in the final bitmap byte are nonzero")
	}
	return nil
}

func allocatorSnapshotPopcount(bitmap []byte) uint64 {
	var count uint64
	for _, value := range bitmap {
		count += uint64(bits.OnesCount8(value))
	}
	return count
}

func allocatorSnapshotCRC32C(data []byte) uint32 {
	return crc32.Checksum(data, allocatorSnapshotCRC32CTable)
}

func allocatorSnapshotHeaderCRC32C(header []byte) uint32 {
	if len(header) != int(AllocatorSnapshotEnvelopeHeaderBytes) {
		return 0
	}
	checksum := crc32.Update(
		0,
		allocatorSnapshotCRC32CTable,
		header[:allocatorSnapshotHeaderCRCOffset])
	checksum = crc32.Update(
		checksum,
		allocatorSnapshotCRC32CTable,
		allocatorSnapshotZeroCRCField[:])
	return crc32.Update(
		checksum,
		allocatorSnapshotCRC32CTable,
		header[allocatorSnapshotReservedOffset:AllocatorSnapshotEnvelopeHeaderBytes])
}

func allocatorSnapshotAllZero(data []byte) bool {
	for _, value := range data {
		if value != 0 {
			return false
		}
	}
	return true
}

func allocatorSnapshotCompiledContractValid() bool {
	if AllocatorSnapshotMagicString != "TRALC007" ||
		string(allocatorSnapshotMagic[:]) != AllocatorSnapshotMagicString ||
		AllocatorSnapshotVersion != 7 ||
		AllocatorSnapshotDomain != "allocation-bitmap-v1" ||
		len(AllocatorSnapshotDomain) > allocatorSnapshotDomainFieldBytes ||
		AllocatorSnapshotEnvelopeHeaderBytes != 64 ||
		AllocatorSnapshotFixedBytes != 192 ||
		allocatorSnapshotFixedPayloadBytes != 128 {
		return false
	}
	if string(allocatorSnapshotDomain[:len(AllocatorSnapshotDomain)]) != AllocatorSnapshotDomain {
		return false
	}
	return allocatorSnapshotAllZero(allocatorSnapshotDomain[len(AllocatorSnapshotDomain):])
}

func allocatorSnapshotInvalidf(format string, arguments ...interface{}) error {
	return fmt.Errorf("%w: %s", ErrInvalidAllocatorSnapshot, fmt.Sprintf(format, arguments...))
}

func allocatorSnapshotWrongFormatf(format string, arguments ...interface{}) error {
	return fmt.Errorf("%w: %s", ErrWrongAllocatorSnapshotFormat, fmt.Sprintf(format, arguments...))
}

func allocatorSnapshotCorruptf(format string, arguments ...interface{}) error {
	return fmt.Errorf("%w: %s", ErrCorruptAllocatorSnapshot, fmt.Sprintf(format, arguments...))
}

func allocatorSnapshotMismatchf(format string, arguments ...interface{}) error {
	return fmt.Errorf("%w: %s", ErrAllocatorSnapshotMismatch, fmt.Sprintf(format, arguments...))
}

package trcxl007

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"hash/crc32"

	"github.com/containerd/containerd/third_party/trenv-containerd/pkg/cxlcheckpoint"
)

const (
	ownerStateDomainFieldBytes = 32

	ownerStateMagicOffset         = 0
	ownerStateVersionOffset       = 8
	ownerStateHeaderSizeOffset    = 12
	ownerStateDomainOffset        = 16
	ownerStatePayloadLengthOffset = 48
	ownerStatePayloadCRCOffset    = 56
	ownerStateHeaderCRCOffset     = 60

	ownerStateStateFieldBytes = 8

	ownerStateMinimumDeviceWireBytes   uint64 = 53  // one-byte UUID plus fixed fields
	ownerStateMinimumRecordWireBytes   uint64 = 273 // five one-byte IDs plus fixed fields
	ownerStateContentDemandWireBytes   uint64 = 40
	ownerStateMinimumFragmentWireBytes uint64 = 29 // one-byte UUID plus fixed fields
	ownerStateExtentWireBytes          uint64 = 24
	ownerStateAuthorityWireBytes       uint64 = 4 * sha256.Size
	ownerStateRecordTailWireBytes      uint64 = ownerStateAuthorityWireBytes + sha256.Size
)

var (
	ownerStateMagic  = [8]byte{'T', 'R', 'O', 'W', 'N', '0', '0', '7'}
	ownerStateDomain = func() [ownerStateDomainFieldBytes]byte {
		var value [ownerStateDomainFieldBytes]byte
		copy(value[:], OwnerStateDomain)
		return value
	}()
	ownerStateCRC32CTable  = crc32.MakeTable(crc32.Castagnoli)
	ownerStateZeroCRCField [4]byte
)

// CanonicalOwnerStateBytes returns one exact TROWN007 envelope. It checks the
// complete encoded length against the configured Owner-state slot before
// allocating an output buffer.
func CanonicalOwnerStateBytes(
	snapshot OwnerStateSnapshot,
	geometry DeviceGeometry,
) ([]byte, error) {
	if err := geometry.Validate(); err != nil {
		return nil, err
	}
	if err := snapshot.Validate(); err != nil {
		return nil, err
	}
	payloadLength, err := ownerStatePayloadLength(snapshot)
	if err != nil {
		return nil, err
	}
	exactLength, ok := checkedAdd(OwnerStateEnvelopeHeaderBytes, payloadLength)
	if !ok || exactLength > geometry.OwnerStateSnapshotSlotBytes {
		return nil, ownerStateMetadataFullf(
			"canonical snapshot needs %d bytes, slot capacity is %d",
			exactLength, geometry.OwnerStateSnapshotSlotBytes)
	}
	if exactLength > uint64(maxIntValue()) {
		return nil, ownerStateMetadataFullf("canonical snapshot length %d exceeds host int", exactLength)
	}

	payload := make([]byte, 0, int(payloadLength))
	payload = ownerStateAppendString(payload, snapshot.ClusterID)
	payload = ownerStateAppendString(payload, snapshot.OwnerGroupID)
	payload = ownerStateAppendString(payload, snapshot.CurrentOwnerID)
	payload = ownerStateAppendString(payload, snapshot.AnchorDeviceUUID)
	payload = ownerStateAppendString(payload, snapshot.StorageCompatibilityID)
	payload = ownerStateAppendU64(payload, snapshot.OwnerEpoch)
	payload = ownerStateAppendU64(payload, snapshot.GroupConfigurationSequence)
	payload = append(payload, snapshot.MembershipSHA256[:]...)
	payload = ownerStateAppendU64(payload, snapshot.SnapshotSequence)
	payload = ownerStateAppendU64(payload, snapshot.NextAllocationRecordID)
	payload = ownerStateAppendU64(payload, snapshot.NextOwnerTransactionSequence)
	payload = ownerStateAppendU32(payload, uint32(len(snapshot.devices)))
	payload = ownerStateAppendU32(payload, uint32(len(snapshot.records)))
	for _, device := range snapshot.devices {
		payload = ownerStateAppendString(payload, device.DeviceUUID)
		payload = ownerStateAppendU64(payload, device.DeviceOwnerEpoch)
		payload = ownerStateAppendU64(payload, device.DataPageCount)
		payload = append(payload, device.DeviceBindingSHA256[:]...)
	}
	for _, record := range snapshot.records {
		payload = ownerStateAppendRecord(payload, record)
	}
	if uint64(len(payload)) != payloadLength {
		return nil, ownerStateInvalidf(
			"internal payload length %d does not equal preflight length %d",
			len(payload), payloadLength)
	}

	wire := make([]byte, int(exactLength))
	copy(wire[ownerStateMagicOffset:ownerStateVersionOffset], ownerStateMagic[:])
	binary.LittleEndian.PutUint32(wire[ownerStateVersionOffset:], OwnerStateVersion)
	binary.LittleEndian.PutUint32(
		wire[ownerStateHeaderSizeOffset:], uint32(OwnerStateEnvelopeHeaderBytes))
	copy(wire[ownerStateDomainOffset:ownerStatePayloadLengthOffset], ownerStateDomain[:])
	binary.LittleEndian.PutUint64(wire[ownerStatePayloadLengthOffset:], payloadLength)
	binary.LittleEndian.PutUint32(wire[ownerStatePayloadCRCOffset:], ownerStateCRC32C(payload))
	copy(wire[OwnerStateEnvelopeHeaderBytes:], payload)
	binary.LittleEndian.PutUint32(
		wire[ownerStateHeaderCRCOffset:],
		ownerStateHeaderCRC32C(wire[:OwnerStateEnvelopeHeaderBytes]))
	return wire, nil
}

// ParseOwnerState accepts exactly one canonical envelope. Slot capacity and
// every declared count/length are bounded before constructing a variable-size
// table or retaining input bytes.
func ParseOwnerState(data []byte, geometry DeviceGeometry) (OwnerStateSnapshot, error) {
	if err := geometry.Validate(); err != nil {
		return OwnerStateSnapshot{}, err
	}
	if !ownerStateCompiledContractValid() {
		return OwnerStateSnapshot{}, ownerStateCorruptf("compiled TROWN007 wire contract is invalid")
	}
	if len(data) < int(OwnerStateEnvelopeHeaderBytes) {
		return OwnerStateSnapshot{}, ownerStateCorruptf("envelope is truncated at %d bytes", len(data))
	}
	if uint64(len(data)) > geometry.OwnerStateSnapshotSlotBytes {
		return OwnerStateSnapshot{}, ownerStateCorruptf(
			"envelope is %d bytes, slot capacity is %d",
			len(data), geometry.OwnerStateSnapshotSlotBytes)
	}
	if !bytes.Equal(data[ownerStateMagicOffset:ownerStateVersionOffset], ownerStateMagic[:]) {
		return OwnerStateSnapshot{}, ownerStateWrongFormatf("magic is not %q", OwnerStateMagicString)
	}
	if version := binary.LittleEndian.Uint32(data[ownerStateVersionOffset:]); version != OwnerStateVersion {
		return OwnerStateSnapshot{}, ownerStateWrongFormatf(
			"version %d is not %d", version, OwnerStateVersion)
	}
	if size := binary.LittleEndian.Uint32(data[ownerStateHeaderSizeOffset:]); size != uint32(OwnerStateEnvelopeHeaderBytes) {
		return OwnerStateSnapshot{}, ownerStateWrongFormatf(
			"header size %d is not %d", size, OwnerStateEnvelopeHeaderBytes)
	}
	if !bytes.Equal(
		data[ownerStateDomainOffset:ownerStatePayloadLengthOffset], ownerStateDomain[:]) {
		return OwnerStateSnapshot{}, ownerStateWrongFormatf("domain is not %q", OwnerStateDomain)
	}
	wantHeaderCRC := binary.LittleEndian.Uint32(data[ownerStateHeaderCRCOffset:])
	if got := ownerStateHeaderCRC32C(data[:OwnerStateEnvelopeHeaderBytes]); got != wantHeaderCRC {
		return OwnerStateSnapshot{}, ownerStateCorruptf(
			"header CRC32C %#08x does not equal stored %#08x", got, wantHeaderCRC)
	}
	payloadLength := binary.LittleEndian.Uint64(data[ownerStatePayloadLengthOffset:])
	if payloadLength > geometry.OwnerStateSnapshotSlotBytes-OwnerStateEnvelopeHeaderBytes {
		return OwnerStateSnapshot{}, ownerStateCorruptf(
			"payload length %d exceeds configured bound %d",
			payloadLength,
			geometry.OwnerStateSnapshotSlotBytes-OwnerStateEnvelopeHeaderBytes)
	}
	totalLength, ok := checkedAdd(OwnerStateEnvelopeHeaderBytes, payloadLength)
	if !ok || totalLength != uint64(len(data)) {
		return OwnerStateSnapshot{}, ownerStateCorruptf(
			"envelope is %d bytes, header declares %d", len(data), totalLength)
	}
	payload := data[OwnerStateEnvelopeHeaderBytes:]
	wantPayloadCRC := binary.LittleEndian.Uint32(data[ownerStatePayloadCRCOffset:])
	if got := ownerStateCRC32C(payload); got != wantPayloadCRC {
		return OwnerStateSnapshot{}, ownerStateCorruptf(
			"payload CRC32C %#08x does not equal stored %#08x", got, wantPayloadCRC)
	}

	decoder := ownerStateDecoder{payload: payload}
	snapshot, err := decoder.snapshot()
	if err != nil {
		return OwnerStateSnapshot{}, err
	}
	if decoder.remaining() != 0 {
		return OwnerStateSnapshot{}, ownerStateCorruptf(
			"payload has %d trailing bytes", decoder.remaining())
	}
	if err := snapshot.Validate(); err != nil {
		return OwnerStateSnapshot{}, ownerStateCorruptf("decoded snapshot is invalid: %v", err)
	}
	canonical, err := CanonicalOwnerStateBytes(snapshot, geometry)
	if err != nil {
		return OwnerStateSnapshot{}, ownerStateCorruptf("canonical re-encode failed: %v", err)
	}
	if !bytes.Equal(canonical, data) {
		return OwnerStateSnapshot{}, ownerStateCorruptf("envelope is not canonically encoded")
	}
	snapshot.rebuildIndexes()
	return snapshot, nil
}

// EncodeOwnerStateForStorage returns detached exact bytes, their SHA-256, and
// the configured slot length. It deliberately allocates no full padded slot.
func EncodeOwnerStateForStorage(
	snapshot OwnerStateSnapshot,
	geometry DeviceGeometry,
) (OwnerStateStorage, error) {
	exact, err := CanonicalOwnerStateBytes(snapshot, geometry)
	if err != nil {
		return OwnerStateStorage{}, err
	}
	return OwnerStateStorage{
		exactBytes: exact,
		sha256:     sha256.Sum256(exact),
		slotLength: geometry.OwnerStateSnapshotSlotBytes,
	}, nil
}

func (storage OwnerStateStorage) ExactBytes() []byte {
	return append([]byte(nil), storage.exactBytes...)
}

func (storage OwnerStateStorage) ExactLength() uint64 {
	return uint64(len(storage.exactBytes))
}

func (storage OwnerStateStorage) SHA256() [sha256.Size]byte {
	return storage.sha256
}

func (storage OwnerStateStorage) SlotLength() uint64 {
	return storage.slotLength
}

// SelectLatestValidOwnerState selects the highest self-valid TROWN007 A/B
// snapshot. An all-zero byte range is absent. A slot reader may supply either
// exact envelope bytes or a complete slot image; bytes after a valid declared
// envelope are stale slot tail and are not part of the canonical state.
func SelectLatestValidOwnerState(
	slotA []byte,
	slotB []byte,
	geometry DeviceGeometry,
) (OwnerStateSlot, OwnerStateSnapshot, error) {
	type candidate struct {
		slot     OwnerStateSlot
		exact    []byte
		snapshot OwnerStateSnapshot
		err      error
		blank    bool
	}
	parse := func(slot OwnerStateSlot, input []byte) candidate {
		result := candidate{slot: slot}
		if len(input) > 0 && ownerStateAllZero(input) {
			result.blank = true
			return result
		}
		result.exact, result.err = ownerStateExactEnvelopeFromSlot(input, geometry)
		if result.err != nil {
			return result
		}
		result.snapshot, result.err = ParseOwnerState(result.exact, geometry)
		return result
	}
	left := parse(OwnerStateSlotA, slotA)
	right := parse(OwnerStateSlotB, slotB)
	leftValid := !left.blank && left.err == nil
	rightValid := !right.blank && right.err == nil
	switch {
	case leftValid && !rightValid:
		return left.slot, left.snapshot, nil
	case !leftValid && rightValid:
		return right.slot, right.snapshot, nil
	case !leftValid && !rightValid:
		return 0, OwnerStateSnapshot{}, fmt.Errorf(
			"%w: slot A %s; slot B %s",
			ErrNoValidOwnerState,
			ownerStateCandidateFailure(left.blank, left.err),
			ownerStateCandidateFailure(right.blank, right.err))
	}
	if left.snapshot.SnapshotSequence > right.snapshot.SnapshotSequence {
		return left.slot, left.snapshot, nil
	}
	if right.snapshot.SnapshotSequence > left.snapshot.SnapshotSequence {
		return right.slot, right.snapshot, nil
	}
	if !bytes.Equal(left.exact, right.exact) {
		return 0, OwnerStateSnapshot{}, fmt.Errorf(
			"%w: valid slot A and B both claim sequence %d with different bytes",
			ErrOwnerStateSplitBrain,
			left.snapshot.SnapshotSequence)
	}
	return left.slot, left.snapshot, nil
}

func ownerStateExactEnvelopeFromSlot(
	input []byte,
	geometry DeviceGeometry,
) ([]byte, error) {
	if err := geometry.Validate(); err != nil {
		return nil, err
	}
	if len(input) < int(OwnerStateEnvelopeHeaderBytes) {
		return nil, ownerStateCorruptf("slot image is truncated at %d bytes", len(input))
	}
	if uint64(len(input)) > geometry.OwnerStateSnapshotSlotBytes {
		return nil, ownerStateCorruptf(
			"slot image is %d bytes, capacity is %d", len(input), geometry.OwnerStateSnapshotSlotBytes)
	}
	payloadLength := binary.LittleEndian.Uint64(input[ownerStatePayloadLengthOffset:])
	if payloadLength > geometry.OwnerStateSnapshotSlotBytes-OwnerStateEnvelopeHeaderBytes {
		return nil, ownerStateCorruptf("slot payload length %d exceeds capacity", payloadLength)
	}
	total, ok := checkedAdd(OwnerStateEnvelopeHeaderBytes, payloadLength)
	if !ok || total > uint64(len(input)) {
		return nil, ownerStateCorruptf(
			"slot has %d bytes, header requires %d", len(input), total)
	}
	return input[:total], nil
}

func ownerStatePayloadLength(snapshot OwnerStateSnapshot) (uint64, error) {
	var length uint64
	add := func(value uint64) error {
		var ok bool
		length, ok = checkedAdd(length, value)
		if !ok {
			return ownerStateMetadataFullf("encoded length overflows")
		}
		return nil
	}
	addString := func(value string) error {
		return add(4 + uint64(len(value)))
	}
	for _, value := range []string{
		snapshot.ClusterID,
		snapshot.OwnerGroupID,
		snapshot.CurrentOwnerID,
		snapshot.AnchorDeviceUUID,
		snapshot.StorageCompatibilityID,
	} {
		if err := addString(value); err != nil {
			return 0, err
		}
	}
	if err := add(80); err != nil { // six u64, membership SHA-256, and two u32 counts
		return 0, err
	}
	for _, device := range snapshot.devices {
		if err := addString(device.DeviceUUID); err != nil {
			return 0, err
		}
		if err := add(48); err != nil { // two u64 and one SHA-256
			return 0, err
		}
	}
	for _, record := range snapshot.records {
		if err := add(248); err != nil { // fixed scalars, digests, counts, evidence, and seal
			return 0, err
		}
		for _, value := range []string{
			record.RequestID,
			record.CheckpointID,
			record.ProducerID,
			record.DedupDomainID,
			record.SharingPolicyID,
		} {
			if err := addString(value); err != nil {
				return 0, err
			}
		}
		if err := add(uint64(len(record.ContentDemands)) * 40); err != nil {
			return 0, err
		}
		for _, fragment := range record.Fragments {
			if err := addString(fragment.DeviceUUID); err != nil {
				return 0, err
			}
			if err := add(24); err != nil { // two u64 plus extent count/reserved
				return 0, err
			}
			if err := add(uint64(len(fragment.Extents)) * 24); err != nil {
				return 0, err
			}
		}
	}
	return length, nil
}

func ownerStateAppendRecord(destination []byte, record OwnerStateAllocationRecord) []byte {
	destination = ownerStateAppendU64(destination, record.AllocationRecordID)
	destination = ownerStateAppendU64(destination, record.ReservationTransactionSequence)
	destination = ownerStateAppendU64(destination, record.OwnerTransactionSequence)
	destination = append(destination, byte(record.State))
	destination = append(destination, make([]byte, ownerStateStateFieldBytes-1)...)
	destination = ownerStateAppendString(destination, record.RequestID)
	destination = ownerStateAppendString(destination, record.CheckpointID)
	destination = ownerStateAppendString(destination, record.ProducerID)
	destination = ownerStateAppendString(destination, record.DedupDomainID)
	destination = ownerStateAppendString(destination, record.SharingPolicyID)
	destination = append(destination, record.RequestSHA256[:]...)
	destination = ownerStateAppendU64(destination, record.TotalDemandPages)
	destination = ownerStateAppendU32(destination, record.MaxExtents)
	destination = ownerStateAppendU32(destination, uint32(len(record.ContentDemands)))
	for _, demand := range record.ContentDemands {
		destination = append(destination, byte(demand.Kind))
		destination = append(destination, make([]byte, 7)...)
		destination = ownerStateAppendU64(destination, demand.ObjectID)
		destination = ownerStateAppendU64(destination, demand.ByteLength)
		destination = ownerStateAppendU64(destination, demand.CapacityPages)
		destination = ownerStateAppendU64(destination, demand.LogicalPageStart)
	}
	destination = ownerStateAppendU32(destination, uint32(len(record.Fragments)))
	destination = append(destination, make([]byte, 4)...)
	for _, fragment := range record.Fragments {
		destination = ownerStateAppendString(destination, fragment.DeviceUUID)
		destination = ownerStateAppendU64(destination, fragment.DeviceOwnerEpoch)
		destination = ownerStateAppendU64(destination, fragment.TargetAllocatorSnapshotSequence)
		destination = ownerStateAppendU32(destination, uint32(len(fragment.Extents)))
		destination = append(destination, make([]byte, 4)...)
		for _, extent := range fragment.Extents {
			destination = ownerStateAppendU64(destination, extent.StartDataPageIndex)
			destination = ownerStateAppendU64(destination, extent.LogicalPageStart)
			destination = ownerStateAppendU64(destination, extent.PageCount)
		}
	}
	destination = append(destination, record.AuthorityEvidence.SchedulerReserveSHA256[:]...)
	destination = append(destination, record.AuthorityEvidence.ProducerCapabilitySHA256[:]...)
	destination = append(destination, record.AuthorityEvidence.PublicationAuthoritySHA256[:]...)
	destination = append(destination, record.AuthorityEvidence.ReclaimAuthoritySHA256[:]...)
	return append(destination, record.OwnerVerifiedSealSHA256[:]...)
}

type ownerStateDecoder struct {
	payload []byte
	offset  int
}

func (decoder *ownerStateDecoder) snapshot() (OwnerStateSnapshot, error) {
	var snapshot OwnerStateSnapshot
	var err error
	if snapshot.ClusterID, err = decoder.text("cluster ID"); err != nil {
		return OwnerStateSnapshot{}, err
	}
	if snapshot.OwnerGroupID, err = decoder.text("Owner-group ID"); err != nil {
		return OwnerStateSnapshot{}, err
	}
	if snapshot.CurrentOwnerID, err = decoder.text("current Owner ID"); err != nil {
		return OwnerStateSnapshot{}, err
	}
	if snapshot.AnchorDeviceUUID, err = decoder.text("anchor device UUID"); err != nil {
		return OwnerStateSnapshot{}, err
	}
	if snapshot.StorageCompatibilityID, err = decoder.text("storage compatibility ID"); err != nil {
		return OwnerStateSnapshot{}, err
	}
	if snapshot.OwnerEpoch, err = decoder.u64("Owner epoch"); err != nil {
		return OwnerStateSnapshot{}, err
	}
	if snapshot.GroupConfigurationSequence, err = decoder.u64("group-configuration sequence"); err != nil {
		return OwnerStateSnapshot{}, err
	}
	membership, err := decoder.bytes("membership SHA-256", sha256.Size)
	if err != nil {
		return OwnerStateSnapshot{}, err
	}
	copy(snapshot.MembershipSHA256[:], membership)
	if snapshot.SnapshotSequence, err = decoder.u64("snapshot sequence"); err != nil {
		return OwnerStateSnapshot{}, err
	}
	if snapshot.NextAllocationRecordID, err = decoder.u64("next allocation-record ID"); err != nil {
		return OwnerStateSnapshot{}, err
	}
	if snapshot.NextOwnerTransactionSequence, err = decoder.u64("next Owner-transaction sequence"); err != nil {
		return OwnerStateSnapshot{}, err
	}
	deviceCount, err := decoder.count("device", MaxOwnerStateDevices)
	if err != nil {
		return OwnerStateSnapshot{}, err
	}
	recordCount, err := decoder.count("allocation record", MaxOwnerStateRecords)
	if err != nil {
		return OwnerStateSnapshot{}, err
	}
	minimumRecordBytes, ok := checkedMul(
		uint64(recordCount), ownerStateMinimumRecordWireBytes)
	if !ok {
		return OwnerStateSnapshot{}, ownerStateCorruptf("minimum allocation-record bytes overflow")
	}
	if err := decoder.requireTable(
		"device", deviceCount, ownerStateMinimumDeviceWireBytes, minimumRecordBytes); err != nil {
		return OwnerStateSnapshot{}, err
	}
	snapshot.devices = make([]OwnerStateDevice, deviceCount)
	for index := range snapshot.devices {
		device := &snapshot.devices[index]
		if device.DeviceUUID, err = decoder.text("device UUID"); err != nil {
			return OwnerStateSnapshot{}, err
		}
		if device.DeviceOwnerEpoch, err = decoder.u64("device Owner epoch"); err != nil {
			return OwnerStateSnapshot{}, err
		}
		if device.DataPageCount, err = decoder.u64("device data-page count"); err != nil {
			return OwnerStateSnapshot{}, err
		}
		digest, digestErr := decoder.bytes("device-binding SHA-256", sha256.Size)
		if digestErr != nil {
			return OwnerStateSnapshot{}, digestErr
		}
		copy(device.DeviceBindingSHA256[:], digest)
	}
	if err := decoder.requireTable(
		"allocation record", recordCount, ownerStateMinimumRecordWireBytes, 0); err != nil {
		return OwnerStateSnapshot{}, err
	}
	snapshot.records = make([]OwnerStateAllocationRecord, recordCount)
	for index := range snapshot.records {
		snapshot.records[index], err = decoder.record()
		if err != nil {
			return OwnerStateSnapshot{}, ownerStateCorruptf(
				"decode allocation record %d: %v", index, err)
		}
	}
	return snapshot, nil
}

func (decoder *ownerStateDecoder) record() (OwnerStateAllocationRecord, error) {
	var record OwnerStateAllocationRecord
	var err error
	if record.AllocationRecordID, err = decoder.u64("allocation-record ID"); err != nil {
		return record, err
	}
	if record.ReservationTransactionSequence, err = decoder.u64("reservation transaction sequence"); err != nil {
		return record, err
	}
	if record.OwnerTransactionSequence, err = decoder.u64("Owner-transaction sequence"); err != nil {
		return record, err
	}
	state, err := decoder.bytes("allocation state", ownerStateStateFieldBytes)
	if err != nil {
		return record, err
	}
	if !ownerStateAllZero(state[1:]) {
		return record, ownerStateCorruptf("allocation-state reserved bytes are nonzero")
	}
	record.State = OwnerAllocationState(state[0])
	if record.RequestID, err = decoder.text("request ID"); err != nil {
		return record, err
	}
	if record.CheckpointID, err = decoder.text("checkpoint ID"); err != nil {
		return record, err
	}
	if record.ProducerID, err = decoder.text("Producer ID"); err != nil {
		return record, err
	}
	if record.DedupDomainID, err = decoder.text("deduplication-domain ID"); err != nil {
		return record, err
	}
	if record.SharingPolicyID, err = decoder.text("sharing-policy ID"); err != nil {
		return record, err
	}
	requestDigest, err := decoder.bytes("request SHA-256", sha256.Size)
	if err != nil {
		return record, err
	}
	copy(record.RequestSHA256[:], requestDigest)
	if record.TotalDemandPages, err = decoder.u64("total demand pages"); err != nil {
		return record, err
	}
	if record.MaxExtents, err = decoder.u32("maximum extent count"); err != nil {
		return record, err
	}
	contentCount, err := decoder.count("content demand", MaxOwnerStateContentDemands)
	if err != nil {
		return record, err
	}
	if err := decoder.requireTable(
		"content demand",
		contentCount,
		ownerStateContentDemandWireBytes,
		8+ownerStateRecordTailWireBytes); err != nil {
		return record, err
	}
	record.ContentDemands = make([]OwnerStateContentDemand, contentCount)
	for index := range record.ContentDemands {
		demand := &record.ContentDemands[index]
		kind, kindErr := decoder.bytes("content kind", 8)
		if kindErr != nil {
			return record, kindErr
		}
		if !ownerStateAllZero(kind[1:]) {
			return record, ownerStateCorruptf("content-kind reserved bytes are nonzero")
		}
		demand.Kind = cxlcheckpoint.ContentKindV7(kind[0])
		if demand.ObjectID, err = decoder.u64("content object ID"); err != nil {
			return record, err
		}
		if demand.ByteLength, err = decoder.u64("content byte length"); err != nil {
			return record, err
		}
		if demand.CapacityPages, err = decoder.u64("content capacity pages"); err != nil {
			return record, err
		}
		if demand.LogicalPageStart, err = decoder.u64("content logical-page start"); err != nil {
			return record, err
		}
	}
	fragmentCount, err := decoder.count("device fragment", MaxOwnerStateDevices)
	if err != nil {
		return record, err
	}
	reserved, err := decoder.bytes("fragment-count reserved", 4)
	if err != nil {
		return record, err
	}
	if !ownerStateAllZero(reserved) {
		return record, ownerStateCorruptf("fragment-count reserved bytes are nonzero")
	}
	if err := decoder.requireTable(
		"device fragment",
		fragmentCount,
		ownerStateMinimumFragmentWireBytes,
		ownerStateRecordTailWireBytes); err != nil {
		return record, err
	}
	record.Fragments = make([]OwnerStateDeviceFragment, fragmentCount)
	totalExtents := 0
	for index := range record.Fragments {
		fragment := &record.Fragments[index]
		if fragment.DeviceUUID, err = decoder.text("fragment device UUID"); err != nil {
			return record, err
		}
		if fragment.DeviceOwnerEpoch, err = decoder.u64("fragment device Owner epoch"); err != nil {
			return record, err
		}
		if fragment.TargetAllocatorSnapshotSequence, err = decoder.u64("target allocator-snapshot sequence"); err != nil {
			return record, err
		}
		extentCount, countErr := decoder.count("extent", MaxOwnerStateExtents)
		if countErr != nil {
			return record, countErr
		}
		reserved, err = decoder.bytes("extent-count reserved", 4)
		if err != nil {
			return record, err
		}
		if !ownerStateAllZero(reserved) {
			return record, ownerStateCorruptf("extent-count reserved bytes are nonzero")
		}
		totalExtents += extentCount
		if totalExtents > MaxOwnerStateExtents || uint32(totalExtents) > record.MaxExtents {
			return record, ownerStateCorruptf(
				"record extent count %d exceeds bounds %d/%d",
				totalExtents, record.MaxExtents, MaxOwnerStateExtents)
		}
		futureFragmentBytes, overflow := checkedMul(
			uint64(fragmentCount-index-1), ownerStateMinimumFragmentWireBytes)
		if !overflow {
			return record, ownerStateCorruptf("minimum future-fragment bytes overflow")
		}
		tailBytes, overflow := checkedAdd(futureFragmentBytes, ownerStateRecordTailWireBytes)
		if !overflow {
			return record, ownerStateCorruptf("minimum fragment-tail bytes overflow")
		}
		if tableErr := decoder.requireTable(
			"extent", extentCount, ownerStateExtentWireBytes, tailBytes); tableErr != nil {
			return record, tableErr
		}
		fragment.Extents = make([]OwnerStateExtent, extentCount)
		for extentIndex := range fragment.Extents {
			extent := &fragment.Extents[extentIndex]
			if extent.StartDataPageIndex, err = decoder.u64("extent data-page start"); err != nil {
				return record, err
			}
			if extent.LogicalPageStart, err = decoder.u64("extent logical-page start"); err != nil {
				return record, err
			}
			if extent.PageCount, err = decoder.u64("extent page count"); err != nil {
				return record, err
			}
		}
	}
	evidence := []*[sha256.Size]byte{
		&record.AuthorityEvidence.SchedulerReserveSHA256,
		&record.AuthorityEvidence.ProducerCapabilitySHA256,
		&record.AuthorityEvidence.PublicationAuthoritySHA256,
		&record.AuthorityEvidence.ReclaimAuthoritySHA256,
	}
	for index, destination := range evidence {
		value, evidenceErr := decoder.bytes(fmt.Sprintf("authority evidence %d SHA-256", index), sha256.Size)
		if evidenceErr != nil {
			return record, evidenceErr
		}
		copy(destination[:], value)
	}
	seal, err := decoder.bytes("Owner-verified seal SHA-256", sha256.Size)
	if err != nil {
		return record, err
	}
	copy(record.OwnerVerifiedSealSHA256[:], seal)
	return record, nil
}

func (decoder *ownerStateDecoder) count(name string, maximum int) (int, error) {
	value, err := decoder.u32(name + " count")
	if err != nil {
		return 0, err
	}
	if uint64(value) > uint64(maximum) {
		return 0, ownerStateCorruptf(
			"%s count %d exceeds %d", name, value, maximum)
	}
	return int(value), nil
}

func (decoder *ownerStateDecoder) requireTable(
	name string,
	count int,
	minimumElementBytes uint64,
	minimumTailBytes uint64,
) error {
	tableBytes, ok := checkedMul(uint64(count), minimumElementBytes)
	if !ok {
		return ownerStateCorruptf("minimum %s table bytes overflow", name)
	}
	requiredBytes, ok := checkedAdd(tableBytes, minimumTailBytes)
	if !ok || requiredBytes > uint64(decoder.remaining()) {
		return ownerStateCorruptf(
			"%s count %d needs at least %d bytes with %d remaining",
			name, count, requiredBytes, decoder.remaining())
	}
	return nil
}

func (decoder *ownerStateDecoder) text(name string) (string, error) {
	length, err := decoder.u32(name + " length")
	if err != nil {
		return "", err
	}
	if length == 0 || length > MaxOwnerStateIdentityBytes {
		return "", ownerStateCorruptf(
			"%s length %d is outside 1..%d", name, length, MaxOwnerStateIdentityBytes)
	}
	value, err := decoder.bytes(name, int(length))
	if err != nil {
		return "", err
	}
	return string(value), nil
}

func (decoder *ownerStateDecoder) u32(name string) (uint32, error) {
	value, err := decoder.bytes(name, 4)
	if err != nil {
		return 0, err
	}
	return binary.LittleEndian.Uint32(value), nil
}

func (decoder *ownerStateDecoder) u64(name string) (uint64, error) {
	value, err := decoder.bytes(name, 8)
	if err != nil {
		return 0, err
	}
	return binary.LittleEndian.Uint64(value), nil
}

func (decoder *ownerStateDecoder) bytes(name string, length int) ([]byte, error) {
	if length < 0 || length > decoder.remaining() {
		return nil, ownerStateCorruptf(
			"%s needs %d bytes with %d remaining", name, length, decoder.remaining())
	}
	start := decoder.offset
	decoder.offset += length
	return decoder.payload[start:decoder.offset], nil
}

func (decoder *ownerStateDecoder) remaining() int {
	return len(decoder.payload) - decoder.offset
}

func ownerStateAppendString(destination []byte, value string) []byte {
	destination = ownerStateAppendU32(destination, uint32(len(value)))
	return append(destination, value...)
}

func ownerStateAppendU32(destination []byte, value uint32) []byte {
	var encoded [4]byte
	binary.LittleEndian.PutUint32(encoded[:], value)
	return append(destination, encoded[:]...)
}

func ownerStateAppendU64(destination []byte, value uint64) []byte {
	var encoded [8]byte
	binary.LittleEndian.PutUint64(encoded[:], value)
	return append(destination, encoded[:]...)
}

func ownerStateCRC32C(value []byte) uint32 {
	return crc32.Checksum(value, ownerStateCRC32CTable)
}

func ownerStateHeaderCRC32C(header []byte) uint32 {
	if len(header) != int(OwnerStateEnvelopeHeaderBytes) {
		return 0
	}
	checksum := crc32.Update(
		0, ownerStateCRC32CTable, header[:ownerStateHeaderCRCOffset])
	return crc32.Update(checksum, ownerStateCRC32CTable, ownerStateZeroCRCField[:])
}

func ownerStateAllZero(value []byte) bool {
	for _, current := range value {
		if current != 0 {
			return false
		}
	}
	return true
}

func ownerStateCandidateFailure(blank bool, err error) string {
	if blank {
		return "is blank"
	}
	return fmt.Sprintf("is invalid (%v)", err)
}

func maxIntValue() int {
	return int(^uint(0) >> 1)
}

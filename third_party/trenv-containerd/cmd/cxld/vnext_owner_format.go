package main

import (
	"bytes"
	"errors"
	"fmt"
	"math"
	"sort"
)

const (
	vnextMinimumOwnerControlSlotBytes uint64 = 4096
	vnextMaxOwnerTransactions                = 1 << 20
)

var vnextOwnerJournalMagic = [8]byte{'T', 'R', 'O', 'W', 'N', '0', '0', '6'}

type vnextOwnerTransactionState uint8

const (
	vnextOwnerPreparing vnextOwnerTransactionState = iota + 1
	vnextOwnerGranted
	vnextOwnerCommitting
	vnextOwnerCommitted
	vnextOwnerAborting
	vnextOwnerAborted
	vnextOwnerReclaiming
	vnextOwnerReclaimed
	vnextOwnerQuarantined
)

func (state vnextOwnerTransactionState) valid() bool {
	return state >= vnextOwnerPreparing && state <= vnextOwnerQuarantined
}

type vnextOwnerExtent struct {
	StartDataPageIndex uint64
	PageCount          uint64
	GlobalLogicalStart uint64
}

type vnextOwnerDeviceFragment struct {
	DeviceUUID         string
	GlobalLogicalStart uint64
	PageCount          uint64
	Extents            []vnextOwnerExtent
}

type vnextOwnerTransaction struct {
	AllocationRecordID uint64
	RequestID          string
	CheckpointID       string
	ProducerID         string
	RequestDigest      [32]byte
	State              vnextOwnerTransactionState
	TotalPages         uint64
	MaxExtents         uint32
	Fragments          []vnextOwnerDeviceFragment
}

// vnextOwnerJournal is a bounded full-snapshot redo/control record. Its file
// backing models a future CXL-shared Owner control region; regular files are a
// deterministic test backend, not a claim of local-filesystem production
// durability for physical CXL.
type vnextOwnerJournal struct {
	OwnerID                string
	OwnerEpoch             uint64
	SnapshotSequence       uint64
	NextAllocationRecordID uint64
	Transactions           map[uint64]*vnextOwnerTransaction
	RequestIndex           map[string]uint64
	CheckpointIndex        map[string]uint64
}

func newVNextOwnerJournal(ownerID string, ownerEpoch, nextAllocationID uint64) (*vnextOwnerJournal, error) {
	journal := &vnextOwnerJournal{
		OwnerID:                ownerID,
		OwnerEpoch:             ownerEpoch,
		NextAllocationRecordID: nextAllocationID,
		Transactions:           make(map[uint64]*vnextOwnerTransaction),
		RequestIndex:           make(map[string]uint64),
		CheckpointIndex:        make(map[string]uint64),
	}
	if err := journal.validate(nil); err != nil {
		return nil, err
	}
	return journal, nil
}

func (journal *vnextOwnerJournal) clone() *vnextOwnerJournal {
	cloned := &vnextOwnerJournal{
		OwnerID:                journal.OwnerID,
		OwnerEpoch:             journal.OwnerEpoch,
		SnapshotSequence:       journal.SnapshotSequence,
		NextAllocationRecordID: journal.NextAllocationRecordID,
		Transactions:           make(map[uint64]*vnextOwnerTransaction, len(journal.Transactions)),
		RequestIndex:           make(map[string]uint64, len(journal.RequestIndex)),
		CheckpointIndex:        make(map[string]uint64, len(journal.CheckpointIndex)),
	}
	for allocationID, transaction := range journal.Transactions {
		copyTransaction := *transaction
		copyTransaction.Fragments = make([]vnextOwnerDeviceFragment, len(transaction.Fragments))
		for index, fragment := range transaction.Fragments {
			copyTransaction.Fragments[index] = fragment
			copyTransaction.Fragments[index].Extents = append([]vnextOwnerExtent(nil), fragment.Extents...)
		}
		cloned.Transactions[allocationID] = &copyTransaction
	}
	for requestID, allocationID := range journal.RequestIndex {
		cloned.RequestIndex[requestID] = allocationID
	}
	for checkpointID, allocationID := range journal.CheckpointIndex {
		cloned.CheckpointIndex[checkpointID] = allocationID
	}
	return cloned
}

func (journal *vnextOwnerJournal) marshalAtSequence(
	sequence uint64,
	attachedDevices map[string]*vnextPersistentDevice,
) ([]byte, error) {
	if sequence == 0 {
		return nil, errors.New("Owner journal sequence must be non-zero")
	}
	if err := journal.validate(attachedDevices); err != nil {
		return nil, err
	}
	var payload bytes.Buffer
	vnextWriteU64(&payload, sequence)
	vnextWriteString(&payload, journal.OwnerID)
	vnextWriteU64(&payload, journal.OwnerEpoch)
	vnextWriteU64(&payload, journal.NextAllocationRecordID)
	transactions := make([]*vnextOwnerTransaction, 0, len(journal.Transactions))
	for _, transaction := range journal.Transactions {
		transactions = append(transactions, transaction)
	}
	sort.Slice(transactions, func(i, j int) bool {
		return transactions[i].AllocationRecordID < transactions[j].AllocationRecordID
	})
	vnextWriteU32(&payload, uint32(len(transactions)))
	for _, transaction := range transactions {
		vnextWriteU64(&payload, transaction.AllocationRecordID)
		payload.WriteByte(byte(transaction.State))
		payload.Write(make([]byte, 7))
		vnextWriteU64(&payload, transaction.TotalPages)
		vnextWriteU32(&payload, transaction.MaxExtents)
		payload.Write(make([]byte, 4))
		vnextWriteString(&payload, transaction.RequestID)
		vnextWriteString(&payload, transaction.CheckpointID)
		vnextWriteString(&payload, transaction.ProducerID)
		payload.Write(transaction.RequestDigest[:])
		vnextWriteU32(&payload, uint32(len(transaction.Fragments)))
		for _, fragment := range transaction.Fragments {
			vnextWriteString(&payload, fragment.DeviceUUID)
			vnextWriteU64(&payload, fragment.GlobalLogicalStart)
			vnextWriteU64(&payload, fragment.PageCount)
			vnextWriteU32(&payload, uint32(len(fragment.Extents)))
			for _, extent := range fragment.Extents {
				vnextWriteU64(&payload, extent.StartDataPageIndex)
				vnextWriteU64(&payload, extent.PageCount)
				vnextWriteU64(&payload, extent.GlobalLogicalStart)
			}
		}
	}
	return vnextMarshalEnvelope(vnextOwnerJournalMagic, payload.Bytes())
}

func parseVNextOwnerJournal(
	data []byte,
	attachedDevices map[string]*vnextPersistentDevice,
) (*vnextOwnerJournal, error) {
	payload, err := vnextParseEnvelope(data, vnextOwnerJournalMagic, vnextMaxEnvelopePayload)
	if err != nil {
		return nil, err
	}
	decoder := newVNextDecoder(payload)
	sequence, err := decoder.u64()
	if err != nil || sequence == 0 {
		return nil, fmt.Errorf("decode Owner journal sequence: %w", firstVNextError(err, errVNextCorrupt))
	}
	ownerID, err := decoder.string(vnextMaxIdentityBytes)
	if err != nil {
		return nil, err
	}
	ownerEpoch, err := decoder.u64()
	if err != nil {
		return nil, err
	}
	nextAllocationID, err := decoder.u64()
	if err != nil {
		return nil, err
	}
	transactionCount, err := decoder.u32()
	if err != nil {
		return nil, err
	}
	if transactionCount > vnextMaxOwnerTransactions {
		return nil, fmt.Errorf("Owner transaction count %d exceeds %d: %w",
			transactionCount, vnextMaxOwnerTransactions, errVNextCorrupt)
	}
	journal := &vnextOwnerJournal{
		OwnerID:                ownerID,
		OwnerEpoch:             ownerEpoch,
		SnapshotSequence:       sequence,
		NextAllocationRecordID: nextAllocationID,
		Transactions:           make(map[uint64]*vnextOwnerTransaction, transactionCount),
		RequestIndex:           make(map[string]uint64, transactionCount),
		CheckpointIndex:        make(map[string]uint64, transactionCount),
	}
	for index := uint32(0); index < transactionCount; index++ {
		transaction, err := vnextParseOwnerTransaction(decoder)
		if err != nil {
			return nil, fmt.Errorf("parse Owner transaction %d: %w", index, err)
		}
		if _, exists := journal.Transactions[transaction.AllocationRecordID]; exists {
			return nil, fmt.Errorf("duplicate Owner allocation ID %d: %w",
				transaction.AllocationRecordID, errVNextCorrupt)
		}
		if _, exists := journal.RequestIndex[transaction.RequestID]; exists {
			return nil, fmt.Errorf("duplicate Owner request ID %q: %w",
				transaction.RequestID, errVNextCorrupt)
		}
		if _, exists := journal.CheckpointIndex[transaction.CheckpointID]; exists {
			return nil, fmt.Errorf("duplicate Owner checkpoint ID %q: %w",
				transaction.CheckpointID, errVNextCorrupt)
		}
		journal.Transactions[transaction.AllocationRecordID] = transaction
		journal.RequestIndex[transaction.RequestID] = transaction.AllocationRecordID
		journal.CheckpointIndex[transaction.CheckpointID] = transaction.AllocationRecordID
	}
	if err := decoder.done(); err != nil {
		return nil, err
	}
	if err := journal.validate(attachedDevices); err != nil {
		return nil, err
	}
	return journal, nil
}

func vnextParseOwnerTransaction(decoder *vnextDecoder) (*vnextOwnerTransaction, error) {
	transaction := &vnextOwnerTransaction{}
	var err error
	if transaction.AllocationRecordID, err = decoder.u64(); err != nil {
		return nil, err
	}
	state, err := decoder.u8()
	if err != nil {
		return nil, err
	}
	transaction.State = vnextOwnerTransactionState(state)
	reserved, err := decoder.bytes(7)
	if err != nil {
		return nil, err
	}
	if !vnextAllZero(reserved) {
		return nil, fmt.Errorf("Owner state reserved bytes are non-zero: %w", errVNextWrongFormat)
	}
	if transaction.TotalPages, err = decoder.u64(); err != nil {
		return nil, err
	}
	if transaction.MaxExtents, err = decoder.u32(); err != nil {
		return nil, err
	}
	reserved, err = decoder.bytes(4)
	if err != nil {
		return nil, err
	}
	if !vnextAllZero(reserved) {
		return nil, fmt.Errorf("Owner bounds reserved bytes are non-zero: %w", errVNextWrongFormat)
	}
	if transaction.RequestID, err = decoder.string(vnextMaxIdentityBytes); err != nil {
		return nil, err
	}
	if transaction.CheckpointID, err = decoder.string(vnextMaxIdentityBytes); err != nil {
		return nil, err
	}
	if transaction.ProducerID, err = decoder.string(vnextMaxIdentityBytes); err != nil {
		return nil, err
	}
	digest, err := decoder.bytes(32)
	if err != nil {
		return nil, err
	}
	copy(transaction.RequestDigest[:], digest)
	fragmentCount, err := decoder.u32()
	if err != nil {
		return nil, err
	}
	if fragmentCount == 0 || fragmentCount > vnextMaxExtentsPerRecord {
		return nil, fmt.Errorf("Owner fragment count %d is invalid: %w", fragmentCount, errVNextCorrupt)
	}
	transaction.Fragments = make([]vnextOwnerDeviceFragment, 0, fragmentCount)
	for fragmentIndex := uint32(0); fragmentIndex < fragmentCount; fragmentIndex++ {
		fragment := vnextOwnerDeviceFragment{}
		if fragment.DeviceUUID, err = decoder.string(vnextMaxIdentityBytes); err != nil {
			return nil, err
		}
		if fragment.GlobalLogicalStart, err = decoder.u64(); err != nil {
			return nil, err
		}
		if fragment.PageCount, err = decoder.u64(); err != nil {
			return nil, err
		}
		extentCount, err := decoder.u32()
		if err != nil {
			return nil, err
		}
		if extentCount == 0 || extentCount > vnextMaxExtentsPerRecord {
			return nil, fmt.Errorf("Owner extent count %d is invalid: %w", extentCount, errVNextCorrupt)
		}
		fragment.Extents = make([]vnextOwnerExtent, 0, extentCount)
		for extentIndex := uint32(0); extentIndex < extentCount; extentIndex++ {
			extent := vnextOwnerExtent{}
			if extent.StartDataPageIndex, err = decoder.u64(); err != nil {
				return nil, err
			}
			if extent.PageCount, err = decoder.u64(); err != nil {
				return nil, err
			}
			if extent.GlobalLogicalStart, err = decoder.u64(); err != nil {
				return nil, err
			}
			fragment.Extents = append(fragment.Extents, extent)
		}
		transaction.Fragments = append(transaction.Fragments, fragment)
	}
	return transaction, nil
}

func (journal *vnextOwnerJournal) validate(attachedDevices map[string]*vnextPersistentDevice) error {
	if journal.OwnerID == "" || len(journal.OwnerID) > vnextMaxIdentityBytes {
		return fmt.Errorf("Owner journal owner ID is empty or too long: %w", errVNextWrongFormat)
	}
	if journal.OwnerEpoch == 0 || journal.OwnerEpoch > uint64(math.MaxInt64) {
		return fmt.Errorf("Owner journal epoch %d is outside the signed ABI: %w",
			journal.OwnerEpoch, errVNextWrongFormat)
	}
	if journal.NextAllocationRecordID == 0 ||
		journal.NextAllocationRecordID > uint64(math.MaxInt64) {
		return fmt.Errorf("Owner allocation high-water %d is outside the signed ABI: %w",
			journal.NextAllocationRecordID, errVNextWrongFormat)
	}
	if len(journal.Transactions) > vnextMaxOwnerTransactions {
		return fmt.Errorf("too many Owner transactions: %w", errVNextMetadataFull)
	}
	requests := make(map[string]uint64, len(journal.Transactions))
	checkpoints := make(map[string]uint64, len(journal.Transactions))
	var maxAllocationID uint64
	for allocationID, transaction := range journal.Transactions {
		if transaction == nil || allocationID != transaction.AllocationRecordID {
			return fmt.Errorf("Owner transaction map key mismatch: %w", errVNextCorrupt)
		}
		if err := vnextValidateOwnerTransaction(transaction, attachedDevices); err != nil {
			return err
		}
		if _, exists := requests[transaction.RequestID]; exists {
			return fmt.Errorf("duplicate Owner request %q: %w", transaction.RequestID, errVNextCorrupt)
		}
		if _, exists := checkpoints[transaction.CheckpointID]; exists {
			return fmt.Errorf("duplicate Owner checkpoint %q: %w", transaction.CheckpointID, errVNextCorrupt)
		}
		requests[transaction.RequestID] = allocationID
		checkpoints[transaction.CheckpointID] = allocationID
		if allocationID > maxAllocationID {
			maxAllocationID = allocationID
		}
	}
	if journal.NextAllocationRecordID <= maxAllocationID {
		return fmt.Errorf("Owner allocation high-water %d does not exceed %d: %w",
			journal.NextAllocationRecordID, maxAllocationID, errVNextCorrupt)
	}
	if len(journal.RequestIndex) != len(requests) || len(journal.CheckpointIndex) != len(checkpoints) {
		return fmt.Errorf("Owner journal indexes have wrong size: %w", errVNextCorrupt)
	}
	for requestID, allocationID := range requests {
		if journal.RequestIndex[requestID] != allocationID {
			return fmt.Errorf("Owner request index mismatch: %w", errVNextCorrupt)
		}
	}
	for checkpointID, allocationID := range checkpoints {
		if journal.CheckpointIndex[checkpointID] != allocationID {
			return fmt.Errorf("Owner checkpoint index mismatch: %w", errVNextCorrupt)
		}
	}
	return nil
}

func vnextValidateOwnerTransaction(
	transaction *vnextOwnerTransaction,
	attachedDevices map[string]*vnextPersistentDevice,
) error {
	if transaction.AllocationRecordID == 0 || transaction.AllocationRecordID >= uint64(math.MaxInt64) ||
		transaction.RequestID == "" || transaction.CheckpointID == "" || transaction.ProducerID == "" ||
		!transaction.State.valid() || transaction.TotalPages == 0 ||
		transaction.TotalPages > uint64(math.MaxInt64) || transaction.MaxExtents == 0 ||
		len(transaction.Fragments) == 0 {
		return fmt.Errorf("Owner transaction %d has invalid identity/state: %w",
			transaction.AllocationRecordID, errVNextCorrupt)
	}
	if len(transaction.RequestID) > vnextMaxIdentityBytes ||
		len(transaction.CheckpointID) > vnextMaxIdentityBytes ||
		len(transaction.ProducerID) > vnextMaxIdentityBytes {
		return fmt.Errorf("Owner transaction %d has overlong identity: %w",
			transaction.AllocationRecordID, errVNextCorrupt)
	}
	seenDevices := make(map[string]struct{}, len(transaction.Fragments))
	var globalLogical uint64
	var extentCount uint64
	for _, fragment := range transaction.Fragments {
		if fragment.DeviceUUID == "" || fragment.PageCount == 0 ||
			fragment.GlobalLogicalStart != globalLogical || len(fragment.Extents) == 0 {
			return fmt.Errorf("Owner transaction %d has invalid fragment: %w",
				transaction.AllocationRecordID, errVNextCorrupt)
		}
		if _, exists := seenDevices[fragment.DeviceUUID]; exists {
			return fmt.Errorf("Owner transaction %d repeats device %q: %w",
				transaction.AllocationRecordID, fragment.DeviceUUID, errVNextCorrupt)
		}
		seenDevices[fragment.DeviceUUID] = struct{}{}
		device := attachedDevices[fragment.DeviceUUID]
		if attachedDevices != nil && device == nil {
			return fmt.Errorf("Owner transaction references unattached device %q: %w",
				fragment.DeviceUUID, errVNextWrongFormat)
		}
		var fragmentLogical uint64
		var previousEnd uint64
		for index, extent := range fragment.Extents {
			expectedLogical, ok := vnextAdd(fragment.GlobalLogicalStart, fragmentLogical)
			if !ok || extent.PageCount == 0 || extent.GlobalLogicalStart != expectedLogical {
				return fmt.Errorf("Owner transaction extent has invalid logical coverage: %w", errVNextCorrupt)
			}
			end, ok := vnextAdd(extent.StartDataPageIndex, extent.PageCount)
			if !ok || (device != nil && end > device.superblock.Geometry.DataPageCount) {
				return fmt.Errorf("Owner transaction extent exceeds device: %w", errVNextCorrupt)
			}
			if index > 0 && extent.StartDataPageIndex <= previousEnd {
				return fmt.Errorf("Owner transaction extents are not canonical: %w", errVNextCorrupt)
			}
			previousEnd = end
			fragmentLogical, ok = vnextAdd(fragmentLogical, extent.PageCount)
			if !ok {
				return fmt.Errorf("Owner fragment page count overflows: %w", errVNextCorrupt)
			}
			extentCount++
		}
		if fragmentLogical != fragment.PageCount {
			return fmt.Errorf("Owner fragment page coverage mismatch: %w", errVNextCorrupt)
		}
		var ok bool
		globalLogical, ok = vnextAdd(globalLogical, fragment.PageCount)
		if !ok {
			return fmt.Errorf("Owner global logical page count overflows: %w", errVNextCorrupt)
		}
	}
	if globalLogical != transaction.TotalPages || extentCount > uint64(transaction.MaxExtents) {
		return fmt.Errorf("Owner transaction total/extent budget mismatch: %w", errVNextCorrupt)
	}
	return nil
}

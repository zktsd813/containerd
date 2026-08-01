package main

import (
	"bytes"
	"errors"
	"fmt"
	"math"
	"sort"
)

const (
	vnextMinimumOwnerControlSlotBytes        uint64 = 4096
	vnextMaxOwnerTransactions                       = 1 << 20
	vnextOwnerSchedulerHighWaterEncodedBytes        = 168
	vnextOwnerSchedulerProofEncodedBytes            = 96
)

var vnextOwnerJournalMagic = [8]byte{'T', 'R', 'O', 'W', 'N', '0', '0', '9'}

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
	vnextOwnerRejectedNoSpace
)

func (state vnextOwnerTransactionState) valid() bool {
	return state >= vnextOwnerPreparing && state <= vnextOwnerRejectedNoSpace
}

// vnextOwnerAbortOrigin makes terminal abort authority durable. A Scheduler
// abort carries its exact Scheduler proof; Producer and recovery aborts never
// do. This prevents a later Scheduler request from claiming an abort that was
// actually authorized by a different path.
type vnextOwnerAbortOrigin uint8

const (
	vnextOwnerAbortNone vnextOwnerAbortOrigin = iota
	vnextOwnerAbortByScheduler
	vnextOwnerAbortByProducer
	vnextOwnerAbortByRecovery
)

func (origin vnextOwnerAbortOrigin) valid() bool {
	return origin >= vnextOwnerAbortByScheduler && origin <= vnextOwnerAbortByRecovery
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
	AllocationRecordID    uint64
	RequestID             string
	CheckpointID          string
	ProducerID            string
	RequestDigest         [32]byte
	SchedulerReserveProof vnextOwnerSchedulerProof
	SchedulerCommitProof  vnextOwnerSchedulerProof
	SchedulerAbortProof   vnextOwnerSchedulerProof
	AbortOrigin           vnextOwnerAbortOrigin
	State                 vnextOwnerTransactionState
	TotalPages            uint64
	MaxExtents            uint32
	Contents              []vnextContentSegment
	Fragments             []vnextOwnerDeviceFragment
	ProducerCapability    *vnextProducerCapabilityRecord
}

// vnextOwnerJournal is a bounded full-snapshot redo/control record. Its file
// backing models a future CXL-shared Owner control region; regular files are a
// deterministic test backend, not a claim of local-filesystem production
// durability for physical CXL.
type vnextOwnerJournal struct {
	OwnerID                string
	OwnerEpoch             uint64
	SchedulerHighWater     vnextOwnerSchedulerHighWater
	AdmissionState         vnextOwnerAdmissionState
	AdmissionSequence      uint64
	AdmissionTransitions   []vnextOwnerAdmissionTransitionRecord
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
		AdmissionState:         vnextOwnerAdmissionActive,
		AdmissionSequence:      1,
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
		SchedulerHighWater:     journal.SchedulerHighWater,
		AdmissionState:         journal.AdmissionState,
		AdmissionSequence:      journal.AdmissionSequence,
		AdmissionTransitions:   append([]vnextOwnerAdmissionTransitionRecord(nil), journal.AdmissionTransitions...),
		SnapshotSequence:       journal.SnapshotSequence,
		NextAllocationRecordID: journal.NextAllocationRecordID,
		Transactions:           make(map[uint64]*vnextOwnerTransaction, len(journal.Transactions)),
		RequestIndex:           make(map[string]uint64, len(journal.RequestIndex)),
		CheckpointIndex:        make(map[string]uint64, len(journal.CheckpointIndex)),
	}
	for allocationID, transaction := range journal.Transactions {
		copyTransaction := *transaction
		copyTransaction.Contents = append([]vnextContentSegment(nil), transaction.Contents...)
		copyTransaction.Fragments = make([]vnextOwnerDeviceFragment, len(transaction.Fragments))
		for index, fragment := range transaction.Fragments {
			copyTransaction.Fragments[index] = fragment
			copyTransaction.Fragments[index].Extents = append([]vnextOwnerExtent(nil), fragment.Extents...)
		}
		if transaction.ProducerCapability != nil {
			capability := *transaction.ProducerCapability
			copyTransaction.ProducerCapability = &capability
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
	vnextMarshalOwnerSchedulerHighWater(&payload, journal.SchedulerHighWater)
	payload.WriteByte(byte(journal.AdmissionState))
	payload.Write(make([]byte, 7))
	vnextWriteU64(&payload, journal.AdmissionSequence)
	vnextWriteU32(&payload, uint32(len(journal.AdmissionTransitions)))
	payload.Write(make([]byte, 4))
	for _, transition := range journal.AdmissionTransitions {
		vnextWriteString(&payload, transition.RequestID)
		payload.Write(transition.RequestDigest[:])
		vnextMarshalOwnerSchedulerProof(&payload, transition.SchedulerProof)
		payload.WriteByte(byte(transition.From))
		payload.WriteByte(byte(transition.Target))
		payload.Write(make([]byte, 6))
		vnextWriteU64(&payload, transition.ExpectedSequence)
		vnextWriteU64(&payload, transition.ResultSequence)
	}
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
		payload.WriteByte(byte(transaction.AbortOrigin))
		payload.Write(make([]byte, 6))
		vnextWriteU64(&payload, transaction.TotalPages)
		vnextWriteU32(&payload, transaction.MaxExtents)
		payload.Write(make([]byte, 4))
		vnextWriteString(&payload, transaction.RequestID)
		vnextWriteString(&payload, transaction.CheckpointID)
		vnextWriteString(&payload, transaction.ProducerID)
		payload.Write(transaction.RequestDigest[:])
		vnextMarshalOwnerSchedulerProof(&payload, transaction.SchedulerReserveProof)
		vnextMarshalOwnerSchedulerProof(&payload, transaction.SchedulerCommitProof)
		vnextMarshalOwnerSchedulerProof(&payload, transaction.SchedulerAbortProof)
		vnextWriteU32(&payload, uint32(len(transaction.Contents)))
		for _, content := range transaction.Contents {
			payload.WriteByte(byte(content.Kind))
			payload.Write(make([]byte, 7))
			vnextWriteU64(&payload, content.ObjectID)
			vnextWriteU64(&payload, content.ByteLength)
			vnextWriteU64(&payload, content.LogicalPageStart)
			vnextWriteU64(&payload, content.PageCount)
		}
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
		if transaction.ProducerCapability == nil {
			payload.WriteByte(0)
			payload.Write(make([]byte, 7))
		} else {
			capability := transaction.ProducerCapability
			payload.WriteByte(1)
			payload.Write(make([]byte, 7))
			vnextWriteString(&payload, capability.IssueRequestID)
			payload.Write(capability.IssueRequestDigest[:])
			vnextWriteString(&payload, capability.CapabilityID)
			payload.Write(capability.TokenDigest[:])
			payload.Write(capability.ScopeDigest[:])
			vnextWriteString(&payload, capability.ProducerPrincipal)
			vnextWriteString(&payload, capability.IssuerPrincipal)
			payload.WriteByte(byte(capability.AllowedOperations))
			payload.Write(make([]byte, 7))
			vnextMarshalOwnerSchedulerProof(&payload, capability.IssueSchedulerProof)
			vnextWriteU64(&payload, capability.IssuedAtUnixNano)
			vnextWriteU64(&payload, capability.ExpiresAtUnixNano)
			if capability.Revoked {
				payload.WriteByte(1)
			} else {
				payload.WriteByte(0)
			}
			payload.Write(make([]byte, 7))
			vnextWriteString(&payload, capability.RevokeRequestID)
			payload.Write(capability.RevokeRequestDigest[:])
			vnextWriteString(&payload, capability.RevokedByPrincipal)
			vnextMarshalOwnerSchedulerProof(&payload, capability.RevokeSchedulerProof)
			vnextWriteU64(&payload, capability.RevokedAtUnixNano)
		}
	}
	return vnextMarshalEnvelope(vnextOwnerJournalMagic, payload.Bytes())
}

func vnextMarshalOwnerSchedulerHighWater(
	payload *bytes.Buffer,
	highWater vnextOwnerSchedulerHighWater,
) {
	if highWater.Initialized {
		payload.WriteByte(1)
	} else {
		payload.WriteByte(0)
	}
	payload.Write(make([]byte, 7))
	payload.Write(highWater.LeaderKeyDigest[:])
	vnextWriteU64(payload, highWater.ClusterID)
	vnextWriteU64(payload, highWater.CreateRevision)
	vnextWriteU64(payload, highWater.ModRevision)
	vnextWriteU64(payload, highWater.LeaseID)
	payload.Write(highWater.LeaderValueDigest[:])
	payload.Write(highWater.PublicKeyDigest[:])
	payload.Write(highWater.SchedulerTermID[:])
}

func vnextMarshalOwnerSchedulerProof(
	payload *bytes.Buffer,
	proof vnextOwnerSchedulerProof,
) {
	payload.Write(proof.TermID[:])
	payload.Write(proof.MutationDigest[:])
	payload.Write(proof.Receipt[:])
}

func vnextParseOwnerSchedulerProof(
	decoder *vnextDecoder,
) (vnextOwnerSchedulerProof, error) {
	var proof vnextOwnerSchedulerProof
	termID, err := decoder.bytes(uint64(len(proof.TermID)))
	if err != nil {
		return proof, err
	}
	copy(proof.TermID[:], termID)
	mutationDigest, err := decoder.bytes(uint64(len(proof.MutationDigest)))
	if err != nil {
		return proof, err
	}
	copy(proof.MutationDigest[:], mutationDigest)
	receipt, err := decoder.bytes(uint64(len(proof.Receipt)))
	if err != nil {
		return proof, err
	}
	copy(proof.Receipt[:], receipt)
	if proof != (vnextOwnerSchedulerProof{}) && !proof.valid() {
		return vnextOwnerSchedulerProof{}, fmt.Errorf(
			"Owner Scheduler proof is partial: %w", errVNextCorrupt)
	}
	return proof, nil
}

func vnextParseOwnerSchedulerHighWater(
	decoder *vnextDecoder,
) (vnextOwnerSchedulerHighWater, error) {
	var highWater vnextOwnerSchedulerHighWater
	initialized, err := decoder.u8()
	if err != nil {
		return highWater, err
	}
	reserved, err := decoder.bytes(7)
	if err != nil {
		return highWater, err
	}
	if initialized > 1 || !vnextAllZero(reserved) {
		return highWater, fmt.Errorf(
			"Owner Scheduler high-water presence encoding is invalid: %w",
			errVNextWrongFormat)
	}
	highWater.Initialized = initialized == 1
	leaderKeyDigest, err := decoder.bytes(uint64(len(highWater.LeaderKeyDigest)))
	if err != nil {
		return highWater, err
	}
	copy(highWater.LeaderKeyDigest[:], leaderKeyDigest)
	if highWater.ClusterID, err = decoder.u64(); err != nil {
		return highWater, err
	}
	if highWater.CreateRevision, err = decoder.u64(); err != nil {
		return highWater, err
	}
	if highWater.ModRevision, err = decoder.u64(); err != nil {
		return highWater, err
	}
	if highWater.LeaseID, err = decoder.u64(); err != nil {
		return highWater, err
	}
	leaderValueDigest, err := decoder.bytes(uint64(len(highWater.LeaderValueDigest)))
	if err != nil {
		return highWater, err
	}
	copy(highWater.LeaderValueDigest[:], leaderValueDigest)
	publicKeyDigest, err := decoder.bytes(uint64(len(highWater.PublicKeyDigest)))
	if err != nil {
		return highWater, err
	}
	copy(highWater.PublicKeyDigest[:], publicKeyDigest)
	termID, err := decoder.bytes(uint64(len(highWater.SchedulerTermID)))
	if err != nil {
		return highWater, err
	}
	copy(highWater.SchedulerTermID[:], termID)
	if err := highWater.validate(); err != nil {
		return vnextOwnerSchedulerHighWater{}, err
	}
	return highWater, nil
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
	schedulerHighWater, err := vnextParseOwnerSchedulerHighWater(decoder)
	if err != nil {
		return nil, err
	}
	admissionState, err := decoder.u8()
	if err != nil {
		return nil, err
	}
	reserved, err := decoder.bytes(7)
	if err != nil {
		return nil, err
	}
	if !vnextAllZero(reserved) {
		return nil, fmt.Errorf("Owner admission reserved bytes are non-zero: %w", errVNextWrongFormat)
	}
	admissionSequence, err := decoder.u64()
	if err != nil {
		return nil, err
	}
	transitionCount, err := decoder.u32()
	if err != nil {
		return nil, err
	}
	reserved, err = decoder.bytes(4)
	if err != nil {
		return nil, err
	}
	if !vnextAllZero(reserved) {
		return nil, fmt.Errorf("Owner admission count reserved bytes are non-zero: %w", errVNextWrongFormat)
	}
	if transitionCount > vnextMaxOwnerAdmissionTransitions {
		return nil, fmt.Errorf("Owner admission transition count %d exceeds %d: %w",
			transitionCount, vnextMaxOwnerAdmissionTransitions, errVNextCorrupt)
	}
	transitions := make([]vnextOwnerAdmissionTransitionRecord, 0, transitionCount)
	for index := uint32(0); index < transitionCount; index++ {
		transition, err := vnextParseOwnerAdmissionTransition(decoder)
		if err != nil {
			return nil, fmt.Errorf("parse Owner admission transition %d: %w", index, err)
		}
		transitions = append(transitions, transition)
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
		SchedulerHighWater:     schedulerHighWater,
		AdmissionState:         vnextOwnerAdmissionState(admissionState),
		AdmissionSequence:      admissionSequence,
		AdmissionTransitions:   transitions,
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

func vnextParseOwnerAdmissionTransition(
	decoder *vnextDecoder,
) (vnextOwnerAdmissionTransitionRecord, error) {
	var transition vnextOwnerAdmissionTransitionRecord
	var err error
	if transition.RequestID, err = decoder.string(vnextMaxIdentityBytes); err != nil {
		return vnextOwnerAdmissionTransitionRecord{}, err
	}
	digest, err := decoder.bytes(uint64(len(transition.RequestDigest)))
	if err != nil {
		return vnextOwnerAdmissionTransitionRecord{}, err
	}
	copy(transition.RequestDigest[:], digest)
	transition.SchedulerProof, err = vnextParseOwnerSchedulerProof(decoder)
	if err != nil {
		return vnextOwnerAdmissionTransitionRecord{}, err
	}
	from, err := decoder.u8()
	if err != nil {
		return vnextOwnerAdmissionTransitionRecord{}, err
	}
	target, err := decoder.u8()
	if err != nil {
		return vnextOwnerAdmissionTransitionRecord{}, err
	}
	transition.From = vnextOwnerAdmissionState(from)
	transition.Target = vnextOwnerAdmissionState(target)
	reserved, err := decoder.bytes(6)
	if err != nil {
		return vnextOwnerAdmissionTransitionRecord{}, err
	}
	if !vnextAllZero(reserved) {
		return vnextOwnerAdmissionTransitionRecord{}, fmt.Errorf(
			"Owner admission transition reserved bytes are non-zero: %w", errVNextWrongFormat)
	}
	if transition.ExpectedSequence, err = decoder.u64(); err != nil {
		return vnextOwnerAdmissionTransitionRecord{}, err
	}
	if transition.ResultSequence, err = decoder.u64(); err != nil {
		return vnextOwnerAdmissionTransitionRecord{}, err
	}
	return transition, nil
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
	abortOrigin, err := decoder.u8()
	if err != nil {
		return nil, err
	}
	transaction.AbortOrigin = vnextOwnerAbortOrigin(abortOrigin)
	reserved, err := decoder.bytes(6)
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
	transaction.SchedulerReserveProof, err = vnextParseOwnerSchedulerProof(decoder)
	if err != nil {
		return nil, err
	}
	transaction.SchedulerCommitProof, err = vnextParseOwnerSchedulerProof(decoder)
	if err != nil {
		return nil, err
	}
	transaction.SchedulerAbortProof, err = vnextParseOwnerSchedulerProof(decoder)
	if err != nil {
		return nil, err
	}
	contentCount, err := decoder.u32()
	if err != nil {
		return nil, err
	}
	if contentCount == 0 || contentCount > vnextMaxContentsPerRecord {
		return nil, fmt.Errorf("Owner content count %d is invalid: %w",
			contentCount, errVNextCorrupt)
	}
	transaction.Contents = make([]vnextContentSegment, 0, contentCount)
	for contentIndex := uint32(0); contentIndex < contentCount; contentIndex++ {
		kind, err := decoder.u8()
		if err != nil {
			return nil, err
		}
		reserved, err := decoder.bytes(7)
		if err != nil {
			return nil, err
		}
		if !vnextAllZero(reserved) {
			return nil, fmt.Errorf(
				"Owner content reserved bytes are non-zero: %w", errVNextWrongFormat)
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
		transaction.Contents = append(transaction.Contents, content)
	}
	fragmentCount, err := decoder.u32()
	if err != nil {
		return nil, err
	}
	negativeTombstone := transaction.State == vnextOwnerRejectedNoSpace
	if fragmentCount > vnextMaxExtentsPerRecord || (fragmentCount == 0) != negativeTombstone {
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
	hasCapability, err := decoder.u8()
	if err != nil {
		return nil, err
	}
	reserved, err = decoder.bytes(7)
	if err != nil {
		return nil, err
	}
	if !vnextAllZero(reserved) || hasCapability > 1 {
		return nil, fmt.Errorf("Owner capability presence encoding is invalid: %w", errVNextWrongFormat)
	}
	if hasCapability == 1 {
		capability, err := vnextParseProducerCapabilityRecord(decoder)
		if err != nil {
			return nil, err
		}
		transaction.ProducerCapability = capability
	}
	return transaction, nil
}

func vnextParseProducerCapabilityRecord(
	decoder *vnextDecoder,
) (*vnextProducerCapabilityRecord, error) {
	record := &vnextProducerCapabilityRecord{}
	var err error
	if record.IssueRequestID, err = decoder.string(vnextMaxIdentityBytes); err != nil {
		return nil, err
	}
	digest, err := decoder.bytes(32)
	if err != nil {
		return nil, err
	}
	copy(record.IssueRequestDigest[:], digest)
	if record.CapabilityID, err = decoder.string(2 * vnextProducerCapabilityIDBytes); err != nil {
		return nil, err
	}
	digest, err = decoder.bytes(32)
	if err != nil {
		return nil, err
	}
	copy(record.TokenDigest[:], digest)
	digest, err = decoder.bytes(32)
	if err != nil {
		return nil, err
	}
	copy(record.ScopeDigest[:], digest)
	if record.ProducerPrincipal, err = decoder.string(vnextMaxIdentityBytes); err != nil {
		return nil, err
	}
	if record.IssuerPrincipal, err = decoder.string(vnextMaxIdentityBytes); err != nil {
		return nil, err
	}
	operations, err := decoder.u8()
	if err != nil {
		return nil, err
	}
	record.AllowedOperations = vnextProducerCapabilityOperations(operations)
	reserved, err := decoder.bytes(7)
	if err != nil {
		return nil, err
	}
	if !vnextAllZero(reserved) {
		return nil, fmt.Errorf("Producer capability operation reserved bytes are non-zero: %w", errVNextWrongFormat)
	}
	record.IssueSchedulerProof, err = vnextParseOwnerSchedulerProof(decoder)
	if err != nil {
		return nil, err
	}
	if record.IssuedAtUnixNano, err = decoder.u64(); err != nil {
		return nil, err
	}
	if record.ExpiresAtUnixNano, err = decoder.u64(); err != nil {
		return nil, err
	}
	revoked, err := decoder.u8()
	if err != nil {
		return nil, err
	}
	reserved, err = decoder.bytes(7)
	if err != nil {
		return nil, err
	}
	if !vnextAllZero(reserved) || revoked > 1 {
		return nil, fmt.Errorf("Producer capability revocation encoding is invalid: %w", errVNextWrongFormat)
	}
	record.Revoked = revoked == 1
	if record.RevokeRequestID, err = decoder.string(vnextMaxIdentityBytes); err != nil {
		return nil, err
	}
	digest, err = decoder.bytes(32)
	if err != nil {
		return nil, err
	}
	copy(record.RevokeRequestDigest[:], digest)
	if record.RevokedByPrincipal, err = decoder.string(vnextMaxIdentityBytes); err != nil {
		return nil, err
	}
	record.RevokeSchedulerProof, err = vnextParseOwnerSchedulerProof(decoder)
	if err != nil {
		return nil, err
	}
	if record.RevokedAtUnixNano, err = decoder.u64(); err != nil {
		return nil, err
	}
	return record, nil
}

func (journal *vnextOwnerJournal) validate(attachedDevices map[string]*vnextPersistentDevice) error {
	if journal.OwnerID == "" || len(journal.OwnerID) > vnextMaxIdentityBytes {
		return fmt.Errorf("Owner journal owner ID is empty or too long: %w", errVNextWrongFormat)
	}
	if journal.OwnerEpoch == 0 || journal.OwnerEpoch > uint64(math.MaxInt64) {
		return fmt.Errorf("Owner journal epoch %d is outside the signed ABI: %w",
			journal.OwnerEpoch, errVNextWrongFormat)
	}
	if err := journal.SchedulerHighWater.validate(); err != nil {
		return err
	}
	if (len(journal.Transactions) != 0 || len(journal.AdmissionTransitions) != 0) &&
		!journal.SchedulerHighWater.Initialized {
		return fmt.Errorf(
			"Owner journal has Scheduler-authorized records without a fencing high-water: %w",
			errVNextCorrupt)
	}
	if err := validateVNextOwnerAdmissionJournal(journal); err != nil {
		return err
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
		if err := vnextValidateOwnerTransaction(
			transaction, attachedDevices, journal.OwnerID, journal.OwnerEpoch); err != nil {
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
	ownerID string,
	ownerEpoch uint64,
) error {
	if transaction.AllocationRecordID == 0 || transaction.AllocationRecordID >= uint64(math.MaxInt64) ||
		transaction.RequestID == "" || transaction.CheckpointID == "" || transaction.ProducerID == "" ||
		!transaction.State.valid() || transaction.TotalPages == 0 ||
		transaction.TotalPages > uint64(math.MaxInt64) || transaction.MaxExtents == 0 {
		return fmt.Errorf("Owner transaction %d has invalid identity/state: %w",
			transaction.AllocationRecordID, errVNextCorrupt)
	}
	if !transaction.SchedulerReserveProof.valid() {
		return fmt.Errorf("Owner transaction %d lacks its Scheduler Reserve proof: %w",
			transaction.AllocationRecordID, errVNextCorrupt)
	}
	commitProofRequired := transaction.State == vnextOwnerCommitting ||
		transaction.State == vnextOwnerCommitted ||
		transaction.State == vnextOwnerReclaiming ||
		transaction.State == vnextOwnerReclaimed
	if commitProofRequired != transaction.SchedulerCommitProof.valid() {
		return fmt.Errorf("Owner transaction %d has inconsistent Scheduler Commit proof: %w",
			transaction.AllocationRecordID, errVNextCorrupt)
	}
	abortState := transaction.State == vnextOwnerAborting ||
		transaction.State == vnextOwnerAborted
	if !abortState {
		if transaction.AbortOrigin != vnextOwnerAbortNone ||
			transaction.SchedulerAbortProof != (vnextOwnerSchedulerProof{}) {
			return fmt.Errorf("Owner transaction %d has abort metadata outside an abort state: %w",
				transaction.AllocationRecordID, errVNextCorrupt)
		}
	} else if !transaction.AbortOrigin.valid() {
		return fmt.Errorf("Owner transaction %d lacks a durable abort origin: %w",
			transaction.AllocationRecordID, errVNextCorrupt)
	} else if transaction.AbortOrigin == vnextOwnerAbortByScheduler {
		if !transaction.SchedulerAbortProof.valid() {
			return fmt.Errorf("Owner transaction %d lacks its Scheduler Abort proof: %w",
				transaction.AllocationRecordID, errVNextCorrupt)
		}
	} else if transaction.SchedulerAbortProof != (vnextOwnerSchedulerProof{}) {
		return fmt.Errorf("Owner transaction %d attributes a non-Scheduler abort to Scheduler: %w",
			transaction.AllocationRecordID, errVNextCorrupt)
	}
	negativeTombstone := transaction.State == vnextOwnerRejectedNoSpace
	if (len(transaction.Fragments) == 0) != negativeTombstone {
		return fmt.Errorf("Owner transaction %d has fragments inconsistent with state %d: %w",
			transaction.AllocationRecordID, transaction.State, errVNextCorrupt)
	}
	if len(transaction.RequestID) > vnextMaxIdentityBytes ||
		len(transaction.CheckpointID) > vnextMaxIdentityBytes ||
		len(transaction.ProducerID) > vnextMaxIdentityBytes {
		return fmt.Errorf("Owner transaction %d has overlong identity: %w",
			transaction.AllocationRecordID, errVNextCorrupt)
	}
	if len(transaction.Contents) == 0 ||
		len(transaction.Contents) > vnextMaxContentsPerRecord {
		return fmt.Errorf("Owner transaction %d has invalid content count: %w",
			transaction.AllocationRecordID, errVNextCorrupt)
	}
	seenObjects := make(map[uint64]struct{}, len(transaction.Contents))
	var contentLogical uint64
	for _, content := range transaction.Contents {
		if !content.Kind.valid() || content.ObjectID == 0 || content.PageCount == 0 ||
			content.LogicalPageStart != contentLogical {
			return fmt.Errorf("Owner transaction %d has invalid content: %w",
				transaction.AllocationRecordID, errVNextCorrupt)
		}
		if _, exists := seenObjects[content.ObjectID]; exists {
			return fmt.Errorf("Owner transaction %d repeats content object %d: %w",
				transaction.AllocationRecordID, content.ObjectID, errVNextCorrupt)
		}
		seenObjects[content.ObjectID] = struct{}{}
		capacity, ok := vnextMul(content.PageCount, vnextContentPageSize)
		if !ok || content.ByteLength > capacity ||
			(content.Kind == vnextContentMemory && content.ByteLength != capacity) ||
			(content.Kind == vnextContentPublication && content.ByteLength != capacity) {
			return fmt.Errorf("Owner transaction %d has invalid content capacity: %w",
				transaction.AllocationRecordID, errVNextCorrupt)
		}
		contentLogical, ok = vnextAdd(contentLogical, content.PageCount)
		if !ok {
			return fmt.Errorf("Owner transaction content coverage overflows: %w", errVNextCorrupt)
		}
	}
	if contentLogical != transaction.TotalPages {
		return fmt.Errorf("Owner transaction content covers %d of %d pages: %w",
			contentLogical, transaction.TotalPages, errVNextCorrupt)
	}
	if !negativeTombstone {
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
	}
	requestContents := make([]vnextContentRequest, len(transaction.Contents))
	for index, content := range transaction.Contents {
		requestContents[index] = vnextContentRequest{
			Kind:       content.Kind,
			ObjectID:   content.ObjectID,
			ByteLength: content.ByteLength,
			PageCount:  content.PageCount,
		}
	}
	expectedDigest := vnextOwnerRequestDigest(vnextCheckpointAllocationRequest{
		RequestID:    transaction.RequestID,
		CheckpointID: transaction.CheckpointID,
		ProducerID:   transaction.ProducerID,
		OwnerID:      ownerID,
		OwnerEpoch:   ownerEpoch,
		Contents:     requestContents,
		MaxExtents:   transaction.MaxExtents,
	})
	if transaction.RequestDigest != expectedDigest {
		return fmt.Errorf("Owner transaction %d request digest mismatch: %w",
			transaction.AllocationRecordID, errVNextCorrupt)
	}
	if err := validateVNextProducerCapabilityRecord(
		transaction.ProducerCapability, ownerID, ownerEpoch, transaction); err != nil {
		return fmt.Errorf("Owner transaction %d Producer capability is invalid: %w",
			transaction.AllocationRecordID, err)
	}
	return nil
}

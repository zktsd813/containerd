package main

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"math"
)

const vnextMaxOwnerAdmissionTransitions = 2

var (
	errVNextOwnerAdmissionClosed           = errors.New("VNext Owner allocation admission is closed")
	errVNextOwnerAdmissionRequestConflict  = errors.New("VNext Owner admission request conflicts with durable history")
	errVNextOwnerAdmissionSequenceConflict = errors.New("VNext Owner admission sequence conflicts with the durable head")
)

// vnextOwnerAdmissionState is the durable allocation-admission state for one
// exact Owner epoch. State only moves forward. Reopening allocation requires a
// new Owner epoch and a newly formatted TROWN008 journal.
type vnextOwnerAdmissionState uint8

const (
	vnextOwnerAdmissionActive vnextOwnerAdmissionState = iota + 1
	vnextOwnerAdmissionReadOnly
	vnextOwnerAdmissionFenced
)

func (state vnextOwnerAdmissionState) valid() bool {
	return state >= vnextOwnerAdmissionActive && state <= vnextOwnerAdmissionFenced
}

func (state vnextOwnerAdmissionState) String() string {
	switch state {
	case vnextOwnerAdmissionActive:
		return "ACTIVE"
	case vnextOwnerAdmissionReadOnly:
		return "READ_ONLY"
	case vnextOwnerAdmissionFenced:
		return "FENCED"
	default:
		return fmt.Sprintf("UNKNOWN(%d)", state)
	}
}

type vnextOwnerAdmissionTransitionRequest struct {
	RequestID        string
	OwnerID          string
	OwnerEpoch       uint64
	From             vnextOwnerAdmissionState
	Target           vnextOwnerAdmissionState
	ExpectedSequence uint64
}

type vnextOwnerAdmissionTransitionRecord struct {
	RequestID        string
	RequestDigest    [32]byte
	From             vnextOwnerAdmissionState
	Target           vnextOwnerAdmissionState
	ExpectedSequence uint64
	ResultSequence   uint64
}

type vnextOwnerAdmissionTransitionResult struct {
	Record   vnextOwnerAdmissionTransitionRecord
	Replayed bool
}

type vnextOwnerAdmissionSnapshot struct {
	OwnerID           string
	OwnerEpoch        uint64
	State             vnextOwnerAdmissionState
	AdmissionSequence uint64
	SnapshotSequence  uint64
	HasLastTransition bool
	LastTransition    vnextOwnerAdmissionTransitionRecord
}

type vnextOwnerAdmissionClosedError struct {
	Operation string
	State     vnextOwnerAdmissionState
	Sequence  uint64
}

// vnextOwnerAdmissionRequestConflictError identifies the fail-closed case in
// which an idempotency key already names a different durable transition. The
// digest itself remains in the Owner journal and transition proof; callers do
// not need it to classify this error.
type vnextOwnerAdmissionRequestConflictError struct {
	RequestID string
}

func (err *vnextOwnerAdmissionRequestConflictError) Error() string {
	if err == nil {
		return "<nil>"
	}
	return fmt.Sprintf(
		"Owner admission request ID %q conflicts with its durable transition",
		err.RequestID)
}

func (err *vnextOwnerAdmissionRequestConflictError) Unwrap() error {
	return errVNextOwnerAdmissionRequestConflict
}

// vnextOwnerAdmissionSequenceConflictError carries both sides of a rejected
// compare-and-transition. It is returned only after exact request replay has
// been checked, so a lost successful reply remains replayable even when the
// durable head has advanced again.
type vnextOwnerAdmissionSequenceConflictError struct {
	CurrentState     vnextOwnerAdmissionState
	CurrentSequence  uint64
	RequestedFrom    vnextOwnerAdmissionState
	ExpectedSequence uint64
}

func (err *vnextOwnerAdmissionSequenceConflictError) Error() string {
	if err == nil {
		return "<nil>"
	}
	return fmt.Sprintf(
		"Owner admission head is state=%s sequence=%d, request expected state=%s sequence=%d",
		err.CurrentState,
		err.CurrentSequence,
		err.RequestedFrom,
		err.ExpectedSequence)
}

func (err *vnextOwnerAdmissionSequenceConflictError) Unwrap() error {
	return errVNextOwnerAdmissionSequenceConflict
}

func (err *vnextOwnerAdmissionClosedError) Error() string {
	if err == nil {
		return "<nil>"
	}
	return fmt.Sprintf(
		"VNext Owner %s rejected because allocation admission is state=%s sequence=%d",
		err.Operation,
		err.State,
		err.Sequence)
}

func (err *vnextOwnerAdmissionClosedError) Unwrap() error {
	return errVNextOwnerAdmissionClosed
}

func vnextOwnerAdmissionRequestDigest(
	request vnextOwnerAdmissionTransitionRequest,
) [32]byte {
	var buffer bytes.Buffer
	vnextWriteString(&buffer, "cxld-vnext-owner-admission-transition-v1")
	vnextWriteString(&buffer, request.RequestID)
	vnextWriteString(&buffer, request.OwnerID)
	vnextWriteU64(&buffer, request.OwnerEpoch)
	buffer.WriteByte(byte(request.From))
	buffer.WriteByte(byte(request.Target))
	buffer.Write(make([]byte, 6))
	vnextWriteU64(&buffer, request.ExpectedSequence)
	return sha256.Sum256(buffer.Bytes())
}

func validateVNextOwnerAdmissionTransitionRequest(
	request vnextOwnerAdmissionTransitionRequest,
) error {
	if request.RequestID == "" || len(request.RequestID) > vnextMaxIdentityBytes ||
		request.OwnerID == "" || len(request.OwnerID) > vnextMaxIdentityBytes {
		return errors.New("Owner admission transition identity is empty or too long")
	}
	if request.OwnerEpoch == 0 || request.OwnerEpoch > uint64(math.MaxInt64) ||
		request.ExpectedSequence == 0 || request.ExpectedSequence >= uint64(math.MaxInt64) {
		return errors.New("Owner admission transition epoch or sequence is outside the signed ABI")
	}
	if !request.From.valid() || !request.Target.valid() || request.Target <= request.From {
		return fmt.Errorf(
			"Owner admission transition %s -> %s is not monotonic",
			request.From,
			request.Target)
	}
	switch request.ExpectedSequence {
	case 1:
		if request.From != vnextOwnerAdmissionActive {
			return errors.New(
				"Owner admission sequence 1 must transition from ACTIVE")
		}
	case 2:
		if request.From != vnextOwnerAdmissionReadOnly ||
			request.Target != vnextOwnerAdmissionFenced {
			return errors.New(
				"Owner admission sequence 2 must transition READ_ONLY -> FENCED")
		}
	default:
		return errors.New("Owner admission expected sequence must be 1 or 2")
	}
	return nil
}

func validateVNextOwnerAdmissionJournal(journal *vnextOwnerJournal) error {
	if journal == nil {
		return fmt.Errorf("Owner admission journal is nil: %w", errVNextCorrupt)
	}
	if len(journal.AdmissionTransitions) > vnextMaxOwnerAdmissionTransitions {
		return fmt.Errorf("Owner admission state, sequence, or history is invalid: %w", errVNextCorrupt)
	}
	if err := validateVNextOwnerAdmissionHeadPair(
		journal.AdmissionState, journal.AdmissionSequence); err != nil {
		return err
	}
	state := vnextOwnerAdmissionActive
	sequence := uint64(1)
	seenRequestIDs := make(map[string]struct{}, len(journal.AdmissionTransitions))
	for index, record := range journal.AdmissionTransitions {
		if record.RequestID == "" || len(record.RequestID) > vnextMaxIdentityBytes {
			return fmt.Errorf("Owner admission transition %d has an invalid request ID: %w",
				index, errVNextCorrupt)
		}
		if _, duplicate := seenRequestIDs[record.RequestID]; duplicate {
			return fmt.Errorf("Owner admission request %q is duplicated: %w",
				record.RequestID, errVNextCorrupt)
		}
		seenRequestIDs[record.RequestID] = struct{}{}
		request := vnextOwnerAdmissionTransitionRequest{
			RequestID:        record.RequestID,
			OwnerID:          journal.OwnerID,
			OwnerEpoch:       journal.OwnerEpoch,
			From:             record.From,
			Target:           record.Target,
			ExpectedSequence: record.ExpectedSequence,
		}
		if err := validateVNextOwnerAdmissionTransitionRequest(request); err != nil {
			return fmt.Errorf("Owner admission transition %d is invalid: %w", index, errVNextCorrupt)
		}
		if record.From != state || record.ExpectedSequence != sequence ||
			record.ResultSequence != sequence+1 ||
			record.RequestDigest != vnextOwnerAdmissionRequestDigest(request) {
			return fmt.Errorf("Owner admission transition %d is not canonical: %w",
				index, errVNextCorrupt)
		}
		state = record.Target
		sequence = record.ResultSequence
	}
	if journal.AdmissionState != state || journal.AdmissionSequence != sequence {
		return fmt.Errorf("Owner admission head does not match its transition history: %w",
			errVNextCorrupt)
	}
	return nil
}

// validateVNextOwnerAdmissionHeadPair is the single canonical state/sequence
// rule shared by durable journal validation and read-only status boundaries.
// FENCED/2 is the direct ACTIVE -> FENCED path; FENCED/3 is the path through
// READ_ONLY. No other same-epoch head can be produced by the transition ABI.
func validateVNextOwnerAdmissionHeadPair(
	state vnextOwnerAdmissionState,
	sequence uint64,
) error {
	valid := (state == vnextOwnerAdmissionActive && sequence == 1) ||
		(state == vnextOwnerAdmissionReadOnly && sequence == 2) ||
		(state == vnextOwnerAdmissionFenced && (sequence == 2 || sequence == 3))
	if !valid {
		return fmt.Errorf(
			"Owner admission head state=%s sequence=%d is not canonical: %w",
			state,
			sequence,
			errVNextCorrupt)
	}
	return nil
}

func validateVNextOwnerAdmissionHeadProof(
	ownerID string,
	ownerEpoch uint64,
	state vnextOwnerAdmissionState,
	sequence uint64,
	hasLastTransition bool,
	lastTransition vnextOwnerAdmissionTransitionRecord,
) error {
	if ownerID == "" || len(ownerID) > vnextMaxIdentityBytes ||
		ownerEpoch == 0 || ownerEpoch > uint64(math.MaxInt64) {
		return fmt.Errorf("Owner admission head identity, state, or sequence is invalid: %w",
			errVNextCorrupt)
	}
	if err := validateVNextOwnerAdmissionHeadPair(state, sequence); err != nil {
		return err
	}
	if !hasLastTransition {
		if lastTransition != (vnextOwnerAdmissionTransitionRecord{}) ||
			state != vnextOwnerAdmissionActive || sequence != 1 {
			return fmt.Errorf("fresh Owner admission proof is not canonical: %w", errVNextCorrupt)
		}
		return nil
	}
	request := vnextOwnerAdmissionTransitionRequest{
		RequestID:        lastTransition.RequestID,
		OwnerID:          ownerID,
		OwnerEpoch:       ownerEpoch,
		From:             lastTransition.From,
		Target:           lastTransition.Target,
		ExpectedSequence: lastTransition.ExpectedSequence,
	}
	if err := validateVNextOwnerAdmissionTransitionRequest(request); err != nil ||
		lastTransition.RequestDigest != vnextOwnerAdmissionRequestDigest(request) ||
		lastTransition.ResultSequence != lastTransition.ExpectedSequence+1 ||
		lastTransition.Target != state || lastTransition.ResultSequence != sequence {
		return fmt.Errorf("last Owner admission transition does not prove the durable head: %w",
			errVNextCorrupt)
	}
	return nil
}

func (group *vnextOwnerGroup) admissionStatus(
	expectedOwnerID string,
	expectedOwnerEpoch uint64,
) (vnextOwnerAdmissionSnapshot, error) {
	group.mu.Lock()
	defer group.mu.Unlock()
	if err := group.checkUsableLocked(); err != nil {
		return vnextOwnerAdmissionSnapshot{}, err
	}
	if expectedOwnerID != group.ownerID || expectedOwnerEpoch != group.ownerEpoch {
		return vnextOwnerAdmissionSnapshot{}, fmt.Errorf(
			"expected Owner %q/%d, live Owner is %q/%d: %w",
			expectedOwnerID,
			expectedOwnerEpoch,
			group.ownerID,
			group.ownerEpoch,
			errVNextAuthority)
	}
	if err := validateVNextOwnerAdmissionJournal(group.journal); err != nil {
		return vnextOwnerAdmissionSnapshot{}, err
	}
	return group.admissionSnapshotLocked(), nil
}

func (group *vnextOwnerGroup) setAdmission(
	request vnextOwnerAdmissionTransitionRequest,
) (vnextOwnerAdmissionTransitionResult, error) {
	group.mu.Lock()
	defer group.mu.Unlock()
	if err := group.checkUsableLocked(); err != nil {
		return vnextOwnerAdmissionTransitionResult{}, err
	}
	if err := validateVNextOwnerAdmissionTransitionRequest(request); err != nil {
		return vnextOwnerAdmissionTransitionResult{}, err
	}
	if request.OwnerID != group.ownerID || request.OwnerEpoch != group.ownerEpoch {
		return vnextOwnerAdmissionTransitionResult{}, fmt.Errorf(
			"admission request Owner %q/%d does not match group %q/%d: %w",
			request.OwnerID,
			request.OwnerEpoch,
			group.ownerID,
			group.ownerEpoch,
			errVNextAuthority)
	}
	if err := validateVNextOwnerAdmissionJournal(group.journal); err != nil {
		return vnextOwnerAdmissionTransitionResult{}, err
	}
	digest := vnextOwnerAdmissionRequestDigest(request)
	for _, record := range group.journal.AdmissionTransitions {
		if record.RequestID != request.RequestID {
			continue
		}
		if record.RequestDigest != digest {
			return vnextOwnerAdmissionTransitionResult{},
				&vnextOwnerAdmissionRequestConflictError{RequestID: request.RequestID}
		}
		return vnextOwnerAdmissionTransitionResult{Record: record, Replayed: true}, nil
	}
	if request.From != group.journal.AdmissionState ||
		request.ExpectedSequence != group.journal.AdmissionSequence {
		return vnextOwnerAdmissionTransitionResult{},
			&vnextOwnerAdmissionSequenceConflictError{
				CurrentState:     group.journal.AdmissionState,
				CurrentSequence:  group.journal.AdmissionSequence,
				RequestedFrom:    request.From,
				ExpectedSequence: request.ExpectedSequence,
			}
	}
	if len(group.journal.AdmissionTransitions) >= vnextMaxOwnerAdmissionTransitions {
		return vnextOwnerAdmissionTransitionResult{}, fmt.Errorf(
			"Owner admission transition history is full: %w", errVNextMetadataFull)
	}
	record := vnextOwnerAdmissionTransitionRecord{
		RequestID:        request.RequestID,
		RequestDigest:    digest,
		From:             request.From,
		Target:           request.Target,
		ExpectedSequence: request.ExpectedSequence,
		ResultSequence:   request.ExpectedSequence + 1,
	}
	candidate := group.journal.clone()
	candidate.AdmissionState = request.Target
	candidate.AdmissionSequence = record.ResultSequence
	candidate.AdmissionTransitions = append(candidate.AdmissionTransitions, record)
	if err := group.persistJournalLocked(candidate); err != nil {
		return vnextOwnerAdmissionTransitionResult{}, group.poisonLocked(fmt.Errorf(
			"persist Owner admission transition: %w", err))
	}
	return vnextOwnerAdmissionTransitionResult{Record: record}, nil
}

func (group *vnextOwnerGroup) admissionSnapshotLocked() vnextOwnerAdmissionSnapshot {
	snapshot := vnextOwnerAdmissionSnapshot{
		OwnerID:           group.ownerID,
		OwnerEpoch:        group.ownerEpoch,
		State:             group.journal.AdmissionState,
		AdmissionSequence: group.journal.AdmissionSequence,
		SnapshotSequence:  group.journal.SnapshotSequence,
	}
	if count := len(group.journal.AdmissionTransitions); count != 0 {
		snapshot.HasLastTransition = true
		snapshot.LastTransition = group.journal.AdmissionTransitions[count-1]
	}
	return snapshot
}

func (group *vnextOwnerGroup) requireNewAllocationAdmissionLocked(operation string) error {
	if group.journal == nil || !group.journal.AdmissionState.valid() ||
		group.journal.AdmissionSequence == 0 {
		return fmt.Errorf("Owner admission metadata is invalid: %w", errVNextCorrupt)
	}
	if group.journal.AdmissionState != vnextOwnerAdmissionActive {
		return &vnextOwnerAdmissionClosedError{
			Operation: operation,
			State:     group.journal.AdmissionState,
			Sequence:  group.journal.AdmissionSequence,
		}
	}
	return nil
}

func (group *vnextOwnerGroup) requireProducerMutationAllowedLocked(operation string) error {
	if group.journal == nil || !group.journal.AdmissionState.valid() ||
		group.journal.AdmissionSequence == 0 {
		return fmt.Errorf("Owner admission metadata is invalid: %w", errVNextCorrupt)
	}
	if group.journal.AdmissionState == vnextOwnerAdmissionFenced {
		return &vnextOwnerAdmissionClosedError{
			Operation: operation,
			State:     group.journal.AdmissionState,
			Sequence:  group.journal.AdmissionSequence,
		}
	}
	return nil
}

func (group *vnextOwnerGroup) requireReclaimSafetyLocked(operation string) error {
	if group.journal == nil || !group.journal.AdmissionState.valid() ||
		group.journal.AdmissionSequence == 0 {
		return fmt.Errorf("Owner admission metadata is invalid: %w", errVNextCorrupt)
	}
	if group.journal.AdmissionState == vnextOwnerAdmissionFenced {
		return &vnextOwnerAdmissionClosedError{
			Operation: operation,
			State:     group.journal.AdmissionState,
			Sequence:  group.journal.AdmissionSequence,
		}
	}
	return nil
}

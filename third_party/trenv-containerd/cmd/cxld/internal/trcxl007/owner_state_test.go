package trcxl007

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/containerd/containerd/third_party/trenv-containerd/pkg/cxlcheckpoint"
)

const (
	ownerStateKnownMembershipSHA256 = "e4ed58ce1730f545f2439b7b7fb20316c139b483849ff438e880b1e8914aff6f"
	ownerStateKnownEnvelopeSHA256   = "846141f607a13416e9f01be4823737b7e50992d27b6b06c186394b6ebea73fe6"
)

func TestOwnerStateKnownAnswerRoundTripAndStorage(t *testing.T) {
	geometry := ownerStateTestGeometry(t, 64<<10)
	snapshot := ownerStateTestSnapshot(t)
	wire, err := CanonicalOwnerStateBytes(snapshot, geometry)
	if err != nil {
		t.Fatalf("CanonicalOwnerStateBytes: %v", err)
	}
	if got := string(wire[:8]); got != OwnerStateMagicString {
		t.Fatalf("magic = %q, want %q", got, OwnerStateMagicString)
	}
	if got := binary.LittleEndian.Uint32(wire[8:12]); got != OwnerStateVersion {
		t.Fatalf("version = %d, want %d", got, OwnerStateVersion)
	}
	if got := binary.LittleEndian.Uint32(wire[12:16]); got != uint32(OwnerStateEnvelopeHeaderBytes) {
		t.Fatalf("header bytes = %d, want %d", got, OwnerStateEnvelopeHeaderBytes)
	}
	wantDomain := make([]byte, ownerStateDomainFieldBytes)
	copy(wantDomain, OwnerStateDomain)
	if !bytes.Equal(wire[16:48], wantDomain) {
		t.Fatalf("domain bytes = %x, want %x", wire[16:48], wantDomain)
	}
	if got := binary.LittleEndian.Uint64(wire[48:56]); got != uint64(len(wire))-64 {
		t.Fatalf("payload length = %d, want %d", got, len(wire)-64)
	}
	recordOffset := int(OwnerStateEnvelopeHeaderBytes)
	for index := 0; index < 5; index++ {
		length := int(binary.LittleEndian.Uint32(wire[recordOffset : recordOffset+4]))
		recordOffset += 4 + length
	}
	recordOffset += 80
	deviceCount := int(binary.LittleEndian.Uint32(wire[recordOffset-8 : recordOffset-4]))
	for index := 0; index < deviceCount; index++ {
		length := int(binary.LittleEndian.Uint32(wire[recordOffset : recordOffset+4]))
		recordOffset += 4 + length + 8 + 8 + sha256.Size
	}
	if got := binary.LittleEndian.Uint64(wire[recordOffset:]); got != 29 {
		t.Fatalf("wire allocation-record ID = %d, want 29", got)
	}
	if got := binary.LittleEndian.Uint64(wire[recordOffset+8:]); got != 31 {
		t.Fatalf("wire reservation transaction = %d, want 31", got)
	}
	if got := binary.LittleEndian.Uint64(wire[recordOffset+16:]); got != 31 {
		t.Fatalf("wire current Owner transaction = %d, want 31", got)
	}
	if got := OwnerAllocationState(wire[recordOffset+24]); got != OwnerAllocationPreparing {
		t.Fatalf("wire allocation state = %d, want PREPARING", got)
	}

	membershipHex := hex.EncodeToString(snapshot.MembershipSHA256[:])
	if membershipHex != ownerStateKnownMembershipSHA256 {
		t.Fatalf("membership SHA-256 = %s, freeze as known answer", membershipHex)
	}
	wireSHA := sha256.Sum256(wire)
	wireHex := hex.EncodeToString(wireSHA[:])
	if wireHex != ownerStateKnownEnvelopeSHA256 {
		t.Fatalf("envelope SHA-256 = %s, freeze as known answer (length %d)", wireHex, len(wire))
	}

	parsed, err := ParseOwnerState(wire, geometry)
	if err != nil {
		t.Fatalf("ParseOwnerState: %v", err)
	}
	if !reflect.DeepEqual(parsed, snapshot) {
		t.Fatalf("round trip differs:\n got %#v\nwant %#v", parsed, snapshot)
	}
	requestRecord, ok := parsed.AllocationRecordForRequest("request-29")
	if !ok || requestRecord.AllocationRecordID != 29 {
		t.Fatalf("request index = %#v, %v", requestRecord, ok)
	}
	checkpointRecord, ok := parsed.AllocationRecordForCheckpoint("checkpoint-29")
	if !ok || checkpointRecord.AllocationRecordID != 29 {
		t.Fatalf("checkpoint index = %#v, %v", checkpointRecord, ok)
	}
	if _, ok := parsed.AllocationRecordForRequest("missing"); ok {
		t.Fatal("missing request unexpectedly resolved")
	}

	storage, err := EncodeOwnerStateForStorage(snapshot, geometry)
	if err != nil {
		t.Fatalf("EncodeOwnerStateForStorage: %v", err)
	}
	if storage.ExactLength() != uint64(len(wire)) ||
		storage.SlotLength() != geometry.OwnerStateSnapshotSlotBytes ||
		storage.SHA256() != wireSHA ||
		!bytes.Equal(storage.ExactBytes(), wire) {
		t.Fatalf("storage mismatch: length=%d slot=%d SHA=%x",
			storage.ExactLength(), storage.SlotLength(), storage.SHA256())
	}
	if storage.ExactLength() >= storage.SlotLength() {
		t.Fatalf("fixture must prove exact-only storage: exact=%d slot=%d",
			storage.ExactLength(), storage.SlotLength())
	}
	first := storage.ExactBytes()
	first[0] ^= 0xff
	if bytes.Equal(first, storage.ExactBytes()) {
		t.Fatal("ExactBytes aliases internal storage")
	}
}

func TestOwnerStateV2StateNumbersAndTransactionSemantics(t *testing.T) {
	wantNumbers := []OwnerAllocationState{
		OwnerAllocationPreparing,
		OwnerAllocationGranted,
		OwnerAllocationCommitting,
		OwnerAllocationCommitted,
		OwnerAllocationAborting,
		OwnerAllocationAborted,
		OwnerAllocationReclaiming,
		OwnerAllocationReclaimed,
		OwnerAllocationQuarantined,
		OwnerAllocationRejectedNoSpace,
		OwnerAllocationCanceling,
		OwnerAllocationCanceled,
	}
	for index, state := range wantNumbers {
		if got, want := uint8(state), uint8(index+1); got != want {
			t.Fatalf("state %d numeric value = %d, want %d", index, got, want)
		}
	}

	base := ownerStateTestSnapshot(t)
	checks := []struct {
		name   string
		mutate func(*OwnerStateSnapshot)
	}{
		{"preparing-reservation-differs", func(value *OwnerStateSnapshot) {
			value.records[0].ReservationTransactionSequence--
		}},
		{"reservation-after-current", func(value *OwnerStateSnapshot) {
			value.records[0].ReservationTransactionSequence++
		}},
		{"granted-not-reservation-plus-one", func(value *OwnerStateSnapshot) {
			value.records[0].State = OwnerAllocationGranted
		}},
		{"rejected-retains-reservation", func(value *OwnerStateSnapshot) {
			value.records[0].State = OwnerAllocationRejectedNoSpace
			value.records[0].Fragments = nil
		}},
	}
	for _, check := range checks {
		t.Run(check.name, func(t *testing.T) {
			candidate := base.Clone()
			check.mutate(&candidate)
			if err := candidate.Validate(); !errors.Is(err, ErrInvalidOwnerState) {
				t.Fatalf("Validate error = %v", err)
			}
		})
	}

	granted := base.Clone()
	granted.records[0].State = OwnerAllocationGranted
	granted.records[0].OwnerTransactionSequence++
	granted.NextOwnerTransactionSequence++
	if err := granted.Validate(); err != nil {
		t.Fatalf("valid GRANTED reservation/current pair: %v", err)
	}

	canceled := granted.Clone()
	canceled.records[0].State = OwnerAllocationCanceled
	if err := canceled.Validate(); err != nil {
		t.Fatalf("CANCELED terminal state: %v", err)
	}
}

func TestOwnerStatePreparingAllowsAlternatingDevicePlacement(t *testing.T) {
	snapshot := ownerStateTestSnapshot(t)
	record := snapshot.records[0]
	if record.State != OwnerAllocationPreparing {
		t.Fatalf("fixture state = %d, want PREPARING", record.State)
	}
	if record.Fragments[0].TargetAllocatorSnapshotSequence == 0 ||
		record.Fragments[1].TargetAllocatorSnapshotSequence == 0 {
		t.Fatal("PREPARING target allocator sequence is not positive")
	}
	// device-a owns logical 0..2 and 4..6, while device-b owns 2..4.
	if got := record.Fragments[0].Extents[1].LogicalPageStart; got != 4 {
		t.Fatalf("device-a second logical start = %d, want 4", got)
	}
	if got := record.Fragments[1].Extents[0].LogicalPageStart; got != 2 {
		t.Fatalf("device-b logical start = %d, want 2", got)
	}
	if err := snapshot.Validate(); err != nil {
		t.Fatalf("A/B/A PREPARING snapshot: %v", err)
	}

	// Physical adjacency alone is not coalescible when device-a's two runs are
	// separated in logical space by device-b.
	adjacentPhysical := snapshot.Clone()
	adjacentPhysical.records[0].Fragments[0].Extents[1].StartDataPageIndex = 12
	if err := adjacentPhysical.Validate(); err != nil {
		t.Fatalf("physically adjacent but logically disjoint extents rejected: %v", err)
	}

	zeroTarget := snapshot.Clone()
	zeroTarget.records[0].Fragments[0].TargetAllocatorSnapshotSequence = 0
	if err := zeroTarget.Validate(); !errors.Is(err, ErrInvalidOwnerState) {
		t.Fatalf("zero target sequence error = %v", err)
	}
}

func TestOwnerStateMembershipDigestAndBootstrap(t *testing.T) {
	snapshot := ownerStateTestSnapshot(t)
	digest, err := OwnerGroupMembershipSHA256(snapshot.Devices())
	if err != nil {
		t.Fatalf("OwnerGroupMembershipSHA256: %v", err)
	}
	if digest != snapshot.MembershipSHA256 {
		t.Fatalf("membership digest = %x, want %x", digest, snapshot.MembershipSHA256)
	}
	bootstrap := ownerStateTestBootstrap(snapshot)
	if err := snapshot.CrossCheckBootstrap(bootstrap); err != nil {
		t.Fatalf("CrossCheckBootstrap: %v", err)
	}

	checks := []struct {
		name   string
		mutate func(*OwnerStateBootstrap)
	}{
		{"cluster", func(value *OwnerStateBootstrap) { value.ClusterID += "-other" }},
		{"group", func(value *OwnerStateBootstrap) { value.OwnerGroupID += "-other" }},
		{"Owner", func(value *OwnerStateBootstrap) { value.CurrentOwnerID += "-other" }},
		{"anchor", func(value *OwnerStateBootstrap) { value.AnchorDeviceUUID = "device-b" }},
		{"compatibility", func(value *OwnerStateBootstrap) { value.StorageCompatibilityID += "-other" }},
		{"epoch", func(value *OwnerStateBootstrap) { value.OwnerEpoch++ }},
		{"configuration", func(value *OwnerStateBootstrap) { value.GroupConfigurationSequence++ }},
		{"membership", func(value *OwnerStateBootstrap) { value.MembershipSHA256[0] ^= 1 }},
		{"device", func(value *OwnerStateBootstrap) {
			value.Devices[0].DataPageCount++
			value.MembershipSHA256, _ = OwnerGroupMembershipSHA256(value.Devices)
		}},
	}
	for _, check := range checks {
		t.Run(check.name, func(t *testing.T) {
			candidate := bootstrap
			candidate.Devices = cloneOwnerStateDevices(bootstrap.Devices)
			check.mutate(&candidate)
			if err := snapshot.CrossCheckBootstrap(candidate); !errors.Is(err, ErrOwnerStateBootstrapMismatch) {
				t.Fatalf("CrossCheckBootstrap error = %v", err)
			}
		})
	}

	unsorted := snapshot.Devices()
	unsorted[0], unsorted[1] = unsorted[1], unsorted[0]
	if _, err := OwnerGroupMembershipSHA256(unsorted); !errors.Is(err, ErrInvalidOwnerState) {
		t.Fatalf("unsorted membership error = %v", err)
	}
	duplicate := snapshot.Devices()
	duplicate[1].DeviceUUID = duplicate[0].DeviceUUID
	if _, err := OwnerGroupMembershipSHA256(duplicate); !errors.Is(err, ErrInvalidOwnerState) {
		t.Fatalf("duplicate membership error = %v", err)
	}
	path := snapshot.Devices()
	path[0].DeviceUUID = "/dev/dax0.0"
	if _, err := OwnerGroupMembershipSHA256(path); !errors.Is(err, ErrInvalidOwnerState) {
		t.Fatalf("path membership error = %v", err)
	}
	zeroBinding := snapshot.Devices()
	zeroBinding[0].DeviceBindingSHA256 = [sha256.Size]byte{}
	if _, err := OwnerGroupMembershipSHA256(zeroBinding); !errors.Is(err, ErrInvalidOwnerState) {
		t.Fatalf("zero binding error = %v", err)
	}
}

func TestOwnerStateDeepCopyAndIndexRebuild(t *testing.T) {
	config := ownerStateTestConfig(t)
	snapshot, err := NewOwnerStateSnapshot(config)
	if err != nil {
		t.Fatalf("NewOwnerStateSnapshot: %v", err)
	}
	config.Devices[0].DeviceUUID = "mutated-device"
	config.Records[0].RequestID = "mutated-request"
	config.Records[0].ContentDemands[0].ObjectID++
	config.Records[0].Fragments[0].Extents[0].StartDataPageIndex++
	if snapshot.devices[0].DeviceUUID != "device-a" ||
		snapshot.records[0].RequestID != "request-29" ||
		snapshot.records[0].ContentDemands[0].ObjectID != 1 ||
		snapshot.records[0].Fragments[0].Extents[0].StartDataPageIndex != 10 {
		t.Fatal("constructed snapshot aliases input")
	}

	devices := snapshot.Devices()
	records := snapshot.Records()
	devices[0].DeviceUUID = "mutated-device"
	records[0].ContentDemands[0].ObjectID++
	records[0].Fragments[0].Extents[0].StartDataPageIndex++
	indexed, ok := snapshot.AllocationRecordForRequest("request-29")
	if !ok || indexed.ContentDemands[0].ObjectID != 1 ||
		indexed.Fragments[0].Extents[0].StartDataPageIndex != 10 ||
		snapshot.devices[0].DeviceUUID != "device-a" {
		t.Fatal("snapshot accessors alias internal state")
	}
	indexed.ContentDemands[0].ObjectID++
	again, _ := snapshot.AllocationRecordForRequest("request-29")
	if again.ContentDemands[0].ObjectID != 1 {
		t.Fatal("request lookup aliases internal state")
	}
	if snapshot.requestIndex["request-29"] != 0 ||
		snapshot.checkpointIndex["checkpoint-29"] != 0 {
		t.Fatal("constructor did not rebuild derived indexes")
	}

	geometry := ownerStateTestGeometry(t, 64<<10)
	wire := ownerStateTestEncode(t, snapshot, geometry)
	indexPoisoned := snapshot.Clone()
	indexPoisoned.requestIndex = map[string]int{"not-encoded": 99}
	indexPoisoned.checkpointIndex = map[string]int{"not-encoded": 99}
	if got := ownerStateTestEncode(t, indexPoisoned, geometry); !bytes.Equal(got, wire) {
		t.Fatal("derived indexes changed canonical bytes")
	}
	parsed, err := ParseOwnerState(wire, geometry)
	if err != nil {
		t.Fatalf("parse indexed fixture: %v", err)
	}
	if parsed.requestIndex["request-29"] != 0 ||
		parsed.checkpointIndex["checkpoint-29"] != 0 {
		t.Fatal("parser did not rebuild derived indexes")
	}

	typeOfSnapshot := reflect.TypeOf(OwnerStateSnapshot{})
	for _, forbidden := range []string{"RequestIndex", "CheckpointIndex"} {
		if _, exists := typeOfSnapshot.FieldByName(forbidden); exists {
			t.Fatalf("snapshot persists derived %s", forbidden)
		}
	}
}

func TestOwnerStateAllStatesAndNoSpaceSemantics(t *testing.T) {
	base := ownerStateTestSnapshot(t)
	geometry := ownerStateTestGeometry(t, 64<<10)
	states := []OwnerAllocationState{
		OwnerAllocationPreparing,
		OwnerAllocationGranted,
		OwnerAllocationCommitting,
		OwnerAllocationCommitted,
		OwnerAllocationAborting,
		OwnerAllocationAborted,
		OwnerAllocationReclaiming,
		OwnerAllocationReclaimed,
		OwnerAllocationQuarantined,
		OwnerAllocationRejectedNoSpace,
		OwnerAllocationCanceling,
		OwnerAllocationCanceled,
	}
	for _, state := range states {
		t.Run(fmt.Sprintf("state-%d", state), func(t *testing.T) {
			candidate := base.Clone()
			candidate.records[0].State = state
			switch state {
			case OwnerAllocationGranted:
				candidate.records[0].OwnerTransactionSequence++
				candidate.NextOwnerTransactionSequence++
			case OwnerAllocationRejectedNoSpace:
				candidate.records[0].ReservationTransactionSequence = 0
				candidate.records[0].Fragments = nil
			}
			if err := candidate.Validate(); err != nil {
				t.Fatalf("valid state %d: %v", state, err)
			}
			wire := ownerStateTestEncode(t, candidate, geometry)
			parsed, err := ParseOwnerState(wire, geometry)
			if err != nil || parsed.records[0].State != state {
				t.Fatalf("state %d codec = %d, %v", state, parsed.records[0].State, err)
			}
		})
	}

	noSpaceWithFragments := base.Clone()
	noSpaceWithFragments.records[0].State = OwnerAllocationRejectedNoSpace
	noSpaceWithFragments.records[0].ReservationTransactionSequence = 0
	if err := noSpaceWithFragments.Validate(); !errors.Is(err, ErrInvalidOwnerState) {
		t.Fatalf("no-space fragments error = %v", err)
	}
	liveWithoutFragments := base.Clone()
	liveWithoutFragments.records[0].Fragments = nil
	if err := liveWithoutFragments.Validate(); !errors.Is(err, ErrInvalidOwnerState) {
		t.Fatalf("live no-fragments error = %v", err)
	}
	noSpace := base.Clone()
	noSpace.records[0].State = OwnerAllocationRejectedNoSpace
	noSpace.records[0].ReservationTransactionSequence = 0
	noSpace.records[0].Fragments = nil
	if noSpace.records[0].AllocationRecordID == 0 || noSpace.records[0].TotalDemandPages == 0 {
		t.Fatal("no-space fixture lost positive identity or exact demand")
	}
	if err := noSpace.Validate(); err != nil {
		t.Fatalf("valid no-space tombstone: %v", err)
	}
}

func TestOwnerStateValidationRejectsCanonicalityAndCoverageErrors(t *testing.T) {
	base := ownerStateTestSnapshot(t)
	checks := []struct {
		name   string
		mutate func(*OwnerStateSnapshot)
	}{
		{"zero-owner-epoch", func(value *OwnerStateSnapshot) { value.OwnerEpoch = 0 }},
		{"large-snapshot-sequence", func(value *OwnerStateSnapshot) {
			value.SnapshotSequence = cxlcheckpoint.MaxSignedLong + 1
		}},
		{"zero-next-allocation", func(value *OwnerStateSnapshot) { value.NextAllocationRecordID = 0 }},
		{"next-allocation-not-high", func(value *OwnerStateSnapshot) { value.NextAllocationRecordID = 29 }},
		{"next-transaction-not-high", func(value *OwnerStateSnapshot) {
			value.NextOwnerTransactionSequence = 31
		}},
		{"membership-digest", func(value *OwnerStateSnapshot) { value.MembershipSHA256[0] ^= 1 }},
		{"anchor-missing", func(value *OwnerStateSnapshot) { value.AnchorDeviceUUID = "device-c" }},
		{"device-unsorted", func(value *OwnerStateSnapshot) {
			value.devices[0], value.devices[1] = value.devices[1], value.devices[0]
		}},
		{"record-zero-id", func(value *OwnerStateSnapshot) { value.records[0].AllocationRecordID = 0 }},
		{"record-zero-transaction", func(value *OwnerStateSnapshot) {
			value.records[0].OwnerTransactionSequence = 0
		}},
		{"record-zero-reservation", func(value *OwnerStateSnapshot) {
			value.records[0].ReservationTransactionSequence = 0
		}},
		{"record-bad-state", func(value *OwnerStateSnapshot) { value.records[0].State = 0 }},
		{"request-digest-zero", func(value *OwnerStateSnapshot) {
			value.records[0].RequestSHA256 = [sha256.Size]byte{}
		}},
		{"content-object-unsorted", func(value *OwnerStateSnapshot) {
			value.records[0].ContentDemands[1].ObjectID = 1
		}},
		{"content-gap", func(value *OwnerStateSnapshot) {
			value.records[0].ContentDemands[1].LogicalPageStart++
		}},
		{"content-capacity", func(value *OwnerStateSnapshot) {
			value.records[0].ContentDemands[1].ByteLength = 9000
		}},
		{"fragment-unsorted", func(value *OwnerStateSnapshot) {
			value.records[0].Fragments[0], value.records[0].Fragments[1] =
				value.records[0].Fragments[1], value.records[0].Fragments[0]
		}},
		{"fragment-device-missing", func(value *OwnerStateSnapshot) {
			value.records[0].Fragments[1].DeviceUUID = "device-c"
		}},
		{"fragment-epoch", func(value *OwnerStateSnapshot) {
			value.records[0].Fragments[0].DeviceOwnerEpoch++
		}},
		{"extent-logical-order", func(value *OwnerStateSnapshot) {
			value.records[0].Fragments[0].Extents[1].LogicalPageStart = 0
		}},
		{"extent-logical-gap", func(value *OwnerStateSnapshot) {
			value.records[0].Fragments[1].Extents[0].LogicalPageStart = 3
		}},
		{"extent-physical-overlap", func(value *OwnerStateSnapshot) {
			value.records[0].Fragments[0].Extents[1].StartDataPageIndex = 11
		}},
		{"extent-capacity", func(value *OwnerStateSnapshot) {
			value.records[0].Fragments[1].Extents[0].StartDataPageIndex = 127
		}},
		{"too-many-for-request", func(value *OwnerStateSnapshot) {
			value.records[0].MaxExtents = 2
		}},
	}
	for _, check := range checks {
		t.Run(check.name, func(t *testing.T) {
			candidate := base.Clone()
			check.mutate(&candidate)
			if err := candidate.Validate(); !errors.Is(err, ErrInvalidOwnerState) {
				t.Fatalf("Validate error = %v", err)
			}
		})
	}

	coalescible := base.Clone()
	coalescible.records[0].Fragments[0].Extents = []OwnerStateExtent{
		{StartDataPageIndex: 10, LogicalPageStart: 0, PageCount: 2},
		{StartDataPageIndex: 12, LogicalPageStart: 2, PageCount: 2},
	}
	coalescible.records[0].Fragments[1].Extents[0].LogicalPageStart = 4
	if err := coalescible.Validate(); !errors.Is(err, ErrInvalidOwnerState) {
		t.Fatalf("coalescible extents error = %v", err)
	}
}

func TestOwnerStateDuplicateRequestCheckpointAndRecordOrdering(t *testing.T) {
	base := ownerStateTestSnapshot(t)
	second := cloneOwnerStateRecord(base.records[0])
	second.AllocationRecordID = 30
	second.ReservationTransactionSequence = 32
	second.OwnerTransactionSequence = 32
	second.RequestID = "request-30"
	second.CheckpointID = "checkpoint-30"
	base.records = append(base.records, second)
	base.NextAllocationRecordID = 31
	base.NextOwnerTransactionSequence = 33
	if err := base.Validate(); err != nil {
		t.Fatalf("two records: %v", err)
	}

	checks := []struct {
		name   string
		mutate func(*OwnerStateSnapshot)
	}{
		{"record-order", func(value *OwnerStateSnapshot) {
			value.records[0], value.records[1] = value.records[1], value.records[0]
		}},
		{"duplicate-request", func(value *OwnerStateSnapshot) {
			value.records[1].RequestID = value.records[0].RequestID
		}},
		{"duplicate-checkpoint", func(value *OwnerStateSnapshot) {
			value.records[1].CheckpointID = value.records[0].CheckpointID
		}},
		{"duplicate-owner-transaction", func(value *OwnerStateSnapshot) {
			value.records[1].OwnerTransactionSequence = value.records[0].OwnerTransactionSequence
			value.records[1].ReservationTransactionSequence = 30
			value.records[1].State = OwnerAllocationCommitted
		}},
		{"duplicate-reservation-transaction", func(value *OwnerStateSnapshot) {
			value.records[1].ReservationTransactionSequence =
				value.records[0].ReservationTransactionSequence
			value.records[1].State = OwnerAllocationCommitted
		}},
		{"reservation-collides-with-other-current", func(value *OwnerStateSnapshot) {
			value.records[0].State = OwnerAllocationCommitted
			value.records[0].OwnerTransactionSequence = 32
			value.records[1].State = OwnerAllocationCommitted
			value.records[1].ReservationTransactionSequence = 32
			value.records[1].OwnerTransactionSequence = 33
			value.NextOwnerTransactionSequence = 34
		}},
	}
	for _, check := range checks {
		t.Run(check.name, func(t *testing.T) {
			candidate := base.Clone()
			check.mutate(&candidate)
			if err := candidate.Validate(); !errors.Is(err, ErrInvalidOwnerState) {
				t.Fatalf("Validate error = %v", err)
			}
		})
	}
}

func TestOwnerStateMetadataFullBeforeEncoding(t *testing.T) {
	geometry := ownerStateTestGeometry(t, 4096)
	base := ownerStateTestSnapshot(t)
	records := make([]OwnerStateAllocationRecord, 32)
	for index := range records {
		records[index] = ownerStateTestNoSpaceRecord(uint64(index + 1))
	}
	base.records = records
	base.NextAllocationRecordID = uint64(len(records) + 1)
	base.NextOwnerTransactionSequence = uint64(len(records) + 2)
	base.rebuildIndexes()
	before := base.Clone()
	if _, err := CanonicalOwnerStateBytes(base, geometry); !errors.Is(err, ErrOwnerStateMetadataFull) {
		t.Fatalf("metadata-full error = %v", err)
	}
	if !reflect.DeepEqual(base, before) {
		t.Fatal("metadata-full preflight mutated snapshot")
	}
}

func TestOwnerStateParserRejectsTruncationCorruptionAndCountAttacks(t *testing.T) {
	geometry := ownerStateTestGeometry(t, 64<<10)
	snapshot := ownerStateTestSnapshot(t)
	wire, err := CanonicalOwnerStateBytes(snapshot, geometry)
	if err != nil {
		t.Fatalf("encode fixture: %v", err)
	}
	for length := 0; length < len(wire); length++ {
		if _, err := ParseOwnerState(wire[:length], geometry); err == nil {
			t.Fatalf("truncation at %d bytes succeeded", length)
		}
	}
	trailing := append(append([]byte(nil), wire...), 0)
	if _, err := ParseOwnerState(trailing, geometry); !errors.Is(err, ErrCorruptOwnerState) {
		t.Fatalf("trailing-byte error = %v", err)
	}

	checks := []struct {
		name   string
		mutate func([]byte)
		want   error
	}{
		{"magic", func(value []byte) { value[0] ^= 1 }, ErrWrongOwnerStateFormat},
		{"version", func(value []byte) { binary.LittleEndian.PutUint32(value[8:12], 8) }, ErrWrongOwnerStateFormat},
		{"domain", func(value []byte) { value[16] ^= 1 }, ErrWrongOwnerStateFormat},
		{"header-crc", func(value []byte) { value[60] ^= 1 }, ErrCorruptOwnerState},
		{"payload", func(value []byte) { value[len(value)-1] ^= 1 }, ErrCorruptOwnerState},
	}
	for _, check := range checks {
		t.Run(check.name, func(t *testing.T) {
			candidate := append([]byte(nil), wire...)
			check.mutate(candidate)
			if _, err := ParseOwnerState(candidate, geometry); !errors.Is(err, check.want) {
				t.Fatalf("ParseOwnerState error = %v, want %v", err, check.want)
			}
		})
	}

	oldDraftDomain := append([]byte(nil), wire...)
	var oldDomain [ownerStateDomainFieldBytes]byte
	copy(oldDomain[:], "owner-group-full-snapshot-v1")
	copy(oldDraftDomain[ownerStateDomainOffset:ownerStatePayloadLengthOffset], oldDomain[:])
	ownerStateTestRefreshCRCs(oldDraftDomain)
	if _, err := ParseOwnerState(oldDraftDomain, geometry); !errors.Is(err, ErrWrongOwnerStateFormat) {
		t.Fatalf("old draft-v1 domain error = %v, want wrong format", err)
	}

	oversized := append([]byte(nil), wire[:64]...)
	binary.LittleEndian.PutUint64(
		oversized[ownerStatePayloadLengthOffset:], geometry.OwnerStateSnapshotSlotBytes)
	binary.LittleEndian.PutUint32(oversized[ownerStateHeaderCRCOffset:], 0)
	binary.LittleEndian.PutUint32(
		oversized[ownerStateHeaderCRCOffset:], ownerStateHeaderCRC32C(oversized))
	if _, err := ParseOwnerState(oversized, geometry); !errors.Is(err, ErrCorruptOwnerState) {
		t.Fatalf("oversized declared payload error = %v", err)
	}

	// Locate the two top-level counts without relying on fixed identity lengths,
	// then prove count bounds are checked before any table allocation.
	countAttack := append([]byte(nil), wire...)
	offset := int(OwnerStateEnvelopeHeaderBytes)
	for index := 0; index < 5; index++ {
		length := int(binary.LittleEndian.Uint32(countAttack[offset : offset+4]))
		offset += 4 + length
	}
	offset += 8 + 8 + sha256.Size + 8 + 8 + 8
	binary.LittleEndian.PutUint32(countAttack[offset:offset+4], MaxOwnerStateDevices+1)
	ownerStateTestRefreshCRCs(countAttack)
	if _, err := ParseOwnerState(countAttack, geometry); !errors.Is(err, ErrCorruptOwnerState) {
		t.Fatalf("device-count attack error = %v", err)
	}

	// Counts at their global maxima can still be impossible for this slot.
	// Exercise every variable-size table gate with a CRC-correct envelope.
	cursor := int(OwnerStateEnvelopeHeaderBytes)
	for index := 0; index < 5; index++ {
		length := int(binary.LittleEndian.Uint32(wire[cursor : cursor+4]))
		cursor += 4 + length
	}
	cursor += 8 + 8 + sha256.Size + 8 + 8 + 8
	deviceCountOffset := cursor
	recordCountOffset := cursor + 4
	deviceCount := int(binary.LittleEndian.Uint32(wire[deviceCountOffset : deviceCountOffset+4]))
	cursor += 8
	for index := 0; index < deviceCount; index++ {
		length := int(binary.LittleEndian.Uint32(wire[cursor : cursor+4]))
		cursor += 4 + length + 8 + 8 + sha256.Size
	}
	cursor += 8 + 8 + 8 + ownerStateStateFieldBytes
	for index := 0; index < 5; index++ {
		length := int(binary.LittleEndian.Uint32(wire[cursor : cursor+4]))
		cursor += 4 + length
	}
	cursor += sha256.Size + 8 + 4
	contentCountOffset := cursor
	contentCount := int(binary.LittleEndian.Uint32(wire[contentCountOffset : contentCountOffset+4]))
	cursor += 4 + contentCount*int(ownerStateContentDemandWireBytes)
	fragmentCountOffset := cursor
	cursor += 8
	fragmentUUIDLength := int(binary.LittleEndian.Uint32(wire[cursor : cursor+4]))
	cursor += 4 + fragmentUUIDLength + 8 + 8
	extentCountOffset := cursor

	feasibilityChecks := []struct {
		name   string
		offset int
		count  uint32
	}{
		{"device", deviceCountOffset, MaxOwnerStateDevices},
		{"record", recordCountOffset, MaxOwnerStateRecords},
		{"content", contentCountOffset, MaxOwnerStateContentDemands},
		{"fragment", fragmentCountOffset, MaxOwnerStateDevices},
		{"extent", extentCountOffset, MaxOwnerStateExtents},
	}
	for _, check := range feasibilityChecks {
		t.Run("count-feasibility-"+check.name, func(t *testing.T) {
			candidate := append([]byte(nil), wire...)
			binary.LittleEndian.PutUint32(candidate[check.offset:check.offset+4], check.count)
			ownerStateTestRefreshCRCs(candidate)
			if _, err := ParseOwnerState(candidate, geometry); !errors.Is(err, ErrCorruptOwnerState) {
				t.Fatalf("ParseOwnerState error = %v", err)
			}
		})
	}
}

func TestOwnerStateSelectLatestValidAB(t *testing.T) {
	geometry := ownerStateTestGeometry(t, 64<<10)
	left := ownerStateTestSnapshot(t)
	right := left.Clone()
	right.SnapshotSequence++
	leftBytes := ownerStateTestEncode(t, left, geometry)
	rightBytes := ownerStateTestEncode(t, right, geometry)

	slot, selected, err := SelectLatestValidOwnerState(leftBytes, rightBytes, geometry)
	if err != nil || slot != OwnerStateSlotB || selected.SnapshotSequence != right.SnapshotSequence {
		t.Fatalf("latest selection = %s/%d, %v", slot, selected.SnapshotSequence, err)
	}
	corruptRight := append([]byte(nil), rightBytes...)
	corruptRight[len(corruptRight)-1] ^= 1
	slot, selected, err = SelectLatestValidOwnerState(leftBytes, corruptRight, geometry)
	if err != nil || slot != OwnerStateSlotA || selected.SnapshotSequence != left.SnapshotSequence {
		t.Fatalf("corrupt-newer fallback = %s/%d, %v", slot, selected.SnapshotSequence, err)
	}
	blank := make([]byte, geometry.OwnerStateSnapshotSlotBytes)
	slot, _, err = SelectLatestValidOwnerState(leftBytes, blank, geometry)
	if err != nil || slot != OwnerStateSlotA {
		t.Fatalf("blank fallback slot = %s, %v", slot, err)
	}
	if _, _, err := SelectLatestValidOwnerState(blank, blank, geometry); !errors.Is(err, ErrNoValidOwnerState) {
		t.Fatalf("both blank error = %v", err)
	}

	// Complete slot images may retain an old nonzero tail. Only the declared
	// exact envelope participates in validity and equal-sequence comparison.
	fullLeft := bytes.Repeat([]byte{0xa5}, int(geometry.OwnerStateSnapshotSlotBytes))
	copy(fullLeft, leftBytes)
	slot, selected, err = SelectLatestValidOwnerState(fullLeft, blank, geometry)
	if err != nil || slot != OwnerStateSlotA || selected.SnapshotSequence != left.SnapshotSequence {
		t.Fatalf("full-slot selection = %s/%d, %v", slot, selected.SnapshotSequence, err)
	}

	slot, _, err = SelectLatestValidOwnerState(leftBytes, append([]byte(nil), leftBytes...), geometry)
	if err != nil || slot != OwnerStateSlotA {
		t.Fatalf("identical equal sequence = %s, %v", slot, err)
	}
	split := left.Clone()
	split.CurrentOwnerID = "owner-other"
	splitBytes := ownerStateTestEncode(t, split, geometry)
	if _, _, err := SelectLatestValidOwnerState(leftBytes, splitBytes, geometry); !errors.Is(err, ErrOwnerStateSplitBrain) {
		t.Fatalf("equal-sequence split-brain error = %v", err)
	}
}

func TestOwnerStateMaximumBounds(t *testing.T) {
	geometry := ownerStateTestGeometryWithDevice(t, 64<<20, 4<<20)
	base := ownerStateTestSnapshot(t)
	base.devices = []OwnerStateDevice{
		{
			DeviceUUID:          "device-a",
			DeviceOwnerEpoch:    11,
			DataPageCount:       4096,
			DeviceBindingSHA256: sha256.Sum256([]byte("binding-a")),
		},
	}
	base.AnchorDeviceUUID = "device-a"
	base.MembershipSHA256, _ = OwnerGroupMembershipSHA256(base.devices)
	records := make([]OwnerStateAllocationRecord, MaxOwnerStateRecords)
	for index := range records {
		records[index] = ownerStateTestNoSpaceRecord(uint64(index + 1))
	}
	base.records = records
	base.NextAllocationRecordID = MaxOwnerStateRecords + 1
	base.NextOwnerTransactionSequence = MaxOwnerStateRecords + 2
	wire := ownerStateTestEncode(t, base, geometry)
	if _, err := ParseOwnerState(wire, geometry); err != nil {
		t.Fatalf("parse maximum records: %v", err)
	}

	tooManyRecords := base.Clone()
	tooManyRecords.records = append(
		tooManyRecords.records,
		ownerStateTestNoSpaceRecord(MaxOwnerStateRecords+1))
	tooManyRecords.NextAllocationRecordID++
	tooManyRecords.NextOwnerTransactionSequence++
	if err := tooManyRecords.Validate(); !errors.Is(err, ErrInvalidOwnerState) {
		t.Fatalf("too many records error = %v", err)
	}

	maximumRuns := ownerStateTestSnapshot(t)
	maximumRuns.devices[0].DataPageCount = 1024
	maximumRuns.MembershipSHA256, _ = OwnerGroupMembershipSHA256(maximumRuns.devices)
	contents := make([]OwnerStateContentDemand, MaxOwnerStateContentDemands)
	extents := make([]OwnerStateExtent, MaxOwnerStateExtents)
	for index := 0; index < MaxOwnerStateContentDemands; index++ {
		contents[index] = OwnerStateContentDemand{
			Kind:             cxlcheckpoint.ContentMemoryPayloadV7,
			ObjectID:         uint64(index + 1),
			ByteLength:       uint64(ContentPageBytes),
			CapacityPages:    1,
			LogicalPageStart: uint64(index),
		}
		extents[index] = OwnerStateExtent{
			StartDataPageIndex: uint64(index * 2),
			LogicalPageStart:   uint64(index),
			PageCount:          1,
		}
	}
	maximumRuns.records[0].ContentDemands = contents
	maximumRuns.records[0].TotalDemandPages = MaxOwnerStateContentDemands
	maximumRuns.records[0].MaxExtents = MaxOwnerStateExtents
	maximumRuns.records[0].Fragments = []OwnerStateDeviceFragment{
		{
			DeviceUUID:                      "device-a",
			DeviceOwnerEpoch:                11,
			TargetAllocatorSnapshotSequence: 12,
			Extents:                         extents,
		},
	}
	if err := maximumRuns.Validate(); err != nil {
		t.Fatalf("maximum content/extents: %v", err)
	}

	tooManyContents := maximumRuns.Clone()
	tooManyContents.records[0].ContentDemands = append(
		tooManyContents.records[0].ContentDemands,
		OwnerStateContentDemand{})
	if err := tooManyContents.Validate(); !errors.Is(err, ErrInvalidOwnerState) {
		t.Fatalf("too many contents error = %v", err)
	}
	tooManyExtents := maximumRuns.Clone()
	tooManyExtents.records[0].Fragments[0].Extents = append(
		tooManyExtents.records[0].Fragments[0].Extents,
		OwnerStateExtent{})
	if err := tooManyExtents.Validate(); !errors.Is(err, ErrInvalidOwnerState) {
		t.Fatalf("too many extents error = %v", err)
	}
}

func TestOwnerStateZeroValueAndStorageDoNotClaimIO(t *testing.T) {
	if err := (OwnerStateSnapshot{}).Validate(); !errors.Is(err, ErrInvalidOwnerState) {
		t.Fatalf("zero snapshot error = %v", err)
	}
	for _, value := range []reflect.Type{
		reflect.TypeOf(OwnerStateSnapshot{}),
		reflect.TypeOf(OwnerStateStorage{}),
		reflect.TypeOf(OwnerStateBootstrap{}),
	} {
		for index := 0; index < value.NumField(); index++ {
			field := value.Field(index)
			for _, forbidden := range []string{
				"Path", "File", "DAX", "Writer", "Reader", "Context", "Callback", "Flush", "Durable",
			} {
				if strings.Contains(field.Name, forbidden) {
					t.Fatalf("%s contains forbidden I/O/durability field %s", value.Name(), field.Name)
				}
			}
		}
	}
}

func ownerStateTestGeometry(t *testing.T, ownerSlotBytes uint64) DeviceGeometry {
	t.Helper()
	return ownerStateTestGeometryWithDevice(t, 2<<20, ownerSlotBytes)
}

func ownerStateTestGeometryWithDevice(
	t *testing.T,
	deviceBytes uint64,
	ownerSlotBytes uint64,
) DeviceGeometry {
	t.Helper()
	geometry, err := CalculateDeviceGeometry(deviceBytes, 4096, ownerSlotBytes)
	if err != nil {
		t.Fatalf("CalculateDeviceGeometry(%d,%d): %v", deviceBytes, ownerSlotBytes, err)
	}
	return geometry
}

func ownerStateTestSnapshot(t *testing.T) OwnerStateSnapshot {
	t.Helper()
	snapshot, err := NewOwnerStateSnapshot(ownerStateTestConfig(t))
	if err != nil {
		t.Fatalf("NewOwnerStateSnapshot fixture: %v", err)
	}
	return snapshot
}

func ownerStateTestConfig(t *testing.T) OwnerStateConfig {
	t.Helper()
	devices := []OwnerStateDevice{
		{
			DeviceUUID:          "device-a",
			DeviceOwnerEpoch:    11,
			DataPageCount:       128,
			DeviceBindingSHA256: sha256.Sum256([]byte("binding-a")),
		},
		{
			DeviceUUID:          "device-b",
			DeviceOwnerEpoch:    12,
			DataPageCount:       128,
			DeviceBindingSHA256: sha256.Sum256([]byte("binding-b")),
		},
	}
	membership, err := OwnerGroupMembershipSHA256(devices)
	if err != nil {
		t.Fatalf("membership fixture: %v", err)
	}
	record := OwnerStateAllocationRecord{
		AllocationRecordID:             29,
		ReservationTransactionSequence: 31,
		OwnerTransactionSequence:       31,
		State:                          OwnerAllocationPreparing,
		RequestID:                      "request-29",
		CheckpointID:                   "checkpoint-29",
		ProducerID:                     "producer-a",
		DedupDomainID:                  "dedup-a",
		SharingPolicyID:                "sharing-a",
		RequestSHA256:                  sha256.Sum256([]byte("request-29-canonical")),
		TotalDemandPages:               6,
		MaxExtents:                     3,
		ContentDemands: []OwnerStateContentDemand{
			{
				Kind:             cxlcheckpoint.ContentMemoryPayloadV7,
				ObjectID:         1,
				ByteLength:       3 * uint64(ContentPageBytes),
				CapacityPages:    3,
				LogicalPageStart: 0,
			},
			{
				Kind:             cxlcheckpoint.ContentArtifactPayloadV7,
				ObjectID:         2,
				ByteLength:       5000,
				CapacityPages:    2,
				LogicalPageStart: 3,
			},
			{
				Kind:             cxlcheckpoint.ContentPlacementSlotBV7,
				ObjectID:         3,
				ByteLength:       0,
				CapacityPages:    1,
				LogicalPageStart: 5,
			},
		},
		Fragments: []OwnerStateDeviceFragment{
			{
				DeviceUUID:                      "device-a",
				DeviceOwnerEpoch:                11,
				TargetAllocatorSnapshotSequence: 41,
				Extents: []OwnerStateExtent{
					{StartDataPageIndex: 10, LogicalPageStart: 0, PageCount: 2},
					{StartDataPageIndex: 30, LogicalPageStart: 4, PageCount: 2},
				},
			},
			{
				DeviceUUID:                      "device-b",
				DeviceOwnerEpoch:                12,
				TargetAllocatorSnapshotSequence: 42,
				Extents: []OwnerStateExtent{
					{StartDataPageIndex: 20, LogicalPageStart: 2, PageCount: 2},
				},
			},
		},
		AuthorityEvidence: OwnerStateAuthorityEvidence{
			SchedulerReserveSHA256:     sha256.Sum256([]byte("scheduler-reserve")),
			ProducerCapabilitySHA256:   sha256.Sum256([]byte("producer-capability")),
			PublicationAuthoritySHA256: sha256.Sum256([]byte("publication-authority")),
			ReclaimAuthoritySHA256:     sha256.Sum256([]byte("reclaim-authority")),
		},
	}
	return OwnerStateConfig{
		ClusterID:                    "cluster-a",
		OwnerGroupID:                 "group-a",
		CurrentOwnerID:               "owner-a",
		AnchorDeviceUUID:             "device-a",
		StorageCompatibilityID:       cxlcheckpoint.V7StorageCompatibilityID,
		OwnerEpoch:                   17,
		GroupConfigurationSequence:   3,
		MembershipSHA256:             membership,
		SnapshotSequence:             7,
		NextAllocationRecordID:       30,
		NextOwnerTransactionSequence: 32,
		Devices:                      devices,
		Records:                      []OwnerStateAllocationRecord{record},
	}
}

func ownerStateTestNoSpaceRecord(id uint64) OwnerStateAllocationRecord {
	return OwnerStateAllocationRecord{
		AllocationRecordID:             id,
		ReservationTransactionSequence: 0,
		OwnerTransactionSequence:       id + 1,
		State:                          OwnerAllocationRejectedNoSpace,
		RequestID:                      fmt.Sprintf("request-%08d", id),
		CheckpointID:                   fmt.Sprintf("checkpoint-%08d", id),
		ProducerID:                     "producer-a",
		DedupDomainID:                  "dedup-a",
		SharingPolicyID:                "sharing-a",
		RequestSHA256:                  sha256.Sum256([]byte(fmt.Sprintf("request-%08d", id))),
		TotalDemandPages:               1,
		MaxExtents:                     1,
		ContentDemands: []OwnerStateContentDemand{
			{
				Kind:             cxlcheckpoint.ContentMemoryPayloadV7,
				ObjectID:         1,
				ByteLength:       uint64(ContentPageBytes),
				CapacityPages:    1,
				LogicalPageStart: 0,
			},
		},
	}
}

func ownerStateTestBootstrap(snapshot OwnerStateSnapshot) OwnerStateBootstrap {
	return OwnerStateBootstrap{
		ClusterID:                  snapshot.ClusterID,
		OwnerGroupID:               snapshot.OwnerGroupID,
		CurrentOwnerID:             snapshot.CurrentOwnerID,
		AnchorDeviceUUID:           snapshot.AnchorDeviceUUID,
		StorageCompatibilityID:     snapshot.StorageCompatibilityID,
		OwnerEpoch:                 snapshot.OwnerEpoch,
		GroupConfigurationSequence: snapshot.GroupConfigurationSequence,
		MembershipSHA256:           snapshot.MembershipSHA256,
		Devices:                    snapshot.Devices(),
	}
}

func ownerStateTestEncode(
	t *testing.T,
	snapshot OwnerStateSnapshot,
	geometry DeviceGeometry,
) []byte {
	t.Helper()
	wire, err := CanonicalOwnerStateBytes(snapshot, geometry)
	if err != nil {
		t.Fatalf("CanonicalOwnerStateBytes: %v", err)
	}
	return wire
}

func ownerStateTestRefreshCRCs(wire []byte) {
	payload := wire[OwnerStateEnvelopeHeaderBytes:]
	binary.LittleEndian.PutUint32(wire[ownerStatePayloadCRCOffset:], ownerStateCRC32C(payload))
	binary.LittleEndian.PutUint32(wire[ownerStateHeaderCRCOffset:], 0)
	binary.LittleEndian.PutUint32(
		wire[ownerStateHeaderCRCOffset:], ownerStateHeaderCRC32C(wire[:OwnerStateEnvelopeHeaderBytes]))
}

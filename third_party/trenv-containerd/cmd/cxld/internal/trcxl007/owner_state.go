package trcxl007

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/containerd/containerd/third_party/trenv-containerd/pkg/cxlcheckpoint"
)

const (
	// OwnerStateMagicString, OwnerStateVersion, and OwnerStateDomain identify
	// one clean-slate, group-global TROWN007 full snapshot. The snapshot is
	// checkpoint-level Owner metadata, not a per-page journal and not a
	// PublicationV7 pinned-control object. The v2 domain is a destructive ABI
	// cut: old draft-v1 media must be reformatted, because no dual decoder or
	// live migration is supplied.
	OwnerStateMagicString = "TROWN007"
	OwnerStateVersion     = uint32(7)
	OwnerStateDomain      = "owner-group-full-snapshot-v2"

	OwnerStateEnvelopeHeaderBytes uint64 = 64
	MaxOwnerStateIdentityBytes           = 256
	MaxOwnerStateDevices                 = 256
	MaxOwnerStateContentDemands          = 256
	MaxOwnerStateExtents                 = 256
	MaxOwnerStateRecords                 = 4096

	OwnerStateMembershipDigestDomain = "TROWN007-owner-group-membership-v1"
)

var (
	ErrInvalidOwnerState           = errors.New("invalid TROWN007 Owner state")
	ErrWrongOwnerStateFormat       = errors.New("not a TROWN007 Owner state")
	ErrCorruptOwnerState           = errors.New("corrupt TROWN007 Owner state")
	ErrOwnerStateBootstrapMismatch = errors.New("TROWN007 Owner-state bootstrap mismatch")
	ErrOwnerStateMetadataFull      = errors.New("TROWN007 Owner-state metadata slot is full")
	ErrNoValidOwnerState           = errors.New("no valid TROWN007 Owner-state slot")
	ErrOwnerStateSplitBrain        = errors.New("TROWN007 Owner-state A/B split brain")
)

// OwnerStateSlot is the stable A/B slot identity for group-global Owner state.
// It is intentionally independent of the superblock and allocator slot types.
type OwnerStateSlot uint8

const (
	OwnerStateSlotA OwnerStateSlot = iota + 1
	OwnerStateSlotB
)

func (slot OwnerStateSlot) valid() bool {
	return slot == OwnerStateSlotA || slot == OwnerStateSlotB
}

func (slot OwnerStateSlot) String() string {
	switch slot {
	case OwnerStateSlotA:
		return "A"
	case OwnerStateSlotB:
		return "B"
	default:
		return fmt.Sprintf("OwnerStateSlot(%d)", slot)
	}
}

// OwnerAllocationState is the complete durable checkpoint-allocation state
// machine represented by a TROWN007 full snapshot.
type OwnerAllocationState uint8

const (
	OwnerAllocationPreparing OwnerAllocationState = iota + 1
	OwnerAllocationGranted
	OwnerAllocationCommitting
	OwnerAllocationCommitted
	OwnerAllocationAborting
	OwnerAllocationAborted
	OwnerAllocationReclaiming
	OwnerAllocationReclaimed
	OwnerAllocationQuarantined
	OwnerAllocationRejectedNoSpace
	OwnerAllocationCanceling
	OwnerAllocationCanceled
)

func (state OwnerAllocationState) valid() bool {
	return state >= OwnerAllocationPreparing && state <= OwnerAllocationCanceled
}

// OwnerStateDevice is one canonical member of an Owner group. DeviceUUID is
// the format-lifetime identity, never a host-local path. DeviceBindingSHA256
// binds the complete static TRCXL007 device geometry/compatibility contract.
type OwnerStateDevice struct {
	DeviceUUID          string
	DeviceOwnerEpoch    uint64
	DataPageCount       uint64
	DeviceBindingSHA256 [sha256.Size]byte
}

// OwnerStateContentDemand describes one checkpoint object in allocation order.
// CapacityPages, rather than ByteLength, is the allocator demand. ByteLength
// retains the exact meaningful-length contract for later handback validation.
type OwnerStateContentDemand struct {
	Kind             cxlcheckpoint.ContentKindV7
	ObjectID         uint64
	ByteLength       uint64
	CapacityPages    uint64
	LogicalPageStart uint64
}

// OwnerStateExtent is one device-relative physical run and its checkpoint-
// global logical position.
type OwnerStateExtent struct {
	StartDataPageIndex uint64
	LogicalPageStart   uint64
	PageCount          uint64
}

// OwnerStateDeviceFragment groups all extents placed on one Owner-group device.
// TargetAllocatorSnapshotSequence is the planned local snapshot sequence. It
// is valid in PREPARING before that snapshot is selected; actual application is
// proven later by the selected allocator snapshot's sequence and
// AppliedOwnerTransactionSequence.
type OwnerStateDeviceFragment struct {
	DeviceUUID                      string
	DeviceOwnerEpoch                uint64
	TargetAllocatorSnapshotSequence uint64
	Extents                         []OwnerStateExtent
}

// OwnerStateAuthorityEvidence contains only SHA-256 commitments. Raw
// capabilities, nonces, tokens, private keys, and bearer secrets never enter
// shared Owner state. An all-zero field means the corresponding evidence is
// absent.
type OwnerStateAuthorityEvidence struct {
	SchedulerReserveSHA256     [sha256.Size]byte
	ProducerCapabilitySHA256   [sha256.Size]byte
	PublicationAuthoritySHA256 [sha256.Size]byte
	ReclaimAuthoritySHA256     [sha256.Size]byte
}

// OwnerStateAllocationRecord is the checkpoint-level recovery and idempotency
// unit. AllocationRecordID remains positive even for REJECTED_NO_SPACE, whose
// exact demand is retained without physical fragments. The reservation
// transaction adds eight bytes per checkpoint record, never per page, and is
// immutable for the lifetime of a physical allocation. OwnerTransactionSequence
// instead names the latest transaction that produced the current record state.
type OwnerStateAllocationRecord struct {
	AllocationRecordID             uint64
	ReservationTransactionSequence uint64
	OwnerTransactionSequence       uint64
	State                          OwnerAllocationState

	RequestID       string
	CheckpointID    string
	ProducerID      string
	DedupDomainID   string
	SharingPolicyID string
	RequestSHA256   [sha256.Size]byte

	TotalDemandPages  uint64
	MaxExtents        uint32
	ContentDemands    []OwnerStateContentDemand
	Fragments         []OwnerStateDeviceFragment
	AuthorityEvidence OwnerStateAuthorityEvidence
}

// OwnerStateConfig supplies one complete logical full snapshot. Construction
// deep-copies both nested tables and rebuilds process-local lookup indexes.
type OwnerStateConfig struct {
	ClusterID              string
	OwnerGroupID           string
	CurrentOwnerID         string
	AnchorDeviceUUID       string
	StorageCompatibilityID string

	OwnerEpoch                   uint64
	GroupConfigurationSequence   uint64
	MembershipSHA256             [sha256.Size]byte
	SnapshotSequence             uint64
	NextAllocationRecordID       uint64
	NextOwnerTransactionSequence uint64

	Devices []OwnerStateDevice
	Records []OwnerStateAllocationRecord
}

// OwnerStateBootstrap is the static group contract obtained from validated
// device superblocks and group membership. It deliberately contains no mutable
// snapshot sequence, high-water value, allocation record, or local path.
type OwnerStateBootstrap struct {
	ClusterID                  string
	OwnerGroupID               string
	CurrentOwnerID             string
	AnchorDeviceUUID           string
	StorageCompatibilityID     string
	OwnerEpoch                 uint64
	GroupConfigurationSequence uint64
	MembershipSHA256           [sha256.Size]byte
	Devices                    []OwnerStateDevice
}

// OwnerStateSnapshot is one logical canonical TROWN007 full snapshot. Nested
// slices are private so parsed/constructed state cannot alias caller buffers.
// The request/checkpoint indexes are derived, process-local accelerators: they
// are rebuilt after construction, parsing, and cloning, and never encoded.
type OwnerStateSnapshot struct {
	ClusterID              string
	OwnerGroupID           string
	CurrentOwnerID         string
	AnchorDeviceUUID       string
	StorageCompatibilityID string

	OwnerEpoch                   uint64
	GroupConfigurationSequence   uint64
	MembershipSHA256             [sha256.Size]byte
	SnapshotSequence             uint64
	NextAllocationRecordID       uint64
	NextOwnerTransactionSequence uint64

	devices []OwnerStateDevice
	records []OwnerStateAllocationRecord

	requestIndex    map[string]int
	checkpointIndex map[string]int
}

// OwnerStateStorage owns the exact canonical envelope and its digest. It never
// materializes a zero-padded Owner-state slot and makes no I/O or durability
// claim.
type OwnerStateStorage struct {
	exactBytes []byte
	sha256     [sha256.Size]byte
	slotLength uint64
}

// NewOwnerStateSnapshot validates and deep-copies one complete group snapshot.
func NewOwnerStateSnapshot(config OwnerStateConfig) (OwnerStateSnapshot, error) {
	snapshot := OwnerStateSnapshot{
		ClusterID:                    config.ClusterID,
		OwnerGroupID:                 config.OwnerGroupID,
		CurrentOwnerID:               config.CurrentOwnerID,
		AnchorDeviceUUID:             config.AnchorDeviceUUID,
		StorageCompatibilityID:       config.StorageCompatibilityID,
		OwnerEpoch:                   config.OwnerEpoch,
		GroupConfigurationSequence:   config.GroupConfigurationSequence,
		MembershipSHA256:             config.MembershipSHA256,
		SnapshotSequence:             config.SnapshotSequence,
		NextAllocationRecordID:       config.NextAllocationRecordID,
		NextOwnerTransactionSequence: config.NextOwnerTransactionSequence,
		devices:                      cloneOwnerStateDevices(config.Devices),
		records:                      cloneOwnerStateRecords(config.Records),
	}
	if err := snapshot.Validate(); err != nil {
		return OwnerStateSnapshot{}, err
	}
	snapshot.rebuildIndexes()
	return snapshot, nil
}

// Validate enforces static membership, high-water, canonical ordering,
// checkpoint-demand, physical-fragment, and idempotency invariants without
// relying on one configured slot size.
func (snapshot OwnerStateSnapshot) Validate() error {
	if !ownerStateCompiledContractValid() {
		return ownerStateInvalidf("compiled TROWN007 wire contract differs from the required ABI")
	}
	for _, identity := range []struct {
		name  string
		value string
	}{
		{"cluster ID", snapshot.ClusterID},
		{"Owner-group ID", snapshot.OwnerGroupID},
		{"current Owner ID", snapshot.CurrentOwnerID},
		{"anchor device UUID", snapshot.AnchorDeviceUUID},
	} {
		if err := validateOwnerStateIdentity(identity.name, identity.value); err != nil {
			return err
		}
	}
	if err := validateOwnerStateDeviceUUID("anchor device UUID", snapshot.AnchorDeviceUUID); err != nil {
		return err
	}
	if snapshot.StorageCompatibilityID != cxlcheckpoint.V7StorageCompatibilityID {
		return ownerStateInvalidf("storage compatibility ID does not equal the compiled V7 target")
	}
	for _, field := range []struct {
		name  string
		value uint64
	}{
		{"Owner epoch", snapshot.OwnerEpoch},
		{"group-configuration sequence", snapshot.GroupConfigurationSequence},
		{"snapshot sequence", snapshot.SnapshotSequence},
		{"next allocation-record ID", snapshot.NextAllocationRecordID},
		{"next Owner-transaction sequence", snapshot.NextOwnerTransactionSequence},
	} {
		if err := ownerStatePositiveLong(field.name, field.value); err != nil {
			return err
		}
	}
	if err := validateOwnerStateDevices(snapshot.devices, snapshot.AnchorDeviceUUID); err != nil {
		return err
	}
	membership, err := OwnerGroupMembershipSHA256(snapshot.devices)
	if err != nil {
		return err
	}
	if snapshot.MembershipSHA256 == ([sha256.Size]byte{}) || snapshot.MembershipSHA256 != membership {
		return ownerStateInvalidf("Owner-group membership SHA-256 does not match the canonical device table")
	}
	if len(snapshot.records) > MaxOwnerStateRecords {
		return ownerStateInvalidf(
			"allocation-record count %d exceeds %d", len(snapshot.records), MaxOwnerStateRecords)
	}
	deviceByUUID := make(map[string]OwnerStateDevice, len(snapshot.devices))
	for _, device := range snapshot.devices {
		deviceByUUID[device.DeviceUUID] = device
	}
	requestIndex := make(map[string]uint64, len(snapshot.records))
	checkpointIndex := make(map[string]uint64, len(snapshot.records))
	transactionIndex := make(map[uint64]uint64, len(snapshot.records))
	reservationIndex := make(map[uint64]uint64, len(snapshot.records))
	var previousAllocationID uint64
	var maximumTransactionSequence uint64
	for index := range snapshot.records {
		record := snapshot.records[index]
		if index > 0 && previousAllocationID >= record.AllocationRecordID {
			return ownerStateInvalidf(
				"allocation records are duplicate or not strictly ordered by ID at index %d", index)
		}
		if err := validateOwnerStateRecord(record, deviceByUUID); err != nil {
			return ownerStateFieldInvalid(fmt.Sprintf("allocation record %d", index), err)
		}
		if previous, exists := requestIndex[record.RequestID]; exists {
			return ownerStateInvalidf(
				"request ID %q is shared by allocation records %d and %d",
				record.RequestID, previous, record.AllocationRecordID)
		}
		if previous, exists := checkpointIndex[record.CheckpointID]; exists {
			return ownerStateInvalidf(
				"checkpoint ID %q is shared by allocation records %d and %d",
				record.CheckpointID, previous, record.AllocationRecordID)
		}
		if previous, exists := transactionIndex[record.OwnerTransactionSequence]; exists {
			return ownerStateInvalidf(
				"Owner-transaction sequence %d is shared by allocation records %d and %d",
				record.OwnerTransactionSequence, previous, record.AllocationRecordID)
		}
		if record.ReservationTransactionSequence != 0 {
			if previous, exists := reservationIndex[record.ReservationTransactionSequence]; exists {
				return ownerStateInvalidf(
					"reservation transaction sequence %d is shared by allocation records %d and %d",
					record.ReservationTransactionSequence, previous, record.AllocationRecordID)
			}
			reservationIndex[record.ReservationTransactionSequence] = record.AllocationRecordID
		}
		requestIndex[record.RequestID] = record.AllocationRecordID
		checkpointIndex[record.CheckpointID] = record.AllocationRecordID
		transactionIndex[record.OwnerTransactionSequence] = record.AllocationRecordID
		previousAllocationID = record.AllocationRecordID
		if record.OwnerTransactionSequence > maximumTransactionSequence {
			maximumTransactionSequence = record.OwnerTransactionSequence
		}
		if record.ReservationTransactionSequence > maximumTransactionSequence {
			maximumTransactionSequence = record.ReservationTransactionSequence
		}
	}
	for _, record := range snapshot.records {
		if record.ReservationTransactionSequence == 0 {
			continue
		}
		if retainedBy, exists := transactionIndex[record.ReservationTransactionSequence]; exists && retainedBy != record.AllocationRecordID {
			return ownerStateInvalidf(
				"reservation transaction sequence %d for allocation record %d collides with retained transaction of allocation record %d",
				record.ReservationTransactionSequence,
				record.AllocationRecordID,
				retainedBy)
		}
	}
	if len(snapshot.records) > 0 && snapshot.NextAllocationRecordID <= previousAllocationID {
		return ownerStateInvalidf(
			"next allocation-record ID %d does not exceed record high-water %d",
			snapshot.NextAllocationRecordID, previousAllocationID)
	}
	if snapshot.NextOwnerTransactionSequence <= maximumTransactionSequence {
		return ownerStateInvalidf(
			"next Owner-transaction sequence %d does not exceed record high-water %d",
			snapshot.NextOwnerTransactionSequence, maximumTransactionSequence)
	}
	return nil
}

// Devices returns a detached canonical device table.
func (snapshot OwnerStateSnapshot) Devices() []OwnerStateDevice {
	return cloneOwnerStateDevices(snapshot.devices)
}

// Records returns detached records including detached content/fragment/extent
// slices.
func (snapshot OwnerStateSnapshot) Records() []OwnerStateAllocationRecord {
	return cloneOwnerStateRecords(snapshot.records)
}

// Clone returns a deep copy of one logical snapshot.
func (snapshot OwnerStateSnapshot) Clone() OwnerStateSnapshot {
	snapshot.devices = cloneOwnerStateDevices(snapshot.devices)
	snapshot.records = cloneOwnerStateRecords(snapshot.records)
	snapshot.rebuildIndexes()
	return snapshot
}

// AllocationRecordForRequest rebuilds the non-persisted request index and
// returns one detached exact record.
func (snapshot OwnerStateSnapshot) AllocationRecordForRequest(
	requestID string,
) (OwnerStateAllocationRecord, bool) {
	if index, exists := snapshot.requestIndex[requestID]; exists &&
		index >= 0 && index < len(snapshot.records) &&
		snapshot.records[index].RequestID == requestID {
		return cloneOwnerStateRecord(snapshot.records[index]), true
	}
	return OwnerStateAllocationRecord{}, false
}

// AllocationRecordForCheckpoint rebuilds the non-persisted checkpoint index
// and returns one detached exact record.
func (snapshot OwnerStateSnapshot) AllocationRecordForCheckpoint(
	checkpointID string,
) (OwnerStateAllocationRecord, bool) {
	if index, exists := snapshot.checkpointIndex[checkpointID]; exists &&
		index >= 0 && index < len(snapshot.records) &&
		snapshot.records[index].CheckpointID == checkpointID {
		return cloneOwnerStateRecord(snapshot.records[index]), true
	}
	return OwnerStateAllocationRecord{}, false
}

func (snapshot *OwnerStateSnapshot) rebuildIndexes() {
	snapshot.requestIndex = make(map[string]int, len(snapshot.records))
	snapshot.checkpointIndex = make(map[string]int, len(snapshot.records))
	for index := range snapshot.records {
		snapshot.requestIndex[snapshot.records[index].RequestID] = index
		snapshot.checkpointIndex[snapshot.records[index].CheckpointID] = index
	}
}

// CrossCheckBootstrap binds a decoded mutable snapshot to the static
// Owner-group bootstrap obtained independently from validated superblocks.
func (snapshot OwnerStateSnapshot) CrossCheckBootstrap(expected OwnerStateBootstrap) error {
	if err := snapshot.Validate(); err != nil {
		return err
	}
	if err := validateOwnerStateDevices(expected.Devices, expected.AnchorDeviceUUID); err != nil {
		return ownerStateBootstrapMismatchf("expected device table: %v", err)
	}
	wantMembership, err := OwnerGroupMembershipSHA256(expected.Devices)
	if err != nil {
		return ownerStateBootstrapMismatchf("expected membership digest: %v", err)
	}
	if expected.MembershipSHA256 != wantMembership {
		return ownerStateBootstrapMismatchf("expected membership SHA-256 is not canonical")
	}
	if snapshot.ClusterID != expected.ClusterID ||
		snapshot.OwnerGroupID != expected.OwnerGroupID ||
		snapshot.CurrentOwnerID != expected.CurrentOwnerID ||
		snapshot.AnchorDeviceUUID != expected.AnchorDeviceUUID ||
		snapshot.StorageCompatibilityID != expected.StorageCompatibilityID ||
		snapshot.OwnerEpoch != expected.OwnerEpoch ||
		snapshot.GroupConfigurationSequence != expected.GroupConfigurationSequence ||
		snapshot.MembershipSHA256 != expected.MembershipSHA256 ||
		!equalOwnerStateDevices(snapshot.devices, expected.Devices) {
		return ownerStateBootstrapMismatchf("snapshot static Owner-group fields differ")
	}
	return nil
}

// OwnerGroupMembershipSHA256 computes the stable digest of an already
// canonical device table. It rejects unsorted input rather than silently
// normalizing it, so every language hashes the same byte sequence.
func OwnerGroupMembershipSHA256(devices []OwnerStateDevice) ([sha256.Size]byte, error) {
	if err := validateOwnerStateDevices(devices, ""); err != nil {
		return [sha256.Size]byte{}, err
	}
	digest := sha256.New()
	ownerStateDigestString(digest, OwnerStateMembershipDigestDomain)
	var count [4]byte
	binary.LittleEndian.PutUint32(count[:], uint32(len(devices)))
	_, _ = digest.Write(count[:])
	var scalar [8]byte
	for _, device := range devices {
		ownerStateDigestString(digest, device.DeviceUUID)
		binary.LittleEndian.PutUint64(scalar[:], device.DeviceOwnerEpoch)
		_, _ = digest.Write(scalar[:])
		binary.LittleEndian.PutUint64(scalar[:], device.DataPageCount)
		_, _ = digest.Write(scalar[:])
		_, _ = digest.Write(device.DeviceBindingSHA256[:])
	}
	var result [sha256.Size]byte
	copy(result[:], digest.Sum(nil))
	return result, nil
}

func validateOwnerStateDevices(devices []OwnerStateDevice, requiredAnchor string) error {
	if len(devices) == 0 || len(devices) > MaxOwnerStateDevices {
		return ownerStateInvalidf(
			"device count %d is outside 1..%d", len(devices), MaxOwnerStateDevices)
	}
	previousUUID := ""
	anchorFound := requiredAnchor == ""
	for index, device := range devices {
		if err := validateOwnerStateDeviceUUID("device UUID", device.DeviceUUID); err != nil {
			return ownerStateFieldInvalid(fmt.Sprintf("device %d", index), err)
		}
		if index > 0 && previousUUID >= device.DeviceUUID {
			return ownerStateInvalidf(
				"devices are duplicate or not strictly ordered by UUID at index %d", index)
		}
		if err := ownerStatePositiveLong("device Owner epoch", device.DeviceOwnerEpoch); err != nil {
			return ownerStateFieldInvalid(fmt.Sprintf("device %d", index), err)
		}
		if err := ownerStatePositiveLong("device data-page count", device.DataPageCount); err != nil {
			return ownerStateFieldInvalid(fmt.Sprintf("device %d", index), err)
		}
		if device.DeviceBindingSHA256 == ([sha256.Size]byte{}) {
			return ownerStateInvalidf("device %d has a zero device-binding SHA-256", index)
		}
		if device.DeviceUUID == requiredAnchor {
			anchorFound = true
		}
		previousUUID = device.DeviceUUID
	}
	if !anchorFound {
		return ownerStateInvalidf("anchor device UUID %q is absent from the canonical device table", requiredAnchor)
	}
	return nil
}

func validateOwnerStateRecord(
	record OwnerStateAllocationRecord,
	deviceByUUID map[string]OwnerStateDevice,
) error {
	if err := ownerStatePositiveLong("allocation-record ID", record.AllocationRecordID); err != nil {
		return err
	}
	if err := ownerStatePositiveLong(
		"Owner-transaction sequence", record.OwnerTransactionSequence); err != nil {
		return err
	}
	if !record.State.valid() {
		return ownerStateInvalidf("allocation state %d is outside the TROWN007 v2 state machine", record.State)
	}
	if record.State == OwnerAllocationRejectedNoSpace {
		if record.ReservationTransactionSequence != 0 {
			return ownerStateInvalidf(
				"REJECTED_NO_SPACE reservation transaction sequence is %d, want zero",
				record.ReservationTransactionSequence)
		}
	} else {
		if err := ownerStatePositiveLong(
			"reservation transaction sequence",
			record.ReservationTransactionSequence); err != nil {
			return err
		}
		if record.ReservationTransactionSequence > record.OwnerTransactionSequence {
			return ownerStateInvalidf(
				"reservation transaction sequence %d exceeds current Owner transaction %d",
				record.ReservationTransactionSequence,
				record.OwnerTransactionSequence)
		}
		switch record.State {
		case OwnerAllocationPreparing:
			if record.ReservationTransactionSequence != record.OwnerTransactionSequence {
				return ownerStateInvalidf(
					"PREPARING current transaction %d does not equal reservation transaction %d",
					record.OwnerTransactionSequence,
					record.ReservationTransactionSequence)
			}
		case OwnerAllocationGranted:
			wantCurrent, ok := checkedAdd(record.ReservationTransactionSequence, 1)
			if !ok || wantCurrent > cxlcheckpoint.MaxSignedLong ||
				record.OwnerTransactionSequence != wantCurrent {
				return ownerStateInvalidf(
					"GRANTED current transaction %d does not immediately follow reservation transaction %d",
					record.OwnerTransactionSequence,
					record.ReservationTransactionSequence)
			}
		}
	}
	for _, identity := range []struct {
		name  string
		value string
	}{
		{"request ID", record.RequestID},
		{"checkpoint ID", record.CheckpointID},
		{"Producer ID", record.ProducerID},
		{"deduplication-domain ID", record.DedupDomainID},
		{"sharing-policy ID", record.SharingPolicyID},
	} {
		if err := validateOwnerStateIdentity(identity.name, identity.value); err != nil {
			return err
		}
	}
	if record.RequestSHA256 == ([sha256.Size]byte{}) {
		return ownerStateInvalidf("request SHA-256 is zero")
	}
	if err := ownerStatePositiveLong("total demand pages", record.TotalDemandPages); err != nil {
		return err
	}
	if record.MaxExtents == 0 || record.MaxExtents > MaxOwnerStateExtents {
		return ownerStateInvalidf(
			"maximum extent count %d is outside 1..%d", record.MaxExtents, MaxOwnerStateExtents)
	}
	if err := validateOwnerStateContentDemands(record); err != nil {
		return err
	}
	if record.State == OwnerAllocationRejectedNoSpace {
		if len(record.Fragments) != 0 {
			return ownerStateInvalidf("REJECTED_NO_SPACE must not contain physical fragments")
		}
		return nil
	}
	if len(record.Fragments) == 0 || len(record.Fragments) > MaxOwnerStateDevices {
		return ownerStateInvalidf(
			"physical fragment count %d is outside 1..%d", len(record.Fragments), MaxOwnerStateDevices)
	}
	return validateOwnerStateFragments(record, deviceByUUID)
}

func validateOwnerStateContentDemands(record OwnerStateAllocationRecord) error {
	if len(record.ContentDemands) == 0 || len(record.ContentDemands) > MaxOwnerStateContentDemands {
		return ownerStateInvalidf(
			"content-demand count %d is outside 1..%d",
			len(record.ContentDemands), MaxOwnerStateContentDemands)
	}
	expectedLogical := uint64(0)
	previousObjectID := uint64(0)
	for index, demand := range record.ContentDemands {
		if !validOwnerStateContentKind(demand.Kind) {
			return ownerStateInvalidf("content demand %d has invalid V7 kind %d", index, demand.Kind)
		}
		if err := ownerStatePositiveLong("content object ID", demand.ObjectID); err != nil {
			return ownerStateFieldInvalid(fmt.Sprintf("content demand %d", index), err)
		}
		if index > 0 && previousObjectID >= demand.ObjectID {
			return ownerStateInvalidf(
				"content demands are duplicate or not strictly ordered by object ID at index %d", index)
		}
		if demand.LogicalPageStart != expectedLogical {
			return ownerStateInvalidf(
				"content demands have a logical gap/overlap at page %d", expectedLogical)
		}
		if err := ownerStatePositiveLong("content capacity pages", demand.CapacityPages); err != nil {
			return ownerStateFieldInvalid(fmt.Sprintf("content demand %d", index), err)
		}
		if demand.ByteLength > cxlcheckpoint.MaxSignedLong {
			return ownerStateInvalidf("content demand %d byte length exceeds the signed-Long ABI", index)
		}
		capacityBytes, ok := checkedMul(demand.CapacityPages, uint64(ContentPageBytes))
		if !ok || capacityBytes > cxlcheckpoint.MaxSignedLong || demand.ByteLength > capacityBytes {
			return ownerStateInvalidf(
				"content demand %d byte length %d exceeds capacity %d",
				index, demand.ByteLength, capacityBytes)
		}
		zeroLengthKind := demand.Kind == cxlcheckpoint.ContentPlacementSlotAV7 ||
			demand.Kind == cxlcheckpoint.ContentPlacementSlotBV7 ||
			demand.Kind == cxlcheckpoint.ContentPublicationV7
		if (demand.ByteLength == 0) != zeroLengthKind {
			return ownerStateInvalidf(
				"content demand %d kind %d has invalid byte length %d",
				index, demand.Kind, demand.ByteLength)
		}
		if demand.Kind == cxlcheckpoint.ContentMemoryPayloadV7 && demand.ByteLength != capacityBytes {
			return ownerStateInvalidf("memory content demand %d does not fill every reserved page", index)
		}
		nextLogical, ok := checkedAdd(expectedLogical, demand.CapacityPages)
		if !ok || nextLogical > cxlcheckpoint.MaxSignedLong {
			return ownerStateInvalidf("content-demand logical coverage overflows")
		}
		expectedLogical = nextLogical
		previousObjectID = demand.ObjectID
	}
	if expectedLogical != record.TotalDemandPages {
		return ownerStateInvalidf(
			"content demands cover %d pages, record declares %d",
			expectedLogical, record.TotalDemandPages)
	}
	return nil
}

func validateOwnerStateFragments(
	record OwnerStateAllocationRecord,
	deviceByUUID map[string]OwnerStateDevice,
) error {
	previousUUID := ""
	totalExtents := 0
	allExtents := make([]OwnerStateExtent, 0, record.MaxExtents)
	for fragmentIndex, fragment := range record.Fragments {
		if err := validateOwnerStateDeviceUUID("fragment device UUID", fragment.DeviceUUID); err != nil {
			return ownerStateFieldInvalid(fmt.Sprintf("fragment %d", fragmentIndex), err)
		}
		if fragmentIndex > 0 && previousUUID >= fragment.DeviceUUID {
			return ownerStateInvalidf(
				"fragments are duplicate or not strictly ordered by device UUID at index %d", fragmentIndex)
		}
		device, exists := deviceByUUID[fragment.DeviceUUID]
		if !exists {
			return ownerStateInvalidf("fragment device %q is absent from Owner-group membership", fragment.DeviceUUID)
		}
		if fragment.DeviceOwnerEpoch != device.DeviceOwnerEpoch {
			return ownerStateInvalidf(
				"fragment device %q Owner epoch %d does not equal membership epoch %d",
				fragment.DeviceUUID, fragment.DeviceOwnerEpoch, device.DeviceOwnerEpoch)
		}
		if err := ownerStatePositiveLong(
			"target allocator-snapshot sequence", fragment.TargetAllocatorSnapshotSequence); err != nil {
			return ownerStateFieldInvalid(fmt.Sprintf("fragment %d", fragmentIndex), err)
		}
		if len(fragment.Extents) == 0 {
			return ownerStateInvalidf("fragment %d has no extents", fragmentIndex)
		}
		totalExtents += len(fragment.Extents)
		if totalExtents > MaxOwnerStateExtents || uint32(totalExtents) > record.MaxExtents {
			return ownerStateInvalidf(
				"extent count %d exceeds record/configured bounds %d/%d",
				totalExtents, record.MaxExtents, MaxOwnerStateExtents)
		}
		previousLogicalEnd := uint64(0)
		for extentIndex, extent := range fragment.Extents {
			if extentIndex > 0 && extent.LogicalPageStart <= fragment.Extents[extentIndex-1].LogicalPageStart {
				return ownerStateInvalidf(
					"fragment %d extents are not strictly ordered by logical-page start at index %d",
					fragmentIndex, extentIndex)
			}
			if err := ownerStatePositiveLong("extent page count", extent.PageCount); err != nil {
				return ownerStateFieldInvalid(
					fmt.Sprintf("fragment %d extent %d", fragmentIndex, extentIndex), err)
			}
			physicalEnd, ok := checkedAdd(extent.StartDataPageIndex, extent.PageCount)
			if !ok || physicalEnd > device.DataPageCount {
				return ownerStateInvalidf(
					"fragment %d extent %d exceeds device %q capacity %d",
					fragmentIndex, extentIndex, fragment.DeviceUUID, device.DataPageCount)
			}
			nextLogical, ok := checkedAdd(extent.LogicalPageStart, extent.PageCount)
			if !ok || nextLogical > cxlcheckpoint.MaxSignedLong {
				return ownerStateInvalidf("fragment %d extent logical coverage overflows", fragmentIndex)
			}
			if extentIndex > 0 {
				previous := fragment.Extents[extentIndex-1]
				previousPhysicalEnd, physicalOK := checkedAdd(previous.StartDataPageIndex, previous.PageCount)
				previousLogicalEnd, logicalOK := checkedAdd(previous.LogicalPageStart, previous.PageCount)
				if physicalOK && logicalOK &&
					previousPhysicalEnd == extent.StartDataPageIndex &&
					previousLogicalEnd == extent.LogicalPageStart {
					return ownerStateInvalidf(
						"fragment %d extents %d and %d are logically and physically coalescible",
						fragmentIndex, extentIndex-1, extentIndex)
				}
			}
			if extentIndex > 0 && extent.LogicalPageStart < previousLogicalEnd {
				return ownerStateInvalidf("fragment %d extents overlap logically", fragmentIndex)
			}
			previousLogicalEnd = nextLogical
			allExtents = append(allExtents, extent)
		}
		previousUUID = fragment.DeviceUUID
	}
	logicalOrder := append([]OwnerStateExtent(nil), allExtents...)
	sortOwnerStateExtentsByLogical(logicalOrder)
	expectedLogical := uint64(0)
	for index, extent := range logicalOrder {
		if extent.LogicalPageStart != expectedLogical {
			return ownerStateInvalidf(
				"detached extent union has a logical gap/overlap at page %d (extent %d starts at %d)",
				expectedLogical, index, extent.LogicalPageStart)
		}
		var ok bool
		expectedLogical, ok = checkedAdd(expectedLogical, extent.PageCount)
		if !ok || expectedLogical > cxlcheckpoint.MaxSignedLong {
			return ownerStateInvalidf("detached extent union logical coverage overflows")
		}
	}
	if expectedLogical != record.TotalDemandPages {
		return ownerStateInvalidf(
			"fragments cover %d pages, record declares %d",
			expectedLogical, record.TotalDemandPages)
	}
	for _, fragment := range record.Fragments {
		ordered := append([]OwnerStateExtent(nil), fragment.Extents...)
		sortOwnerStateExtentsByPhysical(ordered)
		for index := 1; index < len(ordered); index++ {
			previousEnd, ok := checkedAdd(ordered[index-1].StartDataPageIndex, ordered[index-1].PageCount)
			if !ok || previousEnd > ordered[index].StartDataPageIndex {
				return ownerStateInvalidf("physical extents overlap on device %q", fragment.DeviceUUID)
			}
		}
	}
	// This check is deliberately record-local. Allocation records retain
	// historical reservation/recovery evidence; deduplication and later reuse
	// can make different records mention the same physical page. Current global
	// exclusivity belongs to the selected allocator/descriptor/placement state.
	return nil
}

func sortOwnerStateExtentsByLogical(extents []OwnerStateExtent) {
	for index := 1; index < len(extents); index++ {
		value := extents[index]
		position := index
		for position > 0 && extents[position-1].LogicalPageStart > value.LogicalPageStart {
			extents[position] = extents[position-1]
			position--
		}
		extents[position] = value
	}
}

func sortOwnerStateExtentsByPhysical(extents []OwnerStateExtent) {
	// The bound is 256, so insertion sort avoids importing a second ordering
	// implementation and remains deterministic under Go 1.17.
	for index := 1; index < len(extents); index++ {
		value := extents[index]
		position := index
		for position > 0 && extents[position-1].StartDataPageIndex > value.StartDataPageIndex {
			extents[position] = extents[position-1]
			position--
		}
		extents[position] = value
	}
}

func validOwnerStateContentKind(kind cxlcheckpoint.ContentKindV7) bool {
	return kind >= cxlcheckpoint.ContentMemoryPayloadV7 &&
		kind <= cxlcheckpoint.ContentPublicationV7
}

func cloneOwnerStateDevices(source []OwnerStateDevice) []OwnerStateDevice {
	return append([]OwnerStateDevice(nil), source...)
}

func cloneOwnerStateRecords(source []OwnerStateAllocationRecord) []OwnerStateAllocationRecord {
	if source == nil {
		return nil
	}
	result := make([]OwnerStateAllocationRecord, len(source))
	for index := range source {
		result[index] = cloneOwnerStateRecord(source[index])
	}
	return result
}

func cloneOwnerStateRecord(source OwnerStateAllocationRecord) OwnerStateAllocationRecord {
	result := source
	result.ContentDemands = append([]OwnerStateContentDemand(nil), source.ContentDemands...)
	if source.Fragments == nil {
		result.Fragments = nil
		return result
	}
	result.Fragments = make([]OwnerStateDeviceFragment, len(source.Fragments))
	for index := range source.Fragments {
		result.Fragments[index] = source.Fragments[index]
		result.Fragments[index].Extents = append(
			[]OwnerStateExtent(nil), source.Fragments[index].Extents...)
	}
	return result
}

func equalOwnerStateDevices(left, right []OwnerStateDevice) bool {
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

func validateOwnerStateIdentity(name, value string) error {
	if value == "" {
		return ownerStateInvalidf("%s is empty", name)
	}
	if !utf8.ValidString(value) {
		return ownerStateInvalidf("%s is not valid UTF-8", name)
	}
	if len(value) > MaxOwnerStateIdentityBytes {
		return ownerStateInvalidf(
			"%s is %d UTF-8 bytes, limit is %d", name, len(value), MaxOwnerStateIdentityBytes)
	}
	if strings.TrimSpace(value) != value {
		return ownerStateInvalidf("%s has surrounding whitespace", name)
	}
	for _, character := range value {
		if unicode.IsControl(character) {
			return ownerStateInvalidf("%s contains a control character", name)
		}
	}
	return nil
}

func validateOwnerStateDeviceUUID(name, value string) error {
	if err := validateOwnerStateIdentity(name, value); err != nil {
		return err
	}
	fileURI := len(value) >= len("file:") && strings.EqualFold(value[:len("file:")], "file:")
	if strings.ContainsAny(value, "/\\") || value == "." || value == ".." || fileURI {
		return ownerStateInvalidf("%s %q looks like a local path", name, value)
	}
	return nil
}

func ownerStatePositiveLong(name string, value uint64) error {
	if value == 0 || value > cxlcheckpoint.MaxSignedLong {
		return ownerStateInvalidf(
			"%s %d is outside 1..%d", name, value, cxlcheckpoint.MaxSignedLong)
	}
	return nil
}

func ownerStateDigestString(writer io.Writer, value string) {
	var length [4]byte
	binary.LittleEndian.PutUint32(length[:], uint32(len(value)))
	_, _ = writer.Write(length[:])
	_, _ = io.WriteString(writer, value)
}

func ownerStateCompiledContractValid() bool {
	return OwnerStateMagicString == "TROWN007" &&
		OwnerStateVersion == 7 &&
		OwnerStateDomain == "owner-group-full-snapshot-v2" &&
		len(OwnerStateDomain) <= ownerStateDomainFieldBytes &&
		len(cxlcheckpoint.V7StorageCompatibilityID) <= MaxOwnerStateIdentityBytes &&
		OwnerStateEnvelopeHeaderBytes == 64 &&
		MaxOwnerStateDevices == 256 &&
		MaxOwnerStateContentDemands == 256 &&
		MaxOwnerStateExtents == 256 &&
		MaxOwnerStateRecords == 4096 &&
		bytes.Equal(ownerStateMagic[:], []byte(OwnerStateMagicString))
}

func ownerStateInvalidf(format string, arguments ...interface{}) error {
	return fmt.Errorf("%w: %s", ErrInvalidOwnerState, fmt.Sprintf(format, arguments...))
}

func ownerStateFieldInvalid(name string, err error) error {
	return ownerStateInvalidf("%s: %v", name, err)
}

func ownerStateWrongFormatf(format string, arguments ...interface{}) error {
	return fmt.Errorf("%w: %s", ErrWrongOwnerStateFormat, fmt.Sprintf(format, arguments...))
}

func ownerStateCorruptf(format string, arguments ...interface{}) error {
	return fmt.Errorf("%w: %s", ErrCorruptOwnerState, fmt.Sprintf(format, arguments...))
}

func ownerStateBootstrapMismatchf(format string, arguments ...interface{}) error {
	return fmt.Errorf("%w: %s", ErrOwnerStateBootstrapMismatch, fmt.Sprintf(format, arguments...))
}

func ownerStateMetadataFullf(format string, arguments ...interface{}) error {
	return fmt.Errorf("%w: %s", ErrOwnerStateMetadataFull, fmt.Sprintf(format, arguments...))
}

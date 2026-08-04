package trcxl007

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"reflect"
	"sort"
)

var (
	ErrOwnerDeviceGroupInput    = errors.New("invalid TRCXL007 Owner device-group input")
	ErrOwnerDeviceGroupMismatch = errors.New(
		"TRCXL007 Owner device group does not match canonical membership")
	ErrOwnerDeviceGroupFormatIncomplete = errors.New(
		"TRCXL007 offline Owner device-group format is incomplete")
)

// OwnerDeviceGroupDeviceInput identifies exactly one caller-owned storage
// object. ExpectedDeviceUUID is the persistent format-lifetime identity, never
// a path or host-local device name. This package neither opens nor closes the
// supplied storage and does not take ownership of it on success or failure.
type OwnerDeviceGroupDeviceInput struct {
	ExpectedDeviceUUID       string
	Storage                  DeviceMetadataStorage
	Geometry                 DeviceGeometry
	OwnerStateReadLimitBytes uint64
}

// OwnerDeviceGroupInput is one exact Owner-group membership view. Devices may
// arrive in any order, but must be a one-to-one match for the already-canonical
// OwnerStateBootstrap device table. No missing, extra, duplicate, or inferred
// device is accepted. Pointer-identical storage objects are rejected; because
// DeviceMetadataStorage is a generic interface, callers must also ensure that
// distinct wrapper objects do not alias the same physical storage authority.
type OwnerDeviceGroupInput struct {
	Devices             []OwnerDeviceGroupDeviceInput
	OwnerStateBootstrap OwnerStateBootstrap
}

// OwnerDeviceGroup is a validated read-only group foundation. It retains the
// caller-owned storage views through DeviceMetadata but never closes them.
// Raw persistence commits remain package-private until the Owner executor
// supplies legal transition and authority checks.
type OwnerDeviceGroup struct {
	bootstrap OwnerStateBootstrap
	devices   []ownerDeviceGroupOpenedDevice
	anchor    *DeviceMetadata
}

type ownerDeviceGroupOpenedDevice struct {
	deviceUUID string
	geometry   DeviceGeometry
	metadata   *DeviceMetadata
}

type preparedOwnerDeviceGroup struct {
	bootstrap   OwnerStateBootstrap
	genesis     OwnerStateSnapshot
	devices     []preparedOwnerDeviceGroupDevice
	anchorIndex int
}

type preparedOwnerDeviceGroupDevice struct {
	input  OwnerDeviceGroupDeviceInput
	member OwnerStateDevice
}

type ownerDeviceGroupStorageKey struct {
	typeOf  reflect.Type
	pointer uintptr
}

type ownerDeviceGroupFormatError struct {
	deviceUUID string
	cause      error
}

func (formatError *ownerDeviceGroupFormatError) Error() string {
	return fmt.Sprintf(
		"%v: device %q: %v; formatting is sequential and not group-atomic",
		ErrOwnerDeviceGroupFormatIncomplete,
		formatError.deviceUUID,
		formatError.cause)
}

func (formatError *ownerDeviceGroupFormatError) Unwrap() error {
	return formatError.cause
}

func (formatError *ownerDeviceGroupFormatError) Is(target error) bool {
	return target == ErrOwnerDeviceGroupFormatIncomplete
}

// FormatOwnerDeviceGroupOffline destructively creates one genesis format per
// supplied device. Every entry and every exact per-device genesis is validated
// before the first write. MEMBER devices are then formatted in ascending
// persistent DeviceUUID order and the ANCHOR is formatted last.
//
// The ordering keeps a fresh ANCHOR unpublished until every MEMBER format has
// completed, but it is not a cross-device transaction. A failure may leave a
// subset formatted; the caller must keep the group offline and explicitly
// restart a destructive format. Existing content-region payload bytes retain
// FormatDeviceMetadata's preservation semantics.
func FormatOwnerDeviceGroupOffline(input OwnerDeviceGroupInput) error {
	prepared, err := prepareOwnerDeviceGroup(input)
	if err != nil {
		return err
	}
	formatInputs := make([]DeviceFormatInput, len(prepared.devices))
	for index := range prepared.devices {
		device := prepared.devices[index]
		formatInput, err := buildOwnerDeviceGroupGenesis(prepared, index)
		if err != nil {
			return err
		}
		if device.input.ExpectedDeviceUUID == prepared.bootstrap.AnchorDeviceUUID {
			ownerStorage, err := EncodeOwnerStateForStorage(
				prepared.genesis,
				device.input.Geometry)
			if err != nil {
				return ownerDeviceGroupInputMismatchf(
					"ANCHOR %q genesis Owner state: %v",
					device.input.ExpectedDeviceUUID,
					err)
			}
			if ownerStorage.ExactLength() > device.input.OwnerStateReadLimitBytes {
				return fmt.Errorf(
					"%w: ANCHOR %q genesis envelope %d exceeds read policy %d",
					ErrDeviceMetadataOwnerStateReadLimit,
					device.input.ExpectedDeviceUUID,
					ownerStorage.ExactLength(),
					device.input.OwnerStateReadLimitBytes)
			}
		}
		if _, err := validateDeviceFormatInput(device.input.Storage, formatInput); err != nil {
			return ownerDeviceGroupInputMismatchf(
				"device %q genesis: %v",
				device.input.ExpectedDeviceUUID,
				err)
		}
		formatInputs[index] = formatInput
	}

	writeOne := func(index int) error {
		device := prepared.devices[index]
		if err := FormatDeviceMetadata(device.input.Storage, formatInputs[index]); err != nil {
			return &ownerDeviceGroupFormatError{
				deviceUUID: device.input.ExpectedDeviceUUID,
				cause:      err,
			}
		}
		return nil
	}
	for index := range prepared.devices {
		if index == prepared.anchorIndex {
			continue
		}
		if err := writeOne(index); err != nil {
			return err
		}
	}
	return writeOne(prepared.anchorIndex)
}

// OpenOwnerDeviceGroup opens every expected device read-only through
// OpenDeviceMetadata. It never repairs or formats media. The selected
// persistent DeviceUUID and role must match the expected entry, exactly one
// ANCHOR must exist, and every selected allocator transaction must be below
// the ANCHOR Owner-state next-transaction high-water value.
//
// This is not a cross-device atomic snapshot operation. The caller must fence
// Owner writers while opening the group if it needs one stable multi-device
// observation.
func OpenOwnerDeviceGroup(input OwnerDeviceGroupInput) (*OwnerDeviceGroup, error) {
	prepared, err := prepareOwnerDeviceGroup(input)
	if err != nil {
		return nil, err
	}
	opened := make([]ownerDeviceGroupOpenedDevice, len(prepared.devices))
	var anchor *DeviceMetadata
	anchorCount := 0
	for index := range prepared.devices {
		device := prepared.devices[index]
		metadata, err := OpenDeviceMetadata(device.input.Storage, DeviceOpenInput{
			Geometry:                 device.input.Geometry,
			OwnerStateBootstrap:      prepared.bootstrap,
			OwnerStateReadLimitBytes: device.input.OwnerStateReadLimitBytes,
		})
		if err != nil {
			return nil, fmt.Errorf(
				"open Owner-group device %q: %w",
				device.input.ExpectedDeviceUUID,
				err)
		}
		_, superblock := metadata.ActiveSuperblock()
		if superblock.DeviceUUID != device.input.ExpectedDeviceUUID {
			return nil, ownerDeviceGroupMismatchf(
				"storage expected as %q contains persistent device %q",
				device.input.ExpectedDeviceUUID,
				superblock.DeviceUUID)
		}
		expectedRole := OwnerGroupRoleMember
		if device.input.ExpectedDeviceUUID == prepared.bootstrap.AnchorDeviceUUID {
			expectedRole = OwnerGroupRoleAnchor
		}
		if superblock.OwnerGroupRole != expectedRole {
			return nil, ownerDeviceGroupMismatchf(
				"device %q role %s does not equal expected %s",
				device.input.ExpectedDeviceUUID,
				superblock.OwnerGroupRole,
				expectedRole)
		}
		if superblock.Geometry != device.input.Geometry ||
			superblock.DeviceBindingSHA256() != device.member.DeviceBindingSHA256 {
			return nil, ownerDeviceGroupMismatchf(
				"device %q geometry or static binding differs from membership",
				device.input.ExpectedDeviceUUID)
		}
		if superblock.OwnerGroupRole == OwnerGroupRoleAnchor {
			anchorCount++
			anchor = metadata
		}
		opened[index] = ownerDeviceGroupOpenedDevice{
			deviceUUID: device.input.ExpectedDeviceUUID,
			geometry:   device.input.Geometry,
			metadata:   metadata,
		}
	}
	if anchorCount != 1 || anchor == nil {
		return nil, ownerDeviceGroupMismatchf(
			"opened group has %d ANCHOR devices, expected exactly one",
			anchorCount)
	}
	_, ownerState, present := anchor.ActiveOwnerState()
	if !present {
		return nil, ownerDeviceGroupMismatchf("ANCHOR has no selected Owner state")
	}
	if err := ownerState.CrossCheckBootstrap(prepared.bootstrap); err != nil {
		return nil, ownerDeviceGroupMismatchf("ANCHOR Owner state: %v", err)
	}
	for index := range opened {
		_, allocator := opened[index].metadata.ActiveAllocatorSnapshot()
		if allocator.AppliedOwnerTransactionSequence >=
			ownerState.NextOwnerTransactionSequence {
			return nil, ownerDeviceGroupMismatchf(
				"device %q applied transaction %d is not below ANCHOR next transaction %d",
				opened[index].deviceUUID,
				allocator.AppliedOwnerTransactionSequence,
				ownerState.NextOwnerTransactionSequence)
		}
	}
	return &OwnerDeviceGroup{
		bootstrap: cloneOwnerStateBootstrap(prepared.bootstrap),
		devices:   opened,
		anchor:    anchor,
	}, nil
}

// PlannerInputs returns detached values in canonical persistent DeviceUUID
// order, ready for PlanOwnerCheckpointReserve. Repeated calls perform no
// storage I/O and cannot mutate the group's cached snapshots through aliases.
func (group *OwnerDeviceGroup) PlannerInputs() (
	OwnerStateSnapshot,
	[]OwnerAllocatorDeviceSnapshot,
) {
	if group == nil || group.anchor == nil {
		return OwnerStateSnapshot{}, nil
	}
	_, ownerState, present := group.anchor.ActiveOwnerState()
	if !present {
		return OwnerStateSnapshot{}, nil
	}
	inputs := make([]OwnerAllocatorDeviceSnapshot, len(group.devices))
	for index := range group.devices {
		device := group.devices[index]
		_, allocator := device.metadata.ActiveAllocatorSnapshot()
		inputs[index] = OwnerAllocatorDeviceSnapshot{
			DeviceUUID: device.deviceUUID,
			Geometry:   device.geometry,
			Snapshot:   allocator,
		}
	}
	return ownerState, inputs
}

// Bootstrap returns a detached copy of the validated static group contract.
func (group *OwnerDeviceGroup) Bootstrap() OwnerStateBootstrap {
	if group == nil {
		return OwnerStateBootstrap{}
	}
	return cloneOwnerStateBootstrap(group.bootstrap)
}

func prepareOwnerDeviceGroup(input OwnerDeviceGroupInput) (preparedOwnerDeviceGroup, error) {
	bootstrap := cloneOwnerStateBootstrap(input.OwnerStateBootstrap)
	genesis, err := NewOwnerStateSnapshot(OwnerStateConfig{
		ClusterID:                    bootstrap.ClusterID,
		OwnerGroupID:                 bootstrap.OwnerGroupID,
		CurrentOwnerID:               bootstrap.CurrentOwnerID,
		AnchorDeviceUUID:             bootstrap.AnchorDeviceUUID,
		StorageCompatibilityID:       bootstrap.StorageCompatibilityID,
		OwnerEpoch:                   bootstrap.OwnerEpoch,
		GroupConfigurationSequence:   bootstrap.GroupConfigurationSequence,
		MembershipSHA256:             bootstrap.MembershipSHA256,
		SnapshotSequence:             1,
		NextAllocationRecordID:       1,
		NextOwnerTransactionSequence: 1,
		Devices:                      bootstrap.Devices,
	})
	if err != nil {
		return preparedOwnerDeviceGroup{}, ownerDeviceGroupInputMismatchf(
			"OwnerStateBootstrap is not canonical: %v",
			err)
	}
	if len(input.Devices) != len(bootstrap.Devices) {
		return preparedOwnerDeviceGroup{}, ownerDeviceGroupInputMismatchf(
			"input device count %d does not equal membership count %d",
			len(input.Devices),
			len(bootstrap.Devices))
	}

	orderedInputs := append([]OwnerDeviceGroupDeviceInput(nil), input.Devices...)
	sort.Slice(orderedInputs, func(left, right int) bool {
		return orderedInputs[left].ExpectedDeviceUUID < orderedInputs[right].ExpectedDeviceUUID
	})
	prepared := preparedOwnerDeviceGroup{
		bootstrap:   bootstrap,
		genesis:     genesis,
		devices:     make([]preparedOwnerDeviceGroupDevice, len(orderedInputs)),
		anchorIndex: -1,
	}
	seenStorage := make(map[ownerDeviceGroupStorageKey]string, len(orderedInputs))
	for index := range orderedInputs {
		entry := orderedInputs[index]
		if index > 0 && orderedInputs[index-1].ExpectedDeviceUUID == entry.ExpectedDeviceUUID {
			return preparedOwnerDeviceGroup{}, ownerDeviceGroupInputMismatchf(
				"expected persistent DeviceUUID %q is duplicated",
				entry.ExpectedDeviceUUID)
		}
		member := bootstrap.Devices[index]
		if entry.ExpectedDeviceUUID != member.DeviceUUID {
			return preparedOwnerDeviceGroup{}, ownerDeviceGroupInputMismatchf(
				"expected device %q does not equal membership device %q at index %d",
				entry.ExpectedDeviceUUID,
				member.DeviceUUID,
				index)
		}
		if member.DeviceOwnerEpoch != bootstrap.OwnerEpoch {
			return preparedOwnerDeviceGroup{}, ownerDeviceGroupInputMismatchf(
				"device %q Owner epoch %d does not equal group epoch %d",
				member.DeviceUUID,
				member.DeviceOwnerEpoch,
				bootstrap.OwnerEpoch)
		}
		if err := entry.Geometry.Validate(); err != nil {
			return preparedOwnerDeviceGroup{}, ownerDeviceGroupInputMismatchf(
				"device %q geometry: %v",
				entry.ExpectedDeviceUUID,
				err)
		}
		if entry.Geometry.DataPageCount != member.DataPageCount {
			return preparedOwnerDeviceGroup{}, ownerDeviceGroupInputMismatchf(
				"device %q geometry page count %d does not equal membership count %d",
				entry.ExpectedDeviceUUID,
				entry.Geometry.DataPageCount,
				member.DataPageCount)
		}
		if entry.OwnerStateReadLimitBytes < OwnerStateEnvelopeHeaderBytes ||
			entry.OwnerStateReadLimitBytes > entry.Geometry.OwnerStateSnapshotSlotBytes {
			return preparedOwnerDeviceGroup{}, fmt.Errorf(
				"%w: device %q limit %d is outside %d..%d",
				ErrDeviceMetadataOwnerStateReadLimit,
				entry.ExpectedDeviceUUID,
				entry.OwnerStateReadLimitBytes,
				OwnerStateEnvelopeHeaderBytes,
				entry.Geometry.OwnerStateSnapshotSlotBytes)
		}
		storageKey, hasKey, err := ownerDeviceGroupStorageIdentity(entry.Storage)
		if err != nil {
			return preparedOwnerDeviceGroup{}, ownerDeviceGroupInputMismatchf(
				"device %q storage: %v",
				entry.ExpectedDeviceUUID,
				err)
		}
		if hasKey {
			if previous, exists := seenStorage[storageKey]; exists {
				return preparedOwnerDeviceGroup{}, ownerDeviceGroupInputMismatchf(
					"devices %q and %q alias the same storage object",
					previous,
					entry.ExpectedDeviceUUID)
			}
			seenStorage[storageKey] = entry.ExpectedDeviceUUID
		}
		if err := validateMetadataStorageSize(entry.Storage, entry.Geometry); err != nil {
			return preparedOwnerDeviceGroup{}, ownerDeviceGroupInputMismatchf(
				"device %q storage size: %v",
				entry.ExpectedDeviceUUID,
				err)
		}
		bindingSource := DeviceSuperblock{
			ClusterID:              bootstrap.ClusterID,
			DeviceUUID:             entry.ExpectedDeviceUUID,
			StorageCompatibilityID: bootstrap.StorageCompatibilityID,
			Geometry:               entry.Geometry,
		}
		if bindingSource.DeviceBindingSHA256() != member.DeviceBindingSHA256 {
			return preparedOwnerDeviceGroup{}, ownerDeviceGroupInputMismatchf(
				"device %q geometry/static binding differs from membership",
				entry.ExpectedDeviceUUID)
		}
		if entry.ExpectedDeviceUUID == bootstrap.AnchorDeviceUUID {
			if prepared.anchorIndex != -1 {
				return preparedOwnerDeviceGroup{}, ownerDeviceGroupInputMismatchf(
					"more than one input claims ANCHOR DeviceUUID %q",
					bootstrap.AnchorDeviceUUID)
			}
			prepared.anchorIndex = index
		}
		prepared.devices[index] = preparedOwnerDeviceGroupDevice{
			input:  entry,
			member: member,
		}
	}
	if prepared.anchorIndex < 0 {
		return preparedOwnerDeviceGroup{}, ownerDeviceGroupInputMismatchf(
			"ANCHOR device %q is missing",
			bootstrap.AnchorDeviceUUID)
	}
	return prepared, nil
}

func buildOwnerDeviceGroupGenesis(
	prepared preparedOwnerDeviceGroup,
	index int,
) (DeviceFormatInput, error) {
	if index < 0 || index >= len(prepared.devices) {
		return DeviceFormatInput{}, ownerDeviceGroupInputMismatchf(
			"genesis device index %d is outside group",
			index)
	}
	device := prepared.devices[index]
	role := OwnerGroupRoleMember
	if index == prepared.anchorIndex {
		role = OwnerGroupRoleAnchor
	}
	superblock := DeviceSuperblock{
		ClusterID:                       prepared.bootstrap.ClusterID,
		DeviceUUID:                      device.input.ExpectedDeviceUUID,
		OwnerGroupID:                    prepared.bootstrap.OwnerGroupID,
		CurrentOwnerID:                  prepared.bootstrap.CurrentOwnerID,
		OwnerGroupAnchorDeviceUUID:      prepared.bootstrap.AnchorDeviceUUID,
		StorageCompatibilityID:          prepared.bootstrap.StorageCompatibilityID,
		OwnerEpoch:                      prepared.bootstrap.OwnerEpoch,
		SuperblockSequence:              1,
		OwnerGroupRole:                  role,
		OwnerGroupConfigurationSequence: prepared.bootstrap.GroupConfigurationSequence,
		OwnerGroupMembershipSHA256:      prepared.bootstrap.MembershipSHA256,
		Geometry:                        device.input.Geometry,
		ActiveAllocatorSnapshotSlot:     SuperblockSlotA,
		ActiveAllocatorSnapshotSequence: 1,
	}
	bitmapBytes, err := device.input.Geometry.AllocationBitmapBytes()
	if err != nil {
		return DeviceFormatInput{}, ownerDeviceGroupInputMismatchf(
			"device %q genesis allocation bitmap size: %v",
			device.input.ExpectedDeviceUUID,
			err)
	}
	bitmap, err := allocateOwnerDeviceGroupZeroBitmap(bitmapBytes)
	if err != nil {
		return DeviceFormatInput{}, ownerDeviceGroupInputMismatchf(
			"device %q genesis allocation bitmap: %v",
			device.input.ExpectedDeviceUUID,
			err)
	}
	allocator, err := NewAllocatorSnapshot(AllocatorSnapshotConfig{
		DeviceBindingSHA256:             superblock.DeviceBindingSHA256(),
		OwnerGroupIdentitySHA256:        superblock.OwnerGroupIdentitySHA256(),
		OwnerEpoch:                      prepared.bootstrap.OwnerEpoch,
		SnapshotSequence:                1,
		AppliedOwnerTransactionSequence: 0,
		DataPageCount:                   device.input.Geometry.DataPageCount,
	}, bitmap)
	if err != nil {
		return DeviceFormatInput{}, ownerDeviceGroupInputMismatchf(
			"device %q genesis allocator: %v",
			device.input.ExpectedDeviceUUID,
			err)
	}
	allocatorExact, err := CanonicalAllocatorSnapshotBytes(allocator, device.input.Geometry)
	if err != nil {
		return DeviceFormatInput{}, ownerDeviceGroupInputMismatchf(
			"device %q genesis allocator encoding: %v",
			device.input.ExpectedDeviceUUID,
			err)
	}
	superblock.ActiveAllocatorSnapshotLength = uint64(len(allocatorExact))
	superblock.ActiveAllocatorSnapshotSHA256 = sha256.Sum256(allocatorExact)
	var ownerState *OwnerStateSnapshot
	if role == OwnerGroupRoleAnchor {
		value := prepared.genesis.Clone()
		ownerState = &value
	}
	return DeviceFormatInput{
		Superblock:          superblock,
		AllocatorSnapshot:   allocator,
		OwnerStateBootstrap: cloneOwnerStateBootstrap(prepared.bootstrap),
		OwnerState:          ownerState,
	}, nil
}

func allocateOwnerDeviceGroupZeroBitmap(bitmapBytes uint64) (
	[]byte,
	error,
) {
	if bitmapBytes > uint64(maxIntValue()) {
		return nil, fmt.Errorf(
			"%d bytes cannot be represented by the host int type",
			bitmapBytes)
	}
	// Valid geometry bounds this below MaxAllocatorSnapshotSlotBytes.
	return make([]byte, int(bitmapBytes)), nil
}

func ownerDeviceGroupStorageIdentity(
	storage DeviceMetadataStorage,
) (ownerDeviceGroupStorageKey, bool, error) {
	if storage == nil {
		return ownerDeviceGroupStorageKey{}, false, fmt.Errorf("storage is nil")
	}
	value := reflect.ValueOf(storage)
	switch value.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map,
		reflect.Ptr, reflect.Slice:
		if value.IsNil() {
			return ownerDeviceGroupStorageKey{}, false, fmt.Errorf("storage is typed nil")
		}
	}
	if value.Kind() != reflect.Ptr {
		return ownerDeviceGroupStorageKey{}, false, nil
	}
	return ownerDeviceGroupStorageKey{
		typeOf:  value.Type(),
		pointer: value.Pointer(),
	}, true, nil
}

func ownerDeviceGroupInputMismatchf(format string, arguments ...interface{}) error {
	return fmt.Errorf(
		"%w: %s",
		ErrOwnerDeviceGroupInput,
		fmt.Sprintf(format, arguments...))
}

func ownerDeviceGroupMismatchf(format string, arguments ...interface{}) error {
	return fmt.Errorf(
		"%w: %s",
		ErrOwnerDeviceGroupMismatch,
		fmt.Sprintf(format, arguments...))
}

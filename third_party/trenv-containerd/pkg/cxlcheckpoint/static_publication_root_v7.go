package cxlcheckpoint

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"
)

const (
	StaticPublicationRootV7Version uint32 = 7

	StaticPublicationRootV7MagicString = "TRPSR007"
	StaticPublicationRootV7Domain      = "publication-bootstrap-v1"

	StaticPublicationRootV7EnvelopeHeaderBytes uint64 = 64
	MaxStaticPublicationRootV7Bytes            uint64 = 128 << 10
	MaxStaticPublicationRootV7IdentityBytes           = 256
	MaxStaticPublicationRootV7Devices                 = 256
	MaxStaticPublicationRootV7Runs                    = 256

	// Every variable-sized collection is bounded before allocation. Even the
	// impossible all-maximum identity case remains below the chosen 128 KiB
	// complete-envelope ceiling.
	maxStaticPublicationRootV7WorstCaseBytes = StaticPublicationRootV7EnvelopeHeaderBytes +
		1 + // state
		3*(4+MaxStaticPublicationRootV7IdentityBytes) + // checkpoint, contract, Owner
		4*8 + // object, epoch, allocation record, exact length
		sha256.Size + 2*4 + // digest and collection counts
		MaxStaticPublicationRootV7Devices*(4+MaxStaticPublicationRootV7IdentityBytes+8) +
		MaxStaticPublicationRootV7Runs*(8+4+8+8)
)

var (
	_ [MaxStaticPublicationRootV7Bytes - maxStaticPublicationRootV7WorstCaseBytes]byte

	ErrWrongStaticPublicationRootV7Format = errors.New("not a TRPSR007 static publication root")
	ErrCorruptStaticPublicationRootV7     = errors.New("corrupt TRPSR007 static publication root")
	ErrInvalidStaticPublicationRootV7     = errors.New("invalid TRPSR007 static publication root")
)

type StaticPublicationRootV7State uint8

const (
	StaticPublicationRootV7Committed StaticPublicationRootV7State = 1
)

// StaticPublicationRootV7Device is the compact subset of allocation devices
// used by the immutable publication object's exact bytes. Host-local paths,
// routes, and mounts are deliberately absent. The table is ordered by
// unsigned lexicographic UTF-8 bytes, not a language's native UTF-16 order.
type StaticPublicationRootV7Device struct {
	DeviceUUID    string
	DataPageCount uint64
}

// StaticPublicationRootV7Run maps one gap-free publication-object page range
// into the compact device table. Owner and allocation identity appear once in
// StaticPublicationRootV7 rather than once per run.
type StaticPublicationRootV7Run struct {
	ObjectPageStart uint64
	DeviceIndex     uint32
	DataPageIndex   uint64
	PageCount       uint64
}

// StaticPublicationRootV7 is the immutable bootstrap needed to find and
// authenticate one canonical TRPUB007 envelope. It binds a target TRCXL007
// compatibility contract, but does not claim that a live TRCXL007 formatter,
// descriptor I/O path, DAX writer, or restore runtime exists.
type StaticPublicationRootV7 struct {
	State                  StaticPublicationRootV7State
	CheckpointID           string
	StorageCompatibilityID string
	PublicationObjectID    uint64
	OwnerID                string
	OwnerEpoch             uint64
	AllocationRecordID     uint64
	PublicationLength      uint64
	PublicationSHA256      [sha256.Size]byte
	Devices                []StaticPublicationRootV7Device
	Runs                   []StaticPublicationRootV7Run
}

// staticPublicationRootV7ExactSource is deliberately smaller than
// PublicationStorageV7. Restore-side cross-checking needs the exact envelope
// locator and digest, but must not allocate or zero the publication slot's
// potentially 8 MiB PaddedBytes buffer.
type staticPublicationRootV7ExactSource struct {
	contentObjectID uint64
	exactLength     uint64
	sha256          [sha256.Size]byte
	pageRuns        []AllocationPageRunV7
}

// Validate proves the compact root is canonical, bounded, gap-free, and
// physically safe within its target device capacities.
func (root StaticPublicationRootV7) Validate() error {
	if root.State != StaticPublicationRootV7Committed {
		return staticPublicationRootV7Invalidf("root state %d is not COMMITTED", root.State)
	}
	if err := validateStaticPublicationRootV7Identity("checkpoint ID", root.CheckpointID); err != nil {
		return err
	}
	if err := validateStaticPublicationRootV7Identity(
		"storage compatibility ID", root.StorageCompatibilityID); err != nil {
		return err
	}
	if root.StorageCompatibilityID != V7StorageCompatibilityID {
		return staticPublicationRootV7Invalidf(
			"storage compatibility ID %q is not the exact V7 target", root.StorageCompatibilityID)
	}
	if err := staticPublicationRootV7PositiveLong(
		"publication object ID", root.PublicationObjectID); err != nil {
		return err
	}
	if err := validateStaticPublicationRootV7Identity("Owner ID", root.OwnerID); err != nil {
		return err
	}
	if err := staticPublicationRootV7PositiveLong("Owner epoch", root.OwnerEpoch); err != nil {
		return err
	}
	if err := staticPublicationRootV7PositiveLong(
		"allocation record ID", root.AllocationRecordID); err != nil {
		return err
	}
	if root.PublicationLength <= PublicationV7EnvelopeHeaderBytes ||
		root.PublicationLength > MaxPublicationV7Bytes ||
		root.PublicationLength > MaxSignedLong {
		return staticPublicationRootV7Invalidf(
			"publication length %d is outside (%d,%d]",
			root.PublicationLength, PublicationV7EnvelopeHeaderBytes, MaxPublicationV7Bytes)
	}
	if root.PublicationSHA256 == [sha256.Size]byte{} {
		return staticPublicationRootV7Invalidf("publication SHA-256 is zero")
	}
	if V7StoragePageSize != PublicationV7PageSize {
		return staticPublicationRootV7Invalidf("compiled V7 target storage ABI is inconsistent")
	}
	if V7StoragePageSize != PageSize {
		return staticPublicationRootV7Invalidf("compiled V7 target storage ABI is inconsistent")
	}
	if V7StoragePageDescriptorBytes != 64 ||
		V7StorageDeviceFormatMagicString != "TRCXL007" {
		return staticPublicationRootV7Invalidf("compiled V7 target storage ABI is inconsistent")
	}

	if len(root.Devices) == 0 || len(root.Devices) > MaxStaticPublicationRootV7Devices {
		return staticPublicationRootV7Invalidf(
			"device count %d is outside 1..%d",
			len(root.Devices), MaxStaticPublicationRootV7Devices)
	}
	previousUUID := ""
	for index, device := range root.Devices {
		if err := validateStaticPublicationRootV7Identity("device UUID", device.DeviceUUID); err != nil {
			return staticPublicationRootV7FieldInvalid(fmt.Sprintf("device %d", index), err)
		}
		if err := validatePublicationV7DeviceUUID(device.DeviceUUID); err != nil {
			return staticPublicationRootV7FieldInvalid(fmt.Sprintf("device %d", index), err)
		}
		if index > 0 && !staticPublicationRootV7DeviceUUIDLess(
			previousUUID, device.DeviceUUID) {
			return staticPublicationRootV7Invalidf(
				"devices are duplicate or not strictly ordered by UUID at index %d", index)
		}
		if err := staticPublicationRootV7PositiveLong(
			"device data page count", device.DataPageCount); err != nil {
			return staticPublicationRootV7FieldInvalid(fmt.Sprintf("device %d", index), err)
		}
		previousUUID = device.DeviceUUID
	}

	if len(root.Runs) == 0 || len(root.Runs) > MaxStaticPublicationRootV7Runs {
		return staticPublicationRootV7Invalidf(
			"run count %d is outside 1..%d", len(root.Runs), MaxStaticPublicationRootV7Runs)
	}
	expectedPages := root.PublicationLength / V7StoragePageSize
	if root.PublicationLength%V7StoragePageSize != 0 {
		expectedPages++
	}
	expectedObjectPage := uint64(0)
	usedDevices := make([]bool, len(root.Devices))
	physicalByDevice := make([][]StaticPublicationRootV7Run, len(root.Devices))
	var previousRun StaticPublicationRootV7Run
	var previousPhysicalEnd uint64
	for index, run := range root.Runs {
		if run.ObjectPageStart > MaxSignedLong {
			return staticPublicationRootV7Invalidf(
				"run %d object page start %d exceeds signed-Long ABI", index, run.ObjectPageStart)
		}
		if run.ObjectPageStart != expectedObjectPage {
			return staticPublicationRootV7Invalidf(
				"runs have a gap, overlap, or noncanonical order at object page %d",
				expectedObjectPage)
		}
		if uint64(run.DeviceIndex) >= uint64(len(root.Devices)) {
			return staticPublicationRootV7Invalidf(
				"run %d device index %d exceeds table size %d",
				index, run.DeviceIndex, len(root.Devices))
		}
		if err := staticPublicationRootV7NonNegativeLong(
			"run data page index", run.DataPageIndex); err != nil {
			return staticPublicationRootV7FieldInvalid(fmt.Sprintf("run %d", index), err)
		}
		if err := staticPublicationRootV7PositiveLong("run page count", run.PageCount); err != nil {
			return staticPublicationRootV7FieldInvalid(fmt.Sprintf("run %d", index), err)
		}
		objectEnd, ok := addLong(run.ObjectPageStart, run.PageCount)
		if !ok {
			return staticPublicationRootV7Invalidf("run %d object coverage overflows", index)
		}
		device := root.Devices[run.DeviceIndex]
		physicalEnd, ok := addLong(run.DataPageIndex, run.PageCount)
		if !ok || physicalEnd > device.DataPageCount {
			return staticPublicationRootV7Invalidf(
				"run %d exceeds device %q capacity %d",
				index, device.DeviceUUID, device.DataPageCount)
		}
		if index > 0 && run.DeviceIndex == previousRun.DeviceIndex &&
			previousPhysicalEnd == run.DataPageIndex {
			return staticPublicationRootV7Invalidf(
				"runs %d and %d are adjacent and coalescible", index-1, index)
		}
		usedDevices[run.DeviceIndex] = true
		physicalByDevice[run.DeviceIndex] = append(physicalByDevice[run.DeviceIndex], run)
		expectedObjectPage = objectEnd
		previousRun = run
		previousPhysicalEnd = physicalEnd
	}
	if expectedObjectPage != expectedPages {
		return staticPublicationRootV7Invalidf(
			"runs cover %d pages, exact publication length requires %d",
			expectedObjectPage, expectedPages)
	}
	for deviceIndex, used := range usedDevices {
		if !used {
			return staticPublicationRootV7Invalidf(
				"compact device %q is not referenced by any run",
				root.Devices[deviceIndex].DeviceUUID)
		}
		physical := append([]StaticPublicationRootV7Run(nil), physicalByDevice[deviceIndex]...)
		sort.Slice(physical, func(left, right int) bool {
			return physical[left].DataPageIndex < physical[right].DataPageIndex
		})
		for runIndex := 1; runIndex < len(physical); runIndex++ {
			previousEnd, ok := addLong(
				physical[runIndex-1].DataPageIndex, physical[runIndex-1].PageCount)
			if !ok || previousEnd > physical[runIndex].DataPageIndex {
				return staticPublicationRootV7Invalidf(
					"runs overlap physically on device %q",
					root.Devices[deviceIndex].DeviceUUID)
			}
		}
	}
	return nil
}

// ExpandedPageRuns restores the complete portable PageID form without
// repeating Owner and allocation identity in the persisted root.
func (root StaticPublicationRootV7) ExpandedPageRuns() ([]AllocationPageRunV7, error) {
	if err := root.Validate(); err != nil {
		return nil, err
	}
	return root.expandedPageRunsValidated(), nil
}

func (root StaticPublicationRootV7) expandedPageRunsValidated() []AllocationPageRunV7 {
	expanded := make([]AllocationPageRunV7, len(root.Runs))
	for index, run := range root.Runs {
		device := root.Devices[run.DeviceIndex]
		expanded[index] = AllocationPageRunV7{
			ObjectPageStart: run.ObjectPageStart,
			FirstPage: PageID{
				OwnerID:            root.OwnerID,
				DeviceUUID:         device.DeviceUUID,
				AllocationRecordID: root.AllocationRecordID,
				DataPageIndex:      run.DataPageIndex,
			},
			OwnerEpoch: root.OwnerEpoch,
			PageCount:  run.PageCount,
		}
	}
	return expanded
}

// BuildStaticPublicationRootV7 accepts only the exact storage result for the
// supplied immutable graph, including its complete zero-padded slot write.
func BuildStaticPublicationRootV7(
	publication PublicationV7,
	storage PublicationStorageV7,
) (StaticPublicationRootV7, error) {
	wantStorage, err := EncodePublicationV7ForStorage(publication)
	if err != nil {
		return StaticPublicationRootV7{}, err
	}
	if err := validateExactPublicationStorageV7(storage, wantStorage); err != nil {
		return StaticPublicationRootV7{}, err
	}
	source := staticPublicationRootV7ExactSource{
		contentObjectID: wantStorage.ContentObjectID,
		exactLength:     uint64(len(wantStorage.ExactBytes)),
		sha256:          wantStorage.SHA256,
		pageRuns:        wantStorage.PageRuns,
	}
	root, err := buildStaticPublicationRootV7Validated(publication, source)
	if err != nil {
		return StaticPublicationRootV7{}, err
	}
	if err := root.CrossCheckPublication(storage.ExactBytes); err != nil {
		return StaticPublicationRootV7{}, err
	}
	return root, nil
}

func buildStaticPublicationRootV7Validated(
	publication PublicationV7,
	source staticPublicationRootV7ExactSource,
) (StaticPublicationRootV7, error) {
	capacityByUUID := make(map[string]uint64, len(publication.InitialAllocation.Devices))
	for _, device := range publication.InitialAllocation.Devices {
		capacityByUUID[device.DeviceUUID] = device.DataPageCount
	}
	used := make(map[string]struct{}, len(source.pageRuns))
	for _, run := range source.pageRuns {
		used[run.FirstPage.DeviceUUID] = struct{}{}
	}
	deviceUUIDs := make([]string, 0, len(used))
	for deviceUUID := range used {
		deviceUUIDs = append(deviceUUIDs, deviceUUID)
	}
	sort.Slice(deviceUUIDs, func(left, right int) bool {
		return staticPublicationRootV7DeviceUUIDLess(deviceUUIDs[left], deviceUUIDs[right])
	})
	devices := make([]StaticPublicationRootV7Device, len(deviceUUIDs))
	deviceIndex := make(map[string]uint32, len(deviceUUIDs))
	for index, deviceUUID := range deviceUUIDs {
		capacity, exists := capacityByUUID[deviceUUID]
		if !exists {
			return StaticPublicationRootV7{}, staticPublicationRootV7Invalidf(
				"publication run references unknown device %q", deviceUUID)
		}
		devices[index] = StaticPublicationRootV7Device{
			DeviceUUID: deviceUUID, DataPageCount: capacity}
		deviceIndex[deviceUUID] = uint32(index)
	}
	runs := make([]StaticPublicationRootV7Run, len(source.pageRuns))
	for index, run := range source.pageRuns {
		runs[index] = StaticPublicationRootV7Run{
			ObjectPageStart: run.ObjectPageStart,
			DeviceIndex:     deviceIndex[run.FirstPage.DeviceUUID],
			DataPageIndex:   run.FirstPage.DataPageIndex,
			PageCount:       run.PageCount,
		}
	}
	root := StaticPublicationRootV7{
		State:                  StaticPublicationRootV7Committed,
		CheckpointID:           publication.CheckpointID,
		StorageCompatibilityID: V7StorageCompatibilityID,
		PublicationObjectID:    source.contentObjectID,
		OwnerID:                publication.InitialAllocation.OwnerID,
		OwnerEpoch:             publication.InitialAllocation.OwnerEpoch,
		AllocationRecordID:     publication.InitialAllocation.AllocationRecordID,
		PublicationLength:      source.exactLength,
		PublicationSHA256:      source.sha256,
		Devices:                devices,
		Runs:                   runs,
	}
	if err := root.Validate(); err != nil {
		return StaticPublicationRootV7{}, err
	}
	return root, nil
}

// CrossCheckPublication strictly decodes and canonically re-encodes the exact
// TRPUB007 bytes, then re-derives the publication control-object locator and
// exact used-device capacities before comparing every persisted field.
func (root StaticPublicationRootV7) CrossCheckPublication(publicationBytes []byte) error {
	if err := root.Validate(); err != nil {
		return err
	}
	publication, err := DecodePublicationV7(publicationBytes)
	if err != nil {
		return fmt.Errorf("decode static-root publication: %w", err)
	}
	canonical, err := CanonicalPublicationV7Bytes(publication)
	if err != nil {
		return fmt.Errorf("canonicalize static-root publication: %w", err)
	}
	if !bytes.Equal(canonical, publicationBytes) {
		return staticPublicationRootV7Invalidf("publication bytes are not canonical TRPUB007")
	}
	source, err := deriveStaticPublicationRootV7ExactSource(publication, canonical)
	if err != nil {
		return fmt.Errorf("derive static-root exact publication locator: %w", err)
	}
	expected, err := buildStaticPublicationRootV7Validated(publication, source)
	if err != nil {
		return err
	}
	if !equalStaticPublicationRootV7(root, expected) {
		return staticPublicationRootV7Invalidf(
			"root does not exactly match the immutable publication and derived locator")
	}
	expanded := root.expandedPageRunsValidated()
	if !equalAllocationPageRunsV7(expanded, source.pageRuns) {
		return staticPublicationRootV7Invalidf(
			"expanded root runs do not match derived publication control-object runs")
	}
	return nil
}

// deriveStaticPublicationRootV7ExactSource is the restore-side derivation
// seam. It hashes and locates only the exact canonical TRPUB007 bytes; unlike
// EncodePublicationV7ForStorage it cannot materialize slot padding or padded
// write runs.
func deriveStaticPublicationRootV7ExactSource(
	publication PublicationV7,
	canonical []byte,
) (staticPublicationRootV7ExactSource, error) {
	var publicationObject ContentObjectV7
	found := false
	for _, object := range publication.Objects {
		if object.Kind == ContentPublicationV7 {
			publicationObject = object
			found = true
			break
		}
	}
	if !found {
		return staticPublicationRootV7ExactSource{}, staticPublicationRootV7Invalidf(
			"immutable publication has no publication slot")
	}
	exactLength := uint64(len(canonical))
	runs, err := publication.controlObjectPageRunsValidated(
		publicationObject, exactLength, exactLength)
	if err != nil {
		return staticPublicationRootV7ExactSource{}, err
	}
	return staticPublicationRootV7ExactSource{
		contentObjectID: publicationObject.ObjectID,
		exactLength:     exactLength,
		sha256:          sha256.Sum256(canonical),
		pageRuns:        runs,
	}, nil
}

func validateExactPublicationStorageV7(
	got PublicationStorageV7,
	want PublicationStorageV7,
) error {
	switch {
	case got.ContentObjectID != want.ContentObjectID:
		return staticPublicationRootV7Invalidf("publication storage object ID does not match")
	case got.LogicalPageStart != want.LogicalPageStart:
		return staticPublicationRootV7Invalidf("publication storage logical page start does not match")
	case got.CapacityPages != want.CapacityPages:
		return staticPublicationRootV7Invalidf("publication storage capacity does not match")
	case !bytes.Equal(got.ExactBytes, want.ExactBytes):
		return staticPublicationRootV7Invalidf("publication storage exact bytes do not match")
	case !bytes.Equal(got.PaddedBytes, want.PaddedBytes):
		return staticPublicationRootV7Invalidf("publication storage padded bytes do not match")
	case got.SHA256 != want.SHA256:
		return staticPublicationRootV7Invalidf("publication storage SHA-256 does not match")
	case !equalAllocationPageRunsV7(got.PageRuns, want.PageRuns):
		return staticPublicationRootV7Invalidf("publication storage exact-byte runs do not match")
	case !equalAllocationPageRunsV7(got.PaddedWriteRuns, want.PaddedWriteRuns):
		return staticPublicationRootV7Invalidf("publication storage padded-write runs do not match")
	default:
		return nil
	}
}

func equalAllocationPageRunsV7(left, right []AllocationPageRunV7) bool {
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

func equalStaticPublicationRootV7(left, right StaticPublicationRootV7) bool {
	if left.State != right.State ||
		left.CheckpointID != right.CheckpointID ||
		left.StorageCompatibilityID != right.StorageCompatibilityID ||
		left.PublicationObjectID != right.PublicationObjectID ||
		left.OwnerID != right.OwnerID ||
		left.OwnerEpoch != right.OwnerEpoch ||
		left.AllocationRecordID != right.AllocationRecordID ||
		left.PublicationLength != right.PublicationLength ||
		left.PublicationSHA256 != right.PublicationSHA256 ||
		len(left.Devices) != len(right.Devices) || len(left.Runs) != len(right.Runs) {
		return false
	}
	for index := range left.Devices {
		if left.Devices[index] != right.Devices[index] {
			return false
		}
	}
	for index := range left.Runs {
		if left.Runs[index] != right.Runs[index] {
			return false
		}
	}
	return true
}

func validateStaticPublicationRootV7Identity(name, value string) error {
	if value == "" {
		return staticPublicationRootV7Invalidf("%s is empty", name)
	}
	if !utf8.ValidString(value) {
		return staticPublicationRootV7Invalidf("%s is not valid UTF-8", name)
	}
	if len(value) > MaxStaticPublicationRootV7IdentityBytes {
		return staticPublicationRootV7Invalidf(
			"%s is %d UTF-8 bytes, limit is %d",
			name, len(value), MaxStaticPublicationRootV7IdentityBytes)
	}
	if strings.TrimSpace(value) != value {
		return staticPublicationRootV7Invalidf("%s has surrounding whitespace", name)
	}
	for _, character := range value {
		if unicode.IsControl(character) {
			return staticPublicationRootV7Invalidf("%s contains a control character", name)
		}
	}
	return nil
}

func staticPublicationRootV7DeviceUUIDLess(left, right string) bool {
	return bytes.Compare([]byte(left), []byte(right)) < 0
}

func staticPublicationRootV7PositiveLong(name string, value uint64) error {
	if value == 0 || value > MaxSignedLong {
		return staticPublicationRootV7Invalidf(
			"%s %d is outside 1..%d", name, value, MaxSignedLong)
	}
	return nil
}

func staticPublicationRootV7NonNegativeLong(name string, value uint64) error {
	if value > MaxSignedLong {
		return staticPublicationRootV7Invalidf(
			"%s %d exceeds %d", name, value, MaxSignedLong)
	}
	return nil
}

func staticPublicationRootV7FieldInvalid(context string, err error) error {
	return fmt.Errorf("%s: %v: %w", context, err, ErrInvalidStaticPublicationRootV7)
}

func staticPublicationRootV7Invalidf(format string, arguments ...interface{}) error {
	return fmt.Errorf(format+": %w", append(arguments, ErrInvalidStaticPublicationRootV7)...)
}

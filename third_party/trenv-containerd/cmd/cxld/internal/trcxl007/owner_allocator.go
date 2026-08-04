package trcxl007

import (
	"container/heap"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"sort"

	"github.com/containerd/containerd/third_party/trenv-containerd/pkg/cxlcheckpoint"
)

const (
	// OwnerReserveRequestDigestDomain identifies the exact, caller-independent
	// digest of one checkpoint reserve request. The request type deliberately
	// has no RequestSHA256 field: callers supply identities, demand, limits, and
	// authority commitments, and the Owner derives the digest itself.
	OwnerReserveRequestDigestDomain = "TRCXL007-owner-reserve-request-v1"
)

var (
	ErrInvalidOwnerReserveRequest  = errors.New("invalid TRCXL007 Owner reserve request")
	ErrOwnerAllocatorInputMismatch = errors.New(
		"TRCXL007 Owner allocator input does not match committed Owner state")
	ErrOwnerReserveConflict = errors.New(
		"TRCXL007 Owner reserve request/checkpoint conflicts with an existing record")
	ErrOwnerReserveSequenceOverflow = errors.New(
		"TRCXL007 Owner reserve sequence exceeds the signed-Long ABI")
)

// OwnerReserveOutcome identifies which pure planning result was returned.
// REPLAY and REJECTED_NO_SPACE never contain desired device mutations.
type OwnerReserveOutcome uint8

const (
	OwnerReservePlanned OwnerReserveOutcome = iota + 1
	OwnerReserveReplay
	OwnerReserveRejectedNoSpace
)

// OwnerReserveRequest is the complete checkpoint-granular allocation request.
// Static Owner-group fields prevent the same textual request ID from being
// replayed under a different authority epoch or membership. ContentDemands
// uses one 4 KiB capacity unit for memory, artifact, restore, and control
// objects; there is no separate artifact allocator or byte-sized allocation.
// V7 requires nonzero Scheduler-reserve, Producer-capability, and reclaim-
// authority SHA-256 commitments so every PREPARING record is reclaimable by
// an exact capability commitment rather than becoming permanently abortless.
type OwnerReserveRequest struct {
	ClusterID              string
	OwnerGroupID           string
	CurrentOwnerID         string
	AnchorDeviceUUID       string
	StorageCompatibilityID string

	OwnerEpoch                 uint64
	GroupConfigurationSequence uint64
	MembershipSHA256           [sha256.Size]byte

	RequestID       string
	CheckpointID    string
	ProducerID      string
	DedupDomainID   string
	SharingPolicyID string

	MaxExtents        uint32
	ContentDemands    []OwnerStateContentDemand
	AuthorityEvidence OwnerStateAuthorityEvidence
}

// OwnerAllocatorDeviceSnapshot is one canonical device-local allocator input.
// DeviceUUID is a persistent identity, never a path. Geometry permits an exact
// cross-check of the device binding and canonical allocator envelope without
// opening, mapping, reading, or writing a device.
type OwnerAllocatorDeviceSnapshot struct {
	DeviceUUID string
	Geometry   DeviceGeometry
	Snapshot   AllocatorSnapshot
}

// OwnerAllocatorSnapshotUpdate is one desired device-local bitmap snapshot.
// It is a value to hand to the later single-writer persistence state machine;
// this planner does not select A/B, perform I/O, or claim durability.
type OwnerAllocatorSnapshotUpdate struct {
	DeviceUUID               string
	PreviousSnapshotSequence uint64
	DesiredSnapshot          AllocatorSnapshot
}

// OwnerReservedDescriptorRun compactly describes identical RESERVED page
// descriptors. Runs are emitted in checkpoint-logical order and split at every
// content-object boundary, so OriginObjectID and ContentKind are unambiguous.
// No descriptor or payload page bytes are copied into the plan.
type OwnerReservedDescriptorRun struct {
	DeviceUUID         string
	StartDataPageIndex uint64
	LogicalPageStart   uint64
	ObjectPageStart    uint64
	PageCount          uint64
	Descriptor         Descriptor
}

// OwnerCheckpointReservePlan is a pure result. Exactly one state shape is
// populated:
//
//   - PLANNED: PREPARING, affected allocator snapshots and descriptor runs,
//     followed by GRANTED;
//   - REPLAY: the existing exact allocation record and no mutation;
//   - REJECTED_NO_SPACE: one durable rejection snapshot and no device mutation.
//
// The caller remains responsible for the ordered persistence protocol.
type OwnerCheckpointReservePlan struct {
	Outcome       OwnerReserveOutcome
	RequestSHA256 [sha256.Size]byte
	Record        OwnerStateAllocationRecord

	PreparingOwnerState OwnerStateSnapshot
	AllocatorUpdates    []OwnerAllocatorSnapshotUpdate
	ReservedDescriptors []OwnerReservedDescriptorRun
	GrantedOwnerState   OwnerStateSnapshot

	RejectedOwnerState OwnerStateSnapshot
}

// OwnerReserveRequestSHA256 validates and hashes one request. The encoding is
// domain-separated, length-prefixes every UTF-8 identity, uses little-endian
// fixed-width numbers, and includes every demand and authority commitment.
func OwnerReserveRequestSHA256(request OwnerReserveRequest) ([sha256.Size]byte, error) {
	totalDemandPages, err := validateOwnerReserveRequest(request)
	if err != nil {
		return [sha256.Size]byte{}, err
	}

	digest := sha256.New()
	ownerStateDigestString(digest, OwnerReserveRequestDigestDomain)
	ownerStateDigestString(digest, request.ClusterID)
	ownerStateDigestString(digest, request.OwnerGroupID)
	ownerStateDigestString(digest, request.CurrentOwnerID)
	ownerStateDigestString(digest, request.AnchorDeviceUUID)
	ownerStateDigestString(digest, request.StorageCompatibilityID)
	ownerReserveDigestUint64(digest, request.OwnerEpoch)
	ownerReserveDigestUint64(digest, request.GroupConfigurationSequence)
	_, _ = digest.Write(request.MembershipSHA256[:])

	ownerStateDigestString(digest, request.RequestID)
	ownerStateDigestString(digest, request.CheckpointID)
	ownerStateDigestString(digest, request.ProducerID)
	ownerStateDigestString(digest, request.DedupDomainID)
	ownerStateDigestString(digest, request.SharingPolicyID)
	ownerReserveDigestUint32(digest, request.MaxExtents)
	ownerReserveDigestUint64(digest, uint64(ContentPageBytes))
	ownerReserveDigestUint64(digest, totalDemandPages)
	ownerReserveDigestUint32(digest, uint32(len(request.ContentDemands)))
	for _, demand := range request.ContentDemands {
		_, _ = digest.Write([]byte{byte(demand.Kind)})
		ownerReserveDigestUint64(digest, demand.ObjectID)
		ownerReserveDigestUint64(digest, demand.ByteLength)
		ownerReserveDigestUint64(digest, demand.CapacityPages)
		ownerReserveDigestUint64(digest, demand.LogicalPageStart)
	}
	_, _ = digest.Write(request.AuthorityEvidence.SchedulerReserveSHA256[:])
	_, _ = digest.Write(request.AuthorityEvidence.ProducerCapabilitySHA256[:])
	_, _ = digest.Write(request.AuthorityEvidence.PublicationAuthoritySHA256[:])
	_, _ = digest.Write(request.AuthorityEvidence.ReclaimAuthoritySHA256[:])

	var result [sha256.Size]byte
	copy(result[:], digest.Sum(nil))
	if result == ([sha256.Size]byte{}) {
		return [sha256.Size]byte{}, ownerReserveInvalidf("derived request SHA-256 is zero")
	}
	return result, nil
}

// PlanOwnerCheckpointReserve computes a complete checkpoint reserve protocol
// without performing it. Allocation policy is deterministic and explicitly
// bounded:
//
//  1. use the smallest single free run that fits the whole checkpoint;
//  2. otherwise, use the fewest runs on one sufficient device;
//  3. otherwise, grow a deterministic descending-free-capacity device prefix
//     and retain the best feasible plan made from its globally largest runs.
//
// Equal choices use DeviceUUID and data-page index ordering. Step 3 is a
// bounded lexicographic greedy policy, not an exponential subset search and
// not a claim of globally minimum devices across all subsets. It never returns
// REJECTED_NO_SPACE merely because one prefix is fragmented: all prefixes are
// considered, and rejection requires the sum of the globally largest
// MaxExtents runs across every device to be below the demand. At most
// request.MaxExtents (and never more than 256) free runs are retained per
// device and globally while scanning and selecting.
func PlanOwnerCheckpointReserve(
	committed OwnerStateSnapshot,
	allocatorInputs []OwnerAllocatorDeviceSnapshot,
	request OwnerReserveRequest,
) (OwnerCheckpointReservePlan, error) {
	devices, anchorGeometry, err := validateOwnerAllocatorInputs(committed, allocatorInputs)
	if err != nil {
		return OwnerCheckpointReservePlan{}, err
	}
	totalDemandPages, err := validateOwnerReserveRequestAgainstState(request, committed)
	if err != nil {
		return OwnerCheckpointReservePlan{}, err
	}
	requestSHA256, err := OwnerReserveRequestSHA256(request)
	if err != nil {
		return OwnerCheckpointReservePlan{}, err
	}

	if record, replay, err := ownerReserveReplay(committed, request, requestSHA256, totalDemandPages); err != nil {
		return OwnerCheckpointReservePlan{}, err
	} else if replay {
		return OwnerCheckpointReservePlan{
			Outcome:       OwnerReserveReplay,
			RequestSHA256: requestSHA256,
			Record:        record,
		}, nil
	}

	for index := range devices {
		if err := devices[index].scanFreeRuns(totalDemandPages, request.MaxExtents); err != nil {
			return OwnerCheckpointReservePlan{}, err
		}
	}
	placedRuns, fits := chooseOwnerReserveRuns(devices, totalDemandPages, request.MaxExtents)
	if !fits {
		return buildOwnerReserveNoSpacePlan(
			committed,
			anchorGeometry,
			request,
			requestSHA256,
			totalDemandPages)
	}

	return buildOwnerReserveSuccessPlan(
		committed,
		anchorGeometry,
		devices,
		request,
		requestSHA256,
		totalDemandPages,
		placedRuns)
}

type ownerAllocatorDevice struct {
	member        OwnerStateDevice
	geometry      DeviceGeometry
	snapshot      AllocatorSnapshot
	totalFree     uint64
	freeRunCount  uint64
	retainedRuns  []ownerAllocatorFreeRun
	bestSingleFit ownerAllocatorFreeRun
	hasSingleFit  bool
}

type ownerAllocatorFreeRun struct {
	DeviceUUID         string
	StartDataPageIndex uint64
	PageCount          uint64
}

type ownerAllocatorPlacedRun struct {
	DeviceUUID         string
	StartDataPageIndex uint64
	LogicalPageStart   uint64
	PageCount          uint64
}

// ownerAllocatorFreeRunHeap keeps its least desirable retained run at index
// zero. Replacement therefore caps metadata at MaxExtents without retaining
// every sparse hole in a large device.
type ownerAllocatorFreeRunHeap []ownerAllocatorFreeRun

func (runs ownerAllocatorFreeRunHeap) Len() int { return len(runs) }
func (runs ownerAllocatorFreeRunHeap) Less(left, right int) bool {
	return ownerAllocatorRunWorse(runs[left], runs[right])
}
func (runs ownerAllocatorFreeRunHeap) Swap(left, right int) {
	runs[left], runs[right] = runs[right], runs[left]
}
func (runs *ownerAllocatorFreeRunHeap) Push(value interface{}) {
	*runs = append(*runs, value.(ownerAllocatorFreeRun))
}
func (runs *ownerAllocatorFreeRunHeap) Pop() interface{} {
	old := *runs
	last := len(old) - 1
	value := old[last]
	*runs = old[:last]
	return value
}

func validateOwnerReserveRequest(request OwnerReserveRequest) (uint64, error) {
	for _, identity := range []struct {
		name  string
		value string
	}{
		{"cluster ID", request.ClusterID},
		{"Owner-group ID", request.OwnerGroupID},
		{"current Owner ID", request.CurrentOwnerID},
		{"anchor device UUID", request.AnchorDeviceUUID},
	} {
		if err := validateOwnerStateIdentity(identity.name, identity.value); err != nil {
			return 0, ownerReserveInvalidf("%v", err)
		}
	}
	if err := validateOwnerStateDeviceUUID("anchor device UUID", request.AnchorDeviceUUID); err != nil {
		return 0, ownerReserveInvalidf("%v", err)
	}
	if request.StorageCompatibilityID != cxlcheckpoint.V7StorageCompatibilityID {
		return 0, ownerReserveInvalidf("storage compatibility ID does not equal the compiled V7 target")
	}
	if err := ownerStatePositiveLong("Owner epoch", request.OwnerEpoch); err != nil {
		return 0, ownerReserveInvalidf("%v", err)
	}
	if err := ownerStatePositiveLong(
		"group-configuration sequence", request.GroupConfigurationSequence); err != nil {
		return 0, ownerReserveInvalidf("%v", err)
	}
	if request.MembershipSHA256 == ([sha256.Size]byte{}) {
		return 0, ownerReserveInvalidf("membership SHA-256 is zero")
	}
	if request.AuthorityEvidence.SchedulerReserveSHA256 == ([sha256.Size]byte{}) {
		return 0, ownerReserveInvalidf("scheduler reserve SHA-256 is zero")
	}
	if request.AuthorityEvidence.ProducerCapabilitySHA256 == ([sha256.Size]byte{}) {
		return 0, ownerReserveInvalidf("Producer capability SHA-256 is zero")
	}
	if request.AuthorityEvidence.ReclaimAuthoritySHA256 == ([sha256.Size]byte{}) {
		return 0, ownerReserveInvalidf("reclaim authority SHA-256 is zero")
	}

	totalDemandPages, err := ownerReserveTotalDemandPages(request.ContentDemands)
	if err != nil {
		return 0, err
	}
	probe := OwnerStateAllocationRecord{
		AllocationRecordID:       1,
		OwnerTransactionSequence: 1,
		State:                    OwnerAllocationRejectedNoSpace,
		RequestID:                request.RequestID,
		CheckpointID:             request.CheckpointID,
		ProducerID:               request.ProducerID,
		DedupDomainID:            request.DedupDomainID,
		SharingPolicyID:          request.SharingPolicyID,
		RequestSHA256:            [sha256.Size]byte{1},
		TotalDemandPages:         totalDemandPages,
		MaxExtents:               request.MaxExtents,
		ContentDemands:           request.ContentDemands,
		AuthorityEvidence:        request.AuthorityEvidence,
	}
	if err := validateOwnerStateRecord(probe, nil); err != nil {
		return 0, ownerReserveInvalidf("request record shape: %v", err)
	}
	return totalDemandPages, nil
}

func validateOwnerReserveRequestAgainstState(
	request OwnerReserveRequest,
	committed OwnerStateSnapshot,
) (uint64, error) {
	totalDemandPages, err := validateOwnerReserveRequest(request)
	if err != nil {
		return 0, err
	}
	if request.ClusterID != committed.ClusterID ||
		request.OwnerGroupID != committed.OwnerGroupID ||
		request.CurrentOwnerID != committed.CurrentOwnerID ||
		request.AnchorDeviceUUID != committed.AnchorDeviceUUID ||
		request.StorageCompatibilityID != committed.StorageCompatibilityID ||
		request.OwnerEpoch != committed.OwnerEpoch ||
		request.GroupConfigurationSequence != committed.GroupConfigurationSequence ||
		request.MembershipSHA256 != committed.MembershipSHA256 {
		return 0, ownerAllocatorInputMismatchf(
			"request static Owner-group identity differs from committed Owner state")
	}
	return totalDemandPages, nil
}

func ownerReserveTotalDemandPages(demands []OwnerStateContentDemand) (uint64, error) {
	var total uint64
	for _, demand := range demands {
		var ok bool
		total, ok = checkedAdd(total, demand.CapacityPages)
		if !ok || total > cxlcheckpoint.MaxSignedLong {
			return 0, ownerReserveInvalidf("content demand page total exceeds the signed-Long ABI")
		}
	}
	if total == 0 {
		return 0, ownerReserveInvalidf("content demand page total is zero")
	}
	return total, nil
}

func validateOwnerAllocatorInputs(
	committed OwnerStateSnapshot,
	inputs []OwnerAllocatorDeviceSnapshot,
) ([]ownerAllocatorDevice, DeviceGeometry, error) {
	if err := committed.Validate(); err != nil {
		return nil, DeviceGeometry{}, ownerAllocatorInputMismatchf(
			"committed Owner state: %v", err)
	}
	members := committed.Devices()
	if len(inputs) != len(members) {
		return nil, DeviceGeometry{}, ownerAllocatorInputMismatchf(
			"allocator input count %d does not equal device count %d", len(inputs), len(members))
	}
	ordered := append([]OwnerAllocatorDeviceSnapshot(nil), inputs...)
	sort.Slice(ordered, func(left, right int) bool {
		return ordered[left].DeviceUUID < ordered[right].DeviceUUID
	})

	result := make([]ownerAllocatorDevice, len(ordered))
	var anchorGeometry DeviceGeometry
	anchorFound := false
	for index := range ordered {
		input := ordered[index]
		member := members[index]
		if input.DeviceUUID != member.DeviceUUID {
			return nil, DeviceGeometry{}, ownerAllocatorInputMismatchf(
				"allocator device %q does not equal membership device %q at index %d",
				input.DeviceUUID, member.DeviceUUID, index)
		}
		if index > 0 && ordered[index-1].DeviceUUID == input.DeviceUUID {
			return nil, DeviceGeometry{}, ownerAllocatorInputMismatchf(
				"allocator device UUID %q is duplicated", input.DeviceUUID)
		}
		if err := input.Geometry.Validate(); err != nil {
			return nil, DeviceGeometry{}, ownerAllocatorInputMismatchf(
				"device %q geometry: %v", input.DeviceUUID, err)
		}
		if input.Geometry.DataPageCount != member.DataPageCount {
			return nil, DeviceGeometry{}, ownerAllocatorInputMismatchf(
				"device %q geometry page count %d does not equal membership count %d",
				input.DeviceUUID, input.Geometry.DataPageCount, member.DataPageCount)
		}
		if member.DeviceOwnerEpoch != committed.OwnerEpoch {
			return nil, DeviceGeometry{}, ownerAllocatorInputMismatchf(
				"device %q Owner epoch %d does not equal committed group epoch %d",
				input.DeviceUUID, member.DeviceOwnerEpoch, committed.OwnerEpoch)
		}

		bindingSource := DeviceSuperblock{
			ClusterID:              committed.ClusterID,
			DeviceUUID:             member.DeviceUUID,
			StorageCompatibilityID: committed.StorageCompatibilityID,
			Geometry:               input.Geometry,
		}
		deviceBinding := bindingSource.DeviceBindingSHA256()
		if deviceBinding != member.DeviceBindingSHA256 {
			return nil, DeviceGeometry{}, ownerAllocatorInputMismatchf(
				"device %q static binding differs from membership", input.DeviceUUID)
		}
		groupBindingSource := DeviceSuperblock{
			ClusterID:                       committed.ClusterID,
			OwnerGroupID:                    committed.OwnerGroupID,
			CurrentOwnerID:                  committed.CurrentOwnerID,
			OwnerGroupAnchorDeviceUUID:      committed.AnchorDeviceUUID,
			OwnerEpoch:                      member.DeviceOwnerEpoch,
			OwnerGroupConfigurationSequence: committed.GroupConfigurationSequence,
			OwnerGroupMembershipSHA256:      committed.MembershipSHA256,
		}
		ownerGroupBinding := groupBindingSource.OwnerGroupIdentitySHA256()
		if err := input.Snapshot.CrossCheck(
			input.Geometry,
			deviceBinding,
			ownerGroupBinding,
			member.DeviceOwnerEpoch); err != nil {
			return nil, DeviceGeometry{}, ownerAllocatorInputMismatchf(
				"device %q allocator snapshot: %v", input.DeviceUUID, err)
		}
		if input.Snapshot.AppliedOwnerTransactionSequence >=
			committed.NextOwnerTransactionSequence {
			return nil, DeviceGeometry{}, ownerAllocatorInputMismatchf(
				"device %q applied transaction %d is not below next Owner transaction %d",
				input.DeviceUUID,
				input.Snapshot.AppliedOwnerTransactionSequence,
				committed.NextOwnerTransactionSequence)
		}
		if _, err := CanonicalAllocatorSnapshotBytes(input.Snapshot, input.Geometry); err != nil {
			return nil, DeviceGeometry{}, ownerAllocatorInputMismatchf(
				"device %q allocator snapshot is not canonical: %v", input.DeviceUUID, err)
		}
		if input.DeviceUUID == committed.AnchorDeviceUUID {
			anchorGeometry = input.Geometry
			anchorFound = true
		}
		result[index] = ownerAllocatorDevice{
			member:   member,
			geometry: input.Geometry,
			snapshot: input.Snapshot.Clone(),
		}
	}
	if !anchorFound {
		return nil, DeviceGeometry{}, ownerAllocatorInputMismatchf(
			"anchor device %q has no allocator input", committed.AnchorDeviceUUID)
	}
	if _, err := CanonicalOwnerStateBytes(committed, anchorGeometry); err != nil {
		return nil, DeviceGeometry{}, ownerAllocatorInputMismatchf(
			"committed Owner state is not canonical for the anchor geometry: %v", err)
	}
	return result, anchorGeometry, nil
}

func (device *ownerAllocatorDevice) scanFreeRuns(demand uint64, maxExtents uint32) error {
	bitmap := device.snapshot.BitmapBytes()
	retained := make(ownerAllocatorFreeRunHeap, 0, int(maxExtents))
	heap.Init(&retained)
	for page := uint64(0); page < device.snapshot.DataPageCount; {
		if ownerAllocatorBitmapSet(bitmap, page) {
			page++
			continue
		}
		start := page
		for page < device.snapshot.DataPageCount && !ownerAllocatorBitmapSet(bitmap, page) {
			page++
		}
		run := ownerAllocatorFreeRun{
			DeviceUUID:         device.member.DeviceUUID,
			StartDataPageIndex: start,
			PageCount:          page - start,
		}
		var ok bool
		device.totalFree, ok = checkedAdd(device.totalFree, run.PageCount)
		if !ok || device.totalFree > cxlcheckpoint.MaxSignedLong {
			return ownerAllocatorInputMismatchf(
				"device %q free-page count overflows", device.member.DeviceUUID)
		}
		device.freeRunCount++
		ownerAllocatorRetainFreeRun(&retained, run, int(maxExtents))
		if run.PageCount >= demand &&
			(!device.hasSingleFit || ownerAllocatorSingleFitBetter(run, device.bestSingleFit)) {
			device.bestSingleFit = run
			device.hasSingleFit = true
		}
	}
	device.retainedRuns = append([]ownerAllocatorFreeRun(nil), retained...)
	sort.Slice(device.retainedRuns, func(left, right int) bool {
		return ownerAllocatorRunBetter(device.retainedRuns[left], device.retainedRuns[right])
	})
	return nil
}

func ownerAllocatorRetainFreeRun(
	runs *ownerAllocatorFreeRunHeap,
	candidate ownerAllocatorFreeRun,
	limit int,
) {
	if limit <= 0 {
		return
	}
	if runs.Len() < limit {
		heap.Push(runs, candidate)
		return
	}
	if ownerAllocatorRunBetter(candidate, (*runs)[0]) {
		_ = heap.Pop(runs)
		heap.Push(runs, candidate)
	}
}

func chooseOwnerReserveRuns(
	devices []ownerAllocatorDevice,
	demand uint64,
	maxExtents uint32,
) ([]ownerAllocatorPlacedRun, bool) {
	var bestSingle ownerAllocatorFreeRun
	hasSingle := false
	for _, device := range devices {
		if device.hasSingleFit &&
			(!hasSingle || ownerAllocatorSingleFitBetter(device.bestSingleFit, bestSingle)) {
			bestSingle = device.bestSingleFit
			hasSingle = true
		}
	}
	if hasSingle {
		return ownerAllocatorMaterializeRuns([]ownerAllocatorFreeRun{bestSingle}, demand), true
	}

	var bestDeviceRuns []ownerAllocatorFreeRun
	bestDeviceUUID := ""
	for _, device := range devices {
		if device.totalFree < demand {
			continue
		}
		candidate, fits := ownerAllocatorTakeRuns(device.retainedRuns, demand, maxExtents)
		if !fits {
			continue
		}
		if bestDeviceRuns == nil || len(candidate) < len(bestDeviceRuns) ||
			(len(candidate) == len(bestDeviceRuns) && device.member.DeviceUUID < bestDeviceUUID) {
			bestDeviceRuns = candidate
			bestDeviceUUID = device.member.DeviceUUID
		}
	}
	if bestDeviceRuns != nil {
		return ownerAllocatorMaterializeRuns(bestDeviceRuns, demand), true
	}

	// Multi-device policy remains bounded: devices are introduced in descending
	// total-free order, while one size-MaxExtents heap retains the globally
	// largest runs in the current prefix. We inspect every prefix and retain the
	// candidate with the fewest actual devices and then extents. This is a
	// deterministic heuristic for device count, not combinatorial subset search.
	// At the final prefix the heap contains the global top-E runs; if they cannot
	// cover demand, no placement with E or fewer runs can cover it.
	byCapacity := make([]ownerAllocatorDevice, len(devices))
	copy(byCapacity, devices)
	sort.Slice(byCapacity, func(left, right int) bool {
		if byCapacity[left].totalFree != byCapacity[right].totalFree {
			return byCapacity[left].totalFree > byCapacity[right].totalFree
		}
		return byCapacity[left].member.DeviceUUID < byCapacity[right].member.DeviceUUID
	})
	globalTop := make(ownerAllocatorFreeRunHeap, 0, int(maxExtents))
	heap.Init(&globalTop)
	var best []ownerAllocatorFreeRun
	bestDeviceCount := 0
	for _, device := range byCapacity {
		for _, run := range device.retainedRuns {
			ownerAllocatorRetainFreeRun(&globalTop, run, int(maxExtents))
		}
		ordered := append([]ownerAllocatorFreeRun(nil), globalTop...)
		sort.Slice(ordered, func(left, right int) bool {
			return ownerAllocatorRunBetter(ordered[left], ordered[right])
		})
		candidate, fits := ownerAllocatorTakeRuns(ordered, demand, maxExtents)
		if !fits {
			continue
		}
		deviceCount := ownerAllocatorRunDeviceCount(candidate)
		if best == nil || deviceCount < bestDeviceCount ||
			(deviceCount == bestDeviceCount && len(candidate) < len(best)) ||
			(deviceCount == bestDeviceCount && len(candidate) == len(best) &&
				ownerAllocatorRunListLess(candidate, best)) {
			best = append([]ownerAllocatorFreeRun(nil), candidate...)
			bestDeviceCount = deviceCount
		}
	}
	if best == nil {
		return nil, false
	}
	return ownerAllocatorMaterializeRuns(best, demand), true
}

func ownerAllocatorTakeRuns(
	runs []ownerAllocatorFreeRun,
	demand uint64,
	maxExtents uint32,
) ([]ownerAllocatorFreeRun, bool) {
	selected := make([]ownerAllocatorFreeRun, 0, int(maxExtents))
	capacity := uint64(0)
	for _, run := range runs {
		if uint32(len(selected)) == maxExtents {
			break
		}
		selected = append(selected, run)
		capacity = ownerAllocatorSaturatingAdd(capacity, run.PageCount, demand)
		if capacity >= demand {
			return selected, true
		}
	}
	return nil, false
}

func ownerAllocatorRunDeviceCount(runs []ownerAllocatorFreeRun) int {
	devices := make(map[string]struct{}, len(runs))
	for _, run := range runs {
		devices[run.DeviceUUID] = struct{}{}
	}
	return len(devices)
}

func ownerAllocatorRunListLess(left, right []ownerAllocatorFreeRun) bool {
	for index := 0; index < len(left) && index < len(right); index++ {
		if left[index] == right[index] {
			continue
		}
		return ownerAllocatorRunBetter(left[index], right[index])
	}
	return len(left) < len(right)
}

func ownerAllocatorSaturatingAdd(value, increment, limit uint64) uint64 {
	if value >= limit || increment >= limit-value {
		return limit
	}
	return value + increment
}

func ownerAllocatorMaterializeRuns(
	selected []ownerAllocatorFreeRun,
	demand uint64,
) []ownerAllocatorPlacedRun {
	result := make([]ownerAllocatorPlacedRun, 0, len(selected))
	remaining := demand
	logical := uint64(0)
	for _, run := range selected {
		pageCount := run.PageCount
		if pageCount > remaining {
			pageCount = remaining
		}
		result = append(result, ownerAllocatorPlacedRun{
			DeviceUUID:         run.DeviceUUID,
			StartDataPageIndex: run.StartDataPageIndex,
			LogicalPageStart:   logical,
			PageCount:          pageCount,
		})
		logical += pageCount
		remaining -= pageCount
		if remaining == 0 {
			break
		}
	}
	return result
}

func buildOwnerReserveSuccessPlan(
	committed OwnerStateSnapshot,
	anchorGeometry DeviceGeometry,
	devices []ownerAllocatorDevice,
	request OwnerReserveRequest,
	requestSHA256 [sha256.Size]byte,
	totalDemandPages uint64,
	placedRuns []ownerAllocatorPlacedRun,
) (OwnerCheckpointReservePlan, error) {
	preparingSnapshotSequence, err := ownerReserveAddSequence(
		committed.SnapshotSequence, 1, "PREPARING Owner-state snapshot sequence")
	if err != nil {
		return OwnerCheckpointReservePlan{}, err
	}
	grantedSnapshotSequence, err := ownerReserveAddSequence(
		committed.SnapshotSequence, 2, "GRANTED Owner-state snapshot sequence")
	if err != nil {
		return OwnerCheckpointReservePlan{}, err
	}
	nextAllocationRecordID, err := ownerReserveAddSequence(
		committed.NextAllocationRecordID, 1, "next allocation-record ID")
	if err != nil {
		return OwnerCheckpointReservePlan{}, err
	}
	preparingNextTransaction, err := ownerReserveAddSequence(
		committed.NextOwnerTransactionSequence, 1, "post-PREPARING Owner transaction")
	if err != nil {
		return OwnerCheckpointReservePlan{}, err
	}
	grantedTransaction, err := ownerReserveAddSequence(
		committed.NextOwnerTransactionSequence, 1, "GRANTED Owner transaction")
	if err != nil {
		return OwnerCheckpointReservePlan{}, err
	}
	grantedNextTransaction, err := ownerReserveAddSequence(
		committed.NextOwnerTransactionSequence, 2, "post-GRANTED Owner transaction")
	if err != nil {
		return OwnerCheckpointReservePlan{}, err
	}

	updates, targetSequences, err := ownerReserveAllocatorUpdates(
		devices, placedRuns, committed.NextOwnerTransactionSequence)
	if err != nil {
		return OwnerCheckpointReservePlan{}, err
	}
	fragments, err := ownerReserveFragments(devices, placedRuns, targetSequences)
	if err != nil {
		return OwnerCheckpointReservePlan{}, err
	}
	preparingRecord := ownerReserveRecord(
		request,
		requestSHA256,
		totalDemandPages,
		committed.NextAllocationRecordID,
		committed.NextOwnerTransactionSequence,
		OwnerAllocationPreparing,
		fragments)
	preparing, err := ownerReserveAppendRecordSnapshot(
		committed,
		preparingRecord,
		preparingSnapshotSequence,
		nextAllocationRecordID,
		preparingNextTransaction,
		anchorGeometry)
	if err != nil {
		return OwnerCheckpointReservePlan{}, err
	}

	grantedRecord := cloneOwnerStateRecord(preparingRecord)
	grantedRecord.State = OwnerAllocationGranted
	grantedRecord.OwnerTransactionSequence = grantedTransaction
	granted, err := ownerReserveReplaceLastRecordSnapshot(
		preparing,
		grantedRecord,
		grantedSnapshotSequence,
		nextAllocationRecordID,
		grantedNextTransaction,
		anchorGeometry)
	if err != nil {
		return OwnerCheckpointReservePlan{}, err
	}
	descriptors, err := ownerReserveDescriptorRuns(
		request.ContentDemands,
		placedRuns,
		preparingRecord.AllocationRecordID,
		preparingRecord.OwnerTransactionSequence)
	if err != nil {
		return OwnerCheckpointReservePlan{}, err
	}

	return OwnerCheckpointReservePlan{
		Outcome:             OwnerReservePlanned,
		RequestSHA256:       requestSHA256,
		Record:              grantedRecord,
		PreparingOwnerState: preparing,
		AllocatorUpdates:    updates,
		ReservedDescriptors: descriptors,
		GrantedOwnerState:   granted,
	}, nil
}

func buildOwnerReserveNoSpacePlan(
	committed OwnerStateSnapshot,
	anchorGeometry DeviceGeometry,
	request OwnerReserveRequest,
	requestSHA256 [sha256.Size]byte,
	totalDemandPages uint64,
) (OwnerCheckpointReservePlan, error) {
	rejectedSnapshotSequence, err := ownerReserveAddSequence(
		committed.SnapshotSequence, 1, "REJECTED_NO_SPACE Owner-state snapshot sequence")
	if err != nil {
		return OwnerCheckpointReservePlan{}, err
	}
	nextAllocationRecordID, err := ownerReserveAddSequence(
		committed.NextAllocationRecordID, 1, "next allocation-record ID")
	if err != nil {
		return OwnerCheckpointReservePlan{}, err
	}
	nextTransaction, err := ownerReserveAddSequence(
		committed.NextOwnerTransactionSequence, 1, "post-rejection Owner transaction")
	if err != nil {
		return OwnerCheckpointReservePlan{}, err
	}
	record := ownerReserveRecord(
		request,
		requestSHA256,
		totalDemandPages,
		committed.NextAllocationRecordID,
		committed.NextOwnerTransactionSequence,
		OwnerAllocationRejectedNoSpace,
		nil)
	rejected, err := ownerReserveAppendRecordSnapshot(
		committed,
		record,
		rejectedSnapshotSequence,
		nextAllocationRecordID,
		nextTransaction,
		anchorGeometry)
	if err != nil {
		return OwnerCheckpointReservePlan{}, err
	}
	return OwnerCheckpointReservePlan{
		Outcome:            OwnerReserveRejectedNoSpace,
		RequestSHA256:      requestSHA256,
		Record:             record,
		RejectedOwnerState: rejected,
	}, nil
}

func ownerReserveAllocatorUpdates(
	devices []ownerAllocatorDevice,
	placedRuns []ownerAllocatorPlacedRun,
	preparingTransaction uint64,
) ([]OwnerAllocatorSnapshotUpdate, map[string]uint64, error) {
	runsByDevice := make(map[string][]ownerAllocatorPlacedRun)
	for _, run := range placedRuns {
		runsByDevice[run.DeviceUUID] = append(runsByDevice[run.DeviceUUID], run)
	}
	updates := make([]OwnerAllocatorSnapshotUpdate, 0, len(runsByDevice))
	targetSequences := make(map[string]uint64, len(runsByDevice))
	for _, device := range devices {
		runs := runsByDevice[device.member.DeviceUUID]
		if len(runs) == 0 {
			continue
		}
		nextSequence, err := ownerReserveAddSequence(
			device.snapshot.SnapshotSequence,
			1,
			fmt.Sprintf("device %q allocator snapshot sequence", device.member.DeviceUUID))
		if err != nil {
			return nil, nil, err
		}
		bitmap := device.snapshot.BitmapBytes()
		for _, run := range runs {
			end, ok := checkedAdd(run.StartDataPageIndex, run.PageCount)
			if !ok || end > device.snapshot.DataPageCount {
				return nil, nil, ownerAllocatorInputMismatchf(
					"planned run exceeds device %q", device.member.DeviceUUID)
			}
			for page := run.StartDataPageIndex; page < end; page++ {
				if ownerAllocatorBitmapSet(bitmap, page) {
					return nil, nil, ownerAllocatorInputMismatchf(
						"planned page %d on device %q was already unavailable",
						page, device.member.DeviceUUID)
				}
				ownerAllocatorSetBitmap(bitmap, page)
			}
		}
		desired, err := NewAllocatorSnapshot(AllocatorSnapshotConfig{
			DeviceBindingSHA256:             device.snapshot.DeviceBindingSHA256,
			OwnerGroupIdentitySHA256:        device.snapshot.OwnerGroupIdentitySHA256,
			OwnerEpoch:                      device.snapshot.OwnerEpoch,
			SnapshotSequence:                nextSequence,
			AppliedOwnerTransactionSequence: preparingTransaction,
			DataPageCount:                   device.snapshot.DataPageCount,
		}, bitmap)
		if err != nil {
			return nil, nil, err
		}
		if _, err := CanonicalAllocatorSnapshotBytes(desired, device.geometry); err != nil {
			return nil, nil, err
		}
		updates = append(updates, OwnerAllocatorSnapshotUpdate{
			DeviceUUID:               device.member.DeviceUUID,
			PreviousSnapshotSequence: device.snapshot.SnapshotSequence,
			DesiredSnapshot:          desired,
		})
		targetSequences[device.member.DeviceUUID] = nextSequence
	}
	return updates, targetSequences, nil
}

func ownerReserveFragments(
	devices []ownerAllocatorDevice,
	placedRuns []ownerAllocatorPlacedRun,
	targetSequences map[string]uint64,
) ([]OwnerStateDeviceFragment, error) {
	deviceByUUID := make(map[string]OwnerStateDevice, len(devices))
	for _, device := range devices {
		deviceByUUID[device.member.DeviceUUID] = device.member
	}
	extentsByDevice := make(map[string][]OwnerStateExtent)
	for _, run := range placedRuns {
		extentsByDevice[run.DeviceUUID] = append(
			extentsByDevice[run.DeviceUUID],
			OwnerStateExtent{
				StartDataPageIndex: run.StartDataPageIndex,
				LogicalPageStart:   run.LogicalPageStart,
				PageCount:          run.PageCount,
			})
	}
	uuids := make([]string, 0, len(extentsByDevice))
	for uuid := range extentsByDevice {
		uuids = append(uuids, uuid)
	}
	sort.Strings(uuids)
	fragments := make([]OwnerStateDeviceFragment, 0, len(uuids))
	for _, uuid := range uuids {
		member, exists := deviceByUUID[uuid]
		sequence, sequenceExists := targetSequences[uuid]
		if !exists || !sequenceExists {
			return nil, ownerAllocatorInputMismatchf(
				"planned fragment device %q has no validated target", uuid)
		}
		fragments = append(fragments, OwnerStateDeviceFragment{
			DeviceUUID:                      uuid,
			DeviceOwnerEpoch:                member.DeviceOwnerEpoch,
			TargetAllocatorSnapshotSequence: sequence,
			Extents:                         extentsByDevice[uuid],
		})
	}
	return fragments, nil
}

func ownerReserveDescriptorRuns(
	demands []OwnerStateContentDemand,
	placedRuns []ownerAllocatorPlacedRun,
	allocationRecordID uint64,
	ownerTransactionSequence uint64,
) ([]OwnerReservedDescriptorRun, error) {
	result := make([]OwnerReservedDescriptorRun, 0, len(placedRuns)+len(demands)-1)
	demandIndex := 0
	for _, placed := range placedRuns {
		physical := placed.StartDataPageIndex
		logical := placed.LogicalPageStart
		remaining := placed.PageCount
		for remaining > 0 {
			for demandIndex < len(demands) {
				demandEnd := demands[demandIndex].LogicalPageStart + demands[demandIndex].CapacityPages
				if logical < demandEnd {
					break
				}
				demandIndex++
			}
			if demandIndex >= len(demands) || logical < demands[demandIndex].LogicalPageStart {
				return nil, ownerReserveInvalidf("descriptor planning encountered a logical demand gap")
			}
			demand := demands[demandIndex]
			demandEnd := demand.LogicalPageStart + demand.CapacityPages
			count := demandEnd - logical
			if count > remaining {
				count = remaining
			}
			descriptor := Descriptor{
				AllocationRecordID:  allocationRecordID,
				OriginObjectID:      demand.ObjectID,
				OwnerTransactionSeq: ownerTransactionSequence,
				State:               DescriptorReserved,
				ContentKind:         demand.Kind,
			}
			if err := descriptor.Validate(); err != nil {
				return nil, err
			}
			run := OwnerReservedDescriptorRun{
				DeviceUUID:         placed.DeviceUUID,
				StartDataPageIndex: physical,
				LogicalPageStart:   logical,
				ObjectPageStart:    logical - demand.LogicalPageStart,
				PageCount:          count,
				Descriptor:         descriptor,
			}
			result = ownerReserveAppendDescriptorRun(result, run)
			physical += count
			logical += count
			remaining -= count
		}
	}
	return result, nil
}

func ownerReserveAppendDescriptorRun(
	runs []OwnerReservedDescriptorRun,
	candidate OwnerReservedDescriptorRun,
) []OwnerReservedDescriptorRun {
	if len(runs) == 0 {
		return append(runs, candidate)
	}
	last := &runs[len(runs)-1]
	if last.DeviceUUID == candidate.DeviceUUID &&
		last.Descriptor == candidate.Descriptor &&
		last.StartDataPageIndex+last.PageCount == candidate.StartDataPageIndex &&
		last.LogicalPageStart+last.PageCount == candidate.LogicalPageStart &&
		last.ObjectPageStart+last.PageCount == candidate.ObjectPageStart {
		last.PageCount += candidate.PageCount
		return runs
	}
	return append(runs, candidate)
}

func ownerReserveRecord(
	request OwnerReserveRequest,
	requestSHA256 [sha256.Size]byte,
	totalDemandPages uint64,
	allocationRecordID uint64,
	transactionSequence uint64,
	state OwnerAllocationState,
	fragments []OwnerStateDeviceFragment,
) OwnerStateAllocationRecord {
	return OwnerStateAllocationRecord{
		AllocationRecordID:       allocationRecordID,
		OwnerTransactionSequence: transactionSequence,
		State:                    state,
		RequestID:                request.RequestID,
		CheckpointID:             request.CheckpointID,
		ProducerID:               request.ProducerID,
		DedupDomainID:            request.DedupDomainID,
		SharingPolicyID:          request.SharingPolicyID,
		RequestSHA256:            requestSHA256,
		TotalDemandPages:         totalDemandPages,
		MaxExtents:               request.MaxExtents,
		ContentDemands:           append([]OwnerStateContentDemand(nil), request.ContentDemands...),
		Fragments:                fragments,
		AuthorityEvidence:        request.AuthorityEvidence,
	}
}

func ownerReserveAppendRecordSnapshot(
	base OwnerStateSnapshot,
	record OwnerStateAllocationRecord,
	snapshotSequence uint64,
	nextAllocationRecordID uint64,
	nextTransactionSequence uint64,
	anchorGeometry DeviceGeometry,
) (OwnerStateSnapshot, error) {
	records := base.Records()
	records = append(records, cloneOwnerStateRecord(record))
	return ownerReserveNewSnapshot(
		base,
		records,
		snapshotSequence,
		nextAllocationRecordID,
		nextTransactionSequence,
		anchorGeometry)
}

func ownerReserveReplaceLastRecordSnapshot(
	base OwnerStateSnapshot,
	record OwnerStateAllocationRecord,
	snapshotSequence uint64,
	nextAllocationRecordID uint64,
	nextTransactionSequence uint64,
	anchorGeometry DeviceGeometry,
) (OwnerStateSnapshot, error) {
	records := base.Records()
	if len(records) == 0 || records[len(records)-1].AllocationRecordID != record.AllocationRecordID {
		return OwnerStateSnapshot{}, ownerAllocatorInputMismatchf(
			"cannot replace missing allocation record %d", record.AllocationRecordID)
	}
	records[len(records)-1] = cloneOwnerStateRecord(record)
	return ownerReserveNewSnapshot(
		base,
		records,
		snapshotSequence,
		nextAllocationRecordID,
		nextTransactionSequence,
		anchorGeometry)
}

func ownerReserveNewSnapshot(
	base OwnerStateSnapshot,
	records []OwnerStateAllocationRecord,
	snapshotSequence uint64,
	nextAllocationRecordID uint64,
	nextTransactionSequence uint64,
	anchorGeometry DeviceGeometry,
) (OwnerStateSnapshot, error) {
	snapshot, err := NewOwnerStateSnapshot(OwnerStateConfig{
		ClusterID:                    base.ClusterID,
		OwnerGroupID:                 base.OwnerGroupID,
		CurrentOwnerID:               base.CurrentOwnerID,
		AnchorDeviceUUID:             base.AnchorDeviceUUID,
		StorageCompatibilityID:       base.StorageCompatibilityID,
		OwnerEpoch:                   base.OwnerEpoch,
		GroupConfigurationSequence:   base.GroupConfigurationSequence,
		MembershipSHA256:             base.MembershipSHA256,
		SnapshotSequence:             snapshotSequence,
		NextAllocationRecordID:       nextAllocationRecordID,
		NextOwnerTransactionSequence: nextTransactionSequence,
		Devices:                      base.Devices(),
		Records:                      records,
	})
	if err != nil {
		return OwnerStateSnapshot{}, err
	}
	if _, err := CanonicalOwnerStateBytes(snapshot, anchorGeometry); err != nil {
		return OwnerStateSnapshot{}, err
	}
	return snapshot, nil
}

func ownerReserveReplay(
	committed OwnerStateSnapshot,
	request OwnerReserveRequest,
	requestSHA256 [sha256.Size]byte,
	totalDemandPages uint64,
) (OwnerStateAllocationRecord, bool, error) {
	records := committed.Records()
	requestIndex := -1
	checkpointIndex := -1
	for index := range records {
		if records[index].RequestID == request.RequestID {
			requestIndex = index
		}
		if records[index].CheckpointID == request.CheckpointID {
			checkpointIndex = index
		}
	}
	if requestIndex < 0 && checkpointIndex < 0 {
		return OwnerStateAllocationRecord{}, false, nil
	}
	if requestIndex < 0 || checkpointIndex < 0 || requestIndex != checkpointIndex {
		return OwnerStateAllocationRecord{}, false, ownerReserveConflictf(
			"request ID %q and checkpoint ID %q do not identify the same record",
			request.RequestID,
			request.CheckpointID)
	}
	record := records[requestIndex]
	if record.RequestSHA256 != requestSHA256 ||
		record.RequestID != request.RequestID ||
		record.CheckpointID != request.CheckpointID ||
		record.ProducerID != request.ProducerID ||
		record.DedupDomainID != request.DedupDomainID ||
		record.SharingPolicyID != request.SharingPolicyID ||
		record.TotalDemandPages != totalDemandPages ||
		record.MaxExtents != request.MaxExtents ||
		record.AuthorityEvidence != request.AuthorityEvidence ||
		!ownerReserveEqualContentDemands(record.ContentDemands, request.ContentDemands) {
		return OwnerStateAllocationRecord{}, false, ownerReserveConflictf(
			"existing allocation record %d is not an exact request replay",
			record.AllocationRecordID)
	}
	return record, true, nil
}

func ownerReserveEqualContentDemands(left, right []OwnerStateContentDemand) bool {
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

func ownerAllocatorRunBetter(left, right ownerAllocatorFreeRun) bool {
	if left.PageCount != right.PageCount {
		return left.PageCount > right.PageCount
	}
	if left.DeviceUUID != right.DeviceUUID {
		return left.DeviceUUID < right.DeviceUUID
	}
	return left.StartDataPageIndex < right.StartDataPageIndex
}

func ownerAllocatorRunWorse(left, right ownerAllocatorFreeRun) bool {
	if left.PageCount != right.PageCount {
		return left.PageCount < right.PageCount
	}
	if left.DeviceUUID != right.DeviceUUID {
		return left.DeviceUUID > right.DeviceUUID
	}
	return left.StartDataPageIndex > right.StartDataPageIndex
}

func ownerAllocatorSingleFitBetter(left, right ownerAllocatorFreeRun) bool {
	if left.PageCount != right.PageCount {
		return left.PageCount < right.PageCount
	}
	if left.DeviceUUID != right.DeviceUUID {
		return left.DeviceUUID < right.DeviceUUID
	}
	return left.StartDataPageIndex < right.StartDataPageIndex
}

func ownerAllocatorBitmapSet(bitmap []byte, page uint64) bool {
	return bitmap[page/8]&(byte(1)<<uint(page%8)) != 0
}

func ownerAllocatorSetBitmap(bitmap []byte, page uint64) {
	bitmap[page/8] |= byte(1) << uint(page%8)
}

func ownerReserveAddSequence(value, increment uint64, name string) (uint64, error) {
	if value > cxlcheckpoint.MaxSignedLong ||
		increment > cxlcheckpoint.MaxSignedLong-value {
		return 0, fmt.Errorf(
			"%w: %s %d + %d exceeds %d",
			ErrOwnerReserveSequenceOverflow,
			name,
			value,
			increment,
			cxlcheckpoint.MaxSignedLong)
	}
	return value + increment, nil
}

func ownerReserveDigestUint64(digest interface{ Write([]byte) (int, error) }, value uint64) {
	var encoded [8]byte
	binary.LittleEndian.PutUint64(encoded[:], value)
	_, _ = digest.Write(encoded[:])
}

func ownerReserveDigestUint32(digest interface{ Write([]byte) (int, error) }, value uint32) {
	var encoded [4]byte
	binary.LittleEndian.PutUint32(encoded[:], value)
	_, _ = digest.Write(encoded[:])
}

func ownerReserveInvalidf(format string, arguments ...interface{}) error {
	return fmt.Errorf("%w: %s", ErrInvalidOwnerReserveRequest, fmt.Sprintf(format, arguments...))
}

func ownerAllocatorInputMismatchf(format string, arguments ...interface{}) error {
	return fmt.Errorf("%w: %s", ErrOwnerAllocatorInputMismatch, fmt.Sprintf(format, arguments...))
}

func ownerReserveConflictf(format string, arguments ...interface{}) error {
	return fmt.Errorf("%w: %s", ErrOwnerReserveConflict, fmt.Sprintf(format, arguments...))
}

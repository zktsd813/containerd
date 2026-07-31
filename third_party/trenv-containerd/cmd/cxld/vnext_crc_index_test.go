package main

import (
	"bytes"
	"errors"
	"hash/crc32"
	"reflect"
	"testing"

	"github.com/containerd/containerd/third_party/trenv-containerd/pkg/cxlcheckpoint"
)

func commitVNextCRCCheckpoint(
	t *testing.T,
	group *vnextOwnerGroup,
	id string,
	objectID uint64,
	kind vnextContentKind,
	pages [][]byte,
) vnextOwnerWriteGrant {
	t.Helper()
	if len(pages) == 0 {
		t.Fatal("CRC test checkpoint requires at least one page")
	}
	var byteLength uint64
	for index, page := range pages {
		if len(page) == 0 || uint64(len(page)) > vnextContentPageSize {
			t.Fatalf("CRC test page %d has invalid length %d", index, len(page))
		}
		if index != len(pages)-1 && uint64(len(page)) != vnextContentPageSize {
			t.Fatalf("CRC test non-tail page %d is short", index)
		}
		byteLength += uint64(len(page))
	}
	request := vnextCheckpointAllocationRequest{
		RequestID:    "crc-request-" + id,
		CheckpointID: "crc-checkpoint-" + id,
		ProducerID:   "crc-producer-" + id,
		OwnerID:      group.ownerID,
		OwnerEpoch:   group.ownerEpoch,
		Contents: []vnextContentRequest{{
			Kind:       kind,
			ObjectID:   objectID,
			ByteLength: byteLength,
		}},
		MaxExtents: 32,
	}
	grant, err := group.reserve(request)
	if err != nil {
		t.Fatalf("reserve CRC checkpoint %q: %v", id, err)
	}
	for logicalPage, content := range pages {
		if err := group.writePage(grant, uint64(logicalPage), content); err != nil {
			t.Fatalf("write CRC checkpoint %q page %d: %v", id, logicalPage, err)
		}
	}
	if err := group.commit(grant); err != nil {
		t.Fatalf("commit CRC checkpoint %q: %v", id, err)
	}
	return grant
}

func reserveVNextCRCCheckpoint(
	t *testing.T,
	group *vnextOwnerGroup,
	id string,
	objectID uint64,
	content []byte,
) vnextOwnerWriteGrant {
	t.Helper()
	request := vnextCheckpointAllocationRequest{
		RequestID:    "crc-request-" + id,
		CheckpointID: "crc-checkpoint-" + id,
		ProducerID:   "crc-producer-" + id,
		OwnerID:      group.ownerID,
		OwnerEpoch:   group.ownerEpoch,
		Contents: []vnextContentRequest{{
			Kind:       vnextContentMemory,
			ObjectID:   objectID,
			ByteLength: vnextContentPageSize,
		}},
		MaxExtents: 1,
	}
	grant, err := group.reserve(request)
	if err != nil {
		t.Fatalf("reserve uncommitted CRC checkpoint %q: %v", id, err)
	}
	if err := group.writePage(grant, 0, content); err != nil {
		t.Fatalf("write uncommitted CRC checkpoint %q: %v", id, err)
	}
	return grant
}

func findVNextCandidateByAllocation(
	t *testing.T,
	result vnextCRCCandidatePageResult,
	allocationRecordID uint64,
) cxlcheckpoint.PageID {
	t.Helper()
	for _, candidate := range result.Pages {
		if candidate.PageID.AllocationRecordID == allocationRecordID {
			return candidate.PageID
		}
	}
	t.Fatalf("candidate result has no allocation %d: %#v", allocationRecordID, result.Pages)
	return cxlcheckpoint.PageID{}
}

// vnextCRC32CCollisionPages constructs a deterministic non-zero element of
// the CRC linear kernel. Thirty-three independent input bits map into a
// 32-bit result, so Gaussian elimination must find a non-empty combination
// whose CRC influence is zero. This proves that exact comparison is required
// without relying on a probabilistic birthday search.
func vnextCRC32CCollisionPages(t *testing.T) ([vnextContentPageSize]byte, [vnextContentPageSize]byte) {
	t.Helper()
	var first [vnextContentPageSize]byte
	baseCRC := crc32.Checksum(first[:], vnextCRCTable)
	type crcBasis struct {
		value       uint32
		combination uint64
	}
	var basis [32]crcBasis
	var dependency uint64
	for inputBit := uint(0); inputBit < 33; inputBit++ {
		var probe [vnextContentPageSize]byte
		probe[inputBit/8] ^= byte(1 << (inputBit % 8))
		value := crc32.Checksum(probe[:], vnextCRCTable) ^ baseCRC
		combination := uint64(1) << inputBit
		inserted := false
		for outputBit := 31; outputBit >= 0; outputBit-- {
			mask := uint32(1) << uint(outputBit)
			if value&mask == 0 {
				continue
			}
			if basis[outputBit].value == 0 {
				basis[outputBit] = crcBasis{value: value, combination: combination}
				inserted = true
				break
			}
			value ^= basis[outputBit].value
			combination ^= basis[outputBit].combination
		}
		if !inserted {
			if value != 0 || combination == 0 {
				t.Fatalf("invalid CRC dependency value=%#x combination=%#x", value, combination)
			}
			dependency = combination
			break
		}
	}
	if dependency == 0 {
		t.Fatal("33 CRC input vectors unexpectedly had full rank")
	}
	second := first
	for inputBit := uint(0); inputBit < 33; inputBit++ {
		if dependency&(uint64(1)<<inputBit) != 0 {
			second[inputBit/8] ^= byte(1 << (inputBit % 8))
		}
	}
	if first == second {
		t.Fatal("constructed CRC collision uses identical pages")
	}
	if got := crc32.Checksum(second[:], vnextCRCTable); got != baseCRC {
		t.Fatalf("constructed page CRC is %#x, expected collision at %#x", got, baseCRC)
	}
	return first, second
}

func TestVNextOwnerCRCIndexCoalescesCountsAndRequiresExactComparison(t *testing.T) {
	fixture := newVNextOwnerTestFixture(t, []vnextOwnerTestDeviceSpec{
		{UUID: "crc-device", Size: 384 << 10},
	})
	first, collision := vnextCRC32CCollisionPages(t)
	contentCRC := crc32.Checksum(first[:], vnextCRCTable)

	firstGrant := commitVNextCRCCheckpoint(
		t, fixture.group, "first", 1001, vnextContentMemory, [][]byte{first[:]})
	collisionGrant := commitVNextCRCCheckpoint(
		t, fixture.group, "collision", 1002, vnextContentMemory, [][]byte{collision[:]})
	artifactGrant := commitVNextCRCCheckpoint(
		t, fixture.group, "artifact", 1003, vnextContentArtifact, [][]byte{first[:]})
	commitVNextCRCCheckpoint(
		t, fixture.group, "page-map-control", 1004, vnextContentPageMap, [][]byte{first[:]})
	reservedGrant := reserveVNextCRCCheckpoint(
		t, fixture.group, "not-committed", 1005, first[:])
	t.Cleanup(func() { _ = fixture.group.abort(reservedGrant) })

	index, err := fixture.group.buildCRCIndex(41)
	if err != nil {
		t.Fatalf("build Owner CRC index: %v", err)
	}
	if index.ContractID != vnextCRCContractID ||
		index.Statistics.CommittedAllocations != 4 ||
		index.Statistics.DescriptorReads != 4 ||
		index.Statistics.DescriptorBytes != 4*vnextPageDescriptorSize ||
		index.Statistics.IndexedPayloadPages != 3 ||
		index.Statistics.SkippedControlPages != 1 ||
		index.Statistics.DistinctCRCValues != 1 {
		t.Fatalf("unexpected CRC index identity/statistics: %#v", index)
	}

	summary, err := index.summary(vnextCRCSummaryRequest{
		Limit:             1,
		MinimumLocalPages: 1,
	})
	if err != nil {
		t.Fatalf("summarize Owner CRC index: %v", err)
	}
	if len(summary.Groups) != 1 ||
		summary.Groups[0].ContentCRC32C != contentCRC ||
		summary.Groups[0].LocalPageCount != 3 ||
		summary.NextAfterCRC32C != nil {
		t.Fatalf("unexpected coalesced CRC summary: %#v", summary)
	}

	firstCandidates, err := index.candidates(contentCRC, 0, 2)
	if err != nil {
		t.Fatalf("get first CRC candidate page: %v", err)
	}
	if firstCandidates.TotalLocalPages != 3 || len(firstCandidates.Pages) != 2 ||
		!firstCandidates.More || firstCandidates.NextOffset != 2 {
		t.Fatalf("unexpected first candidate page: %#v", firstCandidates)
	}
	lastCandidates, err := index.candidates(contentCRC, firstCandidates.NextOffset, 2)
	if err != nil {
		t.Fatalf("get last CRC candidate page: %v", err)
	}
	allCandidates := firstCandidates
	allCandidates.Pages = append(allCandidates.Pages, lastCandidates.Pages...)
	if len(allCandidates.Pages) != 3 || lastCandidates.More {
		t.Fatalf("unexpected complete candidate list: %#v / %#v", firstCandidates, lastCandidates)
	}

	firstID := findVNextCandidateByAllocation(t, allCandidates, firstGrant.AllocationRecordID)
	collisionID := findVNextCandidateByAllocation(t, allCandidates, collisionGrant.AllocationRecordID)
	artifactID := findVNextCandidateByAllocation(t, allCandidates, artifactGrant.AllocationRecordID)

	collisionResult, err := fixture.group.exactCRCMatch(index, contentCRC, firstID, collisionID)
	if err != nil {
		t.Fatalf("exactly compare CRC collision: %v", err)
	}
	if collisionResult.Equal ||
		collisionResult.PayloadReads != 2 ||
		collisionResult.PayloadBytes != 2*vnextContentPageSize ||
		collisionResult.ComparedBytes != vnextContentPageSize {
		t.Fatalf("CRC collision was treated as equal: %#v", collisionResult)
	}

	crossKindResult, err := fixture.group.exactCRCMatch(index, contentCRC, firstID, artifactID)
	if err != nil {
		t.Fatalf("exactly compare memory/artifact duplicate: %v", err)
	}
	if !crossKindResult.Equal {
		t.Fatal("identical memory and artifact pages were not equal")
	}
	verifiedArtifact, err := fixture.group.readVerifiedCRCPage(index, contentCRC, artifactID)
	if err != nil {
		t.Fatalf("read verified artifact candidate: %v", err)
	}
	if verifiedArtifact.ContentKind != vnextContentArtifact ||
		!bytes.Equal(verifiedArtifact.Content[:], first[:]) {
		t.Fatalf("unexpected verified artifact candidate: %#v", verifiedArtifact)
	}
}

func TestVNextOwnerCRCIndexPaginatesSingletonsAndRebuildsAfterRestart(t *testing.T) {
	fixture := newVNextOwnerTestFixture(t, []vnextOwnerTestDeviceSpec{
		{UUID: "crc-restart", Size: 384 << 10},
	})
	for index, fill := range []byte{0x11, 0x22, 0x33} {
		page := bytes.Repeat([]byte{fill}, int(vnextContentPageSize))
		commitVNextCRCCheckpoint(
			t,
			fixture.group,
			string(rune('a'+index)),
			2000+uint64(index),
			vnextContentMemory,
			[][]byte{page})
	}
	before, err := fixture.group.buildCRCIndex(52)
	if err != nil {
		t.Fatalf("build pre-restart CRC index: %v", err)
	}
	first, err := before.summary(vnextCRCSummaryRequest{
		Limit:             2,
		MinimumLocalPages: 1,
	})
	if err != nil {
		t.Fatalf("get first singleton summary page: %v", err)
	}
	if len(first.Groups) != 2 || first.NextAfterCRC32C == nil {
		t.Fatalf("unexpected first singleton summary page: %#v", first)
	}
	second, err := before.summary(vnextCRCSummaryRequest{
		AfterCRC32C:       first.NextAfterCRC32C,
		Limit:             2,
		MinimumLocalPages: 1,
	})
	if err != nil {
		t.Fatalf("get second singleton summary page: %v", err)
	}
	if len(second.Groups) != 1 || second.NextAfterCRC32C != nil {
		t.Fatalf("unexpected second singleton summary page: %#v", second)
	}
	duplicatesOnly, err := before.summary(vnextCRCSummaryRequest{
		Limit:             2,
		MinimumLocalPages: 2,
	})
	if err != nil {
		t.Fatalf("summarize local duplicates: %v", err)
	}
	if len(duplicatesOnly.Groups) != 0 {
		t.Fatalf("singleton groups passed minimum-two filter: %#v", duplicatesOnly.Groups)
	}

	fixture.reopen(t)
	after, err := fixture.group.buildCRCIndex(52)
	if err != nil {
		t.Fatalf("rebuild post-restart CRC index: %v", err)
	}
	if before.ContractID != after.ContractID ||
		before.OwnerID != after.OwnerID ||
		before.OwnerEpoch != after.OwnerEpoch ||
		before.DedupEpoch != after.DedupEpoch ||
		!reflect.DeepEqual(before.Groups, after.Groups) ||
		before.Statistics != after.Statistics {
		t.Fatalf("CRC index changed across restart:\nbefore=%#v\nafter=%#v", before, after)
	}

	if _, err := before.summary(vnextCRCSummaryRequest{
		Limit: 1,
	}); !errors.Is(err, errVNextCRCIndexQuery) {
		t.Fatalf("zero minimum-local-pages returned %v", err)
	}
	if _, err := before.candidates(first.Groups[0].ContentCRC32C, 0, 0); !errors.Is(err, errVNextCRCIndexQuery) {
		t.Fatalf("zero candidate limit returned %v", err)
	}
}

func TestVNextOwnerCRCIndexRejectsCandidateAfterCheckpointReclaim(t *testing.T) {
	fixture := newVNextOwnerTestFixture(t, []vnextOwnerTestDeviceSpec{
		{UUID: "crc-reclaim", Size: 256 << 10},
	})
	content := bytes.Repeat([]byte{0x7a}, int(vnextContentPageSize))
	grant := commitVNextCRCCheckpoint(
		t, fixture.group, "reclaim", 3001, vnextContentMemory, [][]byte{content})
	contentCRC := crc32.Checksum(content, vnextCRCTable)
	index, err := fixture.group.buildCRCIndex(63)
	if err != nil {
		t.Fatalf("build reclaim CRC index: %v", err)
	}
	candidates, err := index.candidates(contentCRC, 0, 1)
	if err != nil || len(candidates.Pages) != 1 {
		t.Fatalf("get reclaim candidate: %#v / %v", candidates, err)
	}
	if err := fixture.group.reclaimCheckpoint(
		grant.CheckpointID, grant.AllocationRecordID); err != nil {
		t.Fatalf("reclaim indexed checkpoint: %v", err)
	}
	if _, err := fixture.group.readVerifiedCRCPage(
		index, contentCRC, candidates.Pages[0].PageID); !errors.Is(err, errVNextCRCIndexStale) {
		t.Fatalf("stale CRC candidate returned %v", err)
	}
}

func TestVNextOwnerCRCIndexScansOneAllocationAcrossMultipleDAXDevices(t *testing.T) {
	fixture := newVNextOwnerTestFixture(t, []vnextOwnerTestDeviceSpec{
		{UUID: "crc-multi-a", Size: 80 << 10},
		{UUID: "crc-multi-b", Size: 80 << 10},
	})
	firstCapacity := fixture.devices[0].superblock.Geometry.DataPageCount
	pageCount := firstCapacity + 1
	content := bytes.Repeat([]byte{0x5c}, int(vnextContentPageSize))
	pages := make([][]byte, pageCount)
	for index := range pages {
		pages[index] = content
	}
	grant := commitVNextCRCCheckpoint(
		t, fixture.group, "multi-dax", 4001, vnextContentMemory, pages)
	devices := make(map[string]struct{})
	for _, extent := range grant.Extents {
		devices[extent.DeviceUUID] = struct{}{}
	}
	if len(devices) != 2 {
		t.Fatalf("test allocation did not span both DAX devices: %#v", grant.Extents)
	}

	index, err := fixture.group.buildCRCIndex(74)
	if err != nil {
		t.Fatalf("build multi-DAX CRC index: %v", err)
	}
	contentCRC := crc32.Checksum(content, vnextCRCTable)
	if index.Statistics.DescriptorReads != pageCount ||
		index.Statistics.IndexedPayloadPages != pageCount ||
		uint64(len(index.Groups[contentCRC])) != pageCount {
		t.Fatalf("multi-DAX CRC scan missed pages: %#v", index.Statistics)
	}
	groupDevices := make(map[string]struct{})
	for _, local := range index.Groups[contentCRC] {
		groupDevices[local.DeviceUUID] = struct{}{}
	}
	if len(groupDevices) != 2 {
		t.Fatalf("CRC group did not preserve both device UUIDs: %#v", index.Groups[contentCRC])
	}
}

package main

import (
	"bytes"
	"errors"
	"fmt"
	"sort"

	"github.com/containerd/containerd/third_party/trenv-containerd/pkg/cxlcheckpoint"
)

// vnextCRCContractID names both the polynomial and the exact byte domain.
// Changing any part of this contract requires a new identifier; values from
// different contracts must never be coalesced into one deduplication epoch.
const vnextCRCContractID = "trenv-v6-crc32c-castagnoli-4096-zero-padded"

const vnextMaxCRCResponseEntries uint32 = 4096

var (
	errVNextCRCIndexStale = errors.New("VNext Owner CRC observation is stale")
	errVNextCRCIndexQuery = errors.New("invalid VNext Owner CRC query")
)

// vnextLocalCRCPage is deliberately small and Owner-local. OwnerID and
// OwnerEpoch are stored once in vnextOwnerCRCIndex rather than repeated for
// every indexed page. The portable PageID is materialized only when a
// candidate is requested.
type vnextLocalCRCPage struct {
	DeviceUUID         string
	AllocationRecordID uint64
	DataPageIndex      uint64
}

// vnextOwnerCRCIndex is an immutable DRAM observation rebuilt by an Owner for
// a Scheduler-selected periodic deduplication epoch. It is not persistent CXL
// metadata and it never changes allocation, reference counts, or PageMaps.
//
// The CXL read cost of building the index is one 64-byte descriptor per page
// in a committed Owner allocation. It does not read 4 KiB payloads. Payloads
// are read only for the small set of candidates selected after summaries from
// all Owners have been coalesced.
type vnextOwnerCRCIndex struct {
	ContractID           string
	OwnerID              string
	OwnerEpoch           uint64
	DedupEpoch           uint64
	OwnerJournalSequence uint64
	Groups               map[uint32][]vnextLocalCRCPage
	Statistics           vnextCRCIndexStatistics
}

type vnextCRCIndexStatistics struct {
	CommittedAllocations uint64
	DescriptorReads      uint64
	DescriptorBytes      uint64
	IndexedPayloadPages  uint64
	SkippedControlPages  uint64
	DistinctCRCValues    uint64
}

// vnextCRCGroupCount is the first, low-bandwidth Owner response. It carries no
// PageID. The Scheduler first sums these counts by CRC across Owners and asks
// for concrete candidates only for CRC values whose global count can dedup.
type vnextCRCGroupCount struct {
	ContentCRC32C  uint32
	LocalPageCount uint64
}

type vnextCRCSummaryRequest struct {
	// AfterCRC32C is an exclusive cursor. Nil starts from the first CRC value.
	AfterCRC32C       *uint32
	Limit             uint32
	MinimumLocalPages uint64
}

type vnextCRCSummaryPage struct {
	ContractID           string
	OwnerID              string
	OwnerEpoch           uint64
	DedupEpoch           uint64
	OwnerJournalSequence uint64
	Groups               []vnextCRCGroupCount
	NextAfterCRC32C      *uint32
}

type vnextCRCCandidatePage struct {
	PageID cxlcheckpoint.PageID
}

type vnextCRCCandidatePageResult struct {
	ContractID      string
	OwnerID         string
	OwnerEpoch      uint64
	DedupEpoch      uint64
	ContentCRC32C   uint32
	TotalLocalPages uint64
	Pages           []vnextCRCCandidatePage
	NextOffset      uint64
	More            bool
}

type vnextVerifiedCRCPage struct {
	PageID         cxlcheckpoint.PageID
	ContentCRC32C  uint32
	PayloadLength  uint32
	ContentKind    vnextContentKind
	ReferenceCount uint64
	Content        [vnextContentPageSize]byte
}

type vnextCRCExactComparison struct {
	Equal         bool
	PayloadReads  uint64
	PayloadBytes  uint64
	ComparedBytes uint64
}

// buildCRCIndex scans only committed allocations and only their descriptor
// cache lines. Holding the Owner lock gives this observation a clear boundary
// with dump, abort, and reclaim in the current model. A future live service
// may replace the long critical section with Scheduler-issued dedup pins, but
// it must preserve the same no-reclaim observation guarantee.
func (group *vnextOwnerGroup) buildCRCIndex(dedupEpoch uint64) (*vnextOwnerCRCIndex, error) {
	group.mu.Lock()
	defer group.mu.Unlock()

	if err := group.checkUsableLocked(); err != nil {
		return nil, err
	}
	if dedupEpoch == 0 {
		return nil, fmt.Errorf("dedup epoch must be non-zero: %w", errVNextCRCIndexQuery)
	}

	index := &vnextOwnerCRCIndex{
		ContractID:           vnextCRCContractID,
		OwnerID:              group.ownerID,
		OwnerEpoch:           group.ownerEpoch,
		DedupEpoch:           dedupEpoch,
		OwnerJournalSequence: group.journal.SnapshotSequence,
		Groups:               make(map[uint32][]vnextLocalCRCPage),
	}

	allocationIDs := make([]uint64, 0, len(group.journal.Transactions))
	for allocationID, transaction := range group.journal.Transactions {
		if transaction.State == vnextOwnerCommitted {
			allocationIDs = append(allocationIDs, allocationID)
		}
	}
	sort.Slice(allocationIDs, func(i, j int) bool { return allocationIDs[i] < allocationIDs[j] })

	for _, allocationID := range allocationIDs {
		transaction := group.journal.Transactions[allocationID]
		if err := group.scanCommittedTransactionCRCsLocked(index, transaction); err != nil {
			return nil, err
		}
		index.Statistics.CommittedAllocations++
	}
	for crc := range index.Groups {
		pages := index.Groups[crc]
		sort.Slice(pages, func(i, j int) bool {
			return vnextLocalCRCPageLess(pages[i], pages[j])
		})
		index.Groups[crc] = pages
	}
	index.Statistics.DistinctCRCValues = uint64(len(index.Groups))
	return index, nil
}

func (group *vnextOwnerGroup) scanCommittedTransactionCRCsLocked(
	index *vnextOwnerCRCIndex,
	transaction *vnextOwnerTransaction,
) error {
	if transaction == nil || transaction.State != vnextOwnerCommitted {
		return fmt.Errorf("CRC scan received a non-committed Owner transaction: %w", errVNextInvalidState)
	}
	var scannedPages uint64
	for _, fragment := range transaction.Fragments {
		device := group.devices[fragment.DeviceUUID]
		if device == nil {
			return fmt.Errorf("CRC scan cannot resolve device %q: %w",
				fragment.DeviceUUID, errVNextCorrupt)
		}
		device.mu.Lock()
		err := func() error {
			if err := device.checkUsableLocked(); err != nil {
				return err
			}
			record, ok := device.allocator.lookup(transaction.CheckpointID)
			if !ok || record.AllocationRecordID != transaction.AllocationRecordID ||
				record.State != vnextAllocationCommitted {
				return fmt.Errorf(
					"CRC scan allocation %d is not committed on device %q: %w",
					transaction.AllocationRecordID, fragment.DeviceUUID, errVNextCRCIndexStale)
			}
			for _, extent := range fragment.Extents {
				for page := uint64(0); page < extent.PageCount; page++ {
					dataPageIndex := extent.StartDataPageIndex + page
					descriptor, err := device.readDescriptorLocked(dataPageIndex)
					if err != nil {
						return err
					}
					index.Statistics.DescriptorReads++
					index.Statistics.DescriptorBytes += vnextPageDescriptorSize
					scannedPages++
					if descriptor.State != vnextDescriptorSealed ||
						descriptor.AllocationRecordID != transaction.AllocationRecordID {
						return fmt.Errorf(
							"CRC scan found device %q page %d in state %d/allocation %d: %w",
							fragment.DeviceUUID,
							dataPageIndex,
							descriptor.State,
							descriptor.AllocationRecordID,
							errVNextCRCIndexStale)
					}
					if !vnextDedupPayloadKind(descriptor.ContentKind) {
						index.Statistics.SkippedControlPages++
						continue
					}
					index.Groups[descriptor.ContentCRC32] = append(
						index.Groups[descriptor.ContentCRC32],
						vnextLocalCRCPage{
							DeviceUUID:         fragment.DeviceUUID,
							AllocationRecordID: transaction.AllocationRecordID,
							DataPageIndex:      dataPageIndex,
						})
					index.Statistics.IndexedPayloadPages++
				}
			}
			return nil
		}()
		device.mu.Unlock()
		if err != nil {
			return err
		}
	}
	if scannedPages != transaction.TotalPages {
		return fmt.Errorf(
			"CRC scan covered %d pages for allocation %d, expected %d: %w",
			scannedPages,
			transaction.AllocationRecordID,
			transaction.TotalPages,
			errVNextCorrupt)
	}
	return nil
}

// vnextDedupPayloadKind deliberately includes memory and artifacts in one
// namespace, so identical 4 KiB bytes can be grouped across those origins.
// PageMap slots are excluded because an inactive A/B slot is writable during a
// future mapping update. MMTemplate is also control metadata and has little
// payload-reclamation value. Both remain protected by their CXL descriptors.
func vnextDedupPayloadKind(kind vnextContentKind) bool {
	return kind == vnextContentMemory ||
		kind == vnextContentArtifact ||
		kind == vnextContentRestoreBlob
}

func (index *vnextOwnerCRCIndex) summary(
	request vnextCRCSummaryRequest,
) (vnextCRCSummaryPage, error) {
	if err := index.validateIdentity(); err != nil {
		return vnextCRCSummaryPage{}, err
	}
	if request.Limit == 0 || request.Limit > vnextMaxCRCResponseEntries ||
		request.MinimumLocalPages == 0 {
		return vnextCRCSummaryPage{}, fmt.Errorf(
			"CRC summary limit/minimum is %d/%d: %w",
			request.Limit, request.MinimumLocalPages, errVNextCRCIndexQuery)
	}

	crcs := make([]uint32, 0, len(index.Groups))
	for crc, pages := range index.Groups {
		if uint64(len(pages)) < request.MinimumLocalPages {
			continue
		}
		if request.AfterCRC32C != nil && crc <= *request.AfterCRC32C {
			continue
		}
		crcs = append(crcs, crc)
	}
	sort.Slice(crcs, func(i, j int) bool { return crcs[i] < crcs[j] })

	page := vnextCRCSummaryPage{
		ContractID:           index.ContractID,
		OwnerID:              index.OwnerID,
		OwnerEpoch:           index.OwnerEpoch,
		DedupEpoch:           index.DedupEpoch,
		OwnerJournalSequence: index.OwnerJournalSequence,
	}
	count := len(crcs)
	if count > int(request.Limit) {
		count = int(request.Limit)
	}
	page.Groups = make([]vnextCRCGroupCount, 0, count)
	for _, crc := range crcs[:count] {
		page.Groups = append(page.Groups, vnextCRCGroupCount{
			ContentCRC32C:  crc,
			LocalPageCount: uint64(len(index.Groups[crc])),
		})
	}
	if count < len(crcs) {
		cursor := crcs[count-1]
		page.NextAfterCRC32C = &cursor
	}
	return page, nil
}

func (index *vnextOwnerCRCIndex) candidates(
	contentCRC32C uint32,
	offset uint64,
	limit uint32,
) (vnextCRCCandidatePageResult, error) {
	if err := index.validateIdentity(); err != nil {
		return vnextCRCCandidatePageResult{}, err
	}
	if limit == 0 || limit > vnextMaxCRCResponseEntries {
		return vnextCRCCandidatePageResult{}, fmt.Errorf(
			"CRC candidate limit %d is invalid: %w", limit, errVNextCRCIndexQuery)
	}
	localPages := index.Groups[contentCRC32C]
	if offset > uint64(len(localPages)) {
		return vnextCRCCandidatePageResult{}, fmt.Errorf(
			"CRC candidate offset %d exceeds group size %d: %w",
			offset, len(localPages), errVNextCRCIndexQuery)
	}
	end := offset + uint64(limit)
	if end > uint64(len(localPages)) {
		end = uint64(len(localPages))
	}
	result := vnextCRCCandidatePageResult{
		ContractID:      index.ContractID,
		OwnerID:         index.OwnerID,
		OwnerEpoch:      index.OwnerEpoch,
		DedupEpoch:      index.DedupEpoch,
		ContentCRC32C:   contentCRC32C,
		TotalLocalPages: uint64(len(localPages)),
		Pages:           make([]vnextCRCCandidatePage, 0, end-offset),
		NextOffset:      end,
		More:            end < uint64(len(localPages)),
	}
	for _, local := range localPages[offset:end] {
		result.Pages = append(result.Pages, vnextCRCCandidatePage{
			PageID: index.portablePageID(local),
		})
	}
	return result, nil
}

// readVerifiedCRCPage is the expensive second stage. It reads exactly one
// selected 4 KiB payload, validates it against the current descriptor, and
// rejects a reclaimed or changed candidate. Cross-Owner comparison must call
// this only while the Scheduler's later dedup transaction pins both pages.
func (group *vnextOwnerGroup) readVerifiedCRCPage(
	index *vnextOwnerCRCIndex,
	contentCRC32C uint32,
	pageID cxlcheckpoint.PageID,
) (vnextVerifiedCRCPage, error) {
	group.mu.Lock()
	defer group.mu.Unlock()
	return group.readVerifiedCRCPageLocked(index, contentCRC32C, pageID)
}

// exactCRCMatch provides an atomic same-Owner exact comparison under the
// Owner lock. Equal CRC values are only a candidate grouping key; only this
// 4,096-byte comparison can establish page equality.
func (group *vnextOwnerGroup) exactCRCMatch(
	index *vnextOwnerCRCIndex,
	contentCRC32C uint32,
	left cxlcheckpoint.PageID,
	right cxlcheckpoint.PageID,
) (vnextCRCExactComparison, error) {
	group.mu.Lock()
	defer group.mu.Unlock()

	if left == right {
		return vnextCRCExactComparison{}, fmt.Errorf(
			"exact comparison requires two distinct PageIDs: %w", errVNextCRCIndexQuery)
	}
	leftPage, err := group.readVerifiedCRCPageLocked(index, contentCRC32C, left)
	if err != nil {
		return vnextCRCExactComparison{}, err
	}
	rightPage, err := group.readVerifiedCRCPageLocked(index, contentCRC32C, right)
	if err != nil {
		return vnextCRCExactComparison{}, err
	}
	return vnextCRCExactComparison{
		Equal:         bytes.Equal(leftPage.Content[:], rightPage.Content[:]),
		PayloadReads:  2,
		PayloadBytes:  2 * vnextContentPageSize,
		ComparedBytes: vnextContentPageSize,
	}, nil
}

func (group *vnextOwnerGroup) readVerifiedCRCPageLocked(
	index *vnextOwnerCRCIndex,
	contentCRC32C uint32,
	pageID cxlcheckpoint.PageID,
) (vnextVerifiedCRCPage, error) {
	if err := group.checkUsableLocked(); err != nil {
		return vnextVerifiedCRCPage{}, err
	}
	if index == nil {
		return vnextVerifiedCRCPage{}, fmt.Errorf("CRC index is nil: %w", errVNextCRCIndexQuery)
	}
	if err := index.validateIdentity(); err != nil {
		return vnextVerifiedCRCPage{}, err
	}
	if index.OwnerID != group.ownerID || index.OwnerEpoch != group.ownerEpoch ||
		pageID.OwnerID != group.ownerID {
		return vnextVerifiedCRCPage{}, fmt.Errorf(
			"CRC candidate Owner identity does not match: %w", errVNextAuthority)
	}
	local := vnextLocalCRCPage{
		DeviceUUID:         pageID.DeviceUUID,
		AllocationRecordID: pageID.AllocationRecordID,
		DataPageIndex:      pageID.DataPageIndex,
	}
	if !index.contains(contentCRC32C, local) {
		return vnextVerifiedCRCPage{}, fmt.Errorf(
			"PageID was not observed in dedup epoch %d CRC %#x: %w",
			index.DedupEpoch, contentCRC32C, errVNextCRCIndexStale)
	}
	transaction := group.journal.Transactions[pageID.AllocationRecordID]
	if transaction == nil || transaction.State != vnextOwnerCommitted ||
		!vnextOwnerTransactionContainsPage(transaction, pageID.DeviceUUID, pageID.DataPageIndex) {
		return vnextVerifiedCRCPage{}, fmt.Errorf(
			"PageID no longer belongs to a committed Owner allocation: %w",
			errVNextCRCIndexStale)
	}
	device := group.devices[pageID.DeviceUUID]
	if device == nil {
		return vnextVerifiedCRCPage{}, fmt.Errorf(
			"PageID device %q is no longer attached: %w",
			pageID.DeviceUUID, errVNextCRCIndexStale)
	}
	device.mu.Lock()
	defer device.mu.Unlock()
	if err := device.checkUsableLocked(); err != nil {
		return vnextVerifiedCRCPage{}, err
	}
	descriptor, err := device.readDescriptorLocked(pageID.DataPageIndex)
	if err != nil {
		return vnextVerifiedCRCPage{}, err
	}
	if descriptor.State != vnextDescriptorSealed ||
		descriptor.AllocationRecordID != pageID.AllocationRecordID ||
		descriptor.ContentCRC32 != contentCRC32C ||
		!vnextDedupPayloadKind(descriptor.ContentKind) {
		return vnextVerifiedCRCPage{}, fmt.Errorf(
			"CRC candidate descriptor changed after observation: %w",
			errVNextCRCIndexStale)
	}
	content, err := device.readContentPageLocked(pageID.DataPageIndex)
	if err != nil {
		return vnextVerifiedCRCPage{}, err
	}
	if err := descriptor.validateContent(content); err != nil {
		return vnextVerifiedCRCPage{}, err
	}
	verified := vnextVerifiedCRCPage{
		PageID:         pageID,
		ContentCRC32C:  contentCRC32C,
		PayloadLength:  descriptor.PayloadLength,
		ContentKind:    descriptor.ContentKind,
		ReferenceCount: descriptor.ContentReferenceCount,
	}
	copy(verified.Content[:], content)
	return verified, nil
}

func (index *vnextOwnerCRCIndex) validateIdentity() error {
	if index == nil || index.ContractID != vnextCRCContractID ||
		index.OwnerID == "" || index.OwnerEpoch == 0 ||
		index.DedupEpoch == 0 || index.OwnerJournalSequence == 0 ||
		index.Groups == nil {
		return fmt.Errorf("CRC index identity is incomplete: %w", errVNextCRCIndexQuery)
	}
	return nil
}

func (index *vnextOwnerCRCIndex) portablePageID(local vnextLocalCRCPage) cxlcheckpoint.PageID {
	return cxlcheckpoint.PageID{
		OwnerID:            index.OwnerID,
		DeviceUUID:         local.DeviceUUID,
		AllocationRecordID: local.AllocationRecordID,
		DataPageIndex:      local.DataPageIndex,
	}
}

func (index *vnextOwnerCRCIndex) contains(
	contentCRC32C uint32,
	target vnextLocalCRCPage,
) bool {
	pages := index.Groups[contentCRC32C]
	position := sort.Search(len(pages), func(i int) bool {
		return !vnextLocalCRCPageLess(pages[i], target)
	})
	return position < len(pages) && pages[position] == target
}

func vnextLocalCRCPageLess(left, right vnextLocalCRCPage) bool {
	if left.DeviceUUID != right.DeviceUUID {
		return left.DeviceUUID < right.DeviceUUID
	}
	if left.AllocationRecordID != right.AllocationRecordID {
		return left.AllocationRecordID < right.AllocationRecordID
	}
	return left.DataPageIndex < right.DataPageIndex
}

func vnextOwnerTransactionContainsPage(
	transaction *vnextOwnerTransaction,
	deviceUUID string,
	dataPageIndex uint64,
) bool {
	for _, fragment := range transaction.Fragments {
		if fragment.DeviceUUID != deviceUUID {
			continue
		}
		for _, extent := range fragment.Extents {
			end, ok := vnextAdd(extent.StartDataPageIndex, extent.PageCount)
			if ok && dataPageIndex >= extent.StartDataPageIndex && dataPageIndex < end {
				return true
			}
		}
	}
	return false
}

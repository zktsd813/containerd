package main

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"sort"

	"github.com/containerd/containerd/third_party/trenv-containerd/pkg/cxlcheckpoint"
)

const (
	vnextCRCPageSidecarMagic      = "TRCRC006"
	vnextCRCPageSidecarHeaderSize = 56
	vnextCRCPageSidecarRecordSize = 40
	vnextCRCPageAlgorithmCRC32C   = 1

	vnextCRCFlagInitialOnes    uint64 = 1 << 0
	vnextCRCFlagFinalXOROnes          = 1 << 1
	vnextCRCFlagReflected             = 1 << 2
	vnextCRCFlagExactPageBytes        = 1 << 3
	vnextCRCFlagScatter               = 1 << 4
	vnextCRCRequiredFlags             = vnextCRCFlagInitialOnes |
		vnextCRCFlagFinalXOROnes |
		vnextCRCFlagReflected |
		vnextCRCFlagExactPageBytes |
		vnextCRCFlagScatter
)

var errVNextCRCSidecar = errors.New("invalid TRCRC006 sidecar")

type vnextCRCCopyEngine uint32

const (
	vnextCRCCopyEngineCPU vnextCRCCopyEngine = iota + 1
	vnextCRCCopyEngineDMLSoftware
	vnextCRCCopyEngineDMLHardware
)

func (engine vnextCRCCopyEngine) valid() bool {
	return engine >= vnextCRCCopyEngineCPU && engine <= vnextCRCCopyEngineDMLHardware
}

type vnextCRCPageSidecarHeader struct {
	PagesImageID     uint32
	CopyEngine       vnextCRCCopyEngine
	PageCount        uint64
	ScatterStartPage uint64
	ContractFlags    uint64
}

type vnextCRCPageSidecarRecord struct {
	PageIndex        uint64
	VAddr            uint64
	DevicePageOffset uint64
	ExtentIndex      uint32
	ContentCRC32C    uint32
}

type vnextCRCPageSidecar struct {
	Header  vnextCRCPageSidecarHeader
	Records []vnextCRCPageSidecarRecord
}

type vnextValidatedPageCRC struct {
	PagesImageID  uint32
	VAddr         uint64
	PageID        cxlcheckpoint.PageID
	ExtentIndex   uint32
	ContentCRC32C uint32
	CopyEngine    vnextCRCCopyEngine
}

func parseVNextCRCPageSidecar(
	data []byte,
	expectedPagesImageID uint32,
) (vnextCRCPageSidecar, error) {
	if expectedPagesImageID == 0 {
		return vnextCRCPageSidecar{}, fmt.Errorf(
			"expected pages image ID is zero: %w", errVNextCRCSidecar)
	}
	if len(data) < vnextCRCPageSidecarHeaderSize {
		return vnextCRCPageSidecar{}, fmt.Errorf(
			"TRCRC006 header is truncated: %w", errVNextCRCSidecar)
	}
	if string(data[:8]) != vnextCRCPageSidecarMagic {
		return vnextCRCPageSidecar{}, fmt.Errorf(
			"TRCRC006 magic is %q: %w", data[:8], errVNextCRCSidecar)
	}
	if headerSize := binary.LittleEndian.Uint32(data[8:12]); headerSize != vnextCRCPageSidecarHeaderSize {
		return vnextCRCPageSidecar{}, fmt.Errorf(
			"TRCRC006 header size is %d: %w", headerSize, errVNextCRCSidecar)
	}
	if recordSize := binary.LittleEndian.Uint32(data[12:16]); recordSize != vnextCRCPageSidecarRecordSize {
		return vnextCRCPageSidecar{}, fmt.Errorf(
			"TRCRC006 record size is %d: %w", recordSize, errVNextCRCSidecar)
	}
	if pageSize := binary.LittleEndian.Uint32(data[16:20]); uint64(pageSize) != cxlcheckpoint.PageSize {
		return vnextCRCPageSidecar{}, fmt.Errorf(
			"TRCRC006 page size is %d: %w", pageSize, errVNextCRCSidecar)
	}
	pagesImageID := binary.LittleEndian.Uint32(data[20:24])
	if pagesImageID != expectedPagesImageID {
		return vnextCRCPageSidecar{}, fmt.Errorf(
			"TRCRC006 pages image ID is %d, expected %d: %w",
			pagesImageID, expectedPagesImageID, errVNextCRCSidecar)
	}
	if algorithm := binary.LittleEndian.Uint32(data[24:28]); algorithm != vnextCRCPageAlgorithmCRC32C {
		return vnextCRCPageSidecar{}, fmt.Errorf(
			"TRCRC006 algorithm is %d, expected CRC-32C: %w",
			algorithm, errVNextCRCSidecar)
	}
	engine := vnextCRCCopyEngine(binary.LittleEndian.Uint32(data[28:32]))
	if !engine.valid() {
		return vnextCRCPageSidecar{}, fmt.Errorf(
			"TRCRC006 copy engine is %d: %w", engine, errVNextCRCSidecar)
	}
	pageCount := binary.LittleEndian.Uint64(data[32:40])
	if pageCount == 0 || pageCount > uint64(math.MaxInt64) {
		return vnextCRCPageSidecar{}, fmt.Errorf(
			"TRCRC006 page count is %d: %w", pageCount, errVNextCRCSidecar)
	}
	scatterStart := binary.LittleEndian.Uint64(data[40:48])
	if scatterStart != 0 {
		return vnextCRCPageSidecar{}, fmt.Errorf(
			"TRCRC006 scatter sidecar has contiguous start %d: %w",
			scatterStart, errVNextCRCSidecar)
	}
	flags := binary.LittleEndian.Uint64(data[48:56])
	if flags != vnextCRCRequiredFlags {
		return vnextCRCPageSidecar{}, fmt.Errorf(
			"TRCRC006 contract flags are %#x, expected %#x: %w",
			flags, uint64(vnextCRCRequiredFlags), errVNextCRCSidecar)
	}
	recordBytes, ok := vnextMul(pageCount, vnextCRCPageSidecarRecordSize)
	if !ok {
		return vnextCRCPageSidecar{}, fmt.Errorf(
			"TRCRC006 record bytes overflow: %w", errVNextCRCSidecar)
	}
	totalBytes, ok := vnextAdd(vnextCRCPageSidecarHeaderSize, recordBytes)
	if !ok || totalBytes != uint64(len(data)) {
		return vnextCRCPageSidecar{}, fmt.Errorf(
			"TRCRC006 length is %d, expected %d: %w",
			len(data), totalBytes, errVNextCRCSidecar)
	}
	sidecar := vnextCRCPageSidecar{
		Header: vnextCRCPageSidecarHeader{
			PagesImageID:     pagesImageID,
			CopyEngine:       engine,
			PageCount:        pageCount,
			ScatterStartPage: scatterStart,
			ContractFlags:    flags,
		},
		Records: make([]vnextCRCPageSidecarRecord, int(pageCount)),
	}
	for index := range sidecar.Records {
		offset := vnextCRCPageSidecarHeaderSize + index*vnextCRCPageSidecarRecordSize
		recordData := data[offset : offset+vnextCRCPageSidecarRecordSize]
		record := &sidecar.Records[index]
		record.PageIndex = binary.LittleEndian.Uint64(recordData[0:8])
		record.VAddr = binary.LittleEndian.Uint64(recordData[8:16])
		record.DevicePageOffset = binary.LittleEndian.Uint64(recordData[16:24])
		record.ExtentIndex = binary.LittleEndian.Uint32(recordData[24:28])
		record.ContentCRC32C = binary.LittleEndian.Uint32(recordData[28:32])
		recordPageSize := binary.LittleEndian.Uint32(recordData[32:36])
		reserved := binary.LittleEndian.Uint32(recordData[36:40])
		if record.PageIndex != uint64(index) ||
			record.VAddr%cxlcheckpoint.PageSize != 0 ||
			recordPageSize != uint32(cxlcheckpoint.PageSize) ||
			reserved != 0 {
			return vnextCRCPageSidecar{}, fmt.Errorf(
				"TRCRC006 record %d has invalid index/address/page-size/reserved fields: %w",
				index, errVNextCRCSidecar)
		}
	}
	return sidecar, nil
}

// validateVNextCRCPageSidecars proves that CRIU produced one exact CRC record
// for every sparse PageMap page and no others. It does not trust extent index
// or DAX page offset from the sidecar: both are recomputed from the validated
// publication and local V6 superblock bindings.
func (directory *vnextLocalDAXDirectory) validateVNextCRCPageSidecars(
	publication cxlcheckpoint.Publication,
	sidecarBytes map[uint32][]byte,
) ([]vnextValidatedPageCRC, error) {
	if _, err := directory.buildVNextCRIUCompleteRemap(publication); err != nil {
		return nil, err
	}
	type expectedPage struct {
		pagesImageID     uint32
		vaddr            uint64
		pageID           cxlcheckpoint.PageID
		devicePageOffset uint64
		extentIndex      uint32
	}
	expectedByImage := make(map[uint32][]expectedPage)
	var expectedTotal uint64
	for runIndex, run := range publication.PageMap.Runs {
		if runIndex > math.MaxUint32 {
			return nil, fmt.Errorf("PageMap run index exceeds TRCRC006 extent ABI")
		}
		binding := directory.byUUID[run.FirstPage.DeviceUUID]
		contentBasePage := binding.ContentRegionBase / cxlcheckpoint.PageSize
		for page := uint64(0); page < run.PageCount; page++ {
			vaddrDelta, ok := vnextMul(page, cxlcheckpoint.PageSize)
			if !ok {
				return nil, fmt.Errorf("PageMap virtual offset overflows")
			}
			vaddr, ok := vnextAdd(run.StartVAddr, vaddrDelta)
			if !ok {
				return nil, fmt.Errorf("PageMap virtual address overflows")
			}
			dataPageIndex, ok := vnextAdd(run.FirstPage.DataPageIndex, page)
			if !ok {
				return nil, fmt.Errorf("PageMap data page index overflows")
			}
			devicePageOffset, ok := vnextAdd(contentBasePage, dataPageIndex)
			if !ok {
				return nil, fmt.Errorf("PageMap local device page offset overflows")
			}
			expectedByImage[run.PagesImageID] = append(
				expectedByImage[run.PagesImageID],
				expectedPage{
					pagesImageID: run.PagesImageID,
					vaddr:        vaddr,
					pageID: cxlcheckpoint.PageID{
						OwnerID:            run.FirstPage.OwnerID,
						DeviceUUID:         run.FirstPage.DeviceUUID,
						AllocationRecordID: run.FirstPage.AllocationRecordID,
						DataPageIndex:      dataPageIndex,
					},
					devicePageOffset: devicePageOffset,
					extentIndex:      uint32(runIndex),
				})
			expectedTotal++
		}
	}
	if len(sidecarBytes) != len(expectedByImage) {
		return nil, fmt.Errorf(
			"TRCRC006 sidecar set has %d pages images, expected %d: %w",
			len(sidecarBytes), len(expectedByImage), errVNextCRCSidecar)
	}
	imageIDs := make([]uint32, 0, len(expectedByImage))
	for imageID := range expectedByImage {
		imageIDs = append(imageIDs, imageID)
	}
	sort.Slice(imageIDs, func(i, j int) bool { return imageIDs[i] < imageIDs[j] })

	validated := make([]vnextValidatedPageCRC, 0, expectedTotal)
	for _, imageID := range imageIDs {
		data, exists := sidecarBytes[imageID]
		if !exists {
			return nil, fmt.Errorf(
				"TRCRC006 sidecar for pages image %d is missing: %w",
				imageID, errVNextCRCSidecar)
		}
		sidecar, err := parseVNextCRCPageSidecar(data, imageID)
		if err != nil {
			return nil, err
		}
		expected := expectedByImage[imageID]
		if sidecar.Header.PageCount != uint64(len(expected)) {
			return nil, fmt.Errorf(
				"TRCRC006 pages image %d has %d records, expected %d: %w",
				imageID, sidecar.Header.PageCount, len(expected), errVNextCRCSidecar)
		}
		for index, record := range sidecar.Records {
			want := expected[index]
			if record.VAddr != want.vaddr ||
				record.DevicePageOffset != want.devicePageOffset ||
				record.ExtentIndex != want.extentIndex {
				return nil, fmt.Errorf(
					"TRCRC006 pages image %d record %d does not match PageMap/local binding: %w",
					imageID, index, errVNextCRCSidecar)
			}
			validated = append(validated, vnextValidatedPageCRC{
				PagesImageID:  imageID,
				VAddr:         want.vaddr,
				PageID:        want.pageID,
				ExtentIndex:   want.extentIndex,
				ContentCRC32C: record.ContentCRC32C,
				CopyEngine:    sidecar.Header.CopyEngine,
			})
		}
	}
	for imageID := range sidecarBytes {
		if _, exists := expectedByImage[imageID]; !exists {
			return nil, fmt.Errorf(
				"TRCRC006 sidecar for unexpected pages image %d: %w",
				imageID, errVNextCRCSidecar)
		}
	}
	if uint64(len(validated)) != expectedTotal {
		return nil, fmt.Errorf(
			"TRCRC006 validated %d pages, expected %d: %w",
			len(validated), expectedTotal, errVNextCRCSidecar)
	}
	return validated, nil
}

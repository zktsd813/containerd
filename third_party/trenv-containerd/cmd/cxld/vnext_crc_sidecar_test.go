package main

import (
	"encoding/binary"
	"errors"
	"testing"

	"github.com/containerd/containerd/third_party/trenv-containerd/pkg/cxlcheckpoint"
)

func vnextTestCRCPageSidecars(
	t *testing.T,
	publication cxlcheckpoint.Publication,
	directory *vnextLocalDAXDirectory,
) map[uint32][]byte {
	t.Helper()
	counts := make(map[uint32]uint64)
	for _, run := range publication.PageMap.Runs {
		counts[run.PagesImageID] += run.PageCount
	}
	sidecars := make(map[uint32][]byte, len(counts))
	for pagesImageID, count := range counts {
		size := vnextCRCPageSidecarHeaderSize + int(count)*vnextCRCPageSidecarRecordSize
		data := make([]byte, size)
		copy(data[0:8], []byte(vnextCRCPageSidecarMagic))
		binary.LittleEndian.PutUint32(data[8:12], vnextCRCPageSidecarHeaderSize)
		binary.LittleEndian.PutUint32(data[12:16], vnextCRCPageSidecarRecordSize)
		binary.LittleEndian.PutUint32(data[16:20], uint32(cxlcheckpoint.PageSize))
		binary.LittleEndian.PutUint32(data[20:24], pagesImageID)
		binary.LittleEndian.PutUint32(data[24:28], vnextCRCPageAlgorithmCRC32C)
		binary.LittleEndian.PutUint32(data[28:32], uint32(vnextCRCCopyEngineCPU))
		binary.LittleEndian.PutUint64(data[32:40], count)
		binary.LittleEndian.PutUint64(data[40:48], 0)
		binary.LittleEndian.PutUint64(data[48:56], vnextCRCRequiredFlags)
		sidecars[pagesImageID] = data
	}
	nextRecord := make(map[uint32]uint64)
	for extentIndex, run := range publication.PageMap.Runs {
		binding := directory.byUUID[run.FirstPage.DeviceUUID]
		contentBasePage := binding.ContentRegionBase / cxlcheckpoint.PageSize
		for page := uint64(0); page < run.PageCount; page++ {
			recordIndex := nextRecord[run.PagesImageID]
			nextRecord[run.PagesImageID]++
			data := sidecars[run.PagesImageID]
			offset := vnextCRCPageSidecarHeaderSize +
				int(recordIndex)*vnextCRCPageSidecarRecordSize
			binary.LittleEndian.PutUint64(data[offset:offset+8], recordIndex)
			binary.LittleEndian.PutUint64(
				data[offset+8:offset+16],
				run.StartVAddr+page*cxlcheckpoint.PageSize)
			binary.LittleEndian.PutUint64(
				data[offset+16:offset+24],
				contentBasePage+run.FirstPage.DataPageIndex+page)
			binary.LittleEndian.PutUint32(
				data[offset+24:offset+28], uint32(extentIndex))
			binary.LittleEndian.PutUint32(
				data[offset+28:offset+32], uint32(0x10203040+extentIndex)+uint32(page))
			binary.LittleEndian.PutUint32(
				data[offset+32:offset+36], uint32(cxlcheckpoint.PageSize))
		}
	}
	return sidecars
}

func TestVNextCRCPageSidecarsMatchEverySparsePageMapEntry(t *testing.T) {
	publication := validVNextCRIURemapPublication(t)
	bindings, _, _ := vnextCRIUTestBindings(t, publication)
	directory, err := newVNextLocalDAXDirectory(bindings)
	if err != nil {
		t.Fatalf("create local DAX directory: %v", err)
	}
	sidecars := vnextTestCRCPageSidecars(t, publication, directory)
	validated, err := directory.validateVNextCRCPageSidecars(publication, sidecars)
	if err != nil {
		t.Fatalf("validate TRCRC006 sidecars: %v", err)
	}
	if len(validated) != 2 ||
		validated[0].PagesImageID != 7 ||
		validated[0].VAddr != 0x2000 ||
		validated[0].PageID.DeviceUUID != "remap-device-a" ||
		validated[0].PageID.DataPageIndex != 10 ||
		validated[0].ExtentIndex != 0 ||
		validated[0].CopyEngine != vnextCRCCopyEngineCPU ||
		validated[1].PagesImageID != 8 ||
		validated[1].VAddr != 0x1000 ||
		validated[1].PageID.DeviceUUID != "remap-device-b" ||
		validated[1].PageID.DataPageIndex != 20 ||
		validated[1].ExtentIndex != 1 {
		t.Fatalf("unexpected validated TRCRC006 records: %#v", validated)
	}
}

func TestVNextCRCPageSidecarParserRejectsWrongContract(t *testing.T) {
	publication := validVNextCRIURemapPublication(t)
	bindings, _, _ := vnextCRIUTestBindings(t, publication)
	directory, err := newVNextLocalDAXDirectory(bindings)
	if err != nil {
		t.Fatalf("create local DAX directory: %v", err)
	}
	valid := vnextTestCRCPageSidecars(t, publication, directory)[7]
	tests := []struct {
		name   string
		mutate func([]byte) []byte
	}{
		{
			name: "legacy magic",
			mutate: func(data []byte) []byte {
				copy(data[:8], []byte("TRCRC001"))
				return data
			},
		},
		{
			name: "wrong record size",
			mutate: func(data []byte) []byte {
				binary.LittleEndian.PutUint32(data[12:16], 24)
				return data
			},
		},
		{
			name: "wrong page size",
			mutate: func(data []byte) []byte {
				binary.LittleEndian.PutUint32(data[16:20], 8192)
				return data
			},
		},
		{
			name: "IEEE algorithm",
			mutate: func(data []byte) []byte {
				binary.LittleEndian.PutUint32(data[24:28], 2)
				return data
			},
		},
		{
			name: "auto engine",
			mutate: func(data []byte) []byte {
				binary.LittleEndian.PutUint32(data[28:32], 0)
				return data
			},
		},
		{
			name: "non-scatter header",
			mutate: func(data []byte) []byte {
				binary.LittleEndian.PutUint64(data[40:48], 1)
				return data
			},
		},
		{
			name: "missing reflected flag",
			mutate: func(data []byte) []byte {
				binary.LittleEndian.PutUint64(
					data[48:56], vnextCRCRequiredFlags&^vnextCRCFlagReflected)
				return data
			},
		},
		{
			name: "unknown contract flag",
			mutate: func(data []byte) []byte {
				binary.LittleEndian.PutUint64(
					data[48:56], vnextCRCRequiredFlags|(1<<63))
				return data
			},
		},
		{
			name: "wrong stream page index",
			mutate: func(data []byte) []byte {
				binary.LittleEndian.PutUint64(data[56:64], 1)
				return data
			},
		},
		{
			name: "unaligned vaddr",
			mutate: func(data []byte) []byte {
				binary.LittleEndian.PutUint64(data[64:72], 0x2001)
				return data
			},
		},
		{
			name: "record reserved",
			mutate: func(data []byte) []byte {
				binary.LittleEndian.PutUint32(data[92:96], 1)
				return data
			},
		},
		{
			name: "truncated",
			mutate: func(data []byte) []byte {
				return data[:len(data)-1]
			},
		},
		{
			name: "trailing",
			mutate: func(data []byte) []byte {
				return append(data, 0)
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			data := test.mutate(append([]byte(nil), valid...))
			if _, err := parseVNextCRCPageSidecar(data, 7); !errors.Is(err, errVNextCRCSidecar) {
				t.Fatalf("parse error is %v", err)
			}
		})
	}
	if _, err := parseVNextCRCPageSidecar(valid, 8); !errors.Is(err, errVNextCRCSidecar) {
		t.Fatalf("wrong expected pages image ID returned %v", err)
	}
}

func TestVNextCRCPageSidecarSetRejectsMissingExtraOrRemappedRecord(t *testing.T) {
	publication := validVNextCRIURemapPublication(t)
	bindings, _, _ := vnextCRIUTestBindings(t, publication)
	directory, err := newVNextLocalDAXDirectory(bindings)
	if err != nil {
		t.Fatalf("create local DAX directory: %v", err)
	}

	missing := vnextTestCRCPageSidecars(t, publication, directory)
	delete(missing, 8)
	if _, err := directory.validateVNextCRCPageSidecars(
		publication, missing); !errors.Is(err, errVNextCRCSidecar) {
		t.Fatalf("missing sidecar returned %v", err)
	}

	extra := vnextTestCRCPageSidecars(t, publication, directory)
	extra[99] = append([]byte(nil), extra[7]...)
	if _, err := directory.validateVNextCRCPageSidecars(
		publication, extra); !errors.Is(err, errVNextCRCSidecar) {
		t.Fatalf("extra sidecar returned %v", err)
	}

	for _, mutation := range []struct {
		name   string
		offset int
		value  uint64
	}{
		{name: "vaddr", offset: 64, value: 0x3000},
		{name: "device pgoff", offset: 72, value: 999},
		{name: "extent index", offset: 80, value: 1},
	} {
		t.Run(mutation.name, func(t *testing.T) {
			sidecars := vnextTestCRCPageSidecars(t, publication, directory)
			if mutation.name == "extent index" {
				binary.LittleEndian.PutUint32(
					sidecars[7][mutation.offset:mutation.offset+4],
					uint32(mutation.value))
			} else {
				binary.LittleEndian.PutUint64(
					sidecars[7][mutation.offset:mutation.offset+8],
					mutation.value)
			}
			if _, err := directory.validateVNextCRCPageSidecars(
				publication, sidecars); !errors.Is(err, errVNextCRCSidecar) {
				t.Fatalf("remapped record returned %v", err)
			}
		})
	}
}

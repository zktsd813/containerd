package main

import (
	"bytes"
	"errors"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/containerd/containerd/third_party/trenv-containerd/pkg/cxlcheckpoint"
)

type vnextContentMappingRemapFixture struct {
	contentObjects []cxlcheckpoint.ContentObject
	virtual        cxlcheckpoint.VirtualPageMap
	placement      cxlcheckpoint.ContentPlacementMap
	directory      *vnextLocalDAXDirectory
	pathA          string
	pathB          string
}

func newVNextContentMappingRemapFixture(t testing.TB) vnextContentMappingRemapFixture {
	t.Helper()
	contentObjects := []cxlcheckpoint.ContentObject{
		{
			ObjectID:         10,
			Kind:             cxlcheckpoint.ContentMemory,
			ByteLength:       6 * cxlcheckpoint.PageSize,
			LogicalPageStart: 0,
			PageCount:        6,
		},
		{
			ObjectID:         20,
			Kind:             cxlcheckpoint.ContentArtifact,
			ByteLength:       17,
			LogicalPageStart: 6,
			PageCount:        1,
		},
		{
			ObjectID:         30,
			Kind:             cxlcheckpoint.ContentMMTemplate,
			ByteLength:       100,
			LogicalPageStart: 7,
			PageCount:        1,
		},
		{
			ObjectID:         31,
			Kind:             cxlcheckpoint.ContentPageMap,
			ByteLength:       100,
			LogicalPageStart: 8,
			PageCount:        1,
		},
		{
			ObjectID:         32,
			Kind:             cxlcheckpoint.ContentPageMap,
			ByteLength:       0,
			LogicalPageStart: 9,
			PageCount:        1,
		},
		{
			ObjectID:         40,
			Kind:             cxlcheckpoint.ContentRestoreBlob,
			ByteLength:       cxlcheckpoint.PageSize,
			LogicalPageStart: 10,
			PageCount:        1,
		},
		{
			ObjectID:         50,
			Kind:             cxlcheckpoint.ContentPublication,
			ByteLength:       cxlcheckpoint.PageSize,
			LogicalPageStart: 11,
			PageCount:        1,
		},
	}
	virtual := cxlcheckpoint.VirtualPageMap{
		VirtualPageMapID: "reader-virtual-map",
		Version:          4,
		PageSize:         cxlcheckpoint.PageSize,
		Runs: []cxlcheckpoint.VirtualPageMapRun{
			{
				// 0x1000 is an intentional sparse hole in pages image 7.
				PagesImageID:    7,
				StartVAddr:      0x2000,
				PageCount:       4,
				ContentObjectID: 10,
				ObjectPageIndex: 0,
			},
			{
				// 0x6000 and 0x7000 remain sparse holes.
				PagesImageID:    7,
				StartVAddr:      0x8000,
				PageCount:       1,
				ContentObjectID: 10,
				ObjectPageIndex: 4,
			},
			{
				PagesImageID:    8,
				StartVAddr:      0x1000,
				PageCount:       1,
				ContentObjectID: 10,
				ObjectPageIndex: 5,
			},
		},
	}
	placement := cxlcheckpoint.ContentPlacementMap{
		ContentPlacementMapID: "reader-placement-map",
		Version:               12,
		PageSize:              cxlcheckpoint.PageSize,
		Devices: []cxlcheckpoint.Device{
			{
				DeviceUUID:    "reader-device-a",
				OwnerID:       "owner-a",
				OwnerEpoch:    7,
				DataPageCount: 128,
			},
			{
				DeviceUUID:    "reader-device-b",
				OwnerID:       "owner-b",
				OwnerEpoch:    9,
				DataPageCount: 128,
			},
		},
		Runs: []cxlcheckpoint.ContentPlacementRun{
			{
				ContentObjectID:    10,
				ObjectPageIndex:    0,
				PageCount:          2,
				DeviceIndex:        0,
				AllocationRecordID: 101,
				DataPageIndex:      10,
			},
			{
				ContentObjectID:    10,
				ObjectPageIndex:    2,
				PageCount:          1,
				DeviceIndex:        1,
				AllocationRecordID: 202,
				DataPageIndex:      20,
			},
			{
				ContentObjectID:    10,
				ObjectPageIndex:    3,
				PageCount:          1,
				DeviceIndex:        0,
				AllocationRecordID: 303,
				DataPageIndex:      12,
			},
			{
				ContentObjectID:    10,
				ObjectPageIndex:    4,
				PageCount:          1,
				DeviceIndex:        1,
				AllocationRecordID: 404,
				DataPageIndex:      30,
			},
			{
				// Memory page 5 aliases the canonical physical page used by
				// memory page 0 after deduplication.
				ContentObjectID:    10,
				ObjectPageIndex:    5,
				PageCount:          1,
				DeviceIndex:        0,
				AllocationRecordID: 101,
				DataPageIndex:      10,
			},
			{
				ContentObjectID:    20,
				ObjectPageIndex:    0,
				PageCount:          1,
				DeviceIndex:        1,
				AllocationRecordID: 505,
				DataPageIndex:      40,
			},
			{
				ContentObjectID:    40,
				ObjectPageIndex:    0,
				PageCount:          1,
				DeviceIndex:        0,
				AllocationRecordID: 606,
				DataPageIndex:      50,
			},
		},
	}
	if err := virtual.Validate(contentObjects); err != nil {
		t.Fatalf("validate fixture VirtualPageMap: %v", err)
	}
	if err := placement.Validate(contentObjects); err != nil {
		t.Fatalf("validate fixture ContentPlacementMap: %v", err)
	}
	pathA := t.TempDir() + "/dax-a"
	pathB := t.TempDir() + "/dax-b"
	directory, err := newVNextLocalDAXDirectory([]vnextLocalDAXBinding{
		{
			DeviceUUID:        placement.Devices[0].DeviceUUID,
			OwnerID:           placement.Devices[0].OwnerID,
			OwnerEpoch:        placement.Devices[0].OwnerEpoch,
			DataPageCount:     placement.Devices[0].DataPageCount,
			ContentRegionBase: 100 * cxlcheckpoint.PageSize,
			DevicePath:        pathA,
		},
		{
			DeviceUUID:        placement.Devices[1].DeviceUUID,
			OwnerID:           placement.Devices[1].OwnerID,
			OwnerEpoch:        placement.Devices[1].OwnerEpoch,
			DataPageCount:     placement.Devices[1].DataPageCount,
			ContentRegionBase: 200 * cxlcheckpoint.PageSize,
			DevicePath:        pathB,
		},
	})
	if err != nil {
		t.Fatalf("create fixture local DAX directory: %v", err)
	}
	return vnextContentMappingRemapFixture{
		contentObjects: contentObjects,
		virtual:        virtual,
		placement:      placement,
		directory:      directory,
		pathA:          pathA,
		pathB:          pathB,
	}
}

func TestVNextContentMappingRemapExactGoldenMultiOwnerFragmentedAliasAndSparse(
	t *testing.T,
) {
	fixture := newVNextContentMappingRemapFixture(t)
	wantObjects := append([]cxlcheckpoint.ContentObject(nil), fixture.contentObjects...)
	wantVirtual := cloneVNextContentMappingVirtualMap(fixture.virtual)
	wantPlacement := cloneVNextContentMappingPlacementMap(fixture.placement)
	wantDirectory := cloneVNextContentMappingDirectory(fixture.directory)

	first, err := fixture.directory.buildVNextContentMappingCRIUCompleteRemap(
		fixture.contentObjects, fixture.virtual, fixture.placement)
	if err != nil {
		t.Fatalf("build V7 content-mapping CRIU remap: %v", err)
	}
	second, err := fixture.directory.buildVNextContentMappingCRIUCompleteRemap(
		fixture.contentObjects, fixture.virtual, fixture.placement)
	if err != nil {
		t.Fatalf("build V7 content-mapping CRIU remap again: %v", err)
	}
	if !bytes.Equal(first, second) {
		t.Fatal("identical V7 content mappings produced different remap bytes")
	}
	want := vnextCRIURemapMagic + "\n" +
		"7 8192 2 110 " + fixture.pathA + "\n" +
		"7 16384 1 220 " + fixture.pathB + "\n" +
		"7 20480 1 112 " + fixture.pathA + "\n" +
		"7 32768 1 230 " + fixture.pathB + "\n" +
		"8 4096 1 110 " + fixture.pathA + "\n"
	if string(first) != want {
		t.Fatalf("V7 content-mapping remap differs:\n got %q\nwant %q", first, want)
	}
	if strings.Contains(string(first), " 4096 1 200 ") ||
		strings.Contains(string(first), "7 24576") ||
		strings.Contains(string(first), "7 28672") {
		t.Fatalf("sparse virtual hole was materialized: %q", first)
	}
	if strings.Count(string(first), " 110 "+fixture.pathA+"\n") != 2 {
		t.Fatalf("dedup physical alias is absent from remap: %q", first)
	}
	if !reflect.DeepEqual(fixture.contentObjects, wantObjects) ||
		!reflect.DeepEqual(fixture.virtual, wantVirtual) ||
		!reflect.DeepEqual(fixture.placement, wantPlacement) ||
		!reflect.DeepEqual(fixture.directory, wantDirectory) {
		t.Fatal("V7 remap composition mutated an input map, object, or local binding")
	}
}

func TestVNextContentMappingRemapIsPureAndDoesNotReadConfiguredDAXPaths(t *testing.T) {
	fixture := newVNextContentMappingRemapFixture(t)
	for _, path := range []string{fixture.pathA, fixture.pathB} {
		if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("fixture DAX path unexpectedly exists before composition: %q / %v", path, err)
		}
	}
	if _, err := fixture.directory.buildVNextContentMappingCRIUCompleteRemap(
		fixture.contentObjects, fixture.virtual, fixture.placement); err != nil {
		t.Fatalf("pure V7 remap composition: %v", err)
	}
	for _, path := range []string{fixture.pathA, fixture.pathB} {
		if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("composition created or opened a DAX path: %q / %v", path, err)
		}
	}
	// Success here is deliberately not a superblock or authorization proof:
	// production must live-verify every device after ACTIVE_ARMED before CRIU.
}

func TestVNextContentMappingRemapFailsClosedOnInvalidMapsAndContext(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(*vnextContentMappingRemapFixture)
		message string
	}{
		{
			name: "VirtualPageMap logical hole",
			mutate: func(fixture *vnextContentMappingRemapFixture) {
				fixture.virtual.Runs[0].PageCount--
			},
			message: "validate V7 VirtualPageMap",
		},
		{
			name: "VirtualPageMap logical alias",
			mutate: func(fixture *vnextContentMappingRemapFixture) {
				fixture.virtual.Runs[1].ObjectPageIndex = 3
			},
			message: "validate V7 VirtualPageMap",
		},
		{
			name: "ContentPlacementMap logical hole",
			mutate: func(fixture *vnextContentMappingRemapFixture) {
				fixture.placement.Runs = fixture.placement.Runs[:len(fixture.placement.Runs)-1]
			},
			message: "validate V7 ContentPlacementMap",
		},
		{
			name: "ContentPlacementMap memory gap",
			mutate: func(fixture *vnextContentMappingRemapFixture) {
				fixture.placement.Runs[1].ObjectPageIndex = 1
			},
			message: "validate V7 ContentPlacementMap",
		},
		{
			name: "partial memory context",
			mutate: func(fixture *vnextContentMappingRemapFixture) {
				fixture.contentObjects[0].ByteLength--
			},
			message: "validate V7 VirtualPageMap",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newVNextContentMappingRemapFixture(t)
			test.mutate(&fixture)
			if _, err := fixture.directory.buildVNextContentMappingCRIUCompleteRemap(
				fixture.contentObjects, fixture.virtual, fixture.placement); err == nil ||
				!strings.Contains(err.Error(), test.message) {
				t.Fatalf("invalid input error = %v, want %q", err, test.message)
			}
		})
	}
}

func TestVNextContentMappingRemapRequiresEveryConfiguredBindingToMatchExactly(t *testing.T) {
	t.Run("nil directory", func(t *testing.T) {
		fixture := newVNextContentMappingRemapFixture(t)
		var directory *vnextLocalDAXDirectory
		if _, err := directory.buildVNextContentMappingCRIUCompleteRemap(
			fixture.contentObjects, fixture.virtual, fixture.placement); err == nil ||
			!strings.Contains(err.Error(), "directory is unavailable") {
			t.Fatalf("nil directory error = %v", err)
		}
	})

	tests := []struct {
		name    string
		mutate  func(*vnextLocalDAXDirectory)
		message string
	}{
		{
			name: "missing UUID",
			mutate: func(directory *vnextLocalDAXDirectory) {
				delete(directory.byUUID, "reader-device-b")
			},
			message: "no local DAX binding",
		},
		{
			name: "stale Owner ID",
			mutate: func(directory *vnextLocalDAXDirectory) {
				binding := directory.byUUID["reader-device-b"]
				binding.OwnerID = "stale-owner"
				directory.byUUID[binding.DeviceUUID] = binding
			},
			message: "does not match V7 placement",
		},
		{
			name: "stale Owner epoch",
			mutate: func(directory *vnextLocalDAXDirectory) {
				binding := directory.byUUID["reader-device-b"]
				binding.OwnerEpoch++
				directory.byUUID[binding.DeviceUUID] = binding
			},
			message: "does not match V7 placement",
		},
		{
			name: "stale capacity",
			mutate: func(directory *vnextLocalDAXDirectory) {
				binding := directory.byUUID["reader-device-b"]
				binding.DataPageCount++
				directory.byUUID[binding.DeviceUUID] = binding
			},
			message: "does not match V7 placement",
		},
		{
			name: "binding value UUID mismatch",
			mutate: func(directory *vnextLocalDAXDirectory) {
				binding := directory.byUUID["reader-device-b"]
				binding.DeviceUUID = "different-device"
				directory.byUUID["reader-device-b"] = binding
			},
			message: "does not match V7 placement",
		},
		{
			name: "unclean path",
			mutate: func(directory *vnextLocalDAXDirectory) {
				binding := directory.byUUID["reader-device-b"]
				binding.DevicePath += " with-space"
				directory.byUUID[binding.DeviceUUID] = binding
			},
			message: "whitespace",
		},
		{
			name: "unaligned content region",
			mutate: func(directory *vnextLocalDAXDirectory) {
				binding := directory.byUUID["reader-device-b"]
				binding.ContentRegionBase++
				directory.byUUID[binding.DeviceUUID] = binding
			},
			message: "invalid V7 content-region base",
		},
		{
			name: "aliased local path",
			mutate: func(directory *vnextLocalDAXDirectory) {
				bindingA := directory.byUUID["reader-device-a"]
				bindingB := directory.byUUID["reader-device-b"]
				bindingB.DevicePath = bindingA.DevicePath
				directory.byUUID[bindingB.DeviceUUID] = bindingB
			},
			message: "aliases V7 placement devices",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newVNextContentMappingRemapFixture(t)
			directory := cloneVNextContentMappingDirectory(fixture.directory)
			test.mutate(directory)
			if _, err := directory.buildVNextContentMappingCRIUCompleteRemap(
				fixture.contentObjects, fixture.virtual, fixture.placement); err == nil ||
				!strings.Contains(err.Error(), test.message) {
				t.Fatalf("binding error = %v, want %q", err, test.message)
			}
		})
	}

	t.Run("artifact-only placement device must also be bound", func(t *testing.T) {
		fixture := newVNextContentMappingRemapFixture(t)
		fixture.placement.Devices = append(
			fixture.placement.Devices,
			cxlcheckpoint.Device{
				DeviceUUID:    "reader-device-c",
				OwnerID:       "owner-c",
				OwnerEpoch:    11,
				DataPageCount: 128,
			})
		// Object 20 is artifact content and therefore has no virtual-memory
		// remap line, but its placement device is still part of the active map.
		fixture.placement.Runs[5].DeviceIndex = 2
		if err := fixture.placement.Validate(fixture.contentObjects); err != nil {
			t.Fatalf("artifact-only device fixture is invalid: %v", err)
		}
		if _, err := fixture.directory.buildVNextContentMappingCRIUCompleteRemap(
			fixture.contentObjects, fixture.virtual, fixture.placement); err == nil ||
			!strings.Contains(err.Error(), "reader-device-c") {
			t.Fatalf("missing artifact-only binding error = %v", err)
		}
	})
}

func TestVNextContentMappingRemapRejectsSignedGeometryOverflowAndByteBound(t *testing.T) {
	t.Run("signed content geometry overflow", func(t *testing.T) {
		fixture := newVNextContentMappingRemapFixture(t)
		directory := cloneVNextContentMappingDirectory(fixture.directory)
		binding := directory.byUUID["reader-device-a"]
		binding.ContentRegionBase = cxlcheckpoint.MaxSignedLong -
			cxlcheckpoint.MaxSignedLong%cxlcheckpoint.PageSize
		directory.byUUID[binding.DeviceUUID] = binding
		if _, err := directory.buildVNextContentMappingCRIUCompleteRemap(
			fixture.contentObjects, fixture.virtual, fixture.placement); err == nil ||
			!strings.Contains(err.Error(), "overflows signed ABI") {
			t.Fatalf("signed geometry overflow error = %v", err)
		}
	})

	t.Run("bounded output", func(t *testing.T) {
		fixture := newVNextContentMappingRemapFixture(t)
		limit := len(vnextCRIURemapMagic) + 1
		if _, err := fixture.directory.buildVNextContentMappingCRIUCompleteRemapBounded(
			fixture.contentObjects, fixture.virtual, fixture.placement, limit); err == nil ||
			!strings.Contains(err.Error(), "exceeds") {
			t.Fatalf("bounded remap error = %v", err)
		}
	})

	t.Run("bound cannot be widened", func(t *testing.T) {
		fixture := newVNextContentMappingRemapFixture(t)
		if _, err := fixture.directory.buildVNextContentMappingCRIUCompleteRemapBounded(
			fixture.contentObjects,
			fixture.virtual,
			fixture.placement,
			vnextMaxCRIURemapBytes+1); err == nil ||
			!strings.Contains(err.Error(), "outside") {
			t.Fatalf("widened remap bound error = %v", err)
		}
	})
}

func cloneVNextContentMappingVirtualMap(
	source cxlcheckpoint.VirtualPageMap,
) cxlcheckpoint.VirtualPageMap {
	result := source
	result.Runs = append([]cxlcheckpoint.VirtualPageMapRun(nil), source.Runs...)
	return result
}

func cloneVNextContentMappingPlacementMap(
	source cxlcheckpoint.ContentPlacementMap,
) cxlcheckpoint.ContentPlacementMap {
	result := source
	result.Devices = append([]cxlcheckpoint.Device(nil), source.Devices...)
	result.Runs = append([]cxlcheckpoint.ContentPlacementRun(nil), source.Runs...)
	return result
}

func cloneVNextContentMappingDirectory(
	source *vnextLocalDAXDirectory,
) *vnextLocalDAXDirectory {
	result := &vnextLocalDAXDirectory{
		byUUID: make(map[string]vnextLocalDAXBinding, len(source.byUUID)),
	}
	for uuid, binding := range source.byUUID {
		result.byUUID[uuid] = binding
	}
	return result
}

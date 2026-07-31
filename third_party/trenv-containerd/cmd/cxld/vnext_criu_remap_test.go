package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/containerd/containerd/third_party/trenv-containerd/pkg/cxlcheckpoint"
)

func validVNextCRIURemapPublication(t *testing.T) cxlcheckpoint.Publication {
	t.Helper()
	publication := cxlcheckpoint.Publication{
		CheckpointID: "remap-checkpoint",
		Devices: []cxlcheckpoint.Device{
			{
				DeviceUUID:    "remap-device-a",
				OwnerID:       "owner-a",
				OwnerEpoch:    7,
				DataPageCount: 128,
			},
			{
				DeviceUUID:    "remap-device-b",
				OwnerID:       "owner-b",
				OwnerEpoch:    9,
				DataPageCount: 128,
			},
		},
		ContentObjects: []cxlcheckpoint.ContentObject{
			{
				ObjectID:         1,
				Kind:             cxlcheckpoint.ContentMemory,
				ByteLength:       2 * cxlcheckpoint.PageSize,
				LogicalPageStart: 0,
				PageCount:        2,
			},
			{
				ObjectID:         2,
				Kind:             cxlcheckpoint.ContentMMTemplate,
				LogicalPageStart: 2,
				PageCount:        1,
			},
			{
				ObjectID:         3,
				Kind:             cxlcheckpoint.ContentPageMap,
				LogicalPageStart: 3,
				PageCount:        1,
			},
			{
				ObjectID:         4,
				Kind:             cxlcheckpoint.ContentPageMap,
				LogicalPageStart: 4,
				PageCount:        1,
			},
			{
				ObjectID:         5,
				Kind:             cxlcheckpoint.ContentPublication,
				ByteLength:       cxlcheckpoint.PageSize,
				LogicalPageStart: 5,
				PageCount:        1,
			},
		},
		Allocation: cxlcheckpoint.InitialAllocation{
			OwnerID:            "owner-a",
			OwnerEpoch:         7,
			AllocationRecordID: 42,
			TotalPages:         6,
			Extents: []cxlcheckpoint.AllocationExtent{{
				DeviceUUID:         "remap-device-a",
				StartDataPageIndex: 10,
				PageCount:          6,
				LogicalPageStart:   0,
			}},
		},
		MMTemplate: cxlcheckpoint.MMTemplate{
			TemplateID:             "remap-template",
			ContentObjectID:        2,
			RuntimeCompatibilityID: "trenv-v6-test-runtime",
			PageSize:               cxlcheckpoint.PageSize,
			VMAs: []cxlcheckpoint.VMA{
				{
					PagesImageID:    7,
					StartVAddr:      0x1000,
					EndVAddr:        0x4000,
					ProtectionFlags: cxlcheckpoint.ProtectionRead | cxlcheckpoint.ProtectionWrite,
					MappingFlags:    cxlcheckpoint.MappingPrivate | cxlcheckpoint.MappingAnonymous,
					BackingKind:     cxlcheckpoint.BackingAnonymous,
					PageMapRunStart: 0,
					PageMapRunCount: 1,
				},
				{
					// The second CRIU address space intentionally reuses
					// virtual address 0x1000.
					PagesImageID:    8,
					StartVAddr:      0x1000,
					EndVAddr:        0x3000,
					ProtectionFlags: cxlcheckpoint.ProtectionRead | cxlcheckpoint.ProtectionWrite,
					MappingFlags:    cxlcheckpoint.MappingPrivate | cxlcheckpoint.MappingAnonymous,
					BackingKind:     cxlcheckpoint.BackingAnonymous,
					PageMapRunStart: 1,
					PageMapRunCount: 1,
				},
			},
		},
		PageMap: cxlcheckpoint.PageMap{
			PageMapID:       "remap-page-map",
			Version:         1,
			ContentObjectID: 3,
			PageSize:        cxlcheckpoint.PageSize,
			Runs: []cxlcheckpoint.PageMapRun{
				{
					// The first present page follows an intentional VMA
					// hole at 0x1000.
					PagesImageID: 7,
					StartVAddr:   0x2000,
					PageCount:    1,
					FirstPage: cxlcheckpoint.PageID{
						OwnerID:            "owner-a",
						DeviceUUID:         "remap-device-a",
						AllocationRecordID: 42,
						DataPageIndex:      10,
					},
				},
				{
					PagesImageID: 8,
					StartVAddr:   0x1000,
					PageCount:    1,
					FirstPage: cxlcheckpoint.PageID{
						OwnerID:            "owner-b",
						DeviceUUID:         "remap-device-b",
						AllocationRecordID: 99,
						DataPageIndex:      20,
					},
				},
			},
		},
		Artifacts: cxlcheckpoint.ArtifactManifest{
			ManifestID: "remap-artifacts",
		},
		MappingSlots: cxlcheckpoint.MappingSlots{
			A: cxlcheckpoint.MappingSlot{
				Name:            cxlcheckpoint.MappingSlotA,
				ContentObjectID: 3,
				CapacityPages:   1,
			},
			B: cxlcheckpoint.MappingSlot{
				Name:            cxlcheckpoint.MappingSlotB,
				ContentObjectID: 4,
				CapacityPages:   1,
			},
		},
		Root: cxlcheckpoint.CommittedRoot{
			State:               cxlcheckpoint.RootCommitted,
			RootID:              "remap-root",
			CheckpointID:        "remap-checkpoint",
			OwnerID:             "owner-a",
			AllocationRecordID:  42,
			MMTemplateID:        "remap-template",
			PageMapID:           "remap-page-map",
			PageMapVersion:      1,
			ArtifactManifestID:  "remap-artifacts",
			ActiveMappingSlot:   cxlcheckpoint.MappingSlotA,
			PublicationSequence: 1,
		},
	}
	mmSize, err := cxlcheckpoint.CanonicalMMTemplateSize(publication.MMTemplate)
	if err != nil {
		t.Fatalf("canonical test MMTemplate size: %v", err)
	}
	pageMapSize, err := cxlcheckpoint.CanonicalPageMapSize(publication.PageMap)
	if err != nil {
		t.Fatalf("canonical test PageMap size: %v", err)
	}
	publication.ContentObjects[1].ByteLength = mmSize
	publication.ContentObjects[2].ByteLength = pageMapSize
	digest, err := cxlcheckpoint.DeviceTableDigest(publication.Devices)
	if err != nil {
		t.Fatalf("test DeviceTable digest: %v", err)
	}
	publication.Root.DeviceTableDigest = digest
	if err := publication.Validate(); err != nil {
		t.Fatalf("test remap publication is invalid: %v", err)
	}
	return publication
}

func vnextCRIUTestBindings(
	t *testing.T,
	publication cxlcheckpoint.Publication,
) ([]vnextLocalDAXBinding, string, string) {
	t.Helper()
	root := t.TempDir()
	pathA := filepath.Join(root, "dax-a")
	pathB := filepath.Join(root, "dax-b")
	return []vnextLocalDAXBinding{
		{
			DeviceUUID:        publication.Devices[0].DeviceUUID,
			OwnerID:           publication.Devices[0].OwnerID,
			OwnerEpoch:        publication.Devices[0].OwnerEpoch,
			DataPageCount:     publication.Devices[0].DataPageCount,
			ContentRegionBase: 100 * cxlcheckpoint.PageSize,
			DevicePath:        pathA,
		},
		{
			DeviceUUID:        publication.Devices[1].DeviceUUID,
			OwnerID:           publication.Devices[1].OwnerID,
			OwnerEpoch:        publication.Devices[1].OwnerEpoch,
			DataPageCount:     publication.Devices[1].DataPageCount,
			ContentRegionBase: 200 * cxlcheckpoint.PageSize,
			DevicePath:        pathB,
		},
	}, pathA, pathB
}

func TestVNextCRIUCompleteRemapResolvesUUIDsOnlyAfterPortableValidation(t *testing.T) {
	publication := validVNextCRIURemapPublication(t)
	bindings, pathA, pathB := vnextCRIUTestBindings(t, publication)
	directory, err := newVNextLocalDAXDirectory(bindings)
	if err != nil {
		t.Fatalf("create local DAX directory: %v", err)
	}
	data, err := directory.buildVNextCRIUCompleteRemap(publication)
	if err != nil {
		t.Fatalf("build strict CRIU remap: %v", err)
	}
	want := vnextCRIURemapMagic + "\n" +
		"7 8192 1 110 " + pathA + "\n" +
		"8 4096 1 220 " + pathB + "\n"
	if string(data) != want {
		t.Fatalf("strict CRIU remap differs:\n got %q\nwant %q", data, want)
	}

	encoded, err := cxlcheckpoint.Encode(publication)
	if err != nil {
		t.Fatalf("encode portable publication: %v", err)
	}
	if bytes.Contains(encoded, []byte(pathA)) || bytes.Contains(encoded, []byte(pathB)) {
		t.Fatal("node-local DAX path leaked into portable V6 publication")
	}
}

func TestVNextCRIUCompleteRemapFailsClosedOnBindingMismatch(t *testing.T) {
	publication := validVNextCRIURemapPublication(t)
	bindings, _, _ := vnextCRIUTestBindings(t, publication)

	missing, err := newVNextLocalDAXDirectory(bindings[:1])
	if err != nil {
		t.Fatalf("create incomplete local directory: %v", err)
	}
	if _, err := missing.buildVNextCRIUCompleteRemap(publication); err == nil ||
		!strings.Contains(err.Error(), "no local DAX binding") {
		t.Fatalf("missing UUID binding returned %v", err)
	}

	mismatched := append([]vnextLocalDAXBinding(nil), bindings...)
	mismatched[1].OwnerEpoch++
	directory, err := newVNextLocalDAXDirectory(mismatched)
	if err != nil {
		t.Fatalf("create mismatched local directory: %v", err)
	}
	if _, err := directory.buildVNextCRIUCompleteRemap(publication); err == nil ||
		!strings.Contains(err.Error(), "does not match publication") {
		t.Fatalf("Owner epoch mismatch returned %v", err)
	}

	badPath := append([]vnextLocalDAXBinding(nil), bindings...)
	badPath[0].DevicePath += " with-space"
	if _, err := newVNextLocalDAXDirectory(badPath); err == nil ||
		!strings.Contains(err.Error(), "whitespace") {
		t.Fatalf("whitespace-bearing local path returned %v", err)
	}

	aliasedPath := append([]vnextLocalDAXBinding(nil), bindings...)
	aliasedPath[1].DevicePath = aliasedPath[0].DevicePath
	if _, err := newVNextLocalDAXDirectory(aliasedPath); err == nil ||
		!strings.Contains(err.Error(), "aliases UUIDs") {
		t.Fatalf("two UUIDs bound to one local path returned %v", err)
	}
}

func TestVNextCRIUCompleteRemapIsPrivateAtomicAndEphemeral(t *testing.T) {
	publication := validVNextCRIURemapPublication(t)
	bindings, _, _ := vnextCRIUTestBindings(t, publication)
	directory, err := newVNextLocalDAXDirectory(bindings)
	if err != nil {
		t.Fatalf("create local DAX directory: %v", err)
	}
	workDirectory := filepath.Join(t.TempDir(), "work")
	path, cleanup, err := directory.materializeVNextCRIUCompleteRemap(
		workDirectory, publication)
	if err != nil {
		t.Fatalf("materialize strict CRIU remap: %v", err)
	}
	if filepath.Base(path) != vnextCRIURemapFilename {
		t.Fatalf("materialized remap path is %q", path)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat materialized remap: %v", err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("materialized remap mode is %#o", info.Mode().Perm())
	}
	data, err := os.ReadFile(path)
	if err != nil || !bytes.HasPrefix(data, []byte(vnextCRIURemapMagic+"\n")) {
		t.Fatalf("read materialized remap: %q / %v", data, err)
	}
	if matches, _ := filepath.Glob(
		filepath.Join(workDirectory, "."+vnextCRIURemapFilename+".tmp.*")); len(matches) != 0 {
		t.Fatalf("temporary remap files remain: %#v", matches)
	}
	cleanup()
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("ephemeral remap remains after cleanup: %v", err)
	}
}

func TestVNextLocalDAXBindingUsesValidatedDeviceGeometry(t *testing.T) {
	fixture := newVNextOwnerTestFixture(t, []vnextOwnerTestDeviceSpec{
		{UUID: "binding-device", Size: 256 << 10},
	})
	device := fixture.devices[0]
	binding, err := vnextLocalDAXBindingFromDevice(device, fixture.deviceFiles[0].Name())
	if err != nil {
		t.Fatalf("build local binding from V6 device: %v", err)
	}
	if binding.DeviceUUID != device.superblock.DeviceUUID ||
		binding.OwnerID != device.superblock.OwnerID ||
		binding.OwnerEpoch != device.superblock.OwnerEpoch ||
		binding.DataPageCount != device.superblock.Geometry.DataPageCount ||
		binding.ContentRegionBase != device.superblock.Geometry.ContentRegionBase {
		t.Fatalf("local binding does not match V6 superblock: %#v", binding)
	}
}

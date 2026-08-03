package trcxl007

import (
	"errors"
	"math"
	"reflect"
	"testing"

	"github.com/containerd/containerd/third_party/trenv-containerd/pkg/cxlcheckpoint"
)

func TestDeviceGeometryTwoGiBHasOneDescriptorAndBitmapBitPerPage(t *testing.T) {
	geometry, err := CalculateDeviceGeometry(2<<30, 128<<10)
	if err != nil {
		t.Fatalf("calculate geometry: %v", err)
	}
	if err := geometry.Validate(); err != nil {
		t.Fatalf("validate geometry: %v", err)
	}
	if geometry.DataPageCount != 516157 {
		t.Fatalf("data page count = %d, expected 516157", geometry.DataPageCount)
	}
	want := DeviceGeometry{
		DeviceBytes:                2147483648,
		SuperblockAOffset:          0,
		SuperblockBOffset:          4096,
		AllocatorSnapshotAOffset:   8192,
		AllocatorSnapshotBOffset:   139264,
		AllocatorSnapshotSlotBytes: 131072,
		ControlRegionBytes:         270336,
		DescriptorRegionBase:       270336,
		DescriptorRegionBytes:      33034048,
		ContentRegionBase:          33304576,
		ContentRegionBytes:         2114179072,
		DataPageCount:              516157,
	}
	if geometry != want {
		t.Fatalf("2 GiB geometry = %#v, expected %#v", geometry, want)
	}
	if geometry.DescriptorRegionBytes != geometry.DataPageCount*64 {
		t.Fatalf("descriptor bytes = %d", geometry.DescriptorRegionBytes)
	}
	if geometry.ContentRegionBytes != geometry.DataPageCount*4096 {
		t.Fatalf("content bytes = %d", geometry.ContentRegionBytes)
	}
	bitmapBytes, err := geometry.AllocationBitmapBytes()
	if err != nil {
		t.Fatalf("bitmap bytes: %v", err)
	}
	if bitmapBytes != 64520 {
		t.Fatalf("bitmap bytes = %d, expected 64520", bitmapBytes)
	}
	if AllocatorSnapshotFixedBytes+bitmapBytes > geometry.AllocatorSnapshotSlotBytes {
		t.Fatal("bitmap does not fit either allocator snapshot slot")
	}
	if geometry.DescriptorRegionBytes*16 != geometry.ContentRegionBytes/4 {
		// 64 B is exactly 1/64 of 4096 B. Spell the ratio without
		// floating point so this remains an exact metadata accounting test.
		t.Fatalf("descriptor/content ratio is not exactly 1:64")
	}
}

func TestDeviceGeometryAddressCalculationIsOneToOne(t *testing.T) {
	geometry, err := CalculateDeviceGeometry(2<<30, 128<<10)
	if err != nil {
		t.Fatalf("calculate geometry: %v", err)
	}
	indexes := []uint64{0, 1, geometry.DataPageCount / 2, geometry.DataPageCount - 1}
	for _, index := range indexes {
		descriptor, err := geometry.DescriptorOffset(index)
		if err != nil {
			t.Fatalf("descriptor %d: %v", index, err)
		}
		content, err := geometry.ContentOffset(index)
		if err != nil {
			t.Fatalf("content %d: %v", index, err)
		}
		if descriptor != geometry.DescriptorRegionBase+index*uint64(PageDescriptorBytes) {
			t.Fatalf("descriptor %d offset = %d", index, descriptor)
		}
		if content != geometry.ContentRegionBase+index*uint64(ContentPageBytes) {
			t.Fatalf("content %d offset = %d", index, content)
		}
		recovered, err := geometry.DataPageIndex(content)
		if err != nil {
			t.Fatalf("recover content %d: %v", index, err)
		}
		if recovered != index {
			t.Fatalf("recovered index = %d, expected %d", recovered, index)
		}
	}
	if _, err := geometry.DescriptorOffset(geometry.DataPageCount); !errors.Is(err, ErrGeometryBounds) {
		t.Fatalf("out-of-range descriptor error = %v", err)
	}
	if _, err := geometry.ContentOffset(geometry.DataPageCount); !errors.Is(err, ErrGeometryBounds) {
		t.Fatalf("out-of-range content error = %v", err)
	}
	if _, err := geometry.DataPageIndex(geometry.ContentRegionBase + 1); !errors.Is(err, ErrGeometryBounds) {
		t.Fatalf("unaligned content error = %v", err)
	}
}

func TestDeviceGeometryUsesBitmapCapacityAsARealBound(t *testing.T) {
	const deviceBytes = uint64(128 << 20)
	geometry, err := CalculateDeviceGeometry(deviceBytes, 4096)
	if err != nil {
		t.Fatalf("calculate bitmap-limited geometry: %v", err)
	}
	wantPages := (uint64(4096) - AllocatorSnapshotFixedBytes) * 8
	if geometry.DataPageCount != wantPages {
		t.Fatalf("bitmap-limited page count = %d, expected %d", geometry.DataPageCount, wantPages)
	}
	bitmapBytes, err := geometry.AllocationBitmapBytes()
	if err != nil {
		t.Fatalf("bitmap bytes: %v", err)
	}
	if AllocatorSnapshotFixedBytes+bitmapBytes != geometry.AllocatorSnapshotSlotBytes {
		t.Fatalf("bitmap-limited snapshot uses %d bytes, slot is %d",
			AllocatorSnapshotFixedBytes+bitmapBytes,
			geometry.AllocatorSnapshotSlotBytes)
	}
	_, _, physicalEnd, ok := geometryEnd(geometry.ControlRegionBytes, wantPages+1)
	if !ok || physicalEnd > deviceBytes {
		t.Fatalf("page %d is not physically feasible; bitmap was not isolated as the limiter", wantPages+1)
	}
}

func TestDeviceGeometryRejectsAlternateAndInvalidLayouts(t *testing.T) {
	for name, inputs := range map[string][2]uint64{
		"zero-device":    {0, 4096},
		"signed-device":  {cxlcheckpoint.MaxSignedLong + 1, 4096},
		"small-slot":     {2 << 30, 2048},
		"unaligned-slot": {2 << 30, 4097},
		"oversized-slot": {2 << 30, MaxAllocatorSnapshotSlotBytes + 4096},
		"control-only":   {SuperblockSlotBytes*2 + 4096*2, 4096},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := CalculateDeviceGeometry(inputs[0], inputs[1]); err == nil {
				t.Fatal("invalid geometry inputs succeeded")
			}
		})
	}

	geometry, err := CalculateDeviceGeometry(2<<30, 128<<10)
	if err != nil {
		t.Fatalf("calculate geometry: %v", err)
	}
	geometry.DataPageCount--
	geometry.DescriptorRegionBytes -= uint64(PageDescriptorBytes)
	geometry.ContentRegionBytes -= uint64(ContentPageBytes)
	if err := geometry.Validate(); !errors.Is(err, ErrInvalidGeometry) {
		t.Fatalf("non-maximal geometry error = %v", err)
	}
}

func TestDeviceGeometryHasNoArtifactPool(t *testing.T) {
	geometry, err := CalculateDeviceGeometry(2<<30, 128<<10)
	if err != nil {
		t.Fatalf("calculate geometry: %v", err)
	}
	if geometry.ContentRegionBase <= geometry.DescriptorRegionBase {
		t.Fatal("content region does not follow the descriptor array")
	}
	// The geometry exposes one undifferentiated content region. Memory,
	// artifact, restore, and control semantics are expressed only by V7
	// content objects/descriptors, so no page0/artifact0 shard exists here.
	if cxlcheckpoint.V7StorageContentKindCount != 9 {
		t.Fatalf("compiled V7 kind count = %d", cxlcheckpoint.V7StorageContentKindCount)
	}
	geometryType := reflect.TypeOf(DeviceGeometry{})
	wantFields := []string{
		"DeviceBytes",
		"SuperblockAOffset",
		"SuperblockBOffset",
		"AllocatorSnapshotAOffset",
		"AllocatorSnapshotBOffset",
		"AllocatorSnapshotSlotBytes",
		"ControlRegionBytes",
		"DescriptorRegionBase",
		"DescriptorRegionBytes",
		"ContentRegionBase",
		"ContentRegionBytes",
		"DataPageCount",
	}
	if geometryType.NumField() != len(wantFields) {
		t.Fatalf("DeviceGeometry has %d fields, expected exact single-content-region schema %d",
			geometryType.NumField(), len(wantFields))
	}
	for index, name := range wantFields {
		if geometryType.Field(index).Name != name {
			t.Fatalf("DeviceGeometry field[%d] = %q, expected %q",
				index, geometryType.Field(index).Name, name)
		}
	}
}

func TestDeviceGeometryArithmeticHelpersFailClosed(t *testing.T) {
	if _, ok := checkedAdd(math.MaxUint64, 1); ok {
		t.Fatal("checkedAdd accepted overflow")
	}
	if _, ok := checkedMul(math.MaxUint64, 2); ok {
		t.Fatal("checkedMul accepted overflow")
	}
	if _, ok := alignUp(math.MaxUint64, uint64(ContentPageBytes)); ok {
		t.Fatal("alignUp accepted overflow")
	}
	if _, ok := alignUp(1, 3); ok {
		t.Fatal("alignUp accepted a non-power-of-two alignment")
	}
	if _, _, _, ok := geometryEnd(math.MaxUint64-1, 1); ok {
		t.Fatal("geometryEnd accepted an overflowing descriptor boundary")
	}
	if _, err := (DeviceGeometry{}).DescriptorOffset(0); !errors.Is(err, ErrGeometryBounds) {
		t.Fatalf("zero-value DescriptorOffset error = %v", err)
	}
}

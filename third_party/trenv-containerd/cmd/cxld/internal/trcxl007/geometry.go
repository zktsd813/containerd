package trcxl007

import (
	"errors"
	"fmt"
	"math"

	"github.com/containerd/containerd/third_party/trenv-containerd/pkg/cxlcheckpoint"
)

const (
	// SuperblockSlotBytes is one independently checksummed A/B superblock
	// copy. The two copies are the first bytes of every TRCXL007 device.
	SuperblockSlotBytes uint64 = 4096
	SuperblockSlotCount uint64 = 2

	// AllocatorSnapshotSlotCount is deliberately two. The Owner publishes a
	// new complete allocation-bitmap snapshot into the inactive slot before
	// selecting it through the superblock sequence. Readers may inspect these
	// bytes, but only the current Owner writes them.
	AllocatorSnapshotSlotCount    uint64 = 2
	MinAllocatorSnapshotSlotBytes        = uint64(4096)
	MaxAllocatorSnapshotSlotBytes        = uint64(64 << 20)

	// OwnerStateSnapshotSlotCount is deliberately two. Each slot holds a
	// complete Owner-group state snapshot, not an append-only log. Group-global
	// next IDs and allocation records live only in this Owner state, never in a
	// per-device allocation-bitmap snapshot.
	OwnerStateSnapshotSlotCount    uint64 = 2
	MinOwnerStateSnapshotSlotBytes        = uint64(4096)
	MaxOwnerStateSnapshotSlotBytes        = uint64(64 << 20)

	// AllocatorSnapshotFixedBytes reserves the 64-byte envelope, two 32-byte
	// device/Owner-group binding digests, and six 64-bit scalar fields that
	// precede the one-bit-per-page allocation bitmap. This per-device snapshot
	// records only the last Owner transaction it applied and local page state.
	AllocatorSnapshotFixedBytes uint64 = 176
)

var (
	ErrInvalidGeometry = errors.New("invalid TRCXL007 device geometry")
	ErrGeometryBounds  = errors.New("TRCXL007 geometry address is out of bounds")
)

// DeviceGeometry is the deterministic inline-metadata layout of one DAX
// device. Artifact and memory bytes share ContentRegion; ContentKindV7 is a
// descriptor/object property, never a separate physical pool.
//
// For every data-page index i there is exactly one descriptor and one payload:
//
//   descriptor = DescriptorRegionBase + i * 64
//   payload    = ContentRegionBase    + i * 4096
//
// The CRC/reference metadata therefore cannot run out independently of its
// payload page.
type DeviceGeometry struct {
	DeviceBytes uint64

	SuperblockAOffset uint64
	SuperblockBOffset uint64

	AllocatorSnapshotAOffset   uint64
	AllocatorSnapshotBOffset   uint64
	AllocatorSnapshotSlotBytes uint64

	OwnerStateSnapshotAOffset   uint64
	OwnerStateSnapshotBOffset   uint64
	OwnerStateSnapshotSlotBytes uint64

	ControlRegionBytes uint64

	DescriptorRegionBase  uint64
	DescriptorRegionBytes uint64
	ContentRegionBase     uint64
	ContentRegionBytes    uint64
	DataPageCount         uint64
}

// CalculateDeviceGeometry chooses the largest page count for which the
// complete A/B superblock, allocator-snapshot, and Owner-state control area,
// one 64-byte descriptor per page, one 4 KiB payload per page, and a complete
// one-bit-per-page bitmap in either allocator snapshot slot all fit. The
// result depends only on the three inputs.
func CalculateDeviceGeometry(
	deviceBytes,
	allocatorSnapshotSlotBytes,
	ownerStateSnapshotSlotBytes uint64,
) (DeviceGeometry, error) {
	if deviceBytes == 0 || deviceBytes > cxlcheckpoint.MaxSignedLong {
		return DeviceGeometry{}, geometryInvalidf(
			"device size %d is outside the positive signed-Long ABI", deviceBytes)
	}
	if allocatorSnapshotSlotBytes < MinAllocatorSnapshotSlotBytes ||
		allocatorSnapshotSlotBytes > MaxAllocatorSnapshotSlotBytes ||
		allocatorSnapshotSlotBytes%uint64(ContentPageBytes) != 0 {
		return DeviceGeometry{}, geometryInvalidf(
			"allocator snapshot slot size %d must be page-aligned and in %d..%d",
			allocatorSnapshotSlotBytes,
			MinAllocatorSnapshotSlotBytes,
			MaxAllocatorSnapshotSlotBytes)
	}
	if ownerStateSnapshotSlotBytes < MinOwnerStateSnapshotSlotBytes ||
		ownerStateSnapshotSlotBytes > MaxOwnerStateSnapshotSlotBytes ||
		ownerStateSnapshotSlotBytes%uint64(ContentPageBytes) != 0 {
		return DeviceGeometry{}, geometryInvalidf(
			"Owner-state snapshot slot size %d must be page-aligned and in %d..%d",
			ownerStateSnapshotSlotBytes,
			MinOwnerStateSnapshotSlotBytes,
			MaxOwnerStateSnapshotSlotBytes)
	}

	superblockBytes, ok := checkedMul(SuperblockSlotBytes, SuperblockSlotCount)
	if !ok {
		return DeviceGeometry{}, geometryInvalidf("superblock region overflows")
	}
	allocatorBytes, ok := checkedMul(allocatorSnapshotSlotBytes, AllocatorSnapshotSlotCount)
	if !ok {
		return DeviceGeometry{}, geometryInvalidf("allocator snapshot region overflows")
	}
	ownerStateBytes, ok := checkedMul(ownerStateSnapshotSlotBytes, OwnerStateSnapshotSlotCount)
	if !ok {
		return DeviceGeometry{}, geometryInvalidf("Owner-state snapshot region overflows")
	}
	controlBytes, ok := checkedAdd(superblockBytes, allocatorBytes)
	if ok {
		controlBytes, ok = checkedAdd(controlBytes, ownerStateBytes)
	}
	if !ok || controlBytes >= deviceBytes {
		return DeviceGeometry{}, geometryInvalidf(
			"device size %d does not extend beyond control region %d",
			deviceBytes,
			controlBytes)
	}

	bitmapCapacityBytes := allocatorSnapshotSlotBytes - AllocatorSnapshotFixedBytes
	bitmapPageLimit, ok := checkedMul(bitmapCapacityBytes, 8)
	if !ok {
		return DeviceGeometry{}, geometryInvalidf("allocator bitmap capacity overflows")
	}
	spacePageLimit := (deviceBytes - controlBytes) / uint64(ContentPageBytes)
	upper := spacePageLimit
	if bitmapPageLimit < upper {
		upper = bitmapPageLimit
	}
	if upper == 0 {
		return DeviceGeometry{}, geometryInvalidf("device has no room for one descriptor/payload pair")
	}

	var best uint64
	low, high := uint64(1), upper
	for low <= high {
		middle := low + (high-low)/2
		_, _, end, fits := geometryEnd(controlBytes, middle)
		if fits && end <= deviceBytes {
			best = middle
			low = middle + 1
		} else {
			high = middle - 1
		}
	}
	if best == 0 {
		return DeviceGeometry{}, geometryInvalidf("device has no complete descriptor/payload pair")
	}

	descriptorBytes, contentBase, _, ok := geometryEnd(controlBytes, best)
	if !ok {
		return DeviceGeometry{}, geometryInvalidf("device layout overflows")
	}
	contentBytes, ok := checkedMul(best, uint64(ContentPageBytes))
	if !ok {
		return DeviceGeometry{}, geometryInvalidf("content region overflows")
	}
	geometry := DeviceGeometry{
		DeviceBytes:                 deviceBytes,
		SuperblockAOffset:           0,
		SuperblockBOffset:           SuperblockSlotBytes,
		AllocatorSnapshotAOffset:    superblockBytes,
		AllocatorSnapshotBOffset:    superblockBytes + allocatorSnapshotSlotBytes,
		AllocatorSnapshotSlotBytes:  allocatorSnapshotSlotBytes,
		OwnerStateSnapshotAOffset:   superblockBytes + allocatorBytes,
		OwnerStateSnapshotBOffset:   superblockBytes + allocatorBytes + ownerStateSnapshotSlotBytes,
		OwnerStateSnapshotSlotBytes: ownerStateSnapshotSlotBytes,
		ControlRegionBytes:          controlBytes,
		DescriptorRegionBase:        controlBytes,
		DescriptorRegionBytes:       descriptorBytes,
		ContentRegionBase:           contentBase,
		ContentRegionBytes:          contentBytes,
		DataPageCount:               best,
	}
	if err := geometry.Validate(); err != nil {
		return DeviceGeometry{}, err
	}
	return geometry, nil
}

// Validate rejects layouts that are merely in-bounds but differ from the
// deterministic maximum-capacity result. A persisted superblock therefore
// cannot smuggle in an alternate descriptor/payload mapping.
func (geometry DeviceGeometry) Validate() error {
	if geometry.DataPageCount == 0 {
		return geometryInvalidf("data page count is zero")
	}
	if geometry.SuperblockAOffset != 0 ||
		geometry.SuperblockBOffset != SuperblockSlotBytes ||
		geometry.AllocatorSnapshotAOffset != SuperblockSlotBytes*SuperblockSlotCount {
		return geometryInvalidf("fixed superblock/allocator offsets differ from TRCXL007")
	}
	if geometry.AllocatorSnapshotSlotBytes < MinAllocatorSnapshotSlotBytes ||
		geometry.AllocatorSnapshotSlotBytes > MaxAllocatorSnapshotSlotBytes ||
		geometry.AllocatorSnapshotSlotBytes%uint64(ContentPageBytes) != 0 {
		return geometryInvalidf("allocator snapshot slot size is invalid")
	}
	if geometry.OwnerStateSnapshotSlotBytes < MinOwnerStateSnapshotSlotBytes ||
		geometry.OwnerStateSnapshotSlotBytes > MaxOwnerStateSnapshotSlotBytes ||
		geometry.OwnerStateSnapshotSlotBytes%uint64(ContentPageBytes) != 0 {
		return geometryInvalidf("Owner-state snapshot slot size is invalid")
	}
	expectedSnapshotB, ok := checkedAdd(
		geometry.AllocatorSnapshotAOffset,
		geometry.AllocatorSnapshotSlotBytes)
	if !ok || geometry.AllocatorSnapshotBOffset != expectedSnapshotB {
		return geometryInvalidf("allocator snapshot A/B slots overlap or have a gap")
	}
	expectedOwnerStateA, ok := checkedAdd(
		geometry.AllocatorSnapshotBOffset,
		geometry.AllocatorSnapshotSlotBytes)
	if !ok || geometry.OwnerStateSnapshotAOffset != expectedOwnerStateA {
		return geometryInvalidf("Owner-state snapshot A does not immediately follow allocator snapshot B")
	}
	expectedOwnerStateB, ok := checkedAdd(
		geometry.OwnerStateSnapshotAOffset,
		geometry.OwnerStateSnapshotSlotBytes)
	if !ok || geometry.OwnerStateSnapshotBOffset != expectedOwnerStateB {
		return geometryInvalidf("Owner-state snapshot A/B slots overlap or have a gap")
	}
	expectedControlEnd, ok := checkedAdd(
		geometry.OwnerStateSnapshotBOffset,
		geometry.OwnerStateSnapshotSlotBytes)
	if !ok || geometry.ControlRegionBytes != expectedControlEnd {
		return geometryInvalidf("control region does not end after Owner-state snapshot B")
	}
	if geometry.DescriptorRegionBase != geometry.ControlRegionBytes ||
		geometry.DescriptorRegionBase%uint64(PageDescriptorBytes) != 0 {
		return geometryInvalidf("descriptor region is not adjacent and cache-line aligned")
	}
	expectedDescriptorBytes, ok := checkedMul(
		geometry.DataPageCount,
		uint64(PageDescriptorBytes))
	if !ok || geometry.DescriptorRegionBytes != expectedDescriptorBytes {
		return geometryInvalidf("descriptor region is not exactly one descriptor per data page")
	}
	expectedContentBytes, ok := checkedMul(
		geometry.DataPageCount,
		uint64(ContentPageBytes))
	if !ok || geometry.ContentRegionBytes != expectedContentBytes {
		return geometryInvalidf("content region is not exactly one payload per descriptor")
	}
	descriptorEnd, ok := checkedAdd(
		geometry.DescriptorRegionBase,
		geometry.DescriptorRegionBytes)
	if !ok || geometry.ContentRegionBase < descriptorEnd ||
		geometry.ContentRegionBase%uint64(ContentPageBytes) != 0 {
		return geometryInvalidf("descriptor/content boundary is invalid")
	}
	contentEnd, ok := checkedAdd(geometry.ContentRegionBase, geometry.ContentRegionBytes)
	if !ok || contentEnd > geometry.DeviceBytes {
		return geometryInvalidf("content region exceeds the device")
	}
	bitmapBytes, err := geometry.AllocationBitmapBytes()
	if err != nil {
		return err
	}
	requiredSnapshotBytes, ok := checkedAdd(AllocatorSnapshotFixedBytes, bitmapBytes)
	if !ok || requiredSnapshotBytes > geometry.AllocatorSnapshotSlotBytes {
		return geometryInvalidf(
			"allocation bitmap needs %d bytes in a %d-byte snapshot slot",
			requiredSnapshotBytes,
			geometry.AllocatorSnapshotSlotBytes)
	}

	expected, err := calculateDeviceGeometryUnchecked(
		geometry.DeviceBytes,
		geometry.AllocatorSnapshotSlotBytes,
		geometry.OwnerStateSnapshotSlotBytes)
	if err != nil {
		return err
	}
	if geometry != expected {
		return geometryInvalidf("layout is not the deterministic maximum-capacity geometry")
	}
	return nil
}

// AllocationBitmapBytes returns ceil(DataPageCount/8). The last byte's unused
// high bits must be zero in the later snapshot codec.
func (geometry DeviceGeometry) AllocationBitmapBytes() (uint64, error) {
	if geometry.DataPageCount == 0 || geometry.DataPageCount > cxlcheckpoint.MaxSignedLong {
		return 0, geometryInvalidf("data page count %d is outside the signed-Long ABI", geometry.DataPageCount)
	}
	plusSeven, ok := checkedAdd(geometry.DataPageCount, 7)
	if !ok {
		return 0, geometryInvalidf("allocation bitmap byte count overflows")
	}
	return plusSeven / 8, nil
}

func (geometry DeviceGeometry) DescriptorOffset(dataPageIndex uint64) (uint64, error) {
	return geometry.pageOffset(
		"descriptor",
		dataPageIndex,
		geometry.DescriptorRegionBase,
		uint64(PageDescriptorBytes))
}

func (geometry DeviceGeometry) ContentOffset(dataPageIndex uint64) (uint64, error) {
	return geometry.pageOffset(
		"content",
		dataPageIndex,
		geometry.ContentRegionBase,
		uint64(ContentPageBytes))
}

func (geometry DeviceGeometry) pageOffset(
	name string,
	dataPageIndex uint64,
	base uint64,
	stride uint64,
) (uint64, error) {
	// Callers obtain geometry from a validated superblock. Keep this explicit
	// zero-capacity guard as well so a zero-value receiver fails without an
	// underflowed diagnostic range.
	if geometry.DataPageCount == 0 {
		return 0, fmt.Errorf("%w: %s geometry has zero data-page capacity", ErrGeometryBounds, name)
	}
	if dataPageIndex >= geometry.DataPageCount {
		return 0, fmt.Errorf(
			"%w: %s data-page index %d is outside 0..%d",
			ErrGeometryBounds,
			name,
			dataPageIndex,
			geometry.DataPageCount-1)
	}
	delta, ok := checkedMul(dataPageIndex, stride)
	if !ok {
		return 0, fmt.Errorf("%w: %s offset multiplication overflows", ErrGeometryBounds, name)
	}
	offset, ok := checkedAdd(base, delta)
	if !ok || offset > cxlcheckpoint.MaxSignedLong {
		return 0, fmt.Errorf("%w: %s offset addition overflows", ErrGeometryBounds, name)
	}
	return offset, nil
}

// DataPageIndex converts an exact 4 KiB-aligned content address back to the
// device-relative page index. Host paths and virtual addresses are never part
// of the persisted identity.
func (geometry DeviceGeometry) DataPageIndex(contentOffset uint64) (uint64, error) {
	if contentOffset < geometry.ContentRegionBase {
		return 0, fmt.Errorf("%w: content offset precedes the content region", ErrGeometryBounds)
	}
	delta := contentOffset - geometry.ContentRegionBase
	if delta%uint64(ContentPageBytes) != 0 {
		return 0, fmt.Errorf("%w: content offset is not 4 KiB aligned", ErrGeometryBounds)
	}
	index := delta / uint64(ContentPageBytes)
	if index >= geometry.DataPageCount {
		return 0, fmt.Errorf("%w: content offset exceeds the content region", ErrGeometryBounds)
	}
	return index, nil
}

func calculateDeviceGeometryUnchecked(
	deviceBytes,
	allocatorSnapshotSlotBytes,
	ownerStateSnapshotSlotBytes uint64,
) (DeviceGeometry, error) {
	if deviceBytes == 0 || deviceBytes > cxlcheckpoint.MaxSignedLong ||
		allocatorSnapshotSlotBytes < MinAllocatorSnapshotSlotBytes ||
		allocatorSnapshotSlotBytes > MaxAllocatorSnapshotSlotBytes ||
		allocatorSnapshotSlotBytes%uint64(ContentPageBytes) != 0 ||
		ownerStateSnapshotSlotBytes < MinOwnerStateSnapshotSlotBytes ||
		ownerStateSnapshotSlotBytes > MaxOwnerStateSnapshotSlotBytes ||
		ownerStateSnapshotSlotBytes%uint64(ContentPageBytes) != 0 {
		return DeviceGeometry{}, geometryInvalidf("geometry inputs are invalid")
	}
	superblockBytes := SuperblockSlotBytes * SuperblockSlotCount
	allocatorBytes, ok := checkedMul(allocatorSnapshotSlotBytes, AllocatorSnapshotSlotCount)
	if !ok {
		return DeviceGeometry{}, geometryInvalidf("allocator snapshot region overflows")
	}
	controlBytes, ok := checkedAdd(superblockBytes, allocatorBytes)
	ownerStateBytes, ownerStateOK := checkedMul(ownerStateSnapshotSlotBytes, OwnerStateSnapshotSlotCount)
	if !ownerStateOK {
		return DeviceGeometry{}, geometryInvalidf("Owner-state snapshot region overflows")
	}
	if ok {
		controlBytes, ok = checkedAdd(controlBytes, ownerStateBytes)
	}
	if !ok || controlBytes >= deviceBytes {
		return DeviceGeometry{}, geometryInvalidf("control region exceeds the device")
	}
	bitmapPageLimit, ok := checkedMul(
		allocatorSnapshotSlotBytes-AllocatorSnapshotFixedBytes,
		8)
	if !ok {
		return DeviceGeometry{}, geometryInvalidf("allocator bitmap capacity overflows")
	}
	upper := (deviceBytes - controlBytes) / uint64(ContentPageBytes)
	if bitmapPageLimit < upper {
		upper = bitmapPageLimit
	}
	var best uint64
	low, high := uint64(1), upper
	for low <= high {
		middle := low + (high-low)/2
		_, _, end, fits := geometryEnd(controlBytes, middle)
		if fits && end <= deviceBytes {
			best = middle
			low = middle + 1
		} else {
			high = middle - 1
		}
	}
	if best == 0 {
		return DeviceGeometry{}, geometryInvalidf("device has no complete descriptor/payload pair")
	}
	descriptorBytes, contentBase, _, ok := geometryEnd(controlBytes, best)
	if !ok {
		return DeviceGeometry{}, geometryInvalidf("device layout overflows")
	}
	contentBytes, ok := checkedMul(best, uint64(ContentPageBytes))
	if !ok {
		return DeviceGeometry{}, geometryInvalidf("content region overflows")
	}
	return DeviceGeometry{
		DeviceBytes:                 deviceBytes,
		SuperblockAOffset:           0,
		SuperblockBOffset:           SuperblockSlotBytes,
		AllocatorSnapshotAOffset:    superblockBytes,
		AllocatorSnapshotBOffset:    superblockBytes + allocatorSnapshotSlotBytes,
		AllocatorSnapshotSlotBytes:  allocatorSnapshotSlotBytes,
		OwnerStateSnapshotAOffset:   superblockBytes + allocatorBytes,
		OwnerStateSnapshotBOffset:   superblockBytes + allocatorBytes + ownerStateSnapshotSlotBytes,
		OwnerStateSnapshotSlotBytes: ownerStateSnapshotSlotBytes,
		ControlRegionBytes:          controlBytes,
		DescriptorRegionBase:        controlBytes,
		DescriptorRegionBytes:       descriptorBytes,
		ContentRegionBase:           contentBase,
		ContentRegionBytes:          contentBytes,
		DataPageCount:               best,
	}, nil
}

func geometryEnd(controlBytes, pageCount uint64) (descriptorBytes, contentBase, end uint64, ok bool) {
	descriptorBytes, ok = checkedMul(pageCount, uint64(PageDescriptorBytes))
	if !ok {
		return 0, 0, 0, false
	}
	descriptorEnd, ok := checkedAdd(controlBytes, descriptorBytes)
	if !ok {
		return 0, 0, 0, false
	}
	contentBase, ok = alignUp(descriptorEnd, uint64(ContentPageBytes))
	if !ok {
		return 0, 0, 0, false
	}
	contentBytes, ok := checkedMul(pageCount, uint64(ContentPageBytes))
	if !ok {
		return 0, 0, 0, false
	}
	end, ok = checkedAdd(contentBase, contentBytes)
	return descriptorBytes, contentBase, end, ok
}

func alignUp(value, alignment uint64) (uint64, bool) {
	if alignment == 0 || alignment&(alignment-1) != 0 {
		return 0, false
	}
	mask := alignment - 1
	if value > math.MaxUint64-mask {
		return 0, false
	}
	return (value + mask) &^ mask, true
}

func checkedAdd(left, right uint64) (uint64, bool) {
	if left > math.MaxUint64-right {
		return 0, false
	}
	return left + right, true
}

func checkedMul(left, right uint64) (uint64, bool) {
	if left != 0 && right > math.MaxUint64/left {
		return 0, false
	}
	return left * right, true
}

func geometryInvalidf(format string, arguments ...interface{}) error {
	return fmt.Errorf("%w: %s", ErrInvalidGeometry, fmt.Sprintf(format, arguments...))
}

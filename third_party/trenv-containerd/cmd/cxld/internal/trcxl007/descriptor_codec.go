package trcxl007

import (
	"encoding/binary"
	"fmt"
	"hash/crc32"

	"github.com/containerd/containerd/third_party/trenv-containerd/pkg/cxlcheckpoint"
)

const (
	paddedPageCRC32COffset      = 0
	descriptorCRC32COffset      = 4
	allocationRecordIDOffset    = 8
	originObjectIDOffset        = 16
	contentReferenceCountOffset = 24
	ownerTransactionSeqOffset   = 32
	payloadLengthOffset         = 40
	stateOffset                 = 44
	contentKindOffset           = 45
	flagsOffset                 = 46
	reservedOffset              = 48
)

var (
	crc32cTable            = crc32.MakeTable(crc32.Castagnoli)
	zeroContentPage        [ContentPageBytes]byte
	zeroContentPageCRC32C  = crc32.Checksum(zeroContentPage[:], crc32cTable)
	zeroDescriptorCRCField [4]byte
)

// MarshalBinary emits the one canonical 64-byte little-endian descriptor.
// The descriptor CRC32C is calculated with bytes 4..7 treated as zero.
func (descriptor Descriptor) MarshalBinary() ([]byte, error) {
	if err := validateCompiledDescriptorContract(); err != nil {
		return nil, err
	}
	if err := descriptor.Validate(); err != nil {
		return nil, err
	}
	wire := make([]byte, PageDescriptorBytes)
	if descriptor.State == DescriptorFree {
		return wire, nil
	}

	binary.LittleEndian.PutUint32(wire[paddedPageCRC32COffset:], descriptor.PaddedPageCRC32C)
	binary.LittleEndian.PutUint64(wire[allocationRecordIDOffset:], descriptor.AllocationRecordID)
	binary.LittleEndian.PutUint64(wire[originObjectIDOffset:], descriptor.OriginObjectID)
	binary.LittleEndian.PutUint64(wire[contentReferenceCountOffset:], descriptor.ContentReferenceCount)
	binary.LittleEndian.PutUint64(wire[ownerTransactionSeqOffset:], descriptor.OwnerTransactionSeq)
	binary.LittleEndian.PutUint32(wire[payloadLengthOffset:], descriptor.PayloadLength)
	wire[stateOffset] = byte(descriptor.State)
	wire[contentKindOffset] = byte(descriptor.ContentKind)
	binary.LittleEndian.PutUint16(wire[flagsOffset:], descriptor.Flags)
	binary.LittleEndian.PutUint32(wire[descriptorCRC32COffset:], descriptorCRC32C(wire))
	return wire, nil
}

// ParseDescriptor accepts exactly one canonical descriptor. FREE is the
// explicit all-zero exception; every other state must pass integrity,
// reserved-byte, signed-range, and state/kind validation.
func ParseDescriptor(wire []byte) (Descriptor, error) {
	if err := validateCompiledDescriptorContract(); err != nil {
		return Descriptor{}, err
	}
	if len(wire) != PageDescriptorBytes {
		return Descriptor{}, corruptDescriptorf(
			"descriptor length %d does not equal %d", len(wire), PageDescriptorBytes)
	}
	if allZero(wire) {
		return Descriptor{}, nil
	}

	storedDescriptorCRC32C := binary.LittleEndian.Uint32(wire[descriptorCRC32COffset:])
	computedDescriptorCRC32C := descriptorCRC32C(wire)
	if storedDescriptorCRC32C != computedDescriptorCRC32C {
		return Descriptor{}, corruptDescriptorf(
			"descriptor CRC32C %#08x does not equal computed CRC32C %#08x",
			storedDescriptorCRC32C,
			computedDescriptorCRC32C)
	}
	if !allZero(wire[reservedOffset:PageDescriptorBytes]) {
		return Descriptor{}, corruptDescriptorf("reserved bytes 48..63 must be zero")
	}

	descriptor := Descriptor{
		PaddedPageCRC32C:      binary.LittleEndian.Uint32(wire[paddedPageCRC32COffset:]),
		AllocationRecordID:    binary.LittleEndian.Uint64(wire[allocationRecordIDOffset:]),
		OriginObjectID:        binary.LittleEndian.Uint64(wire[originObjectIDOffset:]),
		ContentReferenceCount: binary.LittleEndian.Uint64(wire[contentReferenceCountOffset:]),
		OwnerTransactionSeq:   binary.LittleEndian.Uint64(wire[ownerTransactionSeqOffset:]),
		PayloadLength:         binary.LittleEndian.Uint32(wire[payloadLengthOffset:]),
		State:                 DescriptorState(wire[stateOffset]),
		ContentKind:           cxlcheckpoint.ContentKindV7(wire[contentKindOffset]),
		Flags:                 binary.LittleEndian.Uint16(wire[flagsOffset:]),
	}
	if descriptor.State == DescriptorFree {
		return Descriptor{}, invalidDescriptorf("FREE wire must be the canonical all-zero descriptor")
	}
	if err := descriptor.Validate(); err != nil {
		return Descriptor{}, err
	}
	return descriptor, nil
}

func validateCompiledDescriptorContract() error {
	if cxlcheckpoint.V7StorageDeviceFormatMagicString != "TRCXL007" ||
		cxlcheckpoint.V7StorageDeviceFormatVersion != 7 ||
		PageDescriptorBytes != 64 || ContentPageBytes != 4096 ||
		cxlcheckpoint.V7StoragePageDescriptorABI != "trcxl007-page-descriptor-little-endian-v2" ||
		cxlcheckpoint.V7StorageFingerprintAlgorithm != "crc32c-castagnoli" ||
		cxlcheckpoint.V7StorageFingerprintPolynomial != "0x11edc6f41" {
		return invalidDescriptorf("compiled V7 storage constants do not name the required TRCXL007 ABI")
	}
	return nil
}

func descriptorCRC32C(wire []byte) uint32 {
	if len(wire) != PageDescriptorBytes {
		return 0
	}
	checksum := crc32.Update(0, crc32cTable, wire[:descriptorCRC32COffset])
	checksum = crc32.Update(checksum, crc32cTable, zeroDescriptorCRCField[:])
	return crc32.Update(checksum, crc32cTable, wire[descriptorCRC32COffset+4:])
}

func paddedContentPageCRC32C(content []byte) (uint32, error) {
	if len(content) > ContentPageBytes {
		return 0, fmt.Errorf(
			"%w: meaningful content length %d exceeds %d",
			ErrInvalidContentPage,
			len(content),
			ContentPageBytes)
	}
	checksum := crc32.Update(0, crc32cTable, content)
	return crc32.Update(checksum, crc32cTable, zeroContentPage[:ContentPageBytes-len(content)]), nil
}

func allZero(value []byte) bool {
	for _, current := range value {
		if current != 0 {
			return false
		}
	}
	return true
}

func corruptDescriptorf(format string, arguments ...interface{}) error {
	return fmt.Errorf("%w: %s", ErrCorruptDescriptor, fmt.Sprintf(format, arguments...))
}

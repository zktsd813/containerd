package trcxl007

import (
	"errors"
	"fmt"

	"github.com/containerd/containerd/third_party/trenv-containerd/pkg/cxlcheckpoint"
)

const (
	// PageDescriptorBytes and ContentPageBytes are fixed by the TRCXL007 V7
	// storage contract. They are aliases of the canonical contract constants,
	// not a second format definition.
	PageDescriptorBytes = int(cxlcheckpoint.V7StoragePageDescriptorBytes)
	ContentPageBytes    = int(cxlcheckpoint.V7StoragePageSize)
)

var (
	// ErrInvalidDescriptor identifies a structurally decoded descriptor whose
	// state, identity, kind, length, or reference-count semantics are invalid.
	ErrInvalidDescriptor = errors.New("invalid TRCXL007 page descriptor")
	// ErrCorruptDescriptor identifies wrong-sized, torn, checksummed, or
	// nonzero-reserved descriptor bytes.
	ErrCorruptDescriptor = errors.New("corrupt TRCXL007 page descriptor")
	// ErrInvalidContentPage identifies content that does not have the exact
	// meaningful length and zero-padded CRC32C committed by a descriptor.
	ErrInvalidContentPage = errors.New("invalid TRCXL007 content page")
)

// DescriptorState is the complete persisted TRCXL007 page lifecycle. There is
// deliberately no per-page generation: allocation and reclamation authority
// belongs to the checkpoint/allocation transaction rather than this record.
type DescriptorState uint8

const (
	DescriptorFree DescriptorState = iota
	DescriptorReserved
	DescriptorImmutableSealed
	DescriptorEmptySlot
	DescriptorPublishedSlot
	DescriptorRetiring
	DescriptorQuarantined
)

func (state DescriptorState) valid() bool {
	return state >= DescriptorFree && state <= DescriptorQuarantined
}

// Descriptor is the logical form of one exact 64-byte little-endian
// TRCXL007 page descriptor. Descriptor integrity CRC32C and the reserved tail
// are wire-only canonical fields and therefore are not caller-controlled.
type Descriptor struct {
	PaddedPageCRC32C      uint32
	AllocationRecordID    uint64
	OriginObjectID        uint64
	ContentReferenceCount uint64
	OwnerTransactionSeq   uint64
	PayloadLength         uint32
	State                 DescriptorState
	ContentKind           cxlcheckpoint.ContentKindV7
	Flags                 uint16
}

// Validate enforces the complete logical descriptor contract without reading
// a content page. MarshalBinary calls it before producing any bytes.
func (descriptor Descriptor) Validate() error {
	if !descriptor.State.valid() {
		return invalidDescriptorf("state %d is outside FREE..QUARANTINED", descriptor.State)
	}
	if descriptor.State == DescriptorFree {
		if descriptor != (Descriptor{}) {
			return invalidDescriptorf("FREE must be the canonical all-zero descriptor")
		}
		return nil
	}

	if descriptor.Flags != 0 {
		return invalidDescriptorf("flags %#x must be zero", descriptor.Flags)
	}
	if err := validateRequiredSignedIdentity("allocation record ID", descriptor.AllocationRecordID); err != nil {
		return err
	}
	if err := validateRequiredSignedIdentity("origin object ID", descriptor.OriginObjectID); err != nil {
		return err
	}
	if err := validateRequiredSignedIdentity("Owner transaction sequence", descriptor.OwnerTransactionSeq); err != nil {
		return err
	}
	if descriptor.ContentReferenceCount > cxlcheckpoint.MaxSignedLong {
		return invalidDescriptorf(
			"content reference count %d exceeds %d",
			descriptor.ContentReferenceCount,
			cxlcheckpoint.MaxSignedLong)
	}
	if !validContentKind(descriptor.ContentKind) {
		return invalidDescriptorf("content kind %d is outside the nine-kind V7 contract", descriptor.ContentKind)
	}
	if uint64(descriptor.PayloadLength) > cxlcheckpoint.V7StoragePageSize {
		return invalidDescriptorf(
			"payload length %d exceeds one %d-byte page",
			descriptor.PayloadLength,
			cxlcheckpoint.V7StoragePageSize)
	}

	switch descriptor.State {
	case DescriptorReserved:
		if descriptor.PaddedPageCRC32C != 0 || descriptor.ContentReferenceCount != 0 ||
			descriptor.PayloadLength != 0 {
			return invalidDescriptorf("RESERVED must have zero page CRC32C, reference count, and payload length")
		}
	case DescriptorImmutableSealed:
		if placementSlotKind(descriptor.ContentKind) {
			return invalidDescriptorf("IMMUTABLE_SEALED excludes mutable placement slot kinds")
		}
		if descriptor.PayloadLength == 0 || descriptor.ContentReferenceCount == 0 {
			return invalidDescriptorf("IMMUTABLE_SEALED requires meaningful content and a positive reference count")
		}
		if descriptor.ContentKind == cxlcheckpoint.ContentMemoryPayloadV7 &&
			descriptor.PayloadLength != uint32(cxlcheckpoint.V7StoragePageSize) {
			return invalidDescriptorf("IMMUTABLE_SEALED memory content must contain exactly one 4 KiB page")
		}
	case DescriptorEmptySlot:
		if !placementSlotKind(descriptor.ContentKind) {
			return invalidDescriptorf("EMPTY_SLOT requires placement slot A or B")
		}
		if descriptor.PayloadLength != 0 || descriptor.ContentReferenceCount != 0 {
			return invalidDescriptorf("EMPTY_SLOT requires zero payload length and reference count")
		}
		if descriptor.PaddedPageCRC32C != zeroContentPageCRC32C {
			return invalidDescriptorf(
				"EMPTY_SLOT page CRC32C %#08x does not equal the zero-page CRC32C %#08x",
				descriptor.PaddedPageCRC32C,
				zeroContentPageCRC32C)
		}
	case DescriptorPublishedSlot:
		if !placementSlotKind(descriptor.ContentKind) {
			return invalidDescriptorf("PUBLISHED_SLOT requires placement slot A or B")
		}
		if descriptor.PayloadLength == 0 || descriptor.ContentReferenceCount == 0 {
			return invalidDescriptorf("PUBLISHED_SLOT requires meaningful content and a positive reference count")
		}
	case DescriptorRetiring, DescriptorQuarantined:
		// These states retain their prior identity, kind, bounded length, and
		// bounded reference count for diagnosis and checkpoint-level reclaim.
		// Zero length/reference count remain representable because quarantine
		// may capture an incomplete transition.
	default:
		return invalidDescriptorf("state %d has no validation rule", descriptor.State)
	}
	return nil
}

// ValidateContentPage verifies meaningful content bytes against the exact
// zero-padded 4 KiB CRC32C stored in this descriptor. CRC32C is only
// DSA-compatible candidate/corruption metadata; it is neither content-equality
// proof nor authentication.
func (descriptor Descriptor) ValidateContentPage(content []byte) error {
	if err := descriptor.Validate(); err != nil {
		return fmt.Errorf("%w: descriptor: %v", ErrInvalidContentPage, err)
	}
	if descriptor.State == DescriptorFree || descriptor.State == DescriptorReserved ||
		descriptor.State == DescriptorQuarantined {
		return fmt.Errorf("%w: state %d has no readable sealed content", ErrInvalidContentPage, descriptor.State)
	}
	if len(content) != int(descriptor.PayloadLength) {
		return fmt.Errorf(
			"%w: meaningful content length %d does not equal descriptor length %d",
			ErrInvalidContentPage,
			len(content),
			descriptor.PayloadLength)
	}
	checksum, err := paddedContentPageCRC32C(content)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidContentPage, err)
	}
	if checksum != descriptor.PaddedPageCRC32C {
		return fmt.Errorf(
			"%w: zero-padded page CRC32C %#08x does not equal descriptor CRC32C %#08x",
			ErrInvalidContentPage,
			checksum,
			descriptor.PaddedPageCRC32C)
	}
	return nil
}

// BuildImmutableContentPageDescriptor seals one immutable non-slot page.
// Memory content is exactly 4 KiB; artifact, restore, and pinned-control tails
// may contain 1..4096 meaningful bytes and are CRC32C-covered with zero padding.
func BuildImmutableContentPageDescriptor(
	allocationRecordID uint64,
	originObjectID uint64,
	contentReferenceCount uint64,
	ownerTransactionSeq uint64,
	kind cxlcheckpoint.ContentKindV7,
	content []byte,
) (Descriptor, error) {
	if len(content) == 0 || len(content) > ContentPageBytes {
		return Descriptor{}, invalidDescriptorf(
			"immutable content length %d is outside 1..%d", len(content), ContentPageBytes)
	}
	checksum, err := paddedContentPageCRC32C(content)
	if err != nil {
		return Descriptor{}, err
	}
	descriptor := Descriptor{
		PaddedPageCRC32C:      checksum,
		AllocationRecordID:    allocationRecordID,
		OriginObjectID:        originObjectID,
		ContentReferenceCount: contentReferenceCount,
		OwnerTransactionSeq:   ownerTransactionSeq,
		PayloadLength:         uint32(len(content)),
		State:                 DescriptorImmutableSealed,
		ContentKind:           kind,
	}
	if err := descriptor.Validate(); err != nil {
		return Descriptor{}, err
	}
	return descriptor, nil
}

// BuildEmptySlotPageDescriptor creates canonical zero-content placement slot
// A or B metadata. The CRC32C covers the complete zero-filled 4 KiB page.
func BuildEmptySlotPageDescriptor(
	allocationRecordID uint64,
	originObjectID uint64,
	ownerTransactionSeq uint64,
	kind cxlcheckpoint.ContentKindV7,
) (Descriptor, error) {
	descriptor := Descriptor{
		PaddedPageCRC32C:    zeroContentPageCRC32C,
		AllocationRecordID:  allocationRecordID,
		OriginObjectID:      originObjectID,
		OwnerTransactionSeq: ownerTransactionSeq,
		State:               DescriptorEmptySlot,
		ContentKind:         kind,
	}
	if err := descriptor.Validate(); err != nil {
		return Descriptor{}, err
	}
	return descriptor, nil
}

// BuildPublishedSlotPageDescriptor seals meaningful placement-map bytes in
// slot A or B and CRC32C-covers the zero-padded 4 KiB content page.
func BuildPublishedSlotPageDescriptor(
	allocationRecordID uint64,
	originObjectID uint64,
	contentReferenceCount uint64,
	ownerTransactionSeq uint64,
	kind cxlcheckpoint.ContentKindV7,
	content []byte,
) (Descriptor, error) {
	if len(content) == 0 || len(content) > ContentPageBytes {
		return Descriptor{}, invalidDescriptorf(
			"published slot content length %d is outside 1..%d", len(content), ContentPageBytes)
	}
	checksum, err := paddedContentPageCRC32C(content)
	if err != nil {
		return Descriptor{}, err
	}
	descriptor := Descriptor{
		PaddedPageCRC32C:      checksum,
		AllocationRecordID:    allocationRecordID,
		OriginObjectID:        originObjectID,
		ContentReferenceCount: contentReferenceCount,
		OwnerTransactionSeq:   ownerTransactionSeq,
		PayloadLength:         uint32(len(content)),
		State:                 DescriptorPublishedSlot,
		ContentKind:           kind,
	}
	if err := descriptor.Validate(); err != nil {
		return Descriptor{}, err
	}
	return descriptor, nil
}

func validContentKind(kind cxlcheckpoint.ContentKindV7) bool {
	return kind >= cxlcheckpoint.V7StorageFirstContentKind && kind <= cxlcheckpoint.V7StorageLastContentKind
}

func placementSlotKind(kind cxlcheckpoint.ContentKindV7) bool {
	return kind == cxlcheckpoint.ContentPlacementSlotAV7 || kind == cxlcheckpoint.ContentPlacementSlotBV7
}

func validateRequiredSignedIdentity(name string, value uint64) error {
	if value == 0 || value > cxlcheckpoint.MaxSignedLong {
		return invalidDescriptorf("%s %d is outside 1..%d", name, value, cxlcheckpoint.MaxSignedLong)
	}
	return nil
}

func invalidDescriptorf(format string, arguments ...interface{}) error {
	return fmt.Errorf("%w: %s", ErrInvalidDescriptor, fmt.Sprintf(format, arguments...))
}

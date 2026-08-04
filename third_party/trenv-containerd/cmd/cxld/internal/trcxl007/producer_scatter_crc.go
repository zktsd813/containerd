package trcxl007

import (
	"encoding/binary"
	"errors"
	"fmt"
)

const (
	// ProducerScatterCRCBytesPerPage is the exact raw-vector density. The
	// vector has no header and repeats no page, device, owner, or offset data.
	ProducerScatterCRCBytesPerPage = 4
)

var ErrInvalidProducerScatterCRCVector = errors.New("invalid TRCXL007 Producer CRC32C vector")

// ProducerScatterCRCVector is a detached raw little-endian CRC32C vector in
// checkpoint-global logical-capacity-page order. It is an execution result,
// not a descriptor array and not yet a shared-DAX metadata layout.
type ProducerScatterCRCVector struct {
	totalPages uint64
	raw        []byte
}

// ParseProducerScatterCRCVector validates and defensively copies an exact raw
// vector. A CRC value of zero is valid and is never treated as an unwritten
// sentinel.
func ParseProducerScatterCRCVector(
	raw []byte,
	totalPages uint64,
) (ProducerScatterCRCVector, error) {
	want, err := producerScatterCRCVectorLength(totalPages)
	if err != nil {
		return ProducerScatterCRCVector{}, err
	}
	if len(raw) != want {
		return ProducerScatterCRCVector{}, fmt.Errorf(
			"%w: raw length %d, want %d for %d pages",
			ErrInvalidProducerScatterCRCVector, len(raw), want, totalPages)
	}
	return ProducerScatterCRCVector{
		totalPages: totalPages,
		raw:        append([]byte(nil), raw...),
	}, nil
}

func parseProducerScatterCRCVectorOwned(
	raw []byte,
	totalPages uint64,
) (ProducerScatterCRCVector, error) {
	want, err := producerScatterCRCVectorLength(totalPages)
	if err != nil {
		return ProducerScatterCRCVector{}, err
	}
	if len(raw) != want {
		return ProducerScatterCRCVector{}, fmt.Errorf(
			"%w: raw length %d, want %d", ErrInvalidProducerScatterCRCVector, len(raw), want)
	}
	return ProducerScatterCRCVector{totalPages: totalPages, raw: raw}, nil
}

func (vector ProducerScatterCRCVector) TotalPages() uint64 { return vector.totalPages }

// Bytes returns a defensive copy of the headerless raw vector.
func (vector ProducerScatterCRCVector) Bytes() []byte {
	return append([]byte(nil), vector.raw...)
}

// CRC32C returns the value at one checkpoint-global logical page.
func (vector ProducerScatterCRCVector) CRC32C(logicalPage uint64) (uint32, error) {
	want, err := producerScatterCRCVectorLength(vector.totalPages)
	if err != nil || len(vector.raw) != want {
		if err == nil {
			err = fmt.Errorf("raw length %d, want %d", len(vector.raw), want)
		}
		return 0, fmt.Errorf("%w: %v", ErrInvalidProducerScatterCRCVector, err)
	}
	if logicalPage >= vector.totalPages {
		return 0, fmt.Errorf("%w: logical page %d exceeds %d",
			ErrInvalidProducerScatterCRCVector, logicalPage, vector.totalPages)
	}
	offset, ok := checkedMul(logicalPage, uint64(ProducerScatterCRCBytesPerPage))
	if !ok || offset > uint64(len(vector.raw)-ProducerScatterCRCBytesPerPage) {
		return 0, fmt.Errorf("%w: logical page offset overflows", ErrInvalidProducerScatterCRCVector)
	}
	return binary.LittleEndian.Uint32(
		vector.raw[int(offset) : int(offset)+ProducerScatterCRCBytesPerPage]), nil
}

// Clone returns a fully detached vector.
func (vector ProducerScatterCRCVector) Clone() ProducerScatterCRCVector {
	return ProducerScatterCRCVector{
		totalPages: vector.totalPages,
		raw:        append([]byte(nil), vector.raw...),
	}
}

func producerScatterCRCVectorLength(totalPages uint64) (int, error) {
	if totalPages == 0 {
		return 0, fmt.Errorf("%w: total pages is zero", ErrInvalidProducerScatterCRCVector)
	}
	length, ok := checkedMul(totalPages, uint64(ProducerScatterCRCBytesPerPage))
	if !ok {
		return 0, fmt.Errorf("%w: byte length overflows uint64", ErrInvalidProducerScatterCRCVector)
	}
	maximumInt := uint64(^uint(0) >> 1)
	if length > maximumInt {
		return 0, fmt.Errorf("%w: byte length %d exceeds host int %d",
			ErrInvalidProducerScatterCRCVector, length, maximumInt)
	}
	return int(length), nil
}

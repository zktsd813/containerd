package trcxl007

import (
	"encoding/binary"
	"errors"
	"math"
	"testing"
)

func TestProducerScatterCRCVectorRawLittleEndianAndDefensiveParsing(t *testing.T) {
	raw := make([]byte, 12)
	binary.LittleEndian.PutUint32(raw[0:4], 0)
	binary.LittleEndian.PutUint32(raw[4:8], 0x11223344)
	binary.LittleEndian.PutUint32(raw[8:12], 0x98f94189)
	vector, err := ParseProducerScatterCRCVector(raw, 3)
	if err != nil {
		t.Fatalf("ParseProducerScatterCRCVector: %v", err)
	}
	raw[4] ^= 0xff
	want := []uint32{0, 0x11223344, 0x98f94189}
	for page, expected := range want {
		got, err := vector.CRC32C(uint64(page))
		if err != nil || got != expected {
			t.Fatalf("CRC32C(%d) = %#08x, %v, want %#08x", page, got, err, expected)
		}
	}
	copyOfRaw := vector.Bytes()
	copyOfRaw[0] = 0xff
	got, _ := vector.CRC32C(0)
	if got != 0 {
		t.Fatalf("Bytes aliases vector: CRC[0] = %#08x", got)
	}
	clone := vector.Clone()
	clone.raw[8] ^= 0xff
	got, _ = vector.CRC32C(2)
	if got != 0x98f94189 {
		t.Fatalf("Clone aliases vector: CRC[2] = %#08x", got)
	}
}

func TestProducerScatterCRCVectorRejectsWrongLengthRangeAndOverflow(t *testing.T) {
	maximumInt := uint64(^uint(0) >> 1)
	for _, test := range []struct {
		name  string
		raw   []byte
		pages uint64
	}{
		{"zero-pages", nil, 0},
		{"short", make([]byte, 7), 2},
		{"long", make([]byte, 9), 2},
		{"host-int-overflow", nil, maximumInt/ProducerScatterCRCBytesPerPage + 1},
		{"multiply-overflow", nil, math.MaxUint64},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := ParseProducerScatterCRCVector(test.raw, test.pages); !errors.Is(err, ErrInvalidProducerScatterCRCVector) {
				t.Fatalf("error = %v", err)
			}
		})
	}
	vector, err := ParseProducerScatterCRCVector(make([]byte, 8), 2)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := vector.CRC32C(2); !errors.Is(err, ErrInvalidProducerScatterCRCVector) {
		t.Fatalf("out-of-range error = %v", err)
	}
	vector.raw = vector.raw[:4]
	if _, err := vector.CRC32C(0); !errors.Is(err, ErrInvalidProducerScatterCRCVector) {
		t.Fatalf("mutated-vector error = %v", err)
	}
}

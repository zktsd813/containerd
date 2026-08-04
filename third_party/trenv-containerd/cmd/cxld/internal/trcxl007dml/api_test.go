package trcxl007dml

import (
	"errors"
	"strings"
	"testing"
)

func TestValidatePageBuffers(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		dst  []byte
		src  []byte
		want error
	}{
		{
			name: "separate pages",
			dst:  make([]byte, PageSize),
			src:  make([]byte, PageSize),
		},
		{
			name: "adjacent pages in one allocation",
			dst:  make([]byte, PageSize*2)[:PageSize],
			src:  make([]byte, PageSize),
		},
		{
			name: "short destination",
			dst:  make([]byte, PageSize-1),
			src:  make([]byte, PageSize),
			want: ErrInvalidPage,
		},
		{
			name: "long destination",
			dst:  make([]byte, PageSize+1),
			src:  make([]byte, PageSize),
			want: ErrInvalidPage,
		},
		{
			name: "short source",
			dst:  make([]byte, PageSize),
			src:  make([]byte, PageSize-1),
			want: ErrInvalidPage,
		},
		{
			name: "long source",
			dst:  make([]byte, PageSize),
			src:  make([]byte, PageSize+1),
			want: ErrInvalidPage,
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			err := validatePageBuffers(test.dst, test.src)
			if !errors.Is(err, test.want) {
				t.Fatalf("validatePageBuffers() error = %v, want %v", err, test.want)
			}
		})
	}
}

func TestValidatePageBuffersRejectsAnyOverlap(t *testing.T) {
	t.Parallel()

	backing := make([]byte, PageSize+1)
	tests := []struct {
		name string
		dst  []byte
		src  []byte
	}{
		{
			name: "same page",
			dst:  backing[:PageSize],
			src:  backing[:PageSize],
		},
		{
			name: "destination begins first",
			dst:  backing[:PageSize],
			src:  backing[1:],
		},
		{
			name: "source begins first",
			dst:  backing[1:],
			src:  backing[:PageSize],
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if err := validatePageBuffers(test.dst, test.src); !errors.Is(err, ErrOverlappingPages) {
				t.Fatalf("validatePageBuffers() error = %v, want ErrOverlappingPages", err)
			}
		})
	}
}

func TestValidatePageBuffersAcceptsAdjacentSlices(t *testing.T) {
	t.Parallel()

	backing := make([]byte, PageSize*2)
	if err := validatePageBuffers(backing[:PageSize], backing[PageSize:]); err != nil {
		t.Fatalf("validatePageBuffers() error = %v", err)
	}
}

func TestStatusErrorClassification(t *testing.T) {
	t.Parallel()

	err := newStatusError(ErrHardwareCopy, "copy", 123)
	if !errors.Is(err, ErrHardwareCopy) {
		t.Fatalf("errors.Is(%v, ErrHardwareCopy) = false", err)
	}
	if errors.Is(err, ErrHardwareInitialization) {
		t.Fatalf("errors.Is(%v, ErrHardwareInitialization) = true", err)
	}
	if !strings.Contains(err.Error(), "copy returned DML status 123") {
		t.Fatalf("error %q does not include operation and status", err)
	}
}

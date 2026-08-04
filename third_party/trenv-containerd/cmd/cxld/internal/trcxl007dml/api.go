// Package trcxl007dml provides the fail-closed Intel DML page-copy boundary
// used by the TRCXL007 producer path.
//
// The production implementation accepts exactly one 4 KiB page per call and
// returns the CRC32C/Castagnoli checksum of the bytes copied to the
// destination. It deliberately has no software or CPU fallback.
package trcxl007dml

import (
	"errors"
	"fmt"
	"unsafe"
)

const (
	// PageSize is the only source and destination size accepted by Copier.
	PageSize = 4096
)

var (
	// ErrHardwareBackendNotBuilt means the binary was built without the
	// trenv_v7_dml_hw build tag.
	ErrHardwareBackendNotBuilt = errors.New("TRCXL007 Intel DML hardware backend was not built")
	// ErrInvalidPage means either source or destination is not exactly PageSize.
	ErrInvalidPage = errors.New("TRCXL007 Intel DML requires exact 4096-byte pages")
	// ErrOverlappingPages means source and destination overlap in memory.
	ErrOverlappingPages = errors.New("TRCXL007 Intel DML source and destination overlap")
	// ErrHardwareUnavailable means no usable Intel DSA hardware path or work
	// queue was available.
	ErrHardwareUnavailable = errors.New("TRCXL007 Intel DML hardware is unavailable")
	// ErrHardwareInitialization means the hardware-only DML job could not be
	// initialized for a reason other than hardware availability.
	ErrHardwareInitialization = errors.New("TRCXL007 Intel DML hardware initialization failed")
	// ErrHardwareSelfTest means the hardware known-answer COPY_CRC test failed.
	ErrHardwareSelfTest = errors.New("TRCXL007 Intel DML hardware self-test failed")
	// ErrHardwareCopy means a hardware COPY_CRC operation failed.
	ErrHardwareCopy = errors.New("TRCXL007 Intel DML hardware COPY_CRC failed")
	// ErrClosed means CopyPage was called after Copier.Close.
	ErrClosed = errors.New("TRCXL007 Intel DML copier is closed")
)

// Copier copies one exact 4 KiB source page to one non-overlapping exact 4 KiB
// destination page and returns the CRC32C/Castagnoli checksum of the copied
// bytes. Implementations serialize concurrent calls. Close is idempotent.
type Copier interface {
	CopyPage(dst, src []byte) (uint32, error)
	Close() error
}

type statusError struct {
	kind      error
	related   []error
	operation string
	status    uint32
}

func (e *statusError) Error() string {
	return fmt.Sprintf("%s: %s returned DML status %d", e.kind, e.operation, e.status)
}

func (e *statusError) Unwrap() error {
	return e.kind
}

func (e *statusError) Is(target error) bool {
	for _, related := range e.related {
		if errors.Is(related, target) {
			return true
		}
	}
	return false
}

func newStatusError(kind error, operation string, status uint32) error {
	return newClassifiedStatusError(kind, operation, status)
}

func newClassifiedStatusError(kind error, operation string, status uint32, related ...error) error {
	return &statusError{
		kind:      kind,
		related:   related,
		operation: operation,
		status:    status,
	}
}

func validatePageBuffers(dst, src []byte) error {
	if len(dst) != PageSize || len(src) != PageSize {
		return fmt.Errorf("%w: destination=%d source=%d", ErrInvalidPage, len(dst), len(src))
	}

	dstStart := uintptr(unsafe.Pointer(&dst[0]))
	srcStart := uintptr(unsafe.Pointer(&src[0]))
	dstEnd := dstStart + uintptr(PageSize)
	srcEnd := srcStart + uintptr(PageSize)
	if dstStart < srcEnd && srcStart < dstEnd {
		return ErrOverlappingPages
	}
	return nil
}

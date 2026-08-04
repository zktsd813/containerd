//go:build trenv_v7_dml_hw && linux && amd64 && cgo
// +build trenv_v7_dml_hw,linux,amd64,cgo

package trcxl007dml

import (
	"errors"
	"testing"
)

func TestHardwareCopierCloseIsIdempotent(t *testing.T) {
	copier := &hardwareCopier{}
	if err := copier.Close(); err != nil {
		t.Fatalf("first Close() error = %v", err)
	}
	if err := copier.Close(); err != nil {
		t.Fatalf("second Close() error = %v", err)
	}
	if _, err := copier.CopyPage(make([]byte, PageSize), make([]byte, PageSize)); !errors.Is(err, ErrClosed) {
		t.Fatalf("CopyPage() after Close error = %v, want ErrClosed", err)
	}
}

func TestHardwareInitializationErrorClassification(t *testing.T) {
	t.Parallel()

	for _, status := range []uint32{
		dmlStatusLibAccelNotFound,
		dmlStatusWorkQueuesNotAvailable,
		dmlStatusInitializationUnsupported,
	} {
		err := hardwareInitializationError("initialize", status)
		if !errors.Is(err, ErrHardwareUnavailable) {
			t.Errorf("status %d error = %v, want ErrHardwareUnavailable", status, err)
		}
	}

	for _, status := range []uint32{6, dmlStatusLibAccelError} {
		err := hardwareInitializationError("initialize", status)
		if !errors.Is(err, ErrHardwareInitialization) {
			t.Errorf("status %d error = %v, want ErrHardwareInitialization", status, err)
		}
	}
}

func TestHardwareCopyStatusErrorClassification(t *testing.T) {
	t.Parallel()

	for _, status := range []uint32{
		dmlStatusLibAccelNotFound,
		dmlStatusWorkQueuesNotAvailable,
		dmlStatusInitializationUnsupported,
		dmlStatusWorkQueueOverflow,
		dmlStatusTrafficClassANotAvailable,
		dmlStatusTrafficClassBNotAvailable,
		dmlStatusOperationNotSupportedByWQ,
	} {
		err := hardwareCopyStatusError("copy", status)
		if !errors.Is(err, ErrHardwareCopy) || !errors.Is(err, ErrHardwareUnavailable) {
			t.Errorf("status %d error = %v, want Copy and Unavailable", status, err)
		}
	}

	err := hardwareCopyStatusError("copy", dmlStatusLibAccelError)
	if !errors.Is(err, ErrHardwareCopy) || !errors.Is(err, ErrHardwareInitialization) {
		t.Fatalf("libaccel API error = %v, want Copy and Initialization", err)
	}
	if errors.Is(err, ErrHardwareUnavailable) {
		t.Fatalf("libaccel API error = %v, unexpectedly classified Unavailable", err)
	}
}

func TestHardwareSelfTestErrorPreservesCauseClassification(t *testing.T) {
	t.Parallel()

	err := &hardwareSelfTestError{
		cause: hardwareCopyStatusError("self-test copy", dmlStatusWorkQueuesNotAvailable),
	}
	for _, want := range []error{ErrHardwareSelfTest, ErrHardwareCopy, ErrHardwareUnavailable} {
		if !errors.Is(err, want) {
			t.Errorf("errors.Is(%v, %v) = false", err, want)
		}
	}
}

func TestHardwareJobResetErrorClassification(t *testing.T) {
	t.Parallel()

	initialization := hardwareJobResetError("reinitialize", 0, 3, dmlResetStageInitialize)
	if !errors.Is(initialization, ErrHardwareCopy) || !errors.Is(initialization, ErrHardwareInitialization) {
		t.Fatalf("reinitialize error = %v, want Copy and Initialization", initialization)
	}

	finalization := hardwareJobResetError("finalize", 0, 3, dmlResetStageFinalize)
	if !errors.Is(finalization, ErrHardwareCopy) {
		t.Fatalf("finalize error = %v, want Copy", finalization)
	}
	if errors.Is(finalization, ErrHardwareInitialization) {
		t.Fatalf("finalize error = %v, unexpectedly classified Initialization", finalization)
	}

	preserved := hardwareJobResetError(
		"finalize",
		dmlStatusWorkQueuesNotAvailable,
		3,
		dmlResetStageFinalize)
	if !errors.Is(preserved, ErrHardwareUnavailable) {
		t.Fatalf("reset error = %v, did not preserve execute Unavailable classification", preserved)
	}
}

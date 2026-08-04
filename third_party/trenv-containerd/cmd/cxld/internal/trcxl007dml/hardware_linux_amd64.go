//go:build trenv_v7_dml_hw && linux && amd64 && cgo
// +build trenv_v7_dml_hw,linux,amd64,cgo

package trcxl007dml

/*
#cgo CFLAGS: -I/usr/local/include
#cgo LDFLAGS: -L/usr/local/lib -ldml -lstdc++ -ldl -pthread

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <dml/dml.h>

_Static_assert(DML_PATH_HW == 0x00000002u, "unexpected DML_PATH_HW value");
_Static_assert(DML_OP_COPY_CRC == 0x11u, "unexpected DML_OP_COPY_CRC value");
_Static_assert(DML_FLAG_DST1_DURABLE == 0x8000u, "unexpected DML durable flag value");
_Static_assert(DML_FLAG_CRC_READ_SEED == 0x10000u, "unexpected DML CRC seed flag value");

typedef struct {
    uint32_t execute_status;
    uint32_t reset_status;
    uint8_t reset_stage;
    uint8_t job_ready;
} trenv_v7_dml_copy_result_t;

#define TRENV_V7_DML_RESET_NONE 0u
#define TRENV_V7_DML_RESET_FINALIZE 1u
#define TRENV_V7_DML_RESET_INITIALIZE 2u

static trenv_v7_dml_copy_result_t trenv_v7_dml_copy_crc(dml_job_t *job,
                                                         uint32_t job_size,
                                                         uint8_t *destination,
                                                         const uint8_t *source,
                                                         uint32_t *checksum) {
    trenv_v7_dml_copy_result_t result = {
        .execute_status = DML_STATUS_INTERNAL_ERROR,
        .reset_status = DML_STATUS_INTERNAL_ERROR,
        .reset_stage = TRENV_V7_DML_RESET_NONE,
        .job_ready = 0u,
    };

    *checksum = 0u;
    job->operation = DML_OP_COPY_CRC;
    job->source_first_ptr = (uint8_t *)source;
    job->source_second_ptr = NULL;
    job->destination_first_ptr = destination;
    job->destination_second_ptr = NULL;
    job->crc_checksum_ptr = checksum;
    job->source_length = 4096u;
    job->destination_length = 4096u;
    job->flags = DML_FLAG_CRC_READ_SEED | DML_FLAG_DST1_DURABLE;

    result.execute_status = dml_execute_job(job, DML_WAIT_MODE_BUSY_POLL);

    // DML also materializes source and destination addresses in its hidden
    // task descriptor. Finalize and clear the complete C allocation before
    // returning so neither the public job nor hidden state retains Go
    // pointers after this synchronous cgo call.
    result.reset_stage = TRENV_V7_DML_RESET_FINALIZE;
    result.reset_status = dml_finalize_job(job);
    memset(job, 0, job_size);
    if (result.reset_status != DML_STATUS_OK) {
        return result;
    }

    result.reset_stage = TRENV_V7_DML_RESET_INITIALIZE;
    result.reset_status = dml_init_job(DML_PATH_HW, job);
    if (result.reset_status != DML_STATUS_OK) {
        return result;
    }

    result.reset_stage = TRENV_V7_DML_RESET_NONE;
    result.job_ready = 1u;
    return result;
}

static dml_status_t trenv_v7_dml_finalize_and_clear(dml_job_t *job,
                                                     uint32_t job_size) {
    dml_status_t status = dml_finalize_job(job);
    memset(job, 0, job_size);
    return status;
}
*/
import "C"

import (
	"bytes"
	"fmt"
	"runtime"
	"sync"
	"unsafe"
)

const (
	zeroPageCRC32C                     = uint32(0x98f94189)
	dmlStatusLibAccelNotFound          = uint32(C.DML_STATUS_LIBACCEL_NOT_FOUND)
	dmlStatusLibAccelError             = uint32(C.DML_STATUS_LIBACCEL_ERROR)
	dmlStatusWorkQueuesNotAvailable    = uint32(C.DML_STATUS_WORK_QUEUES_NOT_AVAILABLE)
	dmlStatusInitializationUnsupported = uint32(C.DML_STATUS_INIT_HW_NOT_SUPPORTED)
	dmlStatusWorkQueueOverflow         = uint32(C.DML_STATUS_WORK_QUEUE_OVERFLOW_ERROR)
	dmlStatusTrafficClassANotAvailable = uint32(C.DML_STATUS_TC_A_NOT_AVAILABLE)
	dmlStatusTrafficClassBNotAvailable = uint32(C.DML_STATUS_TC_B_NOT_AVAILABLE)
	dmlStatusOperationNotSupportedByWQ = uint32(C.DML_STATUS_NOT_SUPPORTED_BY_WQ)
	dmlResetStageFinalize              = uint8(C.TRENV_V7_DML_RESET_FINALIZE)
	dmlResetStageInitialize            = uint8(C.TRENV_V7_DML_RESET_INITIALIZE)
)

type hardwareCopier struct {
	mu       sync.Mutex
	job      *C.dml_job_t
	jobSize  C.uint32_t
	checksum *C.uint32_t
	closed   bool
	closeErr error
}

var _ Copier = (*hardwareCopier)(nil)

// OpenHardware creates a hardware-only DML COPY_CRC job and executes a known-
// answer test before returning it. DML hardware completion, including
// DML_FLAG_DST1_DURABLE, does not by itself prove persistence or visibility on
// a physical non-coherent CXL topology; that remains a platform-level proof.
func OpenHardware() (Copier, error) {
	var jobSize C.uint32_t
	status := C.dml_get_job_size(C.DML_PATH_HW, &jobSize)
	if status != C.DML_STATUS_OK {
		return nil, hardwareInitializationError("dml_get_job_size", uint32(status))
	}
	if jobSize == 0 {
		return nil, fmt.Errorf("%w: dml_get_job_size returned zero", ErrHardwareInitialization)
	}

	jobMemory := C.calloc(1, C.size_t(jobSize))
	if jobMemory == nil {
		return nil, fmt.Errorf("%w: allocate DML job", ErrHardwareInitialization)
	}
	job := (*C.dml_job_t)(jobMemory)

	status = C.dml_init_job(C.DML_PATH_HW, job)
	if status != C.DML_STATUS_OK {
		C.free(jobMemory)
		return nil, hardwareInitializationError("dml_init_job", uint32(status))
	}

	checksumMemory := C.calloc(1, C.size_t(unsafe.Sizeof(C.uint32_t(0))))
	if checksumMemory == nil {
		C.trenv_v7_dml_finalize_and_clear(job, jobSize)
		C.free(jobMemory)
		return nil, fmt.Errorf("%w: allocate DML checksum", ErrHardwareInitialization)
	}

	copier := &hardwareCopier{
		job:      job,
		jobSize:  jobSize,
		checksum: (*C.uint32_t)(checksumMemory),
	}
	if err := copier.selfTest(); err != nil {
		_ = copier.Close()
		return nil, err
	}
	return copier, nil
}

func (c *hardwareCopier) CopyPage(dst, src []byte) (uint32, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.closed {
		return 0, ErrClosed
	}
	if err := validatePageBuffers(dst, src); err != nil {
		return 0, err
	}

	result := C.trenv_v7_dml_copy_crc(
		c.job,
		c.jobSize,
		(*C.uint8_t)(unsafe.Pointer(&dst[0])),
		(*C.uint8_t)(unsafe.Pointer(&src[0])),
		c.checksum,
	)
	runtime.KeepAlive(dst)
	runtime.KeepAlive(src)
	executeStatus := uint32(result.execute_status)
	resetStatus := uint32(result.reset_status)
	if result.job_ready == 0 {
		operation := "reset DML job"
		switch result.reset_stage {
		case C.TRENV_V7_DML_RESET_FINALIZE:
			operation = "dml_finalize_job after COPY_CRC"
		case C.TRENV_V7_DML_RESET_INITIALIZE:
			operation = "dml_init_job after COPY_CRC"
		}
		resetStage := uint8(result.reset_stage)
		c.discardUnreadyJobLocked()
		return 0, hardwareJobResetError(operation, executeStatus, resetStatus, resetStage)
	}
	if executeStatus != uint32(C.DML_STATUS_OK) {
		return 0, hardwareCopyStatusError("dml_execute_job", executeStatus)
	}
	return uint32(*c.checksum), nil
}

func (c *hardwareCopier) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.closed {
		return c.closeErr
	}
	c.closed = true
	var err error
	if c.job != nil {
		status := C.trenv_v7_dml_finalize_and_clear(c.job, c.jobSize)
		if status != C.DML_STATUS_OK {
			err = fmt.Errorf("TRCXL007 Intel DML finalization failed: dml_finalize_job returned DML status %d", uint32(status))
		}
		C.free(unsafe.Pointer(c.job))
		c.job = nil
	}
	if c.checksum != nil {
		C.free(unsafe.Pointer(c.checksum))
		c.checksum = nil
	}
	c.closeErr = err
	return c.closeErr
}

func (c *hardwareCopier) selfTest() error {
	source := make([]byte, PageSize)
	destination := bytes.Repeat([]byte{0xa5}, PageSize)
	checksum, err := c.CopyPage(destination, source)
	if err != nil {
		return &hardwareSelfTestError{cause: err}
	}
	if checksum != zeroPageCRC32C {
		return fmt.Errorf("%w: zero-page CRC32C got %#08x want %#08x", ErrHardwareSelfTest, checksum, zeroPageCRC32C)
	}
	if !bytes.Equal(destination, source) {
		return fmt.Errorf("%w: COPY_CRC destination mismatch", ErrHardwareSelfTest)
	}
	return nil
}

func hardwareInitializationError(operation string, status uint32) error {
	kind := ErrHardwareInitialization
	switch status {
	case dmlStatusLibAccelNotFound,
		dmlStatusWorkQueuesNotAvailable,
		dmlStatusInitializationUnsupported:
		kind = ErrHardwareUnavailable
	}
	return newStatusError(kind, operation, status)
}

func hardwareCopyStatusError(operation string, status uint32) error {
	if hardwareStatusUnavailable(status) {
		return newClassifiedStatusError(
			ErrHardwareCopy,
			operation,
			status,
			ErrHardwareUnavailable)
	}
	if status == dmlStatusLibAccelError {
		return newClassifiedStatusError(
			ErrHardwareCopy,
			operation,
			status,
			ErrHardwareInitialization)
	}
	return newStatusError(ErrHardwareCopy, operation, status)
}

func hardwareJobResetError(operation string, executeStatus, resetStatus uint32, resetStage uint8) error {
	related := make([]error, 0, 2)
	if hardwareStatusUnavailable(executeStatus) || hardwareStatusUnavailable(resetStatus) {
		related = append(related, ErrHardwareUnavailable)
	}
	if executeStatus == dmlStatusLibAccelError ||
		(resetStage == dmlResetStageInitialize && !hardwareStatusUnavailable(resetStatus)) {
		related = append(related, ErrHardwareInitialization)
	}
	operation = fmt.Sprintf("%s after dml_execute_job status %d", operation, executeStatus)
	if len(related) != 0 {
		return newClassifiedStatusError(
			ErrHardwareCopy,
			operation,
			resetStatus,
			related...)
	}
	return newStatusError(ErrHardwareCopy, operation, resetStatus)
}

func hardwareStatusUnavailable(status uint32) bool {
	switch status {
	case dmlStatusLibAccelNotFound,
		dmlStatusWorkQueuesNotAvailable,
		dmlStatusInitializationUnsupported,
		dmlStatusWorkQueueOverflow,
		dmlStatusTrafficClassANotAvailable,
		dmlStatusTrafficClassBNotAvailable,
		dmlStatusOperationNotSupportedByWQ:
		return true
	default:
		return false
	}
}

func (c *hardwareCopier) discardUnreadyJobLocked() {
	C.free(unsafe.Pointer(c.job))
	C.free(unsafe.Pointer(c.checksum))
	c.job = nil
	c.checksum = nil
	c.closed = true
}

type hardwareSelfTestError struct {
	cause error
}

func (e *hardwareSelfTestError) Error() string {
	return fmt.Sprintf("%s: %v", ErrHardwareSelfTest, e.cause)
}

func (e *hardwareSelfTestError) Unwrap() error {
	return e.cause
}

func (e *hardwareSelfTestError) Is(target error) bool {
	return target == ErrHardwareSelfTest
}

//go:build amd64
// +build amd64

package main

import (
	"errors"
	"unsafe"
)

//go:noescape
func directDaxCLWBRange(address uintptr, length uintptr)

//go:noescape
func directDaxCLFlushOptRange(address uintptr, length uintptr)

//go:noescape
func directDaxCLFlushRange(address uintptr, length uintptr)

func directWritebackDaxCache(mapped []byte) error {
	if len(mapped) == 0 {
		return errors.New("cannot write back empty DAX mapping")
	}
	features, err := currentDirectDaxCPUFeatures()
	if err != nil {
		return err
	}
	address := uintptr(unsafe.Pointer(&mapped[0]))
	length := uintptr(len(mapped))
	switch selectDirectDaxWritebackInstruction(features) {
	case directDaxCacheCLWB:
		directDaxCLWBRange(address, length)
	case directDaxCacheCLFlushOpt:
		directDaxCLFlushOptRange(address, length)
	case directDaxCacheCLFlush:
		directDaxCLFlushRange(address, length)
	default:
		return errors.New("CPU does not expose clwb, clflushopt, or clflush for DAX writeback")
	}
	return nil
}

func directInvalidateDaxCache(mapped []byte) error {
	if len(mapped) == 0 {
		return errors.New("cannot invalidate empty DAX mapping")
	}
	features, err := currentDirectDaxCPUFeatures()
	if err != nil {
		return err
	}
	address := uintptr(unsafe.Pointer(&mapped[0]))
	length := uintptr(len(mapped))
	switch selectDirectDaxInvalidateInstruction(features) {
	case directDaxCacheCLFlushOpt:
		directDaxCLFlushOptRange(address, length)
	case directDaxCacheCLFlush:
		directDaxCLFlushRange(address, length)
	default:
		return errors.New("CPU does not expose clflushopt or clflush for DAX invalidation")
	}
	return nil
}

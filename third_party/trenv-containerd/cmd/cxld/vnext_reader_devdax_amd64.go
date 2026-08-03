//go:build amd64
// +build amd64

package main

import (
	"errors"
	"fmt"
	"os"
	"unsafe"
)

//go:noescape
func vnextReaderCLFlushOptRange(address uintptr, length uintptr)

//go:noescape
func vnextReaderCLFlushRange(address uintptr, length uintptr)

func newVNextReaderDAXCacheInvalidator() (
	vnextReaderDAXCacheInvalidator,
	error,
) {
	data, err := os.ReadFile("/proc/cpuinfo")
	if err != nil {
		return nil, fmt.Errorf("read CPU features for VNext Reader devdax: %w", err)
	}
	features := parseVNextReaderDAXCPUFeatures(string(data))
	instruction := selectVNextReaderDAXCacheInstruction(features)
	if instruction == vnextReaderDAXCacheUnavailable {
		return nil, errors.New(
			"CPU exposes neither CLFLUSHOPT nor CLFLUSH for VNext Reader devdax")
	}
	cacheLineBytes, err := readVNextSysfsUint(vnextCPUCacheLineSizePath)
	if err != nil {
		return nil, fmt.Errorf(
			"read CPU cache-line size for VNext Reader devdax: %w", err)
	}
	if cacheLineBytes != vnextDAXCacheLineBytes {
		return nil, fmt.Errorf(
			"CPU cache-line size %d differs from VNext Reader descriptor ABI %d",
			cacheLineBytes, vnextDAXCacheLineBytes)
	}
	return func(mapped []byte) error {
		if len(mapped) == 0 {
			return errors.New("cannot invalidate an empty VNext Reader devdax range")
		}
		address := uintptr(unsafe.Pointer(&mapped[0]))
		length := uintptr(len(mapped))
		if err := validateVNextReaderDAXCacheRange(address, length); err != nil {
			return err
		}
		switch instruction {
		case vnextReaderDAXCacheCLFlushOpt:
			vnextReaderCLFlushOptRange(address, length)
		case vnextReaderDAXCacheCLFlush:
			vnextReaderCLFlushRange(address, length)
		default:
			return errors.New("VNext Reader devdax invalidation instruction is unavailable")
		}
		return nil
	}, nil
}

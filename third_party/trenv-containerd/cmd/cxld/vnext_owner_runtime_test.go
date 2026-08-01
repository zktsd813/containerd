package main

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"math"
	"os"
	"strings"
	"testing"
	"time"
)

func vnextOwnerTestSchedulerAuthorityConfig() vnextOwnerSchedulerAuthorityConfig {
	return vnextOwnerSchedulerAuthorityConfig{
		Endpoints:       []string{"https://etcd.test:2379"},
		LeaderKey:       "/openwhisk/cxl-checkpoint/global-orchestrator-leader",
		ExpectedCluster: 0xfedcba9876543210,
		CAFile:          "/test/cxld-etcd-ca.pem",
		ClientCertFile:  "/test/cxld-etcd-client.pem",
		ClientKeyFile:   "/test/cxld-etcd-client-key.pem",
		DialTimeout:     10 * time.Second,
		ReadTimeout:     5 * time.Second,
	}
}

func vnextOwnerTestRuntimeDependencies() vnextOwnerRuntimeDependencies {
	return vnextOwnerRuntimeDependencies{
		openControlFile: func(path string) (*os.File, error) {
			return os.OpenFile(path, os.O_RDWR, 0)
		},
		openDevice: func(path string) (vnextOwnerOpenedDevice, error) {
			file, err := os.OpenFile(path, os.O_RDWR, 0)
			if err != nil {
				return vnextOwnerOpenedDevice{}, err
			}
			device, err := openVNextFileDevice(file)
			if err != nil {
				_ = file.Close()
				return vnextOwnerOpenedDevice{}, err
			}
			return vnextOwnerOpenedDevice{
				device: device,
				close:  file.Close,
			}, nil
		},
		openSchedulerAuthority: func(
			config vnextOwnerSchedulerAuthorityConfig,
		) (vnextOwnerSchedulerAuthorityVerifier, func() error, error) {
			return &vnextOwnerSchedulerVerifier{}, func() error { return nil }, nil
		},
	}
}

func vnextOwnerTestRuntimeConfig(fixture *vnextOwnerTestFixture) vnextOwnerRuntimeConfig {
	paths := make([]string, len(fixture.deviceFiles))
	for index, file := range fixture.deviceFiles {
		paths[index] = file.Name()
	}
	return vnextOwnerRuntimeConfig{
		ControlFilePath:    fixture.controlFile.Name(),
		ControlSlotBytes:   testVNextOwnerControlSlotBytes,
		DAXDeviceList:      strings.Join(paths, ","),
		SchedulerAuthority: vnextOwnerTestSchedulerAuthorityConfig(),
	}
}

func TestVNextOwnerRuntimeDisabledAndPartialConfigurationFailClosed(t *testing.T) {
	runtime, err := openVNextOwnerRuntimeWithDependencies(
		vnextOwnerRuntimeConfig{}, vnextOwnerTestRuntimeDependencies())
	if err != nil || runtime != nil {
		t.Fatalf("empty VNext Owner config should be disabled, runtime=%#v err=%v", runtime, err)
	}

	partial := []vnextOwnerRuntimeConfig{
		{ControlFilePath: "/tmp/owner-control"},
		{ControlSlotBytes: testVNextOwnerControlSlotBytes},
		{DAXDeviceList: "/dev/dax0.0"},
		{
			ControlFilePath:  "/tmp/owner-control",
			ControlSlotBytes: testVNextOwnerControlSlotBytes,
		},
		{
			ControlFilePath:  "/tmp/owner-control",
			ControlSlotBytes: testVNextOwnerControlSlotBytes,
			DAXDeviceList:    "/dev/dax0.0",
		},
		{
			SchedulerAuthority: vnextOwnerTestSchedulerAuthorityConfig(),
		},
		{
			ControlFilePath:  "/tmp/owner-control",
			ControlSlotBytes: testVNextOwnerControlSlotBytes,
			DAXDeviceList:    "/dev/dax0.0",
			SchedulerAuthority: vnextOwnerSchedulerAuthorityConfig{
				Endpoints: []string{"https://etcd.test:2379"},
			},
		},
	}
	for index, config := range partial {
		if got, err := openVNextOwnerRuntimeWithDependencies(
			config, vnextOwnerTestRuntimeDependencies()); err == nil || got != nil {
			t.Fatalf("partial config %d did not fail closed: runtime=%#v err=%v", index, got, err)
		}
	}
}

func TestVNextOwnerRuntimeOpensExistingFormattedStateAndRecoversGrant(t *testing.T) {
	fixture := newVNextOwnerTestFixture(t, []vnextOwnerTestDeviceSpec{
		{UUID: "runtime-device-a", Size: 128 << 10},
		{UUID: "runtime-device-b", Size: 128 << 10},
	})
	config := vnextOwnerTestRuntimeConfig(fixture)
	dependencies := vnextOwnerTestRuntimeDependencies()
	runtime, err := openVNextOwnerRuntimeWithDependencies(config, dependencies)
	if err != nil {
		t.Fatalf("open existing VNext Owner runtime: %v", err)
	}
	if runtime == nil || runtime.service == nil {
		t.Fatal("configured VNext Owner runtime is unavailable")
	}
	reserved, err := runtime.service.reserve(vnextOwnerReserveRequest{
		RequestID:    "runtime-restart-request",
		CheckpointID: "runtime-restart-checkpoint",
		ProducerID:   "runtime-restart-producer",
		OwnerID:      "owner-0",
		OwnerEpoch:   7,
		Contents: []vnextOwnerReserveContent{
			{
				Kind:          vnextOwnerServiceContentMemory,
				ObjectID:      1,
				ByteLength:    vnextContentPageSize,
				CapacityPages: 1,
			},
			{
				Kind:          vnextOwnerServiceContentPublication,
				ObjectID:      2,
				ByteLength:    vnextContentPageSize,
				CapacityPages: 1,
			},
		},
		MaxExtents: 2,
	})
	if err != nil {
		t.Fatalf("reserve through opened runtime: %v", err)
	}
	if err := runtime.Close(); err != nil {
		t.Fatalf("close first VNext Owner runtime: %v", err)
	}
	if err := runtime.Close(); err != nil {
		t.Fatalf("idempotent runtime close: %v", err)
	}

	reopened, err := openVNextOwnerRuntimeWithDependencies(config, dependencies)
	if err != nil {
		t.Fatalf("reopen VNext Owner runtime: %v", err)
	}
	defer reopened.Close()
	if err := reopened.service.abort(reserved.Operation); err != nil {
		t.Fatalf("restart did not reconstruct durable abort authority: %v", err)
	}
}

func TestVNextOwnerRuntimeNeverFormatsBlankDeviceOnOpenFailure(t *testing.T) {
	fixture := newVNextOwnerTestFixture(t, []vnextOwnerTestDeviceSpec{
		{UUID: "runtime-valid-device", Size: 128 << 10},
	})
	blankPath := t.TempDir() + "/blank-device.img"
	blank := bytes.Repeat([]byte{0x5a}, 128<<10)
	if err := os.WriteFile(blankPath, blank, 0o600); err != nil {
		t.Fatalf("write blank device: %v", err)
	}
	before := sha256.Sum256(blank)
	config := vnextOwnerRuntimeConfig{
		ControlFilePath:    fixture.controlFile.Name(),
		ControlSlotBytes:   testVNextOwnerControlSlotBytes,
		DAXDeviceList:      blankPath,
		SchedulerAuthority: vnextOwnerTestSchedulerAuthorityConfig(),
	}
	runtime, err := openVNextOwnerRuntimeWithDependencies(
		config, vnextOwnerTestRuntimeDependencies())
	if err == nil || runtime != nil {
		t.Fatalf("blank device unexpectedly opened/formatted: runtime=%#v err=%v", runtime, err)
	}
	afterBytes, readErr := os.ReadFile(blankPath)
	if readErr != nil {
		t.Fatalf("read blank device after failed open: %v", readErr)
	}
	after := sha256.Sum256(afterBytes)
	if before != after || !bytes.Equal(blank, afterBytes) {
		t.Fatal("failed startup changed blank device bytes instead of failing closed")
	}
}

func TestVNextOwnerRuntimeRejectsUnsafeOrDuplicateDevicePaths(t *testing.T) {
	invalid := []string{
		"relative-device",
		"/dev/../dev/dax0.0",
		"/dev/dax0.0,/dev/dax0.0",
		"/dev/dax0.0,",
		"/dev/dax 0.0",
	}
	for _, value := range invalid {
		if paths, err := parseVNextOwnerDevicePaths(value); err == nil || paths != nil {
			t.Fatalf("invalid device list %q accepted as %#v", value, paths)
		}
	}
}

func TestVNextOwnerRuntimeRetriesDeviceWorkButClosesControlExactlyOnce(t *testing.T) {
	attempts := []int{0, 0}
	controlAttempts := 0
	controlFailure := errors.New("injected control close failure")
	writebackFailure := errors.New("injected writeback failure")
	runtime := &vnextOwnerRuntime{
		service: &vnextOwnerService{},
		controlClose: func() error {
			controlAttempts++
			if controlAttempts == 1 {
				return controlFailure
			}
			return nil
		},
		devices: []vnextOwnerOpenedDevice{
			{
				close: func() error {
					attempts[0]++
					return nil
				},
			},
			{
				close: func() error {
					attempts[1]++
					if attempts[1] == 1 {
						return writebackFailure
					}
					return nil
				},
			},
		},
	}
	firstCloseErr := runtime.Close()
	if !errors.Is(firstCloseErr, writebackFailure) ||
		!errors.Is(firstCloseErr, controlFailure) {
		t.Fatalf("first close did not preserve both failures: %v", firstCloseErr)
	}
	if runtime.closed || runtime.service != nil ||
		attempts[0] != 1 || attempts[1] != 1 || controlAttempts != 1 {
		t.Fatalf("failed close state is not retryable: closed=%v attempts=%v control=%d service=%#v",
			runtime.closed, attempts, controlAttempts, runtime.service)
	}
	if err := runtime.Close(); err != nil {
		t.Fatalf("retry close failed: %v", err)
	}
	if !runtime.closed || attempts[0] != 1 || attempts[1] != 2 || controlAttempts != 1 {
		t.Fatalf("retry did not close only failed resources: closed=%v attempts=%v control=%d",
			runtime.closed, attempts, controlAttempts)
	}
	if err := runtime.Close(); err != nil || attempts[1] != 2 || controlAttempts != 1 {
		t.Fatalf("terminal close was not idempotent: err=%v attempts=%v control=%d",
			err, attempts, controlAttempts)
	}
}

func TestCloseVNextOwnerRuntimeWithRetryPreservesTerminalControlFailure(t *testing.T) {
	attempts := 0
	closeFailure := errors.New("terminal close failure")
	runtime := &vnextOwnerRuntime{
		controlClose: func() error {
			attempts++
			return closeFailure
		},
	}
	if err := closeVNextOwnerRuntimeWithRetry(runtime, 3); !errors.Is(err, closeFailure) {
		t.Fatalf("terminal close failure was hidden: %v", err)
	}
	if attempts != 1 || !runtime.closed {
		t.Fatalf("shutdown close attempts=%d closed=%v, expected 1/true",
			attempts, runtime.closed)
	}
}

func TestCloseVNextOwnerRuntimeWithRetryPreservesRecoveredWritebackFailure(t *testing.T) {
	attempts := 0
	writebackFailure := errors.New("transient writeback failure")
	runtime := &vnextOwnerRuntime{
		devices: []vnextOwnerOpenedDevice{{
			close: func() error {
				attempts++
				if attempts == 1 {
					return writebackFailure
				}
				return nil
			},
		}},
	}
	if err := closeVNextOwnerRuntimeWithRetry(runtime, 3); !errors.Is(err, writebackFailure) {
		t.Fatalf("recovered writeback diagnosis was hidden: %v", err)
	}
	if attempts != 2 || !runtime.closed {
		t.Fatalf("writeback close attempts=%d closed=%v, expected 2/true",
			attempts, runtime.closed)
	}
}

func TestCloseVNextOwnerRuntimeWithRetryAggregatesTerminalAndRecoveredFailures(t *testing.T) {
	controlFailure := errors.New("terminal control failure")
	writebackFailure := errors.New("recoverable writeback failure")
	deviceAttempts := 0
	controlAttempts := 0
	runtime := &vnextOwnerRuntime{
		controlClose: func() error {
			controlAttempts++
			return controlFailure
		},
		devices: []vnextOwnerOpenedDevice{{
			close: func() error {
				deviceAttempts++
				if deviceAttempts == 1 {
					return writebackFailure
				}
				return nil
			},
		}},
	}
	err := closeVNextOwnerRuntimeWithRetry(runtime, 3)
	if !errors.Is(err, writebackFailure) || !errors.Is(err, controlFailure) {
		t.Fatalf("shutdown retry lost one of its diagnoses: %v", err)
	}
	if deviceAttempts != 2 || controlAttempts != 1 || !runtime.closed {
		t.Fatalf("shutdown retry state device=%d control=%d closed=%v",
			deviceAttempts, controlAttempts, runtime.closed)
	}
}

func TestVNextOwnerRuntimeClosesEarlierResourcesWhenLaterDeviceOpenFails(t *testing.T) {
	fixture := newVNextOwnerTestFixture(t, []vnextOwnerTestDeviceSpec{
		{UUID: "runtime-partial-device", Size: 128 << 10},
	})
	controlPath := fixture.controlFile.Name()
	devicePath := fixture.deviceFiles[0].Name()
	missingPath := t.TempDir() + "/missing-device"
	var openedControl *os.File
	deviceCloseCount := 0
	dependencies := vnextOwnerRuntimeDependencies{
		openControlFile: func(path string) (*os.File, error) {
			file, err := os.OpenFile(path, os.O_RDWR, 0)
			openedControl = file
			return file, err
		},
		openDevice: func(path string) (vnextOwnerOpenedDevice, error) {
			if path == missingPath {
				return vnextOwnerOpenedDevice{}, errors.New("injected second-device open failure")
			}
			file, err := os.OpenFile(path, os.O_RDWR, 0)
			if err != nil {
				return vnextOwnerOpenedDevice{}, err
			}
			device, err := openVNextFileDevice(file)
			if err != nil {
				_ = file.Close()
				return vnextOwnerOpenedDevice{}, err
			}
			return vnextOwnerOpenedDevice{
				device: device,
				close: func() error {
					deviceCloseCount++
					return file.Close()
				},
			}, nil
		},
		openSchedulerAuthority: vnextOwnerTestRuntimeDependencies().openSchedulerAuthority,
	}
	runtime, err := openVNextOwnerRuntimeWithDependencies(vnextOwnerRuntimeConfig{
		ControlFilePath:    controlPath,
		ControlSlotBytes:   testVNextOwnerControlSlotBytes,
		DAXDeviceList:      devicePath + "," + missingPath,
		SchedulerAuthority: vnextOwnerTestSchedulerAuthorityConfig(),
	}, dependencies)
	if err == nil || runtime != nil {
		t.Fatalf("partial device open unexpectedly succeeded: runtime=%#v err=%v", runtime, err)
	}
	if deviceCloseCount != 1 {
		t.Fatalf("earlier device close count is %d, expected 1; startup err=%v",
			deviceCloseCount, err)
	}
	if openedControl == nil {
		t.Fatal("control file was never opened")
	}
	if _, statErr := openedControl.Stat(); statErr == nil {
		t.Fatal("control file remained open after partial startup failure")
	}
}

func TestParseVNextOwnerSchedulerAuthorityInputPreservesExactConfiguration(t *testing.T) {
	config, err := parseVNextOwnerSchedulerAuthorityInput(
		vnextOwnerSchedulerAuthorityInput{
			Endpoints:         "https://etcd-a.test:2379,https://etcd-b.test:2379",
			LeaderKey:         "/openwhisk/cxl-checkpoint/global-orchestrator-leader",
			ExpectedCluster:   "fedcba9876543210",
			CAFile:            "/etc/cxld/etcd/ca.pem",
			ClientCertFile:    "/etc/cxld/etcd/client.pem",
			ClientKeyFile:     "/etc/cxld/etcd/client-key.pem",
			DialTimeoutMillis: 10000,
			ReadTimeoutMillis: 5000,
		})
	if err != nil {
		t.Fatal(err)
	}
	if len(config.Endpoints) != 2 ||
		config.Endpoints[0] != "https://etcd-a.test:2379" ||
		config.Endpoints[1] != "https://etcd-b.test:2379" ||
		config.ExpectedCluster != 0xfedcba9876543210 ||
		config.DialTimeout != 10*time.Second ||
		config.ReadTimeout != 5*time.Second ||
		vnextOwnerSchedulerAuthorityConfiguredFields(config) != 8 {
		t.Fatalf("exact Scheduler authority input changed during parsing: %#v", config)
	}
	if err := validateVNextOwnerSchedulerAuthorityConfig(config, true); err != nil {
		t.Fatalf("parsed exact Scheduler authority is invalid: %v", err)
	}
}

func TestParseVNextOwnerSchedulerAuthorityInputRejectsNoncanonicalValues(t *testing.T) {
	overflowMillis := int64(math.MaxInt64)/int64(time.Millisecond) + 1
	tests := []vnextOwnerSchedulerAuthorityInput{
		{Endpoints: " https://etcd.test:2379"},
		{Endpoints: "https://etcd.test:2379,"},
		{ExpectedCluster: "0000000000000000"},
		{ExpectedCluster: "0123456789ABCDEf"},
		{ExpectedCluster: "0123456789abcdef "},
		{DialTimeoutMillis: -1},
		{ReadTimeoutMillis: overflowMillis},
	}
	for index, input := range tests {
		if config, err := parseVNextOwnerSchedulerAuthorityInput(input); err == nil {
			t.Fatalf("noncanonical input %d was accepted as %#v", index, config)
		}
	}
}

func TestVNextOwnerRuntimeOpensAndClosesSchedulerAuthorityExactlyOnce(t *testing.T) {
	fixture := newVNextOwnerTestFixture(t, []vnextOwnerTestDeviceSpec{
		{UUID: "runtime-authority-device", Size: 128 << 10},
	})
	dependencies := vnextOwnerTestRuntimeDependencies()
	openCount := 0
	closeCount := 0
	dependencies.openSchedulerAuthority = func(
		config vnextOwnerSchedulerAuthorityConfig,
	) (vnextOwnerSchedulerAuthorityVerifier, func() error, error) {
		openCount++
		if config.ExpectedCluster != 0xfedcba9876543210 {
			t.Fatalf("authority opener received the wrong cluster: %#v", config)
		}
		return &vnextOwnerSchedulerVerifier{}, func() error {
			closeCount++
			return nil
		}, nil
	}
	runtime, err := openVNextOwnerRuntimeWithDependencies(
		vnextOwnerTestRuntimeConfig(fixture), dependencies)
	if err != nil {
		t.Fatal(err)
	}
	if runtime == nil || runtime.service == nil ||
		runtime.service.schedulerAuthority == nil || openCount != 1 {
		t.Fatalf("Scheduler authority was not injected: runtime=%#v opens=%d",
			runtime, openCount)
	}
	if err := runtime.Close(); err != nil {
		t.Fatal(err)
	}
	if err := runtime.Close(); err != nil {
		t.Fatal(err)
	}
	if closeCount != 1 {
		t.Fatalf("Scheduler authority close count = %d, want 1", closeCount)
	}
}

func TestVNextOwnerRuntimeAuthorityFailurePrecedesStorageOpen(t *testing.T) {
	fixture := newVNextOwnerTestFixture(t, []vnextOwnerTestDeviceSpec{
		{UUID: "runtime-authority-failure-device", Size: 128 << 10},
	})
	dependencies := vnextOwnerTestRuntimeDependencies()
	controlOpenCount := 0
	dependencies.openControlFile = func(path string) (*os.File, error) {
		controlOpenCount++
		return os.OpenFile(path, os.O_RDWR, 0)
	}
	authorityFailure := errors.New("injected authority open failure")
	dependencies.openSchedulerAuthority = func(
		config vnextOwnerSchedulerAuthorityConfig,
	) (vnextOwnerSchedulerAuthorityVerifier, func() error, error) {
		return nil, nil, authorityFailure
	}
	runtime, err := openVNextOwnerRuntimeWithDependencies(
		vnextOwnerTestRuntimeConfig(fixture), dependencies)
	if runtime != nil || !errors.Is(err, authorityFailure) {
		t.Fatalf("authority failure was not preserved: runtime=%#v err=%v", runtime, err)
	}
	if controlOpenCount != 0 {
		t.Fatalf("storage opened %d times after authority failure", controlOpenCount)
	}
}

func TestVNextOwnerRuntimeAuthorityCloseFailureIsTerminal(t *testing.T) {
	closeCount := 0
	closeFailure := errors.New("injected authority close failure")
	runtime := &vnextOwnerRuntime{
		service: &vnextOwnerService{},
		schedulerAuthorityClose: func() error {
			closeCount++
			return closeFailure
		},
	}
	if err := runtime.Close(); !errors.Is(err, closeFailure) {
		t.Fatalf("authority close failure was hidden: %v", err)
	}
	if err := runtime.Close(); err != nil {
		t.Fatalf("terminal authority close was retried: %v", err)
	}
	if closeCount != 1 || !runtime.closed || runtime.service != nil {
		t.Fatalf("authority close state count=%d closed=%v service=%#v",
			closeCount, runtime.closed, runtime.service)
	}
}

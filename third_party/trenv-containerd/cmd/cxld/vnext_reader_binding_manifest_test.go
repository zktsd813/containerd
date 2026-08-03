package main

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

func vnextReaderBindingManifestDeviceJSONForTest(
	deviceUUID string,
	ownerID string,
	ownerEpoch uint64,
	dataPageCount uint64,
	contentRegionBase uint64,
	devicePath string,
) string {
	return fmt.Sprintf(
		`{"deviceUuid":%q,"ownerId":%q,"ownerEpoch":%d,"dataPageCount":%d,"contentRegionBase":%d,"devicePath":%q}`,
		deviceUUID, ownerID, ownerEpoch, dataPageCount, contentRegionBase, devicePath)
}

func vnextReaderBindingManifestJSONForTest(devices ...string) []byte {
	return []byte(fmt.Sprintf(
		`{"protocol":%q,"version":%d,"devices":[%s]}`,
		vnextReaderBindingManifestProtocol,
		vnextReaderBindingManifestVersion,
		strings.Join(devices, ",")))
}

func vnextReaderBindingManifestManyDevicesForTest(count int) []byte {
	devices := make([]string, 0, count)
	for index := 0; index < count; index++ {
		devices = append(devices, vnextReaderBindingManifestDeviceJSONForTest(
			fmt.Sprintf("device-%04d", index),
			"owner-a",
			7,
			uint64(index+1),
			4096,
			fmt.Sprintf("/dev/dax%d.0", index)))
	}
	return vnextReaderBindingManifestJSONForTest(devices...)
}

func vnextReaderBindingManifestJSONFromBindingsForTest(
	bindings []vnextLocalDAXBinding,
) []byte {
	devices := make([]string, 0, len(bindings))
	for _, binding := range bindings {
		devices = append(devices, vnextReaderBindingManifestDeviceJSONForTest(
			binding.DeviceUUID,
			binding.OwnerID,
			binding.OwnerEpoch,
			binding.DataPageCount,
			binding.ContentRegionBase,
			binding.DevicePath))
	}
	return vnextReaderBindingManifestJSONForTest(devices...)
}

func TestVNextReaderBindingManifestParsesCanonicalMultiDAXWithoutRetainingInput(
	t *testing.T,
) {
	raw := vnextReaderBindingManifestJSONForTest(
		vnextReaderBindingManifestDeviceJSONForTest(
			"device-a", "owner-a", 7, 31, 4096, "/dev/dax0.0"),
		vnextReaderBindingManifestDeviceJSONForTest(
			"device-b", "owner-b", 9, 47, 8192, "/dev/dax1.0"))
	directory, err := parseVNextReaderBindingManifest(raw)
	if err != nil {
		t.Fatalf("parse canonical multi-DAX manifest: %v", err)
	}
	if directory == nil || len(directory.byUUID) != 2 {
		t.Fatalf("parsed directory=%#v", directory)
	}
	wantA := vnextLocalDAXBinding{
		DeviceUUID:        "device-a",
		OwnerID:           "owner-a",
		OwnerEpoch:        7,
		DataPageCount:     31,
		ContentRegionBase: 4096,
		DevicePath:        "/dev/dax0.0",
	}
	wantB := vnextLocalDAXBinding{
		DeviceUUID:        "device-b",
		OwnerID:           "owner-b",
		OwnerEpoch:        9,
		DataPageCount:     47,
		ContentRegionBase: 8192,
		DevicePath:        "/dev/dax1.0",
	}
	if directory.byUUID[wantA.DeviceUUID] != wantA ||
		directory.byUUID[wantB.DeviceUUID] != wantB {
		t.Fatalf("parsed bindings=%#v", directory.byUUID)
	}
	for index := range raw {
		raw[index] = 'x'
	}
	if directory.byUUID[wantA.DeviceUUID] != wantA ||
		directory.byUUID[wantB.DeviceUUID] != wantB {
		t.Fatal("directory retained or aliased the raw manifest input")
	}
}

func TestVNextReaderBindingManifestRejectsNonStrictJSONAndInvalidBindings(
	t *testing.T,
) {
	device := vnextReaderBindingManifestDeviceJSONForTest(
		"device-a", "owner-a", 7, 31, 4096, "/dev/dax0.0")
	valid := string(vnextReaderBindingManifestJSONForTest(device))
	second := vnextReaderBindingManifestDeviceJSONForTest(
		"device-b", "owner-b", 9, 47, 8192, "/dev/dax1.0")
	utf8First := vnextReaderBindingManifestDeviceJSONForTest(
		"é-device", "owner-a", 7, 31, 4096, "/dev/dax2.0")
	utf8Second := vnextReaderBindingManifestDeviceJSONForTest(
		"z-device", "owner-a", 7, 31, 4096, "/dev/dax3.0")
	tests := []struct {
		name    string
		raw     []byte
		contain string
	}{
		{name: "empty", raw: nil},
		{name: "invalid UTF-8", raw: []byte{'{', 0xff, '}'}, contain: "UTF-8"},
		{name: "root null", raw: []byte(`null`)},
		{name: "unknown root field", raw: []byte(strings.Replace(
			valid, `"devices":`, `"unknown":1,"devices":`, 1)), contain: "unknown field"},
		{name: "duplicate root field", raw: []byte(strings.Replace(
			valid, `"version":1`, `"version":1,"version":1`, 1)), contain: "duplicate field"},
		{name: "missing protocol", raw: []byte(fmt.Sprintf(
			`{"version":1,"devices":[%s]}`, device)), contain: "missing required"},
		{name: "missing version", raw: []byte(fmt.Sprintf(
			`{"protocol":%q,"devices":[%s]}`,
			vnextReaderBindingManifestProtocol, device)), contain: "missing required"},
		{name: "missing devices", raw: []byte(fmt.Sprintf(
			`{"protocol":%q,"version":1}`,
			vnextReaderBindingManifestProtocol)), contain: "missing required"},
		{name: "null protocol", raw: []byte(strings.Replace(
			valid, fmt.Sprintf("%q", vnextReaderBindingManifestProtocol), "null", 1)),
			contain: "non-null"},
		{name: "null version", raw: []byte(strings.Replace(
			valid, `"version":1`, `"version":null`, 1)), contain: "non-null"},
		{name: "null devices", raw: []byte(strings.Replace(
			valid, `"devices":[`+device+`]`, `"devices":null`, 1))},
		{name: "trailing value", raw: []byte(valid + ` {}`), contain: "trailing"},
		{name: "wrong protocol", raw: []byte(strings.Replace(
			valid, vnextReaderBindingManifestProtocol, "wrong.protocol", 1)), contain: "protocol"},
		{name: "wrong version", raw: []byte(strings.Replace(
			valid, `"version":1`, `"version":2`, 1)), contain: "version"},
		{name: "non-integer version", raw: []byte(strings.Replace(
			valid, `"version":1`, `"version":1.0`, 1)), contain: "integer"},
		{name: "empty devices", raw: vnextReaderBindingManifestJSONForTest(), contain: "non-empty"},
		{name: "null device", raw: []byte(strings.Replace(
			valid, device, "null", 1))},
		{name: "unknown device field", raw: []byte(strings.Replace(
			valid, `"deviceUuid":`, `"unknown":1,"deviceUuid":`, 1)), contain: "unknown field"},
		{name: "duplicate device field", raw: []byte(strings.Replace(
			valid, `"ownerId":"owner-a"`,
			`"ownerId":"owner-a","ownerId":"owner-a"`, 1)), contain: "duplicate field"},
		{name: "missing device field", raw: []byte(strings.Replace(
			valid, `,"devicePath":"/dev/dax0.0"`, "", 1)), contain: "missing required"},
		{name: "null device field", raw: []byte(strings.Replace(
			valid, `"deviceUuid":"device-a"`, `"deviceUuid":null`, 1)), contain: "non-null"},
		{name: "non-integer owner epoch", raw: []byte(strings.Replace(
			valid, `"ownerEpoch":7`, `"ownerEpoch":7.5`, 1)), contain: "integer"},
		{name: "zero owner epoch", raw: []byte(strings.Replace(
			valid, `"ownerEpoch":7`, `"ownerEpoch":0`, 1)), contain: "positive"},
		{name: "zero page count", raw: []byte(strings.Replace(
			valid, `"dataPageCount":31`, `"dataPageCount":0`, 1)), contain: "positive"},
		{name: "unaligned content base", raw: []byte(strings.Replace(
			valid, `"contentRegionBase":4096`, `"contentRegionBase":4097`, 1)), contain: "aligned"},
		{name: "relative device path", raw: []byte(strings.Replace(
			valid, `/dev/dax0.0`, `dev/dax0.0`, 1)), contain: "not clean"},
		{name: "unclean device path", raw: []byte(strings.Replace(
			valid, `/dev/dax0.0`, `/dev/../dev/dax0.0`, 1)), contain: "not clean"},
		{name: "whitespace device path", raw: []byte(strings.Replace(
			valid, `/dev/dax0.0`, `/dev/dax 0.0`, 1)), contain: "whitespace"},
		{name: "duplicate UUID", raw: vnextReaderBindingManifestJSONForTest(
			device,
			vnextReaderBindingManifestDeviceJSONForTest(
				"device-a", "owner-b", 9, 47, 8192, "/dev/dax1.0")), contain: "duplicate"},
		{name: "duplicate path", raw: vnextReaderBindingManifestJSONForTest(
			device,
			vnextReaderBindingManifestDeviceJSONForTest(
				"device-b", "owner-b", 9, 47, 8192, "/dev/dax0.0")), contain: "aliases"},
		{name: "non-canonical order", raw: vnextReaderBindingManifestJSONForTest(
			second, device), contain: "UTF-8 byte order"},
		{name: "non-canonical multibyte UTF-8 order", raw: vnextReaderBindingManifestJSONForTest(
			utf8First, utf8Second), contain: "UTF-8 byte order"},
		{name: "over-depth", raw: []byte(fmt.Sprintf(
			`{"protocol":[[[[%q]]]],"version":1,"devices":[%s]}`,
			vnextReaderBindingManifestProtocol, device)), contain: "depth"},
		{name: "oversized device array", raw: vnextReaderBindingManifestManyDevicesForTest(
			vnextReaderBindingManifestMaxDevices + 1), contain: "more than"},
		{name: "oversized raw bytes", raw: bytes.Repeat(
			[]byte{' '}, vnextReaderBindingManifestMaxFileBytes+1), contain: "allowed range"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			directory, err := parseVNextReaderBindingManifest(test.raw)
			if directory != nil || err == nil {
				t.Fatalf("rejected manifest returned directory=%#v err=%v", directory, err)
			}
			if test.contain != "" && !strings.Contains(err.Error(), test.contain) {
				t.Fatalf("error %q does not contain %q", err, test.contain)
			}
		})
	}
}

func TestVNextReaderBindingManifestAcceptsExactDeviceLimit(t *testing.T) {
	raw := vnextReaderBindingManifestManyDevicesForTest(
		vnextReaderBindingManifestMaxDevices)
	if len(raw) > vnextReaderBindingManifestMaxFileBytes {
		t.Fatalf("exact-limit fixture has %d bytes", len(raw))
	}
	directory, err := parseVNextReaderBindingManifest(raw)
	if err != nil {
		t.Fatalf("parse exact device limit: %v", err)
	}
	if got := len(directory.byUUID); got != vnextReaderBindingManifestMaxDevices {
		t.Fatalf("directory devices=%d, want %d",
			got, vnextReaderBindingManifestMaxDevices)
	}
}

func TestVNextReaderBindingManifestFileLoaderIsReadOnlyBoundedAndNoFollow(
	t *testing.T,
) {
	raw := vnextReaderBindingManifestJSONForTest(
		vnextReaderBindingManifestDeviceJSONForTest(
			"device-a", "owner-a", 7, 31, 4096, "/dev/dax0.0"))
	manifestPath := filepath.Join(t.TempDir(), "reader-bindings.json")
	if err := os.WriteFile(manifestPath, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	dependencies := defaultVNextReaderBindingManifestFileDependencies()
	openFile := dependencies.openFile
	openFlags := -1
	dependencies.openFile = func(
		path string,
		flags int,
		mode os.FileMode,
	) (*os.File, error) {
		openFlags = flags
		return openFile(path, flags, mode)
	}
	directory, err := loadVNextReaderBindingManifestWithDependencies(
		manifestPath, dependencies)
	if err != nil || directory == nil || len(directory.byUUID) != 1 {
		t.Fatalf("load regular manifest: directory=%#v err=%v", directory, err)
	}
	if openFlags != vnextReaderBindingManifestOpenFlags ||
		openFlags&unix.O_ACCMODE != unix.O_RDONLY ||
		openFlags&unix.O_CLOEXEC == 0 || openFlags&unix.O_NOFOLLOW == 0 {
		t.Fatalf("manifest open flags=%#x, want %#x read-only/close-on-exec/no-follow",
			openFlags, vnextReaderBindingManifestOpenFlags)
	}

	symlinkPath := filepath.Join(filepath.Dir(manifestPath), "reader-bindings-link.json")
	if err := os.Symlink(manifestPath, symlinkPath); err != nil {
		t.Fatal(err)
	}
	if directory, err := loadVNextReaderBindingManifest(symlinkPath); directory != nil || err == nil {
		t.Fatalf("symlink manifest returned directory=%#v err=%v", directory, err)
	}
	if directory, err := loadVNextReaderBindingManifest(filepath.Dir(manifestPath)); directory != nil || err == nil {
		t.Fatalf("directory manifest returned directory=%#v err=%v", directory, err)
	}

	oversizePath := filepath.Join(filepath.Dir(manifestPath), "oversized.json")
	oversize, err := os.OpenFile(oversizePath, os.O_CREATE|os.O_RDWR|os.O_EXCL, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if err := oversize.Truncate(vnextReaderBindingManifestMaxFileBytes + 1); err != nil {
		_ = oversize.Close()
		t.Fatal(err)
	}
	if err := oversize.Close(); err != nil {
		t.Fatal(err)
	}
	if directory, err := loadVNextReaderBindingManifest(oversizePath); directory != nil || err == nil || !strings.Contains(err.Error(), "outside") {
		t.Fatalf("oversized manifest returned directory=%#v err=%v", directory, err)
	}
}

type vnextReaderBindingManifestChangedFileInfo struct {
	os.FileInfo
	size int64
}

func (info vnextReaderBindingManifestChangedFileInfo) Size() int64 {
	return info.size
}

func TestVNextReaderBindingManifestFileLoaderRejectsShortReadAndChangeDuringRead(
	t *testing.T,
) {
	raw := vnextReaderBindingManifestJSONForTest(
		vnextReaderBindingManifestDeviceJSONForTest(
			"device-a", "owner-a", 7, 31, 4096, "/dev/dax0.0"))
	manifestPath := filepath.Join(t.TempDir(), "reader-bindings.json")
	if err := os.WriteFile(manifestPath, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Run("short read", func(t *testing.T) {
		dependencies := defaultVNextReaderBindingManifestFileDependencies()
		readFile := dependencies.readFile
		calls := 0
		dependencies.readFile = func(file *os.File, destination []byte) (int, error) {
			calls++
			if calls == 1 {
				return readFile(file, destination[:len(destination)-1])
			}
			return 0, io.EOF
		}
		directory, err := loadVNextReaderBindingManifestWithDependencies(
			manifestPath, dependencies)
		if directory != nil || err == nil || !strings.Contains(err.Error(), "short-read") {
			t.Fatalf("short read returned directory=%#v err=%v", directory, err)
		}
	})
	t.Run("change during read", func(t *testing.T) {
		dependencies := defaultVNextReaderBindingManifestFileDependencies()
		statFile := dependencies.statFile
		calls := 0
		dependencies.statFile = func(file *os.File) (os.FileInfo, error) {
			info, err := statFile(file)
			if err != nil {
				return nil, err
			}
			calls++
			if calls == 2 {
				return vnextReaderBindingManifestChangedFileInfo{
					FileInfo: info,
					size:     info.Size() + 1,
				}, nil
			}
			return info, nil
		}
		directory, err := loadVNextReaderBindingManifestWithDependencies(
			manifestPath, dependencies)
		if directory != nil || err == nil || !strings.Contains(err.Error(), "changed during read") {
			t.Fatalf("changed read returned directory=%#v err=%v", directory, err)
		}
	})
	if directory, err := loadVNextReaderBindingManifestWithDependencies(
		manifestPath, vnextReaderBindingManifestFileDependencies{}); directory != nil || err == nil || !strings.Contains(err.Error(), "incomplete") {
		t.Fatalf("incomplete dependencies returned directory=%#v err=%v", directory, err)
	}
}

func TestVNextReaderBindingManifestDoesNotReplaceFirstAuthorizedSourceReadSuperblockValidation(
	t *testing.T,
) {
	fixture := newVNextReaderTestFixture(t)
	bindings, err := cloneVNextReaderDevDAXBindings(fixture.directory)
	if err != nil {
		t.Fatal(err)
	}
	// The local operator manifest is deliberately parseable even when its
	// claimed epoch is stale. It is not authority. The direct lower-level call
	// below isolates the lazy superblock check that production reaches only
	// after authorization consumes the first-read permit.
	bindings[0].OwnerEpoch++
	directory, err := parseVNextReaderBindingManifest(
		vnextReaderBindingManifestJSONFromBindingsForTest(bindings))
	if err != nil {
		t.Fatalf("parse non-authoritative local mapping: %v", err)
	}
	invalidator := &vnextReaderDevDAXTestInvalidator{}
	operations := &vnextReaderDevDAXTestOperations{pretendCharacter: true}
	dependencies := vnextReaderDevDAXRegularFileSimulationDependenciesForTest(
		t, invalidator, operations)
	source, err := openVNextReadOnlyDevDAXSourceWithDependencies(
		directory, dependencies)
	if err != nil {
		t.Fatalf("open read-only source without reading superblock: %v", err)
	}
	t.Cleanup(func() { _ = source.Close() })
	invalidator.bind(source)
	if records := invalidator.snapshot(); len(records) != 0 {
		t.Fatalf("manifest or source construction read shared memory: %#v", records)
	}
	device := source.devices[bindings[0].DeviceUUID]
	if device == nil {
		t.Fatalf("mapped source is missing %q", bindings[0].DeviceUUID)
	}
	if _, err := device.readDescriptor(context.Background(), 0); err == nil ||
		!strings.Contains(err.Error(), "superblock does not match configured local binding") {
		t.Fatalf("first source read accepted manifest as authority: %v", err)
	}
}

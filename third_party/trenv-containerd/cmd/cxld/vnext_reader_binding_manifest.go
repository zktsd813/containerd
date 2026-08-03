package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"unicode/utf8"

	"github.com/containerd/containerd/third_party/trenv-containerd/pkg/cxlcheckpoint"
	"golang.org/x/sys/unix"
)

const (
	vnextReaderBindingManifestProtocol = "cxld.vnext-reader-binding-manifest.v1"
	vnextReaderBindingManifestVersion  = uint64(1)

	vnextReaderBindingManifestMaxDevices   = 1024
	vnextReaderBindingManifestMaxFileBytes = 16 << 20
	vnextReaderBindingManifestMaxJSONDepth = 3

	// O_NOFOLLOW rejects a final-component symlink and O_NONBLOCK prevents a
	// misconfigured FIFO from blocking cxld before its non-regular mode can be
	// rejected. Neither flag weakens the required read-only, close-on-exec
	// contract.
	vnextReaderBindingManifestOpenFlags = unix.O_RDONLY | unix.O_CLOEXEC |
		unix.O_NOFOLLOW | unix.O_NONBLOCK
)

type vnextReaderBindingManifestFileDependencies struct {
	openFile  func(string, int, os.FileMode) (*os.File, error)
	statFile  func(*os.File) (os.FileInfo, error)
	readFile  func(*os.File, []byte) (int, error)
	closeFile func(*os.File) error
}

func defaultVNextReaderBindingManifestFileDependencies() vnextReaderBindingManifestFileDependencies {
	return vnextReaderBindingManifestFileDependencies{
		openFile: func(path string, flags int, mode os.FileMode) (*os.File, error) {
			fd, err := unix.Open(path, flags, uint32(mode.Perm()))
			if err != nil {
				return nil, err
			}
			file := os.NewFile(uintptr(fd), path)
			if file == nil {
				_ = unix.Close(fd)
				return nil, errors.New("construct manifest file from descriptor")
			}
			return file, nil
		},
		statFile: func(file *os.File) (os.FileInfo, error) {
			return file.Stat()
		},
		readFile: func(file *os.File, destination []byte) (int, error) {
			return file.Read(destination)
		},
		closeFile: func(file *os.File) error {
			return file.Close()
		},
	}
}

// loadVNextReaderBindingManifest loads only node-local operator mapping. The
// manifest is not Scheduler or Owner authority and cannot authorize a Reader.
// In particular, it does not replace the exact UUID, Owner, epoch, and geometry
// validation performed against the shared-memory superblock on the first
// authorized source read.
func loadVNextReaderBindingManifest(path string) (*vnextLocalDAXDirectory, error) {
	return loadVNextReaderBindingManifestWithDependencies(
		path, defaultVNextReaderBindingManifestFileDependencies())
}

func loadVNextReaderBindingManifestWithDependencies(
	path string,
	dependencies vnextReaderBindingManifestFileDependencies,
) (*vnextLocalDAXDirectory, error) {
	raw, err := readVNextReaderBindingManifestFile(path, dependencies)
	if err != nil {
		return nil, err
	}
	return parseVNextReaderBindingManifest(raw)
}

func validateVNextReaderBindingManifestFileDependencies(
	dependencies vnextReaderBindingManifestFileDependencies,
) error {
	if dependencies.openFile == nil || dependencies.statFile == nil ||
		dependencies.readFile == nil || dependencies.closeFile == nil {
		return errors.New("VNext Reader binding manifest file dependencies are incomplete")
	}
	return nil
}

func readVNextReaderBindingManifestFile(
	path string,
	dependencies vnextReaderBindingManifestFileDependencies,
) (raw []byte, returnErr error) {
	if err := validateVNextReaderBindingManifestFileDependencies(dependencies); err != nil {
		return nil, err
	}
	if path == "" || len(path) > cxlcheckpoint.MaxIdentityBytes ||
		!filepath.IsAbs(path) || filepath.Clean(path) != path ||
		strings.IndexByte(path, 0) >= 0 {
		return nil, errors.New(
			"VNext Reader binding manifest path must be absolute, clean, non-empty, and bounded")
	}
	file, err := dependencies.openFile(
		path, vnextReaderBindingManifestOpenFlags, 0)
	if err != nil {
		return nil, fmt.Errorf("open VNext Reader binding manifest read-only: %w", err)
	}
	if file == nil {
		return nil, errors.New("open VNext Reader binding manifest returned a nil file")
	}
	defer func() {
		if closeErr := dependencies.closeFile(file); closeErr != nil {
			raw = nil
			if returnErr == nil {
				returnErr = fmt.Errorf("close VNext Reader binding manifest: %w", closeErr)
			} else {
				returnErr = fmt.Errorf(
					"%v; close VNext Reader binding manifest: %w", returnErr, closeErr)
			}
		}
	}()

	before, err := dependencies.statFile(file)
	if err != nil {
		return nil, fmt.Errorf("stat VNext Reader binding manifest: %w", err)
	}
	if err := validateVNextReaderBindingManifestFileInfo(before); err != nil {
		return nil, err
	}
	raw = make([]byte, int(before.Size()))
	if err := readExactVNextReaderBindingManifest(file, raw, dependencies.readFile); err != nil {
		return nil, err
	}
	after, err := dependencies.statFile(file)
	if err != nil {
		return nil, fmt.Errorf(
			"re-stat VNext Reader binding manifest after read: %w", err)
	}
	if err := validateVNextReaderBindingManifestFileInfo(after); err != nil {
		return nil, err
	}
	if err := validateVNextReaderBindingManifestFileStable(before, after); err != nil {
		return nil, fmt.Errorf(
			"VNext Reader binding manifest changed during read: %w", err)
	}
	return raw, nil
}

func validateVNextReaderBindingManifestFileInfo(info os.FileInfo) error {
	if info == nil || !info.Mode().IsRegular() {
		return errors.New("VNext Reader binding manifest must be a regular file")
	}
	if info.Size() <= 0 || info.Size() > vnextReaderBindingManifestMaxFileBytes {
		return fmt.Errorf(
			"VNext Reader binding manifest size %d is outside 1..%d",
			info.Size(), vnextReaderBindingManifestMaxFileBytes)
	}
	if stat, ok := info.Sys().(*syscall.Stat_t); !ok || stat == nil {
		return errors.New("VNext Reader binding manifest Unix metadata is unavailable")
	}
	return nil
}

func validateVNextReaderBindingManifestFileStable(before, after os.FileInfo) error {
	if before == nil || after == nil || !os.SameFile(before, after) {
		return errors.New("file identity changed")
	}
	beforeStat, beforeOK := before.Sys().(*syscall.Stat_t)
	afterStat, afterOK := after.Sys().(*syscall.Stat_t)
	if !beforeOK || !afterOK || beforeStat == nil || afterStat == nil {
		return errors.New("Unix metadata is unavailable")
	}
	if before.Size() != after.Size() || before.Mode() != after.Mode() ||
		!before.ModTime().Equal(after.ModTime()) ||
		beforeStat.Dev != afterStat.Dev || beforeStat.Ino != afterStat.Ino ||
		beforeStat.Mode != afterStat.Mode || beforeStat.Nlink != afterStat.Nlink ||
		beforeStat.Uid != afterStat.Uid || beforeStat.Gid != afterStat.Gid ||
		beforeStat.Size != afterStat.Size || beforeStat.Mtim != afterStat.Mtim ||
		beforeStat.Ctim != afterStat.Ctim {
		return errors.New("file identity, size, mode, ownership, or change time changed")
	}
	return nil
}

func readExactVNextReaderBindingManifest(
	file *os.File,
	destination []byte,
	readFile func(*os.File, []byte) (int, error),
) error {
	readBytes := 0
	for readBytes < len(destination) {
		n, err := readFile(file, destination[readBytes:])
		if n < 0 || n > len(destination)-readBytes {
			return errors.New("VNext Reader binding manifest reader returned an invalid byte count")
		}
		readBytes += n
		if err != nil {
			if errors.Is(err, io.EOF) && readBytes == len(destination) {
				break
			}
			if errors.Is(err, io.EOF) {
				return fmt.Errorf(
					"short-read VNext Reader binding manifest: read %d of %d bytes",
					readBytes, len(destination))
			}
			return fmt.Errorf("read VNext Reader binding manifest: %w", err)
		}
		if n == 0 {
			return fmt.Errorf(
				"short-read VNext Reader binding manifest: read %d of %d bytes",
				readBytes, len(destination))
		}
	}
	var extra [1]byte
	n, err := readFile(file, extra[:])
	if n != 0 {
		return errors.New("VNext Reader binding manifest grew during read")
	}
	if err == nil {
		return errors.New("VNext Reader binding manifest reader made no EOF progress")
	}
	if !errors.Is(err, io.EOF) {
		return fmt.Errorf("read VNext Reader binding manifest trailer: %w", err)
	}
	return nil
}

// parseVNextReaderBindingManifest deliberately returns only the existing
// directory abstraction. It retains neither the manifest bytes nor a wire
// slice, and every successful parse passes through newVNextLocalDAXDirectory.
func parseVNextReaderBindingManifest(raw []byte) (*vnextLocalDAXDirectory, error) {
	if len(raw) == 0 || len(raw) > vnextReaderBindingManifestMaxFileBytes {
		return nil, fmt.Errorf(
			"VNext Reader binding manifest has %d bytes, allowed range is 1..%d",
			len(raw), vnextReaderBindingManifestMaxFileBytes)
	}
	if !utf8.Valid(raw) {
		return nil, errors.New("VNext Reader binding manifest JSON is not valid UTF-8")
	}
	if err := validateVNextReaderBindingManifestJSONDepth(raw); err != nil {
		return nil, err
	}

	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if err := expectVNextReaderBindingManifestDelimiter(decoder, '{', "manifest"); err != nil {
		return nil, err
	}
	seen := make(map[string]struct{}, 3)
	var protocol string
	var version uint64
	var bindings []vnextLocalDAXBinding
	for decoder.More() {
		field, err := readVNextReaderBindingManifestField(decoder, "manifest")
		if err != nil {
			return nil, err
		}
		if _, duplicate := seen[field]; duplicate {
			return nil, fmt.Errorf("manifest has duplicate field %q", field)
		}
		seen[field] = struct{}{}
		switch field {
		case "protocol":
			protocol, err = readVNextReaderBindingManifestString(
				decoder, "manifest.protocol")
		case "version":
			version, err = readVNextReaderBindingManifestUint64(
				decoder, "manifest.version")
		case "devices":
			bindings, err = parseVNextReaderBindingManifestDevices(decoder)
		default:
			return nil, fmt.Errorf("manifest has unknown field %q", field)
		}
		if err != nil {
			return nil, err
		}
	}
	if err := expectVNextReaderBindingManifestDelimiter(decoder, '}', "manifest"); err != nil {
		return nil, err
	}
	for _, required := range []string{"protocol", "version", "devices"} {
		if _, present := seen[required]; !present {
			return nil, fmt.Errorf("manifest is missing required field %q", required)
		}
	}
	if protocol != vnextReaderBindingManifestProtocol {
		return nil, fmt.Errorf(
			"VNext Reader binding manifest protocol is %q, expected %q",
			protocol, vnextReaderBindingManifestProtocol)
	}
	if version != vnextReaderBindingManifestVersion {
		return nil, fmt.Errorf(
			"VNext Reader binding manifest version is %d, expected %d",
			version, vnextReaderBindingManifestVersion)
	}
	if token, err := decoder.Token(); !errors.Is(err, io.EOF) {
		if err == nil {
			return nil, fmt.Errorf(
				"VNext Reader binding manifest has trailing JSON value %v", token)
		}
		return nil, fmt.Errorf("decode VNext Reader binding manifest trailer: %w", err)
	}
	directory, err := newVNextLocalDAXDirectory(bindings)
	if err != nil {
		return nil, fmt.Errorf("construct VNext Reader local DAX directory: %w", err)
	}
	return directory, nil
}

func validateVNextReaderBindingManifestJSONDepth(raw []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	depth := 0
	for {
		token, err := decoder.Token()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return fmt.Errorf("decode VNext Reader binding manifest JSON: %w", err)
		}
		delimiter, ok := token.(json.Delim)
		if !ok {
			continue
		}
		switch delimiter {
		case '{', '[':
			depth++
			if depth > vnextReaderBindingManifestMaxJSONDepth {
				return fmt.Errorf(
					"VNext Reader binding manifest JSON depth exceeds %d",
					vnextReaderBindingManifestMaxJSONDepth)
			}
		case '}', ']':
			depth--
			if depth < 0 {
				return errors.New("VNext Reader binding manifest JSON has an invalid terminator")
			}
		}
	}
	if depth != 0 {
		return errors.New("VNext Reader binding manifest JSON is not structurally complete")
	}
	return nil
}

func parseVNextReaderBindingManifestDevices(
	decoder *json.Decoder,
) ([]vnextLocalDAXBinding, error) {
	if err := expectVNextReaderBindingManifestDelimiter(
		decoder, '[', "manifest.devices"); err != nil {
		return nil, err
	}
	bindings := make([]vnextLocalDAXBinding, 0)
	seenUUIDs := make(map[string]struct{})
	seenPaths := make(map[string]string)
	previousUUID := ""
	for decoder.More() {
		if len(bindings) >= vnextReaderBindingManifestMaxDevices {
			return nil, fmt.Errorf(
				"manifest.devices contains more than %d devices",
				vnextReaderBindingManifestMaxDevices)
		}
		binding, err := parseVNextReaderBindingManifestDevice(
			decoder, len(bindings))
		if err != nil {
			return nil, err
		}
		if _, duplicate := seenUUIDs[binding.DeviceUUID]; duplicate {
			return nil, fmt.Errorf(
				"manifest.devices has duplicate deviceUuid %q", binding.DeviceUUID)
		}
		if previousUUID != "" && bytes.Compare(
			[]byte(previousUUID), []byte(binding.DeviceUUID)) >= 0 {
			return nil, fmt.Errorf(
				"manifest.devices is not in strictly increasing UTF-8 byte order at %q",
				binding.DeviceUUID)
		}
		if previous, duplicate := seenPaths[binding.DevicePath]; duplicate {
			return nil, fmt.Errorf(
				"manifest.devices path %q aliases deviceUuid %q and %q",
				binding.DevicePath, previous, binding.DeviceUUID)
		}
		bindings = append(bindings, binding)
		seenUUIDs[binding.DeviceUUID] = struct{}{}
		seenPaths[binding.DevicePath] = binding.DeviceUUID
		previousUUID = binding.DeviceUUID
	}
	if err := expectVNextReaderBindingManifestDelimiter(
		decoder, ']', "manifest.devices"); err != nil {
		return nil, err
	}
	if len(bindings) == 0 {
		return nil, errors.New("manifest.devices must be non-empty")
	}
	return bindings, nil
}

func parseVNextReaderBindingManifestDevice(
	decoder *json.Decoder,
	index int,
) (vnextLocalDAXBinding, error) {
	path := fmt.Sprintf("manifest.devices[%d]", index)
	if err := expectVNextReaderBindingManifestDelimiter(decoder, '{', path); err != nil {
		return vnextLocalDAXBinding{}, err
	}
	seen := make(map[string]struct{}, 6)
	var binding vnextLocalDAXBinding
	for decoder.More() {
		field, err := readVNextReaderBindingManifestField(decoder, path)
		if err != nil {
			return vnextLocalDAXBinding{}, err
		}
		if _, duplicate := seen[field]; duplicate {
			return vnextLocalDAXBinding{}, fmt.Errorf(
				"%s has duplicate field %q", path, field)
		}
		seen[field] = struct{}{}
		switch field {
		case "deviceUuid":
			binding.DeviceUUID, err = readVNextReaderBindingManifestString(
				decoder, path+".deviceUuid")
		case "ownerId":
			binding.OwnerID, err = readVNextReaderBindingManifestString(
				decoder, path+".ownerId")
		case "ownerEpoch":
			binding.OwnerEpoch, err = readVNextReaderBindingManifestUint64(
				decoder, path+".ownerEpoch")
		case "dataPageCount":
			binding.DataPageCount, err = readVNextReaderBindingManifestUint64(
				decoder, path+".dataPageCount")
		case "contentRegionBase":
			binding.ContentRegionBase, err = readVNextReaderBindingManifestUint64(
				decoder, path+".contentRegionBase")
		case "devicePath":
			binding.DevicePath, err = readVNextReaderBindingManifestString(
				decoder, path+".devicePath")
		default:
			return vnextLocalDAXBinding{}, fmt.Errorf(
				"%s has unknown field %q", path, field)
		}
		if err != nil {
			return vnextLocalDAXBinding{}, err
		}
	}
	if err := expectVNextReaderBindingManifestDelimiter(decoder, '}', path); err != nil {
		return vnextLocalDAXBinding{}, err
	}
	for _, required := range []string{
		"deviceUuid", "ownerId", "ownerEpoch", "dataPageCount",
		"contentRegionBase", "devicePath",
	} {
		if _, present := seen[required]; !present {
			return vnextLocalDAXBinding{}, fmt.Errorf(
				"%s is missing required field %q", path, required)
		}
	}
	if err := validateVNextReaderDeviceID(binding.DeviceUUID); err != nil {
		return vnextLocalDAXBinding{}, fmt.Errorf("%s.deviceUuid: %w", path, err)
	}
	if err := validateVNextReaderIdentity("binding Owner ID", binding.OwnerID); err != nil {
		return vnextLocalDAXBinding{}, fmt.Errorf("%s.ownerId: %w", path, err)
	}
	if binding.OwnerEpoch == 0 || binding.DataPageCount == 0 {
		return vnextLocalDAXBinding{}, fmt.Errorf(
			"%s ownerEpoch and dataPageCount must be positive", path)
	}
	if binding.ContentRegionBase == 0 ||
		binding.ContentRegionBase%cxlcheckpoint.PageSize != 0 {
		return vnextLocalDAXBinding{}, fmt.Errorf(
			"%s.contentRegionBase must be positive and %d-byte aligned",
			path, cxlcheckpoint.PageSize)
	}
	if err := validateVNextLocalDAXPath(binding.DevicePath); err != nil {
		return vnextLocalDAXBinding{}, fmt.Errorf("%s.devicePath: %w", path, err)
	}
	return binding, nil
}

func readVNextReaderBindingManifestField(
	decoder *json.Decoder,
	path string,
) (string, error) {
	token, err := decoder.Token()
	if err != nil {
		return "", fmt.Errorf("%s field: %w", path, err)
	}
	field, ok := token.(string)
	if !ok {
		return "", fmt.Errorf("%s field name is not a string", path)
	}
	return field, nil
}

func readVNextReaderBindingManifestString(
	decoder *json.Decoder,
	path string,
) (string, error) {
	token, err := decoder.Token()
	if err != nil {
		return "", fmt.Errorf("%s: %w", path, err)
	}
	value, ok := token.(string)
	if !ok {
		return "", fmt.Errorf("%s must be a non-null JSON string", path)
	}
	return value, nil
}

func readVNextReaderBindingManifestUint64(
	decoder *json.Decoder,
	path string,
) (uint64, error) {
	token, err := decoder.Token()
	if err != nil {
		return 0, fmt.Errorf("%s: %w", path, err)
	}
	number, ok := token.(json.Number)
	if !ok {
		return 0, fmt.Errorf("%s must be a non-null JSON integer", path)
	}
	value, err := strconv.ParseUint(number.String(), 10, 64)
	if err != nil {
		return 0, fmt.Errorf("%s must be an unsigned JSON integer: %w", path, err)
	}
	return value, nil
}

func expectVNextReaderBindingManifestDelimiter(
	decoder *json.Decoder,
	want json.Delim,
	path string,
) error {
	token, err := decoder.Token()
	if err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	delimiter, ok := token.(json.Delim)
	if !ok || delimiter != want {
		return fmt.Errorf("%s must use JSON delimiter %q", path, want)
	}
	return nil
}

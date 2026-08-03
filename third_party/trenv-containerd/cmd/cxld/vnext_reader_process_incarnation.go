package main

import (
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"golang.org/x/sys/unix"
)

const (
	vnextReaderProcessIncarnationBytes      = 32
	vnextReaderProcessIncarnationPath       = "/run/cxld/process-incarnation"
	vnextReaderProcessIncarnationMode       = 0o600
	vnextReaderProcessIncarnationLockSuffix = ".lock"
)

var errVNextReaderProcessIncarnationLockHeld = errors.New(
	"VNext Reader process-incarnation lock is already held")

// vnextReaderProcessIncarnation identifies one enabled Reader runtime start.
// It is intentionally distinct from the configured logical cxld service ID.
// The value is generated once, never loaded from disk, and is encoded only at
// file and wire boundaries.
type vnextReaderProcessIncarnation [vnextReaderProcessIncarnationBytes]byte

func newVNextReaderProcessIncarnation(
	entropy io.Reader,
) (vnextReaderProcessIncarnation, error) {
	var incarnation vnextReaderProcessIncarnation
	if vnextReaderPreparedStatusNilInterface(entropy) {
		return incarnation, errors.New(
			"VNext Reader process-incarnation entropy source is unavailable")
	}
	if _, err := io.ReadFull(entropy, incarnation[:]); err != nil {
		return vnextReaderProcessIncarnation{}, fmt.Errorf(
			"read VNext Reader process-incarnation entropy: %w", err)
	}
	if allVNextReaderZero(incarnation[:]) {
		return vnextReaderProcessIncarnation{}, errors.New(
			"VNext Reader process incarnation is zero")
	}
	return incarnation, nil
}

func parseVNextReaderProcessIncarnation(
	value string,
) (vnextReaderProcessIncarnation, error) {
	var incarnation vnextReaderProcessIncarnation
	if len(value) != hex.EncodedLen(len(incarnation)) ||
		value != strings.ToLower(value) {
		return incarnation, errors.New(
			"VNext Reader process incarnation is not canonical 64-character lowercase hex")
	}
	decoded, err := hex.DecodeString(value)
	if err != nil || len(decoded) != len(incarnation) {
		return incarnation, fmt.Errorf(
			"decode VNext Reader process incarnation: %w", err)
	}
	copy(incarnation[:], decoded)
	if allVNextReaderZero(incarnation[:]) {
		return vnextReaderProcessIncarnation{}, errors.New(
			"VNext Reader process incarnation is zero")
	}
	return incarnation, nil
}

func (incarnation vnextReaderProcessIncarnation) String() string {
	return hex.EncodeToString(incarnation[:])
}

func validateVNextReaderProcessIncarnation(
	incarnation vnextReaderProcessIncarnation,
) error {
	if allVNextReaderZero(incarnation[:]) {
		return errors.New("VNext Reader process incarnation is zero")
	}
	parsed, err := parseVNextReaderProcessIncarnation(incarnation.String())
	if err != nil {
		return err
	}
	if parsed != incarnation {
		return errors.New(
			"VNext Reader process incarnation did not round-trip canonically")
	}
	return nil
}

type vnextReaderProcessIncarnationPublisher interface {
	Publish(string, vnextReaderProcessIncarnation) error
}

type vnextReaderProcessIncarnationLock interface {
	RemovePublishedIdentity(vnextReaderProcessIncarnation, bool) error
	Release() error
}

type vnextReaderProcessIncarnationLockAcquirer interface {
	Acquire(string) (vnextReaderProcessIncarnationLock, error)
}

type vnextReaderProcessIncarnationFilePublisher struct{}

// Publish atomically replaces only a pre-existing, owner-matched 0600 regular
// file. The directory is opened without following its final path component;
// all subsequent target operations are relative to that stable directory fd.
// A same-directory O_EXCL temporary file is synced before rename and the
// directory is synced after rename.
func (vnextReaderProcessIncarnationFilePublisher) Publish(
	path string,
	incarnation vnextReaderProcessIncarnation,
) error {
	if err := validateVNextReaderProcessIncarnation(incarnation); err != nil {
		return err
	}
	directoryFD, name, err := openVNextReaderProcessIncarnationDirectory(path)
	if err != nil {
		return err
	}
	defer unix.Close(directoryFD)

	var existing unix.Stat_t
	err = unix.Fstatat(directoryFD, name, &existing, unix.AT_SYMLINK_NOFOLLOW)
	switch {
	case err == nil:
		if err := validateVNextReaderProcessIncarnationFileStat(
			"target", existing); err != nil {
			return err
		}
		existingFD, openedStat, existingIncarnation, err :=
			openVNextReaderProcessIncarnationTarget(directoryFD, name, existing)
		if err != nil {
			return err
		}
		if closeErr := unix.Close(existingFD); closeErr != nil {
			return fmt.Errorf(
				"close validated VNext Reader process-incarnation target: %w",
				closeErr)
		}
		_ = openedStat
		// A preserved value is validated solely to make replacement safe. It is
		// never reused as this process's new incarnation.
		_ = existingIncarnation
	case errors.Is(err, unix.ENOENT):
		// First process start in this boot has no preserved target.
	default:
		return fmt.Errorf("lstat VNext Reader process-incarnation target: %w", err)
	}

	temporaryName := "." + name + "." + incarnation.String() + ".tmp"
	temporaryFD, err := unix.Openat(
		directoryFD,
		temporaryName,
		unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC,
		vnextReaderProcessIncarnationMode)
	if err != nil {
		return fmt.Errorf("create VNext Reader process-incarnation temporary file: %w", err)
	}
	temporaryPresent := true
	temporaryOpen := true
	defer func() {
		if temporaryOpen {
			_ = unix.Close(temporaryFD)
		}
		if temporaryPresent {
			_ = unix.Unlinkat(directoryFD, temporaryName, 0)
		}
	}()
	if err := unix.Fchmod(temporaryFD, vnextReaderProcessIncarnationMode); err != nil {
		return fmt.Errorf("chmod VNext Reader process-incarnation temporary file: %w", err)
	}
	var temporaryStat unix.Stat_t
	if err := unix.Fstat(temporaryFD, &temporaryStat); err != nil {
		return fmt.Errorf("stat VNext Reader process-incarnation temporary file: %w", err)
	}
	if err := validateVNextReaderProcessIncarnationFileStat(
		"temporary file", temporaryStat); err != nil {
		return fmt.Errorf("validate VNext Reader process-incarnation temporary file: %w", err)
	}
	content := append([]byte(incarnation.String()), '\n')
	if err := writeVNextReaderProcessIncarnationFile(temporaryFD, content); err != nil {
		return err
	}
	if err := unix.Fsync(temporaryFD); err != nil {
		return fmt.Errorf("sync VNext Reader process-incarnation temporary file: %w", err)
	}
	if err := unix.Close(temporaryFD); err != nil {
		temporaryOpen = false
		return fmt.Errorf("close VNext Reader process-incarnation temporary file: %w", err)
	}
	temporaryOpen = false
	if err := unix.Renameat(directoryFD, temporaryName, directoryFD, name); err != nil {
		return fmt.Errorf("replace VNext Reader process-incarnation file: %w", err)
	}
	temporaryPresent = false
	if err := unix.Fsync(directoryFD); err != nil {
		return fmt.Errorf("sync VNext Reader process-incarnation directory: %w", err)
	}
	return nil
}

func openVNextReaderProcessIncarnationDirectory(
	path string,
) (int, string, error) {
	if path == "" || !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return -1, "", fmt.Errorf(
			"VNext Reader process-incarnation path %q is not absolute and clean", path)
	}
	directory := filepath.Dir(path)
	name := filepath.Base(path)
	if name == "." || name == string(filepath.Separator) || name == "" {
		return -1, "", errors.New(
			"VNext Reader process-incarnation file name is invalid")
	}
	directoryFD, err := unix.Open(
		directory, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return -1, "", fmt.Errorf(
			"open VNext Reader process-incarnation directory: %w", err)
	}
	var directoryStat unix.Stat_t
	if err := unix.Fstat(directoryFD, &directoryStat); err != nil {
		_ = unix.Close(directoryFD)
		return -1, "", fmt.Errorf(
			"stat VNext Reader process-incarnation directory: %w", err)
	}
	if directoryStat.Mode&unix.S_IFMT != unix.S_IFDIR ||
		directoryStat.Uid != uint32(os.Geteuid()) || directoryStat.Mode&0o022 != 0 {
		_ = unix.Close(directoryFD)
		return -1, "", fmt.Errorf(
			"VNext Reader process-incarnation directory is not owner-controlled: mode=%#o uid=%d expectedUid=%d",
			directoryStat.Mode, directoryStat.Uid, os.Geteuid())
	}
	return directoryFD, name, nil
}

func validateVNextReaderProcessIncarnationFileStat(
	role string,
	stat unix.Stat_t,
) error {
	if stat.Mode&unix.S_IFMT != unix.S_IFREG {
		return fmt.Errorf(
			"VNext Reader process-incarnation %s is not a regular file", role)
	}
	if stat.Uid != uint32(os.Geteuid()) {
		return fmt.Errorf(
			"VNext Reader process-incarnation %s has a different owner", role)
	}
	if stat.Mode&0o7777 != vnextReaderProcessIncarnationMode {
		return fmt.Errorf(
			"VNext Reader process-incarnation %s mode is %#o, expected %#o",
			role, stat.Mode&0o7777, vnextReaderProcessIncarnationMode)
	}
	if stat.Nlink != 1 {
		return fmt.Errorf(
			"VNext Reader process-incarnation %s is not singly linked", role)
	}
	return nil
}

func openVNextReaderProcessIncarnationTarget(
	directoryFD int,
	name string,
	lstat unix.Stat_t,
) (int, unix.Stat_t, vnextReaderProcessIncarnation, error) {
	var zeroStat unix.Stat_t
	var zeroIncarnation vnextReaderProcessIncarnation
	fd, err := unix.Openat(
		directoryFD, name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return -1, zeroStat, zeroIncarnation, fmt.Errorf(
			"open preserved VNext Reader process-incarnation target: %w", err)
	}
	fail := func(cause error) (int, unix.Stat_t, vnextReaderProcessIncarnation, error) {
		_ = unix.Close(fd)
		return -1, zeroStat, zeroIncarnation, cause
	}
	var opened unix.Stat_t
	if err := unix.Fstat(fd, &opened); err != nil {
		return fail(fmt.Errorf(
			"fstat preserved VNext Reader process-incarnation target: %w", err))
	}
	if err := validateVNextReaderProcessIncarnationFileStat(
		"target", opened); err != nil {
		return fail(err)
	}
	if opened.Dev != lstat.Dev || opened.Ino != lstat.Ino {
		return fail(errors.New(
			"VNext Reader process-incarnation target changed between lstat and open"))
	}
	incarnation, err := readVNextReaderProcessIncarnationFile(fd)
	if err != nil {
		return fail(err)
	}
	return fd, opened, incarnation, nil
}

func readVNextReaderProcessIncarnationFile(
	fd int,
) (vnextReaderProcessIncarnation, error) {
	var zero vnextReaderProcessIncarnation
	const canonicalBytes = vnextReaderProcessIncarnationBytes * 2
	content := make([]byte, canonicalBytes+1)
	for offset := 0; offset < len(content); {
		read, err := unix.Read(fd, content[offset:])
		if errors.Is(err, unix.EINTR) {
			continue
		}
		if err != nil {
			return zero, fmt.Errorf(
				"read preserved VNext Reader process-incarnation target: %w", err)
		}
		if read == 0 {
			return zero, errors.New(
				"preserved VNext Reader process-incarnation target is shorter than 65 bytes")
		}
		offset += read
	}
	if content[canonicalBytes] != '\n' {
		return zero, errors.New(
			"preserved VNext Reader process-incarnation target has no exact trailing newline")
	}
	var extra [1]byte
	for {
		read, err := unix.Read(fd, extra[:])
		if errors.Is(err, unix.EINTR) {
			continue
		}
		if err != nil {
			return zero, fmt.Errorf(
				"read preserved VNext Reader process-incarnation target EOF: %w", err)
		}
		if read != 0 {
			return zero, errors.New(
				"preserved VNext Reader process-incarnation target has trailing bytes")
		}
		break
	}
	incarnation, err := parseVNextReaderProcessIncarnation(
		string(content[:canonicalBytes]))
	if err != nil {
		return zero, fmt.Errorf(
			"validate preserved VNext Reader process-incarnation target: %w", err)
	}
	return incarnation, nil
}

type vnextReaderProcessIncarnationFileLockAcquirer struct{}

type vnextReaderProcessIncarnationFileLock struct {
	mu          sync.Mutex
	directoryFD int
	lockFD      int
	targetName  string
	released    bool
}

func (vnextReaderProcessIncarnationFileLockAcquirer) Acquire(
	path string,
) (vnextReaderProcessIncarnationLock, error) {
	directoryFD, targetName, err := openVNextReaderProcessIncarnationDirectory(path)
	if err != nil {
		return nil, err
	}
	fail := func(cause error) (vnextReaderProcessIncarnationLock, error) {
		_ = unix.Close(directoryFD)
		return nil, cause
	}
	lockName := targetName + vnextReaderProcessIncarnationLockSuffix
	lockFD, err := unix.Openat(
		directoryFD,
		lockName,
		unix.O_RDWR|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC,
		vnextReaderProcessIncarnationMode)
	created := err == nil
	if errors.Is(err, unix.EEXIST) {
		lockFD, err = unix.Openat(
			directoryFD, lockName,
			unix.O_RDWR|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	}
	if err != nil {
		return fail(fmt.Errorf(
			"open VNext Reader process-incarnation lock file: %w", err))
	}
	failOpen := func(cause error) (vnextReaderProcessIncarnationLock, error) {
		_ = unix.Close(lockFD)
		return fail(cause)
	}
	if created {
		if err := unix.Fchmod(lockFD, vnextReaderProcessIncarnationMode); err != nil {
			return failOpen(fmt.Errorf(
				"chmod VNext Reader process-incarnation lock file: %w", err))
		}
	}
	var lockStat unix.Stat_t
	if err := unix.Fstat(lockFD, &lockStat); err != nil {
		return failOpen(fmt.Errorf(
			"fstat VNext Reader process-incarnation lock file: %w", err))
	}
	if err := validateVNextReaderProcessIncarnationFileStat(
		"lock file", lockStat); err != nil {
		return failOpen(err)
	}
	if err := unix.Flock(lockFD, unix.LOCK_EX|unix.LOCK_NB); err != nil {
		if errors.Is(err, unix.EWOULDBLOCK) || errors.Is(err, unix.EAGAIN) {
			return failOpen(fmt.Errorf(
				"%w: %s", errVNextReaderProcessIncarnationLockHeld, path))
		}
		return failOpen(fmt.Errorf(
			"acquire VNext Reader process-incarnation lock: %w", err))
	}
	return &vnextReaderProcessIncarnationFileLock{
		directoryFD: directoryFD,
		lockFD:      lockFD,
		targetName:  targetName,
	}, nil
}

// RemovePublishedIdentity removes only the exact incarnation published by
// this lock holder. requireExact is true once Publish returned success; it is
// false while cleaning up a Publish error that may have occurred before or
// after rename.
func (lock *vnextReaderProcessIncarnationFileLock) RemovePublishedIdentity(
	incarnation vnextReaderProcessIncarnation,
	requireExact bool,
) error {
	if lock == nil {
		return errors.New("VNext Reader process-incarnation lock is unavailable")
	}
	if err := validateVNextReaderProcessIncarnation(incarnation); err != nil {
		return err
	}
	lock.mu.Lock()
	defer lock.mu.Unlock()
	if lock.released || lock.directoryFD < 0 || lock.lockFD < 0 {
		return errors.New("VNext Reader process-incarnation lock is released")
	}
	var lstat unix.Stat_t
	err := unix.Fstatat(
		lock.directoryFD, lock.targetName, &lstat, unix.AT_SYMLINK_NOFOLLOW)
	if errors.Is(err, unix.ENOENT) {
		if requireExact {
			return errors.New(
				"published VNext Reader process-incarnation target is missing")
		}
		return nil
	}
	if err != nil {
		return fmt.Errorf(
			"lstat published VNext Reader process-incarnation target: %w", err)
	}
	if err := validateVNextReaderProcessIncarnationFileStat(
		"target", lstat); err != nil {
		return err
	}
	targetFD, opened, observed, err := openVNextReaderProcessIncarnationTarget(
		lock.directoryFD, lock.targetName, lstat)
	if err != nil {
		return err
	}
	defer unix.Close(targetFD)
	if observed != incarnation {
		if requireExact {
			return fmt.Errorf(
				"published VNext Reader process incarnation changed from %s to %s",
				incarnation, observed)
		}
		return nil
	}
	var current unix.Stat_t
	if err := unix.Fstatat(
		lock.directoryFD, lock.targetName, &current,
		unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return fmt.Errorf(
			"re-lstat published VNext Reader process-incarnation target: %w", err)
	}
	if err := validateVNextReaderProcessIncarnationFileStat(
		"target", current); err != nil {
		return err
	}
	if current.Dev != opened.Dev || current.Ino != opened.Ino {
		return errors.New(
			"published VNext Reader process-incarnation target changed before removal")
	}
	if err := unix.Unlinkat(lock.directoryFD, lock.targetName, 0); err != nil {
		return fmt.Errorf(
			"remove published VNext Reader process-incarnation target: %w", err)
	}
	if err := unix.Fsync(lock.directoryFD); err != nil {
		return fmt.Errorf(
			"sync VNext Reader process-incarnation directory after removal: %w", err)
	}
	return nil
}

func (lock *vnextReaderProcessIncarnationFileLock) Release() error {
	if lock == nil {
		return nil
	}
	lock.mu.Lock()
	defer lock.mu.Unlock()
	if lock.released {
		return nil
	}
	lock.released = true
	var first error
	if lock.lockFD >= 0 {
		if err := unix.Flock(lock.lockFD, unix.LOCK_UN); err != nil {
			first = fmt.Errorf(
				"release VNext Reader process-incarnation flock: %w", err)
		}
		if err := unix.Close(lock.lockFD); err != nil && first == nil {
			first = fmt.Errorf(
				"close VNext Reader process-incarnation lock file: %w", err)
		}
		lock.lockFD = -1
	}
	if lock.directoryFD >= 0 {
		if err := unix.Close(lock.directoryFD); err != nil && first == nil {
			first = fmt.Errorf(
				"close VNext Reader process-incarnation directory: %w", err)
		}
		lock.directoryFD = -1
	}
	return first
}

func writeVNextReaderProcessIncarnationFile(fd int, content []byte) error {
	for len(content) != 0 {
		written, err := unix.Write(fd, content)
		if errors.Is(err, unix.EINTR) {
			continue
		}
		if err != nil {
			return fmt.Errorf("write VNext Reader process-incarnation file: %w", err)
		}
		if written <= 0 || written > len(content) {
			return io.ErrShortWrite
		}
		content = content[written:]
	}
	return nil
}

var _ vnextReaderProcessIncarnationPublisher = (*vnextReaderProcessIncarnationFilePublisher)(nil)
var _ vnextReaderProcessIncarnationLockAcquirer = (*vnextReaderProcessIncarnationFileLockAcquirer)(nil)
var _ vnextReaderProcessIncarnationLock = (*vnextReaderProcessIncarnationFileLock)(nil)

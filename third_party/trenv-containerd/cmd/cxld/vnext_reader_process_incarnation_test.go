package main

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type vnextReaderProcessIncarnationErrorReader struct {
	err error
}

func (reader vnextReaderProcessIncarnationErrorReader) Read([]byte) (int, error) {
	return 0, reader.err
}

func vnextReaderProcessIncarnationForTest(value byte) vnextReaderProcessIncarnation {
	var incarnation vnextReaderProcessIncarnation
	for index := range incarnation {
		incarnation[index] = value
	}
	return incarnation
}

func vnextReaderProcessIncarnationSecureTestDir(t *testing.T) string {
	t.Helper()
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatalf("chmod secure process-incarnation test directory: %v", err)
	}
	return directory
}

func TestVNextReaderProcessIncarnationCanonicalValidation(t *testing.T) {
	want := vnextReaderProcessIncarnationForTest(0xab)
	parsed, err := parseVNextReaderProcessIncarnation(want.String())
	if err != nil || parsed != want || len(parsed.String()) != 64 {
		t.Fatalf("canonical process incarnation round trip = %q/%v", parsed, err)
	}
	for name, value := range map[string]string{
		"empty":      "",
		"short":      strings.Repeat("a", 63),
		"long":       strings.Repeat("a", 65),
		"uppercase":  strings.Repeat("A", 64),
		"non-hex":    strings.Repeat("g", 64),
		"zero":       strings.Repeat("0", 64),
		"whitespace": strings.Repeat("a", 63) + " ",
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := parseVNextReaderProcessIncarnation(value); err == nil {
				t.Fatalf("accepted non-canonical process incarnation %q", value)
			}
		})
	}
}

func TestVNextReaderProcessIncarnationEntropyFailsClosed(t *testing.T) {
	entropyErr := errors.New("test entropy failure")
	if incarnation, err := newVNextReaderProcessIncarnation(
		vnextReaderProcessIncarnationErrorReader{err: entropyErr}); incarnation != (vnextReaderProcessIncarnation{}) ||
		!errors.Is(err, entropyErr) {
		t.Fatalf("entropy failure returned incarnation=%s err=%v", incarnation, err)
	}
	if _, err := newVNextReaderProcessIncarnation(
		bytes.NewReader(make([]byte, vnextReaderProcessIncarnationBytes))); err == nil {
		t.Fatal("accepted all-zero process-incarnation entropy")
	}
	if _, err := newVNextReaderProcessIncarnation(
		bytes.NewReader(make([]byte, vnextReaderProcessIncarnationBytes-1))); err == nil {
		t.Fatal("accepted short process-incarnation entropy")
	}
}

func TestVNextReaderProcessIncarnationChangesOnEveryStart(t *testing.T) {
	entropy := append(
		bytes.Repeat([]byte{0x11}, vnextReaderProcessIncarnationBytes),
		bytes.Repeat([]byte{0x22}, vnextReaderProcessIncarnationBytes)...)
	reader := bytes.NewReader(entropy)
	first, err := newVNextReaderProcessIncarnation(reader)
	if err != nil {
		t.Fatalf("generate first process incarnation: %v", err)
	}
	second, err := newVNextReaderProcessIncarnation(reader)
	if err != nil {
		t.Fatalf("generate second process incarnation: %v", err)
	}
	if first == second || first.String() != strings.Repeat("11", 32) ||
		second.String() != strings.Repeat("22", 32) {
		t.Fatalf("restart incarnations first=%s second=%s", first, second)
	}
}

func TestVNextReaderProcessIncarnationAtomicPublishAndPreservedOverwrite(
	t *testing.T,
) {
	directory := vnextReaderProcessIncarnationSecureTestDir(t)
	path := filepath.Join(directory, "process-incarnation")
	publisher := &vnextReaderProcessIncarnationFilePublisher{}
	first := vnextReaderProcessIncarnationForTest(0x31)
	second := vnextReaderProcessIncarnationForTest(0x72)
	if err := publisher.Publish(path, first); err != nil {
		t.Fatalf("publish first process incarnation: %v", err)
	}
	assertVNextReaderProcessIncarnationFile(t, path, first)
	firstInfo, err := os.Lstat(path)
	if err != nil {
		t.Fatalf("lstat first process incarnation: %v", err)
	}
	if err := publisher.Publish(path, second); err != nil {
		t.Fatalf("replace preserved process incarnation: %v", err)
	}
	assertVNextReaderProcessIncarnationFile(t, path, second)
	secondInfo, err := os.Lstat(path)
	if err != nil {
		t.Fatalf("lstat second process incarnation: %v", err)
	}
	if os.SameFile(firstInfo, secondInfo) {
		t.Fatal("preserved process-incarnation target was rewritten in place")
	}
	entries, err := os.ReadDir(directory)
	if err != nil {
		t.Fatalf("read process-incarnation directory: %v", err)
	}
	if len(entries) != 1 || entries[0].Name() != filepath.Base(path) {
		t.Fatalf("atomic publish left unexpected directory entries: %#v", entries)
	}
}

func assertVNextReaderProcessIncarnationFile(
	t *testing.T,
	path string,
	want vnextReaderProcessIncarnation,
) {
	t.Helper()
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read process-incarnation file: %v", err)
	}
	if string(body) != want.String()+"\n" {
		t.Fatalf("process-incarnation content = %q, want exact canonical line", body)
	}
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatalf("lstat process-incarnation file: %v", err)
	}
	if !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
		t.Fatalf("process-incarnation mode = %s, want regular 0600", info.Mode())
	}
}

func TestVNextReaderProcessIncarnationPublisherRejectsUnsafeTargets(
	t *testing.T,
) {
	incarnation := vnextReaderProcessIncarnationForTest(0x44)
	for name, arrange := range map[string]func(*testing.T, string){
		"symlink": func(t *testing.T, path string) {
			if err := os.Symlink(filepath.Join(t.TempDir(), "outside"), path); err != nil {
				t.Fatalf("create target symlink: %v", err)
			}
		},
		"directory": func(t *testing.T, path string) {
			if err := os.Mkdir(path, 0o700); err != nil {
				t.Fatalf("create target directory: %v", err)
			}
		},
		"wrong-mode": func(t *testing.T, path string) {
			if err := os.WriteFile(path, []byte("preserved"), 0o640); err != nil {
				t.Fatalf("create wrong-mode target: %v", err)
			}
			if err := os.Chmod(path, 0o640); err != nil {
				t.Fatalf("chmod wrong-mode target: %v", err)
			}
		},
		"hard-link": func(t *testing.T, path string) {
			source := filepath.Join(filepath.Dir(path), "source")
			if err := os.WriteFile(source, []byte("preserved"), 0o600); err != nil {
				t.Fatalf("create hard-link source: %v", err)
			}
			if err := os.Link(source, path); err != nil {
				t.Fatalf("create hard-link target: %v", err)
			}
		},
	} {
		t.Run(name, func(t *testing.T) {
			directory := vnextReaderProcessIncarnationSecureTestDir(t)
			path := filepath.Join(directory, "process-incarnation")
			arrange(t, path)
			before, _ := os.Lstat(path)
			err := (&vnextReaderProcessIncarnationFilePublisher{}).Publish(
				path, incarnation)
			if err == nil {
				t.Fatalf("unsafe %s target was replaced", name)
			}
			after, statErr := os.Lstat(path)
			if statErr != nil || before == nil || !os.SameFile(before, after) {
				t.Fatalf("unsafe target changed after rejection: err=%v", statErr)
			}
		})
	}
}

func TestVNextReaderProcessIncarnationPublisherRejectsMalformedPreservedValue(
	t *testing.T,
) {
	valid := strings.Repeat("ab", vnextReaderProcessIncarnationBytes)
	for name, content := range map[string][]byte{
		"empty":            {},
		"partial":          []byte(valid[:63]),
		"missing-newline":  []byte(valid),
		"extra-byte":       []byte(valid + "\nX"),
		"extra-newline":    []byte(valid + "\n\n"),
		"uppercase":        []byte(strings.ToUpper(valid) + "\n"),
		"zero":             []byte(strings.Repeat("0", 64) + "\n"),
		"non-hex":          []byte(strings.Repeat("g", 64) + "\n"),
		"wrong-terminator": []byte(valid + "X"),
	} {
		t.Run(name, func(t *testing.T) {
			directory := vnextReaderProcessIncarnationSecureTestDir(t)
			path := filepath.Join(directory, "process-incarnation")
			if err := os.WriteFile(path, content, 0o600); err != nil {
				t.Fatalf("write malformed preserved target: %v", err)
			}
			if err := os.Chmod(path, 0o600); err != nil {
				t.Fatalf("chmod malformed preserved target: %v", err)
			}
			before, err := os.Lstat(path)
			if err != nil {
				t.Fatal(err)
			}
			err = (&vnextReaderProcessIncarnationFilePublisher{}).Publish(
				path, vnextReaderProcessIncarnationForTest(0x77))
			if err == nil {
				t.Fatalf("malformed preserved value %q was replaced", content)
			}
			after, err := os.Lstat(path)
			if err != nil || !os.SameFile(before, after) {
				t.Fatalf("malformed preserved target inode changed: %v", err)
			}
			observed, err := os.ReadFile(path)
			if err != nil || !bytes.Equal(observed, content) {
				t.Fatalf("malformed preserved target content changed: %q err=%v",
					observed, err)
			}
		})
	}
}

func TestVNextReaderProcessIncarnationPublisherRejectsUnsafePathAndDirectory(
	t *testing.T,
) {
	incarnation := vnextReaderProcessIncarnationForTest(0x55)
	publisher := &vnextReaderProcessIncarnationFilePublisher{}
	if err := publisher.Publish("relative/process-incarnation", incarnation); err == nil {
		t.Fatal("accepted relative process-incarnation path")
	}
	realDirectory := vnextReaderProcessIncarnationSecureTestDir(t)
	parent := vnextReaderProcessIncarnationSecureTestDir(t)
	symlinkDirectory := filepath.Join(parent, "cxld")
	if err := os.Symlink(realDirectory, symlinkDirectory); err != nil {
		t.Fatalf("create directory symlink: %v", err)
	}
	if err := publisher.Publish(
		filepath.Join(symlinkDirectory, "process-incarnation"), incarnation); err == nil {
		t.Fatal("accepted symlink process-incarnation directory")
	}
	unsafeDirectory := filepath.Join(
		vnextReaderProcessIncarnationSecureTestDir(t), "world-writable")
	if err := os.Mkdir(unsafeDirectory, 0o777); err != nil {
		t.Fatalf("create unsafe directory: %v", err)
	}
	if err := os.Chmod(unsafeDirectory, 0o777); err != nil {
		t.Fatalf("chmod unsafe directory: %v", err)
	}
	if err := publisher.Publish(
		filepath.Join(unsafeDirectory, "process-incarnation"), incarnation); err == nil {
		t.Fatal("accepted group/world-writable process-incarnation directory")
	}
}

func TestVNextReaderProcessIncarnationLockIsNonblockingAndLifetimeBound(
	t *testing.T,
) {
	directory := vnextReaderProcessIncarnationSecureTestDir(t)
	path := filepath.Join(directory, "process-incarnation")
	acquirer := &vnextReaderProcessIncarnationFileLockAcquirer{}
	first, err := acquirer.Acquire(path)
	if err != nil {
		t.Fatalf("acquire first process-incarnation lock: %v", err)
	}
	second, err := acquirer.Acquire(path)
	if err == nil || second != nil ||
		!errors.Is(err, errVNextReaderProcessIncarnationLockHeld) {
		_ = first.Release()
		t.Fatalf("concurrent lock returned lock=%#v err=%v", second, err)
	}
	lockInfo, err := os.Lstat(path + vnextReaderProcessIncarnationLockSuffix)
	if err != nil || !lockInfo.Mode().IsRegular() ||
		lockInfo.Mode().Perm() != 0o600 {
		_ = first.Release()
		t.Fatalf("process-incarnation lock file mode=%v err=%v", lockInfo, err)
	}
	if err := first.Release(); err != nil {
		t.Fatalf("release first process-incarnation lock: %v", err)
	}
	third, err := acquirer.Acquire(path)
	if err != nil {
		t.Fatalf("reacquire process-incarnation lock: %v", err)
	}
	if err := third.Release(); err != nil {
		t.Fatalf("release reacquired process-incarnation lock: %v", err)
	}
}

func TestVNextReaderProcessIncarnationLockRejectsUnsafeTargets(t *testing.T) {
	for name, arrange := range map[string]func(*testing.T, string){
		"symlink": func(t *testing.T, path string) {
			if err := os.Symlink(filepath.Join(t.TempDir(), "outside"), path); err != nil {
				t.Fatal(err)
			}
		},
		"directory": func(t *testing.T, path string) {
			if err := os.Mkdir(path, 0o700); err != nil {
				t.Fatal(err)
			}
		},
		"wrong-mode": func(t *testing.T, path string) {
			if err := os.WriteFile(path, nil, 0o640); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(path, 0o640); err != nil {
				t.Fatal(err)
			}
		},
		"hard-link": func(t *testing.T, path string) {
			source := filepath.Join(filepath.Dir(path), "lock-source")
			if err := os.WriteFile(source, nil, 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.Link(source, path); err != nil {
				t.Fatal(err)
			}
		},
	} {
		t.Run(name, func(t *testing.T) {
			directory := vnextReaderProcessIncarnationSecureTestDir(t)
			path := filepath.Join(directory, "process-incarnation")
			lockPath := path + vnextReaderProcessIncarnationLockSuffix
			arrange(t, lockPath)
			lock, err := (&vnextReaderProcessIncarnationFileLockAcquirer{}).Acquire(path)
			if err == nil || lock != nil {
				if lock != nil {
					_ = lock.Release()
				}
				t.Fatalf("unsafe lock target returned lock=%#v err=%v", lock, err)
			}
		})
	}
}

func TestVNextReaderProcessIncarnationLockRemovesOnlyExactPublishedIdentity(
	t *testing.T,
) {
	directory := vnextReaderProcessIncarnationSecureTestDir(t)
	path := filepath.Join(directory, "process-incarnation")
	lock, err := (&vnextReaderProcessIncarnationFileLockAcquirer{}).Acquire(path)
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Release()
	published := vnextReaderProcessIncarnationForTest(0x41)
	other := vnextReaderProcessIncarnationForTest(0x42)
	if err := (&vnextReaderProcessIncarnationFilePublisher{}).Publish(
		path, published); err != nil {
		t.Fatal(err)
	}
	if err := lock.RemovePublishedIdentity(other, false); err != nil {
		t.Fatalf("optional cleanup of a different identity: %v", err)
	}
	assertVNextReaderProcessIncarnationFile(t, path, published)
	if err := lock.RemovePublishedIdentity(other, true); err == nil {
		t.Fatal("required cleanup accepted a different identity")
	}
	assertVNextReaderProcessIncarnationFile(t, path, published)
	if err := lock.RemovePublishedIdentity(published, true); err != nil {
		t.Fatalf("remove exact published identity: %v", err)
	}
	if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("exact published identity remains: %v", err)
	}
}

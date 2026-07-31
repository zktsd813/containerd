package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"
)

var directReaderPseudoMMPath = directPseudoMMPath

type directReaderPseudoMMFile struct {
	Name string `json:"name"`
	Size int64  `json:"size"`
}

type directReaderPseudoMMManifest struct {
	ArtifactID            string                     `json:"artifact_id"`
	Generation            uint64                     `json:"generation"`
	WriterID              string                     `json:"writer_id"`
	WriterEpoch           uint64                     `json:"writer_epoch"`
	ShardID               string                     `json:"shard_id"`
	LocalDevice           string                     `json:"local_device"`
	OffsetBytes           int64                      `json:"offset_bytes"`
	LengthBytes           int64                      `json:"length_bytes"`
	RestoreMapSHA256      string                     `json:"restore_map_sha256,omitempty"`
	RestoreMapExtentCount uint64                     `json:"restore_map_extent_count,omitempty"`
	RestoreMapPageCount   uint64                     `json:"restore_map_page_count,omitempty"`
	RestoreMapDevice      string                     `json:"restore_map_device,omitempty"`
	KernelBoot            string                     `json:"kernel_boot_id"`
	Files                 []directReaderPseudoMMFile `json:"files"`
	CommittedAt           time.Time                  `json:"committed_at"`
}

func materializeDirectReaderPseudoMM(ctx context.Context, state trenvContainerState, config daemonConfig, plan directPseudoMMImportPlan) error {
	publication := plan.publication
	device := plan.daxDevice
	imagePath := plan.checkpointPath
	bootID, err := directKernelBootID()
	if err != nil {
		return err
	}
	root := strings.TrimSpace(config.PseudoMMMaterializationRoot)
	if root == "" {
		root = filepath.Join(config.WorkingDirectory, "pseudo-mm-materialized")
	}
	materializationIdentity := fmt.Sprintf("%s-g%d-w%d-%s-%s-%d-%d",
		directSafePathSegment(publication.ArtifactID),
		publication.Generation,
		publication.WriterEpoch,
		directSafePathSegment(publication.PageExtent.ShardID),
		directSafePathSegment(filepath.Base(device)),
		publication.PageExtent.OffsetBytes,
		publication.PageExtent.LengthBytes)
	if len(plan.restoreMap) > 0 {
		materializationIdentity += fmt.Sprintf("-rm-%s-n%d-p%d-%s",
			plan.restoreMapSHA256,
			plan.restoreMapExtentCount,
			plan.restoreMapPageCount,
			directSafePathSegment(filepath.Base(device)))
	}
	materializationID := fmt.Sprintf("v2-%x", sha256.Sum256([]byte(materializationIdentity)))
	materializationRoot := filepath.Join(root, sanitizePathPart(bootID), materializationID)
	if err := os.MkdirAll(materializationRoot, 0o700); err != nil {
		return err
	}
	lock, err := os.OpenFile(filepath.Join(materializationRoot, "materialization.lock"), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return err
	}
	defer lock.Close()
	if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX); err != nil {
		return err
	}
	defer syscall.Flock(int(lock.Fd()), syscall.LOCK_UN) //nolint:errcheck

	manifestPath := filepath.Join(materializationRoot, "manifest.json")
	if isRegularFile(manifestPath) {
		return restoreDirectReaderPseudoMMFiles(imagePath, manifestPath, plan, bootID)
	}
	if err := removeDirectPseudoMMFiles(imagePath); err != nil {
		return err
	}
	workPath := filepath.Join(materializationRoot, "work")
	if err := os.MkdirAll(workPath, 0o700); err != nil {
		return err
	}
	if err := runDirectReaderCriuImport(ctx, workPath, state, plan); err != nil {
		_ = removeDirectPseudoMMFiles(imagePath)
		return err
	}
	files, err := cacheDirectReaderPseudoMMFiles(imagePath, materializationRoot)
	if err != nil {
		_ = removeDirectPseudoMMFiles(imagePath)
		_ = os.RemoveAll(filepath.Join(materializationRoot, "image"))
		return err
	}
	manifest := directReaderPseudoMMManifest{
		ArtifactID:            publication.ArtifactID,
		Generation:            publication.Generation,
		WriterID:              publication.WriterID,
		WriterEpoch:           publication.WriterEpoch,
		ShardID:               publication.PageExtent.ShardID,
		LocalDevice:           device,
		OffsetBytes:           publication.PageExtent.OffsetBytes,
		LengthBytes:           publication.PageExtent.LengthBytes,
		RestoreMapSHA256:      plan.restoreMapSHA256,
		RestoreMapExtentCount: plan.restoreMapExtentCount,
		RestoreMapPageCount:   plan.restoreMapPageCount,
		RestoreMapDevice:      directRestoreMapDevice(plan),
		KernelBoot:            bootID,
		Files:                 files,
		CommittedAt:           time.Now().UTC(),
	}
	if err := writeJSONFile(manifestPath, manifest); err != nil {
		_ = removeDirectPseudoMMFiles(imagePath)
		_ = os.RemoveAll(filepath.Join(materializationRoot, "image"))
		return err
	}
	return nil
}

func directRestoreMapDevice(plan directPseudoMMImportPlan) string {
	if len(plan.restoreMap) == 0 {
		return ""
	}
	return plan.daxDevice
}

func writeDirectReaderDaxRemapFile(workPath string, data []byte) (string, func(), error) {
	if len(data) == 0 {
		return "", func() {}, nil
	}
	if err := os.MkdirAll(workPath, 0o700); err != nil {
		return "", func() {}, newDedupRestoreError(dedupRestoreCodeRemapFile, err)
	}
	file, err := os.CreateTemp(workPath, ".dax-remap.txt.tmp.")
	if err != nil {
		return "", func() {}, newDedupRestoreError(dedupRestoreCodeRemapFile, err)
	}
	tempPath := file.Name()
	closed := false
	cleanupTemp := func() {
		if !closed {
			_ = file.Close()
		}
		_ = os.Remove(tempPath)
	}
	if err := file.Chmod(0o600); err != nil {
		cleanupTemp()
		return "", func() {}, newDedupRestoreError(dedupRestoreCodeRemapFile, err)
	}
	if _, err := file.Write(data); err != nil {
		cleanupTemp()
		return "", func() {}, newDedupRestoreError(dedupRestoreCodeRemapFile, err)
	}
	if err := file.Sync(); err != nil {
		cleanupTemp()
		return "", func() {}, newDedupRestoreError(dedupRestoreCodeRemapFile, err)
	}
	if err := file.Close(); err != nil {
		closed = true
		_ = os.Remove(tempPath)
		return "", func() {}, newDedupRestoreError(dedupRestoreCodeRemapFile, err)
	}
	closed = true
	path := filepath.Join(workPath, "dax-remap.txt")
	if err := os.Rename(tempPath, path); err != nil {
		_ = os.Remove(tempPath)
		return "", func() {}, newDedupRestoreError(dedupRestoreCodeRemapFile, err)
	}
	directory, err := os.Open(workPath)
	if err != nil {
		_ = os.Remove(path)
		return "", func() {}, newDedupRestoreError(dedupRestoreCodeRemapFile, err)
	}
	syncErr := directory.Sync()
	closeErr := directory.Close()
	if syncErr != nil {
		_ = os.Remove(path)
		return "", func() {}, newDedupRestoreError(dedupRestoreCodeRemapFile, syncErr)
	}
	if closeErr != nil {
		_ = os.Remove(path)
		return "", func() {}, newDedupRestoreError(dedupRestoreCodeRemapFile, closeErr)
	}
	return path, func() { _ = os.Remove(path) }, nil
}

func runDirectReaderCriuImport(ctx context.Context, workPath string, state trenvContainerState, plan directPseudoMMImportPlan) error {
	imagePath := plan.checkpointPath
	mntNsFile, err := os.Open(fmt.Sprintf("/proc/%d/ns/mnt", state.PID))
	if err != nil {
		return fmt.Errorf("open mount namespace for reader import: %w", err)
	}
	defer mntNsFile.Close()
	pseudoMMDrv, err := os.OpenFile(directReaderPseudoMMPath, os.O_RDWR, 0)
	if err != nil {
		return fmt.Errorf("open %s for reader import: %w", directReaderPseudoMMPath, err)
	}
	defer pseudoMMDrv.Close()

	remapPath, cleanupRemap, err := writeDirectReaderDaxRemapFile(workPath, plan.restoreMap)
	if err != nil {
		return err
	}
	defer cleanupRemap()
	args := directReaderCriuImportArgs(imagePath, workPath, plan.daxDevice, plan.daxStartPage, remapPath)
	cmd := exec.CommandContext(ctx, nonEmptyOrDefault(state.CriuBinary, "criu"), args...)
	cmd.ExtraFiles = []*os.File{mntNsFile, pseudoMMDrv}
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		commandErr := fmt.Errorf("criu reader import failed: %s", commandErrorString(err, stderr.String()+"\n"+stdout.String()))
		if len(plan.restoreMap) > 0 {
			return newDedupRestoreError(dedupRestoreCodeRemapFile, commandErr)
		}
		return commandErr
	}
	return nil
}

func directReaderCriuImportArgs(imagePath, workPath, device string, daxStartPage int64, remapPath string) []string {
	args := []string{
		"convert",
		"-D", imagePath,
		"-W", workPath,
		"-v4",
		"-o", filepath.Join(workPath, "pseudo-mm-import.log"),
		"--inherit-fd", "fd[3]:switch-ns-mnt",
		"--inherit-fd", fmt.Sprintf("fd[4]:%s", directPseudoMMInheritID),
		"--mem-pool", "dax",
		"--dax-device", device,
		"--dax-pgoff", strconv.FormatInt(daxStartPage, 10),
	}
	if remapPath != "" {
		args = append(args, "--dax-remap-file", remapPath)
	}
	return append(args, "--import-existing-dax", "--tcp-close")
}

func cacheDirectReaderPseudoMMFiles(imagePath, materializationRoot string) ([]directReaderPseudoMMFile, error) {
	matches, err := filepath.Glob(filepath.Join(imagePath, "pseudo_mm_id-*"))
	if err != nil {
		return nil, err
	}
	sort.Strings(matches)
	if len(matches) == 0 {
		return nil, errors.New("criu reader import did not create pseudo_mm_id files")
	}
	cacheRoot := filepath.Join(materializationRoot, "image")
	if err := os.RemoveAll(cacheRoot); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(cacheRoot, 0o700); err != nil {
		return nil, err
	}
	files := make([]directReaderPseudoMMFile, 0, len(matches))
	for _, match := range matches {
		name := filepath.Base(match)
		info, err := os.Stat(match)
		if err != nil {
			return nil, err
		}
		if err := copyFile(match, filepath.Join(cacheRoot, name), 0o600); err != nil {
			return nil, err
		}
		files = append(files, directReaderPseudoMMFile{Name: name, Size: info.Size()})
	}
	return files, nil
}

func restoreDirectReaderPseudoMMFiles(imagePath, manifestPath string, plan directPseudoMMImportPlan, bootID string) error {
	publication := plan.publication
	data, err := os.ReadFile(manifestPath)
	if err != nil {
		return err
	}
	var manifest directReaderPseudoMMManifest
	if err := json.Unmarshal(data, &manifest); err != nil {
		return err
	}
	if manifest.ArtifactID != publication.ArtifactID ||
		manifest.Generation != publication.Generation ||
		manifest.WriterID != publication.WriterID ||
		manifest.WriterEpoch != publication.WriterEpoch ||
		manifest.ShardID != publication.PageExtent.ShardID ||
		manifest.LocalDevice != plan.daxDevice ||
		manifest.OffsetBytes != publication.PageExtent.OffsetBytes ||
		manifest.LengthBytes != publication.PageExtent.LengthBytes ||
		manifest.RestoreMapSHA256 != plan.restoreMapSHA256 ||
		manifest.RestoreMapExtentCount != plan.restoreMapExtentCount ||
		manifest.RestoreMapPageCount != plan.restoreMapPageCount ||
		manifest.RestoreMapDevice != directRestoreMapDevice(plan) ||
		manifest.KernelBoot != bootID ||
		len(manifest.Files) == 0 {
		err := errors.New("reader pseudo_mm materialization identity mismatch")
		if len(plan.restoreMap) > 0 {
			return newDedupRestoreError(dedupRestoreCodeBaseMap, err)
		}
		return err
	}
	if err := removeDirectPseudoMMFiles(imagePath); err != nil {
		return err
	}
	cacheRoot := filepath.Join(filepath.Dir(manifestPath), "image")
	for _, file := range manifest.Files {
		if filepath.Base(file.Name) != file.Name || !strings.HasPrefix(file.Name, "pseudo_mm_id-") {
			return fmt.Errorf("invalid cached pseudo_mm file %q", file.Name)
		}
		source := filepath.Join(cacheRoot, file.Name)
		info, err := os.Stat(source)
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() || info.Size() != file.Size {
			return fmt.Errorf("cached pseudo_mm file %q size mismatch", file.Name)
		}
		if err := copyFile(source, filepath.Join(imagePath, file.Name), 0o600); err != nil {
			return err
		}
	}
	return nil
}

func removeDirectPseudoMMFiles(imagePath string) error {
	matches, err := filepath.Glob(filepath.Join(imagePath, "pseudo_mm_id-*"))
	if err != nil {
		return err
	}
	for _, match := range matches {
		if err := os.Remove(match); err != nil && !os.IsNotExist(err) {
			return err
		}
	}
	return nil
}

func directKernelBootID() (string, error) {
	data, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil {
		return "", fmt.Errorf("read kernel boot id: %w", err)
	}
	bootID := strings.TrimSpace(string(data))
	if bootID == "" {
		return "", errors.New("kernel boot id is empty")
	}
	return bootID, nil
}

package main

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"sync"
	"unicode"
	"unicode/utf8"
	"unsafe"

	"github.com/containerd/containerd/third_party/trenv-containerd/cmd/cxld/internal/trcxl007"
	"github.com/containerd/containerd/third_party/trenv-containerd/pkg/cxlcheckpoint"
	"golang.org/x/sys/unix"
)

const trcxl007OwnerSealDevDAXOpenFlags = unix.O_RDONLY | unix.O_CLOEXEC | unix.O_NOFOLLOW

var trcxl007OwnerSealDevDAXSysfsRoots = []string{
	"/sys/bus/dax/devices",
	"/sys/class/dax",
}

var (
	errTRCXL007OwnerSealDevDAXClosed = errors.New(
		"TRCXL007 Owner seal devdax source is closed")
	errTRCXL007OwnerSealDevDAXActivePass = errors.New(
		"TRCXL007 Owner seal devdax source has an active read pass")
	errTRCXL007OwnerSealVisibilityProtocolUnavailable = errors.New(
		"TRCXL007 Owner seal platform visibility protocol is unavailable")
)

// trcxl007OwnerSealDevDAXBinding is trusted daemon-local attach state. The
// path and rdev are never accepted over an Owner RPC and never leave cxld.
// Binding and Geometry come from the already authenticated/opened Owner group.
// ExpectedRdev prevents path replacement and two configured UUIDs from
// silently resolving to one local character device.
type trcxl007OwnerSealDevDAXBinding struct {
	Binding      trcxl007.ProducerScatterDeviceBinding
	Geometry     trcxl007.DeviceGeometry
	DevicePath   string
	ExpectedRdev uint64
}

// trcxl007OwnerSealDevDAXVisibilityProtocol is intentionally not implemented
// by mmap, CLFLUSH, or this adapter. A production platform integration must
// first prove Producer write drain/revocation and then atomically return one
// bounded lease for the complete canonical portable binding table. Until such
// an integration is supplied, the production constructor fails closed before
// opening a device.
type trcxl007OwnerSealDevDAXVisibilityProtocol interface {
	Acquire(
		ctx context.Context,
		devices []trcxl007.ProducerScatterDeviceBinding,
	) (trcxl007OwnerSealDevDAXVisibilityLease, error)
}

// trcxl007OwnerSealDevDAXVisibilityLease owns group-wide platform visibility
// state during one read pass. InvalidateExactRange must make exactly the
// supplied device mapping range observable without replacing it with a copied
// buffer. Close revokes the single group lease. Views returned by the pass are
// no longer valid by contract once Close starts.
type trcxl007OwnerSealDevDAXVisibilityLease interface {
	InvalidateExactRange(
		ctx context.Context,
		binding trcxl007.ProducerScatterDeviceBinding,
		deviceByteOffset uint64,
		directView []byte,
	) error
	Close() error
}

type trcxl007OwnerSealDevDAXFileIdentity struct {
	characterDevice bool
	rdev            uint64
}

type trcxl007OwnerSealDevDAXKernelGeometry struct {
	sizeBytes  uint64
	alignBytes uint64
	rdev       uint64
}

type trcxl007OwnerSealDevDAXDependencies struct {
	openFile func(string, int, os.FileMode) (*os.File, error)
	statFile func(*os.File) (trcxl007OwnerSealDevDAXFileIdentity, error)
	geometry func(string) (trcxl007OwnerSealDevDAXKernelGeometry, error)
	mmap     func(int, int64, int, int, int) ([]byte, error)
	munmap   func([]byte) error
	close    func(*os.File) error
}

func defaultTRCXL007OwnerSealDevDAXDependencies() trcxl007OwnerSealDevDAXDependencies {
	return trcxl007OwnerSealDevDAXDependencies{
		openFile: os.OpenFile,
		statFile: func(file *os.File) (trcxl007OwnerSealDevDAXFileIdentity, error) {
			if file == nil {
				return trcxl007OwnerSealDevDAXFileIdentity{}, errors.New(
					"TRCXL007 Owner seal devdax file is nil")
			}
			var stat unix.Stat_t
			if err := unix.Fstat(int(file.Fd()), &stat); err != nil {
				return trcxl007OwnerSealDevDAXFileIdentity{}, err
			}
			return trcxl007OwnerSealDevDAXFileIdentity{
				characterDevice: stat.Mode&unix.S_IFMT == unix.S_IFCHR,
				rdev:            uint64(stat.Rdev),
			}, nil
		},
		geometry: func(path string) (trcxl007OwnerSealDevDAXKernelGeometry, error) {
			return resolveTRCXL007OwnerSealDevDAXKernelGeometry(
				path, trcxl007OwnerSealDevDAXSysfsRoots)
		},
		mmap:   unix.Mmap,
		munmap: unix.Munmap,
		close: func(file *os.File) error {
			return file.Close()
		},
	}
}

func validateTRCXL007OwnerSealDevDAXDependencies(
	dependencies trcxl007OwnerSealDevDAXDependencies,
) error {
	if dependencies.openFile == nil || dependencies.statFile == nil ||
		dependencies.geometry == nil || dependencies.mmap == nil ||
		dependencies.munmap == nil || dependencies.close == nil {
		return errors.New("TRCXL007 Owner seal devdax dependencies are incomplete")
	}
	return nil
}

// trcxl007OwnerSealDevDAXErrors preserves every cleanup cause for errors.Is on
// Go 1.17, where errors.Join is unavailable.
type trcxl007OwnerSealDevDAXErrors struct {
	failures []error
}

func (failures *trcxl007OwnerSealDevDAXErrors) Error() string {
	if failures == nil {
		return "TRCXL007 Owner seal devdax operation failed"
	}
	messages := make([]string, 0, len(failures.failures))
	for _, failure := range failures.failures {
		messages = append(messages, failure.Error())
	}
	return strings.Join(messages, "; ")
}

func (failures *trcxl007OwnerSealDevDAXErrors) Is(target error) bool {
	if failures == nil {
		return false
	}
	for _, failure := range failures.failures {
		if errors.Is(failure, target) {
			return true
		}
	}
	return false
}

func (failures *trcxl007OwnerSealDevDAXErrors) As(target interface{}) bool {
	if failures == nil {
		return false
	}
	for _, failure := range failures.failures {
		if errors.As(failure, target) {
			return true
		}
	}
	return false
}

func appendTRCXL007OwnerSealDevDAXError(existing, next error) error {
	if next == nil {
		return existing
	}
	if existing == nil {
		return next
	}
	if aggregate, ok := existing.(*trcxl007OwnerSealDevDAXErrors); ok {
		combined := append([]error(nil), aggregate.failures...)
		combined = append(combined, next)
		return &trcxl007OwnerSealDevDAXErrors{failures: combined}
	}
	return &trcxl007OwnerSealDevDAXErrors{failures: []error{existing, next}}
}

type trcxl007OwnerSealDevDAXSource struct {
	mu sync.Mutex

	devices         map[string]*trcxl007OwnerSealDevDAXDevice
	orderedUUIDs    []string
	bindingTable    []trcxl007.ProducerScatterDeviceBinding
	visibility      trcxl007OwnerSealDevDAXVisibilityProtocol
	activePass      *trcxl007OwnerSealDevDAXReadPass
	admissionClosed bool

	closeMu       sync.Mutex
	closeComplete bool
	closeErr      error
}

type trcxl007OwnerSealDevDAXDevice struct {
	local    trcxl007OwnerSealDevDAXBinding
	file     *os.File
	mapped   []byte
	align    uint64
	rdev     uint64
	munmap   func([]byte) error
	close    func(*os.File) error
	unmapped bool
	fdClosed bool
	fdErr    error
}

type trcxl007OwnerSealDevDAXReadPass struct {
	mu sync.Mutex

	source   *trcxl007OwnerSealDevDAXSource
	ctx      context.Context
	lease    trcxl007OwnerSealDevDAXVisibilityLease
	closed   bool
	closeErr error
}

// openTRCXL007OwnerSealDevDAXSource is the production constructor. There is
// deliberately no default visibility implementation: nil is a hard failure,
// and the default dependencies accept only real character devdax devices.
func openTRCXL007OwnerSealDevDAXSource(
	bindings []trcxl007OwnerSealDevDAXBinding,
	visibility trcxl007OwnerSealDevDAXVisibilityProtocol,
) (*trcxl007OwnerSealDevDAXSource, error) {
	return openTRCXL007OwnerSealDevDAXSourceWithDependencies(
		bindings,
		visibility,
		defaultTRCXL007OwnerSealDevDAXDependencies())
}

// openTRCXL007OwnerSealDevDAXSourceWithDependencies is package-private and is
// only a deterministic syscall seam. Production never supplies alternate
// dependencies; in particular it cannot opt a regular file into eligibility.
func openTRCXL007OwnerSealDevDAXSourceWithDependencies(
	bindings []trcxl007OwnerSealDevDAXBinding,
	visibility trcxl007OwnerSealDevDAXVisibilityProtocol,
	dependencies trcxl007OwnerSealDevDAXDependencies,
) (*trcxl007OwnerSealDevDAXSource, error) {
	if err := validateTRCXL007OwnerSealDevDAXDependencies(dependencies); err != nil {
		return nil, err
	}
	if trcxl007OwnerSealNilInterface(visibility) {
		return nil, errTRCXL007OwnerSealVisibilityProtocolUnavailable
	}
	canonical, err := cloneTRCXL007OwnerSealDevDAXBindings(bindings)
	if err != nil {
		return nil, err
	}
	source := &trcxl007OwnerSealDevDAXSource{
		devices:      make(map[string]*trcxl007OwnerSealDevDAXDevice, len(canonical)),
		orderedUUIDs: make([]string, 0, len(canonical)),
		bindingTable: make([]trcxl007.ProducerScatterDeviceBinding, 0, len(canonical)),
		visibility:   visibility,
	}
	observedRdevs := make(map[uint64]string, len(canonical))
	for _, local := range canonical {
		device, openErr := openTRCXL007OwnerSealDevDAXDevice(local, dependencies)
		if openErr != nil {
			primary := fmt.Errorf(
				"open TRCXL007 Owner seal devdax device %q: %w",
				local.Binding.DeviceUUID, openErr)
			return nil, appendTRCXL007OwnerSealDevDAXError(
				primary, discardTRCXL007OwnerSealDevDAXDevices(source.orderedDevices()))
		}
		if previous, exists := observedRdevs[device.rdev]; exists {
			primary := fmt.Errorf(
				"TRCXL007 Owner seal devdax UUIDs %q and %q resolve to rdev %d",
				previous, local.Binding.DeviceUUID, device.rdev)
			devices := append(source.orderedDevices(), device)
			return nil, appendTRCXL007OwnerSealDevDAXError(
				primary, discardTRCXL007OwnerSealDevDAXDevices(devices))
		}
		observedRdevs[device.rdev] = local.Binding.DeviceUUID
		source.devices[local.Binding.DeviceUUID] = device
		source.orderedUUIDs = append(source.orderedUUIDs, local.Binding.DeviceUUID)
		source.bindingTable = append(source.bindingTable, local.Binding)
	}
	return source, nil
}

func cloneTRCXL007OwnerSealDevDAXBindings(
	bindings []trcxl007OwnerSealDevDAXBinding,
) ([]trcxl007OwnerSealDevDAXBinding, error) {
	if len(bindings) == 0 || len(bindings) > trcxl007.MaxOwnerStateDevices {
		return nil, fmt.Errorf(
			"TRCXL007 Owner seal devdax binding count %d is outside 1..%d",
			len(bindings), trcxl007.MaxOwnerStateDevices)
	}
	canonical := append([]trcxl007OwnerSealDevDAXBinding(nil), bindings...)
	sort.Slice(canonical, func(left, right int) bool {
		return canonical[left].Binding.DeviceUUID < canonical[right].Binding.DeviceUUID
	})
	paths := make(map[string]string, len(canonical))
	rdevs := make(map[uint64]string, len(canonical))
	backings := make(map[[sha256.Size]byte]string, len(canonical))
	for index, local := range canonical {
		if err := validateTRCXL007OwnerSealDevDAXBinding(local); err != nil {
			return nil, fmt.Errorf(
				"validate TRCXL007 Owner seal devdax binding %d: %w", index, err)
		}
		uuid := local.Binding.DeviceUUID
		if index > 0 && canonical[index-1].Binding.DeviceUUID == uuid {
			return nil, fmt.Errorf(
				"duplicate TRCXL007 Owner seal devdax UUID %q", uuid)
		}
		if previous, exists := paths[local.DevicePath]; exists {
			return nil, fmt.Errorf(
				"TRCXL007 Owner seal devdax path %q aliases UUIDs %q and %q",
				local.DevicePath, previous, uuid)
		}
		paths[local.DevicePath] = uuid
		if previous, exists := rdevs[local.ExpectedRdev]; exists {
			return nil, fmt.Errorf(
				"TRCXL007 Owner seal devdax rdev %d aliases UUIDs %q and %q",
				local.ExpectedRdev, previous, uuid)
		}
		rdevs[local.ExpectedRdev] = uuid
		if previous, exists := backings[local.Binding.DeviceBindingSHA256]; exists {
			return nil, fmt.Errorf(
				"TRCXL007 Owner seal backing identity aliases UUIDs %q and %q",
				previous, uuid)
		}
		backings[local.Binding.DeviceBindingSHA256] = uuid
	}
	return canonical, nil
}

func validateTRCXL007OwnerSealDevDAXBinding(
	local trcxl007OwnerSealDevDAXBinding,
) error {
	binding := local.Binding
	if binding.DeviceUUID == "" || !utf8.ValidString(binding.DeviceUUID) ||
		len(binding.DeviceUUID) > trcxl007.MaxSuperblockIdentityBytes ||
		strings.TrimSpace(binding.DeviceUUID) != binding.DeviceUUID {
		return fmt.Errorf("device UUID %q is empty, invalid, too long, or not trimmed",
			binding.DeviceUUID)
	}
	for _, character := range binding.DeviceUUID {
		if unicode.IsControl(character) {
			return fmt.Errorf("device UUID %q contains a control character",
				binding.DeviceUUID)
		}
	}
	fileURI := len(binding.DeviceUUID) >= len("file:") &&
		strings.EqualFold(binding.DeviceUUID[:len("file:")], "file:")
	if binding.DeviceUUID == "." || binding.DeviceUUID == ".." || fileURI ||
		strings.ContainsAny(binding.DeviceUUID, "/\\") {
		return fmt.Errorf("device UUID %q looks like a local path", binding.DeviceUUID)
	}
	if binding.DeviceOwnerEpoch == 0 ||
		binding.DeviceOwnerEpoch > cxlcheckpoint.MaxSignedLong {
		return fmt.Errorf("device %q Owner epoch is outside the signed ABI",
			binding.DeviceUUID)
	}
	if binding.DataPageCount == 0 ||
		binding.DataPageCount > cxlcheckpoint.MaxSignedLong {
		return fmt.Errorf("device %q page count is outside the signed ABI",
			binding.DeviceUUID)
	}
	if binding.DeviceBindingSHA256 == ([sha256.Size]byte{}) {
		return fmt.Errorf("device %q binding SHA-256 is zero", binding.DeviceUUID)
	}
	if err := local.Geometry.Validate(); err != nil {
		return fmt.Errorf("device %q geometry: %w", binding.DeviceUUID, err)
	}
	if local.Geometry.DataPageCount != binding.DataPageCount {
		return fmt.Errorf(
			"device %q binding page count %d differs from geometry %d",
			binding.DeviceUUID, binding.DataPageCount, local.Geometry.DataPageCount)
	}
	if local.Geometry.DeviceBytes > uint64(trcxl007OwnerSealMaxInt()) {
		return fmt.Errorf("device %q capacity exceeds the mmap length ABI",
			binding.DeviceUUID)
	}
	if err := validateTRCXL007OwnerSealDevDAXPath(local.DevicePath); err != nil {
		return fmt.Errorf("device %q: %w", binding.DeviceUUID, err)
	}
	if local.ExpectedRdev == 0 {
		return fmt.Errorf("device %q expected rdev is zero", binding.DeviceUUID)
	}
	return nil
}

func validateTRCXL007OwnerSealDevDAXPath(path string) error {
	if path == "" || len(path) > cxlcheckpoint.MaxIdentityBytes ||
		!filepath.IsAbs(path) || filepath.Clean(path) != path ||
		strings.IndexByte(path, 0) >= 0 {
		return fmt.Errorf(
			"local devdax path %q is empty, relative, too long, unclean, or contains NUL",
			path)
	}
	return nil
}

func openTRCXL007OwnerSealDevDAXDevice(
	local trcxl007OwnerSealDevDAXBinding,
	dependencies trcxl007OwnerSealDevDAXDependencies,
) (*trcxl007OwnerSealDevDAXDevice, error) {
	file, err := dependencies.openFile(
		local.DevicePath, trcxl007OwnerSealDevDAXOpenFlags, 0)
	if err != nil {
		primary := fmt.Errorf("open O_RDONLY|O_CLOEXEC|O_NOFOLLOW: %w", err)
		if file != nil {
			if closeErr := dependencies.close(file); closeErr != nil {
				primary = appendTRCXL007OwnerSealDevDAXError(
					primary, fmt.Errorf("close failed open result: %w", closeErr))
			}
		}
		return nil, primary
	}
	if file == nil {
		return nil, errors.New(
			"open O_RDONLY|O_CLOEXEC|O_NOFOLLOW returned a nil devdax file")
	}
	device := &trcxl007OwnerSealDevDAXDevice{
		local:  local,
		file:   file,
		munmap: dependencies.munmap,
		close:  dependencies.close,
	}
	fail := func(primary error) (*trcxl007OwnerSealDevDAXDevice, error) {
		return nil, appendTRCXL007OwnerSealDevDAXError(
			primary, discardTRCXL007OwnerSealDevDAXDevices(
				[]*trcxl007OwnerSealDevDAXDevice{device}))
	}
	identity, err := dependencies.statFile(file)
	if err != nil {
		return fail(fmt.Errorf("fstat devdax: %w", err))
	}
	if !identity.characterDevice {
		return fail(errors.New(
			"TRCXL007 Owner seal production mapping requires a character devdax device"))
	}
	if identity.rdev == 0 || identity.rdev != local.ExpectedRdev {
		return fail(fmt.Errorf(
			"devdax rdev %d differs from expected %d",
			identity.rdev, local.ExpectedRdev))
	}
	device.rdev = identity.rdev
	kernelGeometry, err := dependencies.geometry(local.DevicePath)
	if err != nil {
		return fail(fmt.Errorf("resolve devdax sysfs size/alignment: %w", err))
	}
	if err := validateTRCXL007OwnerSealDevDAXKernelGeometry(
		kernelGeometry.sizeBytes, kernelGeometry.alignBytes); err != nil {
		return fail(fmt.Errorf("validate devdax sysfs size/alignment: %w", err))
	}
	if kernelGeometry.sizeBytes != local.Geometry.DeviceBytes {
		return fail(fmt.Errorf(
			"devdax sysfs size %d differs from expected geometry size %d",
			kernelGeometry.sizeBytes, local.Geometry.DeviceBytes))
	}
	if kernelGeometry.rdev == 0 || kernelGeometry.rdev != identity.rdev {
		return fail(fmt.Errorf(
			"devdax sysfs dev rdev %d differs from opened fd rdev %d",
			kernelGeometry.rdev, identity.rdev))
	}
	mapped, err := dependencies.mmap(
		int(file.Fd()),
		0,
		int(kernelGeometry.sizeBytes),
		unix.PROT_READ,
		unix.MAP_SHARED)
	device.mapped = mapped
	if err != nil {
		return fail(fmt.Errorf("mmap complete devdax capacity PROT_READ|MAP_SHARED: %w", err))
	}
	device.align = kernelGeometry.alignBytes
	if len(mapped) == 0 || uint64(len(mapped)) != kernelGeometry.sizeBytes {
		return fail(fmt.Errorf(
			"devdax mmap length %d differs from expected %d",
			len(mapped), kernelGeometry.sizeBytes))
	}
	address := uintptr(unsafe.Pointer(&mapped[0]))
	if uint64(address)%kernelGeometry.alignBytes != 0 {
		return fail(fmt.Errorf(
			"devdax mapping address %#x is not aligned to %d",
			address, kernelGeometry.alignBytes))
	}
	return device, nil
}

func (source *trcxl007OwnerSealDevDAXSource) orderedDevices() []*trcxl007OwnerSealDevDAXDevice {
	if source == nil {
		return nil
	}
	devices := make([]*trcxl007OwnerSealDevDAXDevice, 0, len(source.orderedUUIDs))
	for _, uuid := range source.orderedUUIDs {
		devices = append(devices, source.devices[uuid])
	}
	return devices
}

func discardTRCXL007OwnerSealDevDAXDevices(
	devices []*trcxl007OwnerSealDevDAXDevice,
) error {
	var cleanupErr error
	for index := len(devices) - 1; index >= 0; index-- {
		device := devices[index]
		if device == nil || device.unmapped || len(device.mapped) == 0 {
			continue
		}
		if err := device.munmap(device.mapped); err != nil {
			cleanupErr = appendTRCXL007OwnerSealDevDAXError(
				cleanupErr,
				fmt.Errorf("unmap partial device %q: %w",
					device.local.Binding.DeviceUUID, err))
		} else {
			device.unmapped = true
			device.mapped = nil
		}
	}
	for index := len(devices) - 1; index >= 0; index-- {
		device := devices[index]
		if device == nil || device.fdClosed || device.file == nil {
			continue
		}
		device.fdClosed = true
		if err := device.close(device.file); err != nil {
			device.fdErr = fmt.Errorf("close partial device %q: %w",
				device.local.Binding.DeviceUUID, err)
			cleanupErr = appendTRCXL007OwnerSealDevDAXError(
				cleanupErr, device.fdErr)
		}
		device.file = nil
	}
	return cleanupErr
}

func (source *trcxl007OwnerSealDevDAXSource) OpenReadPass(
	ctx context.Context,
	devices []trcxl007.ProducerScatterDeviceBinding,
) (trcxl007.OwnerSealContentReadPass, error) {
	if source == nil {
		return nil, errTRCXL007OwnerSealDevDAXClosed
	}
	if trcxl007OwnerSealNilInterface(ctx) {
		return nil, errors.New("TRCXL007 Owner seal read-pass context is nil")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	source.mu.Lock()
	defer source.mu.Unlock()
	if source.admissionClosed || source.closeComplete {
		return nil, errTRCXL007OwnerSealDevDAXClosed
	}
	if source.activePass != nil {
		return nil, errTRCXL007OwnerSealDevDAXActivePass
	}
	if !reflect.DeepEqual(devices, source.bindingTable) {
		return nil, errors.New(
			"TRCXL007 Owner seal read pass requested a stale or non-canonical binding table")
	}
	detachedBindings := append(
		[]trcxl007.ProducerScatterDeviceBinding(nil), source.bindingTable...)
	lease, err := source.visibility.Acquire(ctx, detachedBindings)
	if err != nil {
		primary := fmt.Errorf("acquire group-wide platform visibility: %w", err)
		if !trcxl007OwnerSealNilInterface(lease) {
			if closeErr := lease.Close(); closeErr != nil {
				source.admissionClosed = true
				primary = appendTRCXL007OwnerSealDevDAXError(
					primary,
					fmt.Errorf("close failed group-wide visibility acquisition: %w",
						closeErr))
			}
		}
		return nil, primary
	}
	if trcxl007OwnerSealNilInterface(lease) {
		source.admissionClosed = true
		return nil, errors.New(
			"group-wide platform visibility acquisition returned a nil lease")
	}
	if err := ctx.Err(); err != nil {
		closeErr := lease.Close()
		if closeErr != nil {
			source.admissionClosed = true
		}
		return nil, appendTRCXL007OwnerSealDevDAXError(err, closeErr)
	}
	pass := &trcxl007OwnerSealDevDAXReadPass{
		source: source,
		ctx:    ctx,
		lease:  lease,
	}
	source.activePass = pass
	return pass, nil
}

func (pass *trcxl007OwnerSealDevDAXReadPass) ReadableExtent(
	binding trcxl007.ProducerScatterDeviceBinding,
	startDataPageIndex uint64,
	pageCount uint64,
) (trcxl007.OwnerSealReadableExtent, error) {
	if pass == nil {
		return trcxl007.OwnerSealReadableExtent{}, errTRCXL007OwnerSealDevDAXClosed
	}
	pass.mu.Lock()
	defer pass.mu.Unlock()
	if pass.closed || pass.source == nil {
		return trcxl007.OwnerSealReadableExtent{}, errTRCXL007OwnerSealDevDAXClosed
	}
	if err := pass.ctx.Err(); err != nil {
		return trcxl007.OwnerSealReadableExtent{}, err
	}
	device, exists := pass.source.devices[binding.DeviceUUID]
	if !exists || device == nil || device.local.Binding != binding {
		return trcxl007.OwnerSealReadableExtent{}, errors.New(
			"TRCXL007 Owner seal readable extent binding is stale or unknown")
	}
	if trcxl007OwnerSealNilInterface(pass.lease) {
		return trcxl007.OwnerSealReadableExtent{}, errors.New(
			"TRCXL007 Owner seal readable extent has no visibility lease")
	}
	byteOffset, byteLength, byteEnd, err := trcxl007OwnerSealDevDAXExtentRange(
		device.local.Geometry, startDataPageIndex, pageCount)
	if err != nil {
		return trcxl007.OwnerSealReadableExtent{}, err
	}
	if byteEnd > uint64(len(device.mapped)) ||
		byteEnd > uint64(trcxl007OwnerSealMaxInt()) {
		return trcxl007.OwnerSealReadableExtent{}, errors.New(
			"TRCXL007 Owner seal readable extent exceeds the direct mapping")
	}
	direct := device.mapped[int(byteOffset):int(byteEnd):int(byteEnd)]
	if err := pass.lease.InvalidateExactRange(
		pass.ctx, binding, byteOffset, direct); err != nil {
		return trcxl007.OwnerSealReadableExtent{}, fmt.Errorf(
			"invalidate exact direct range for device %q: %w",
			binding.DeviceUUID, err)
	}
	if err := pass.ctx.Err(); err != nil {
		return trcxl007.OwnerSealReadableExtent{}, err
	}
	return trcxl007.OwnerSealReadableExtent{
		Binding:            binding,
		StartDataPageIndex: startDataPageIndex,
		PageCount:          pageCount,
		Bytes:              direct,
		Backing: trcxl007.ProducerScatterBackingRange{
			BackingID:  binding.DeviceBindingSHA256,
			ByteOffset: byteOffset,
			ByteLength: byteLength,
		},
	}, nil
}

func trcxl007OwnerSealDevDAXExtentRange(
	geometry trcxl007.DeviceGeometry,
	startDataPageIndex uint64,
	pageCount uint64,
) (uint64, uint64, uint64, error) {
	if pageCount == 0 || startDataPageIndex >= geometry.DataPageCount ||
		pageCount > geometry.DataPageCount-startDataPageIndex {
		return 0, 0, 0, errors.New(
			"TRCXL007 Owner seal readable extent page range is empty or out of bounds")
	}
	pageBytes := uint64(trcxl007.ContentPageBytes)
	if startDataPageIndex > (^uint64(0))/pageBytes ||
		pageCount > (^uint64(0))/pageBytes {
		return 0, 0, 0, errors.New(
			"TRCXL007 Owner seal readable extent byte range overflows")
	}
	pageOffset := startDataPageIndex * pageBytes
	byteLength := pageCount * pageBytes
	if geometry.ContentRegionBase > (^uint64(0))-pageOffset {
		return 0, 0, 0, errors.New(
			"TRCXL007 Owner seal readable extent offset overflows")
	}
	byteOffset := geometry.ContentRegionBase + pageOffset
	if byteOffset > (^uint64(0))-byteLength {
		return 0, 0, 0, errors.New(
			"TRCXL007 Owner seal readable extent end overflows")
	}
	byteEnd := byteOffset + byteLength
	if geometry.ContentRegionBase > (^uint64(0))-geometry.ContentRegionBytes {
		return 0, 0, 0, errors.New(
			"TRCXL007 Owner seal content-region end overflows")
	}
	contentEnd := geometry.ContentRegionBase + geometry.ContentRegionBytes
	if byteEnd > contentEnd || byteEnd > geometry.DeviceBytes ||
		byteOffset > uint64(trcxl007OwnerSealMaxInt()) ||
		byteLength > uint64(trcxl007OwnerSealMaxInt()) {
		return 0, 0, 0, errors.New(
			"TRCXL007 Owner seal readable extent exceeds device geometry")
	}
	return byteOffset, byteLength, byteEnd, nil
}

func (pass *trcxl007OwnerSealDevDAXReadPass) Close() error {
	if pass == nil {
		return nil
	}
	pass.mu.Lock()
	defer pass.mu.Unlock()
	if pass.closed {
		return pass.closeErr
	}
	pass.closed = true
	var closeErr error
	if !trcxl007OwnerSealNilInterface(pass.lease) {
		if err := pass.lease.Close(); err != nil {
			closeErr = fmt.Errorf("close group-wide platform visibility lease: %w", err)
		}
	}
	if pass.source != nil {
		pass.source.mu.Lock()
		if closeErr != nil {
			pass.source.admissionClosed = true
		}
		if pass.source.activePass != pass {
			pass.source.admissionClosed = true
			closeErr = appendTRCXL007OwnerSealDevDAXError(
				closeErr,
				errors.New("TRCXL007 Owner seal read-pass authority was replaced"))
		} else {
			pass.source.activePass = nil
		}
		pass.source.mu.Unlock()
	}
	pass.closeErr = closeErr
	pass.lease = nil
	return closeErr
}

// Close permanently closes admission first. An active pass is rejected rather
// than invalidated under a caller; after that pass closes, a repeated Close
// releases every mapping and file. Cleanup uses canonical reverse UUID order,
// attempts all munmaps first and all terminal fd closes second, and preserves
// every cause on Go 1.17.
func (source *trcxl007OwnerSealDevDAXSource) Close() error {
	if source == nil {
		return nil
	}
	source.closeMu.Lock()
	defer source.closeMu.Unlock()
	source.mu.Lock()
	source.admissionClosed = true
	if source.activePass != nil {
		source.mu.Unlock()
		return errTRCXL007OwnerSealDevDAXActivePass
	}
	if source.closeComplete {
		err := source.closeErr
		source.mu.Unlock()
		return err
	}
	devices := source.orderedDevices()
	source.mu.Unlock()

	var closeErr error
	for index := len(devices) - 1; index >= 0; index-- {
		device := devices[index]
		if device.unmapped || len(device.mapped) == 0 {
			continue
		}
		if err := device.munmap(device.mapped); err != nil {
			closeErr = appendTRCXL007OwnerSealDevDAXError(
				closeErr,
				fmt.Errorf("unmap device %q: %w",
					device.local.Binding.DeviceUUID, err))
		} else {
			device.unmapped = true
			device.mapped = nil
		}
	}
	for index := len(devices) - 1; index >= 0; index-- {
		device := devices[index]
		if !device.fdClosed && device.file != nil {
			device.fdClosed = true
			if err := device.close(device.file); err != nil {
				device.fdErr = fmt.Errorf("close device %q: %w",
					device.local.Binding.DeviceUUID, err)
			}
			device.file = nil
		}
		if device.fdErr != nil {
			closeErr = appendTRCXL007OwnerSealDevDAXError(closeErr, device.fdErr)
		}
	}
	complete := true
	for _, device := range devices {
		if !device.unmapped || !device.fdClosed {
			complete = false
			break
		}
	}
	source.mu.Lock()
	if complete {
		source.closeComplete = true
		source.closeErr = closeErr
	}
	source.mu.Unlock()
	return closeErr
}

func trcxl007OwnerSealNilInterface(value interface{}) bool {
	if value == nil {
		return true
	}
	reflected := reflect.ValueOf(value)
	switch reflected.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map,
		reflect.Ptr, reflect.Slice:
		return reflected.IsNil()
	default:
		return false
	}
}

func resolveTRCXL007OwnerSealDevDAXKernelGeometry(
	devicePath string,
	sysfsRoots []string,
) (trcxl007OwnerSealDevDAXKernelGeometry, error) {
	deviceName := filepath.Base(strings.TrimSpace(devicePath))
	if deviceName == "" || deviceName == "." ||
		deviceName == string(os.PathSeparator) {
		return trcxl007OwnerSealDevDAXKernelGeometry{}, fmt.Errorf(
			"invalid TRCXL007 Owner seal devdax path %q", devicePath)
	}
	var failures []string
	for _, root := range sysfsRoots {
		directory := filepath.Join(root, deviceName)
		size, sizeErr := readTRCXL007OwnerSealDevDAXSysfsUint(
			filepath.Join(directory, "size"))
		alignment, alignmentErr := readTRCXL007OwnerSealDevDAXSysfsUint(
			filepath.Join(directory, "align"))
		rdev, rdevErr := readTRCXL007OwnerSealDevDAXSysfsRdev(
			filepath.Join(directory, "dev"))
		if sizeErr != nil || alignmentErr != nil || rdevErr != nil {
			failures = append(failures, fmt.Sprintf(
				"%s (size: %v; align: %v; dev: %v)",
				directory, sizeErr, alignmentErr, rdevErr))
			continue
		}
		if err := validateTRCXL007OwnerSealDevDAXKernelGeometry(
			size, alignment); err != nil {
			return trcxl007OwnerSealDevDAXKernelGeometry{}, fmt.Errorf(
				"invalid devdax geometry in %s: %w", directory, err)
		}
		return trcxl007OwnerSealDevDAXKernelGeometry{
			sizeBytes: size, alignBytes: alignment, rdev: rdev,
		}, nil
	}
	return trcxl007OwnerSealDevDAXKernelGeometry{}, fmt.Errorf(
		"cannot resolve TRCXL007 Owner seal devdax geometry for %q from sysfs: %s",
		deviceName, strings.Join(failures, "; "))
}

func readTRCXL007OwnerSealDevDAXSysfsUint(path string) (uint64, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0, err
	}
	value, err := strconv.ParseUint(strings.TrimSpace(string(data)), 0, 64)
	if err != nil {
		return 0, fmt.Errorf("parse %s: %w", path, err)
	}
	return value, nil
}

func readTRCXL007OwnerSealDevDAXSysfsRdev(path string) (uint64, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0, err
	}
	parts := strings.Split(strings.TrimSpace(string(data)), ":")
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return 0, fmt.Errorf("parse %s: expected major:minor", path)
	}
	major, err := strconv.ParseUint(parts[0], 10, 32)
	if err != nil {
		return 0, fmt.Errorf("parse %s major: %w", path, err)
	}
	minor, err := strconv.ParseUint(parts[1], 10, 32)
	if err != nil {
		return 0, fmt.Errorf("parse %s minor: %w", path, err)
	}
	rdev := unix.Mkdev(uint32(major), uint32(minor))
	if rdev == 0 {
		return 0, fmt.Errorf("parse %s: device number is zero", path)
	}
	return rdev, nil
}

func validateTRCXL007OwnerSealDevDAXKernelGeometry(size, alignment uint64) error {
	pageBytes := uint64(trcxl007.ContentPageBytes)
	if os.Getpagesize() != trcxl007.ContentPageBytes {
		return fmt.Errorf(
			"TRCXL007 Owner seal devdax requires a 4096-byte host page, got %d",
			os.Getpagesize())
	}
	if size == 0 || size > uint64(math.MaxInt64) || size%pageBytes != 0 {
		return fmt.Errorf(
			"devdax size %d is not a positive signed-offset multiple of 4096",
			size)
	}
	if alignment < pageBytes || alignment%pageBytes != 0 ||
		alignment&(alignment-1) != 0 {
		return fmt.Errorf(
			"devdax alignment %d is not a power-of-two multiple of 4096",
			alignment)
	}
	if size%alignment != 0 {
		return fmt.Errorf(
			"devdax size %d is not a multiple of alignment %d", size, alignment)
	}
	return nil
}

func trcxl007OwnerSealMaxInt() int {
	return int(^uint(0) >> 1)
}

var _ trcxl007.OwnerSealContentSource = (*trcxl007OwnerSealDevDAXSource)(nil)
var _ trcxl007.OwnerSealContentReadPass = (*trcxl007OwnerSealDevDAXReadPass)(nil)

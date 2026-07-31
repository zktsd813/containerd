package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"math"
	"os"
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/containerd/containerd/third_party/trenv-containerd/pkg/cxlcheckpoint"
)

const vnextReaderMaxLocatorRuns = 1 << 20

// vnextReaderRequest is the portable input to the reader authorization
// boundary. It deliberately contains no DAX path, file descriptor, or local
// mapping offset. The Scheduler authorizer binds all of these identities to
// one immutable root before cxld is allowed to inspect shared memory.
type vnextReaderRequest struct {
	RestoreAuthorizationID string
	CheckpointID           string
	ExecutorID             string
	CxldInstanceID         string
	TargetContainerID      string
}

// vnextReaderPublicationLocator is the exact Scheduler-authorized byte
// identity. PageRuns are ordered in publication byte order and cover only
// ceil(PublicationByteLength/4096), never the complete reserved slot.
type vnextReaderPublicationLocator struct {
	PublicationByteLength uint64
	PublicationSHA256     [sha256.Size]byte
	PageRuns              []cxlcheckpoint.PublicationPageRun
}

// vnextReaderTrustedRoot mirrors the compact Scheduler CxlCheckpointRoot.
// Decode validates the complete embedded CommittedRoot and object graph; the
// fields here are independently rechecked so an authorized root cannot be
// silently substituted with another valid TRPUB006 graph.
type vnextReaderTrustedRoot struct {
	RootID             string
	RootVersion        uint64
	MMTemplateID       string
	PageMapID          string
	PageMapVersion     uint64
	DeviceTableDigest  [sha256.Size]byte
	ContractID         string
	PublicationLocator vnextReaderPublicationLocator
}

// vnextReaderAuthorization is the trusted result returned by the Scheduler
// authorization adapter. Echoing the portable request identities prevents a
// stale authorization for another executor, cxld instance, or container from
// reaching the DAX read path.
type vnextReaderAuthorization struct {
	RestoreAuthorizationID string
	CheckpointID           string
	ExecutorID             string
	CxldInstanceID         string
	TargetContainerID      string
	Root                   vnextReaderTrustedRoot
}

type vnextReaderAuthorizer interface {
	AuthorizeVNextReader(
		context.Context,
		vnextReaderRequest,
	) (vnextReaderAuthorization, error)
}

type vnextReaderAuthorizerFunc func(
	context.Context,
	vnextReaderRequest,
) (vnextReaderAuthorization, error)

func (authorize vnextReaderAuthorizerFunc) AuthorizeVNextReader(
	ctx context.Context,
	request vnextReaderRequest,
) (vnextReaderAuthorization, error) {
	return authorize(ctx, request)
}

// vnextReaderDAXSource is intentionally below the authorization boundary.
// Implementations must perform no read in their constructor. The bounded
// implementation in this file supports O_RDONLY regular-file devices; a real
// devdax reader needs a separate read-only mmap/cache-invalidation adapter.
type vnextReaderDAXSource interface {
	ReadVNextDescriptor(
		context.Context,
		vnextLocalDAXBinding,
		uint64,
	) (vnextPageDescriptor, error)
	ReadVNextContentPage(
		context.Context,
		vnextLocalDAXBinding,
		uint64,
	) ([]byte, error)
}

// vnextReaderVerifiedPublication is the narrow handoff to restore-specific
// code. ExactBytes excludes both the unused publication-slot pages and the
// zero padding after the exact envelope length in its final located page.
type vnextReaderVerifiedPublication struct {
	Publication cxlcheckpoint.Publication
	ExactBytes  []byte
}

type vnextReaderRunner interface {
	RunAuthorizedVNextPublication(
		context.Context,
		*vnextLocalDAXDirectory,
		vnextReaderVerifiedPublication,
	) error
}

// vnextReaderCRIUInvoke is injected so the reader can own validation and the
// ephemeral TRREMAP006 lifecycle without importing legacy command execution.
type vnextReaderCRIUInvoke func(
	context.Context,
	string,
	vnextReaderVerifiedPublication,
) error

// vnextReaderCRIURemapRunner materializes the existing strict TRREMAP006
// adapter only after the publication has passed authorization, descriptor,
// exact-byte, SHA-256, codec, and graph validation. The remap is deleted after
// Invoke returns and is never retained as portable checkpoint metadata.
type vnextReaderCRIURemapRunner struct {
	WorkDirectory string
	Invoke        vnextReaderCRIUInvoke
}

func (runner vnextReaderCRIURemapRunner) RunAuthorizedVNextPublication(
	ctx context.Context,
	directory *vnextLocalDAXDirectory,
	verified vnextReaderVerifiedPublication,
) error {
	if runner.Invoke == nil {
		return errors.New("VNext reader CRIU invocation is unavailable")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	path, cleanup, err := directory.materializeVNextCRIUCompleteRemap(
		runner.WorkDirectory, verified.Publication)
	if err != nil {
		return fmt.Errorf("materialize authorized VNext CRIU remap: %w", err)
	}
	defer cleanup()
	if err := runner.Invoke(ctx, path, verified); err != nil {
		return fmt.Errorf("run authorized VNext CRIU restore adapter: %w", err)
	}
	return nil
}

type vnextAuthorizedReader struct {
	directory  *vnextLocalDAXDirectory
	authorizer vnextReaderAuthorizer
	source     vnextReaderDAXSource
	runner     vnextReaderRunner
}

func newVNextAuthorizedReader(
	directory *vnextLocalDAXDirectory,
	authorizer vnextReaderAuthorizer,
	source vnextReaderDAXSource,
	runner vnextReaderRunner,
) (*vnextAuthorizedReader, error) {
	if directory == nil || len(directory.byUUID) == 0 {
		return nil, errors.New("VNext reader local DAX directory is unavailable")
	}
	if authorizer == nil {
		return nil, errors.New("VNext reader authorizer is unavailable")
	}
	if source == nil {
		return nil, errors.New("VNext reader DAX source is unavailable")
	}
	if runner == nil {
		return nil, errors.New("VNext reader runner is unavailable")
	}
	return &vnextAuthorizedReader{
		directory:  directory,
		authorizer: authorizer,
		source:     source,
		runner:     runner,
	}, nil
}

// Restore authorizes before the first source call, fetches only the exact
// locator pages, and hands a fully verified publication to the injected
// restore runner. It never invokes an Owner RPC and never accepts a local path
// from request or publication data.
func (reader *vnextAuthorizedReader) Restore(
	ctx context.Context,
	request vnextReaderRequest,
) (vnextReaderVerifiedPublication, error) {
	if reader == nil || reader.directory == nil || reader.authorizer == nil ||
		reader.source == nil || reader.runner == nil {
		return vnextReaderVerifiedPublication{}, errors.New("VNext reader is unavailable")
	}
	if err := validateVNextReaderRequest(request); err != nil {
		return vnextReaderVerifiedPublication{}, err
	}
	if err := ctx.Err(); err != nil {
		return vnextReaderVerifiedPublication{}, err
	}

	authorization, err := reader.authorizer.AuthorizeVNextReader(ctx, request)
	if err != nil {
		return vnextReaderVerifiedPublication{}, fmt.Errorf(
			"authorize VNext restore before DAX read: %w", err)
	}
	authorization = cloneVNextReaderAuthorization(authorization)
	pages, err := reader.validateAuthorization(request, authorization)
	if err != nil {
		return vnextReaderVerifiedPublication{}, fmt.Errorf(
			"validate VNext restore authorization before DAX read: %w", err)
	}

	verified, err := reader.fetchAuthorizedPublication(ctx, authorization, pages)
	if err != nil {
		return vnextReaderVerifiedPublication{}, err
	}
	if err := reader.runner.RunAuthorizedVNextPublication(
		ctx, reader.directory, verified); err != nil {
		return vnextReaderVerifiedPublication{}, err
	}
	return verified, nil
}

type vnextReaderResolvedPage struct {
	PageID  cxlcheckpoint.PageID
	Binding vnextLocalDAXBinding
}

func (reader *vnextAuthorizedReader) validateAuthorization(
	request vnextReaderRequest,
	authorization vnextReaderAuthorization,
) ([]vnextReaderResolvedPage, error) {
	for _, identity := range []struct {
		name    string
		request string
		granted string
	}{
		{"restore authorization ID", request.RestoreAuthorizationID, authorization.RestoreAuthorizationID},
		{"checkpoint ID", request.CheckpointID, authorization.CheckpointID},
		{"executor ID", request.ExecutorID, authorization.ExecutorID},
		{"cxld instance ID", request.CxldInstanceID, authorization.CxldInstanceID},
		{"target container ID", request.TargetContainerID, authorization.TargetContainerID},
	} {
		if identity.request != identity.granted {
			return nil, fmt.Errorf(
				"authorized %s %q does not match request %q",
				identity.name, identity.granted, identity.request)
		}
	}
	root := authorization.Root
	for _, identity := range []struct {
		name  string
		value string
	}{
		{"authorized root ID", root.RootID},
		{"authorized MM template ID", root.MMTemplateID},
		{"authorized PageMap ID", root.PageMapID},
	} {
		if err := validateVNextReaderIdentity(identity.name, identity.value); err != nil {
			return nil, err
		}
	}
	if root.RootVersion == 0 || root.RootVersion > cxlcheckpoint.MaxSignedLong {
		return nil, fmt.Errorf("authorized root version %d is invalid", root.RootVersion)
	}
	if root.PageMapVersion == 0 || root.PageMapVersion > cxlcheckpoint.MaxSignedLong {
		return nil, fmt.Errorf("authorized PageMap version %d is invalid", root.PageMapVersion)
	}
	if root.ContractID != cxlcheckpoint.V6CompatibilityID {
		return nil, fmt.Errorf(
			"authorized contract %q is not the exact V6 compatibility identity",
			root.ContractID)
	}
	locator := root.PublicationLocator
	if locator.PublicationByteLength == 0 ||
		locator.PublicationByteLength > uint64(cxlcheckpoint.PublicationEnvelopeHeaderBytes)+
			cxlcheckpoint.MaxPayloadBytes {
		return nil, fmt.Errorf(
			"authorized publication length %d is outside the V6 envelope limit",
			locator.PublicationByteLength)
	}
	if len(locator.PageRuns) == 0 || len(locator.PageRuns) > vnextReaderMaxLocatorRuns {
		return nil, fmt.Errorf(
			"authorized locator run count %d is outside 1..%d",
			len(locator.PageRuns), vnextReaderMaxLocatorRuns)
	}

	expectedPages := (locator.PublicationByteLength + cxlcheckpoint.PageSize - 1) /
		cxlcheckpoint.PageSize
	locatedPages := uint64(0)
	resolved := make([]vnextReaderResolvedPage, 0, expectedPages)
	type physicalRange struct {
		start uint64
		end   uint64
	}
	byDevice := make(map[string][]physicalRange)
	for index, run := range locator.PageRuns {
		pageID := run.FirstPage
		if err := validateVNextReaderIdentity("locator Owner ID", pageID.OwnerID); err != nil {
			return nil, fmt.Errorf("locator run %d: %w", index, err)
		}
		if err := validateVNextReaderDeviceID(pageID.DeviceUUID); err != nil {
			return nil, fmt.Errorf("locator run %d: %w", index, err)
		}
		if pageID.AllocationRecordID == 0 ||
			pageID.AllocationRecordID > cxlcheckpoint.MaxSignedLong {
			return nil, fmt.Errorf("locator run %d has invalid allocation record ID", index)
		}
		if run.PageCount == 0 || run.PageCount > cxlcheckpoint.MaxSignedLong ||
			pageID.DataPageIndex > cxlcheckpoint.MaxSignedLong-run.PageCount {
			return nil, fmt.Errorf("locator run %d has an invalid or overflowing page range", index)
		}
		if locatedPages > expectedPages || run.PageCount > expectedPages-locatedPages {
			return nil, fmt.Errorf(
				"locator run %d exceeds the %d pages required by the exact length",
				index, expectedPages)
		}
		if locatedPages > cxlcheckpoint.MaxSignedLong-run.PageCount {
			return nil, errors.New("authorized locator page coverage overflows")
		}
		locatedPages += run.PageCount
		binding, exists := reader.directory.byUUID[pageID.DeviceUUID]
		if !exists {
			return nil, fmt.Errorf(
				"locator run %d has no local DAX binding for device %q",
				index, pageID.DeviceUUID)
		}
		end := pageID.DataPageIndex + run.PageCount
		if binding.OwnerID != pageID.OwnerID || end > binding.DataPageCount {
			return nil, fmt.Errorf(
				"locator run %d does not match local Owner identity or capacity", index)
		}
		if index > 0 {
			previous := locator.PageRuns[index-1]
			if previous.FirstPage.OwnerID == pageID.OwnerID &&
				previous.FirstPage.DeviceUUID == pageID.DeviceUUID &&
				previous.FirstPage.AllocationRecordID == pageID.AllocationRecordID &&
				previous.FirstPage.DataPageIndex+previous.PageCount == pageID.DataPageIndex {
				return nil, fmt.Errorf("locator runs %d and %d are not coalesced", index-1, index)
			}
		}
		key := pageID.OwnerID + "\x00" + pageID.DeviceUUID
		byDevice[key] = append(byDevice[key], physicalRange{
			start: pageID.DataPageIndex,
			end:   end,
		})
		for page := uint64(0); page < run.PageCount; page++ {
			current := pageID
			current.DataPageIndex += page
			resolved = append(resolved, vnextReaderResolvedPage{
				PageID:  current,
				Binding: binding,
			})
		}
	}
	if locatedPages != expectedPages {
		return nil, fmt.Errorf(
			"authorized locator covers %d pages, exact length requires %d",
			locatedPages, expectedPages)
	}
	for key, ranges := range byDevice {
		sort.Slice(ranges, func(i, j int) bool {
			if ranges[i].start == ranges[j].start {
				return ranges[i].end < ranges[j].end
			}
			return ranges[i].start < ranges[j].start
		})
		for index := 1; index < len(ranges); index++ {
			if ranges[index-1].end > ranges[index].start {
				return nil, fmt.Errorf("authorized locator has overlapping ranges on %q", key)
			}
		}
	}
	return resolved, nil
}

func (reader *vnextAuthorizedReader) fetchAuthorizedPublication(
	ctx context.Context,
	authorization vnextReaderAuthorization,
	pages []vnextReaderResolvedPage,
) (vnextReaderVerifiedPublication, error) {
	root := authorization.Root
	locator := root.PublicationLocator
	capacity := uint64(len(pages)) * cxlcheckpoint.PageSize
	if capacity > uint64(math.MaxInt) {
		return vnextReaderVerifiedPublication{}, errors.New("authorized publication exceeds host address space")
	}
	located := make([]byte, 0, int(capacity))
	for index, page := range pages {
		if err := ctx.Err(); err != nil {
			return vnextReaderVerifiedPublication{}, err
		}
		descriptor, err := reader.source.ReadVNextDescriptor(
			ctx, page.Binding, page.PageID.DataPageIndex)
		if err != nil {
			return vnextReaderVerifiedPublication{}, fmt.Errorf(
				"read publication descriptor %d: %w", index, err)
		}
		if descriptor.State != vnextDescriptorSealed ||
			descriptor.AllocationRecordID != page.PageID.AllocationRecordID ||
			descriptor.ContentKind != vnextContentPublication ||
			descriptor.PayloadLength != uint32(cxlcheckpoint.PageSize) {
			return vnextReaderVerifiedPublication{}, fmt.Errorf(
				"publication descriptor %d is not SEALED publication content for authorized Owner/device/allocation",
				index)
		}
		if err := ctx.Err(); err != nil {
			return vnextReaderVerifiedPublication{}, err
		}
		content, err := reader.source.ReadVNextContentPage(
			ctx, page.Binding, page.PageID.DataPageIndex)
		if err != nil {
			return vnextReaderVerifiedPublication{}, fmt.Errorf(
				"read publication content page %d: %w", index, err)
		}
		if err := descriptor.validateContent(content); err != nil {
			return vnextReaderVerifiedPublication{}, fmt.Errorf(
				"validate publication content page %d: %w", index, err)
		}
		// Detect an in-process or externally visible descriptor transition
		// across the payload read. Scheduler mapping authority should prevent
		// this; any observed change is nevertheless rejected rather than used.
		after, err := reader.source.ReadVNextDescriptor(
			ctx, page.Binding, page.PageID.DataPageIndex)
		if err != nil {
			return vnextReaderVerifiedPublication{}, fmt.Errorf(
				"reread publication descriptor %d: %w", index, err)
		}
		if after != descriptor {
			return vnextReaderVerifiedPublication{}, fmt.Errorf(
				"publication descriptor %d changed during its payload read", index)
		}
		located = append(located, content...)
	}
	if locator.PublicationByteLength > uint64(len(located)) {
		return vnextReaderVerifiedPublication{}, errors.New("authorized publication locator is truncated")
	}
	exactLength := int(locator.PublicationByteLength)
	if !allVNextReaderZero(located[exactLength:]) {
		return vnextReaderVerifiedPublication{}, errors.New(
			"publication final located page has non-zero bytes after the exact envelope")
	}
	exact := append([]byte(nil), located[:exactLength]...)
	if digest := sha256.Sum256(exact); digest != locator.PublicationSHA256 {
		return vnextReaderVerifiedPublication{}, errors.New(
			"publication exact-byte SHA-256 does not match authorized root")
	}
	publication, err := cxlcheckpoint.Decode(exact)
	if err != nil {
		return vnextReaderVerifiedPublication{}, fmt.Errorf(
			"strictly decode authorized TRPUB006 publication: %w", err)
	}
	canonical, err := cxlcheckpoint.Encode(publication)
	if err != nil {
		return vnextReaderVerifiedPublication{}, fmt.Errorf(
			"re-encode authorized TRPUB006 publication: %w", err)
	}
	if !bytes.Equal(canonical, exact) {
		return vnextReaderVerifiedPublication{}, errors.New(
			"authorized TRPUB006 bytes are not the canonical V6 encoding")
	}
	if err := reader.validateDecodedPublication(authorization, publication); err != nil {
		return vnextReaderVerifiedPublication{}, err
	}
	return vnextReaderVerifiedPublication{
		Publication: publication,
		ExactBytes:  exact,
	}, nil
}

func (reader *vnextAuthorizedReader) validateDecodedPublication(
	authorization vnextReaderAuthorization,
	publication cxlcheckpoint.Publication,
) error {
	trusted := authorization.Root
	root := publication.Root
	if publication.CheckpointID != authorization.CheckpointID ||
		root.CheckpointID != authorization.CheckpointID ||
		root.RootID != trusted.RootID ||
		root.PublicationSequence != trusted.RootVersion ||
		publication.MMTemplate.TemplateID != trusted.MMTemplateID ||
		root.MMTemplateID != trusted.MMTemplateID ||
		publication.PageMap.PageMapID != trusted.PageMapID ||
		root.PageMapID != trusted.PageMapID ||
		publication.PageMap.Version != trusted.PageMapVersion ||
		root.PageMapVersion != trusted.PageMapVersion {
		return errors.New("decoded publication graph does not match the authorized root")
	}
	if root.DeviceTableDigest != trusted.DeviceTableDigest {
		return errors.New("decoded committed root has a different device-table digest")
	}
	digest, err := cxlcheckpoint.DeviceTableDigest(publication.Devices)
	if err != nil {
		return fmt.Errorf("digest decoded V6 device table: %w", err)
	}
	if digest != trusted.DeviceTableDigest {
		return errors.New("decoded V6 device table does not match the authorized digest")
	}
	portableDevices := make(map[string]cxlcheckpoint.Device, len(publication.Devices))
	for _, portable := range publication.Devices {
		binding, exists := reader.directory.byUUID[portable.DeviceUUID]
		if !exists {
			return fmt.Errorf(
				"decoded device %q has no local DAX binding", portable.DeviceUUID)
		}
		if binding.OwnerID != portable.OwnerID ||
			binding.OwnerEpoch != portable.OwnerEpoch ||
			binding.DataPageCount != portable.DataPageCount {
			return fmt.Errorf(
				"decoded device %q does not match local Owner/epoch/capacity",
				portable.DeviceUUID)
		}
		portableDevices[portable.DeviceUUID] = portable
	}
	for index, run := range trusted.PublicationLocator.PageRuns {
		portable, exists := portableDevices[run.FirstPage.DeviceUUID]
		if !exists || portable.OwnerID != run.FirstPage.OwnerID {
			return fmt.Errorf(
				"authorized locator run %d is absent from the decoded device table", index)
		}
	}
	return nil
}

func validateVNextReaderRequest(request vnextReaderRequest) error {
	for _, identity := range []struct {
		name  string
		value string
	}{
		{"restore authorization ID", request.RestoreAuthorizationID},
		{"checkpoint ID", request.CheckpointID},
		{"executor ID", request.ExecutorID},
		{"cxld instance ID", request.CxldInstanceID},
		{"target container ID", request.TargetContainerID},
	} {
		if err := validateVNextReaderIdentity(identity.name, identity.value); err != nil {
			return err
		}
	}
	return nil
}

func validateVNextReaderIdentity(name string, value string) error {
	if value == "" || !utf8.ValidString(value) ||
		len([]byte(value)) > cxlcheckpoint.MaxIdentityBytes ||
		strings.TrimSpace(value) != value {
		return fmt.Errorf("%s is empty, invalid UTF-8, too long, or has surrounding whitespace", name)
	}
	for _, character := range value {
		if unicode.IsControl(character) {
			return fmt.Errorf("%s contains a control character", name)
		}
	}
	return nil
}

func validateVNextReaderDeviceID(value string) error {
	if err := validateVNextReaderIdentity("locator device UUID", value); err != nil {
		return err
	}
	fileURI := len(value) >= len("file:") && strings.EqualFold(value[:len("file:")], "file:")
	if value == "." || value == ".." || strings.ContainsAny(value, "/\\") || fileURI {
		return fmt.Errorf("locator device UUID %q is a local path or URI", value)
	}
	return nil
}

func cloneVNextReaderAuthorization(
	authorization vnextReaderAuthorization,
) vnextReaderAuthorization {
	cloned := authorization
	cloned.Root.PublicationLocator.PageRuns = append(
		[]cxlcheckpoint.PublicationPageRun(nil),
		authorization.Root.PublicationLocator.PageRuns...)
	return cloned
}

func allVNextReaderZero(data []byte) bool {
	for _, value := range data {
		if value != 0 {
			return false
		}
	}
	return true
}

// vnextRegularFileReaderDAXSource is a read-only, file-backed test and QEMU
// adapter. It deliberately does not call openVNextFileDevice or
// openVNextStorageDevice: those functions perform allocator recovery and may
// write Owner metadata. Each operation opens O_RDONLY, selects the existing
// A/B TRCXL006 superblock, verifies the directory binding, and reads only the
// requested descriptor or content page.
type vnextRegularFileReaderDAXSource struct{}

func (vnextRegularFileReaderDAXSource) ReadVNextDescriptor(
	ctx context.Context,
	binding vnextLocalDAXBinding,
	dataPageIndex uint64,
) (vnextPageDescriptor, error) {
	if err := ctx.Err(); err != nil {
		return vnextPageDescriptor{}, err
	}
	file, storage, superblock, err := openVNextReaderRegularFile(binding)
	if err != nil {
		return vnextPageDescriptor{}, err
	}
	defer file.Close() //nolint:errcheck
	offset, err := superblock.Geometry.descriptorOffset(dataPageIndex)
	if err != nil {
		return vnextPageDescriptor{}, err
	}
	raw := make([]byte, vnextPageDescriptorSize)
	if err := vnextReadAtFull(storage, raw, offset); err != nil {
		return vnextPageDescriptor{}, err
	}
	return parseVNextPageDescriptor(raw)
}

func (vnextRegularFileReaderDAXSource) ReadVNextContentPage(
	ctx context.Context,
	binding vnextLocalDAXBinding,
	dataPageIndex uint64,
) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	file, storage, superblock, err := openVNextReaderRegularFile(binding)
	if err != nil {
		return nil, err
	}
	defer file.Close() //nolint:errcheck
	offset, err := superblock.Geometry.contentOffset(dataPageIndex)
	if err != nil {
		return nil, err
	}
	raw := make([]byte, vnextContentPageSize)
	if err := vnextReadAtFull(storage, raw, offset); err != nil {
		return nil, err
	}
	return raw, nil
}

func openVNextReaderRegularFile(
	binding vnextLocalDAXBinding,
) (*os.File, *vnextRegularFileStorage, vnextDeviceSuperblock, error) {
	if err := validateVNextLocalDAXPath(binding.DevicePath); err != nil {
		return nil, nil, vnextDeviceSuperblock{}, err
	}
	file, err := os.Open(binding.DevicePath)
	if err != nil {
		return nil, nil, vnextDeviceSuperblock{}, fmt.Errorf(
			"open VNext reader regular-file DAX %q read-only: %w", binding.DevicePath, err)
	}
	closeWithError := func(cause error) (*os.File, *vnextRegularFileStorage, vnextDeviceSuperblock, error) {
		if closeErr := file.Close(); closeErr != nil {
			return nil, nil, vnextDeviceSuperblock{}, fmt.Errorf("%v; close reader file: %w", cause, closeErr)
		}
		return nil, nil, vnextDeviceSuperblock{}, cause
	}
	storage, err := newVNextRegularFileStorage(file)
	if err != nil {
		return closeWithError(err)
	}
	first, firstErr := vnextReadSuperblockSlot(storage, 0)
	second, secondErr := vnextReadSuperblockSlot(storage, vnextSuperblockSlotBytes)
	superblock, err := vnextSelectSuperblock(first, firstErr, second, secondErr)
	if err != nil {
		return closeWithError(err)
	}
	if storage.Size() != superblock.Geometry.DeviceBytes ||
		superblock.DeviceUUID != binding.DeviceUUID ||
		superblock.OwnerID != binding.OwnerID ||
		superblock.OwnerEpoch != binding.OwnerEpoch ||
		superblock.Geometry.DataPageCount != binding.DataPageCount ||
		superblock.Geometry.ContentRegionBase != binding.ContentRegionBase {
		return closeWithError(errors.New(
			"read-only TRCXL006 superblock does not match the local DAX binding"))
	}
	return file, storage, superblock, nil
}

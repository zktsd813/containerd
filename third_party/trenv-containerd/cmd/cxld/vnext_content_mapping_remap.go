package main

import (
	"bytes"
	"errors"
	"fmt"

	"github.com/containerd/containerd/third_party/trenv-containerd/pkg/cxlcheckpoint"
)

// buildVNextContentMappingCRIUCompleteRemap composes the immutable V7 virtual
// topology with one validated mutable V7 physical placement map and emits the
// existing strict, ephemeral TRREMAP006 input:
//
//   pages_image_id vaddr page_count device_page_offset local_device_path
//
// The method performs no DAX read, file write, CRIU invocation, publication
// selection, or active-slot mutation. Both portable maps are validated before
// any node-local path is resolved. One output line is emitted for each
// VirtualPageMap/ContentPlacementMap run intersection; boundaries are not
// coalesced, so allocation-record and dedup-placement transitions remain
// explicit.
//
// Matching a placement Device against vnextLocalDAXBinding proves only that
// the configured, non-authoritative local directory is internally consistent.
// It does not prove the current shared-DAX superblock, Owner epoch, or Reader
// authorization. Production wiring must call this only after ACTIVE_ARMED and
// a live superblock verification for every placement device (or after a future
// verified-binding token proves the same facts).
func (directory *vnextLocalDAXDirectory) buildVNextContentMappingCRIUCompleteRemap(
	contentObjects []cxlcheckpoint.ContentObject,
	virtualPageMap cxlcheckpoint.VirtualPageMap,
	contentPlacementMap cxlcheckpoint.ContentPlacementMap,
) ([]byte, error) {
	return directory.buildVNextContentMappingCRIUCompleteRemapBounded(
		contentObjects,
		virtualPageMap,
		contentPlacementMap,
		vnextMaxCRIURemapBytes)
}

// buildVNextContentMappingCRIUCompleteRemapBounded is a reduced-bound test seam:
// production always supplies vnextMaxCRIURemapBytes, while tests may prove the
// same fail-closed accounting with a smaller limit. A caller can never widen
// the established 64 MiB TRREMAP006 bound.
func (directory *vnextLocalDAXDirectory) buildVNextContentMappingCRIUCompleteRemapBounded(
	contentObjects []cxlcheckpoint.ContentObject,
	virtualPageMap cxlcheckpoint.VirtualPageMap,
	contentPlacementMap cxlcheckpoint.ContentPlacementMap,
	maxBytes int,
) ([]byte, error) {
	if maxBytes <= len(vnextCRIURemapMagic) || maxBytes > vnextMaxCRIURemapBytes {
		return nil, fmt.Errorf(
			"V7 content-mapping CRIU remap byte limit %d is outside %d..%d",
			maxBytes, len(vnextCRIURemapMagic)+1, vnextMaxCRIURemapBytes)
	}
	if directory == nil || len(directory.byUUID) == 0 {
		return nil, errors.New("VNext local DAX directory is unavailable")
	}
	if err := virtualPageMap.Validate(contentObjects); err != nil {
		return nil, fmt.Errorf(
			"validate V7 VirtualPageMap before CRIU remap: %w", err)
	}
	if err := contentPlacementMap.Validate(contentObjects); err != nil {
		return nil, fmt.Errorf(
			"validate V7 ContentPlacementMap before CRIU remap: %w", err)
	}
	bindings, err := directory.matchVNextContentMappingConfiguredBindings(
		contentPlacementMap.Devices)
	if err != nil {
		return nil, err
	}

	var output bytes.Buffer
	output.WriteString(vnextCRIURemapMagic)
	output.WriteByte('\n')
	for runIndex, virtualRun := range virtualPageMap.Runs {
		remaining := virtualRun.PageCount
		virtualAddress := virtualRun.StartVAddr
		objectPageIndex := virtualRun.ObjectPageIndex
		for segmentIndex := uint64(0); remaining > 0; segmentIndex++ {
			logical, ok := virtualPageMap.ResolveVirtualPage(
				virtualRun.PagesImageID, virtualAddress)
			if !ok || logical.ContentObjectID != virtualRun.ContentObjectID ||
				logical.ObjectPageIndex != objectPageIndex ||
				logical.ContiguousPageCount != remaining {
				return nil, fmt.Errorf(
					"VirtualPageMap run %d segment %d cannot be resolved exactly",
					runIndex, segmentIndex)
			}
			physical, ok := contentPlacementMap.ResolveContentPage(
				logical.ContentObjectID, logical.ObjectPageIndex)
			if !ok || physical.ContiguousPageCount == 0 {
				return nil, fmt.Errorf(
					"ContentPlacementMap has no physical range for VirtualPageMap run %d segment %d",
					runIndex, segmentIndex)
			}
			segmentPages := remaining
			if physical.ContiguousPageCount < segmentPages {
				segmentPages = physical.ContiguousPageCount
			}
			binding, exists := bindings[physical.PageID.DeviceUUID]
			if !exists || binding.OwnerID != physical.PageID.OwnerID ||
				binding.OwnerEpoch != physical.OwnerEpoch {
				return nil, fmt.Errorf(
					"resolved physical page for VirtualPageMap run %d segment %d has no matching configured local binding",
					runIndex, segmentIndex)
			}
			contentBasePage := binding.ContentRegionBase / cxlcheckpoint.PageSize
			devicePageOffset, ok := vnextAdd(
				contentBasePage, physical.PageID.DataPageIndex)
			if !ok || devicePageOffset > cxlcheckpoint.MaxSignedLong {
				return nil, fmt.Errorf(
					"VirtualPageMap run %d segment %d local device offset overflows signed ABI",
					runIndex, segmentIndex)
			}
			devicePageEnd, rangeOK := vnextAdd(devicePageOffset, segmentPages)
			contentRegionEnd, capacityOK := vnextAdd(
				contentBasePage, binding.DataPageCount)
			if !rangeOK || !capacityOK ||
				devicePageEnd > contentRegionEnd ||
				devicePageEnd > cxlcheckpoint.MaxSignedLong {
				return nil, fmt.Errorf(
					"VirtualPageMap run %d segment %d local device range exceeds V7 geometry",
					runIndex, segmentIndex)
			}

			line := fmt.Sprintf(
				"%d %d %d %d %s\n",
				virtualRun.PagesImageID,
				virtualAddress,
				segmentPages,
				devicePageOffset,
				binding.DevicePath)
			if output.Len() > maxBytes || len(line) > maxBytes-output.Len() {
				return nil, fmt.Errorf(
					"strict V7 content-mapping CRIU remap exceeds %d bytes",
					maxBytes)
			}
			output.WriteString(line)

			remaining -= segmentPages
			if remaining == 0 {
				continue
			}
			virtualDelta, ok := vnextMul(segmentPages, cxlcheckpoint.PageSize)
			if !ok {
				return nil, fmt.Errorf(
					"VirtualPageMap run %d segment %d virtual delta overflows",
					runIndex, segmentIndex)
			}
			virtualAddress, ok = vnextAdd(virtualAddress, virtualDelta)
			if !ok || virtualAddress > cxlcheckpoint.MaxSignedLong {
				return nil, fmt.Errorf(
					"VirtualPageMap run %d segment %d virtual address overflows signed ABI",
					runIndex, segmentIndex)
			}
			objectPageIndex, ok = vnextAdd(objectPageIndex, segmentPages)
			if !ok || objectPageIndex > cxlcheckpoint.MaxSignedLong {
				return nil, fmt.Errorf(
					"VirtualPageMap run %d segment %d logical page index overflows signed ABI",
					runIndex, segmentIndex)
			}
		}
	}
	return append([]byte(nil), output.Bytes()...), nil
}

// matchVNextContentMappingConfiguredBindings checks every portable
// placement-map Device against non-authoritative local configuration,
// including Devices used only by artifact or restore-blob content. It performs
// no DAX read and does not replace the required post-ACTIVE_ARMED live
// superblock/Owner-epoch verification.
func (directory *vnextLocalDAXDirectory) matchVNextContentMappingConfiguredBindings(
	devices []cxlcheckpoint.Device,
) (map[string]vnextLocalDAXBinding, error) {
	bindings := make(map[string]vnextLocalDAXBinding, len(devices))
	paths := make(map[string]string, len(devices))
	for index, portable := range devices {
		binding, exists := directory.byUUID[portable.DeviceUUID]
		if !exists {
			return nil, fmt.Errorf(
				"no local DAX binding for V7 placement device %q",
				portable.DeviceUUID)
		}
		if binding.DeviceUUID != portable.DeviceUUID ||
			binding.OwnerID != portable.OwnerID ||
			binding.OwnerEpoch != portable.OwnerEpoch ||
			binding.DataPageCount != portable.DataPageCount {
			return nil, fmt.Errorf(
				"configured local DAX binding %q does not match V7 placement Owner/epoch/capacity",
				portable.DeviceUUID)
		}
		if err := validateVNextLocalDAXPath(binding.DevicePath); err != nil {
			return nil, fmt.Errorf(
				"local DAX binding %q: %w", portable.DeviceUUID, err)
		}
		if binding.ContentRegionBase == 0 ||
			binding.ContentRegionBase%cxlcheckpoint.PageSize != 0 ||
			binding.ContentRegionBase > cxlcheckpoint.MaxSignedLong {
			return nil, fmt.Errorf(
				"local DAX binding %q has invalid V7 content-region base",
				portable.DeviceUUID)
		}
		contentBytes, bytesOK := vnextMul(
			binding.DataPageCount, cxlcheckpoint.PageSize)
		contentEnd, endOK := vnextAdd(binding.ContentRegionBase, contentBytes)
		contentBasePage := binding.ContentRegionBase / cxlcheckpoint.PageSize
		pageEnd, pageEndOK := vnextAdd(contentBasePage, binding.DataPageCount)
		if !bytesOK || !endOK || !pageEndOK ||
			contentEnd > cxlcheckpoint.MaxSignedLong ||
			pageEnd > cxlcheckpoint.MaxSignedLong {
			return nil, fmt.Errorf(
				"local DAX binding %q content geometry overflows signed ABI",
				portable.DeviceUUID)
		}
		if previousUUID, duplicate := paths[binding.DevicePath]; duplicate {
			return nil, fmt.Errorf(
				"local DAX path %q aliases V7 placement devices %q and %q",
				binding.DevicePath, previousUUID, portable.DeviceUUID)
		}
		if _, duplicate := bindings[portable.DeviceUUID]; duplicate {
			return nil, fmt.Errorf(
				"duplicate V7 placement device UUID %q at index %d",
				portable.DeviceUUID, index)
		}
		bindings[portable.DeviceUUID] = binding
		paths[binding.DevicePath] = portable.DeviceUUID
	}
	return bindings, nil
}

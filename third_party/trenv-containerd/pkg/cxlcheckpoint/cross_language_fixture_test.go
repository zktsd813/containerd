package cxlcheckpoint

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"reflect"
	"strings"
	"testing"
)

const (
	crossLanguageFixtureSchema         = "trenv.cxlcheckpoint.cross-language.v1"
	crossLanguageFixtureManifest       = "trpub006-cross-language-v1.json"
	crossLanguageFixturePublication    = "trpub006-cross-language-v1.b64"
	crossLanguageFixtureExactBytes     = 5263
	crossLanguageFixtureSHA256         = "ff2f3685fdbb3fee1d54ff1e26d1819fb20a60f817cfbf41d35b53121261a456"
	crossLanguageFixtureDeviceSHA256   = "1bca732f28cb7a7cbe7bff8bc7b5329b88e0d4a68f0a0c299cc58293af92b339"
	crossLanguageFixtureSlotPages      = 3
	crossLanguageFixtureAllocationID   = 42
	crossLanguageFixtureOwnerEpoch     = 7
	crossLanguageFixtureCheckpointID   = "fixture-checkpoint-v6"
	crossLanguageFixtureInitialOwnerID = "owner-a"
)

type crossLanguageFixtureDevice struct {
	DeviceUUID    string `json:"deviceUuid"`
	OwnerID       string `json:"ownerId"`
	OwnerEpoch    uint64 `json:"ownerEpoch"`
	DataPageCount uint64 `json:"dataPageCount"`
}

type crossLanguageFixtureExtent struct {
	DeviceUUID         string `json:"deviceUuid"`
	StartDataPageIndex uint64 `json:"startDataPageIndex"`
	PageCount          uint64 `json:"pageCount"`
	LogicalPageStart   uint64 `json:"logicalPageStart"`
}

type crossLanguageFixtureAllocation struct {
	CheckpointID       string                       `json:"checkpointId"`
	OwnerID            string                       `json:"ownerId"`
	OwnerEpoch         uint64                       `json:"ownerEpoch"`
	AllocationRecordID uint64                       `json:"allocationRecordId"`
	TotalPages         uint64                       `json:"totalPages"`
	Extents            []crossLanguageFixtureExtent `json:"extents"`
}

type crossLanguageFixturePageID struct {
	OwnerID            string `json:"ownerId"`
	DeviceUUID         string `json:"deviceUuid"`
	DataPageIndex      uint64 `json:"dataPageIndex"`
	AllocationRecordID uint64 `json:"allocationRecordId"`
}

type crossLanguageFixturePageRun struct {
	FirstPage crossLanguageFixturePageID `json:"firstPage"`
	PageCount uint64                     `json:"pageCount"`
}

type crossLanguageFixtureRoot struct {
	RootID         string `json:"rootId"`
	RootVersion    uint64 `json:"rootVersion"`
	MMTemplateID   string `json:"mmTemplateId"`
	PageMapID      string `json:"pageMapId"`
	PageMapVersion uint64 `json:"pageMapVersion"`
}

type crossLanguageFixtureData struct {
	FixtureSchema                string                         `json:"fixtureSchema"`
	PublicationFile              string                         `json:"publicationFile"`
	ContractID                   string                         `json:"contractId"`
	PublicationByteLength        uint64                         `json:"publicationByteLength"`
	PublicationSHA256            string                         `json:"publicationSha256"`
	PublicationSlotCapacityPages uint64                         `json:"publicationSlotCapacityPages"`
	InitialAllocation            crossLanguageFixtureAllocation `json:"initialAllocation"`
	DeviceTable                  []crossLanguageFixtureDevice   `json:"deviceTable"`
	DeviceTableSHA256            string                         `json:"deviceTableSha256"`
	Root                         crossLanguageFixtureRoot       `json:"root"`
	PageRuns                     []crossLanguageFixturePageRun  `json:"pageRuns"`
}

func TestCrossLanguageTRPUB006GoldenV1(t *testing.T) {
	manifest := readCrossLanguageFixtureManifest(t)
	requireCrossLanguageFixtureLiterals(t, manifest)

	publication := buildCrossLanguageFixturePublication(t)
	encoded, err := Encode(publication)
	if err != nil {
		t.Fatalf("encode fixture publication: %v", err)
	}
	requireFixtureEnvelopeIdentity(t, encoded)

	golden := readCrossLanguageFixtureEnvelope(t, manifest.PublicationFile)
	requireFixtureEnvelopeIdentity(t, golden)
	if !bytes.Equal(encoded, golden) {
		t.Fatal("Go TRPUB006 encoder differs from the immutable cross-language golden")
	}

	decoded, err := Decode(golden)
	if err != nil {
		t.Fatalf("decode cross-language golden: %v", err)
	}
	if !reflect.DeepEqual(decoded, publication) {
		t.Fatalf("decoded fixture differs from its semantic publication:\n got: %#v\nwant: %#v",
			decoded, publication)
	}
	reencoded, err := Encode(decoded)
	if err != nil {
		t.Fatalf("re-encode cross-language golden: %v", err)
	}
	if !bytes.Equal(reencoded, golden) {
		t.Fatal("decoded cross-language golden did not re-encode byte-for-byte")
	}

	if decoded.CheckpointID != manifest.InitialAllocation.CheckpointID ||
		decoded.Allocation.OwnerID != manifest.InitialAllocation.OwnerID ||
		decoded.Allocation.OwnerEpoch != manifest.InitialAllocation.OwnerEpoch ||
		decoded.Allocation.AllocationRecordID != manifest.InitialAllocation.AllocationRecordID ||
		decoded.Allocation.TotalPages != manifest.InitialAllocation.TotalPages {
		t.Fatalf("decoded allocation identity differs from manifest: %#v", decoded.Allocation)
	}
	if got, want := decoded.Allocation.Extents, fixtureAllocationExtents(manifest); !reflect.DeepEqual(got, want) {
		t.Fatalf("decoded extents = %#v, want %#v", got, want)
	}
	if got, want := decoded.Devices, fixtureDevices(manifest); !reflect.DeepEqual(got, want) {
		t.Fatalf("decoded DeviceTable = %#v, want %#v", got, want)
	}
	if decoded.Root.RootID != manifest.Root.RootID ||
		decoded.Root.PublicationSequence != manifest.Root.RootVersion ||
		decoded.Root.MMTemplateID != manifest.Root.MMTemplateID ||
		decoded.Root.PageMapID != manifest.Root.PageMapID ||
		decoded.Root.PageMapVersion != manifest.Root.PageMapVersion {
		t.Fatalf("decoded root graph identity differs from manifest: %#v", decoded.Root)
	}

	digest, err := DeviceTableDigest(decoded.Devices)
	if err != nil {
		t.Fatalf("digest fixture DeviceTable: %v", err)
	}
	if got := fmt.Sprintf("%x", digest); got != crossLanguageFixtureDeviceSHA256 ||
		got != manifest.DeviceTableSHA256 {
		t.Fatalf("DeviceTable SHA-256 = %s, want %s", got, crossLanguageFixtureDeviceSHA256)
	}

	storage, err := EncodeForStorage(decoded)
	if err != nil {
		t.Fatalf("prepare fixture publication storage: %v", err)
	}
	if storage.CapacityPages != crossLanguageFixtureSlotPages ||
		storage.CapacityPages != manifest.PublicationSlotCapacityPages {
		t.Fatalf("publication slot capacity = %d, want %d",
			storage.CapacityPages, crossLanguageFixtureSlotPages)
	}
	if !bytes.Equal(storage.ExactBytes, golden) {
		t.Fatal("storage exact bytes differ from cross-language golden")
	}
	if len(storage.PaddedBytes) != crossLanguageFixtureSlotPages*int(PageSize) ||
		!bytes.Equal(storage.PaddedBytes[:len(golden)], golden) ||
		!allZero(storage.PaddedBytes[len(golden):]) {
		t.Fatal("publication slot is not exact golden bytes followed only by zero padding")
	}
	wantRuns := fixturePageRuns(manifest)
	if !reflect.DeepEqual(storage.PageRuns, wantRuns) {
		t.Fatalf("ordered publication PageID runs = %#v, want %#v", storage.PageRuns, wantRuns)
	}
}

func TestV6CompatibilityIDKnownAnswerAndComponents(t *testing.T) {
	const expected = "publication=TRPUB006/v6/little-endian/" +
		"trpub006-envelope-little-endian-pages-image-sparse-publication-slot-v1;" +
		"envelope-header=64;max-payload=67108864;" +
		"page=4096;fingerprint=crc32c-castagnoli/0x11edc6f41;" +
		"descriptor=TRCXL006/64/trcxl006-page-descriptor-little-endian-v1"
	if V6CompatibilityID != expected {
		t.Fatalf("V6 compatibility ID = %q, want %q", V6CompatibilityID, expected)
	}
	if PublicationByteOrder != "little-endian" ||
		PublicationABI != "trpub006-envelope-little-endian-pages-image-sparse-publication-slot-v1" ||
		PublicationEnvelopeHeaderBytes != uint64(envelopeHeaderSize) ||
		ContentFingerprintAlgorithm != "crc32c-castagnoli" ||
		ContentFingerprintPolynomial != "0x11edc6f41" ||
		DeviceFormatMagicString != "TRCXL006" ||
		PageDescriptorBytes != 64 ||
		PageDescriptorABI != "trcxl006-page-descriptor-little-endian-v1" {
		t.Fatal("a V6 compatibility component drifted from its known answer")
	}
}

func buildCrossLanguageFixturePublication(t testing.TB) Publication {
	t.Helper()
	publication := validPublication(t)
	publication.CheckpointID = crossLanguageFixtureCheckpointID
	publication.Root.CheckpointID = crossLanguageFixtureCheckpointID

	publication.ContentObjects[len(publication.ContentObjects)-1].ByteLength =
		crossLanguageFixtureSlotPages * PageSize
	publication.ContentObjects[len(publication.ContentObjects)-1].PageCount =
		crossLanguageFixtureSlotPages
	publication.Allocation.TotalPages = 10
	publication.Allocation.Extents = []AllocationExtent{
		{DeviceUUID: "device-a", StartDataPageIndex: 100, PageCount: 8, LogicalPageStart: 0},
		{DeviceUUID: "device-b", StartDataPageIndex: 200, PageCount: 2, LogicalPageStart: 8},
	}

	entries := append([]ArtifactEntry(nil), publication.Artifacts.Entries[:2]...)
	for index := 0; index < 48; index++ {
		entries = append(entries, ArtifactEntry{
			Path: fmt.Sprintf("fixture-padding/entry-%04d", index),
			Type: ArtifactDirectory,
			Mode: 0755,
		})
	}
	entries = append(entries, publication.Artifacts.Entries[2])
	publication.Artifacts.Entries = entries

	refreshDeviceDigest(t, &publication)
	if err := publication.Validate(); err != nil {
		t.Fatalf("cross-language fixture is invalid: %v", err)
	}
	return publication
}

func readCrossLanguageFixtureManifest(t testing.TB) crossLanguageFixtureData {
	t.Helper()
	data, err := os.ReadFile("testdata/" + crossLanguageFixtureManifest)
	if err != nil {
		t.Fatalf("read cross-language fixture manifest: %v", err)
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var manifest crossLanguageFixtureData
	if err := decoder.Decode(&manifest); err != nil {
		t.Fatalf("decode cross-language fixture manifest: %v", err)
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		t.Fatalf("cross-language fixture manifest has trailing JSON: %v", err)
	}
	return manifest
}

func readCrossLanguageFixtureEnvelope(t testing.TB, name string) []byte {
	t.Helper()
	if name != crossLanguageFixturePublication {
		t.Fatalf("fixture publication file = %q, want %q", name, crossLanguageFixturePublication)
	}
	data, err := os.ReadFile("testdata/" + name)
	if err != nil {
		t.Fatalf("read cross-language fixture envelope: %v", err)
	}
	compact := strings.Join(strings.Fields(string(data)), "")
	decoded, err := base64.StdEncoding.Strict().DecodeString(compact)
	if err != nil {
		t.Fatalf("decode cross-language fixture base64: %v", err)
	}
	return decoded
}

func requireFixtureEnvelopeIdentity(t testing.TB, envelope []byte) {
	t.Helper()
	if len(envelope) != crossLanguageFixtureExactBytes {
		t.Fatalf("fixture envelope length = %d, want %d",
			len(envelope), crossLanguageFixtureExactBytes)
	}
	digest := sha256.Sum256(envelope)
	if got := fmt.Sprintf("%x", digest); got != crossLanguageFixtureSHA256 {
		t.Fatalf("fixture envelope SHA-256 = %s, want %s", got, crossLanguageFixtureSHA256)
	}
}

func requireCrossLanguageFixtureLiterals(t testing.TB, manifest crossLanguageFixtureData) {
	t.Helper()
	if manifest.FixtureSchema != crossLanguageFixtureSchema ||
		manifest.PublicationFile != crossLanguageFixturePublication ||
		manifest.ContractID != V6CompatibilityID ||
		manifest.PublicationByteLength != crossLanguageFixtureExactBytes ||
		manifest.PublicationSHA256 != crossLanguageFixtureSHA256 ||
		manifest.PublicationSlotCapacityPages != crossLanguageFixtureSlotPages ||
		manifest.DeviceTableSHA256 != crossLanguageFixtureDeviceSHA256 {
		t.Fatalf("cross-language fixture literals drifted: %#v", manifest)
	}
	allocation := manifest.InitialAllocation
	if allocation.CheckpointID != crossLanguageFixtureCheckpointID ||
		allocation.OwnerID != crossLanguageFixtureInitialOwnerID ||
		allocation.OwnerEpoch != crossLanguageFixtureOwnerEpoch ||
		allocation.AllocationRecordID != crossLanguageFixtureAllocationID ||
		allocation.TotalPages != 10 {
		t.Fatalf("cross-language allocation literals drifted: %#v", allocation)
	}
	if manifest.Root.RootID != "root-a" ||
		manifest.Root.RootVersion != 1 ||
		manifest.Root.MMTemplateID != "template-a" ||
		manifest.Root.PageMapID != "page-map-a" ||
		manifest.Root.PageMapVersion != 1 {
		t.Fatalf("cross-language root graph literals drifted: %#v", manifest.Root)
	}
	expectedRuns := []PublicationPageRun{
		{
			FirstPage: PageID{
				OwnerID:            "owner-a",
				DeviceUUID:         "device-a",
				AllocationRecordID: 42,
				DataPageIndex:      107,
			},
			PageCount: 1,
		},
		{
			FirstPage: PageID{
				OwnerID:            "owner-a",
				DeviceUUID:         "device-b",
				AllocationRecordID: 42,
				DataPageIndex:      200,
			},
			PageCount: 1,
		},
	}
	if got := fixturePageRuns(manifest); !reflect.DeepEqual(got, expectedRuns) {
		t.Fatalf("cross-language PageID run literals = %#v, want %#v", got, expectedRuns)
	}
}

func fixtureDevices(manifest crossLanguageFixtureData) []Device {
	devices := make([]Device, len(manifest.DeviceTable))
	for index, device := range manifest.DeviceTable {
		devices[index] = Device{
			DeviceUUID:    device.DeviceUUID,
			OwnerID:       device.OwnerID,
			OwnerEpoch:    device.OwnerEpoch,
			DataPageCount: device.DataPageCount,
		}
	}
	return devices
}

func fixtureAllocationExtents(manifest crossLanguageFixtureData) []AllocationExtent {
	extents := make([]AllocationExtent, len(manifest.InitialAllocation.Extents))
	for index, extent := range manifest.InitialAllocation.Extents {
		extents[index] = AllocationExtent{
			DeviceUUID:         extent.DeviceUUID,
			StartDataPageIndex: extent.StartDataPageIndex,
			PageCount:          extent.PageCount,
			LogicalPageStart:   extent.LogicalPageStart,
		}
	}
	return extents
}

func fixturePageRuns(manifest crossLanguageFixtureData) []PublicationPageRun {
	runs := make([]PublicationPageRun, len(manifest.PageRuns))
	for index, run := range manifest.PageRuns {
		runs[index] = PublicationPageRun{
			FirstPage: PageID{
				OwnerID:            run.FirstPage.OwnerID,
				DeviceUUID:         run.FirstPage.DeviceUUID,
				AllocationRecordID: run.FirstPage.AllocationRecordID,
				DataPageIndex:      run.FirstPage.DataPageIndex,
			},
			PageCount: run.PageCount,
		}
	}
	return runs
}

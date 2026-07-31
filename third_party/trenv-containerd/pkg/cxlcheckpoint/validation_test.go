package cxlcheckpoint

import "testing"

func TestAllocationAndContentCoverageRejectsGapsOverlapsAndOverflow(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*Publication)
	}{
		{
			name: "extent logical gap",
			mutate: func(p *Publication) {
				p.Allocation.Extents[1].LogicalPageStart = 5
			},
		},
		{
			name: "extent logical overlap",
			mutate: func(p *Publication) {
				p.Allocation.Extents[1].LogicalPageStart = 3
			},
		},
		{
			name: "extent physical overlap",
			mutate: func(p *Publication) {
				p.Allocation.Extents[1].DeviceUUID = "device-a"
				p.Allocation.Extents[1].StartDataPageIndex = 102
			},
		},
		{
			name: "extent outside device",
			mutate: func(p *Publication) {
				p.Allocation.Extents[1].StartDataPageIndex = 1023
			},
		},
		{
			name: "unknown extent device",
			mutate: func(p *Publication) {
				p.Allocation.Extents[1].DeviceUUID = "device-missing"
			},
		},
		{
			name: "content logical gap",
			mutate: func(p *Publication) {
				p.ContentObjects[1].LogicalPageStart = 3
			},
		},
		{
			name: "content logical overlap",
			mutate: func(p *Publication) {
				p.ContentObjects[1].LogicalPageStart = 1
			},
		},
		{
			name: "content exceeds capacity",
			mutate: func(p *Publication) {
				p.ContentObjects[1].ByteLength = PageSize + 1
			},
		},
		{
			name: "memory page is partial",
			mutate: func(p *Publication) {
				p.ContentObjects[0].ByteLength--
			},
		},
		{
			name: "allocation total differs",
			mutate: func(p *Publication) {
				p.Allocation.TotalPages++
			},
		},
		{
			name: "unknown content kind",
			mutate: func(p *Publication) {
				p.ContentObjects[5].Kind = ContentKind(255)
			},
		},
		{
			name: "duplicate content ID",
			mutate: func(p *Publication) {
				p.ContentObjects[1].ObjectID = p.ContentObjects[0].ObjectID
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			publication := validPublication(t)
			test.mutate(&publication)
			requireInvalid(t, publication)
		})
	}
}

func TestDeviceTableIsStableUniqueAndSorted(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*Publication)
	}{
		{
			name: "unsorted",
			mutate: func(p *Publication) {
				p.Devices[0], p.Devices[1] = p.Devices[1], p.Devices[0]
			},
		},
		{
			name: "duplicate UUID",
			mutate: func(p *Publication) {
				p.Devices[1].DeviceUUID = p.Devices[0].DeviceUUID
			},
		},
		{
			name: "zero owner epoch",
			mutate: func(p *Publication) {
				p.Devices[0].OwnerEpoch = 0
			},
		},
		{
			name: "zero capacity",
			mutate: func(p *Publication) {
				p.Devices[0].DataPageCount = 0
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			publication := validPublication(t)
			test.mutate(&publication)
			requireInvalid(t, publication)
		})
	}
}

func TestMMTemplateAndPageMapAreCompleteAndPortable(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*Publication)
	}{
		{
			name: "unaligned VMA",
			mutate: func(p *Publication) {
				p.MMTemplate.VMAs[0].StartVAddr++
			},
		},
		{
			name: "overlapping VMAs",
			mutate: func(p *Publication) {
				p.MMTemplate.VMAs[1].StartVAddr = 0x2000
			},
		},
		{
			name: "unknown protection",
			mutate: func(p *Publication) {
				p.MMTemplate.VMAs[0].ProtectionFlags |= 1 << 20
			},
		},
		{
			name: "unknown mapping flag",
			mutate: func(p *Publication) {
				p.MMTemplate.VMAs[0].MappingFlags |= 1 << 20
			},
		},
		{
			name: "both private and shared",
			mutate: func(p *Publication) {
				p.MMTemplate.VMAs[0].MappingFlags |= MappingShared
			},
		},
		{
			name: "neither private nor shared",
			mutate: func(p *Publication) {
				p.MMTemplate.VMAs[0].MappingFlags = MappingAnonymous
			},
		},
		{
			name: "unknown backing",
			mutate: func(p *Publication) {
				p.MMTemplate.VMAs[0].BackingKind = BackingKind(255)
			},
		},
		{
			name: "anonymous backing without anonymous flag",
			mutate: func(p *Publication) {
				p.MMTemplate.VMAs[0].MappingFlags = MappingPrivate
			},
		},
		{
			name: "artifact backing with anonymous flag",
			mutate: func(p *Publication) {
				p.MMTemplate.VMAs[1].MappingFlags |= MappingAnonymous
			},
		},
		{
			name: "VMA PageMap slice gap",
			mutate: func(p *Publication) {
				p.MMTemplate.VMAs[1].PageMapRunStart = 2
			},
		},
		{
			name: "VMA mapping not exactly covered",
			mutate: func(p *Publication) {
				p.MMTemplate.VMAs[0].EndVAddr = 0x4000
			},
		},
		{
			name: "PageMap virtual gap inside VMA",
			mutate: func(p *Publication) {
				p.PageMap.Runs[0].StartVAddr = 0x2000
			},
		},
		{
			name: "unconsumed PageMap run",
			mutate: func(p *Publication) {
				p.PageMap.Runs = append(p.PageMap.Runs, PageMapRun{
					StartVAddr: 0x6000,
					PageCount:  1,
					FirstPage: PageID{
						OwnerID:            "owner-b",
						DeviceUUID:         "device-c",
						AllocationRecordID: 99,
						DataPageIndex:      51,
					},
				})
			},
		},
		{
			name: "PageMap run overlap",
			mutate: func(p *Publication) {
				p.PageMap.Runs[1].StartVAddr = 0x2000
			},
		},
		{
			name: "zero PageMap run",
			mutate: func(p *Publication) {
				p.PageMap.Runs[0].PageCount = 0
			},
		},
		{
			name: "unknown PageID device",
			mutate: func(p *Publication) {
				p.PageMap.Runs[1].FirstPage.DeviceUUID = "device-missing"
			},
		},
		{
			name: "PageID exceeds device",
			mutate: func(p *Publication) {
				p.PageMap.Runs[1].FirstPage.DataPageIndex = 1024
			},
		},
		{
			name: "PageMap wrong page size",
			mutate: func(p *Publication) {
				p.PageMap.PageSize = 8192
			},
		},
		{
			name: "MM template wrong page size",
			mutate: func(p *Publication) {
				p.MMTemplate.PageSize = 8192
			},
		},
		{
			name: "PageMap zero version",
			mutate: func(p *Publication) {
				p.PageMap.Version = 0
				p.Root.PageMapVersion = 0
			},
		},
		{
			name: "MM template wrong content kind",
			mutate: func(p *Publication) {
				p.MMTemplate.ContentObjectID = 2
			},
		},
		{
			name: "PageMap wrong content kind",
			mutate: func(p *Publication) {
				p.PageMap.ContentObjectID = 6
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			publication := validPublication(t)
			test.mutate(&publication)
			requireInvalid(t, publication)
		})
	}
}

func TestArtifactMetadataAndExactByteRanges(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*Publication)
	}{
		{
			name: "range beyond exact object length",
			mutate: func(p *Publication) {
				p.Artifacts.Entries[1].ByteLength = 6
			},
		},
		{
			name: "offset beyond exact object length",
			mutate: func(p *Publication) {
				p.Artifacts.Entries[1].ContentOffset = 1
			},
		},
		{
			name: "wrong content kind",
			mutate: func(p *Publication) {
				p.Artifacts.Entries[1].ContentObjectID = 1
			},
		},
		{
			name: "absolute path",
			mutate: func(p *Publication) {
				p.Artifacts.Entries[1].Path = "/bin/action"
			},
		},
		{
			name: "path traversal",
			mutate: func(p *Publication) {
				p.Artifacts.Entries[1].Path = "../action"
			},
		},
		{
			name: "unsorted entries",
			mutate: func(p *Publication) {
				p.Artifacts.Entries[0], p.Artifacts.Entries[1] = p.Artifacts.Entries[1], p.Artifacts.Entries[0]
			},
		},
		{
			name: "unknown artifact type",
			mutate: func(p *Publication) {
				p.Artifacts.Entries[1].Type = ArtifactType(255)
			},
		},
		{
			name: "directory with bytes",
			mutate: func(p *Publication) {
				p.Artifacts.Entries[0].ByteLength = 1
			},
		},
		{
			name: "symlink without target",
			mutate: func(p *Publication) {
				p.Artifacts.Entries[2].LinkTarget = ""
			},
		},
		{
			name: "regular file with link target",
			mutate: func(p *Publication) {
				p.Artifacts.Entries[1].LinkTarget = "other"
			},
		},
		{
			name: "empty file with content reference",
			mutate: func(p *Publication) {
				p.Artifacts.Entries[1].ByteLength = 0
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			publication := validPublication(t)
			test.mutate(&publication)
			requireInvalid(t, publication)
		})
	}
}

func TestCommittedRootBindsPublicationGraph(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*Publication)
	}{
		{
			name: "not committed",
			mutate: func(p *Publication) {
				p.Root.State = RootState(0)
			},
		},
		{
			name: "checkpoint mismatch",
			mutate: func(p *Publication) {
				p.Root.CheckpointID = "checkpoint-other"
			},
		},
		{
			name: "owner mismatch",
			mutate: func(p *Publication) {
				p.Root.OwnerID = "owner-b"
			},
		},
		{
			name: "allocation mismatch",
			mutate: func(p *Publication) {
				p.Root.AllocationRecordID++
			},
		},
		{
			name: "MM template mismatch",
			mutate: func(p *Publication) {
				p.Root.MMTemplateID = "template-other"
			},
		},
		{
			name: "PageMap mismatch",
			mutate: func(p *Publication) {
				p.Root.PageMapID = "page-map-other"
			},
		},
		{
			name: "PageMap version mismatch",
			mutate: func(p *Publication) {
				p.Root.PageMapVersion++
			},
		},
		{
			name: "artifact manifest mismatch",
			mutate: func(p *Publication) {
				p.Root.ArtifactManifestID = "artifacts-other"
			},
		},
		{
			name: "device digest mismatch",
			mutate: func(p *Publication) {
				p.Root.DeviceTableDigest[0] ^= 1
			},
		},
		{
			name: "zero publication sequence",
			mutate: func(p *Publication) {
				p.Root.PublicationSequence = 0
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			publication := validPublication(t)
			test.mutate(&publication)
			requireInvalid(t, publication)
		})
	}
}

func TestDecodeRejectsChecksummedUnknownPayloadValues(t *testing.T) {
	publication := validPublication(t)
	publication.ContentObjects[5].Kind = ContentKind(255)
	payload, err := marshalPayload(publication)
	if err != nil {
		t.Fatalf("marshal structurally encodable payload: %v", err)
	}
	encoded, err := marshalEnvelope(payload)
	if err != nil {
		t.Fatalf("marshal envelope: %v", err)
	}
	requireDecodeError(t, encoded, ErrInvalid)
}

func TestDecoderCollectionMinimumsMatchWireRecords(t *testing.T) {
	for _, test := range []struct {
		name    string
		minimum int
	}{
		{name: "VMA", minimum: 49},
		{name: "artifact", minimum: 57},
	} {
		t.Run(test.name, func(t *testing.T) {
			payload := make([]byte, 4+test.minimum)
			payload[0] = 1 // little-endian count of one
			decoder := newPayloadDecoder(payload)
			count, err := decoder.count(test.name, test.minimum)
			if err != nil {
				t.Fatalf("count rejected exact minimum: %v", err)
			}
			if count != 1 {
				t.Fatalf("count = %d, want 1", count)
			}
		})
	}
}

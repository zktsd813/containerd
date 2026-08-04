package trcxl007

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"hash/crc32"
	"io"
	"reflect"
	"strings"
	"testing"

	"github.com/containerd/containerd/third_party/trenv-containerd/pkg/cxlcheckpoint"
)

func TestOwnerSealTranscriptIndependentByteKnownAnswerAndVerifications(t *testing.T) {
	fixture := newProducerScatterTestFixture(t)
	plan := ownerSealPlanTestBuild(t, fixture)
	pages := ownerSealTranscriptTestPages(t, fixture, plan)
	transcript, err := NewOwnerSealTranscript(plan)
	if err != nil {
		t.Fatalf("NewOwnerSealTranscript: %v", err)
	}

	for logical := uint64(0); logical < plan.TotalPages(); logical++ {
		first, err := transcript.NextPageTarget()
		if err != nil {
			t.Fatalf("NextPageTarget(%d): %v", logical, err)
		}
		repeated, err := transcript.NextPageTarget()
		if err != nil || repeated != first || first.LogicalPage() != logical {
			t.Fatalf("repeated target(%d) = %#v/%#v / %v", logical, first, repeated, err)
		}
		crc := ownerSealTranscriptTestCRC32C(pages[logical])
		verification, err := transcript.AppendOwnerRereadPage(pages[logical], crc)
		if err != nil {
			t.Fatalf("AppendOwnerRereadPage(%d): %v", logical, err)
		}
		wantDescriptor, err := first.TargetDescriptor(crc)
		if err != nil {
			t.Fatalf("TargetDescriptor(%d): %v", logical, err)
		}
		if verification.Target() != first || verification.Descriptor() != wantDescriptor {
			t.Fatalf("verification(%d) = %#v, want target %#v descriptor %#v",
				logical, verification, first, wantDescriptor)
		}
	}
	if _, err := transcript.NextPageTarget(); !errors.Is(err, io.EOF) {
		t.Fatalf("terminal NextPageTarget error = %v, want io.EOF", err)
	}
	seal, err := transcript.Finish()
	if err != nil {
		t.Fatalf("Finish: %v", err)
	}
	if err := seal.Validate(plan); err != nil {
		t.Fatalf("seal.Validate: %v", err)
	}
	if seal.PlanIntegritySHA256() != plan.IntegritySHA256() {
		t.Fatal("seal did not retain the exact local plan binding")
	}

	reference, preimageLength := ownerSealTranscriptTestReference(t, plan, pages, nil)
	if seal.SHA256() != reference {
		t.Fatalf("seal = %x, independent reference = %x", seal.SHA256(), reference)
	}
	const knownPreimageLength = 72914
	if preimageLength != knownPreimageLength {
		t.Fatalf("known-answer preimage length = %d, want %d",
			preimageLength, knownPreimageLength)
	}
	const knownSHA256 = "609da5bc6a04366dd5fa2c1dd7969ca1cb90c8011b52621801bcf6937ac8f018"
	if got := ownerSealTranscriptTestHex(reference); got != knownSHA256 {
		t.Fatalf("known-answer SHA-256 = %s (preimage bytes %d), want %s",
			got, preimageLength, knownSHA256)
	}
	if OwnerVerifiedSealTranscriptDomain != "TRCXL007-owner-verified-seal-transcript-v1" ||
		OwnerVerifiedSealTranscriptVersion != 1 {
		t.Fatalf("transcript domain/version = %q/%d",
			OwnerVerifiedSealTranscriptDomain, OwnerVerifiedSealTranscriptVersion)
	}

	if _, err := transcript.Finish(); !errors.Is(err, ErrInvalidOwnerSealTranscript) {
		t.Fatalf("repeated Finish error = %v", err)
	}
}

func TestOwnerSealTranscriptRejectsWrongScratchLengthsTerminally(t *testing.T) {
	fixture := newProducerScatterTestFixture(t)
	plan := ownerSealPlanTestBuild(t, fixture)
	pages := ownerSealTranscriptTestPages(t, fixture, plan)
	for _, length := range []int{ContentPageBytes - 1, ContentPageBytes + 1} {
		t.Run(ownerSealTranscriptTestLengthName(length), func(t *testing.T) {
			transcript := ownerSealTranscriptTestNew(t, plan)
			verification, err := transcript.AppendOwnerRereadPage(make([]byte, length), 0)
			if !errors.Is(err, ErrInvalidOwnerSealTranscript) ||
				verification != (OwnerSealPageVerification{}) {
				t.Fatalf("wrong-length append = %#v / %v", verification, err)
			}
			terminal := err
			if _, err := transcript.AppendOwnerRereadPage(
				pages[0], ownerSealTranscriptTestCRC32C(pages[0])); err != terminal {
				t.Fatalf("terminal retry error = %v, want identical %v", err, terminal)
			}
			if _, err := transcript.Finish(); err != terminal {
				t.Fatalf("terminal Finish error = %v, want identical %v", err, terminal)
			}
		})
	}
}

func TestOwnerSealTranscriptRejectsNonzeroTailZeroPageAndControlMismatch(t *testing.T) {
	fixture := newProducerScatterTestFixture(t)
	plan := ownerSealPlanTestBuild(t, fixture)
	basePages := ownerSealTranscriptTestPages(t, fixture, plan)
	targets := ownerSealTranscriptTestTargets(t, plan)

	t.Run("nonzero-tail", func(t *testing.T) {
		logical := ownerSealTranscriptTestFindTarget(t, targets, func(target OwnerSealPageTarget) bool {
			return target.MeaningfulByteLength() > 0 &&
				target.MeaningfulByteLength() < uint32(ContentPageBytes) &&
				!target.Object().ExactSHA256Required
		})
		pages := ownerSealTranscriptTestClonePages(basePages)
		pages[logical][targets[logical].MeaningfulByteLength()] = 0xa5
		transcript := ownerSealTranscriptTestNew(t, plan)
		ownerSealTranscriptTestAppendPrefix(t, transcript, pages, logical)
		_, err := transcript.AppendOwnerRereadPage(
			pages[logical], ownerSealTranscriptTestCRC32C(pages[logical]))
		if !errors.Is(err, ErrInvalidOwnerSealTranscript) ||
			!strings.Contains(err.Error(), "nonzero bytes") {
			t.Fatalf("nonzero-tail error = %v", err)
		}
	})

	for _, test := range []struct {
		name  string
		state DescriptorState
	}{
		{name: "empty-slot", state: DescriptorEmptySlot},
		{name: "publication-zero-padding", state: DescriptorZeroPadding},
	} {
		t.Run(test.name, func(t *testing.T) {
			logical := ownerSealTranscriptTestFindTarget(t, targets, func(target OwnerSealPageTarget) bool {
				return target.TargetState() == test.state
			})
			pages := ownerSealTranscriptTestClonePages(basePages)
			pages[logical][17] = 1
			transcript := ownerSealTranscriptTestNew(t, plan)
			ownerSealTranscriptTestAppendPrefix(t, transcript, pages, logical)
			// Keep the DML scalar at the canonical zero-page value so the explicit
			// scratch zero check, rather than TargetDescriptor, catches corruption.
			_, err := transcript.AppendOwnerRereadPage(pages[logical], zeroContentPageCRC32C)
			if !errors.Is(err, ErrInvalidOwnerSealTranscript) ||
				!strings.Contains(err.Error(), "nonzero bytes") {
				t.Fatalf("nonzero full-zero page error = %v", err)
			}
		})
	}

	t.Run("typed-control-sha", func(t *testing.T) {
		logical := ownerSealTranscriptTestFindTarget(t, targets, func(target OwnerSealPageTarget) bool {
			return target.Object().ExactSHA256Required && target.MeaningfulByteLength() > 0
		})
		pages := ownerSealTranscriptTestClonePages(basePages)
		pages[logical][0] ^= 0x80
		transcript := ownerSealTranscriptTestNew(t, plan)
		var mismatch error
		for index := uint64(0); index < plan.TotalPages(); index++ {
			_, appendErr := transcript.AppendOwnerRereadPage(
				pages[index], ownerSealTranscriptTestCRC32C(pages[index]))
			if appendErr != nil {
				mismatch = appendErr
				break
			}
		}
		if !errors.Is(mismatch, ErrInvalidOwnerSealTranscript) ||
			!strings.Contains(mismatch.Error(), "meaningful-prefix SHA-256 differs") {
			t.Fatalf("typed-control mismatch error = %v", mismatch)
		}
	})
}

func TestOwnerSealTranscriptAllowsMeaningfulCRC32CZero(t *testing.T) {
	fixture := newProducerScatterTestFixture(t)
	plan := ownerSealPlanTestBuild(t, fixture)
	pages := ownerSealTranscriptTestPages(t, fixture, plan)
	transcript := ownerSealTranscriptTestNew(t, plan)
	for logical := uint64(0); logical < plan.TotalPages(); logical++ {
		crc := ownerSealTranscriptTestCRC32C(pages[logical])
		if logical == 0 {
			crc = 0
		}
		verification, err := transcript.AppendOwnerRereadPage(pages[logical], crc)
		if err != nil {
			t.Fatalf("AppendOwnerRereadPage(%d): %v", logical, err)
		}
		if logical == 0 && (verification.Descriptor().PaddedPageCRC32C != 0 ||
			verification.Descriptor().PayloadLength == 0) {
			t.Fatalf("meaningful zero-CRC descriptor = %#v", verification.Descriptor())
		}
	}
	if _, err := transcript.Finish(); err != nil {
		t.Fatalf("Finish meaningful zero CRC: %v", err)
	}
}

func TestOwnerSealTranscriptRejectsIncompleteAndExtraPages(t *testing.T) {
	fixture := newProducerScatterTestFixture(t)
	plan := ownerSealPlanTestBuild(t, fixture)
	pages := ownerSealTranscriptTestPages(t, fixture, plan)

	t.Run("incomplete", func(t *testing.T) {
		transcript := ownerSealTranscriptTestNew(t, plan)
		if _, err := transcript.AppendOwnerRereadPage(
			pages[0], ownerSealTranscriptTestCRC32C(pages[0])); err != nil {
			t.Fatalf("first append: %v", err)
		}
		_, err := transcript.Finish()
		if !errors.Is(err, ErrInvalidOwnerSealTranscript) ||
			!strings.Contains(err.Error(), "incomplete transcript") {
			t.Fatalf("incomplete Finish error = %v", err)
		}
		if _, retryErr := transcript.AppendOwnerRereadPage(
			pages[1], ownerSealTranscriptTestCRC32C(pages[1])); retryErr != err {
			t.Fatalf("append after incomplete Finish = %v, want identical %v", retryErr, err)
		}
	})

	t.Run("extra", func(t *testing.T) {
		transcript := ownerSealTranscriptTestNew(t, plan)
		ownerSealTranscriptTestAppendAll(t, transcript, pages, nil)
		verification, err := transcript.AppendOwnerRereadPage(make([]byte, ContentPageBytes), 0)
		if !errors.Is(err, ErrInvalidOwnerSealTranscript) ||
			verification != (OwnerSealPageVerification{}) ||
			!strings.Contains(err.Error(), "extra Owner reread page") {
			t.Fatalf("extra append = %#v / %v", verification, err)
		}
		if _, finishErr := transcript.Finish(); finishErr != err {
			t.Fatalf("Finish after extra page = %v, want identical %v", finishErr, err)
		}
	})

	method, found := reflect.TypeOf((*OwnerSealTranscript)(nil)).MethodByName("AppendOwnerRereadPage")
	if !found || method.Type.NumIn() != 3 || method.Type.In(1) != reflect.TypeOf([]byte{}) ||
		method.Type.In(2).Kind() != reflect.Uint32 || method.Type.NumOut() != 2 {
		t.Fatalf("AppendOwnerRereadPage signature permits page identity input: %v", method.Type)
	}
}

func TestOwnerSealTranscriptDetachesPlanScratchVerificationAndSeal(t *testing.T) {
	fixture := newProducerScatterTestFixture(t)
	plan := ownerSealPlanTestBuild(t, fixture)
	stablePlan := cloneOwnerSealPlan(plan)
	pages := ownerSealTranscriptTestPages(t, fixture, stablePlan)
	left := ownerSealTranscriptTestNew(t, plan)
	right := ownerSealTranscriptTestNew(t, stablePlan)

	plan.clusterID = "mutated-after-construction"
	plan.devices[0].DeviceUUID = "mutated-device"
	plan.objects[0].ObjectID = 999
	plan.runs[0].StartDataPageIndex = 999

	for logical := uint64(0); logical < stablePlan.TotalPages(); logical++ {
		scratch := append([]byte(nil), pages[logical]...)
		crc := ownerSealTranscriptTestCRC32C(scratch)
		verification, err := left.AppendOwnerRereadPage(scratch, crc)
		if err != nil {
			t.Fatalf("left append(%d): %v", logical, err)
		}
		scratch[0] ^= 0xff
		verification.target.logicalPage = 999
		verification.descriptor.OriginObjectID = 999
		if _, err := right.AppendOwnerRereadPage(pages[logical], crc); err != nil {
			t.Fatalf("right append(%d): %v", logical, err)
		}
	}
	leftSeal, err := left.Finish()
	if err != nil {
		t.Fatalf("left Finish: %v", err)
	}
	rightSeal, err := right.Finish()
	if err != nil {
		t.Fatalf("right Finish: %v", err)
	}
	if leftSeal != rightSeal {
		t.Fatalf("post-append mutation changed seal: %#v != %#v", leftSeal, rightSeal)
	}
	shaCopy := leftSeal.SHA256()
	planCopy := leftSeal.PlanIntegritySHA256()
	shaCopy[0] ^= 0xff
	planCopy[0] ^= 0xff
	if leftSeal.SHA256() != rightSeal.SHA256() ||
		leftSeal.PlanIntegritySHA256() != rightSeal.PlanIntegritySHA256() {
		t.Fatal("seal accessors alias opaque seal storage")
	}
	if err := leftSeal.Validate(stablePlan); err != nil {
		t.Fatalf("detached seal validation: %v", err)
	}
	mutatedPlan := cloneOwnerSealPlan(stablePlan)
	mutatedPlan.ownerSnapshotSequence++
	mutatedPlan.integritySHA256 = ownerSealPlanSHA256(mutatedPlan)
	if err := mutatedPlan.Validate(); err != nil {
		t.Fatalf("valid mutated plan fixture: %v", err)
	}
	if err := leftSeal.Validate(mutatedPlan); !errors.Is(err, ErrInvalidOwnerSealTranscript) {
		t.Fatalf("seal accepted different plan binding: %v", err)
	}
	if err := (OwnerVerifiedSeal{}).Validate(stablePlan); !errors.Is(err, ErrInvalidOwnerSealTranscript) {
		t.Fatalf("zero seal validation error = %v", err)
	}
}

func TestOwnerSealTranscriptExcludesOwnerSnapshotWrapperFromCanonicalSeal(t *testing.T) {
	fixture := newProducerScatterTestFixture(t)
	firstPlan := ownerSealPlanTestBuild(t, fixture)
	firstPages := ownerSealTranscriptTestPages(t, fixture, firstPlan)
	firstSeal := ownerSealTranscriptTestComplete(t, firstPlan, firstPages, nil)

	owner := fixture.owner.Clone()
	owner.SnapshotSequence++
	if err := owner.Validate(); err != nil {
		t.Fatalf("Owner state with later wrapper sequence: %v", err)
	}
	secondPlan, err := BuildFreshOwnerSealPlan(owner, 29, fixture.plan, fixture.initial)
	if err != nil {
		t.Fatalf("BuildFreshOwnerSealPlan later wrapper: %v", err)
	}
	secondSeal := ownerSealTranscriptTestComplete(t, secondPlan, firstPages, nil)
	if firstSeal.SHA256() != secondSeal.SHA256() {
		t.Fatal("Owner snapshot persistence wrapper leaked into canonical seal preimage")
	}
	if firstSeal.PlanIntegritySHA256() == secondSeal.PlanIntegritySHA256() {
		t.Fatal("local seal binding did not distinguish different fresh plans")
	}
}

func TestOwnerSealTranscriptRetainsOnlyCompactOrConstantState(t *testing.T) {
	typeOfTranscript := reflect.TypeOf(OwnerSealTranscript{})
	for index := 0; index < typeOfTranscript.NumField(); index++ {
		field := typeOfTranscript.Field(index)
		if field.Type.Kind() == reflect.Slice || field.Type == reflect.TypeOf([]byte{}) {
			t.Fatalf("transcript retains slice field %q (%s)", field.Name, field.Type)
		}
		lower := strings.ToLower(field.Name)
		if strings.Contains(lower, "crcvector") || strings.Contains(lower, "pagebytes") ||
			strings.Contains(lower, "pagetargets") {
			t.Fatalf("transcript retains per-page-looking field %q", field.Name)
		}
	}
	verificationType := reflect.TypeOf(OwnerSealPageVerification{})
	for index := 0; index < verificationType.NumField(); index++ {
		if verificationType.Field(index).Type.Kind() == reflect.Slice {
			t.Fatalf("page verification retains slice field %q", verificationType.Field(index).Name)
		}
	}
}

func ownerSealTranscriptTestNew(t *testing.T, plan OwnerSealPlan) *OwnerSealTranscript {
	t.Helper()
	transcript, err := NewOwnerSealTranscript(plan)
	if err != nil {
		t.Fatalf("NewOwnerSealTranscript: %v", err)
	}
	return transcript
}

func ownerSealTranscriptTestComplete(
	t *testing.T,
	plan OwnerSealPlan,
	pages [][]byte,
	crcOverride map[uint64]uint32,
) OwnerVerifiedSeal {
	t.Helper()
	transcript := ownerSealTranscriptTestNew(t, plan)
	ownerSealTranscriptTestAppendAll(t, transcript, pages, crcOverride)
	seal, err := transcript.Finish()
	if err != nil {
		t.Fatalf("Finish: %v", err)
	}
	return seal
}

func ownerSealTranscriptTestAppendAll(
	t *testing.T,
	transcript *OwnerSealTranscript,
	pages [][]byte,
	crcOverride map[uint64]uint32,
) {
	t.Helper()
	for logical := range pages {
		crc := ownerSealTranscriptTestCRC32C(pages[logical])
		if override, found := crcOverride[uint64(logical)]; found {
			crc = override
		}
		if _, err := transcript.AppendOwnerRereadPage(pages[logical], crc); err != nil {
			t.Fatalf("AppendOwnerRereadPage(%d): %v", logical, err)
		}
	}
}

func ownerSealTranscriptTestAppendPrefix(
	t *testing.T,
	transcript *OwnerSealTranscript,
	pages [][]byte,
	stop uint64,
) {
	t.Helper()
	for logical := uint64(0); logical < stop; logical++ {
		if _, err := transcript.AppendOwnerRereadPage(
			pages[logical], ownerSealTranscriptTestCRC32C(pages[logical])); err != nil {
			t.Fatalf("append prefix page %d: %v", logical, err)
		}
	}
}

func ownerSealTranscriptTestPages(
	t *testing.T,
	fixture producerScatterTestFixture,
	plan OwnerSealPlan,
) [][]byte {
	t.Helper()
	pages := make([][]byte, int(plan.TotalPages()))
	writes := fixture.initial.ObjectWrites
	if len(writes) != len(plan.Objects()) {
		t.Fatalf("initial writes %d, plan objects %d", len(writes), len(plan.Objects()))
	}
	for _, write := range writes {
		var source []byte
		switch write.WriteSource {
		case cxlcheckpoint.InitialPublicationV7ExternalPayload:
			switch write.Kind {
			case cxlcheckpoint.ContentMemoryPayloadV7:
				source = fixture.memory
			case cxlcheckpoint.ContentArtifactPayloadV7:
				source = fixture.artifact
			case cxlcheckpoint.ContentRestoreBlobPayloadV7:
				source = fixture.restoreBlob
			default:
				t.Fatalf("unexpected external kind %d", write.Kind)
			}
		case cxlcheckpoint.InitialPublicationV7CanonicalControlBytes:
			source = write.CanonicalBytes
		case cxlcheckpoint.InitialPublicationV7NeverPublishedZeroSlot:
			source = nil
		default:
			t.Fatalf("unknown write source %d", write.WriteSource)
		}
		if uint64(len(source)) != write.ExactByteLength {
			t.Fatalf("object %d source length %d, want %d",
				write.ObjectID, len(source), write.ExactByteLength)
		}
		for objectPage := uint64(0); objectPage < write.CapacityPages; objectPage++ {
			logical := write.LogicalPageStart + objectPage
			page := make([]byte, ContentPageBytes)
			start := objectPage * uint64(ContentPageBytes)
			if start < uint64(len(source)) {
				end := start + uint64(ContentPageBytes)
				if end > uint64(len(source)) {
					end = uint64(len(source))
				}
				copy(page, source[int(start):int(end)])
			}
			pages[int(logical)] = page
		}
	}
	for logical, page := range pages {
		if len(page) != ContentPageBytes {
			t.Fatalf("logical page %d was not materialized", logical)
		}
	}
	return pages
}

func ownerSealTranscriptTestTargets(t *testing.T, plan OwnerSealPlan) []OwnerSealPageTarget {
	t.Helper()
	iterator, err := plan.PageIterator()
	if err != nil {
		t.Fatalf("PageIterator: %v", err)
	}
	targets := make([]OwnerSealPageTarget, int(plan.TotalPages()))
	for logical := range targets {
		target, err := iterator.Next()
		if err != nil {
			t.Fatalf("Next(%d): %v", logical, err)
		}
		targets[logical] = target
	}
	return targets
}

func ownerSealTranscriptTestFindTarget(
	t *testing.T,
	targets []OwnerSealPageTarget,
	predicate func(OwnerSealPageTarget) bool,
) uint64 {
	t.Helper()
	for logical, target := range targets {
		if predicate(target) {
			return uint64(logical)
		}
	}
	t.Fatal("required page target was absent")
	return 0
}

func ownerSealTranscriptTestClonePages(source [][]byte) [][]byte {
	result := make([][]byte, len(source))
	for index := range source {
		result[index] = append([]byte(nil), source[index]...)
	}
	return result
}

func ownerSealTranscriptTestCRC32C(page []byte) uint32 {
	return crc32.Checksum(page, crc32.MakeTable(crc32.Castagnoli))
}

// ownerSealTranscriptTestReference is deliberately independent of the
// production prefix/page/finish writer helpers. It spells every byte in the
// frozen order and is paired with a hard-coded final SHA-256 known answer.
func ownerSealTranscriptTestReference(
	t *testing.T,
	plan OwnerSealPlan,
	pages [][]byte,
	crcOverride map[uint64]uint32,
) ([sha256.Size]byte, int) {
	t.Helper()
	var preimage bytes.Buffer
	refString := func(value string) {
		var scalar [8]byte
		binary.LittleEndian.PutUint64(scalar[:], uint64(len(value)))
		preimage.Write(scalar[:])
		preimage.WriteString(value)
	}
	refU64 := func(value uint64) {
		var scalar [8]byte
		binary.LittleEndian.PutUint64(scalar[:], value)
		preimage.Write(scalar[:])
	}
	refU32 := func(value uint32) {
		var scalar [4]byte
		binary.LittleEndian.PutUint32(scalar[:], value)
		preimage.Write(scalar[:])
	}

	refString("TRCXL007-owner-verified-seal-transcript-v1")
	refU32(1)
	refString(plan.StorageCompatibilityID())
	refU64(4096)
	refU64(64)
	refString(plan.ClusterID())
	refString(plan.OwnerGroupID())
	refString(plan.OwnerID())
	refString(plan.AnchorDeviceUUID())
	refU64(plan.OwnerEpoch())
	refU64(plan.GroupConfigurationSequence())
	membership := plan.MembershipSHA256()
	preimage.Write(membership[:])
	refString(plan.RequestID())
	refString(plan.CheckpointID())
	refString(plan.ProducerID())
	refString(plan.DedupDomainID())
	refString(plan.SharingPolicyID())
	refU64(plan.AllocationRecordID())
	refU64(plan.ReservationTransactionSequence())
	refU64(plan.SealTransactionSequence())
	for _, digest := range [][sha256.Size]byte{
		plan.RequestSHA256(),
		plan.GrantRecordSHA256(),
		plan.SchedulerReserveSHA256(),
		plan.ProducerCapabilitySHA256(),
		plan.PublicationAuthoritySHA256(),
		plan.ReclaimAuthoritySHA256(),
	} {
		preimage.Write(digest[:])
	}
	refU64(plan.TotalPages())
	devices := plan.Devices()
	refU64(uint64(len(devices)))
	for _, device := range devices {
		refString(device.DeviceUUID)
		refU64(device.DeviceOwnerEpoch)
		refU64(device.DataPageCount)
		preimage.Write(device.DeviceBindingSHA256[:])
	}
	objects := plan.Objects()
	refU64(uint64(len(objects)))
	for _, object := range objects {
		refU64(object.ObjectID)
		preimage.WriteByte(byte(object.Kind))
		refU64(object.LogicalPageStart)
		refU64(object.ExactByteLength)
		refU64(object.CapacityPages)
		if object.ExactSHA256Required {
			preimage.WriteByte(1)
		} else {
			preimage.WriteByte(0)
		}
		preimage.Write(object.ExactSHA256[:])
	}
	runs := plan.ExtentRuns()
	refU64(uint64(len(runs)))
	for _, run := range runs {
		refU32(run.DeviceIndex)
		refU64(run.StartDataPageIndex)
		refU64(run.LogicalPageStart)
		refU64(run.PageCount)
	}

	iterator, err := plan.PageIterator()
	if err != nil {
		t.Fatalf("reference PageIterator: %v", err)
	}
	for logical := uint64(0); logical < plan.TotalPages(); logical++ {
		target, err := iterator.Next()
		if err != nil {
			t.Fatalf("reference Next(%d): %v", logical, err)
		}
		crc := ownerSealTranscriptTestCRC32C(pages[logical])
		if override, found := crcOverride[logical]; found {
			crc = override
		}
		descriptor, err := target.TargetDescriptor(crc)
		if err != nil {
			t.Fatalf("reference TargetDescriptor(%d): %v", logical, err)
		}
		wire, err := descriptor.MarshalBinary()
		if err != nil {
			t.Fatalf("reference descriptor wire(%d): %v", logical, err)
		}
		preimage.WriteByte(0x50)
		refU64(logical)
		refU64(target.ObjectPage())
		refU32(target.DeviceIndex())
		refU64(target.DataPageIndex())
		preimage.Write(wire)
		preimage.Write(pages[logical])
	}
	preimage.WriteByte(0xff)
	refU64(plan.TotalPages())
	return sha256.Sum256(preimage.Bytes()), preimage.Len()
}

func ownerSealTranscriptTestHex(value [sha256.Size]byte) string {
	const digits = "0123456789abcdef"
	result := make([]byte, sha256.Size*2)
	for index, current := range value {
		result[index*2] = digits[current>>4]
		result[index*2+1] = digits[current&0x0f]
	}
	return string(result)
}

func ownerSealTranscriptTestLengthName(length int) string {
	if length < ContentPageBytes {
		return "4095"
	}
	return "4097"
}

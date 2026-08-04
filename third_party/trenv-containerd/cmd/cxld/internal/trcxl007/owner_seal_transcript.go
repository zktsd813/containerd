package trcxl007

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"io"
)

const (
	// OwnerVerifiedSealTranscriptDomain identifies the canonical checkpoint-wide
	// Owner reread transcript. Unlike the process-local fresh plan, every prefix
	// field can be reconstructed from durable V7 media during forward recovery.
	OwnerVerifiedSealTranscriptDomain         = "TRCXL007-owner-verified-seal-transcript-v1"
	OwnerVerifiedSealTranscriptVersion uint32 = 1

	ownerSealPageFrameTag   byte = 0x50
	ownerSealFinishFrameTag byte = 0xff
)

var (
	// ErrInvalidOwnerSealTranscript identifies a mutated plan, an out-of-order
	// lifecycle call, an invalid Owner DML result, nonzero padding, typed-control
	// corruption, or an incomplete/extra transcript. Any Append failure is
	// terminal: callers must not reuse a partial digest.
	ErrInvalidOwnerSealTranscript = errors.New("invalid TRCXL007 Owner seal transcript")
)

// OwnerVerifiedSeal is the opaque, checkpoint-level result of one complete
// Owner reread transcript. It is a recovery/audit commitment, not a bearer
// capability and not proof that COMMITTING or descriptor persistence occurred.
type OwnerVerifiedSeal struct {
	sha256              [sha256.Size]byte
	planIntegritySHA256 [sha256.Size]byte
}

// SHA256 returns the detached digest value. Mutating the returned array cannot
// alter the opaque seal.
func (seal OwnerVerifiedSeal) SHA256() [sha256.Size]byte { return seal.sha256 }

// PlanIntegritySHA256 returns the detached compact-plan binding captured when
// the transcript was created. This value is not part of the seal preimage; it
// prevents a locally returned seal from being applied to another plan. The
// plan commitment itself is process-local and need not be reconstructed from
// media to recompute the canonical seal SHA-256.
func (seal OwnerVerifiedSeal) PlanIntegritySHA256() [sha256.Size]byte {
	return seal.planIntegritySHA256
}

// Validate binds an opaque seal to one exact compact plan. There is
// intentionally no exported constructor for OwnerVerifiedSeal.
func (seal OwnerVerifiedSeal) Validate(plan OwnerSealPlan) error {
	if err := plan.Validate(); err != nil {
		return ownerSealTranscriptInvalidf("seal plan: %v", err)
	}
	if seal.sha256 == ([sha256.Size]byte{}) {
		return ownerSealTranscriptInvalidf("Owner-verified seal SHA-256 is zero")
	}
	if seal.planIntegritySHA256 == ([sha256.Size]byte{}) ||
		seal.planIntegritySHA256 != plan.IntegritySHA256() {
		return ownerSealTranscriptInvalidf("Owner-verified seal plan binding differs")
	}
	return nil
}

// OwnerSealPageVerification is the detached result of one successful append.
// The executor can persist the exact returned descriptor at the exact returned
// target without independently rebuilding either value.
type OwnerSealPageVerification struct {
	target     OwnerSealPageTarget
	descriptor Descriptor
}

// Target returns the internally selected, detached page target.
func (verification OwnerSealPageVerification) Target() OwnerSealPageTarget {
	return verification.target
}

// Descriptor returns the exact target descriptor committed by this page frame.
func (verification OwnerSealPageVerification) Descriptor() Descriptor {
	return verification.descriptor
}

// OwnerSealTranscript incrementally hashes one compact plan and exactly one
// 4 KiB Owner reread for each logical capacity page. It retains no page bytes,
// per-page target table, or CRC vector. The owned iterator and plan use
// O(devices+objects+extents) memory, plus one constant-size current target and
// one SHA-256 state for a typed control object's meaningful prefix.
type OwnerSealTranscript struct {
	plan     OwnerSealPlan
	iterator OwnerSealPageIterator
	digest   hash.Hash

	pendingTarget    OwnerSealPageTarget
	pendingTargetSet bool
	pagesAppended    uint64

	exactObjectID    uint64
	exactBytesHashed uint64
	exactDigest      hash.Hash

	finished    bool
	terminalErr error
}

// NewOwnerSealTranscript validates and detaches one compact plan and emits its
// canonical prefix into a new SHA-256 state. It performs no storage, DML,
// descriptor, Owner-state, network, or runtime I/O.
func NewOwnerSealTranscript(plan OwnerSealPlan) (*OwnerSealTranscript, error) {
	if err := plan.Validate(); err != nil {
		return nil, ownerSealTranscriptInvalidf("plan: %v", err)
	}
	iterator, err := plan.PageIterator()
	if err != nil {
		return nil, ownerSealTranscriptInvalidf("page iterator: %v", err)
	}
	detached := cloneOwnerSealPlan(plan)
	transcript := &OwnerSealTranscript{
		plan:     detached,
		iterator: iterator,
		digest:   sha256.New(),
	}
	if err := writeOwnerSealTranscriptPrefix(transcript.digest, detached); err != nil {
		return nil, ownerSealTranscriptInvalidf("canonical prefix: %v", err)
	}
	return transcript, nil
}

// NextPageTarget returns the next internally selected target without advancing
// it. Repeated calls return the same detached value until AppendOwnerRereadPage
// consumes it. A caller can therefore locate the physical page to reread but
// cannot tell Append to skip or reorder logical pages.
func (transcript *OwnerSealTranscript) NextPageTarget() (OwnerSealPageTarget, error) {
	if transcript == nil {
		return OwnerSealPageTarget{}, ownerSealTranscriptInvalidf("transcript is nil")
	}
	if transcript.terminalErr != nil {
		return OwnerSealPageTarget{}, transcript.terminalErr
	}
	if transcript.finished {
		return OwnerSealPageTarget{}, ownerSealTranscriptInvalidf("transcript is already finished")
	}
	if transcript.pendingTargetSet {
		return transcript.pendingTarget, nil
	}
	target, err := transcript.iterator.Next()
	if err != nil {
		if errors.Is(err, io.EOF) {
			return OwnerSealPageTarget{}, io.EOF
		}
		return OwnerSealPageTarget{}, transcript.failf("select next page target: %v", err)
	}
	transcript.pendingTarget = target
	transcript.pendingTargetSet = true
	return target, nil
}

// AppendOwnerRereadPage verifies and emits the next canonical page frame. The
// caller supplies exactly the 4 KiB Owner DML scratch page and the CRC32C
// returned by that same hardware operation. The method never computes a CPU
// content CRC and accepts CRC32C value zero for meaningful content.
func (transcript *OwnerSealTranscript) AppendOwnerRereadPage(
	scratch []byte,
	ownerDMLCRC32C uint32,
) (OwnerSealPageVerification, error) {
	if transcript == nil {
		return OwnerSealPageVerification{}, ownerSealTranscriptInvalidf("transcript is nil")
	}
	if transcript.terminalErr != nil {
		return OwnerSealPageVerification{}, transcript.terminalErr
	}
	if transcript.finished {
		return OwnerSealPageVerification{}, transcript.failf("append after Finish")
	}
	if len(scratch) != ContentPageBytes {
		return OwnerSealPageVerification{}, transcript.failf(
			"Owner DML scratch length %d, want %d", len(scratch), ContentPageBytes)
	}

	target, err := transcript.NextPageTarget()
	if err != nil {
		if errors.Is(err, io.EOF) {
			return OwnerSealPageVerification{}, transcript.failf(
				"extra Owner reread page after %d pages", transcript.pagesAppended)
		}
		return OwnerSealPageVerification{}, err
	}
	descriptor, err := target.TargetDescriptor(ownerDMLCRC32C)
	if err != nil {
		return OwnerSealPageVerification{}, transcript.failf(
			"logical page %d target descriptor: %v", target.LogicalPage(), err)
	}
	// This is a scalar comparison against the DML result, not a CPU reread of
	// scratch. It makes accidental replacement of the injected CRC explicit.
	if descriptor.PaddedPageCRC32C != ownerDMLCRC32C {
		return OwnerSealPageVerification{}, transcript.failf(
			"logical page %d target CRC32C %#08x differs from Owner DML CRC32C %#08x",
			target.LogicalPage(), descriptor.PaddedPageCRC32C, ownerDMLCRC32C)
	}
	meaningful := int(target.MeaningfulByteLength())
	if meaningful < 0 || meaningful > len(scratch) {
		return OwnerSealPageVerification{}, transcript.failf(
			"logical page %d meaningful length %d is outside one page",
			target.LogicalPage(), meaningful)
	}
	if !allZero(scratch[meaningful:]) {
		return OwnerSealPageVerification{}, transcript.failf(
			"logical page %d has nonzero bytes after meaningful prefix %d",
			target.LogicalPage(), meaningful)
	}
	if err := transcript.appendExactObjectPrefix(target, scratch[:meaningful]); err != nil {
		return OwnerSealPageVerification{}, transcript.failf(
			"logical page %d typed control: %v", target.LogicalPage(), err)
	}
	descriptorWire, err := descriptor.MarshalBinary()
	if err != nil {
		return OwnerSealPageVerification{}, transcript.failf(
			"logical page %d marshal target descriptor: %v", target.LogicalPage(), err)
	}
	if len(descriptorWire) != PageDescriptorBytes {
		return OwnerSealPageVerification{}, transcript.failf(
			"logical page %d target descriptor length %d, want %d",
			target.LogicalPage(), len(descriptorWire), PageDescriptorBytes)
	}
	if err := writeOwnerSealTranscriptPageFrame(
		transcript.digest, target, descriptorWire, scratch); err != nil {
		return OwnerSealPageVerification{}, transcript.failf(
			"logical page %d canonical frame: %v", target.LogicalPage(), err)
	}

	transcript.pendingTarget = OwnerSealPageTarget{}
	transcript.pendingTargetSet = false
	transcript.pagesAppended++
	return OwnerSealPageVerification{target: target, descriptor: descriptor}, nil
}

// Finish emits the terminal frame and returns the opaque seal only after every
// logical capacity page was appended exactly once. Calling Finish early is a
// terminal error; callers cannot resume a partially finalized transcript.
func (transcript *OwnerSealTranscript) Finish() (OwnerVerifiedSeal, error) {
	if transcript == nil {
		return OwnerVerifiedSeal{}, ownerSealTranscriptInvalidf("transcript is nil")
	}
	if transcript.terminalErr != nil {
		return OwnerVerifiedSeal{}, transcript.terminalErr
	}
	if transcript.finished {
		return OwnerVerifiedSeal{}, ownerSealTranscriptInvalidf("transcript is already finished")
	}
	if transcript.pendingTargetSet || transcript.pagesAppended != transcript.plan.TotalPages() {
		return OwnerVerifiedSeal{}, transcript.failf(
			"incomplete transcript has %d of %d pages",
			transcript.pagesAppended, transcript.plan.TotalPages())
	}
	if transcript.exactDigest != nil || transcript.exactObjectID != 0 ||
		transcript.exactBytesHashed != 0 {
		return OwnerVerifiedSeal{}, transcript.failf("typed control SHA-256 remains incomplete")
	}
	if _, err := transcript.iterator.Next(); !errors.Is(err, io.EOF) {
		if err == nil {
			return OwnerVerifiedSeal{}, transcript.failf("page iterator contains an extra target")
		}
		return OwnerVerifiedSeal{}, transcript.failf("finish page iterator: %v", err)
	}
	if err := writeOwnerSealTranscriptFinishFrame(
		transcript.digest, transcript.pagesAppended); err != nil {
		return OwnerVerifiedSeal{}, transcript.failf("canonical finish frame: %v", err)
	}
	var result [sha256.Size]byte
	copy(result[:], transcript.digest.Sum(nil))
	if result == ([sha256.Size]byte{}) {
		return OwnerVerifiedSeal{}, transcript.failf("computed Owner-verified seal is zero")
	}
	transcript.finished = true
	seal := OwnerVerifiedSeal{
		sha256:              result,
		planIntegritySHA256: transcript.plan.IntegritySHA256(),
	}
	if err := seal.Validate(transcript.plan); err != nil {
		return OwnerVerifiedSeal{}, transcript.failf("completed seal: %v", err)
	}
	return seal, nil
}

func (transcript *OwnerSealTranscript) appendExactObjectPrefix(
	target OwnerSealPageTarget,
	meaningful []byte,
) error {
	object := target.Object()
	pageByteStart, ok := checkedMul(target.ObjectPage(), uint64(ContentPageBytes))
	if !ok {
		return errors.New("object-page byte offset overflows")
	}
	if target.ObjectPage() == 0 && object.ExactSHA256Required {
		if transcript.exactDigest != nil {
			return errors.New("previous typed control SHA-256 is incomplete")
		}
		transcript.exactObjectID = object.ObjectID
		transcript.exactBytesHashed = 0
		transcript.exactDigest = sha256.New()
	}
	if !object.ExactSHA256Required {
		if object.ExactSHA256 != ([sha256.Size]byte{}) {
			return errors.New("object without exact-SHA requirement has a nonzero digest")
		}
		return nil
	}
	if pageByteStart >= object.ExactByteLength {
		if len(meaningful) != 0 {
			return errors.New("page beyond exact object length has meaningful bytes")
		}
		if transcript.exactDigest != nil && transcript.exactObjectID == object.ObjectID {
			return errors.New("typed control SHA-256 remained incomplete beyond exact length")
		}
		return nil
	}
	if transcript.exactDigest == nil || transcript.exactObjectID != object.ObjectID {
		return errors.New("typed control SHA-256 state is absent or belongs to another object")
	}
	remaining := object.ExactByteLength - pageByteStart
	want := uint64(ContentPageBytes)
	if remaining < want {
		want = remaining
	}
	if uint64(len(meaningful)) != want {
		return fmt.Errorf("meaningful prefix length %d, want %d", len(meaningful), want)
	}
	_, _ = transcript.exactDigest.Write(meaningful)
	next, addOK := checkedAdd(transcript.exactBytesHashed, uint64(len(meaningful)))
	if !addOK || next > object.ExactByteLength {
		return errors.New("typed control meaningful-byte count overflows")
	}
	transcript.exactBytesHashed = next
	if next != object.ExactByteLength {
		return nil
	}
	var actual [sha256.Size]byte
	copy(actual[:], transcript.exactDigest.Sum(nil))
	if actual != object.ExactSHA256 {
		return fmt.Errorf(
			"object %d meaningful-prefix SHA-256 differs", object.ObjectID)
	}
	transcript.exactObjectID = 0
	transcript.exactBytesHashed = 0
	transcript.exactDigest = nil
	return nil
}

func (transcript *OwnerSealTranscript) failf(format string, arguments ...interface{}) error {
	if transcript == nil {
		return ownerSealTranscriptInvalidf(format, arguments...)
	}
	if transcript.terminalErr == nil {
		transcript.terminalErr = ownerSealTranscriptInvalidf(format, arguments...)
	}
	return transcript.terminalErr
}

func writeOwnerSealTranscriptPrefix(writer io.Writer, plan OwnerSealPlan) error {
	if writer == nil {
		return errors.New("nil transcript writer")
	}
	if err := plan.Validate(); err != nil {
		return err
	}
	if err := writeOwnerSealTranscriptString(writer, OwnerVerifiedSealTranscriptDomain); err != nil {
		return err
	}
	if err := writeOwnerSealTranscriptUint32(writer, OwnerVerifiedSealTranscriptVersion); err != nil {
		return err
	}
	if err := writeOwnerSealTranscriptString(writer, plan.StorageCompatibilityID()); err != nil {
		return err
	}
	if err := writeOwnerSealTranscriptUint64(writer, uint64(ContentPageBytes)); err != nil {
		return err
	}
	if err := writeOwnerSealTranscriptUint64(writer, uint64(PageDescriptorBytes)); err != nil {
		return err
	}

	for _, value := range []string{
		plan.ClusterID(),
		plan.OwnerGroupID(),
		plan.OwnerID(),
		plan.AnchorDeviceUUID(),
	} {
		if err := writeOwnerSealTranscriptString(writer, value); err != nil {
			return err
		}
	}
	for _, value := range []uint64{
		plan.OwnerEpoch(),
		plan.GroupConfigurationSequence(),
	} {
		if err := writeOwnerSealTranscriptUint64(writer, value); err != nil {
			return err
		}
	}
	membershipSHA256 := plan.MembershipSHA256()
	if err := writeOwnerSealTranscriptBytes(writer, membershipSHA256[:]); err != nil {
		return err
	}

	for _, value := range []string{
		plan.RequestID(),
		plan.CheckpointID(),
		plan.ProducerID(),
		plan.DedupDomainID(),
		plan.SharingPolicyID(),
	} {
		if err := writeOwnerSealTranscriptString(writer, value); err != nil {
			return err
		}
	}
	for _, value := range []uint64{
		plan.AllocationRecordID(),
		plan.ReservationTransactionSequence(),
		plan.SealTransactionSequence(),
	} {
		if err := writeOwnerSealTranscriptUint64(writer, value); err != nil {
			return err
		}
	}
	for _, value := range [][sha256.Size]byte{
		plan.RequestSHA256(),
		plan.GrantRecordSHA256(),
		plan.SchedulerReserveSHA256(),
		plan.ProducerCapabilitySHA256(),
		plan.PublicationAuthoritySHA256(),
		plan.ReclaimAuthoritySHA256(),
	} {
		if err := writeOwnerSealTranscriptBytes(writer, value[:]); err != nil {
			return err
		}
	}

	if err := writeOwnerSealTranscriptUint64(writer, plan.TotalPages()); err != nil {
		return err
	}
	devices := plan.Devices()
	if err := writeOwnerSealTranscriptUint64(writer, uint64(len(devices))); err != nil {
		return err
	}
	for _, device := range devices {
		if err := writeOwnerSealTranscriptString(writer, device.DeviceUUID); err != nil {
			return err
		}
		if err := writeOwnerSealTranscriptUint64(writer, device.DeviceOwnerEpoch); err != nil {
			return err
		}
		if err := writeOwnerSealTranscriptUint64(writer, device.DataPageCount); err != nil {
			return err
		}
		if err := writeOwnerSealTranscriptBytes(writer, device.DeviceBindingSHA256[:]); err != nil {
			return err
		}
	}

	objects := plan.Objects()
	if err := writeOwnerSealTranscriptUint64(writer, uint64(len(objects))); err != nil {
		return err
	}
	for _, object := range objects {
		if err := writeOwnerSealTranscriptUint64(writer, object.ObjectID); err != nil {
			return err
		}
		if err := writeOwnerSealTranscriptBytes(writer, []byte{byte(object.Kind)}); err != nil {
			return err
		}
		if err := writeOwnerSealTranscriptUint64(writer, object.LogicalPageStart); err != nil {
			return err
		}
		if err := writeOwnerSealTranscriptUint64(writer, object.ExactByteLength); err != nil {
			return err
		}
		if err := writeOwnerSealTranscriptUint64(writer, object.CapacityPages); err != nil {
			return err
		}
		required := byte(0)
		if object.ExactSHA256Required {
			required = 1
		}
		if err := writeOwnerSealTranscriptBytes(writer, []byte{required}); err != nil {
			return err
		}
		if err := writeOwnerSealTranscriptBytes(writer, object.ExactSHA256[:]); err != nil {
			return err
		}
	}

	runs := plan.ExtentRuns()
	if err := writeOwnerSealTranscriptUint64(writer, uint64(len(runs))); err != nil {
		return err
	}
	for _, run := range runs {
		if err := writeOwnerSealTranscriptUint32(writer, run.DeviceIndex); err != nil {
			return err
		}
		if err := writeOwnerSealTranscriptUint64(writer, run.StartDataPageIndex); err != nil {
			return err
		}
		if err := writeOwnerSealTranscriptUint64(writer, run.LogicalPageStart); err != nil {
			return err
		}
		if err := writeOwnerSealTranscriptUint64(writer, run.PageCount); err != nil {
			return err
		}
	}
	return nil
}

func writeOwnerSealTranscriptPageFrame(
	writer io.Writer,
	target OwnerSealPageTarget,
	descriptorWire []byte,
	scratch []byte,
) error {
	if len(descriptorWire) != PageDescriptorBytes || len(scratch) != ContentPageBytes {
		return fmt.Errorf(
			"page frame has descriptor/scratch lengths %d/%d, want %d/%d",
			len(descriptorWire), len(scratch), PageDescriptorBytes, ContentPageBytes)
	}
	if err := writeOwnerSealTranscriptBytes(writer, []byte{ownerSealPageFrameTag}); err != nil {
		return err
	}
	if err := writeOwnerSealTranscriptUint64(writer, target.LogicalPage()); err != nil {
		return err
	}
	if err := writeOwnerSealTranscriptUint64(writer, target.ObjectPage()); err != nil {
		return err
	}
	if err := writeOwnerSealTranscriptUint32(writer, target.DeviceIndex()); err != nil {
		return err
	}
	if err := writeOwnerSealTranscriptUint64(writer, target.DataPageIndex()); err != nil {
		return err
	}
	if err := writeOwnerSealTranscriptBytes(writer, descriptorWire); err != nil {
		return err
	}
	return writeOwnerSealTranscriptBytes(writer, scratch)
}

func writeOwnerSealTranscriptFinishFrame(writer io.Writer, totalPages uint64) error {
	if err := writeOwnerSealTranscriptBytes(writer, []byte{ownerSealFinishFrameTag}); err != nil {
		return err
	}
	return writeOwnerSealTranscriptUint64(writer, totalPages)
}

func writeOwnerSealTranscriptString(writer io.Writer, value string) error {
	if err := writeOwnerSealTranscriptUint64(writer, uint64(len(value))); err != nil {
		return err
	}
	return writeOwnerSealTranscriptBytes(writer, []byte(value))
}

func writeOwnerSealTranscriptUint64(writer io.Writer, value uint64) error {
	var encoded [8]byte
	binary.LittleEndian.PutUint64(encoded[:], value)
	return writeOwnerSealTranscriptBytes(writer, encoded[:])
}

func writeOwnerSealTranscriptUint32(writer io.Writer, value uint32) error {
	var encoded [4]byte
	binary.LittleEndian.PutUint32(encoded[:], value)
	return writeOwnerSealTranscriptBytes(writer, encoded[:])
}

func writeOwnerSealTranscriptBytes(writer io.Writer, value []byte) error {
	if writer == nil {
		return errors.New("nil transcript writer")
	}
	n, err := writer.Write(value)
	if err != nil {
		return err
	}
	if n != len(value) {
		return io.ErrShortWrite
	}
	return nil
}

func ownerSealTranscriptInvalidf(format string, arguments ...interface{}) error {
	return fmt.Errorf(
		"%w: %s", ErrInvalidOwnerSealTranscript, fmt.Sprintf(format, arguments...))
}

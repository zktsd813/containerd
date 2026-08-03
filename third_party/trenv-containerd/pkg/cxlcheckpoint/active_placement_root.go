package cxlcheckpoint

import (
	"crypto/sha256"
	"errors"
	"fmt"
)

const (
	// ActiveContentPlacementRootVersion is the wire version of the compact V7
	// Scheduler authority. It deliberately does not change Version or the live
	// TRPUB006/V6 publication contract.
	ActiveContentPlacementRootVersion uint32 = 7

	// ActiveContentPlacementRootMagicString and
	// ActiveContentPlacementRootDomain separate this object from TRPUB006 and
	// both V7 mapping envelopes.
	ActiveContentPlacementRootMagicString = "TRAPR007"
	ActiveContentPlacementRootDomain      = "active-placement-root-v1"

	// ActiveContentPlacementRootEnvelopeHeaderBytes is the exact integrity
	// header size. The complete root is bounded to one 4 KiB page so a
	// Scheduler never has to read or compare a full mapping to select A or B.
	ActiveContentPlacementRootEnvelopeHeaderBytes uint64 = 64
	MaxActiveContentPlacementRootBytes            uint64 = PageSize

	// MaxActiveContentPlacementRootIdentityBytes is intentionally tighter than
	// MaxIdentityBytes. Four identities at this limit, all fixed fields, all
	// field headers, and the envelope header still fit comfortably in 4 KiB.
	MaxActiveContentPlacementRootIdentityBytes = 256

	// These limits apply to exact immutable objects referenced by the root, not
	// to the compact root itself. The publication limit is a V7 root contract,
	// not an alias for the V6 TRPUB006 payload limit. The mapping codecs enforce
	// the same 64 MiB complete-envelope ceiling when CrossCheck canonicalizes
	// them.
	MaxActiveContentPlacementPublicationBytes uint64 = 64 << 20
	MaxActiveContentPlacementMapBytes         uint64 = MaxContentMappingBytes
)

var (
	// ErrWrongActiveContentPlacementRootFormat identifies an incompatible
	// magic, version, domain, mandatory wire field, or reserved header field.
	ErrWrongActiveContentPlacementRootFormat = errors.New("not a V7 active content placement root")
	// ErrCorruptActiveContentPlacementRoot identifies truncated, trailing,
	// duplicated, checksummed, or otherwise malformed root bytes.
	ErrCorruptActiveContentPlacementRoot = errors.New("corrupt V7 active content placement root")
	// ErrInvalidActiveContentPlacementRoot identifies a structurally decoded
	// root whose authority or exact object bindings are invalid.
	ErrInvalidActiveContentPlacementRoot = errors.New("invalid V7 active content placement root")
)

// ActiveContentPlacementRootState intentionally has one accepted value.
// Prepared or partially written roots are never authoritative.
type ActiveContentPlacementRootState uint8

const (
	// ActiveContentPlacementRootCommitted is the exact wire value for
	// COMMITTED.
	ActiveContentPlacementRootCommitted ActiveContentPlacementRootState = 1
)

// ActiveContentPlacementRoot is the compact Scheduler-owned authority that
// selects one committed A/B ContentPlacementMap. It binds immutable object
// bytes, not local paths or runtime routing state.
//
// In particular, this structure contains no DAX path, payload page, complete
// map, Owner route, reader lease, or refcount. Physical locators for the A/B
// slots are an immutable-publication concern in a later schema slice. This
// package also does not implement Scheduler compare-and-swap persistence,
// crash durability, reader leases, DAX I/O, or live publication discovery.
type ActiveContentPlacementRoot struct {
	State        ActiveContentPlacementRootState
	RootID       string
	RootVersion  uint64
	CheckpointID string

	ImmutablePublicationLength uint64
	ImmutablePublicationSHA256 [sha256.Size]byte

	VirtualPageMapID      string
	VirtualPageMapVersion uint64
	VirtualPageMapLength  uint64
	VirtualPageMapSHA256  [sha256.Size]byte

	ActiveMappingSlot MappingSlotName

	ContentPlacementMapID      string
	ContentPlacementMapVersion uint64
	ContentPlacementMapLength  uint64
	ContentPlacementMapSHA256  [sha256.Size]byte

	PlacementDeviceTableSHA256 [sha256.Size]byte
}

// Validate proves that root contains only complete, portable, compact
// authority. It does not dereference any bound object.
func (root ActiveContentPlacementRoot) Validate() error {
	if root.State != ActiveContentPlacementRootCommitted {
		return activeContentPlacementRootInvalidf(
			"root state %d is not COMMITTED", root.State)
	}
	if err := validateActiveContentPlacementRootIdentity("root ID", root.RootID); err != nil {
		return activeContentPlacementRootFieldInvalid("root identity", err)
	}
	if err := positiveLong("root version", root.RootVersion); err != nil {
		return activeContentPlacementRootFieldInvalid("root version", err)
	}
	if err := validateActiveContentPlacementRootIdentity(
		"checkpoint ID", root.CheckpointID); err != nil {
		return activeContentPlacementRootFieldInvalid("checkpoint identity", err)
	}
	if err := validateActiveContentPlacementReferencedLength(
		"immutable publication length",
		root.ImmutablePublicationLength,
		MaxActiveContentPlacementPublicationBytes,
	); err != nil {
		return err
	}
	if activeContentPlacementDigestIsZero(root.ImmutablePublicationSHA256) {
		return activeContentPlacementRootInvalidf(
			"immutable publication SHA-256 is zero")
	}

	if err := validateActiveContentPlacementRootIdentity(
		"VirtualPageMap ID", root.VirtualPageMapID); err != nil {
		return activeContentPlacementRootFieldInvalid("VirtualPageMap identity", err)
	}
	if err := positiveLong("VirtualPageMap version", root.VirtualPageMapVersion); err != nil {
		return activeContentPlacementRootFieldInvalid("VirtualPageMap version", err)
	}
	if err := validateActiveContentPlacementReferencedLength(
		"VirtualPageMap length",
		root.VirtualPageMapLength,
		MaxActiveContentPlacementMapBytes,
	); err != nil {
		return err
	}
	if root.VirtualPageMapLength <= ContentMappingEnvelopeHeaderBytes {
		return activeContentPlacementRootInvalidf(
			"VirtualPageMap length %d cannot contain a V7 mapping payload",
			root.VirtualPageMapLength)
	}
	if activeContentPlacementDigestIsZero(root.VirtualPageMapSHA256) {
		return activeContentPlacementRootInvalidf("VirtualPageMap SHA-256 is zero")
	}

	if !root.ActiveMappingSlot.valid() {
		return activeContentPlacementRootInvalidf(
			"active mapping slot %d is not A or B", root.ActiveMappingSlot)
	}

	if err := validateActiveContentPlacementRootIdentity(
		"ContentPlacementMap ID", root.ContentPlacementMapID); err != nil {
		return activeContentPlacementRootFieldInvalid("ContentPlacementMap identity", err)
	}
	if err := positiveLong(
		"ContentPlacementMap version", root.ContentPlacementMapVersion); err != nil {
		return activeContentPlacementRootFieldInvalid("ContentPlacementMap version", err)
	}
	if err := validateActiveContentPlacementReferencedLength(
		"ContentPlacementMap length",
		root.ContentPlacementMapLength,
		MaxActiveContentPlacementMapBytes,
	); err != nil {
		return err
	}
	if root.ContentPlacementMapLength <= ContentMappingEnvelopeHeaderBytes {
		return activeContentPlacementRootInvalidf(
			"ContentPlacementMap length %d cannot contain a V7 mapping payload",
			root.ContentPlacementMapLength)
	}
	if activeContentPlacementDigestIsZero(root.ContentPlacementMapSHA256) {
		return activeContentPlacementRootInvalidf("ContentPlacementMap SHA-256 is zero")
	}
	if activeContentPlacementDigestIsZero(root.PlacementDeviceTableSHA256) {
		return activeContentPlacementRootInvalidf(
			"placement device-table SHA-256 is zero")
	}
	return nil
}

// CrossCheck proves that exact immutable publication bytes and exact canonical
// V7 maps are the objects selected by root. immutablePublication remains an
// opaque immutable byte string in this schema foundation. Its hash proves only
// exact root binding; it does not validate the publication schema or prove
// that the publication carries root.CheckpointID. A later immutable
// publication schema is responsible for that graph and the A/B slot locators.
//
// CrossCheck validates but never retains or mutates any input.
func (root ActiveContentPlacementRoot) CrossCheck(
	contentObjects []ContentObject,
	immutablePublication []byte,
	virtualPageMap VirtualPageMap,
	contentPlacementMap ContentPlacementMap,
) error {
	if err := root.Validate(); err != nil {
		return err
	}
	if uint64(len(immutablePublication)) != root.ImmutablePublicationLength {
		return activeContentPlacementRootInvalidf(
			"immutable publication length is %d, root binds %d",
			len(immutablePublication), root.ImmutablePublicationLength)
	}
	if digest := sha256.Sum256(immutablePublication); digest != root.ImmutablePublicationSHA256 {
		return activeContentPlacementRootInvalidf(
			"immutable publication SHA-256 does not match root")
	}

	virtualBytes, err := CanonicalVirtualPageMapBytes(virtualPageMap, contentObjects)
	if err != nil {
		return activeContentPlacementRootFieldInvalid("canonical VirtualPageMap", err)
	}
	if virtualPageMap.VirtualPageMapID != root.VirtualPageMapID {
		return activeContentPlacementRootInvalidf(
			"VirtualPageMap ID %q does not match root ID %q",
			virtualPageMap.VirtualPageMapID, root.VirtualPageMapID)
	}
	if virtualPageMap.Version != root.VirtualPageMapVersion {
		return activeContentPlacementRootInvalidf(
			"VirtualPageMap version %d does not match root version %d",
			virtualPageMap.Version, root.VirtualPageMapVersion)
	}
	if uint64(len(virtualBytes)) != root.VirtualPageMapLength {
		return activeContentPlacementRootInvalidf(
			"canonical VirtualPageMap length is %d, root binds %d",
			len(virtualBytes), root.VirtualPageMapLength)
	}
	if digest := sha256.Sum256(virtualBytes); digest != root.VirtualPageMapSHA256 {
		return activeContentPlacementRootInvalidf(
			"canonical VirtualPageMap SHA-256 does not match root")
	}

	placementBytes, err := CanonicalContentPlacementMapBytes(
		contentPlacementMap, contentObjects)
	if err != nil {
		return activeContentPlacementRootFieldInvalid("canonical ContentPlacementMap", err)
	}
	if contentPlacementMap.ContentPlacementMapID != root.ContentPlacementMapID {
		return activeContentPlacementRootInvalidf(
			"ContentPlacementMap ID %q does not match root ID %q",
			contentPlacementMap.ContentPlacementMapID, root.ContentPlacementMapID)
	}
	if contentPlacementMap.Version != root.ContentPlacementMapVersion {
		return activeContentPlacementRootInvalidf(
			"ContentPlacementMap version %d does not match root version %d",
			contentPlacementMap.Version, root.ContentPlacementMapVersion)
	}
	if uint64(len(placementBytes)) != root.ContentPlacementMapLength {
		return activeContentPlacementRootInvalidf(
			"canonical ContentPlacementMap length is %d, root binds %d",
			len(placementBytes), root.ContentPlacementMapLength)
	}
	if digest := sha256.Sum256(placementBytes); digest != root.ContentPlacementMapSHA256 {
		return activeContentPlacementRootInvalidf(
			"canonical ContentPlacementMap SHA-256 does not match root")
	}
	deviceDigest, err := DeviceTableDigest(contentPlacementMap.Devices)
	if err != nil {
		return activeContentPlacementRootFieldInvalid(
			"canonical placement device table", err)
	}
	if deviceDigest != root.PlacementDeviceTableSHA256 {
		return activeContentPlacementRootInvalidf(
			"canonical placement device-table SHA-256 does not match root")
	}
	return nil
}

func validateActiveContentPlacementRootIdentity(name, value string) error {
	if err := validateIdentity(name, value); err != nil {
		return err
	}
	if len(value) > MaxActiveContentPlacementRootIdentityBytes {
		return fmt.Errorf(
			"%s is %d UTF-8 bytes, compact-root limit is %d",
			name, len(value), MaxActiveContentPlacementRootIdentityBytes)
	}
	return nil
}

func validateActiveContentPlacementReferencedLength(
	name string,
	value uint64,
	maximum uint64,
) error {
	if err := positiveLong(name, value); err != nil {
		return activeContentPlacementRootFieldInvalid(name, err)
	}
	if value > maximum {
		return activeContentPlacementRootInvalidf(
			"%s %d exceeds %d", name, value, maximum)
	}
	return nil
}

func activeContentPlacementDigestIsZero(digest [sha256.Size]byte) bool {
	return digest == [sha256.Size]byte{}
}

func activeContentPlacementRootFieldInvalid(context string, err error) error {
	return fmt.Errorf(
		"%s: %v: %w", context, err, ErrInvalidActiveContentPlacementRoot)
}

func activeContentPlacementRootInvalidf(format string, arguments ...interface{}) error {
	return fmt.Errorf(
		format+": %w", append(arguments, ErrInvalidActiveContentPlacementRoot)...)
}

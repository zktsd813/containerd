package cxlcheckpoint

const (
	// V7StoragePublicationByteOrder and V7StoragePublicationABI name the
	// immutable TRPUB007 graph carried by the target storage contract.
	V7StoragePublicationByteOrder = "little-endian"
	V7StoragePublicationABI       = PublicationV7Domain

	// The TRCXL007 constants define the target ABI required before a V7
	// publication can become live. This slice does not implement a TRCXL007
	// descriptor formatter, descriptor I/O, or a writable device runtime.
	V7StorageDeviceFormatMagicString = "TRCXL007"
	V7StorageDeviceFormatVersion     = uint32(7)
	V7StoragePageSize                = uint64(4096)
	V7StoragePageDescriptorBytes     = uint64(64)
	V7StoragePageDescriptorABI       = "trcxl007-page-descriptor-little-endian-v1"

	// V7 fingerprints retain the Castagnoli CRC32C page-candidate contract.
	// A fingerprint is neither content equality proof nor authentication.
	V7StorageFingerprintAlgorithm  = "crc32c-castagnoli"
	V7StorageFingerprintPolynomial = "0x11edc6f41"

	// The target descriptor ABI must represent every clean-slate V7 content
	// kind exactly, including the six pinned control-object kinds.
	V7StorageFirstContentKind = ContentMemoryPayloadV7
	V7StorageLastContentKind  = ContentPublicationV7
	V7StorageContentKindCount = 9

	// V7StorageCompatibilityID is the complete persisted target identity.
	// Keep this literal stable. It is a compatibility requirement, not a claim
	// that a live TRCXL007 formatter or device path already exists.
	V7StorageCompatibilityID = "publication=TRPUB007/v7/little-endian/immutable-publication-v1;" +
		"envelope-header=64;max-envelope=8388608;" +
		"page=4096;fingerprint=crc32c-castagnoli/0x11edc6f41;" +
		"descriptor=TRCXL007/64/trcxl007-page-descriptor-little-endian-v1"
)

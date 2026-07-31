package cxlcheckpoint

const (
	// PublicationByteOrder is the byte order of every integer in TRPUB006.
	PublicationByteOrder = "little-endian"
	// PublicationABI names the exact V6 graph and dedicated publication-slot
	// layout. It is not interchangeable with earlier V6 development layouts.
	PublicationABI = "trpub006-envelope-little-endian-pages-image-sparse-publication-slot-v1"
	// PublicationEnvelopeHeaderBytes is the exact TRPUB006 envelope header size.
	PublicationEnvelopeHeaderBytes uint64 = 64

	// ContentFingerprintAlgorithm and ContentFingerprintPolynomial identify the
	// 4 KiB immutable-page fingerprint contract. The fingerprint is not the
	// envelope CRC and does not prove equality or authenticity.
	ContentFingerprintAlgorithm  = "crc32c-castagnoli"
	ContentFingerprintPolynomial = "0x11edc6f41"

	// DeviceFormatMagicString and PageDescriptorBytes bind a publication to the
	// matching portable TRCXL006 device format.
	DeviceFormatMagicString = "TRCXL006"
	PageDescriptorBytes     = uint64(64)
	PageDescriptorABI       = "trcxl006-page-descriptor-little-endian-v1"

	// V6CompatibilityID is the complete Producer/Scheduler/reader identity.
	// Keep this literal stable: changing any component requires a new fixture
	// and an explicit compatibility transition.
	V6CompatibilityID = "publication=TRPUB006/v6/little-endian/" +
		"trpub006-envelope-little-endian-pages-image-sparse-publication-slot-v1;" +
		"envelope-header=64;max-payload=67108864;" +
		"page=4096;fingerprint=crc32c-castagnoli/0x11edc6f41;" +
		"descriptor=TRCXL006/64/trcxl006-page-descriptor-little-endian-v1"
)

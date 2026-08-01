package main

import (
	"bytes"
	"errors"
	"reflect"
	"testing"
)

func TestVNextOwnerTROWN008AdmissionRoundTripIsStrict(t *testing.T) {
	fixture := newVNextOwnerTestFixture(t, []vnextOwnerTestDeviceSpec{{
		UUID: "owner-format-v7", Size: 256 << 10,
	}})
	request := vnextOwnerAdmissionTestRequest(
		"format-round-trip", vnextOwnerAdmissionActive, vnextOwnerAdmissionReadOnly, 1)
	if _, err := fixture.group.setAdmission(request); err != nil {
		t.Fatalf("persist admission transition: %v", err)
	}
	encoded, err := fixture.group.journal.marshalAtSequence(
		fixture.group.journal.SnapshotSequence, fixture.group.devices)
	if err != nil {
		t.Fatalf("marshal TROWN008 journal: %v", err)
	}
	if !bytes.Equal(encoded[:len(vnextOwnerJournalMagic)], vnextOwnerJournalMagic[:]) {
		t.Fatalf("Owner journal magic is %q, expected %q",
			encoded[:len(vnextOwnerJournalMagic)], vnextOwnerJournalMagic)
	}
	decoded, err := parseVNextOwnerJournal(encoded, fixture.group.devices)
	if err != nil {
		t.Fatalf("parse TROWN008 journal: %v", err)
	}
	if decoded.AdmissionState != vnextOwnerAdmissionReadOnly ||
		decoded.AdmissionSequence != 2 ||
		!reflect.DeepEqual(decoded.AdmissionTransitions,
			fixture.group.journal.AdmissionTransitions) {
		t.Fatalf("TROWN008 admission round trip changed state: %#v", decoded)
	}
}

func TestVNextOwnerTROWN007JournalFailsClosedWithoutMigration(t *testing.T) {
	fixture := newVNextOwnerTestFixture(t, []vnextOwnerTestDeviceSpec{{
		UUID: "owner-format-v6-rejected", Size: 256 << 10,
	}})
	encoded, err := fixture.group.journal.marshalAtSequence(
		fixture.group.journal.SnapshotSequence, fixture.group.devices)
	if err != nil {
		t.Fatal(err)
	}
	payload, err := vnextParseEnvelope(encoded, vnextOwnerJournalMagic, vnextMaxEnvelopePayload)
	if err != nil {
		t.Fatal(err)
	}
	legacyMagic := [8]byte{'T', 'R', 'O', 'W', 'N', '0', '0', '7'}
	legacy, err := vnextMarshalEnvelope(legacyMagic, payload)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := parseVNextOwnerJournal(legacy, fixture.group.devices); err == nil {
		t.Fatal("TROWN007 magic was accepted by the clean-slate TROWN008 parser")
	}
	for _, offset := range []uint64{0, testVNextOwnerControlSlotBytes} {
		if err := vnextWriteCommittedEnvelopeSlot(
			fixture.controlFile, offset, testVNextOwnerControlSlotBytes, legacy); err != nil {
			t.Fatalf("write legacy Owner slot at %d: %v", offset, err)
		}
	}
	reopenedDevice, err := openVNextFileDevice(fixture.deviceFiles[0])
	if err != nil {
		t.Fatal(err)
	}
	if _, err := openVNextOwnerGroup(
		fixture.controlFile,
		testVNextOwnerControlSlotBytes,
		[]*vnextPersistentDevice{reopenedDevice}); !errors.Is(err, errVNextCorrupt) {
		t.Fatalf("two TROWN007 slots returned %v, expected fail-closed corruption", err)
	}
}

func TestVNextOwnerTROWN008RejectsAdmissionReservedBytesAndDigestTamper(t *testing.T) {
	fixture := newVNextOwnerTestFixture(t, []vnextOwnerTestDeviceSpec{{
		UUID: "owner-format-admission-corrupt", Size: 256 << 10,
	}})
	request := vnextOwnerAdmissionTestRequest(
		"format-corrupt", vnextOwnerAdmissionActive, vnextOwnerAdmissionReadOnly, 1)
	if _, err := fixture.group.setAdmission(request); err != nil {
		t.Fatal(err)
	}
	encoded, err := fixture.group.journal.marshalAtSequence(
		fixture.group.journal.SnapshotSequence, fixture.group.devices)
	if err != nil {
		t.Fatal(err)
	}
	payload, err := vnextParseEnvelope(encoded, vnextOwnerJournalMagic, vnextMaxEnvelopePayload)
	if err != nil {
		t.Fatal(err)
	}
	admissionStateOffset := 8 + 4 + len(fixture.group.ownerID) + 8

	t.Run("reserved", func(t *testing.T) {
		tamperedPayload := append([]byte(nil), payload...)
		tamperedPayload[admissionStateOffset+1] = 1
		tampered, err := vnextMarshalEnvelope(vnextOwnerJournalMagic, tamperedPayload)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := parseVNextOwnerJournal(
			tampered, fixture.group.devices); !errors.Is(err, errVNextWrongFormat) {
			t.Fatalf("non-zero admission reserved byte returned %v", err)
		}
	})

	t.Run("digest", func(t *testing.T) {
		tamperedPayload := append([]byte(nil), payload...)
		transitionRequestOffset := admissionStateOffset + 8 + 8 + 4 + 4
		digestOffset := transitionRequestOffset + 4 + len(request.RequestID)
		tamperedPayload[digestOffset] ^= 0xff
		tampered, err := vnextMarshalEnvelope(vnextOwnerJournalMagic, tamperedPayload)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := parseVNextOwnerJournal(
			tampered, fixture.group.devices); !errors.Is(err, errVNextCorrupt) {
			t.Fatalf("tampered admission digest returned %v", err)
		}
	})
}

func TestVNextOwnerTROWN008EncoderRejectsNonCanonicalAdmissionHistory(t *testing.T) {
	fixture := newVNextOwnerTestFixture(t, []vnextOwnerTestDeviceSpec{{
		UUID: "owner-format-history-invalid", Size: 256 << 10,
	}})
	request := vnextOwnerAdmissionTestRequest(
		"format-history", vnextOwnerAdmissionActive, vnextOwnerAdmissionReadOnly, 1)
	if _, err := fixture.group.setAdmission(request); err != nil {
		t.Fatal(err)
	}

	for name, mutate := range map[string]func(*vnextOwnerJournal){
		"head": func(journal *vnextOwnerJournal) {
			journal.AdmissionState = vnextOwnerAdmissionActive
		},
		"sequence": func(journal *vnextOwnerJournal) {
			journal.AdmissionSequence++
		},
		"digest": func(journal *vnextOwnerJournal) {
			journal.AdmissionTransitions[0].RequestDigest[0] ^= 0xff
		},
		"duplicate": func(journal *vnextOwnerJournal) {
			journal.AdmissionTransitions = append(
				journal.AdmissionTransitions,
				journal.AdmissionTransitions[0],
				journal.AdmissionTransitions[0])
		},
	} {
		t.Run(name, func(t *testing.T) {
			candidate := fixture.group.journal.clone()
			mutate(candidate)
			if _, err := candidate.marshalAtSequence(
				candidate.SnapshotSequence+1, fixture.group.devices); !errors.Is(err, errVNextCorrupt) {
				t.Fatalf("non-canonical admission history returned %v", err)
			}
		})
	}
}

package main

import (
	"bytes"
	"errors"
	"reflect"
	"testing"
)

func TestVNextOwnerTROWN010AdmissionRoundTripIsStrict(t *testing.T) {
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
		t.Fatalf("marshal TROWN010 journal: %v", err)
	}
	if !bytes.Equal(encoded[:len(vnextOwnerJournalMagic)], vnextOwnerJournalMagic[:]) {
		t.Fatalf("Owner journal magic is %q, expected %q",
			encoded[:len(vnextOwnerJournalMagic)], vnextOwnerJournalMagic)
	}
	decoded, err := parseVNextOwnerJournal(encoded, fixture.group.devices)
	if err != nil {
		t.Fatalf("parse TROWN010 journal: %v", err)
	}
	if decoded.AdmissionState != vnextOwnerAdmissionReadOnly ||
		decoded.AdmissionSequence != 2 ||
		!reflect.DeepEqual(decoded.AdmissionTransitions,
			fixture.group.journal.AdmissionTransitions) {
		t.Fatalf("TROWN010 admission round trip changed state: %#v", decoded)
	}
}

func TestVNextOwnerTROWN009JournalFailsClosedWithoutMigration(t *testing.T) {
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
	legacyMagic := [8]byte{'T', 'R', 'O', 'W', 'N', '0', '0', '9'}
	legacy, err := vnextMarshalEnvelope(legacyMagic, payload)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := parseVNextOwnerJournal(legacy, fixture.group.devices); err == nil {
		t.Fatal("TROWN009 magic was accepted by the clean-slate TROWN010 parser")
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
		t.Fatalf("two TROWN009 slots returned %v, expected fail-closed corruption", err)
	}
}

func TestVNextOwnerTROWN010RejectsAdmissionReservedBytesAndDigestTamper(t *testing.T) {
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
	admissionStateOffset := 8 + 4 + len(fixture.group.ownerID) + 8 +
		vnextOwnerSchedulerHighWaterEncodedBytes

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

func TestVNextOwnerTROWN010EncoderRejectsNonCanonicalAdmissionHistory(t *testing.T) {
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

func TestVNextOwnerTROWN010RejectsProofWithoutSchedulerHighWater(t *testing.T) {
	fixture := newVNextOwnerTestFixture(t, []vnextOwnerTestDeviceSpec{{
		UUID: "owner-format-missing-scheduler-high-water", Size: 256 << 10,
	}})
	request := vnextOwnerAdmissionTestRequest(
		"format-proof-without-high-water",
		vnextOwnerAdmissionActive,
		vnextOwnerAdmissionReadOnly,
		1)
	if _, err := fixture.group.setAdmission(request); err != nil {
		t.Fatal(err)
	}
	encoded, err := fixture.group.journal.marshalAtSequence(
		fixture.group.journal.SnapshotSequence, fixture.group.devices)
	if err != nil {
		t.Fatal(err)
	}
	payload, err := vnextParseEnvelope(
		encoded, vnextOwnerJournalMagic, vnextMaxEnvelopePayload)
	if err != nil {
		t.Fatal(err)
	}
	highWaterOffset := 8 + 4 + len(fixture.group.ownerID) + 8
	for index := 0; index < vnextOwnerSchedulerHighWaterEncodedBytes; index++ {
		payload[highWaterOffset+index] = 0
	}
	tampered, err := vnextMarshalEnvelope(vnextOwnerJournalMagic, payload)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := parseVNextOwnerJournal(
		tampered, fixture.group.devices); !errors.Is(err, errVNextCorrupt) {
		t.Fatalf("proof without Scheduler high-water parsed with %v", err)
	}
	for _, offset := range []uint64{0, testVNextOwnerControlSlotBytes} {
		if err := vnextWriteCommittedEnvelopeSlot(
			fixture.controlFile, offset, testVNextOwnerControlSlotBytes, tampered); err != nil {
			t.Fatalf("write tampered Owner slot at %d: %v", offset, err)
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
		t.Fatalf("restart accepted proof without Scheduler high-water: %v", err)
	}
}

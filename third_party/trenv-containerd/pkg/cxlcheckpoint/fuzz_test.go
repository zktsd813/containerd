package cxlcheckpoint

import (
	"reflect"
	"testing"
)

func FuzzDecode(f *testing.F) {
	publication := validPublication(f)
	encoded, err := Encode(publication)
	if err != nil {
		f.Fatalf("encode seed: %v", err)
	}
	f.Add(encoded)
	f.Add([]byte("TRPUB005"))
	f.Add([]byte{})
	f.Add(encoded[:envelopeHeaderSize])

	f.Fuzz(func(t *testing.T, data []byte) {
		decoded, err := Decode(data)
		if err != nil {
			return
		}
		reencoded, err := Encode(decoded)
		if err != nil {
			t.Fatalf("successfully decoded publication did not re-encode: %v", err)
		}
		decodedAgain, err := Decode(reencoded)
		if err != nil {
			t.Fatalf("canonical re-encoding did not decode: %v", err)
		}
		if err := decodedAgain.Validate(); err != nil {
			t.Fatalf("canonical re-encoding is invalid: %v", err)
		}
		if !reflect.DeepEqual(decodedAgain, decoded) {
			t.Fatal("canonical re-encoding changed the decoded publication")
		}
	})
}

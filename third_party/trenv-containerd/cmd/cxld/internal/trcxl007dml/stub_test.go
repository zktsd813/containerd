//go:build !trenv_v7_dml_hw
// +build !trenv_v7_dml_hw

package trcxl007dml

import (
	"errors"
	"testing"
)

func TestOpenHardwareFailsClosedWhenBackendNotBuilt(t *testing.T) {
	t.Parallel()

	copier, err := OpenHardware()
	if copier != nil {
		t.Fatalf("OpenHardware() copier = %T, want nil", copier)
	}
	if !errors.Is(err, ErrHardwareBackendNotBuilt) {
		t.Fatalf("OpenHardware() error = %v, want ErrHardwareBackendNotBuilt", err)
	}
}

package tpm2tools

import (
	"testing"

	"github.com/google/go-tpm-tools/internal"
	"github.com/google/go-tpm-tools/simulator"
	"github.com/google/go-tpm/tpm2"
)

const (
	// Maximum number of handles to keys tests can create within a simulator.
	maxHandles = 3
)

func TestHandles(t *testing.T) {
	simulator, err := simulator.Get()
	if err != nil {
		t.Fatal(err)
	}
	defer simulator.Close()
	for i := 0; i <= maxHandles; i++ {
		h, err := Handles(simulator, tpm2.HandleTypeTransient)
		if err != nil {
			t.Fatal(err)
		}
		if len(h) != i {
			t.Errorf("Handles mismatch got: %d; want: %d", len(h), i)
		}
		if i < maxHandles {
			internal.LoadRandomExternalKey(t, simulator)
		}
	}
}

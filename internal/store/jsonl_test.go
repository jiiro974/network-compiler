package store

import (
	"path/filepath"
	"testing"

	"network-compiler/internal/ir"
)

func TestJSONLRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "inventory.jsonl")
	devices := []ir.Device{
		{Hostname: "sw1", Vendor: "cisco"},
		{Hostname: "sw2", Vendor: "cisco"},
	}
	if err := WriteJSONL(path, devices); err != nil {
		t.Fatal(err)
	}
	got, err := ReadJSONL(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("devices = %d, want 2", len(got))
	}
	if got[1].Hostname != "sw2" {
		t.Fatalf("hostname = %q", got[1].Hostname)
	}
}

package diff

import (
	"testing"

	"network-compiler/internal/ir"
)

func TestDevicesDetectsInterfaceChange(t *testing.T) {
	before := ir.Device{
		Hostname: "sw1",
		Interfaces: []ir.Interface{
			{Name: "Gi1/0/1", Mode: "access", AccessVLAN: 10},
		},
	}
	after := ir.Device{
		Hostname: "sw1",
		Interfaces: []ir.Interface{
			{Name: "Gi1/0/1", Mode: "access", AccessVLAN: 20},
		},
	}
	changes := Devices(before, after)
	if len(changes) != 1 {
		t.Fatalf("changes = %d, want 1", len(changes))
	}
	if changes[0].Object != "interface:Gi1/0/1" {
		t.Fatalf("object = %q", changes[0].Object)
	}
}

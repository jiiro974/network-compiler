package diff

import (
	"fmt"
	"reflect"

	"network-compiler/internal/ir"
)

type Change struct {
	Type     string      `json:"type"`
	Device   string      `json:"device"`
	Object   string      `json:"object"`
	Summary  string      `json:"summary"`
	Before   any         `json:"before,omitempty"`
	After    any         `json:"after,omitempty"`
	Evidence ir.Evidence `json:"evidence"`
}

func Devices(before, after ir.Device) []Change {
	var changes []Change
	device := after.Hostname
	if device == "" {
		device = before.Hostname
	}

	beforeVLANs := mapBy(before.VLANs, func(v ir.VLAN) int { return v.ID })
	afterVLANs := mapBy(after.VLANs, func(v ir.VLAN) int { return v.ID })
	for id, old := range beforeVLANs {
		if _, ok := afterVLANs[id]; !ok {
			changes = append(changes, Change{Type: "removed", Device: device, Object: fmt.Sprintf("vlan:%d", id), Summary: fmt.Sprintf("vlan %d removed", id), Before: old, Evidence: old.Evidence})
		}
	}
	for id, next := range afterVLANs {
		old, ok := beforeVLANs[id]
		if !ok {
			changes = append(changes, Change{Type: "added", Device: device, Object: fmt.Sprintf("vlan:%d", id), Summary: fmt.Sprintf("vlan %d added", id), After: next, Evidence: next.Evidence})
			continue
		}
		if old.Name != next.Name {
			changes = append(changes, Change{Type: "changed", Device: device, Object: fmt.Sprintf("vlan:%d", id), Summary: fmt.Sprintf("vlan %d name changed", id), Before: old, After: next, Evidence: next.Evidence})
		}
	}

	beforeIfaces := mapBy(before.Interfaces, func(i ir.Interface) string { return i.Name })
	afterIfaces := mapBy(after.Interfaces, func(i ir.Interface) string { return i.Name })
	for name, old := range beforeIfaces {
		if _, ok := afterIfaces[name]; !ok {
			changes = append(changes, Change{Type: "removed", Device: device, Object: "interface:" + name, Summary: fmt.Sprintf("interface %s removed", name), Before: old, Evidence: old.Evidence})
		}
	}
	for name, next := range afterIfaces {
		old, ok := beforeIfaces[name]
		if !ok {
			changes = append(changes, Change{Type: "added", Device: device, Object: "interface:" + name, Summary: fmt.Sprintf("interface %s added", name), After: next, Evidence: next.Evidence})
			continue
		}
		if interfaceChanged(old, next) {
			changes = append(changes, Change{Type: "changed", Device: device, Object: "interface:" + name, Summary: fmt.Sprintf("interface %s changed", name), Before: old, After: next, Evidence: next.Evidence})
		}
	}

	return changes
}

func interfaceChanged(a, b ir.Interface) bool {
	return a.Description != b.Description ||
		a.Mode != b.Mode ||
		a.AccessVLAN != b.AccessVLAN ||
		a.IPv4 != b.IPv4 ||
		a.Shutdown != b.Shutdown ||
		!reflect.DeepEqual(a.TrunkVLANs, b.TrunkVLANs)
}

func mapBy[T any, K comparable](items []T, key func(T) K) map[K]T {
	out := make(map[K]T, len(items))
	for _, item := range items {
		out[key(item)] = item
	}
	return out
}

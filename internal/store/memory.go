package store

import "network-compiler/internal/ir"

type MemoryStore struct {
	devices []ir.Device
}

func NewMemoryStore() *MemoryStore {
	return &MemoryStore{}
}

func (s *MemoryStore) Add(device ir.Device) {
	s.devices = append(s.devices, device)
}

func (s *MemoryStore) Devices() []ir.Device {
	out := make([]ir.Device, len(s.devices))
	copy(out, s.devices)
	return out
}

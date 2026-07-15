package store

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"

	"network-compiler/internal/ir"
)

func WriteJSONL(path string, devices []ir.Device) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	enc := json.NewEncoder(f)
	for _, dev := range devices {
		if err := enc.Encode(dev); err != nil {
			return err
		}
	}
	return nil
}

func ReadJSONL(path string) ([]ir.Device, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var devices []ir.Device
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 1024), 16*1024*1024)
	for line := 1; scanner.Scan(); line++ {
		var dev ir.Device
		if err := json.Unmarshal(scanner.Bytes(), &dev); err != nil {
			return nil, fmt.Errorf("%s:%d: %w", path, line, err)
		}
		devices = append(devices, dev)
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return devices, nil
}

package store

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"

	"network-compiler/internal/ir"
)

func WriteJSONL(path string, devices []ir.Device) error {
	return WriteRecordsJSONL(path, devices)
}

func WriteRecordsJSONL[T any](path string, records []T) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	enc := json.NewEncoder(f)
	for _, record := range records {
		if err := enc.Encode(record); err != nil {
			return err
		}
	}
	return nil
}

func ReadJSONL(path string) ([]ir.Device, error) {
	return ReadRecordsJSONL[ir.Device](path)
}

func ReadRecordsJSONL[T any](path string) ([]T, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var records []T
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 1024), 16*1024*1024)
	for line := 1; scanner.Scan(); line++ {
		var record T
		if err := json.Unmarshal(scanner.Bytes(), &record); err != nil {
			return nil, fmt.Errorf("%s:%d: %w", path, line, err)
		}
		records = append(records, record)
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return records, nil
}

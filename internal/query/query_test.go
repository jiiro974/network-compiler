package query

import (
	"strings"
	"testing"

	"network-compiler/internal/ir"
	"network-compiler/internal/parser/cisco"
)

func TestRunSupportedQueries(t *testing.T) {
	dev, err := cisco.New().ParseFile("../../testdata/cisco-sw1.cfg")
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name      string
		query     string
		wantType  string
		wantCount int
	}{
		{name: "vlan", query: "find vlan 42", wantType: "vlan", wantCount: 3},
		{name: "interface", query: "find interface GigabitEthernet1/0/1", wantType: "interface", wantCount: 1},
		{name: "interfaces trunk", query: "find interfaces trunk", wantType: "interface", wantCount: 1},
		{name: "interfaces access vlan", query: "find interfaces access vlan 42", wantType: "interface", wantCount: 1},
		{name: "default route", query: "find default route", wantType: "route", wantCount: 1},
		{name: "acl", query: "find acl 101", wantType: "acl", wantCount: 1},
		{name: "device", query: "find device sw1", wantType: "device", wantCount: 1},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			results, err := Run([]ir.Device{dev}, tt.query)
			if err != nil {
				t.Fatalf("Run() error = %v", err)
			}
			if got := len(results); got != tt.wantCount {
				t.Fatalf("len(results) = %d, want %d", got, tt.wantCount)
			}
			if results[0].Type != tt.wantType {
				t.Fatalf("Type = %q, want %q", results[0].Type, tt.wantType)
			}
			if results[0].Evidence.StartLine == 0 {
				t.Fatalf("Evidence is empty")
			}
			if results[0].Summary == "" {
				t.Fatalf("Summary is empty")
			}
		})
	}
}

func TestRunNotFound(t *testing.T) {
	dev, err := cisco.New().ParseFile("../../testdata/cisco-sw1.cfg")
	if err != nil {
		t.Fatal(err)
	}
	results, err := Run([]ir.Device{dev}, "find vlan 404")
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if len(results) != 0 {
		t.Fatalf("len(results) = %d, want 0", len(results))
	}
}

func TestRunUnsupportedQuery(t *testing.T) {
	dev, err := cisco.New().ParseFile("../../testdata/cisco-sw1.cfg")
	if err != nil {
		t.Fatal(err)
	}
	_, err = Run([]ir.Device{dev}, "show vlan 10")
	if err == nil {
		t.Fatal("Run() error = nil, want error")
	}
	if !strings.Contains(err.Error(), "requete non supportee") {
		t.Fatalf("error = %q, want unsupported query message", err.Error())
	}
}

func TestRunInvalidVLAN(t *testing.T) {
	dev, err := cisco.New().ParseFile("../../testdata/cisco-sw1.cfg")
	if err != nil {
		t.Fatal(err)
	}
	_, err = Run([]ir.Device{dev}, "find vlan abc")
	if err == nil {
		t.Fatal("Run() error = nil, want error")
	}
	if !strings.Contains(err.Error(), "vlan invalide") {
		t.Fatalf("error = %q, want invalid vlan message", err.Error())
	}
}

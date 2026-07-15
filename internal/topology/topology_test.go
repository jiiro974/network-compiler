package topology

import (
	"path/filepath"
	"testing"

	"network-compiler/internal/discovery"
)

func TestBuildMergesLLDPCDPAndScoresConfidence(t *testing.T) {
	discovered, err := discovery.ParseDir(filepath.Join("..", "..", "testdata", "discovery"))
	if err != nil {
		t.Fatal(err)
	}
	got := Build(discovered.Neighbors, discovered.Addresses)
	var merged, lldpOnly bool
	for _, link := range got.Links {
		if link.A.Device == "sw1" && link.A.Interface == "Gi1/0/1" && link.B.Device == "sw2" && link.B.Interface == "Gi0/1" {
			merged = true
			if link.Confidence != 0.95 {
				t.Fatalf("merged confidence = %.2f, want 0.95", link.Confidence)
			}
			if len(link.Sources) != 2 || link.Sources[0] != "cdp" || link.Sources[1] != "lldp" {
				t.Fatalf("sources = %#v", link.Sources)
			}
		}
		if link.A.Device == "sw1" && link.A.Interface == "Gi1/0/2" && link.B.Device == "sw3" && link.B.Interface == "Gi0/9" {
			lldpOnly = true
			if link.Confidence != 0.8 {
				t.Fatalf("lldp confidence = %.2f, want 0.8", link.Confidence)
			}
		}
		if link.A.Device == "sw1" && link.A.Interface == "Gi1/0/4" && link.B.Device == "sw5" && link.B.Interface == "Gi0/4" {
			if link.Confidence != 0.35 {
				t.Fatalf("description confidence = %.2f, want 0.35", link.Confidence)
			}
		}
	}
	if !merged {
		t.Fatal("merged LLDP/CDP link not found")
	}
	if !lldpOnly {
		t.Fatal("LLDP-only link not found")
	}
}

func TestBuildCreatesMediumConfidenceMACCandidates(t *testing.T) {
	discovered, err := discovery.ParseDir(filepath.Join("..", "..", "testdata", "discovery"))
	if err != nil {
		t.Fatal(err)
	}
	got := Build(discovered.Neighbors, discovered.Addresses)
	var macLinks int
	for _, link := range got.Links {
		if len(link.Sources) == 1 && link.Sources[0] == "mac_table" {
			macLinks++
			if link.Confidence != 0.55 {
				t.Fatalf("mac link confidence = %.2f, want 0.55", link.Confidence)
			}
		}
	}
	if macLinks != 2 {
		t.Fatalf("mac candidate links = %d, want 2", macLinks)
	}
}

func TestBuildExposesConflicts(t *testing.T) {
	discovered, err := discovery.ParseDir(filepath.Join("..", "..", "testdata", "discovery"))
	if err != nil {
		t.Fatal(err)
	}
	got := Build(discovered.Neighbors, discovered.Addresses)
	if len(got.Conflicts) != 1 {
		t.Fatalf("conflicts = %d, want 1: %#v", len(got.Conflicts), got.Conflicts)
	}
	if got.Conflicts[0].Type != "neighbor_mismatch" {
		t.Fatalf("conflict type = %q", got.Conflicts[0].Type)
	}
}

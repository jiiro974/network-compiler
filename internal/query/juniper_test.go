package query

import (
	"testing"

	"network-compiler/internal/parser/juniper"
)

func TestRunJuniperQueries(t *testing.T) {
	dev, err := juniper.New().ParseFile("../../testdata/corpus/juniper-junos/edge-sw1.set.conf")
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		query     string
		wantType  string
		wantCount int
	}{
		{query: "vlan 10", wantType: "interface", wantCount: 2},
		{query: "default route", wantType: "route", wantCount: 1},
	}
	for _, tt := range tests {
		t.Run(tt.query, func(t *testing.T) {
			results, err := Run(dev, tt.query)
			if err != nil {
				t.Fatal(err)
			}
			if len(results) != tt.wantCount {
				t.Fatalf("results = %d, want %d", len(results), tt.wantCount)
			}
			if results[0].Type != tt.wantType {
				t.Fatalf("type = %q, want %q", results[0].Type, tt.wantType)
			}
		})
	}
}

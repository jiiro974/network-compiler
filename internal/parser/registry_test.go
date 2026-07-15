package parser

import (
	"path/filepath"
	"testing"
)

func TestDetectVendor(t *testing.T) {
	tests := []struct {
		name string
		path string
		want string
	}{
		{name: "cisco", path: "../../testdata/cisco-sw1.cfg", want: "cisco"},
		{name: "juniper", path: "../../testdata/corpus/juniper-junos/edge-sw1.set.conf", want: "juniper"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := DetectVendor(filepath.Clean(tt.path))
			if err != nil {
				t.Fatal(err)
			}
			if got != tt.want {
				t.Fatalf("vendor = %q, want %q", got, tt.want)
			}
		})
	}
}

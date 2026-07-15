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
		{name: "panos", path: "../../testdata/corpus/paloalto-panos/edge-fw1.set.conf", want: "paloalto-panos"},
		{name: "fortigate", path: "../../testdata/corpus/fortinet-fortigate/edge-fw1.conf", want: "fortinet-fortigate"},
		{name: "routeros", path: "../../testdata/corpus/mikrotik-routeros/edge-rtr1.rsc", want: "mikrotik-routeros"},
		{name: "sros", path: "../../testdata/corpus/nokia-sros/edge-rtr1.cfg", want: "nokia-sros"},
		{name: "vrp", path: "../../testdata/corpus/huawei-vrp/edge-sw1.cfg", want: "huawei-vrp"},
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

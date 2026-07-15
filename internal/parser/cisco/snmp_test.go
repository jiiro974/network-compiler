package cisco

import (
	"os"
	"path/filepath"
	"testing"
)

func TestParseSNMPStatements(t *testing.T) {
	cfg := `hostname sw-snmp
snmp-server community public RO
snmp-server location MAMOUDZOU - Hopital
snmp-server contact noc@example.invalid
snmp-server enable traps snmp authentication linkdown linkup coldstart warmstart
snmp-server enable traps config
snmp-server host 172.16.24.10 version 2c chm_public
snmp-server host 172.16.24.11 informs version 2c other_public
`
	path := filepath.Join(t.TempDir(), "snmp.cfg")
	if err := os.WriteFile(path, []byte(cfg), 0600); err != nil {
		t.Fatal(err)
	}

	dev, err := New().ParseFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(dev.SNMP.Statements) != 7 {
		t.Fatalf("snmp statements = %d, want 7", len(dev.SNMP.Statements))
	}
	if len(dev.SNMP.Communities) != 1 || dev.SNMP.Communities[0].Value != "public" {
		t.Fatalf("communities = %#v", dev.SNMP.Communities)
	}
	if len(dev.SNMP.Hosts) != 2 {
		t.Fatalf("hosts = %#v", dev.SNMP.Hosts)
	}
	if dev.SNMP.Hosts[0].Host != "172.16.24.10" || dev.SNMP.Hosts[0].Version != "2c" || dev.SNMP.Hosts[0].Community != "chm_public" {
		t.Fatalf("host[0] = %#v", dev.SNMP.Hosts[0])
	}
	if dev.SNMP.Hosts[1].Community != "other_public" || len(dev.SNMP.Hosts[1].Options) != 1 || dev.SNMP.Hosts[1].Options[0] != "informs" {
		t.Fatalf("host[1] = %#v", dev.SNMP.Hosts[1])
	}
	if len(dev.SNMP.Traps) != 2 || dev.SNMP.Traps[0].Name != "snmp" || len(dev.SNMP.Traps[0].Options) != 5 {
		t.Fatalf("traps = %#v", dev.SNMP.Traps)
	}
	if dev.SNMP.Location.Value != "MAMOUDZOU - Hopital" {
		t.Fatalf("location = %#v", dev.SNMP.Location)
	}
	if len(dev.Services.SNMPCommunities) != 3 {
		t.Fatalf("service communities = %#v", dev.Services.SNMPCommunities)
	}
	if dev.SNMP.Statements[0].Raw == "snmp-server community public RO" {
		t.Fatalf("raw statement not redacted: %q", dev.SNMP.Statements[0].Raw)
	}
}

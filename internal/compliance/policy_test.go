package compliance

import (
	"os"
	"path/filepath"
	"testing"
)

func TestReadPolicy(t *testing.T) {
	path := filepath.Join(t.TempDir(), "policy.json")
	data := []byte(`{
	  "required_ntp_servers": ["10.0.0.1"],
	  "required_syslog_hosts": ["10.0.1.1"],
	  "forbidden_snmp_communities": ["public"]
	}`)
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}

	policy, err := ReadPolicy(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(policy.RequiredNTPServers) != 1 || policy.RequiredNTPServers[0] != "10.0.0.1" {
		t.Fatalf("ntp policy = %#v", policy.RequiredNTPServers)
	}
	if len(policy.RequiredSyslogHosts) != 1 || policy.RequiredSyslogHosts[0] != "10.0.1.1" {
		t.Fatalf("syslog policy = %#v", policy.RequiredSyslogHosts)
	}
	if len(policy.ForbiddenSNMPCommunities) != 1 || policy.ForbiddenSNMPCommunities[0] != "public" {
		t.Fatalf("snmp policy = %#v", policy.ForbiddenSNMPCommunities)
	}
}

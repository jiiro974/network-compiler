package compliance

import (
	"testing"

	"network-compiler/internal/ir"
)

func TestCheckFindsMissingAndForbiddenServices(t *testing.T) {
	devices := []ir.Device{
		{
			Hostname: "sw1",
			Services: ir.Services{
				NTPServers:      []ir.ServiceTarget{{Value: "10.0.0.1"}},
				SNMPCommunities: []ir.ServiceTarget{{Value: "public"}},
			},
		},
	}
	findings := Check(devices, Policy{
		RequiredNTPServers:       []string{"10.0.0.1", "10.0.0.2"},
		RequiredSyslogHosts:      []string{"10.0.1.1"},
		ForbiddenSNMPCommunities: []string{"public"},
	})
	if len(findings) != 3 {
		t.Fatalf("findings = %d, want 3: %#v", len(findings), findings)
	}
	if findings[2].Severity != "critical" {
		t.Fatalf("severity = %q", findings[2].Severity)
	}
	summary := Summarize(findings)
	if summary.Findings != 3 || summary.BySeverity["critical"] != 1 {
		t.Fatalf("summary = %#v", summary)
	}
}

package compliance

import (
	"fmt"

	"network-compiler/internal/ir"
)

type Policy struct {
	RequiredNTPServers       []string `json:"required_ntp_servers,omitempty"`
	RequiredSyslogHosts      []string `json:"required_syslog_hosts,omitempty"`
	ForbiddenSNMPCommunities []string `json:"forbidden_snmp_communities,omitempty"`
}

type Finding struct {
	Severity string      `json:"severity"`
	Device   string      `json:"device"`
	Rule     string      `json:"rule"`
	Summary  string      `json:"summary"`
	Evidence ir.Evidence `json:"evidence,omitempty"`
}

type Summary struct {
	Findings   int            `json:"findings"`
	BySeverity map[string]int `json:"by_severity"`
	ByRule     map[string]int `json:"by_rule"`
}

func Check(devices []ir.Device, policy Policy) []Finding {
	var findings []Finding
	for _, dev := range devices {
		findings = append(findings, missingTargets(dev, "ntp", policy.RequiredNTPServers, dev.Services.NTPServers)...)
		findings = append(findings, missingTargets(dev, "syslog", policy.RequiredSyslogHosts, dev.Services.SyslogHosts)...)
		findings = append(findings, forbiddenTargets(dev, "snmp community", policy.ForbiddenSNMPCommunities, dev.Services.SNMPCommunities)...)
	}
	return findings
}

func Summarize(findings []Finding) Summary {
	s := Summary{
		Findings:   len(findings),
		BySeverity: make(map[string]int),
		ByRule:     make(map[string]int),
	}
	for _, finding := range findings {
		s.BySeverity[finding.Severity]++
		s.ByRule[finding.Rule]++
	}
	return s
}

func missingTargets(dev ir.Device, rule string, required []string, actual []ir.ServiceTarget) []Finding {
	var findings []Finding
	have := targetSet(actual)
	for _, want := range required {
		if !have[want] {
			findings = append(findings, Finding{
				Severity: "warning",
				Device:   dev.Hostname,
				Rule:     rule,
				Summary:  fmt.Sprintf("missing %s %s", rule, want),
				Evidence: dev.Evidence,
			})
		}
	}
	return findings
}

func forbiddenTargets(dev ir.Device, rule string, forbidden []string, actual []ir.ServiceTarget) []Finding {
	forbid := make(map[string]bool, len(forbidden))
	for _, item := range forbidden {
		forbid[item] = true
	}
	var findings []Finding
	for _, item := range actual {
		if forbid[item.Value] {
			findings = append(findings, Finding{
				Severity: "critical",
				Device:   dev.Hostname,
				Rule:     rule,
				Summary:  fmt.Sprintf("forbidden %s %s", rule, item.Value),
				Evidence: item.Evidence,
			})
		}
	}
	return findings
}

func targetSet(items []ir.ServiceTarget) map[string]bool {
	out := make(map[string]bool, len(items))
	for _, item := range items {
		out[item.Value] = true
	}
	return out
}

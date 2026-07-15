package query

import (
	"fmt"
	"strconv"
	"strings"

	"network-compiler/internal/ir"
)

type Result struct {
	Type     string      `json:"type"`
	Device   string      `json:"device"`
	Role     string      `json:"role,omitempty"`
	Summary  string      `json:"summary"`
	Object   any         `json:"object"`
	Evidence ir.Evidence `json:"evidence"`
}

func Run(input any, q string) ([]Result, error) {
	var devices []ir.Device
	switch v := input.(type) {
	case ir.Device:
		devices = []ir.Device{v}
	case []ir.Device:
		devices = v
	default:
		return nil, fmt.Errorf("type inventaire non supporte: %T", input)
	}

	pq, err := parseQuery(q)
	if err != nil {
		return nil, err
	}

	switch pq.Intent {
	case IntentHelp:
		return helpResults(), nil
	case IntentVLAN:
		return findVLANs(devices, vlanQuery{ID: pq.VLANID, Mode: pq.VLANMode}), nil
	}

	var out []Result
	for _, dev := range devices {
		results, err := runDevice(dev, pq)
		if err != nil {
			return nil, err
		}
		out = append(out, results...)
	}
	return out, nil
}

type vlanQuery struct {
	ID   int
	Mode string
}

func runDevice(dev ir.Device, pq parsedQuery) ([]Result, error) {
	switch pq.Intent {
	case IntentInterface:
		return findInterface(dev, pq.Name), nil
	case IntentDevice:
		return findDevice(dev, pq.Name), nil
	case IntentACL:
		return findACL(dev, pq.Name), nil
	case IntentTrunks:
		return findTrunks(dev), nil
	case IntentAccessVLAN:
		return findAccessVLAN(dev, strconv.Itoa(pq.VLANID))
	case IntentDefaultRoute:
		return findDefaultRoute(dev), nil
	case IntentRouteDst:
		return findRouteDst(dev, pq.RouteDest), nil
	case IntentNTP:
		return findNTP(dev), nil
	case IntentSyslog:
		return findSyslog(dev), nil
	case IntentSNMP:
		return findSNMP(dev), nil
	case IntentZones:
		return findZones(dev), nil
	case IntentPolicies:
		return findPolicies(dev), nil
	default:
		return nil, fmt.Errorf("intent interne non supporte")
	}
}

func helpResults() []Result {
	patterns := HelpPatterns()
	out := make([]Result, 0, len(patterns))
	for _, pattern := range patterns {
		out = append(out, Result{
			Type:    "help",
			Summary: pattern,
		})
	}
	return out
}

func findVLANs(devices []ir.Device, req vlanQuery) []Result {
	var access, trunks, broadTrunks, declared []Result
	for _, dev := range devices {
		for _, intf := range dev.Interfaces {
			switch classifyVLANInterface(intf, req.ID) {
			case "access":
				access = append(access, Result{Type: "interface", Device: dev.Hostname, Role: "access", Summary: fmt.Sprintf("%s access vlan %d", intf.Name, req.ID), Object: intf, Evidence: intf.Evidence})
			case "trunk":
				trunks = append(trunks, Result{Type: "interface", Device: dev.Hostname, Role: "trunk", Summary: fmt.Sprintf("%s trunk autorise explicitement vlan %d", intf.Name, req.ID), Object: intf, Evidence: intf.Evidence})
			case "trunk_broad":
				broadTrunks = append(broadTrunks, Result{Type: "interface", Device: dev.Hostname, Role: "trunk_broad", Summary: fmt.Sprintf("%s trunk autorise vlan %d via liste large/all", intf.Name, req.ID), Object: intf, Evidence: intf.Evidence})
			}
		}
		for _, vlan := range dev.VLANs {
			if vlan.ID == req.ID {
				declared = append(declared, Result{Type: "vlan", Device: dev.Hostname, Role: "declared", Summary: fmt.Sprintf("vlan %d declare %s", vlan.ID, vlan.Name), Object: vlan, Evidence: vlan.Evidence})
			}
		}
	}

	switch req.Mode {
	case "access":
		return access
	case "trunks":
		out := append([]Result{}, trunks...)
		return append(out, broadTrunks...)
	case "declared":
		return declared
	default:
		out := append([]Result{}, access...)
		out = append(out, trunks...)
		out = append(out, broadTrunks...)
		if len(out) > 0 {
			return out
		}
		return declared
	}
}

func classifyVLANInterface(intf ir.Interface, id int) string {
	if intf.Mode == "access" && intf.AccessVLAN == id {
		return "access"
	}
	if intf.Mode != "trunk" {
		return ""
	}
	if !trunkAllowsVLAN(intf, id) {
		return ""
	}
	if isBroadTrunkAllowance(intf, id) {
		return "trunk_broad"
	}
	return "trunk"
}

func trunkAllowsVLAN(intf ir.Interface, id int) bool {
	if contains(intf.TrunkVLANs, id) {
		return true
	}
	raw := strings.ToLower(intf.Evidence.RawBlock)
	return strings.Contains(raw, "allowed vlan all") || strings.Contains(raw, "allowed all")
}

func isBroadTrunkAllowance(intf ir.Interface, id int) bool {
	raw := strings.ToLower(intf.Evidence.RawBlock)
	if strings.Contains(raw, "allowed vlan all") || strings.Contains(raw, "allowed all") {
		return true
	}
	if len(intf.TrunkVLANs) >= 256 {
		return true
	}
	return rawHasWideRange(raw, id)
}

func rawHasWideRange(raw string, id int) bool {
	fields := strings.FieldsFunc(raw, func(r rune) bool {
		return r == ',' || r == ' ' || r == '\t'
	})
	for _, field := range fields {
		if !strings.Contains(field, "-") {
			continue
		}
		bounds := strings.SplitN(field, "-", 2)
		start, err1 := strconv.Atoi(strings.TrimSpace(bounds[0]))
		end, err2 := strconv.Atoi(strings.TrimSpace(bounds[1]))
		if err1 == nil && err2 == nil && start <= id && id <= end && end-start+1 >= 256 {
			return true
		}
	}
	return false
}

func findInterface(dev ir.Device, name string) []Result {
	var results []Result
	for _, intf := range dev.Interfaces {
		if strings.EqualFold(intf.Name, name) {
			results = append(results, Result{Type: "interface", Device: dev.Hostname, Summary: intf.Name, Object: intf, Evidence: intf.Evidence})
		}
	}
	return results
}

func findTrunks(dev ir.Device) []Result {
	var results []Result
	for _, intf := range dev.Interfaces {
		if intf.Mode == "trunk" {
			results = append(results, Result{Type: "interface", Device: dev.Hostname, Summary: fmt.Sprintf("%s trunk", intf.Name), Object: intf, Evidence: intf.Evidence})
		}
	}
	return results
}

func findAccessVLAN(dev ir.Device, idText string) ([]Result, error) {
	id, err := strconv.Atoi(idText)
	if err != nil {
		return nil, fmt.Errorf("vlan invalide: %q", idText)
	}
	var results []Result
	for _, intf := range dev.Interfaces {
		if intf.Mode == "access" && intf.AccessVLAN == id {
			results = append(results, Result{Type: "interface", Device: dev.Hostname, Summary: fmt.Sprintf("%s access vlan %d", intf.Name, id), Object: intf, Evidence: intf.Evidence})
		}
	}
	return results, nil
}

func findDefaultRoute(dev ir.Device) []Result {
	var results []Result
	for _, route := range dev.Routes {
		if route.Destination == "0.0.0.0 0.0.0.0" || route.Destination == "0.0.0.0/0" || route.Destination == "::/0" {
			results = append(results, Result{Type: "route", Device: dev.Hostname, Summary: fmt.Sprintf("default route via %s", route.NextHop), Object: route, Evidence: route.Evidence})
		}
	}
	return results
}

func findACL(dev ir.Device, name string) []Result {
	var results []Result
	for _, acl := range dev.ACLs {
		if strings.EqualFold(acl.Name, name) {
			results = append(results, Result{Type: "acl", Device: dev.Hostname, Summary: fmt.Sprintf("acl %s", acl.Name), Object: acl, Evidence: acl.Evidence})
		}
	}
	return results
}

func findDevice(dev ir.Device, hostname string) []Result {
	if strings.EqualFold(dev.Hostname, hostname) {
		return []Result{{Type: "device", Device: dev.Hostname, Summary: dev.Hostname, Object: dev, Evidence: dev.Evidence}}
	}
	return nil
}

func findNTP(dev ir.Device) []Result {
	var results []Result
	for _, target := range dev.Services.NTPServers {
		results = append(results, Result{
			Type:     "ntp",
			Device:   dev.Hostname,
			Summary:  fmt.Sprintf("ntp server %s", target.Value),
			Object:   target,
			Evidence: target.Evidence,
		})
	}
	return results
}

func findSyslog(dev ir.Device) []Result {
	var results []Result
	for _, target := range dev.Services.SyslogHosts {
		results = append(results, Result{
			Type:     "syslog",
			Device:   dev.Hostname,
			Summary:  fmt.Sprintf("syslog host %s", target.Value),
			Object:   target,
			Evidence: target.Evidence,
		})
	}
	return results
}

func findSNMP(dev ir.Device) []Result {
	var results []Result
	for _, target := range dev.Services.SNMPCommunities {
		results = append(results, Result{
			Type:     "snmp",
			Device:   dev.Hostname,
			Summary:  fmt.Sprintf("snmp community %s", target.Value),
			Object:   target,
			Evidence: target.Evidence,
		})
	}
	return results
}

func findZones(dev ir.Device) []Result {
	if len(dev.Zones) == 0 {
		return nil
	}
	var results []Result
	for _, zone := range dev.Zones {
		results = append(results, Result{
			Type:     "zone",
			Device:   dev.Hostname,
			Summary:  fmt.Sprintf("zone %s", zone.Name),
			Object:   zone,
			Evidence: zone.Evidence,
		})
	}
	return results
}

func findPolicies(dev ir.Device) []Result {
	var results []Result
	for _, policy := range dev.SecurityPolicies {
		results = append(results, Result{
			Type:     "policy",
			Device:   dev.Hostname,
			Summary:  fmt.Sprintf("policy %s action=%s", policy.Name, policy.Action),
			Object:   policy,
			Evidence: policy.Evidence,
		})
	}
	return results
}

func contains(items []int, want int) bool {
	for _, item := range items {
		if item == want {
			return true
		}
	}
	return false
}

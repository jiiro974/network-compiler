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

	var out []Result
	for _, dev := range devices {
		results, err := runDevice(dev, q)
		if err != nil {
			return nil, err
		}
		out = append(out, results...)
	}
	return out, nil
}

func runDevice(dev ir.Device, q string) ([]Result, error) {
	q = normalizeFindPrefix(q)
	fields := strings.Fields(strings.ToLower(strings.TrimSpace(q)))
	if len(fields) == 0 {
		return nil, fmt.Errorf("requete vide")
	}

	if len(fields) == 2 && fields[0] == "vlan" {
		return findVLAN(dev, fields[1])
	}
	if len(fields) == 2 && fields[0] == "interface" {
		return findInterface(dev, fields[1]), nil
	}
	if len(fields) == 2 && fields[0] == "device" {
		return findDevice(dev, fields[1]), nil
	}
	if len(fields) == 2 && fields[0] == "acl" {
		return findACL(dev, fields[1]), nil
	}
	if len(fields) == 2 && fields[0] == "interfaces" && fields[1] == "trunk" {
		return findTrunks(dev), nil
	}
	if len(fields) == 4 && fields[0] == "interfaces" && fields[1] == "access" && fields[2] == "vlan" {
		return findAccessVLAN(dev, fields[3])
	}
	if strings.Join(fields, " ") == "default route" {
		return findDefaultRoute(dev), nil
	}
	return nil, fmt.Errorf("requete non supportee: %q", q)
}

func normalizeFindPrefix(q string) string {
	fields := strings.Fields(q)
	if len(fields) > 0 && strings.EqualFold(fields[0], "find") {
		return strings.Join(fields[1:], " ")
	}
	return q
}

func findVLAN(dev ir.Device, idText string) ([]Result, error) {
	id, err := strconv.Atoi(idText)
	if err != nil {
		return nil, fmt.Errorf("vlan invalide: %q", idText)
	}
	var results []Result
	for _, vlan := range dev.VLANs {
		if vlan.ID == id {
			results = append(results, Result{Type: "vlan", Device: dev.Hostname, Summary: fmt.Sprintf("vlan %d %s", vlan.ID, vlan.Name), Object: vlan, Evidence: vlan.Evidence})
		}
	}
	for _, intf := range dev.Interfaces {
		if intf.AccessVLAN == id || contains(intf.TrunkVLANs, id) {
			results = append(results, Result{Type: "interface", Device: dev.Hostname, Summary: fmt.Sprintf("%s transporte vlan %d", intf.Name, id), Object: intf, Evidence: intf.Evidence})
		}
	}
	return results, nil
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
		if route.Destination == "0.0.0.0 0.0.0.0" {
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

func contains(items []int, want int) bool {
	for _, item := range items {
		if item == want {
			return true
		}
	}
	return false
}

package parser

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

var registry = map[string]Parser{}

func Register(vendor string, p Parser) {
	registry[normalizeVendor(vendor)] = p
}

func Get(vendor string) (Parser, bool) {
	p, ok := registry[normalizeVendor(vendor)]
	return p, ok
}

func Vendors() []string {
	vendors := make([]string, 0, len(registry))
	for vendor := range registry {
		vendors = append(vendors, vendor)
	}
	sort.Strings(vendors)
	return vendors
}

func Select(vendor, path string) (Parser, string, error) {
	resolvedVendor := normalizeVendor(vendor)
	if resolvedVendor == "auto" {
		var err error
		resolvedVendor, err = DetectVendor(path)
		if err != nil {
			return nil, "", err
		}
	}
	p, ok := Get(resolvedVendor)
	if !ok {
		return nil, "", fmt.Errorf("vendor non supporte: %s", resolvedVendor)
	}
	return p, resolvedVendor, nil
}

func DetectVendor(path string) (string, error) {
	if vendor := detectVendorFromPath(path); vendor != "" {
		return vendor, nil
	}
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "##") {
			continue
		}
		lower := strings.ToLower(line)
		switch {
		case strings.HasPrefix(lower, "/"):
			return "mikrotik-routeros", nil
		case strings.HasPrefix(lower, "config ") || strings.HasPrefix(lower, "edit "):
			return "fortinet-fortigate", nil
		case strings.HasPrefix(lower, "configure "):
			return "nokia-sros", nil
		case strings.HasPrefix(lower, "set "):
			if strings.Contains(lower, " rulebase ") || strings.Contains(lower, " zone ") || strings.Contains(lower, " network interface ") {
				return "paloalto-panos", nil
			}
			if strings.Contains(lower, " interfaces ethernet ") || strings.Contains(lower, " protocols static ") {
				return "vyos", nil
			}
			return "juniper", nil
		case strings.HasPrefix(lower, "sysname "):
			return "huawei-vrp", nil
		case strings.HasPrefix(lower, "hostname ") || strings.HasPrefix(lower, "version "):
			return "cisco", nil
		}
		return "cisco", nil
	}
	if err := scanner.Err(); err != nil {
		return "", err
	}
	return "cisco", nil
}

func detectVendorFromPath(path string) string {
	lower := strings.ToLower(filepath.ToSlash(path))
	known := []string{
		"arista-eos",
		"aruba-cx",
		"aruba-os-switch",
		"cisco-iosxr",
		"cisco-nxos",
		"extreme-exos",
		"fortinet-fortigate",
		"fs-fsos",
		"hpe-comware",
		"hpe-procurve",
		"huawei-vrp",
		"juniper-junos",
		"mikrotik-routeros",
		"nokia-sros",
		"paloalto-panos",
		"ubiquiti-edgeos",
		"vyos",
	}
	for _, vendor := range known {
		if strings.Contains(lower, "/"+vendor+"/") || strings.Contains(lower, vendor) {
			if vendor == "juniper-junos" {
				return "juniper"
			}
			return vendor
		}
	}
	return ""
}

func normalizeVendor(vendor string) string {
	return strings.ToLower(strings.TrimSpace(vendor))
}

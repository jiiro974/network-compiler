package parser

import (
	"bufio"
	"fmt"
	"os"
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
		if strings.HasPrefix(line, "set ") {
			return "juniper", nil
		}
		return "cisco", nil
	}
	if err := scanner.Err(); err != nil {
		return "", err
	}
	return "cisco", nil
}

func normalizeVendor(vendor string) string {
	return strings.ToLower(strings.TrimSpace(vendor))
}

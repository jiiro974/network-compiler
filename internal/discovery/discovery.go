package discovery

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"network-compiler/internal/ir"
	"network-compiler/internal/secretredact"
)

const parserVersion = "discovery-cisco-v0"

type Result struct {
	Neighbors []ir.Neighbor
	Addresses []ir.Address
	Devices   map[string]bool
}

type metadata struct {
	Hostname string `json:"hostname"`
	Vendor   string `json:"vendor"`
}

type commandFile struct {
	Name    string
	Command string
	Kind    string
	Parse   func(device, path string, lines []line) Result
}

type line struct {
	Num  int
	Text string
}

var commandFiles = []commandFile{
	{Name: "show-lldp-neighbors-detail.txt", Command: "show lldp neighbors detail", Kind: "lldp", Parse: parseLLDP},
	{Name: "show-cdp-neighbors-detail.txt", Command: "show cdp neighbors detail", Kind: "cdp", Parse: parseCDP},
	{Name: "show-arp.txt", Command: "show arp", Kind: "arp", Parse: parseARP},
	{Name: "show-mac-address-table.txt", Command: "show mac address-table", Kind: "mac", Parse: parseMACAddressTable},
	{Name: "show-ip-interface-brief.txt", Command: "show ip interface brief", Kind: "interface_ip", Parse: parseIPInterfaceBrief},
	{Name: "show-running-config.txt", Command: "show running-config", Kind: "running_config", Parse: parseRunningConfig},
}

var commandsByKind = map[string]string{
	"lldp":                  "show lldp neighbors detail",
	"cdp":                   "show cdp neighbors detail",
	"arp":                   "show arp",
	"mac_table":             "show mac address-table",
	"interface_ip":          "show ip interface brief",
	"config_ip":             "show running-config",
	"interface_description": "show running-config",
}

func ParseDir(root string) (Result, error) {
	entries, err := os.ReadDir(root)
	if err != nil {
		return Result{}, err
	}
	out := Result{Devices: map[string]bool{}}
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		deviceDir := filepath.Join(root, entry.Name())
		device, err := deviceName(deviceDir, entry.Name())
		if err != nil {
			return Result{}, err
		}
		out.Devices[device] = true
		for _, cf := range commandFiles {
			path := filepath.Join(deviceDir, cf.Name)
			lines, err := readLines(path)
			if os.IsNotExist(err) {
				continue
			}
			if err != nil {
				return Result{}, err
			}
			part := cf.Parse(device, path, lines)
			out.Neighbors = append(out.Neighbors, part.Neighbors...)
			out.Addresses = append(out.Addresses, part.Addresses...)
		}
	}
	sortNeighbors(out.Neighbors)
	sortAddresses(out.Addresses)
	return out, nil
}

func Facts(result Result) []ir.DiscoveryFact {
	facts := make([]ir.DiscoveryFact, 0, len(result.Neighbors)+len(result.Addresses))
	for _, n := range result.Neighbors {
		nn := n
		facts = append(facts, ir.DiscoveryFact{
			Type:       "neighbor",
			Neighbor:   &nn,
			Source:     nn.Source,
			Evidence:   nn.Evidence,
			Confidence: nn.Confidence,
			Status:     nn.Status,
		})
	}
	for _, a := range result.Addresses {
		aa := a
		facts = append(facts, ir.DiscoveryFact{
			Type:       "address",
			Address:    &aa,
			Source:     aa.Source,
			Evidence:   aa.Evidence,
			Confidence: aa.Confidence,
			Status:     aa.Status,
		})
	}
	return facts
}

func deviceName(dir, fallback string) (string, error) {
	path := filepath.Join(dir, "metadata.json")
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return fallback, nil
	}
	if err != nil {
		return "", err
	}
	var md metadata
	if err := json.Unmarshal(data, &md); err != nil {
		return "", fmt.Errorf("%s: %w", path, err)
	}
	if strings.TrimSpace(md.Hostname) == "" {
		return fallback, nil
	}
	return strings.TrimSpace(md.Hostname), nil
}

func readLines(path string) ([]line, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var lines []line
	scanner := bufio.NewScanner(f)
	for n := 1; scanner.Scan(); n++ {
		lines = append(lines, line{Num: n, Text: scanner.Text()})
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return lines, nil
}

func parseLLDP(device, path string, lines []line) Result {
	blocks := splitBlocks(lines, func(s string) bool {
		return strings.HasPrefix(strings.ToLower(strings.TrimSpace(s)), "local intf:")
	})
	var out Result
	for _, block := range blocks {
		local := fieldValue(block, "Local Intf:")
		remote := firstNonEmpty(fieldValue(block, "System Name:"), fieldValue(block, "Chassis id:"))
		remoteIntf := fieldValue(block, "Port id:")
		if local == "" || remote == "" {
			continue
		}
		out.Neighbors = append(out.Neighbors, neighbor(device, path, block, "lldp", local, remote, remoteIntf, fieldValue(block, "System Description:"), fieldValue(block, "System Capabilities:")))
	}
	return out
}

func parseCDP(device, path string, lines []line) Result {
	blocks := splitBlocks(lines, func(s string) bool {
		return strings.HasPrefix(strings.ToLower(strings.TrimSpace(s)), "device id:")
	})
	var out Result
	for _, block := range blocks {
		remote := fieldValue(block, "Device ID:")
		local, remoteIntf := parseCDPInterfaces(fieldValue(block, "Interface:"))
		if local == "" || remote == "" {
			continue
		}
		out.Neighbors = append(out.Neighbors, neighbor(device, path, block, "cdp", local, remote, remoteIntf, fieldValue(block, "Platform:"), fieldValue(block, "Capabilities:")))
	}
	return out
}

func parseARP(device, path string, lines []line) Result {
	var out Result
	for _, ln := range lines {
		fields := strings.Fields(ln.Text)
		if len(fields) < 6 || strings.ToLower(fields[0]) != "internet" {
			continue
		}
		vlan := vlanFromInterface(fields[5])
		out.Addresses = append(out.Addresses, address(device, path, []line{ln}, "arp", fields[5], fields[1], fields[3], vlan, 0.65))
	}
	return out
}

func parseMACAddressTable(device, path string, lines []line) Result {
	var out Result
	for _, ln := range lines {
		fields := strings.Fields(ln.Text)
		if len(fields) < 4 {
			continue
		}
		vlan, err := strconv.Atoi(fields[0])
		if err != nil || !looksLikeMAC(fields[1]) {
			continue
		}
		out.Addresses = append(out.Addresses, address(device, path, []line{ln}, "mac_table", fields[len(fields)-1], "", fields[1], vlan, 0.55))
	}
	return out
}

func parseIPInterfaceBrief(device, path string, lines []line) Result {
	var out Result
	for _, ln := range lines {
		fields := strings.Fields(ln.Text)
		if len(fields) < 2 || strings.EqualFold(fields[0], "Interface") || fields[1] == "unassigned" {
			continue
		}
		out.Addresses = append(out.Addresses, address(device, path, []line{ln}, "interface_ip", fields[0], fields[1], "", vlanFromInterface(fields[0]), 0.75))
	}
	return out
}

func parseRunningConfig(device, path string, lines []line) Result {
	var out Result
	for i := 0; i < len(lines); i++ {
		trimmed := strings.TrimSpace(lines[i].Text)
		if !strings.HasPrefix(trimmed, "interface ") {
			continue
		}
		block, next := collectConfigBlock(lines, i)
		local := strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(block[0].Text), "interface "))
		for _, ln := range block[1:] {
			text := strings.TrimSpace(ln.Text)
			switch {
			case strings.HasPrefix(text, "description "):
				remoteDevice, remoteInterface := parseDescriptionEndpoint(strings.TrimSpace(strings.TrimPrefix(text, "description ")))
				if remoteDevice != "" && remoteInterface != "" {
					out.Neighbors = append(out.Neighbors, neighbor(device, path, block, "interface_description", local, remoteDevice, remoteInterface, "", ""))
				}
			case strings.HasPrefix(text, "ip address "):
				fields := strings.Fields(text)
				if len(fields) >= 3 && fields[2] != "dhcp" {
					out.Addresses = append(out.Addresses, address(device, path, []line{ln}, "config_ip", local, fields[2], "", vlanFromInterface(local), 0.7))
				}
			}
		}
		i = next - 1
	}
	return out
}

func splitBlocks(lines []line, starts func(string) bool) [][]line {
	var blocks [][]line
	var current []line
	for _, ln := range lines {
		if starts(ln.Text) && len(current) > 0 {
			blocks = append(blocks, current)
			current = nil
		}
		if strings.TrimSpace(ln.Text) == "" && len(current) == 0 {
			continue
		}
		current = append(current, ln)
	}
	if len(current) > 0 {
		blocks = append(blocks, current)
	}
	return blocks
}

func collectConfigBlock(lines []line, start int) ([]line, int) {
	block := []line{lines[start]}
	for i := start + 1; i < len(lines); i++ {
		trimmed := strings.TrimSpace(lines[i].Text)
		if trimmed == "!" {
			block = append(block, lines[i])
			return block, i + 1
		}
		if lines[i].Text != "" && !strings.HasPrefix(lines[i].Text, " ") && !strings.HasPrefix(lines[i].Text, "\t") {
			return block, i
		}
		block = append(block, lines[i])
	}
	return block, len(lines)
}

func fieldValue(block []line, prefix string) string {
	for _, ln := range block {
		text := strings.TrimSpace(ln.Text)
		if strings.HasPrefix(strings.ToLower(text), strings.ToLower(prefix)) {
			return strings.TrimSpace(strings.TrimPrefix(text, prefix))
		}
	}
	return ""
}

func parseDescriptionEndpoint(description string) (string, string) {
	fields := strings.Fields(description)
	for i := 0; i < len(fields); i++ {
		if strings.EqualFold(fields[i], "to") && i+2 < len(fields) && looksLikeInterface(fields[i+2]) {
			return trimEndpointToken(fields[i+1]), trimEndpointToken(fields[i+2])
		}
		if looksLikeInterface(fields[i]) && i > 0 {
			return trimEndpointToken(fields[i-1]), trimEndpointToken(fields[i])
		}
	}
	return "", ""
}

func parseCDPInterfaces(value string) (string, string) {
	parts := strings.Split(value, ",")
	if len(parts) == 0 {
		return "", ""
	}
	local := strings.TrimSpace(parts[0])
	remote := ""
	for _, part := range parts[1:] {
		part = strings.TrimSpace(part)
		if strings.HasPrefix(strings.ToLower(part), "port id") {
			if idx := strings.Index(part, ":"); idx >= 0 {
				remote = strings.TrimSpace(part[idx+1:])
			}
		}
	}
	return local, remote
}

func neighbor(device, path string, block []line, protocol, local, remote, remoteIntf, platform, capability string) ir.Neighbor {
	confidence := 0.8
	if protocol == "interface_description" {
		confidence = 0.35
	}
	return ir.Neighbor{
		LocalDevice:     device,
		LocalInterface:  normalizeInterface(local),
		RemoteDevice:    strings.TrimSpace(remote),
		RemoteInterface: normalizeInterface(remoteIntf),
		Protocol:        protocol,
		Platform:        strings.TrimSpace(platform),
		Capability:      strings.TrimSpace(capability),
		Evidence:        evidence(path, block),
		Source:          source(device, protocol, path),
		Confidence:      confidence,
		Status:          ir.StatusCandidate,
	}
}

func address(device, path string, block []line, kind, intf, ip, mac string, vlan int, confidence float64) ir.Address {
	return ir.Address{
		Device:     device,
		Interface:  normalizeInterface(intf),
		IP:         ip,
		MAC:        strings.ToLower(mac),
		VLAN:       vlan,
		Kind:       kind,
		Evidence:   evidence(path, block),
		Source:     source(device, kind, path),
		Confidence: confidence,
		Status:     ir.StatusCandidate,
	}
}

func evidence(path string, block []line) ir.Evidence {
	raw := make([]string, 0, len(block))
	for _, ln := range block {
		raw = append(raw, secretredact.Redact(ln.Text))
	}
	return ir.Evidence{
		File:      path,
		StartLine: block[0].Num,
		EndLine:   block[len(block)-1].Num,
		RawBlock:  strings.Join(raw, "\n"),
		Parser:    parserVersion,
	}
}

func source(device, kind, path string) ir.Source {
	command := commandsByKind[kind]
	if command == "" {
		command = kind
	}
	return ir.Source{Device: device, Command: command, Kind: kind, File: path}
}

func normalizeInterface(s string) string {
	s = strings.TrimSpace(s)
	replacements := []struct{ old, new string }{
		{"GigabitEthernet", "Gi"},
		{"TenGigabitEthernet", "Te"},
		{"FastEthernet", "Fa"},
		{"Ethernet", "Eth"},
	}
	for _, repl := range replacements {
		if strings.HasPrefix(s, repl.old) {
			return repl.new + strings.TrimPrefix(s, repl.old)
		}
	}
	return s
}

func vlanFromInterface(s string) int {
	s = strings.TrimSpace(s)
	if !strings.HasPrefix(strings.ToLower(s), "vlan") {
		return 0
	}
	id, _ := strconv.Atoi(strings.TrimSpace(s[4:]))
	return id
}

func looksLikeMAC(s string) bool {
	return strings.Count(s, ".") == 2 || strings.Count(s, ":") == 5 || strings.Count(s, "-") == 5
}

func looksLikeInterface(s string) bool {
	s = trimEndpointToken(s)
	for _, prefix := range []string{"Gi", "GigabitEthernet", "Te", "TenGigabitEthernet", "Fa", "FastEthernet", "Eth", "Ethernet"} {
		if strings.HasPrefix(s, prefix) && strings.Contains(s, "/") {
			return true
		}
	}
	return false
}

func trimEndpointToken(s string) string {
	return strings.Trim(s, " ,;()[]")
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

func sortNeighbors(items []ir.Neighbor) {
	sort.Slice(items, func(i, j int) bool {
		a, b := items[i], items[j]
		return strings.Join([]string{a.LocalDevice, a.LocalInterface, a.Protocol, a.RemoteDevice, a.RemoteInterface}, "\x00") <
			strings.Join([]string{b.LocalDevice, b.LocalInterface, b.Protocol, b.RemoteDevice, b.RemoteInterface}, "\x00")
	})
}

func sortAddresses(items []ir.Address) {
	sort.Slice(items, func(i, j int) bool {
		a, b := items[i], items[j]
		return strings.Join([]string{a.Device, a.Interface, a.Kind, a.IP, a.MAC}, "\x00") <
			strings.Join([]string{b.Device, b.Interface, b.Kind, b.IP, b.MAC}, "\x00")
	})
}

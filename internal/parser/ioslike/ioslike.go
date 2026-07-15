package ioslike

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"

	"network-compiler/internal/ir"
	"network-compiler/internal/secretredact"
)

type Parser struct {
	vendor        string
	parserVersion string
}

type line struct {
	num  int
	text string
}

func New(vendor string) Parser {
	vendor = strings.ToLower(strings.TrimSpace(vendor))
	if vendor == "" {
		vendor = "ios-like"
	}
	return Parser{vendor: vendor, parserVersion: "ioslike-" + vendor + "-v0"}
}

func (p Parser) ParseFile(path string) (ir.Device, error) {
	lines, err := readLines(path)
	if err != nil {
		return ir.Device{}, err
	}

	dev := ir.Device{
		Vendor:        p.vendor,
		SourceFile:    path,
		ParserVersion: p.parserVersion,
	}
	seenVLANs := map[int]bool{}

	for i := 0; i < len(lines); i++ {
		trimmed := strings.TrimSpace(lines[i].text)
		switch {
		case strings.HasPrefix(trimmed, "hostname "):
			dev.Hostname = strings.TrimSpace(strings.TrimPrefix(trimmed, "hostname "))
			dev.Evidence = p.evidence(path, lines[i].num, lines[i].num, lines[i:i+1])
		case strings.HasPrefix(trimmed, "interface "):
			block, next := collectBlock(lines, i)
			intf, vlans := p.parseInterface(path, block)
			dev.Interfaces = append(dev.Interfaces, intf)
			for _, vlan := range vlans {
				if !seenVLANs[vlan.ID] {
					dev.VLANs = append(dev.VLANs, vlan)
					seenVLANs[vlan.ID] = true
				}
			}
			i = next - 1
		case trimmed == "vlan database":
			block, next := collectBlock(lines, i)
			for _, vlan := range p.parseVLANDatabase(path, block) {
				if !seenVLANs[vlan.ID] {
					dev.VLANs = append(dev.VLANs, vlan)
					seenVLANs[vlan.ID] = true
				}
			}
			i = next - 1
		case strings.HasPrefix(trimmed, "vlan "):
			block, next := collectBlock(lines, i)
			if vlan, ok := p.parseVLAN(path, block); ok && !seenVLANs[vlan.ID] {
				dev.VLANs = append(dev.VLANs, vlan)
				seenVLANs[vlan.ID] = true
			}
			i = next - 1
		case strings.HasPrefix(trimmed, "ip route "):
			if route, ok := p.parseIPRoute(path, lines[i]); ok {
				dev.Routes = append(dev.Routes, route)
			}
		case strings.HasPrefix(trimmed, "router static"):
			block, next := collectBlock(lines, i)
			dev.Routes = append(dev.Routes, p.parseRouterStatic(path, block)...)
			i = next - 1
		case strings.HasPrefix(trimmed, "ntp server "):
			dev.Services.NTPServers = append(dev.Services.NTPServers, p.serviceTarget(path, lines[i], firstFieldAfter(trimmed, "ntp server ")))
		case strings.HasPrefix(trimmed, "sntp server "):
			dev.Services.NTPServers = append(dev.Services.NTPServers, p.serviceTarget(path, lines[i], firstFieldAfter(trimmed, "sntp server ")))
		case strings.HasPrefix(trimmed, "logging host "):
			dev.Services.SyslogHosts = append(dev.Services.SyslogHosts, p.serviceTarget(path, lines[i], firstFieldAfter(trimmed, "logging host ")))
		case strings.HasPrefix(trimmed, "logging server "):
			dev.Services.SyslogHosts = append(dev.Services.SyslogHosts, p.serviceTarget(path, lines[i], firstFieldAfter(trimmed, "logging server ")))
		case strings.HasPrefix(trimmed, "logging "):
			if host := firstFieldAfter(trimmed, "logging "); looksLikeIPv4(host) {
				dev.Services.SyslogHosts = append(dev.Services.SyslogHosts, p.serviceTarget(path, lines[i], host))
			}
		case strings.HasPrefix(trimmed, "snmp-server "):
			p.parseSNMP(path, lines[i], &dev)
		}
	}

	return dev, nil
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
		lines = append(lines, line{num: n, text: scanner.Text()})
	}
	return lines, scanner.Err()
}

func collectBlock(lines []line, start int) ([]line, int) {
	block := []line{lines[start]}
	for i := start + 1; i < len(lines); i++ {
		trimmed := strings.TrimSpace(lines[i].text)
		if trimmed == "!" {
			block = append(block, lines[i])
			return block, i + 1
		}
		if lines[i].text != "" && !strings.HasPrefix(lines[i].text, " ") && !strings.HasPrefix(lines[i].text, "\t") {
			return block, i
		}
		block = append(block, lines[i])
	}
	return block, len(lines)
}

func (p Parser) parseInterface(path string, block []line) (ir.Interface, []ir.VLAN) {
	name := strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(block[0].text), "interface "))
	intf := ir.Interface{Name: name, Mode: "unknown", Evidence: p.evidence(path, block[0].num, block[len(block)-1].num, block)}
	var vlans []ir.VLAN

	for _, ln := range block[1:] {
		t := strings.TrimSpace(ln.text)
		switch {
		case strings.HasPrefix(t, "description "):
			intf.Description = strings.TrimSpace(strings.TrimPrefix(t, "description "))
		case t == "shutdown":
			intf.Shutdown = true
		case t == "no shutdown":
			intf.Shutdown = false
		case t == "switchport mode access":
			intf.Mode = "access"
		case t == "switchport mode trunk":
			intf.Mode = "trunk"
		case strings.HasPrefix(t, "switchport access vlan "):
			intf.Mode = "access"
			intf.AccessVLAN = parseInt(firstFieldAfter(t, "switchport access vlan "))
		case strings.HasPrefix(t, "switchport trunk allowed only "):
			intf.Mode = "trunk"
			intf.TrunkVLANs = parseVLANList(strings.TrimSpace(strings.TrimPrefix(t, "switchport trunk allowed only ")))
		case strings.HasPrefix(t, "switchport trunk allowed vlan "):
			intf.Mode = "trunk"
			intf.TrunkVLANs = parseVLANList(strings.TrimSpace(strings.TrimPrefix(t, "switchport trunk allowed vlan ")))
		case strings.HasPrefix(t, "vlan access "):
			intf.Mode = "access"
			intf.AccessVLAN = parseInt(firstFieldAfter(t, "vlan access "))
		case strings.HasPrefix(t, "vlan trunk allowed "):
			intf.Mode = "trunk"
			intf.TrunkVLANs = parseVLANList(strings.TrimSpace(strings.TrimPrefix(t, "vlan trunk allowed ")))
		case strings.HasPrefix(t, "ip address "):
			intf.Mode = "routed"
			intf.IPv4 = strings.TrimSpace(strings.TrimPrefix(t, "ip address "))
		case strings.HasPrefix(t, "ipv4 address "):
			intf.Mode = "routed"
			intf.IPv4 = strings.TrimSpace(strings.TrimPrefix(t, "ipv4 address "))
		case strings.HasPrefix(t, "encapsulation dot1q "):
			id := parseInt(firstFieldAfter(t, "encapsulation dot1q "))
			if id > 0 {
				intf.AccessVLAN = id
				vlans = append(vlans, ir.VLAN{ID: id, Evidence: p.evidence(path, ln.num, ln.num, []line{ln})})
			}
		}
	}
	return intf, vlans
}

func (p Parser) parseVLAN(path string, block []line) (ir.VLAN, bool) {
	idText := firstFieldAfter(strings.TrimSpace(block[0].text), "vlan ")
	id, err := strconv.Atoi(idText)
	if err != nil {
		return ir.VLAN{}, false
	}
	vlan := ir.VLAN{ID: id, Evidence: p.evidence(path, block[0].num, block[len(block)-1].num, block)}
	for _, ln := range block[1:] {
		t := strings.TrimSpace(ln.text)
		if strings.HasPrefix(t, "name ") {
			vlan.Name = strings.TrimSpace(strings.TrimPrefix(t, "name "))
		}
	}
	return vlan, true
}

func (p Parser) parseVLANDatabase(path string, block []line) []ir.VLAN {
	var vlans []ir.VLAN
	for _, ln := range block[1:] {
		fields := strings.Fields(strings.TrimSpace(ln.text))
		if len(fields) < 2 || fields[0] != "vlan" {
			continue
		}
		id, err := strconv.Atoi(fields[1])
		if err != nil {
			continue
		}
		vlan := ir.VLAN{ID: id, Evidence: p.evidence(path, ln.num, ln.num, []line{ln})}
		for i := 2; i+1 < len(fields); i++ {
			if fields[i] == "name" {
				vlan.Name = strings.Join(fields[i+1:], " ")
				break
			}
		}
		vlans = append(vlans, vlan)
	}
	return vlans
}

func (p Parser) parseIPRoute(path string, ln line) (ir.Route, bool) {
	fields := strings.Fields(strings.TrimSpace(ln.text))
	if len(fields) < 4 || fields[0] != "ip" || fields[1] != "route" {
		return ir.Route{}, false
	}
	route := ir.Route{Evidence: p.evidence(path, ln.num, ln.num, []line{ln})}
	if strings.Contains(fields[2], "/") {
		route.Destination = fields[2]
		route.NextHop = fields[3]
		if len(fields) >= 5 {
			route.AdministrativeDistance = fields[4]
		}
		return route, true
	}
	if len(fields) < 5 {
		return ir.Route{}, false
	}
	route.Destination = fmt.Sprintf("%s %s", fields[2], fields[3])
	if looksLikeIPv4(fields[4]) {
		route.NextHop = fields[4]
		if len(fields) >= 6 {
			route.AdministrativeDistance = fields[5]
		}
		return route, true
	}
	route.Interface = fields[4]
	if len(fields) >= 6 {
		route.NextHop = fields[5]
	}
	if len(fields) >= 7 {
		route.AdministrativeDistance = fields[6]
	}
	return route, true
}

func (p Parser) parseRouterStatic(path string, block []line) []ir.Route {
	var routes []ir.Route
	for _, ln := range block[1:] {
		fields := strings.Fields(strings.TrimSpace(ln.text))
		if len(fields) < 2 || !strings.Contains(fields[0], "/") || !looksLikeIPv4(fields[1]) {
			continue
		}
		routes = append(routes, ir.Route{
			Destination: fields[0],
			NextHop:     fields[1],
			Evidence:    p.evidence(path, ln.num, ln.num, []line{ln}),
		})
	}
	return routes
}

func (p Parser) parseSNMP(path string, ln line, dev *ir.Device) {
	fields := strings.Fields(strings.TrimSpace(ln.text))
	if len(fields) < 2 || fields[0] != "snmp-server" {
		return
	}
	ev := p.evidence(path, ln.num, ln.num, []line{ln})
	dev.SNMP.Statements = append(dev.SNMP.Statements, ir.RawStatement{
		Kind:     fields[1],
		Fields:   append([]string(nil), fields[2:]...),
		Raw:      secretredact.Redact(ln.text),
		Evidence: ev,
	})
	if fields[1] != "community" || len(fields) < 3 {
		return
	}
	valueIndex := 2
	if fields[2] == "0" && len(fields) >= 4 {
		valueIndex = 3
	}
	target := ir.ServiceTarget{Value: fields[valueIndex], Evidence: ev}
	dev.SNMP.Communities = append(dev.SNMP.Communities, target)
	dev.Services.SNMPCommunities = append(dev.Services.SNMPCommunities, target)
}

func (p Parser) evidence(path string, start, end int, lines []line) ir.Evidence {
	raw := make([]string, 0, len(lines))
	for _, ln := range lines {
		raw = append(raw, secretredact.Redact(ln.text))
	}
	return ir.Evidence{File: path, StartLine: start, EndLine: end, RawBlock: strings.Join(raw, "\n"), Parser: p.parserVersion}
}

func (p Parser) serviceTarget(path string, ln line, value string) ir.ServiceTarget {
	return ir.ServiceTarget{Value: value, Evidence: p.evidence(path, ln.num, ln.num, []line{ln})}
}

func firstFieldAfter(s, prefix string) string {
	fields := strings.Fields(strings.TrimSpace(strings.TrimPrefix(s, prefix)))
	if len(fields) == 0 {
		return ""
	}
	return fields[0]
}

func parseInt(s string) int {
	id, _ := strconv.Atoi(s)
	return id
}

func parseVLANList(s string) []int {
	var out []int
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if strings.Contains(part, "-") {
			bounds := strings.SplitN(part, "-", 2)
			start, err1 := strconv.Atoi(strings.TrimSpace(bounds[0]))
			end, err2 := strconv.Atoi(strings.TrimSpace(bounds[1]))
			if err1 == nil && err2 == nil && start <= end {
				for id := start; id <= end; id++ {
					out = append(out, id)
				}
			}
			continue
		}
		if id, err := strconv.Atoi(part); err == nil {
			out = append(out, id)
		}
	}
	return out
}

func looksLikeIPv4(s string) bool {
	parts := strings.Split(s, ".")
	if len(parts) != 4 {
		return false
	}
	for _, part := range parts {
		if part == "" {
			return false
		}
		for _, r := range part {
			if r < '0' || r > '9' {
				return false
			}
		}
	}
	return true
}

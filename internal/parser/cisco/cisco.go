package cisco

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"

	"network-compiler/internal/ir"
	"network-compiler/internal/secretredact"
)

const parserVersion = "cisco-ios-v0"

type Parser struct{}

func New() Parser {
	return Parser{}
}

type line struct {
	num  int
	text string
}

func (Parser) ParseFile(path string) (ir.Device, error) {
	f, err := os.Open(path)
	if err != nil {
		return ir.Device{}, err
	}
	defer f.Close()

	var lines []line
	scanner := bufio.NewScanner(f)
	for n := 1; scanner.Scan(); n++ {
		lines = append(lines, line{num: n, text: scanner.Text()})
	}
	if err := scanner.Err(); err != nil {
		return ir.Device{}, err
	}

	dev := ir.Device{
		Vendor:        "cisco",
		SourceFile:    path,
		ParserVersion: parserVersion,
	}

	for i := 0; i < len(lines); i++ {
		trimmed := strings.TrimSpace(lines[i].text)
		switch {
		case strings.HasPrefix(trimmed, "hostname "):
			dev.Hostname = strings.TrimSpace(strings.TrimPrefix(trimmed, "hostname "))
			dev.Evidence = evidence(path, lines[i].num, lines[i].num, lines[i:i+1])
		case strings.HasPrefix(trimmed, "interface "):
			block, next := collectBlock(lines, i)
			dev.Interfaces = append(dev.Interfaces, parseInterface(path, block))
			i = next - 1
		case strings.HasPrefix(trimmed, "vlan "):
			block, next := collectBlock(lines, i)
			if vlan, ok := parseVLAN(path, block); ok {
				dev.VLANs = append(dev.VLANs, vlan)
			}
			i = next - 1
		case strings.HasPrefix(trimmed, "ip access-list "):
			block, next := collectBlock(lines, i)
			if acl, ok := parseNamedACL(path, block); ok {
				dev.ACLs = append(dev.ACLs, acl)
			}
			i = next - 1
		case strings.HasPrefix(trimmed, "ip route "):
			if route, ok := parseRoute(path, lines[i]); ok {
				dev.Routes = append(dev.Routes, route)
			}
		case strings.HasPrefix(trimmed, "access-list "):
			dev.ACLs = appendACL(path, dev.ACLs, lines[i])
		case strings.HasPrefix(trimmed, "ntp server "):
			dev.Services.NTPServers = append(dev.Services.NTPServers, serviceTarget(path, lines[i], strings.TrimSpace(strings.TrimPrefix(trimmed, "ntp server "))))
		case strings.HasPrefix(trimmed, "logging host "):
			dev.Services.SyslogHosts = append(dev.Services.SyslogHosts, serviceTarget(path, lines[i], strings.TrimSpace(strings.TrimPrefix(trimmed, "logging host "))))
		case strings.HasPrefix(trimmed, "snmp-server community "):
			parseSNMP(path, lines[i], &dev)
		case strings.HasPrefix(trimmed, "snmp-server "):
			parseSNMP(path, lines[i], &dev)
		}
	}

	return dev, nil
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

func parseInterface(path string, block []line) ir.Interface {
	name := strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(block[0].text), "interface "))
	intf := ir.Interface{Name: name, Mode: "unknown", Evidence: evidence(path, block[0].num, block[len(block)-1].num, block)}
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
			intf.AccessVLAN, _ = strconv.Atoi(strings.TrimSpace(strings.TrimPrefix(t, "switchport access vlan ")))
		case strings.HasPrefix(t, "switchport trunk allowed vlan "):
			intf.TrunkVLANs = parseVLANList(strings.TrimSpace(strings.TrimPrefix(t, "switchport trunk allowed vlan ")))
		case strings.HasPrefix(t, "ip address "):
			intf.Mode = "routed"
			intf.IPv4 = strings.TrimSpace(strings.TrimPrefix(t, "ip address "))
		}
	}
	return intf
}

func parseVLAN(path string, block []line) (ir.VLAN, bool) {
	idText := strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(block[0].text), "vlan "))
	id, err := strconv.Atoi(idText)
	if err != nil {
		return ir.VLAN{}, false
	}
	vlan := ir.VLAN{ID: id, Evidence: evidence(path, block[0].num, block[len(block)-1].num, block)}
	for _, ln := range block[1:] {
		t := strings.TrimSpace(ln.text)
		if strings.HasPrefix(t, "name ") {
			vlan.Name = strings.TrimSpace(strings.TrimPrefix(t, "name "))
		}
	}
	return vlan, true
}

func parseRoute(path string, ln line) (ir.Route, bool) {
	fields := strings.Fields(ln.text)
	if len(fields) < 5 || fields[0] != "ip" || fields[1] != "route" {
		return ir.Route{}, false
	}
	route := ir.Route{
		Destination: fmt.Sprintf("%s %s", fields[2], fields[3]),
		Evidence:    evidence(path, ln.num, ln.num, []line{ln}),
	}
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

func appendACL(path string, acls []ir.ACL, ln line) []ir.ACL {
	fields := strings.Fields(ln.text)
	if len(fields) < 4 {
		return acls
	}
	name := fields[1]
	entry := ir.ACLEntry{Action: fields[2], Raw: secretredact.Redact(ln.text), Evidence: evidence(path, ln.num, ln.num, []line{ln})}
	if isIPACLProtocol(fields[3]) {
		entry.Protocol = fields[3]
		entry.Match = strings.Join(fields[4:], " ")
	} else {
		entry.Match = strings.Join(fields[3:], " ")
	}
	for i := range acls {
		if acls[i].Name == name {
			acls[i].Entries = append(acls[i].Entries, entry)
			acls[i].Evidence.EndLine = ln.num
			acls[i].Evidence.RawBlock += "\n" + entry.Raw
			return acls
		}
	}
	return append(acls, ir.ACL{Name: name, Entries: []ir.ACLEntry{entry}, Evidence: entry.Evidence})
}

func parseNamedACL(path string, block []line) (ir.ACL, bool) {
	fields := strings.Fields(strings.TrimSpace(block[0].text))
	if len(fields) < 4 || fields[0] != "ip" || fields[1] != "access-list" {
		return ir.ACL{}, false
	}
	acl := ir.ACL{
		Name:     fields[3],
		Evidence: evidence(path, block[0].num, block[len(block)-1].num, block),
	}
	for _, ln := range block[1:] {
		entry, ok := parseNamedACLEntry(path, ln)
		if ok {
			acl.Entries = append(acl.Entries, entry)
		}
	}
	return acl, true
}

func parseNamedACLEntry(path string, ln line) (ir.ACLEntry, bool) {
	fields := strings.Fields(strings.TrimSpace(ln.text))
	if len(fields) == 0 {
		return ir.ACLEntry{}, false
	}
	if _, err := strconv.Atoi(fields[0]); err == nil {
		fields = fields[1:]
	}
	if len(fields) == 0 || (fields[0] != "permit" && fields[0] != "deny") {
		return ir.ACLEntry{}, false
	}
	entry := ir.ACLEntry{
		Action:   fields[0],
		Raw:      secretredact.Redact(ln.text),
		Evidence: evidence(path, ln.num, ln.num, []line{ln}),
	}
	if len(fields) > 1 && isIPACLProtocol(fields[1]) {
		entry.Protocol = fields[1]
		entry.Match = strings.Join(fields[2:], " ")
	} else if len(fields) > 1 {
		entry.Match = strings.Join(fields[1:], " ")
	}
	return entry, true
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
		id, err := strconv.Atoi(part)
		if err == nil {
			out = append(out, id)
		}
	}
	return out
}

func evidence(path string, start, end int, lines []line) ir.Evidence {
	raw := make([]string, 0, len(lines))
	for _, ln := range lines {
		raw = append(raw, secretredact.Redact(ln.text))
	}
	return ir.Evidence{File: path, StartLine: start, EndLine: end, RawBlock: strings.Join(raw, "\n"), Parser: parserVersion}
}

func serviceTarget(path string, ln line, value string) ir.ServiceTarget {
	return ir.ServiceTarget{Value: value, Evidence: evidence(path, ln.num, ln.num, []line{ln})}
}

func parseSNMP(path string, ln line, dev *ir.Device) {
	fields := strings.Fields(strings.TrimSpace(ln.text))
	if len(fields) < 2 || fields[0] != "snmp-server" {
		return
	}
	ev := evidence(path, ln.num, ln.num, []line{ln})
	dev.SNMP.Statements = append(dev.SNMP.Statements, ir.RawStatement{
		Kind:     fields[1],
		Fields:   append([]string(nil), fields[2:]...),
		Raw:      secretredact.Redact(ln.text),
		Evidence: ev,
	})
	switch fields[1] {
	case "community":
		if len(fields) >= 3 {
			target := ir.ServiceTarget{Value: fields[2], Evidence: ev}
			dev.SNMP.Communities = append(dev.SNMP.Communities, target)
			dev.Services.SNMPCommunities = append(dev.Services.SNMPCommunities, target)
		}
	case "host":
		host := parseSNMPHost(fields, ev)
		if host.Host != "" {
			dev.SNMP.Hosts = append(dev.SNMP.Hosts, host)
			if host.Community != "" {
				dev.Services.SNMPCommunities = append(dev.Services.SNMPCommunities, ir.ServiceTarget{Value: host.Community, Evidence: ev})
			}
		}
	case "enable":
		if len(fields) >= 4 && fields[2] == "traps" {
			trap := ir.SNMPTrap{Name: fields[3], Evidence: ev}
			if len(fields) > 4 {
				trap.Options = append([]string(nil), fields[4:]...)
			}
			dev.SNMP.Traps = append(dev.SNMP.Traps, trap)
		}
	case "location":
		dev.SNMP.Location = ir.ServiceTarget{Value: strings.Join(fields[2:], " "), Evidence: ev}
	case "contact":
		dev.SNMP.Contact = ir.ServiceTarget{Value: strings.Join(fields[2:], " "), Evidence: ev}
	}
}

func parseSNMPHost(fields []string, ev ir.Evidence) ir.SNMPHost {
	host := ir.SNMPHost{Evidence: ev}
	if len(fields) < 3 {
		return host
	}
	host.Host = fields[2]
	var preVersionOptions []string
	for i := 3; i < len(fields); i++ {
		if fields[i] == "version" && i+1 < len(fields) {
			host.Version = fields[i+1]
			host.Options = append(host.Options, preVersionOptions...)
			i++
			if i+1 < len(fields) {
				host.Community = fields[i+1]
				if i+2 < len(fields) {
					host.Options = append(host.Options, fields[i+2:]...)
				}
				return host
			}
			return host
		}
		preVersionOptions = append(preVersionOptions, fields[i])
	}
	if len(fields) > 3 {
		host.Community = fields[3]
		if len(fields) > 4 {
			host.Options = append([]string(nil), fields[4:]...)
		}
	}
	return host
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

func isIPACLProtocol(s string) bool {
	switch s {
	case "ip", "icmp", "tcp", "udp", "gre", "esp", "ah", "eigrp", "ospf":
		return true
	default:
		return false
	}
}

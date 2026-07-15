package setform

import (
	"bufio"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"

	"network-compiler/internal/ir"
	"network-compiler/internal/secretredact"
	"network-compiler/internal/syntax"
)

type Parser struct {
	vendor        string
	parserVersion string
}

type line struct {
	num  int
	text string
}

type ifaceBuild struct {
	iface     ir.Interface
	evidence  []line
	firstLine int
	lastLine  int
}

type routeBuild struct {
	name      string
	route     ir.Route
	evidence  []line
	firstLine int
	lastLine  int
}

type zoneBuild struct {
	zone      ir.Zone
	evidence  []line
	firstLine int
	lastLine  int
}

type policyBuild struct {
	policy    ir.SecurityPolicy
	evidence  []line
	firstLine int
	lastLine  int
}

type natBuild struct {
	rule      ir.NATRule
	evidence  []line
	firstLine int
	lastLine  int
}

func NewVendor(vendor string) Parser {
	return Parser{vendor: vendor, parserVersion: vendor + "-set-v0"}
}

func (p Parser) ParseFile(path string) (ir.Device, error) {
	lines, err := readLines(path)
	if err != nil {
		return ir.Device{}, err
	}
	dev := ir.Device{Vendor: p.vendor, SourceFile: path, ParserVersion: p.parserVersion}
	ifaces := map[string]*ifaceBuild{}
	vlans := map[int]ir.VLAN{}
	routes := map[string]*routeBuild{}
	zones := map[string]*zoneBuild{}
	policies := map[string]*policyBuild{}
	nats := map[string]*natBuild{}

	for _, ln := range lines {
		fields := syntax.Fields(strings.TrimSpace(ln.text))
		if len(fields) == 0 || fields[0] != "set" {
			continue
		}
		switch p.vendor {
		case "vyos", "ubiquiti-edgeos":
			p.parseVyatta(path, ln, fields, &dev, ifaces, vlans)
		case "paloalto-panos":
			p.parsePANOS(path, ln, fields, &dev, ifaces, vlans, routes, zones, policies, nats)
		}
	}

	dev.VLANs = sortedVLANs(vlans)
	dev.Interfaces = sortedInterfaces(path, p.parserVersion, ifaces)
	dev.Routes = append(dev.Routes, sortedRoutes(path, p.parserVersion, routes)...)
	dev.Zones = sortedZones(path, p.parserVersion, zones)
	dev.SecurityPolicies = sortedPolicies(path, p.parserVersion, policies)
	dev.NATRules = sortedNATRules(path, p.parserVersion, nats)
	return dev, nil
}

func (p Parser) parseVyatta(path string, ln line, fields []string, dev *ir.Device, ifaces map[string]*ifaceBuild, vlans map[int]ir.VLAN) {
	switch {
	case len(fields) >= 4 && fields[1] == "system" && fields[2] == "host-name":
		dev.Hostname = fields[3]
		dev.Evidence = p.evidence(path, ln.num, ln.num, []line{ln})
	case len(fields) >= 5 && fields[1] == "system" && fields[2] == "ntp" && fields[3] == "server":
		dev.Services.NTPServers = append(dev.Services.NTPServers, p.serviceTarget(path, ln, fields[4]))
	case len(fields) >= 5 && fields[1] == "system" && fields[2] == "syslog" && fields[3] == "host":
		dev.Services.SyslogHosts = append(dev.Services.SyslogHosts, p.serviceTarget(path, ln, fields[4]))
	case len(fields) >= 5 && fields[1] == "service" && fields[2] == "snmp" && fields[3] == "community":
		dev.Services.SNMPCommunities = append(dev.Services.SNMPCommunities, p.serviceTarget(path, ln, fields[4]))
	case len(fields) >= 5 && fields[1] == "interfaces" && fields[2] == "ethernet":
		p.parseVyattaInterface(path, ln, fields, ifaces, vlans)
	case len(fields) >= 7 && fields[1] == "protocols" && fields[2] == "static" && fields[3] == "route" && fields[5] == "next-hop":
		dev.Routes = append(dev.Routes, ir.Route{Destination: fields[4], NextHop: fields[6], Evidence: p.evidence(path, ln.num, ln.num, []line{ln})})
	}
}

func (p Parser) parseVyattaInterface(path string, ln line, fields []string, ifaces map[string]*ifaceBuild, vlans map[int]ir.VLAN) {
	base := fields[3]
	name := base
	idx := 4
	if len(fields) >= 6 && fields[4] == "vif" {
		id, err := strconv.Atoi(fields[5])
		if err != nil {
			return
		}
		name = fmt.Sprintf("%s.%d", base, id)
		idx = 6
		if _, ok := vlans[id]; !ok {
			vlans[id] = ir.VLAN{ID: id, Evidence: p.evidence(path, ln.num, ln.num, []line{ln})}
		}
	}
	item := ensureInterface(ifaces, name, ln)
	item.evidence = append(item.evidence, ln)
	item.lastLine = ln.num
	switch {
	case idx < len(fields) && fields[idx] == "description":
		item.iface.Description = strings.Join(fields[idx+1:], " ")
	case idx < len(fields) && fields[idx] == "disable":
		item.iface.Shutdown = true
	case idx < len(fields) && fields[idx] == "address":
		item.iface.Mode = "routed"
		item.iface.IPv4 = fields[idx+1]
	case strings.Contains(name, "."):
		item.iface.Mode = "vlan"
	}
}

func (p Parser) parsePANOS(path string, ln line, fields []string, dev *ir.Device, ifaces map[string]*ifaceBuild, vlans map[int]ir.VLAN, routes map[string]*routeBuild, zones map[string]*zoneBuild, policies map[string]*policyBuild, nats map[string]*natBuild) {
	switch {
	case len(fields) >= 5 && fields[1] == "deviceconfig" && fields[2] == "system" && fields[3] == "hostname":
		dev.Hostname = fields[4]
		dev.Evidence = p.evidence(path, ln.num, ln.num, []line{ln})
	case len(fields) >= 7 && fields[1] == "deviceconfig" && fields[2] == "system" && fields[3] == "ntp-servers" && fields[len(fields)-2] == "ntp-server-address":
		dev.Services.NTPServers = append(dev.Services.NTPServers, p.serviceTarget(path, ln, fields[len(fields)-1]))
	case len(fields) >= 7 && fields[1] == "deviceconfig" && fields[2] == "system" && fields[3] == "snmp-setting":
		dev.Services.SNMPCommunities = append(dev.Services.SNMPCommunities, p.serviceTarget(path, ln, fields[len(fields)-1]))
	case len(fields) >= 5 && fields[1] == "shared" && fields[2] == "log-settings" && fields[3] == "syslog":
		if idx := lastIndexOf(fields, "server"); idx >= 0 && idx+1 < len(fields) {
			dev.Services.SyslogHosts = append(dev.Services.SyslogHosts, p.serviceTarget(path, ln, fields[idx+1]))
		}
	case len(fields) >= 7 && fields[1] == "network" && fields[2] == "interface" && fields[3] == "ethernet":
		p.parsePANOSInterface(path, ln, fields, ifaces, vlans)
	case len(fields) >= 10 && fields[1] == "network" && fields[2] == "virtual-router":
		p.parsePANOSRoute(ln, fields, routes)
	case len(fields) >= 6 && fields[1] == "zone":
		p.parsePANOSZone(ln, fields, zones)
	case len(fields) >= 6:
		if idx := indexOf(fields, "security"); idx >= 0 {
			p.parsePANOSPolicy(ln, fields, idx, policies)
		}
		if idx := indexOf(fields, "nat"); idx >= 0 {
			p.parsePANOSNAT(ln, fields, idx, nats)
		}
	}
}

func (p Parser) parsePANOSInterface(path string, ln line, fields []string, ifaces map[string]*ifaceBuild, vlans map[int]ir.VLAN) {
	name := fields[4]
	if idx := indexOf(fields, "units"); idx >= 0 && idx+1 < len(fields) {
		name = fields[idx+1]
	}
	item := ensureInterface(ifaces, name, ln)
	item.evidence = append(item.evidence, ln)
	item.lastLine = ln.num
	if idx := indexOf(fields, "comment"); idx >= 0 && idx+1 < len(fields) {
		item.iface.Description = strings.Join(fields[idx+1:], " ")
	}
	if idx := indexOf(fields, "ip"); idx >= 0 && idx+1 < len(fields) {
		item.iface.Mode = "routed"
		item.iface.IPv4 = fields[idx+1]
	}
	if idx := indexOf(fields, "tag"); idx >= 0 && idx+1 < len(fields) {
		if id, err := strconv.Atoi(fields[idx+1]); err == nil {
			item.iface.AccessVLAN = id
			vlans[id] = ir.VLAN{ID: id, Evidence: p.evidence(path, ln.num, ln.num, []line{ln})}
		}
	}
	if item.iface.Mode == "unknown" && strings.Contains(name, ".") {
		item.iface.Mode = "vlan"
	}
}

func (p Parser) parsePANOSRoute(ln line, fields []string, routes map[string]*routeBuild) {
	idx := indexOf(fields, "static-route")
	if idx < 0 || idx+2 >= len(fields) {
		return
	}
	name := fields[idx+1]
	item := routes[name]
	if item == nil {
		item = &routeBuild{name: name, firstLine: ln.num, lastLine: ln.num}
		routes[name] = item
	}
	item.evidence = append(item.evidence, ln)
	item.lastLine = ln.num
	item.route.VRF = fields[3]
	switch fields[idx+2] {
	case "destination":
		if idx+3 < len(fields) {
			item.route.Destination = fields[idx+3]
		}
	case "nexthop":
		if idx+4 < len(fields) && fields[idx+3] == "ip-address" {
			item.route.NextHop = fields[idx+4]
		}
	}
}

func (p Parser) parsePANOSZone(ln line, fields []string, zones map[string]*zoneBuild) {
	name := fields[2]
	item := zones[name]
	if item == nil {
		item = &zoneBuild{zone: ir.Zone{Name: name}, firstLine: ln.num, lastLine: ln.num}
		zones[name] = item
	}
	item.evidence = append(item.evidence, ln)
	item.lastLine = ln.num
	if idx := indexOf(fields, "layer3"); idx >= 0 {
		for _, field := range fields[idx+1:] {
			if field == "[" || field == "]" {
				continue
			}
			item.zone.Interfaces = appendUnique(item.zone.Interfaces, field)
		}
	}
}

func (p Parser) parsePANOSPolicy(ln line, fields []string, idx int, policies map[string]*policyBuild) {
	if idx+2 >= len(fields) || fields[idx+1] != "rules" {
		return
	}
	name := fields[idx+2]
	item := policies[name]
	if item == nil {
		item = &policyBuild{policy: ir.SecurityPolicy{Name: name}, firstLine: ln.num, lastLine: ln.num}
		policies[name] = item
	}
	item.evidence = append(item.evidence, ln)
	item.lastLine = ln.num
	if idx+3 >= len(fields) {
		return
	}
	value := ""
	if idx+4 < len(fields) {
		value = joinSetValues(fields[idx+4:])
	}
	switch fields[idx+3] {
	case "from":
		item.policy.FromZone = value
	case "to":
		item.policy.ToZone = value
	case "application":
		item.policy.Application = value
	case "service":
		item.policy.Service = value
	case "action":
		item.policy.Action = value
	}
}

func (p Parser) parsePANOSNAT(ln line, fields []string, idx int, nats map[string]*natBuild) {
	if idx+2 >= len(fields) || fields[idx+1] != "rules" {
		return
	}
	name := fields[idx+2]
	item := nats[name]
	if item == nil {
		item = &natBuild{rule: ir.NATRule{Name: name}, firstLine: ln.num, lastLine: ln.num}
		nats[name] = item
	}
	item.evidence = append(item.evidence, ln)
	item.lastLine = ln.num
	if idx+3 >= len(fields) {
		return
	}
	value := ""
	if idx+4 < len(fields) {
		value = joinSetValues(fields[idx+4:])
	}
	switch fields[idx+3] {
	case "from":
		item.rule.FromZone = value
	case "to":
		item.rule.ToZone = value
	case "source-translation":
		item.rule.Kind = "source"
		if translated := valueAfter(fields[idx+4:], "translated-address"); translated != "" {
			item.rule.Translated = translated
		}
	case "destination-translation":
		item.rule.Kind = "destination"
		if translated := valueAfter(fields[idx+4:], "translated-address"); translated != "" {
			item.rule.Translated = translated
		}
	}
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

func ensureInterface(ifaces map[string]*ifaceBuild, name string, ln line) *ifaceBuild {
	item := ifaces[name]
	if item == nil {
		item = &ifaceBuild{iface: ir.Interface{Name: name, Mode: "unknown"}, firstLine: ln.num, lastLine: ln.num}
		ifaces[name] = item
	}
	return item
}

func sortedInterfaces(path, parserVersion string, ifaces map[string]*ifaceBuild) []ir.Interface {
	names := make([]string, 0, len(ifaces))
	for name := range ifaces {
		names = append(names, name)
	}
	sort.Slice(names, func(i, j int) bool { return ifaces[names[i]].firstLine < ifaces[names[j]].firstLine })
	out := make([]ir.Interface, 0, len(names))
	for _, name := range names {
		item := ifaces[name]
		item.iface.Evidence = makeEvidence(path, parserVersion, item.firstLine, item.lastLine, item.evidence)
		out = append(out, item.iface)
	}
	return out
}

func sortedVLANs(vlans map[int]ir.VLAN) []ir.VLAN {
	ids := make([]int, 0, len(vlans))
	for id := range vlans {
		ids = append(ids, id)
	}
	sort.Ints(ids)
	out := make([]ir.VLAN, 0, len(ids))
	for _, id := range ids {
		out = append(out, vlans[id])
	}
	return out
}

func sortedRoutes(path, parserVersion string, routes map[string]*routeBuild) []ir.Route {
	names := make([]string, 0, len(routes))
	for name := range routes {
		names = append(names, name)
	}
	sort.Slice(names, func(i, j int) bool { return routes[names[i]].firstLine < routes[names[j]].firstLine })
	out := make([]ir.Route, 0, len(names))
	for _, name := range names {
		item := routes[name]
		if item.route.Destination == "" || item.route.NextHop == "" {
			continue
		}
		item.route.Evidence = makeEvidence(path, parserVersion, item.firstLine, item.lastLine, item.evidence)
		out = append(out, item.route)
	}
	return out
}

func sortedZones(path, parserVersion string, zones map[string]*zoneBuild) []ir.Zone {
	names := make([]string, 0, len(zones))
	for name := range zones {
		names = append(names, name)
	}
	sort.Slice(names, func(i, j int) bool { return zones[names[i]].firstLine < zones[names[j]].firstLine })
	out := make([]ir.Zone, 0, len(names))
	for _, name := range names {
		item := zones[name]
		item.zone.Evidence = makeEvidence(path, parserVersion, item.firstLine, item.lastLine, item.evidence)
		out = append(out, item.zone)
	}
	return out
}

func sortedPolicies(path, parserVersion string, policies map[string]*policyBuild) []ir.SecurityPolicy {
	names := make([]string, 0, len(policies))
	for name := range policies {
		names = append(names, name)
	}
	sort.Slice(names, func(i, j int) bool { return policies[names[i]].firstLine < policies[names[j]].firstLine })
	out := make([]ir.SecurityPolicy, 0, len(names))
	for _, name := range names {
		item := policies[name]
		if item.policy.Action == "" {
			continue
		}
		item.policy.Evidence = makeEvidence(path, parserVersion, item.firstLine, item.lastLine, item.evidence)
		out = append(out, item.policy)
	}
	return out
}

func sortedNATRules(path, parserVersion string, nats map[string]*natBuild) []ir.NATRule {
	names := make([]string, 0, len(nats))
	for name := range nats {
		names = append(names, name)
	}
	sort.Slice(names, func(i, j int) bool { return nats[names[i]].firstLine < nats[names[j]].firstLine })
	out := make([]ir.NATRule, 0, len(names))
	for _, name := range names {
		item := nats[name]
		if item.rule.Kind == "" {
			continue
		}
		item.rule.Evidence = makeEvidence(path, parserVersion, item.firstLine, item.lastLine, item.evidence)
		out = append(out, item.rule)
	}
	return out
}

func (p Parser) evidence(path string, start, end int, lines []line) ir.Evidence {
	return makeEvidence(path, p.parserVersion, start, end, lines)
}

func makeEvidence(path, parserVersion string, start, end int, lines []line) ir.Evidence {
	raw := make([]string, 0, len(lines))
	for _, ln := range lines {
		raw = append(raw, secretredact.Redact(ln.text))
	}
	return ir.Evidence{File: path, StartLine: start, EndLine: end, RawBlock: strings.Join(raw, "\n"), Parser: parserVersion}
}

func (p Parser) serviceTarget(path string, ln line, value string) ir.ServiceTarget {
	return ir.ServiceTarget{Value: value, Evidence: p.evidence(path, ln.num, ln.num, []line{ln})}
}

func indexOf(fields []string, want string) int {
	for i, field := range fields {
		if field == want {
			return i
		}
	}
	return -1
}

func lastIndexOf(fields []string, want string) int {
	for i := len(fields) - 1; i >= 0; i-- {
		if fields[i] == want {
			return i
		}
	}
	return -1
}

func appendUnique(items []string, item string) []string {
	for _, existing := range items {
		if existing == item {
			return items
		}
	}
	return append(items, item)
}

func joinSetValues(fields []string) string {
	var values []string
	for _, field := range fields {
		if field == "[" || field == "]" {
			continue
		}
		values = append(values, field)
	}
	return strings.Join(values, " ")
}

func valueAfter(fields []string, key string) string {
	for i, field := range fields {
		if field == key && i+1 < len(fields) {
			return fields[i+1]
		}
	}
	return ""
}

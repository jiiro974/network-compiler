package fortios

import (
	"bufio"
	"fmt"
	"math/bits"
	"net"
	"os"
	"sort"
	"strconv"
	"strings"

	"network-compiler/internal/ir"
	"network-compiler/internal/secretredact"
	"network-compiler/internal/syntax"
)

const parserVersion = "fortinet-fortigate-fortios-v0"

type Parser struct{}

type line struct {
	num  int
	text string
}

type ifaceBuild struct {
	iface     ir.Interface
	vlanID    int
	parent    string
	evidence  []line
	firstLine int
	lastLine  int
}

type routeBuild struct {
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
	srcIntfs  []string
	dstIntfs  []string
	evidence  []line
	firstLine int
	lastLine  int
}

func New() Parser {
	return Parser{}
}

func (Parser) ParseFile(path string) (ir.Device, error) {
	lines, err := readLines(path)
	if err != nil {
		return ir.Device{}, err
	}
	dev := ir.Device{Vendor: "fortinet-fortigate", SourceFile: path, ParserVersion: parserVersion}
	ifaces := map[string]*ifaceBuild{}
	routes := map[string]*routeBuild{}
	zones := map[string]*zoneBuild{}
	policies := map[string]*policyBuild{}
	vlans := map[int]ir.VLAN{}
	var stack []string
	var currentEdit string

	for _, ln := range lines {
		fields := syntax.Fields(strings.TrimSpace(ln.text))
		if len(fields) == 0 || strings.HasPrefix(fields[0], "#") {
			continue
		}
		switch fields[0] {
		case "config":
			stack = append(stack, strings.Join(fields[1:], " "))
			currentEdit = ""
		case "edit":
			if len(fields) > 1 {
				currentEdit = fields[1]
				switch currentSection(stack) {
				case "system interface":
					ensureInterface(ifaces, currentEdit, ln)
				case "router static":
					ensureRoute(routes, currentEdit, ln)
				case "system zone":
					ensureZone(zones, currentEdit, ln)
				case "firewall policy":
					ensurePolicy(policies, currentEdit, ln)
				}
			}
		case "set":
			parseSet(path, ln, fields, currentSection(stack), currentEdit, &dev, ifaces, routes, zones, policies, vlans)
		case "next":
			currentEdit = ""
		case "end":
			if len(stack) > 0 {
				stack = stack[:len(stack)-1]
			}
			currentEdit = ""
		}
	}

	dev.VLANs = sortedVLANs(vlans)
	dev.Interfaces = sortedInterfaces(path, ifaces)
	dev.Routes = sortedRoutes(path, routes)
	dev.Zones = sortedZones(path, zones)
	dev.SecurityPolicies = sortedPolicies(path, zones, policies)
	return dev, nil
}

func parseSet(path string, ln line, fields []string, section, currentEdit string, dev *ir.Device, ifaces map[string]*ifaceBuild, routes map[string]*routeBuild, zones map[string]*zoneBuild, policies map[string]*policyBuild, vlans map[int]ir.VLAN) {
	if len(fields) < 3 {
		return
	}
	key := fields[1]
	switch section {
	case "system global":
		if key == "hostname" {
			dev.Hostname = fields[2]
			dev.Evidence = evidence(path, ln.num, ln.num, []line{ln})
		}
	case "ntpserver":
		if key == "server" {
			dev.Services.NTPServers = append(dev.Services.NTPServers, serviceTarget(path, ln, fields[2]))
		}
	case "system snmp community":
		if key == "name" {
			dev.Services.SNMPCommunities = append(dev.Services.SNMPCommunities, serviceTarget(path, ln, fields[2]))
		}
	case "hosts":
		if key == "ip" {
			dev.SNMP.Hosts = append(dev.SNMP.Hosts, ir.SNMPHost{Host: fields[2], Evidence: evidence(path, ln.num, ln.num, []line{ln})})
		}
	case "system interface":
		item := ensureInterface(ifaces, currentEdit, ln)
		addEvidence(item, ln)
		switch key {
		case "alias":
			item.iface.Description = strings.Join(fields[2:], " ")
		case "ip":
			if len(fields) >= 4 {
				item.iface.Mode = "routed"
				item.iface.IPv4 = fmt.Sprintf("%s/%d", fields[2], maskToPrefix(fields[3]))
			}
		case "status":
			item.iface.Shutdown = fields[2] == "down"
		case "type":
			if fields[2] == "vlan" {
				item.iface.Mode = "routed"
			}
		case "vlanid":
			id, _ := strconv.Atoi(fields[2])
			item.vlanID = id
			item.iface.AccessVLAN = id
			if id != 0 {
				vlans[id] = ir.VLAN{ID: id, Evidence: evidence(path, ln.num, ln.num, []line{ln})}
			}
		case "interface":
			item.parent = fields[2]
		}
	case "router static":
		item := ensureRoute(routes, currentEdit, ln)
		addRouteEvidence(item, ln)
		switch key {
		case "dst":
			if len(fields) >= 4 {
				item.route.Destination = fmt.Sprintf("%s/%d", fields[2], maskToPrefix(fields[3]))
			}
		case "gateway":
			item.route.NextHop = fields[2]
		case "device":
			item.route.Interface = fields[2]
		}
	case "system zone":
		item := ensureZone(zones, currentEdit, ln)
		addZoneEvidence(item, ln)
		if key == "interface" {
			for _, iface := range fields[2:] {
				item.zone.Interfaces = appendUnique(item.zone.Interfaces, iface)
			}
		}
	case "firewall policy":
		item := ensurePolicy(policies, currentEdit, ln)
		addPolicyEvidence(item, ln)
		switch key {
		case "name":
			item.policy.Name = strings.Join(fields[2:], " ")
		case "srcintf":
			item.srcIntfs = appendUniqueAll(item.srcIntfs, fields[2:]...)
		case "dstintf":
			item.dstIntfs = appendUniqueAll(item.dstIntfs, fields[2:]...)
		case "action":
			item.policy.Action = fields[2]
		case "service":
			item.policy.Service = strings.Join(fields[2:], " ")
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

func currentSection(stack []string) string {
	if len(stack) == 0 {
		return ""
	}
	return stack[len(stack)-1]
}

func ensureInterface(ifaces map[string]*ifaceBuild, name string, ln line) *ifaceBuild {
	item := ifaces[name]
	if item == nil {
		item = &ifaceBuild{iface: ir.Interface{Name: name, Mode: "unknown"}, firstLine: ln.num, lastLine: ln.num}
		ifaces[name] = item
	}
	return item
}

func ensureRoute(routes map[string]*routeBuild, name string, ln line) *routeBuild {
	item := routes[name]
	if item == nil {
		item = &routeBuild{firstLine: ln.num, lastLine: ln.num}
		routes[name] = item
	}
	return item
}

func ensureZone(zones map[string]*zoneBuild, name string, ln line) *zoneBuild {
	item := zones[name]
	if item == nil {
		item = &zoneBuild{zone: ir.Zone{Name: name}, firstLine: ln.num, lastLine: ln.num}
		zones[name] = item
	}
	return item
}

func ensurePolicy(policies map[string]*policyBuild, name string, ln line) *policyBuild {
	item := policies[name]
	if item == nil {
		item = &policyBuild{policy: ir.SecurityPolicy{Name: name}, firstLine: ln.num, lastLine: ln.num}
		policies[name] = item
	}
	return item
}

func addEvidence(item *ifaceBuild, ln line) {
	item.evidence = append(item.evidence, ln)
	item.lastLine = ln.num
}

func addRouteEvidence(item *routeBuild, ln line) {
	item.evidence = append(item.evidence, ln)
	item.lastLine = ln.num
}

func addZoneEvidence(item *zoneBuild, ln line) {
	item.evidence = append(item.evidence, ln)
	item.lastLine = ln.num
}

func addPolicyEvidence(item *policyBuild, ln line) {
	item.evidence = append(item.evidence, ln)
	item.lastLine = ln.num
}

func sortedInterfaces(path string, ifaces map[string]*ifaceBuild) []ir.Interface {
	names := make([]string, 0, len(ifaces))
	for name := range ifaces {
		names = append(names, name)
	}
	sort.Slice(names, func(i, j int) bool { return ifaces[names[i]].firstLine < ifaces[names[j]].firstLine })
	out := make([]ir.Interface, 0, len(names))
	for _, name := range names {
		item := ifaces[name]
		item.iface.Evidence = evidence(path, item.firstLine, item.lastLine, item.evidence)
		out = append(out, item.iface)
	}
	return out
}

func sortedRoutes(path string, routes map[string]*routeBuild) []ir.Route {
	names := make([]string, 0, len(routes))
	for name := range routes {
		names = append(names, name)
	}
	sort.Slice(names, func(i, j int) bool { return routes[names[i]].firstLine < routes[names[j]].firstLine })
	out := make([]ir.Route, 0, len(names))
	for _, name := range names {
		item := routes[name]
		item.route.Evidence = evidence(path, item.firstLine, item.lastLine, item.evidence)
		out = append(out, item.route)
	}
	return out
}

func sortedZones(path string, zones map[string]*zoneBuild) []ir.Zone {
	names := make([]string, 0, len(zones))
	for name := range zones {
		names = append(names, name)
	}
	sort.Slice(names, func(i, j int) bool { return zones[names[i]].firstLine < zones[names[j]].firstLine })
	out := make([]ir.Zone, 0, len(names))
	for _, name := range names {
		item := zones[name]
		item.zone.Evidence = evidence(path, item.firstLine, item.lastLine, item.evidence)
		out = append(out, item.zone)
	}
	return out
}

func sortedPolicies(path string, zones map[string]*zoneBuild, policies map[string]*policyBuild) []ir.SecurityPolicy {
	lookup := ifaceToZone(zones)
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
		if item.policy.Name == "" {
			item.policy.Name = name
		}
		item.policy.FromZone = zoneForInterfaces(item.srcIntfs, lookup)
		item.policy.ToZone = zoneForInterfaces(item.dstIntfs, lookup)
		item.policy.Evidence = evidence(path, item.firstLine, item.lastLine, item.evidence)
		out = append(out, item.policy)
	}
	return out
}

func ifaceToZone(zones map[string]*zoneBuild) map[string]string {
	out := map[string]string{}
	for _, item := range zones {
		for _, iface := range item.zone.Interfaces {
			out[iface] = item.zone.Name
		}
	}
	return out
}

func zoneForInterfaces(intfs []string, lookup map[string]string) string {
	for _, iface := range intfs {
		if zone, ok := lookup[iface]; ok {
			return zone
		}
	}
	return ""
}

func appendUnique(items []string, item string) []string {
	for _, existing := range items {
		if existing == item {
			return items
		}
	}
	return append(items, item)
}

func appendUniqueAll(items []string, add ...string) []string {
	for _, item := range add {
		items = appendUnique(items, item)
	}
	return items
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

func maskToPrefix(mask string) int {
	ip := net.ParseIP(mask).To4()
	if ip == nil {
		return 0
	}
	return bits.OnesCount32(uint32(ip[0])<<24 | uint32(ip[1])<<16 | uint32(ip[2])<<8 | uint32(ip[3]))
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

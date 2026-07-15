package sros

import (
	"bufio"
	"os"
	"sort"
	"strconv"
	"strings"

	"network-compiler/internal/ir"
	"network-compiler/internal/secretredact"
	"network-compiler/internal/syntax"
)

const parserVersion = "nokia-sros-classic-v0"

type Parser struct{}

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

func New() Parser {
	return Parser{}
}

func (Parser) ParseFile(path string) (ir.Device, error) {
	lines, err := readLines(path)
	if err != nil {
		return ir.Device{}, err
	}
	dev := ir.Device{Vendor: "nokia-sros", SourceFile: path, ParserVersion: parserVersion}
	ifaces := map[string]*ifaceBuild{}
	vlans := map[int]ir.VLAN{}

	for _, ln := range lines {
		fields := syntax.Fields(strings.TrimSpace(ln.text))
		if len(fields) == 0 || fields[0] != "configure" {
			continue
		}
		switch {
		case len(fields) >= 4 && fields[1] == "system" && fields[2] == "name":
			dev.Hostname = fields[3]
			dev.Evidence = evidence(path, ln.num, ln.num, []line{ln})
		case len(fields) >= 5 && fields[1] == "system" && fields[2] == "snmp" && fields[3] == "community":
			dev.Services.SNMPCommunities = append(dev.Services.SNMPCommunities, serviceTarget(path, ln, fields[4]))
		case len(fields) >= 6 && fields[1] == "system" && fields[2] == "time" && fields[3] == "ntp" && fields[4] == "server":
			dev.Services.NTPServers = append(dev.Services.NTPServers, serviceTarget(path, ln, fields[5]))
		case len(fields) >= 3 && fields[1] == "port":
			parsePort(path, ln, fields, ifaces)
		case len(fields) >= 4 && fields[1] == "router" && fields[2] == "interface":
			parseRouterInterface(path, ln, fields, ifaces)
		case len(fields) >= 4 && fields[1] == "service" && fields[2] == "vpls":
			parseVPLS(path, ln, fields, vlans)
		case len(fields) >= 6 && fields[1] == "router" && fields[2] == "static-route-entry":
			if route, ok := parseRoute(path, ln, fields); ok {
				dev.Routes = append(dev.Routes, route)
			}
		}
	}

	dev.VLANs = sortedVLANs(vlans)
	dev.Interfaces = sortedInterfaces(path, ifaces)
	return dev, nil
}

func parsePort(path string, ln line, fields []string, ifaces map[string]*ifaceBuild) {
	name := fields[2]
	item := ensureInterface(ifaces, name, ln)
	addEvidence(item, ln)
	switch {
	case len(fields) >= 5 && fields[3] == "description":
		item.iface.Description = strings.Join(fields[4:], " ")
	case len(fields) >= 6 && fields[3] == "ethernet" && fields[4] == "mode":
		switch fields[5] {
		case "access":
			item.iface.Mode = "access"
		case "network":
			item.iface.Mode = "trunk"
		}
	case len(fields) >= 4 && fields[3] == "shutdown":
		item.iface.Shutdown = true
	}
}

func parseRouterInterface(path string, ln line, fields []string, ifaces map[string]*ifaceBuild) {
	name := fields[3]
	item := ensureInterface(ifaces, name, ln)
	item.iface.Mode = "routed"
	addEvidence(item, ln)
	switch {
	case len(fields) >= 6 && fields[4] == "address":
		item.iface.IPv4 = fields[5]
	case len(fields) >= 6 && fields[4] == "port":
		if id := vlanFromSAP(fields[5]); id != 0 {
			item.iface.AccessVLAN = id
		}
	}
}

func parseVPLS(path string, ln line, fields []string, vlans map[int]ir.VLAN) {
	id, err := strconv.Atoi(fields[3])
	if err != nil {
		return
	}
	vlan := vlans[id]
	vlan.ID = id
	vlan.Evidence = evidence(path, ln.num, ln.num, []line{ln})
	if idx := indexOf(fields, "description"); idx >= 0 && idx+1 < len(fields) {
		vlan.Name = strings.Join(fields[idx+1:], " ")
	}
	vlans[id] = vlan
}

func parseRoute(path string, ln line, fields []string) (ir.Route, bool) {
	idx := indexOf(fields, "next-hop")
	if idx < 0 || idx+1 >= len(fields) {
		return ir.Route{}, false
	}
	return ir.Route{Destination: fields[3], NextHop: fields[idx+1], Evidence: evidence(path, ln.num, ln.num, []line{ln})}, true
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

func addEvidence(item *ifaceBuild, ln line) {
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

func vlanFromSAP(raw string) int {
	_, suffix, ok := strings.Cut(raw, ":")
	if !ok {
		return 0
	}
	id, _ := strconv.Atoi(suffix)
	return id
}

func indexOf(fields []string, want string) int {
	for i, field := range fields {
		if field == want {
			return i
		}
	}
	return -1
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

package juniper

import (
	"bufio"
	"os"
	"sort"
	"strconv"
	"strings"

	"network-compiler/internal/ir"
	"network-compiler/internal/secretredact"
)

const parserVersion = "juniper-junos-set-v0"

type Parser struct{}

func New() Parser {
	return Parser{}
}

type line struct {
	num  int
	text string
}

type ifaceBuild struct {
	iface     ir.Interface
	vlanRefs  []string
	evidence  []line
	firstLine int
	lastLine  int
}

type vlanBuild struct {
	vlan ir.VLAN
	name string
}

func (Parser) ParseFile(path string) (ir.Device, error) {
	lines, err := readLines(path)
	if err != nil {
		return ir.Device{}, err
	}

	dev := ir.Device{
		Vendor:        "juniper",
		SourceFile:    path,
		ParserVersion: parserVersion,
	}
	ifaces := map[string]*ifaceBuild{}
	vlans := map[string]vlanBuild{}

	for _, ln := range lines {
		t := strings.TrimSpace(ln.text)
		if t == "" || strings.HasPrefix(t, "#") || strings.HasPrefix(t, "##") {
			continue
		}
		fields := strings.Fields(t)
		if len(fields) == 0 || fields[0] != "set" {
			continue
		}

		switch {
		case len(fields) >= 4 && fields[1] == "system" && fields[2] == "host-name":
			dev.Hostname = fields[3]
			dev.Evidence = evidence(path, ln.num, ln.num, []line{ln})
		case len(fields) >= 5 && fields[1] == "system" && fields[2] == "ntp" && fields[3] == "server":
			dev.Services.NTPServers = append(dev.Services.NTPServers, serviceTarget(path, ln, fields[4]))
		case len(fields) >= 5 && fields[1] == "system" && fields[2] == "syslog" && fields[3] == "host":
			dev.Services.SyslogHosts = append(dev.Services.SyslogHosts, serviceTarget(path, ln, fields[4]))
		case len(fields) >= 4 && fields[1] == "snmp" && fields[2] == "community":
			dev.Services.SNMPCommunities = append(dev.Services.SNMPCommunities, serviceTarget(path, ln, fields[3]))
		case len(fields) >= 4 && fields[1] == "interfaces":
			parseInterfaceLine(path, ln, fields, ifaces)
		case len(fields) >= 5 && fields[1] == "vlans":
			parseVLANLine(path, ln, fields, vlans)
		case len(fields) >= 7 && fields[1] == "routing-options" && fields[2] == "static" && fields[3] == "route" && fields[5] == "next-hop":
			dev.Routes = append(dev.Routes, ir.Route{
				Destination: fields[4],
				NextHop:     fields[6],
				Evidence:    evidence(path, ln.num, ln.num, []line{ln}),
			})
		}
	}

	vlanIDs := make(map[string]int, len(vlans))
	vlanNames := make([]string, 0, len(vlans))
	for name := range vlans {
		vlanNames = append(vlanNames, name)
	}
	sort.Slice(vlanNames, func(i, j int) bool {
		return vlans[vlanNames[i]].vlan.Evidence.StartLine < vlans[vlanNames[j]].vlan.Evidence.StartLine
	})
	for _, name := range vlanNames {
		item := vlans[name]
		vlanIDs[name] = item.vlan.ID
		dev.VLANs = append(dev.VLANs, item.vlan)
	}
	ifaceNames := make([]string, 0, len(ifaces))
	for name := range ifaces {
		ifaceNames = append(ifaceNames, name)
	}
	sort.Slice(ifaceNames, func(i, j int) bool {
		return ifaces[ifaceNames[i]].firstLine < ifaces[ifaceNames[j]].firstLine
	})
	for _, name := range ifaceNames {
		item := ifaces[name]
		finalizeInterface(path, item, vlanIDs)
		dev.Interfaces = append(dev.Interfaces, item.iface)
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

func parseInterfaceLine(path string, ln line, fields []string, ifaces map[string]*ifaceBuild) {
	name := fields[2]
	item := ensureInterface(ifaces, name, ln)
	item.evidence = append(item.evidence, ln)
	item.lastLine = ln.num

	switch {
	case len(fields) >= 5 && fields[3] == "description":
		item.iface.Description = strings.Join(fields[4:], " ")
	case len(fields) >= 4 && fields[3] == "disable":
		item.iface.Shutdown = true
	case len(fields) >= 9 && fields[3] == "unit" && fields[5] == "family" && fields[6] == "ethernet-switching" && fields[7] == "interface-mode":
		item.iface.Mode = fields[8]
	case len(fields) >= 10 && fields[3] == "unit" && fields[5] == "family" && fields[6] == "ethernet-switching" && fields[7] == "vlan" && fields[8] == "members":
		item.vlanRefs = append(item.vlanRefs, parseMembers(fields[9:])...)
	case len(fields) >= 9 && fields[3] == "unit" && fields[5] == "family" && fields[6] == "inet" && fields[7] == "address":
		item.iface.Mode = "routed"
		item.iface.IPv4 = fields[8]
	}
}

func ensureInterface(ifaces map[string]*ifaceBuild, name string, ln line) *ifaceBuild {
	item := ifaces[name]
	if item == nil {
		item = &ifaceBuild{
			iface:     ir.Interface{Name: name, Mode: "unknown"},
			firstLine: ln.num,
			lastLine:  ln.num,
		}
		ifaces[name] = item
	}
	return item
}

func parseVLANLine(path string, ln line, fields []string, vlans map[string]vlanBuild) {
	name := fields[2]
	if len(fields) < 5 || fields[3] != "vlan-id" {
		return
	}
	id, err := strconv.Atoi(fields[4])
	if err != nil {
		return
	}
	vlans[name] = vlanBuild{
		name: name,
		vlan: ir.VLAN{ID: id, Name: name, Evidence: evidence(path, ln.num, ln.num, []line{ln})},
	}
}

func parseMembers(fields []string) []string {
	joined := strings.Join(fields, " ")
	joined = strings.TrimSpace(strings.Trim(joined, "[]"))
	if joined == "" {
		return nil
	}
	return strings.Fields(joined)
}

func finalizeInterface(path string, item *ifaceBuild, vlanIDs map[string]int) {
	switch item.iface.Mode {
	case "access":
		if len(item.vlanRefs) > 0 {
			item.iface.AccessVLAN = resolveVLAN(item.vlanRefs[0], vlanIDs)
		}
	case "trunk":
		for _, ref := range item.vlanRefs {
			if id := resolveVLAN(ref, vlanIDs); id != 0 {
				item.iface.TrunkVLANs = append(item.iface.TrunkVLANs, id)
			}
		}
	}
	if item.iface.Mode == "unknown" && item.iface.IPv4 != "" {
		item.iface.Mode = "routed"
	}
	item.iface.Evidence = evidence(path, item.firstLine, item.lastLine, item.evidence)
}

func resolveVLAN(ref string, vlanIDs map[string]int) int {
	if id, err := strconv.Atoi(ref); err == nil {
		return id
	}
	return vlanIDs[ref]
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

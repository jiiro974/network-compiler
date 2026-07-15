package routeros

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

const parserVersion = "mikrotik-routeros-rsc-v0"

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
	dev := ir.Device{Vendor: "mikrotik-routeros", SourceFile: path, ParserVersion: parserVersion}
	ifaces := map[string]*ifaceBuild{}
	vlans := map[int]ir.VLAN{}

	for _, ln := range lines {
		fields := syntax.Fields(strings.TrimSpace(ln.text))
		if len(fields) < 2 || !strings.HasPrefix(fields[0], "/") {
			continue
		}
		pathCmd := fields[0]
		action := fields[1]
		args := parseArgs(fields[2:])
		switch {
		case pathCmd == "/system" && action == "identity" && len(fields) >= 4 && fields[2] == "set":
			args = parseArgs(fields[3:])
			dev.Hostname = args["name"]
			dev.Evidence = evidence(path, ln.num, ln.num, []line{ln})
		case pathCmd == "/system" && action == "ntp" && len(fields) >= 5 && fields[2] == "client" && fields[3] == "set":
			args = parseArgs(fields[4:])
			for _, server := range splitCSV(args["servers"]) {
				dev.Services.NTPServers = append(dev.Services.NTPServers, serviceTarget(path, ln, server))
			}
		case pathCmd == "/system" && action == "logging" && len(fields) >= 5 && fields[2] == "action" && fields[3] == "add":
			args = parseArgs(fields[4:])
			if args["target"] == "remote" && args["remote"] != "" {
				dev.Services.SyslogHosts = append(dev.Services.SyslogHosts, serviceTarget(path, ln, args["remote"]))
			}
		case pathCmd == "/snmp" && action == "community" && len(fields) >= 4 && fields[2] == "add":
			args = parseArgs(fields[3:])
			if args["name"] != "" {
				dev.Services.SNMPCommunities = append(dev.Services.SNMPCommunities, serviceTarget(path, ln, args["name"]))
			}
		case pathCmd == "/interface" && action == "bridge" && len(fields) >= 4 && fields[2] == "add":
			args = parseArgs(fields[3:])
			item := ensureInterface(ifaces, args["name"], ln)
			item.iface.Mode = "bridge"
			addEvidence(item, ln)
		case pathCmd == "/interface" && action == "vlan" && len(fields) >= 4 && fields[2] == "add":
			args = parseArgs(fields[3:])
			id, _ := strconv.Atoi(args["vlan-id"])
			item := ensureInterface(ifaces, args["name"], ln)
			item.iface.Mode = "routed"
			item.iface.AccessVLAN = id
			addEvidence(item, ln)
			if id != 0 {
				vlans[id] = ir.VLAN{ID: id, Evidence: evidence(path, ln.num, ln.num, []line{ln})}
			}
		case pathCmd == "/interface" && action == "bridge" && len(fields) >= 5 && fields[2] == "port" && fields[3] == "add":
			args = parseArgs(fields[4:])
			item := ensureInterface(ifaces, args["interface"], ln)
			item.iface.Mode = "access"
			item.iface.Description = args["comment"]
			item.iface.AccessVLAN, _ = strconv.Atoi(args["pvid"])
			addEvidence(item, ln)
		case pathCmd == "/interface" && action == "bridge" && len(fields) >= 5 && fields[2] == "vlan" && fields[3] == "add":
			args = parseArgs(fields[4:])
			for _, name := range splitCSV(args["tagged"]) {
				item := ensureInterface(ifaces, name, ln)
				item.iface.Mode = "trunk"
				item.iface.TrunkVLANs = appendUniqueInts(item.iface.TrunkVLANs, parseVLANIDs(args["vlan-ids"])...)
				addEvidence(item, ln)
			}
		case pathCmd == "/interface" && action == "disable" && len(fields) >= 3:
			item := ensureInterface(ifaces, fields[2], ln)
			item.iface.Shutdown = true
			addEvidence(item, ln)
		case pathCmd == "/ip" && action == "address" && len(fields) >= 4 && fields[2] == "add":
			args = parseArgs(fields[3:])
			item := ensureInterface(ifaces, args["interface"], ln)
			item.iface.Mode = "routed"
			item.iface.IPv4 = args["address"]
			if args["comment"] != "" {
				item.iface.Description = args["comment"]
			}
			addEvidence(item, ln)
		case pathCmd == "/ip" && action == "route" && len(fields) >= 4 && fields[2] == "add":
			args = parseArgs(fields[3:])
			dev.Routes = append(dev.Routes, ir.Route{Destination: args["dst-address"], NextHop: args["gateway"], Evidence: evidence(path, ln.num, ln.num, []line{ln})})
		}
	}

	dev.VLANs = sortedVLANs(vlans)
	dev.Interfaces = sortedInterfaces(path, ifaces)
	return dev, nil
}

func parseArgs(fields []string) map[string]string {
	out := map[string]string{}
	for _, field := range fields {
		k, v, ok := strings.Cut(field, "=")
		if ok {
			out[k] = v
		}
	}
	return out
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

func parseVLANIDs(raw string) []int {
	var out []int
	for _, part := range splitCSV(raw) {
		id, err := strconv.Atoi(part)
		if err == nil {
			out = append(out, id)
		}
	}
	return out
}

func appendUniqueInts(items []int, add ...int) []int {
	seen := map[int]bool{}
	for _, item := range items {
		seen[item] = true
	}
	for _, item := range add {
		if !seen[item] {
			items = append(items, item)
			seen[item] = true
		}
	}
	sort.Ints(items)
	return items
}

func splitCSV(raw string) []string {
	var out []string
	for _, part := range strings.Split(raw, ",") {
		part = strings.TrimSpace(part)
		if part != "" {
			out = append(out, part)
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

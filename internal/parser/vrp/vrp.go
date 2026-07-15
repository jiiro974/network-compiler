package vrp

import (
	"bufio"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"

	"network-compiler/internal/ir"
	"network-compiler/internal/secretredact"
)

type Flavor string

const (
	FlavorHuaweiVRP  Flavor = "huawei-vrp"
	FlavorHPEComware Flavor = "hpe-comware"
)

type Parser struct {
	flavor Flavor
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

func NewHuaweiVRP() Parser {
	return Parser{flavor: FlavorHuaweiVRP}
}

func NewHPEComware() Parser {
	return Parser{flavor: FlavorHPEComware}
}

func (p Parser) ParseFile(path string) (ir.Device, error) {
	lines, err := readLines(path)
	if err != nil {
		return ir.Device{}, err
	}
	dev := ir.Device{
		Vendor:        string(p.flavor),
		SourceFile:    path,
		ParserVersion: fmt.Sprintf("%s-v0", p.flavor),
	}
	ifaces := map[string]*ifaceBuild{}
	vlanSeen := map[int]bool{}

	for i := 0; i < len(lines); i++ {
		t := strings.TrimSpace(lines[i].text)
		if t == "" || t == "#" || strings.HasPrefix(t, "#") {
			continue
		}
		fields := strings.Fields(t)
		if len(fields) == 0 {
			continue
		}
		switch {
		case fields[0] == "sysname" && len(fields) >= 2:
			dev.Hostname = fields[1]
			dev.Evidence = p.evidence(path, lines[i].num, lines[i].num, []line{lines[i]})
		case fields[0] == "snmp-agent" && len(fields) >= 4 && fields[1] == "community":
			dev.Services.SNMPCommunities = append(dev.Services.SNMPCommunities, p.serviceTarget(path, lines[i], fields[len(fields)-1]))
		case fields[0] == "ntp-service" && len(fields) >= 3 && fields[1] == "unicast-server":
			dev.Services.NTPServers = append(dev.Services.NTPServers, p.serviceTarget(path, lines[i], fields[2]))
		case fields[0] == "info-center" && len(fields) >= 3 && fields[1] == "loghost":
			dev.Services.SyslogHosts = append(dev.Services.SyslogHosts, p.serviceTarget(path, lines[i], fields[2]))
		case fields[0] == "vlan" && len(fields) >= 3 && fields[1] == "batch":
			for _, id := range parseVLANIDs(fields[2:]) {
				if !vlanSeen[id] {
					dev.VLANs = append(dev.VLANs, ir.VLAN{ID: id, Evidence: p.evidence(path, lines[i].num, lines[i].num, []line{lines[i]})})
					vlanSeen[id] = true
				}
			}
		case fields[0] == "vlan" && len(fields) >= 2:
			block, next := collectVLANBlock(lines, i)
			p.parseVLANBlock(path, block, &dev, vlanSeen)
			i = next - 1
		case fields[0] == "interface" && len(fields) >= 2:
			block, next := collectHashBlock(lines, i)
			p.parseInterfaceBlock(block, ifaces)
			i = next - 1
		case fields[0] == "ip" && len(fields) >= 5 && fields[1] == "route-static":
			dev.Routes = append(dev.Routes, p.parseRoute(path, lines[i], fields))
		}
	}

	dev.Interfaces = append(dev.Interfaces, finalizeInterfaces(path, p, ifaces)...)
	return dev, nil
}

func (p Parser) parseVLANBlock(path string, block []line, dev *ir.Device, vlanSeen map[int]bool) {
	fields := strings.Fields(strings.TrimSpace(block[0].text))
	if len(fields) < 2 {
		return
	}
	id, err := strconv.Atoi(fields[1])
	if err != nil {
		return
	}
	vlan := ir.VLAN{ID: id, Evidence: p.evidence(path, block[0].num, block[len(block)-1].num, block)}
	for _, ln := range block[1:] {
		t := strings.TrimSpace(ln.text)
		fields := strings.Fields(t)
		if len(fields) >= 2 && (fields[0] == "description" || fields[0] == "name") {
			vlan.Name = strings.Join(fields[1:], " ")
		}
	}
	for i := range dev.VLANs {
		if dev.VLANs[i].ID == id {
			dev.VLANs[i] = vlan
			vlanSeen[id] = true
			return
		}
	}
	if !vlanSeen[id] {
		dev.VLANs = append(dev.VLANs, vlan)
		vlanSeen[id] = true
	}
}

func (p Parser) parseInterfaceBlock(block []line, ifaces map[string]*ifaceBuild) {
	fields := strings.Fields(strings.TrimSpace(block[0].text))
	if len(fields) < 2 {
		return
	}
	item := ensureInterface(ifaces, fields[1], block[0])
	item.evidence = append(item.evidence, block[0])
	item.lastLine = block[len(block)-1].num
	for _, ln := range block[1:] {
		t := strings.TrimSpace(ln.text)
		fields := strings.Fields(t)
		if len(fields) == 0 {
			continue
		}
		switch {
		case fields[0] == "description" && len(fields) >= 2:
			item.iface.Description = strings.Join(fields[1:], " ")
		case fields[0] == "shutdown":
			item.iface.Shutdown = true
		case len(fields) >= 3 && fields[0] == "port" && fields[1] == "link-type":
			item.iface.Mode = fields[2]
		case len(fields) >= 4 && fields[0] == "port" && fields[1] == "default" && fields[2] == "vlan":
			item.iface.Mode = "access"
			item.iface.AccessVLAN, _ = strconv.Atoi(fields[3])
		case len(fields) >= 4 && fields[0] == "port" && fields[1] == "access" && fields[2] == "vlan":
			item.iface.Mode = "access"
			item.iface.AccessVLAN, _ = strconv.Atoi(fields[3])
		case len(fields) >= 5 && fields[0] == "port" && fields[1] == "trunk" && (fields[2] == "allow-pass" || fields[2] == "permit") && fields[3] == "vlan":
			item.iface.Mode = "trunk"
			item.iface.TrunkVLANs = append(item.iface.TrunkVLANs, parseVLANIDs(fields[4:])...)
		case len(fields) >= 4 && fields[0] == "ip" && fields[1] == "address":
			item.iface.Mode = "routed"
			item.iface.IPv4 = strings.Join(fields[2:4], " ")
		}
		item.evidence = append(item.evidence, ln)
		item.lastLine = ln.num
	}
}

func (p Parser) parseRoute(path string, ln line, fields []string) ir.Route {
	route := ir.Route{Evidence: p.evidence(path, ln.num, ln.num, []line{ln})}
	if len(fields) >= 5 && isPrefixLength(fields[3]) {
		route.Destination = fields[2] + "/" + fields[3]
		route.NextHop = fields[4]
		return route
	}
	if len(fields) >= 5 {
		route.Destination = fields[2] + " " + fields[3]
		route.NextHop = fields[4]
	}
	return route
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

func collectHashBlock(lines []line, start int) ([]line, int) {
	block := []line{lines[start]}
	for i := start + 1; i < len(lines); i++ {
		if strings.TrimSpace(lines[i].text) == "#" {
			return block, i + 1
		}
		block = append(block, lines[i])
	}
	return block, len(lines)
}

func collectVLANBlock(lines []line, start int) ([]line, int) {
	block := []line{lines[start]}
	for i := start + 1; i < len(lines); i++ {
		trimmed := strings.TrimSpace(lines[i].text)
		if trimmed == "#" {
			return block, i + 1
		}
		if strings.HasPrefix(trimmed, "vlan ") || strings.HasPrefix(trimmed, "interface ") || strings.HasPrefix(trimmed, "ip route-static ") {
			return block, i
		}
		block = append(block, lines[i])
	}
	return block, len(lines)
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
	if ln.num < item.firstLine {
		item.firstLine = ln.num
	}
	if ln.num > item.lastLine {
		item.lastLine = ln.num
	}
	return item
}

func finalizeInterfaces(path string, p Parser, ifaces map[string]*ifaceBuild) []ir.Interface {
	names := make([]string, 0, len(ifaces))
	for name := range ifaces {
		names = append(names, name)
	}
	sort.Slice(names, func(i, j int) bool {
		return ifaces[names[i]].firstLine < ifaces[names[j]].firstLine
	})
	out := make([]ir.Interface, 0, len(names))
	for _, name := range names {
		item := ifaces[name]
		item.iface.TrunkVLANs = uniqueSortedInts(item.iface.TrunkVLANs)
		item.iface.Evidence = p.evidence(path, item.firstLine, item.lastLine, item.evidence)
		out = append(out, item.iface)
	}
	return out
}

func parseVLANIDs(fields []string) []int {
	var out []int
	for _, field := range fields {
		for _, part := range strings.Split(field, ",") {
			part = strings.TrimSpace(part)
			if part == "" {
				continue
			}
			if strings.Contains(part, "-") || strings.Contains(part, "to") {
				part = strings.ReplaceAll(part, "to", "-")
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
	}
	return uniqueSortedInts(out)
}

func uniqueSortedInts(values []int) []int {
	sort.Ints(values)
	out := values[:0]
	for _, value := range values {
		if len(out) == 0 || out[len(out)-1] != value {
			out = append(out, value)
		}
	}
	return out
}

func isPrefixLength(s string) bool {
	value, err := strconv.Atoi(s)
	return err == nil && value >= 0 && value <= 32
}

func (p Parser) evidence(path string, start, end int, lines []line) ir.Evidence {
	raw := make([]string, 0, len(lines))
	for _, ln := range lines {
		raw = append(raw, secretredact.Redact(ln.text))
	}
	return ir.Evidence{File: path, StartLine: start, EndLine: end, RawBlock: strings.Join(raw, "\n"), Parser: fmt.Sprintf("%s-v0", p.flavor)}
}

func (p Parser) serviceTarget(path string, ln line, value string) ir.ServiceTarget {
	return ir.ServiceTarget{Value: value, Evidence: p.evidence(path, ln.num, ln.num, []line{ln})}
}

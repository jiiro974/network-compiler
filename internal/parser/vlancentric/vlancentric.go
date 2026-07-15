package vlancentric

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

type Flavor string

const (
	FlavorArubaOSSwitch Flavor = "aruba-os-switch"
	FlavorHPEProCurve   Flavor = "hpe-procurve"
	FlavorExtremeEXOS   Flavor = "extreme-exos"
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

func NewArubaOSSwitch() Parser {
	return Parser{flavor: FlavorArubaOSSwitch}
}

func NewHPEProCurve() Parser {
	return Parser{flavor: FlavorHPEProCurve}
}

func NewExtremeEXOS() Parser {
	return Parser{flavor: FlavorExtremeEXOS}
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
	if p.flavor == FlavorExtremeEXOS {
		return p.parseEXOS(path, lines, dev), nil
	}
	return p.parseProCurveLike(path, lines, dev), nil
}

func (p Parser) parseProCurveLike(path string, lines []line, dev ir.Device) ir.Device {
	ifaces := map[string]*ifaceBuild{}
	vlanSeen := map[int]bool{}

	for i := 0; i < len(lines); i++ {
		t := strings.TrimSpace(lines[i].text)
		if t == "" || strings.HasPrefix(t, ";") {
			continue
		}
		fields := syntax.Fields(t)
		switch {
		case len(fields) >= 2 && fields[0] == "hostname":
			dev.Hostname = fields[1]
			dev.Evidence = p.evidence(path, lines[i].num, lines[i].num, []line{lines[i]})
		case len(fields) >= 3 && fields[0] == "snmp-server" && fields[1] == "community":
			dev.Services.SNMPCommunities = append(dev.Services.SNMPCommunities, p.serviceTarget(path, lines[i], fields[2]))
		case len(fields) >= 3 && fields[0] == "ntp" && fields[1] == "server":
			dev.Services.NTPServers = append(dev.Services.NTPServers, p.serviceTarget(path, lines[i], fields[2]))
		case len(fields) >= 3 && fields[0] == "sntp" && fields[1] == "server":
			dev.Services.NTPServers = append(dev.Services.NTPServers, p.serviceTarget(path, lines[i], fields[len(fields)-1]))
		case len(fields) >= 2 && fields[0] == "logging":
			dev.Services.SyslogHosts = append(dev.Services.SyslogHosts, p.serviceTarget(path, lines[i], fields[1]))
		case len(fields) >= 2 && fields[0] == "vlan":
			block, next := collectExitBlock(lines, i)
			p.parseVLANBlock(path, block, &dev, ifaces, vlanSeen)
			i = next - 1
		case len(fields) >= 2 && fields[0] == "interface":
			block, next := collectExitBlock(lines, i)
			p.parseInterfaceBlock(block, ifaces)
			i = next - 1
		case len(fields) >= 5 && fields[0] == "ip" && fields[1] == "route":
			dev.Routes = append(dev.Routes, ir.Route{
				Destination: fmt.Sprintf("%s %s", fields[2], fields[3]),
				NextHop:     fields[4],
				Evidence:    p.evidence(path, lines[i].num, lines[i].num, []line{lines[i]}),
			})
		}
	}

	dev.Interfaces = append(dev.Interfaces, finalizeInterfaces(path, p, ifaces)...)
	return dev
}

func (p Parser) parseVLANBlock(path string, block []line, dev *ir.Device, ifaces map[string]*ifaceBuild, vlanSeen map[int]bool) {
	header := syntax.Fields(strings.TrimSpace(block[0].text))
	if len(header) < 2 {
		return
	}
	id, err := strconv.Atoi(header[1])
	if err != nil {
		return
	}
	vlan := ir.VLAN{ID: id, Evidence: p.evidence(path, block[0].num, block[len(block)-1].num, block)}
	for _, ln := range block[1:] {
		t := strings.TrimSpace(ln.text)
		fields := syntax.Fields(t)
		if len(fields) == 0 {
			continue
		}
		switch fields[0] {
		case "name":
			if len(fields) >= 2 {
				vlan.Name = fields[1]
			}
		case "untagged":
			for _, port := range parsePortList(fields[1:]) {
				item := ensureInterface(ifaces, port, ln)
				item.iface.AccessVLAN = id
				item.evidence = append(item.evidence, ln)
				item.lastLine = ln.num
			}
		case "tagged":
			for _, port := range parsePortList(fields[1:]) {
				item := ensureInterface(ifaces, port, ln)
				item.iface.TrunkVLANs = appendUniqueInt(item.iface.TrunkVLANs, id)
				item.evidence = append(item.evidence, ln)
				item.lastLine = ln.num
			}
		case "ip":
			if len(fields) >= 4 && fields[1] == "address" {
				name := fmt.Sprintf("Vlan%d", id)
				item := ensureInterface(ifaces, name, ln)
				item.iface.Mode = "routed"
				item.iface.IPv4 = strings.Join(fields[2:4], " ")
				item.evidence = append(item.evidence, ln)
				item.lastLine = ln.num
			}
		}
	}
	if !vlanSeen[id] {
		dev.VLANs = append(dev.VLANs, vlan)
		vlanSeen[id] = true
	}
}

func (p Parser) parseInterfaceBlock(block []line, ifaces map[string]*ifaceBuild) {
	header := syntax.Fields(strings.TrimSpace(block[0].text))
	if len(header) < 2 {
		return
	}
	item := ensureInterface(ifaces, header[1], block[0])
	item.evidence = append(item.evidence, block[0])
	item.lastLine = block[len(block)-1].num
	for _, ln := range block[1:] {
		fields := syntax.Fields(strings.TrimSpace(ln.text))
		if len(fields) == 0 {
			continue
		}
		switch fields[0] {
		case "name":
			if len(fields) >= 2 {
				item.iface.Description = fields[1]
			}
		case "disable":
			item.iface.Shutdown = true
		}
		item.evidence = append(item.evidence, ln)
	}
}

func (p Parser) parseEXOS(path string, lines []line, dev ir.Device) ir.Device {
	ifaces := map[string]*ifaceBuild{}
	vlanIDByName := map[string]int{}
	vlanEvidenceByName := map[string]ir.Evidence{}

	for _, ln := range lines {
		t := strings.TrimSpace(ln.text)
		if t == "" || strings.HasPrefix(t, "#") {
			continue
		}
		fields := syntax.Fields(t)
		if len(fields) == 0 {
			continue
		}
		switch {
		case len(fields) >= 4 && fields[0] == "configure" && fields[1] == "snmp" && fields[2] == "sysName":
			dev.Hostname = fields[3]
			dev.Evidence = p.evidence(path, ln.num, ln.num, []line{ln})
		case len(fields) >= 5 && fields[0] == "configure" && fields[1] == "ntp" && fields[2] == "server" && fields[3] == "add":
			dev.Services.NTPServers = append(dev.Services.NTPServers, p.serviceTarget(path, ln, fields[4]))
		case len(fields) >= 4 && fields[0] == "configure" && fields[1] == "syslog" && fields[2] == "add":
			dev.Services.SyslogHosts = append(dev.Services.SyslogHosts, p.serviceTarget(path, ln, fields[3]))
		case len(fields) >= 6 && fields[0] == "configure" && fields[1] == "snmp" && fields[2] == "add" && fields[3] == "community":
			dev.Services.SNMPCommunities = append(dev.Services.SNMPCommunities, p.serviceTarget(path, ln, fields[5]))
		case len(fields) >= 5 && fields[0] == "create" && fields[1] == "vlan" && fields[3] == "tag":
			id, err := strconv.Atoi(fields[4])
			if err != nil {
				continue
			}
			name := fields[2]
			vlanIDByName[name] = id
			vlanEvidenceByName[name] = p.evidence(path, ln.num, ln.num, []line{ln})
			dev.VLANs = append(dev.VLANs, ir.VLAN{ID: id, Name: name, Evidence: vlanEvidenceByName[name]})
		case len(fields) >= 7 && fields[0] == "configure" && fields[1] == "vlan" && fields[3] == "add" && fields[4] == "ports":
			id := vlanIDByName[fields[2]]
			if id == 0 {
				continue
			}
			for _, port := range parsePortList(fields[5 : len(fields)-1]) {
				item := ensureInterface(ifaces, port, ln)
				if fields[len(fields)-1] == "untagged" {
					item.iface.AccessVLAN = id
				} else if fields[len(fields)-1] == "tagged" {
					item.iface.TrunkVLANs = appendUniqueInt(item.iface.TrunkVLANs, id)
				}
				item.evidence = append(item.evidence, ln)
				item.lastLine = ln.num
			}
		case len(fields) >= 5 && fields[0] == "configure" && fields[1] == "vlan" && fields[3] == "ipaddress":
			id := vlanIDByName[fields[2]]
			name := fmt.Sprintf("Vlan%d", id)
			if id == 0 {
				name = "Vlan" + fields[2]
			}
			item := ensureInterface(ifaces, name, ln)
			item.iface.Mode = "routed"
			item.iface.IPv4 = strings.Join(fields[4:], " ")
			item.evidence = append(item.evidence, ln)
			item.lastLine = ln.num
		case len(fields) >= 5 && fields[0] == "configure" && fields[1] == "ports" && fields[3] == "description-string":
			item := ensureInterface(ifaces, fields[2], ln)
			item.iface.Description = fields[4]
			item.evidence = append(item.evidence, ln)
			item.lastLine = ln.num
		case len(fields) >= 3 && fields[0] == "disable" && fields[1] == "ports":
			item := ensureInterface(ifaces, fields[2], ln)
			item.iface.Shutdown = true
			item.evidence = append(item.evidence, ln)
			item.lastLine = ln.num
		case len(fields) >= 4 && fields[0] == "configure" && fields[1] == "iproute" && fields[2] == "add":
			route := ir.Route{Destination: fields[3], Evidence: p.evidence(path, ln.num, ln.num, []line{ln})}
			if route.Destination == "default" {
				route.Destination = "0.0.0.0/0"
			}
			if len(fields) >= 5 {
				route.NextHop = fields[4]
			}
			dev.Routes = append(dev.Routes, route)
		}
	}

	dev.Interfaces = append(dev.Interfaces, finalizeInterfaces(path, p, ifaces)...)
	return dev
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

func collectExitBlock(lines []line, start int) ([]line, int) {
	block := []line{lines[start]}
	for i := start + 1; i < len(lines); i++ {
		trimmed := strings.TrimSpace(lines[i].text)
		block = append(block, lines[i])
		if trimmed == "exit" {
			return block, i + 1
		}
		if trimmed != "" && !strings.HasPrefix(lines[i].text, " ") && !strings.HasPrefix(lines[i].text, "\t") {
			return block[:len(block)-1], i
		}
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
		switch {
		case item.iface.Mode == "routed":
		case len(item.iface.TrunkVLANs) > 0:
			item.iface.Mode = "trunk"
		case item.iface.AccessVLAN != 0:
			item.iface.Mode = "access"
		}
		sort.Ints(item.iface.TrunkVLANs)
		item.iface.Evidence = p.evidence(path, item.firstLine, item.lastLine, item.evidence)
		out = append(out, item.iface)
	}
	return out
}

func parsePortList(fields []string) []string {
	var out []string
	for _, field := range fields {
		for _, part := range strings.Split(field, ",") {
			part = strings.TrimSpace(part)
			if part == "" || part == "no" {
				continue
			}
			if strings.Contains(part, "-") {
				bounds := strings.SplitN(part, "-", 2)
				start, err1 := strconv.Atoi(bounds[0])
				end, err2 := strconv.Atoi(bounds[1])
				if err1 == nil && err2 == nil && start <= end {
					for port := start; port <= end; port++ {
						out = append(out, strconv.Itoa(port))
					}
				}
				continue
			}
			out = append(out, part)
		}
	}
	return out
}

func appendUniqueInt(values []int, value int) []int {
	for _, existing := range values {
		if existing == value {
			return values
		}
	}
	return append(values, value)
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

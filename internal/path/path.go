package path

import (
	"fmt"
	"math/bits"
	"net"
	"net/netip"
	"sort"
	"strconv"
	"strings"

	"network-compiler/internal/ir"
)

const maxHops = 16

type Flow struct {
	Src   string `json:"src"`
	Dst   string `json:"dst"`
	Proto string `json:"proto"`
	DPort int    `json:"dport,omitempty"`
}

type Verdict string

const (
	VerdictDelivered     Verdict = "delivered"
	VerdictDroppedACL    Verdict = "dropped_acl"
	VerdictDroppedPolicy Verdict = "dropped_policy"
	VerdictNoRoute       Verdict = "no_route"
	VerdictLoop          Verdict = "loop"
)

type Hop struct {
	Device       string             `json:"device"`
	Vendor       string             `json:"vendor"`
	IngressIface string             `json:"ingress_iface"`
	IngressZone  string             `json:"ingress_zone,omitempty"`
	RouteMatch   *ir.Route          `json:"route_match,omitempty"`
	ACLMatch     *ir.ACLEntry       `json:"acl_match,omitempty"`
	PolicyMatch  *ir.SecurityPolicy `json:"policy_match,omitempty"`
	NATApplied   *ir.NATRule        `json:"nat_applied,omitempty"`
	EgressIface  string             `json:"egress_iface"`
	EgressZone   string             `json:"egress_zone,omitempty"`
	NextHop      string             `json:"next_hop"`
}

type Path struct {
	Flow    Flow         `json:"flow"`
	Hops    []Hop        `json:"hops"`
	Verdict Verdict      `json:"verdict"`
	Reason  *ir.Evidence `json:"reason,omitempty"`
}

type ifaceRef struct {
	device int
	iface  int
	prefix netip.Prefix
	addr   netip.Addr
}

type routeChoice struct {
	route ir.Route
	order int
	bits  int
	ad    int
}

func Trace(devices []ir.Device, flow Flow) (Path, error) {
	flow.Proto = strings.ToLower(strings.TrimSpace(flow.Proto))
	out := Path{Flow: flow, Hops: []Hop{}}
	src, err := netip.ParseAddr(flow.Src)
	if err != nil {
		return out, fmt.Errorf("invalid src: %w", err)
	}
	dst, err := netip.ParseAddr(flow.Dst)
	if err != nil {
		return out, fmt.Errorf("invalid dst: %w", err)
	}
	if flow.Proto == "" {
		return out, fmt.Errorf("missing proto")
	}

	refs := indexInterfaces(devices)
	start, ok := containingInterface(refs, src)
	if !ok {
		out.Verdict = VerdictNoRoute
		return out, nil
	}

	currentDevice := start.device
	ingressIface := devices[start.device].Interfaces[start.iface].Name
	visited := map[int]bool{}

	for len(out.Hops) < maxHops {
		if visited[currentDevice] {
			out.Verdict = VerdictLoop
			out.Reason = evidencePtr(devices[currentDevice].Evidence)
			return out, nil
		}
		visited[currentDevice] = true
		dev := devices[currentDevice]
		hop := Hop{
			Device:       dev.Hostname,
			Vendor:       dev.Vendor,
			IngressIface: ingressIface,
			IngressZone:  zoneForInterface(dev, ingressIface),
		}

		if acl := firstACLMatch(dev, flow); acl != nil {
			hop.ACLMatch = acl
			if strings.EqualFold(acl.Action, "deny") {
				out.Hops = append(out.Hops, hop)
				out.Verdict = VerdictDroppedACL
				out.Reason = evidencePtr(acl.Evidence)
				return out, nil
			}
		}

		if direct, ok := deviceContainsDst(dev, dst); ok {
			hop.EgressIface = direct.Name
			hop.EgressZone = zoneForInterface(dev, direct.Name)
			hop.NextHop = flow.Dst
			if droppedByPolicy(&out, dev, &hop, flow) {
				return out, nil
			}
			hop.NATApplied = firstNAT(dev, hop.IngressZone, hop.EgressZone)
			out.Hops = append(out.Hops, hop)
			out.Verdict = VerdictDelivered
			out.Reason = evidencePtr(direct.Evidence)
			return out, nil
		}

		choice, ok := longestPrefixRoute(dev, dst)
		if !ok {
			out.Hops = append(out.Hops, hop)
			out.Verdict = VerdictNoRoute
			out.Reason = evidencePtr(dev.Evidence)
			return out, nil
		}
		route := choice.route
		hop.RouteMatch = &route
		hop.EgressIface = egressInterface(dev, route)
		hop.EgressZone = zoneForInterface(dev, hop.EgressIface)
		hop.NextHop = route.NextHop
		if route.NextHop == "" {
			hop.NextHop = flow.Dst
		}
		if droppedByPolicy(&out, dev, &hop, flow) {
			return out, nil
		}
		hop.NATApplied = firstNAT(dev, hop.IngressZone, hop.EgressZone)
		out.Hops = append(out.Hops, hop)

		next, ok := resolveNextHop(refs, currentDevice, hop.NextHop)
		if !ok {
			out.Verdict = VerdictNoRoute
			out.Reason = evidencePtr(route.Evidence)
			return out, nil
		}
		currentDevice = next.device
		ingressIface = devices[next.device].Interfaces[next.iface].Name
	}

	out.Verdict = VerdictLoop
	if len(out.Hops) > 0 && out.Hops[len(out.Hops)-1].RouteMatch != nil {
		out.Reason = evidencePtr(out.Hops[len(out.Hops)-1].RouteMatch.Evidence)
	}
	return out, nil
}

func indexInterfaces(devices []ir.Device) []ifaceRef {
	var refs []ifaceRef
	for di, dev := range devices {
		for ii, intf := range dev.Interfaces {
			prefix, addr, ok := parseInterfaceIPv4(intf.IPv4)
			if !ok {
				continue
			}
			refs = append(refs, ifaceRef{device: di, iface: ii, prefix: prefix, addr: addr})
		}
	}
	sort.SliceStable(refs, func(i, j int) bool {
		if devices[refs[i].device].Hostname != devices[refs[j].device].Hostname {
			return devices[refs[i].device].Hostname < devices[refs[j].device].Hostname
		}
		return devices[refs[i].device].Interfaces[refs[i].iface].Name < devices[refs[j].device].Interfaces[refs[j].iface].Name
	})
	return refs
}

func parseInterfaceIPv4(raw string) (netip.Prefix, netip.Addr, bool) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return netip.Prefix{}, netip.Addr{}, false
	}
	prefix, err := netip.ParsePrefix(raw)
	if err == nil && prefix.Addr().Is4() {
		addr := prefix.Addr()
		return prefix.Masked(), addr, true
	}
	if prefix, addr, ok := parseAddrMask(raw); ok {
		return prefix, addr, true
	}
	addr, err := netip.ParseAddr(raw)
	if err != nil || !addr.Is4() {
		return netip.Prefix{}, netip.Addr{}, false
	}
	return netip.PrefixFrom(addr, 32), addr, true
}

func parseAddrMask(raw string) (netip.Prefix, netip.Addr, bool) {
	fields := strings.Fields(raw)
	if len(fields) != 2 {
		return netip.Prefix{}, netip.Addr{}, false
	}
	addr, err := netip.ParseAddr(fields[0])
	if err != nil || !addr.Is4() {
		return netip.Prefix{}, netip.Addr{}, false
	}
	mask := net.ParseIP(fields[1]).To4()
	if mask == nil {
		return netip.Prefix{}, netip.Addr{}, false
	}
	ones, size := net.IPMask(mask).Size()
	if size != 32 || ones < 0 || bits.OnesCount32(uint32(mask[0])<<24|uint32(mask[1])<<16|uint32(mask[2])<<8|uint32(mask[3])) != ones {
		return netip.Prefix{}, netip.Addr{}, false
	}
	return netip.PrefixFrom(addr, ones).Masked(), addr, true
}

func containingInterface(refs []ifaceRef, addr netip.Addr) (ifaceRef, bool) {
	for _, ref := range refs {
		if ref.prefix.Contains(addr) {
			return ref, true
		}
	}
	return ifaceRef{}, false
}

func deviceContainsDst(dev ir.Device, dst netip.Addr) (ir.Interface, bool) {
	for _, intf := range dev.Interfaces {
		prefix, _, ok := parseInterfaceIPv4(intf.IPv4)
		if ok && prefix.Contains(dst) {
			return intf, true
		}
	}
	return ir.Interface{}, false
}

func longestPrefixRoute(dev ir.Device, dst netip.Addr) (routeChoice, bool) {
	best := routeChoice{}
	found := false
	for i, route := range dev.Routes {
		prefix, ok := parseRoutePrefix(route.Destination)
		if !ok || !prefix.Contains(dst) {
			continue
		}
		choice := routeChoice{route: route, order: i, bits: prefix.Bits(), ad: administrativeDistance(route.AdministrativeDistance)}
		if !found || betterRoute(choice, best) {
			best = choice
			found = true
		}
	}
	return best, found
}

func parseRoutePrefix(raw string) (netip.Prefix, bool) {
	raw = strings.TrimSpace(raw)
	prefix, err := netip.ParsePrefix(raw)
	if err == nil && prefix.Addr().Is4() {
		return prefix.Masked(), true
	}
	prefix, _, ok := parseAddrMask(raw)
	return prefix, ok
}

func betterRoute(a, b routeChoice) bool {
	if a.bits != b.bits {
		return a.bits > b.bits
	}
	if a.ad != b.ad {
		return a.ad < b.ad
	}
	return a.order < b.order
}

func administrativeDistance(raw string) int {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return 0
	}
	n, err := strconv.Atoi(raw)
	if err != nil {
		return 0
	}
	return n
}

func egressInterface(dev ir.Device, route ir.Route) string {
	if route.Interface != "" {
		return route.Interface
	}
	next, err := netip.ParseAddr(route.NextHop)
	if err != nil {
		return ""
	}
	for _, intf := range dev.Interfaces {
		prefix, _, ok := parseInterfaceIPv4(intf.IPv4)
		if ok && prefix.Contains(next) {
			return intf.Name
		}
	}
	return ""
}

func resolveNextHop(refs []ifaceRef, currentDevice int, raw string) (ifaceRef, bool) {
	next, err := netip.ParseAddr(strings.TrimSpace(raw))
	if err != nil {
		return ifaceRef{}, false
	}
	for _, ref := range refs {
		if ref.device != currentDevice && ref.addr == next {
			return ref, true
		}
	}
	for _, ref := range refs {
		if ref.device != currentDevice && ref.prefix.Contains(next) {
			return ref, true
		}
	}
	return ifaceRef{}, false
}

func firstACLMatch(dev ir.Device, flow Flow) *ir.ACLEntry {
	for _, acl := range dev.ACLs {
		for _, entry := range acl.Entries {
			if aclEntryMatches(entry, flow) {
				item := entry
				return &item
			}
		}
	}
	return nil
}

func aclEntryMatches(entry ir.ACLEntry, flow Flow) bool {
	proto := strings.ToLower(strings.TrimSpace(entry.Protocol))
	if proto != "" && proto != "ip" && proto != "any" && proto != strings.ToLower(flow.Proto) {
		return false
	}
	text := strings.ToLower(entry.Match + " " + entry.Raw)
	return portMatches(text, flow)
}

func portMatches(text string, flow Flow) bool {
	if flow.DPort <= 0 {
		return true
	}
	if strings.TrimSpace(text) == "" {
		return true
	}
	port := strconv.Itoa(flow.DPort)
	hasNumericToken := false
	fields := strings.FieldsFunc(text, func(r rune) bool {
		return r == ' ' || r == '\t' || r == ',' || r == ';' || r == ':' || r == '/' || r == '-' || r == '(' || r == ')' || r == '[' || r == ']'
	})
	for _, field := range fields {
		if field == port {
			return true
		}
		if _, err := strconv.Atoi(field); err == nil {
			hasNumericToken = true
		}
	}
	if hasNumericToken {
		return false
	}
	return !strings.Contains(text, "eq ") && !strings.Contains(text, "dport") && !strings.Contains(text, "destination-port") && !strings.Contains(text, "port")
}

func zoneForInterface(dev ir.Device, iface string) string {
	for _, zone := range dev.Zones {
		for _, item := range zone.Interfaces {
			if strings.EqualFold(item, iface) {
				return zone.Name
			}
		}
	}
	return ""
}

func droppedByPolicy(out *Path, dev ir.Device, hop *Hop, flow Flow) bool {
	if len(dev.SecurityPolicies) == 0 {
		return false
	}
	policy := firstPolicy(dev.SecurityPolicies, hop.IngressZone, hop.EgressZone, flow)
	if policy == nil {
		out.Hops = append(out.Hops, *hop)
		out.Verdict = VerdictDroppedPolicy
		out.Reason = evidencePtr(dev.Evidence)
		return true
	}
	hop.PolicyMatch = policy
	if strings.EqualFold(policy.Action, "deny") {
		out.Hops = append(out.Hops, *hop)
		out.Verdict = VerdictDroppedPolicy
		out.Reason = evidencePtr(policy.Evidence)
		return true
	}
	return false
}

func firstPolicy(policies []ir.SecurityPolicy, from, to string, flow Flow) *ir.SecurityPolicy {
	for _, policy := range policies {
		if !zoneMatches(policy.FromZone, from) || !zoneMatches(policy.ToZone, to) {
			continue
		}
		if !serviceMatches(policy.Service, flow) {
			continue
		}
		item := policy
		return &item
	}
	return nil
}

func zoneMatches(ruleZone, actual string) bool {
	ruleZone = strings.TrimSpace(strings.ToLower(ruleZone))
	actual = strings.TrimSpace(strings.ToLower(actual))
	return ruleZone == "" || ruleZone == "any" || ruleZone == actual
}

func serviceMatches(service string, flow Flow) bool {
	service = strings.TrimSpace(strings.ToLower(service))
	if service == "" || service == "any" || service == "application-default" {
		return true
	}
	switch service {
	case "service-http", "http", "tcp-80":
		return strings.EqualFold(flow.Proto, "tcp") && flow.DPort == 80
	case "service-https", "https", "tcp-443":
		return strings.EqualFold(flow.Proto, "tcp") && flow.DPort == 443
	}
	return portMatches(service, flow)
}

func firstNAT(dev ir.Device, from, to string) *ir.NATRule {
	for _, rule := range dev.NATRules {
		if !zoneMatches(rule.FromZone, from) || !zoneMatches(rule.ToZone, to) {
			continue
		}
		item := rule
		return &item
	}
	return nil
}

func evidencePtr(e ir.Evidence) *ir.Evidence {
	return &e
}

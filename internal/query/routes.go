package query

import (
	"fmt"
	"net"
	"strings"

	"network-compiler/internal/ir"
)

func findRouteDst(dev ir.Device, destText string) []Result {
	queryPrefix, ok := parseQueryPrefix(destText)
	if !ok {
		return nil
	}

	var best *ir.Route
	bestLen := -1
	for i := range dev.Routes {
		route := dev.Routes[i]
		routePrefix, ok := parseRoutePrefix(route.Destination)
		if !ok {
			continue
		}
		if !routePrefix.Contains(queryPrefix.IP) {
			continue
		}
		ones, _ := routePrefix.Mask.Size()
		if ones > bestLen {
			best = &route
			bestLen = ones
		}
	}
	if best == nil {
		return nil
	}
	return []Result{{
		Type:     "route",
		Device:   dev.Hostname,
		Summary:  fmt.Sprintf("route %s via %s", best.Destination, best.NextHop),
		Object:   *best,
		Evidence: best.Evidence,
	}}
}

func parseQueryPrefix(destText string) (*net.IPNet, bool) {
	destText = strings.TrimSpace(destText)
	if strings.Contains(destText, "/") {
		_, network, err := net.ParseCIDR(destText)
		if err == nil {
			return network, true
		}
	}
	ip := net.ParseIP(destText)
	if ip == nil {
		return nil, false
	}
	if ip4 := ip.To4(); ip4 != nil {
		bits := 32
		if strings.HasSuffix(destText, ".0") {
			bits = 24
		}
		return &net.IPNet{IP: ip4.Mask(net.CIDRMask(bits, 32)), Mask: net.CIDRMask(bits, 32)}, true
	}
	return &net.IPNet{IP: ip, Mask: net.CIDRMask(128, 128)}, true
}

func parseRoutePrefix(dest string) (*net.IPNet, bool) {
	dest = strings.TrimSpace(dest)
	if strings.Contains(dest, "/") {
		_, network, err := net.ParseCIDR(dest)
		return network, err == nil
	}
	fields := strings.Fields(dest)
	if len(fields) != 2 {
		return nil, false
	}
	ip := net.ParseIP(fields[0])
	maskIP := net.ParseIP(fields[1])
	if ip == nil || maskIP == nil {
		return nil, false
	}
	mask := net.IPMask(maskIP.To4())
	if mask == nil {
		return nil, false
	}
	return &net.IPNet{IP: ip.Mask(mask), Mask: mask}, true
}

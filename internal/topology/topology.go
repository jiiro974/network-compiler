package topology

import (
	"fmt"
	"sort"
	"strings"

	"network-compiler/internal/ir"
)

type Result struct {
	Links     []ir.Link
	Conflicts []ir.Conflict
}

func Build(neighbors []ir.Neighbor, addresses []ir.Address) Result {
	_ = addresses
	byLocal := map[string][]ir.Neighbor{}
	for _, n := range neighbors {
		if n.LocalDevice == "" || n.LocalInterface == "" || n.RemoteDevice == "" || n.RemoteInterface == "" {
			continue
		}
		key := endpointKey(n.LocalDevice, n.LocalInterface)
		byLocal[key] = append(byLocal[key], n)
	}

	var links []ir.Link
	var conflicts []ir.Conflict
	linkGroups := map[string][]ir.Neighbor{}
	for _, group := range byLocal {
		remoteGroups := map[string][]ir.Neighbor{}
		for _, n := range group {
			remoteGroups[endpointKey(n.RemoteDevice, n.RemoteInterface)] = append(remoteGroups[endpointKey(n.RemoteDevice, n.RemoteInterface)], n)
		}
		if len(remoteGroups) > 1 {
			conflicts = append(conflicts, neighborConflict(group))
		}
		for _, ns := range remoteGroups {
			link := linkFromNeighbors(ns)
			key := linkKey(link)
			linkGroups[key] = append(linkGroups[key], ns...)
		}
	}
	for _, ns := range linkGroups {
		links = append(links, linkFromNeighbors(ns))
	}
	links = append(links, linksFromMACAddresses(addresses)...)
	sortLinks(links)
	sortConflicts(conflicts)
	return Result{Links: links, Conflicts: conflicts}
}

func Facts(result Result) []ir.DiscoveryFact {
	facts := make([]ir.DiscoveryFact, 0, len(result.Links)+len(result.Conflicts))
	for _, link := range result.Links {
		ll := link
		source := ir.Source{Kind: "topology", Command: "infer candidate links"}
		evidence := firstEvidence(ll.Evidence)
		facts = append(facts, ir.DiscoveryFact{
			Type:       "link",
			Link:       &ll,
			Source:     source,
			Evidence:   evidence,
			Confidence: ll.Confidence,
			Status:     ll.Status,
		})
	}
	for _, conflict := range result.Conflicts {
		cc := conflict
		source := ir.Source{Kind: "topology", Command: "detect discovery conflicts"}
		evidence := firstEvidence(cc.Evidence)
		facts = append(facts, ir.DiscoveryFact{
			Type:     "conflict",
			Conflict: &cc,
			Source:   source,
			Evidence: evidence,
			Status:   ir.StatusConflict,
		})
	}
	return facts
}

func linkFromNeighbors(neighbors []ir.Neighbor) ir.Link {
	first := neighbors[0]
	sources := uniqueSources(neighbors)
	link := ir.Link{
		A:          ir.LinkEndpoint{Device: first.LocalDevice, Interface: first.LocalInterface},
		B:          ir.LinkEndpoint{Device: first.RemoteDevice, Interface: first.RemoteInterface},
		Sources:    sources,
		Evidence:   evidences(neighbors),
		Confidence: confidence(sources),
		Status:     ir.StatusCandidate,
	}
	if endpointLess(link.B, link.A) {
		link.A, link.B = link.B, link.A
	}
	return link
}

func neighborConflict(neighbors []ir.Neighbor) ir.Conflict {
	return ir.Conflict{
		Type:        "neighbor_mismatch",
		Description: fmt.Sprintf("%s %s has conflicting remote endpoints", neighbors[0].LocalDevice, neighbors[0].LocalInterface),
		Sources:     uniqueSources(neighbors),
		Evidence:    evidences(neighbors),
	}
}

func linksFromMACAddresses(addresses []ir.Address) []ir.Link {
	var links []ir.Link
	seen := map[string]bool{}
	for _, address := range addresses {
		if address.Kind != "mac_table" || address.Device == "" || address.Interface == "" || address.MAC == "" {
			continue
		}
		link := ir.Link{
			A:          ir.LinkEndpoint{Device: address.Device, Interface: address.Interface},
			B:          ir.LinkEndpoint{Device: address.MAC, Interface: "mac"},
			Sources:    []string{"mac_table"},
			Evidence:   []ir.Evidence{address.Evidence},
			Confidence: 0.55,
			Status:     ir.StatusCandidate,
		}
		if endpointLess(link.B, link.A) {
			link.A, link.B = link.B, link.A
		}
		key := linkKey(link)
		if seen[key] {
			continue
		}
		seen[key] = true
		links = append(links, link)
	}
	return links
}

func confidence(sources []string) float64 {
	hasLLDP := contains(sources, "lldp")
	hasCDP := contains(sources, "cdp")
	switch {
	case hasLLDP && hasCDP:
		return 0.95
	case hasLLDP || hasCDP:
		return 0.8
	case contains(sources, "mac_table"):
		return 0.55
	case contains(sources, "interface_description"):
		return 0.35
	default:
		return 0.35
	}
}

func uniqueSources(neighbors []ir.Neighbor) []string {
	set := map[string]bool{}
	for _, n := range neighbors {
		set[n.Protocol] = true
	}
	var out []string
	for source := range set {
		out = append(out, source)
	}
	sort.Strings(out)
	return out
}

func evidences(neighbors []ir.Neighbor) []ir.Evidence {
	out := make([]ir.Evidence, 0, len(neighbors))
	for _, n := range neighbors {
		out = append(out, n.Evidence)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].File != out[j].File {
			return out[i].File < out[j].File
		}
		return out[i].StartLine < out[j].StartLine
	})
	return out
}

func endpointKey(device, intf string) string {
	return strings.ToLower(strings.TrimSpace(device)) + "\x00" + strings.ToLower(strings.TrimSpace(intf))
}

func linkKey(link ir.Link) string {
	return endpointKey(link.A.Device, link.A.Interface) + "\x00" + endpointKey(link.B.Device, link.B.Interface)
}

func endpointLess(a, b ir.LinkEndpoint) bool {
	return endpointKey(a.Device, a.Interface) < endpointKey(b.Device, b.Interface)
}

func contains(values []string, needle string) bool {
	for _, value := range values {
		if value == needle {
			return true
		}
	}
	return false
}

func firstEvidence(values []ir.Evidence) ir.Evidence {
	if len(values) == 0 {
		return ir.Evidence{}
	}
	return values[0]
}

func sortLinks(links []ir.Link) {
	sort.Slice(links, func(i, j int) bool {
		return linkKey(links[i]) < linkKey(links[j])
	})
}

func sortConflicts(conflicts []ir.Conflict) {
	sort.Slice(conflicts, func(i, j int) bool {
		return conflicts[i].Description < conflicts[j].Description
	})
}

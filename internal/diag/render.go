package diag

import (
	"fmt"
	"strconv"
	"strings"
)

func renderCommand(vendor, command string, args DiagArgs) (string, error) {
	switch strings.ToLower(command) {
	case "ping":
		if args.Dst == "" {
			return "", fmt.Errorf("ping requires dst")
		}
		count := args.Count
		if count <= 0 {
			count = 5
		}
		return renderPing(vendor, args.Dst, count, args.Source, args.VRF), nil
	case "traceroute":
		if args.Dst == "" {
			return "", fmt.Errorf("traceroute requires dst")
		}
		return renderTraceroute(vendor, args.Dst, args.VRF), nil
	case "show":
		raw := strings.TrimSpace(args.Raw)
		if raw == "" {
			return "", fmt.Errorf("show requires raw command")
		}
		return renderShow(vendor, raw), nil
	case "exec":
		raw := strings.TrimSpace(args.Raw)
		if raw == "" {
			return "", fmt.Errorf("exec requires raw command")
		}
		return raw, nil
	default:
		return "", fmt.Errorf("unknown command: %s", command)
	}
}

func renderPing(vendor, dst string, count int, source, vrf string) string {
	v := normalizeVendor(vendor)
	n := strconv.Itoa(count)
	switch v {
	case "cisco-ios", "cisco-iosxr", "cisco-nxos", "arista-eos", "aruba-cx", "fs-fsos":
		cmd := fmt.Sprintf("ping %s repeat %s", dst, n)
		if source != "" {
			cmd += " source " + source
		}
		return cmd
	case "juniper", "juniper-junos":
		cmd := fmt.Sprintf("ping %s count %s", dst, n)
		if source != "" {
			cmd += " source " + source
		}
		return cmd
	case "pan-os", "paloalto-panos":
		return fmt.Sprintf("ping host %s count %s", dst, n)
	case "mikrotik", "mikrotik-routeros":
		return fmt.Sprintf("/ping %s count=%s", dst, n)
	case "fortinet-fortigate", "fortigate":
		return fmt.Sprintf("execute ping %s repeat %s", dst, n)
	case "huawei-vrp", "hpe-comware":
		return fmt.Sprintf("ping -c %s %s", n, dst)
	default:
		return fmt.Sprintf("ping -c %s %s", n, dst)
	}
}

func renderTraceroute(vendor, dst, vrf string) string {
	v := normalizeVendor(vendor)
	switch v {
	case "cisco-ios", "cisco-iosxr", "cisco-nxos", "arista-eos", "aruba-cx", "fs-fsos":
		return "traceroute " + dst
	case "juniper", "juniper-junos":
		return "traceroute " + dst
	case "pan-os", "paloalto-panos":
		return "traceroute host " + dst
	case "mikrotik", "mikrotik-routeros":
		return "/tool traceroute " + dst
	case "fortinet-fortigate", "fortigate":
		return "execute traceroute " + dst
	default:
		return "traceroute " + dst
	}
}

func renderShow(vendor, raw string) string {
	v := normalizeVendor(vendor)
	lower := strings.ToLower(strings.TrimSpace(raw))
	switch v {
	case "juniper", "juniper-junos":
		if strings.HasPrefix(lower, "show ") {
			return "display" + raw[4:]
		}
		if strings.HasPrefix(lower, "display ") {
			return raw
		}
		return "display " + raw
	default:
		if strings.HasPrefix(lower, "display ") {
			return "show" + raw[7:]
		}
		return raw
	}
}

func normalizeVendor(vendor string) string {
	v := strings.ToLower(strings.TrimSpace(vendor))
	switch v {
	case "cisco", "ios":
		return "cisco-ios"
	default:
		return v
	}
}

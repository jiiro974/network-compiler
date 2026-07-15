package report

import (
	"fmt"
	"io"

	"network-compiler/internal/ir"
	"network-compiler/internal/query"
)

func WriteParse(w io.Writer, device ir.Device) error {
	if _, err := fmt.Fprintf(w, "source: %s\n", device.SourceFile); err != nil {
		return err
	}
	if device.Hostname != "" {
		if _, err := fmt.Fprintf(w, "hostname: %s\n", device.Hostname); err != nil {
			return err
		}
	}
	if _, err := fmt.Fprintf(w, "vlans: %d\n", len(device.VLANs)); err != nil {
		return err
	}
	for _, vlan := range device.VLANs {
		name := vlan.Name
		if name == "" {
			name = "(unnamed)"
		}
		if _, err := fmt.Fprintf(w, "  - vlan %d name %s\n", vlan.ID, name); err != nil {
			return err
		}
	}
	if _, err := fmt.Fprintf(w, "interfaces: %d\n", len(device.Interfaces)); err != nil {
		return err
	}
	for _, intf := range device.Interfaces {
		if _, err := fmt.Fprintf(w, "  - %s mode=%s access_vlan=%d trunk_allowed=%v\n", intf.Name, intf.Mode, intf.AccessVLAN, intf.TrunkVLANs); err != nil {
			return err
		}
	}
	return nil
}

func WriteQuery(w io.Writer, results []query.Result) error {
	if len(results) == 0 {
		_, err := fmt.Fprintln(w, "non trouvé")
		return err
	}
	for _, result := range results {
		if _, err := fmt.Fprintf(w, "- %s\n", result.Summary); err != nil {
			return err
		}
		ev := result.Evidence
		if _, err := fmt.Fprintf(w, "  evidence: %s:%d-%d\n", ev.File, ev.StartLine, ev.EndLine); err != nil {
			return err
		}
	}
	return nil
}

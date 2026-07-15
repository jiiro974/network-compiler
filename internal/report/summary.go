package report

import (
	"fmt"
	"io"

	"network-compiler/internal/ir"
)

type InventorySummary struct {
	Devices         int `json:"devices"`
	Interfaces      int `json:"interfaces"`
	VLANs           int `json:"vlans"`
	Routes          int `json:"routes"`
	ACLs            int `json:"acls"`
	NTPServers      int `json:"ntp_servers"`
	SyslogHosts     int `json:"syslog_hosts"`
	SNMPCommunities int `json:"snmp_communities"`
	SNMPHosts       int `json:"snmp_hosts"`
	SNMPTraps       int `json:"snmp_traps"`
	SNMPStatements  int `json:"snmp_statements"`
}

func Summarize(devices []ir.Device) InventorySummary {
	var s InventorySummary
	s.Devices = len(devices)
	for _, dev := range devices {
		s.Interfaces += len(dev.Interfaces)
		s.VLANs += len(dev.VLANs)
		s.Routes += len(dev.Routes)
		s.ACLs += len(dev.ACLs)
		s.NTPServers += len(dev.Services.NTPServers)
		s.SyslogHosts += len(dev.Services.SyslogHosts)
		s.SNMPCommunities += len(dev.Services.SNMPCommunities)
		s.SNMPHosts += len(dev.SNMP.Hosts)
		s.SNMPTraps += len(dev.SNMP.Traps)
		s.SNMPStatements += len(dev.SNMP.Statements)
	}
	return s
}

func WriteInventory(w io.Writer, devices []ir.Device) error {
	s := Summarize(devices)
	if _, err := fmt.Fprintf(w, "devices: %d\ninterfaces: %d\nvlans: %d\nroutes: %d\nacls: %d\nntp_servers: %d\nsyslog_hosts: %d\nsnmp_communities: %d\nsnmp_hosts: %d\nsnmp_traps: %d\nsnmp_statements: %d\n", s.Devices, s.Interfaces, s.VLANs, s.Routes, s.ACLs, s.NTPServers, s.SyslogHosts, s.SNMPCommunities, s.SNMPHosts, s.SNMPTraps, s.SNMPStatements); err != nil {
		return err
	}
	for _, dev := range devices {
		if _, err := fmt.Fprintf(w, "- %s interfaces=%d vlans=%d routes=%d acls=%d source=%s\n", dev.Hostname, len(dev.Interfaces), len(dev.VLANs), len(dev.Routes), len(dev.ACLs), dev.SourceFile); err != nil {
			return err
		}
	}
	return nil
}

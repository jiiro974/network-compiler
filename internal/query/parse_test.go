package query

import (
	"strings"
	"testing"
)

func TestNormalizeQuery(t *testing.T) {
	tests := []struct {
		in, want string
	}{
		{"  Find  VLAN 42  ", "vlan 42"},
		{"help?", "help"},
		{"Ou est VLAN 42?", "ou est vlan 42"},
		{"route par défaut", "route par defaut"},
		{"équipement sw1", "equipement sw1"},
	}
	for _, tt := range tests {
		if got := normalizeQuery(tt.in); got != tt.want {
			t.Fatalf("normalizeQuery(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestParseQueryIntents(t *testing.T) {
	tests := []struct {
		query  string
		intent Intent
		vlanID int
		mode   string
		name   string
		dest   string
	}{
		{query: "help", intent: IntentHelp},
		{query: "?", intent: IntentHelp},
		{query: "aide", intent: IntentHelp},
		{query: "commands", intent: IntentHelp},
		{query: "find vlan 42", intent: IntentVLAN, vlanID: 42, mode: "used"},
		{query: "where is vlan 42", intent: IntentVLAN, vlanID: 42, mode: "used"},
		{query: "who uses vlan 42", intent: IntentVLAN, vlanID: 42, mode: "used"},
		{query: "ou est vlan 42", intent: IntentVLAN, vlanID: 42, mode: "used"},
		{query: "vlan 42 trunks", intent: IntentVLAN, vlanID: 42, mode: "trunks"},
		{query: "access vlan 42", intent: IntentAccessVLAN, vlanID: 42},
		{query: "vlan 42 access ports", intent: IntentAccessVLAN, vlanID: 42},
		{query: "interfaces access vlan 42", intent: IntentAccessVLAN, vlanID: 42},
		{query: "default route", intent: IntentDefaultRoute},
		{query: "default gateway", intent: IntentDefaultRoute},
		{query: "route 0/0", intent: IntentDefaultRoute},
		{query: "route par defaut", intent: IntentDefaultRoute},
		{query: "passerelle par defaut", intent: IntentDefaultRoute},
		{query: "route to 192.168.50.0", intent: IntentRouteDst, dest: "192.168.50.0"},
		{query: "routes vers 10.0.0.0/8", intent: IntentRouteDst, dest: "10.0.0.0/8"},
		{query: "route for 192.168.50.0", intent: IntentRouteDst, dest: "192.168.50.0"},
		{query: "trunks", intent: IntentTrunks},
		{query: "trunk ports", intent: IntentTrunks},
		{query: "interfaces trunk", intent: IntentTrunks},
		{query: "interfaces en trunk", intent: IntentTrunks},
		{query: "interface Gi0/1", intent: IntentInterface, name: "gi0/1"},
		{query: "intf Gi0/1", intent: IntentInterface, name: "gi0/1"},
		{query: "port Gi0/1", intent: IntentInterface, name: "gi0/1"},
		{query: "acl 101", intent: IntentACL, name: "101"},
		{query: "access-list 101", intent: IntentACL, name: "101"},
		{query: "acl USERS-IN", intent: IntentACL, name: "users-in"},
		{query: "device sw1", intent: IntentDevice, name: "sw1"},
		{query: "host sw1", intent: IntentDevice, name: "sw1"},
		{query: "switch sw1", intent: IntentDevice, name: "sw1"},
		{query: "equipement sw1", intent: IntentDevice, name: "sw1"},
		{query: "ntp", intent: IntentNTP},
		{query: "ntp servers", intent: IntentNTP},
		{query: "serveurs ntp", intent: IntentNTP},
		{query: "syslog", intent: IntentSyslog},
		{query: "logging", intent: IntentSyslog},
		{query: "serveurs syslog", intent: IntentSyslog},
		{query: "snmp", intent: IntentSNMP},
		{query: "communautes snmp", intent: IntentSNMP},
		{query: "zones", intent: IntentZones},
		{query: "firewall zones", intent: IntentZones},
		{query: "policies", intent: IntentPolicies},
		{query: "security policies", intent: IntentPolicies},
		{query: "politiques", intent: IntentPolicies},
	}
	for _, tt := range tests {
		t.Run(tt.query, func(t *testing.T) {
			pq, err := parseQuery(tt.query)
			if err != nil {
				t.Fatalf("parseQuery() error = %v", err)
			}
			if pq.Intent != tt.intent {
				t.Fatalf("Intent = %v, want %v", pq.Intent, tt.intent)
			}
			if tt.vlanID != 0 && pq.VLANID != tt.vlanID {
				t.Fatalf("VLANID = %d, want %d", pq.VLANID, tt.vlanID)
			}
			if tt.mode != "" && pq.VLANMode != tt.mode {
				t.Fatalf("VLANMode = %q, want %q", pq.VLANMode, tt.mode)
			}
			if tt.name != "" && pq.Name != tt.name {
				t.Fatalf("Name = %q, want %q", pq.Name, tt.name)
			}
			if tt.dest != "" && pq.RouteDest != tt.dest {
				t.Fatalf("RouteDest = %q, want %q", pq.RouteDest, tt.dest)
			}
		})
	}
}

func TestParseQueryErrors(t *testing.T) {
	tests := []struct {
		query    string
		contains string
	}{
		{query: "", contains: "requete vide"},
		{query: "show vlan 10", contains: "requete non reconnue"},
		{query: "show vlan 10", contains: "help"},
		{query: "find vlan abc", contains: "vlan invalide"},
		{query: "vlan 42 unknown", contains: "requete non reconnue"},
	}
	for _, tt := range tests {
		t.Run(tt.query, func(t *testing.T) {
			_, err := parseQuery(tt.query)
			if err == nil {
				t.Fatal("parseQuery() error = nil, want error")
			}
			if !strings.Contains(err.Error(), tt.contains) {
				t.Fatalf("error = %q, want substring %q", err.Error(), tt.contains)
			}
		})
	}
}

func TestHelpPatternsStable(t *testing.T) {
	first := HelpPatterns()
	second := HelpPatterns()
	if len(first) == 0 {
		t.Fatal("HelpPatterns() is empty")
	}
	for i := range first {
		if first[i] != second[i] {
			t.Fatalf("HelpPatterns()[%d] = %q, want stable %q", i, first[i], second[i])
		}
	}
}

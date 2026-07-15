package ir

type Evidence struct {
	File      string `json:"file"`
	StartLine int    `json:"start_line"`
	EndLine   int    `json:"end_line"`
	RawBlock  string `json:"raw_block"`
	Parser    string `json:"parser"`
}

type Device struct {
	Hostname      string      `json:"hostname"`
	Vendor        string      `json:"vendor"`
	SourceFile    string      `json:"source_file"`
	ParserVersion string      `json:"parser_version"`
	Interfaces    []Interface `json:"interfaces"`
	VLANs         []VLAN      `json:"vlans"`
	Routes        []Route     `json:"routes"`
	ACLs          []ACL       `json:"acls"`
	Services      Services    `json:"services"`
	Evidence      Evidence    `json:"evidence"`
}

type Interface struct {
	Name        string   `json:"name"`
	Description string   `json:"description,omitempty"`
	Mode        string   `json:"mode"`
	AccessVLAN  int      `json:"access_vlan,omitempty"`
	TrunkVLANs  []int    `json:"trunk_vlans,omitempty"`
	IPv4        string   `json:"ipv4,omitempty"`
	Shutdown    bool     `json:"shutdown"`
	Evidence    Evidence `json:"evidence"`
}

type VLAN struct {
	ID       int      `json:"id"`
	Name     string   `json:"name,omitempty"`
	Evidence Evidence `json:"evidence"`
}

type Route struct {
	Destination            string   `json:"destination"`
	NextHop                string   `json:"next_hop"`
	Interface              string   `json:"interface,omitempty"`
	AdministrativeDistance string   `json:"administrative_distance,omitempty"`
	VRF                    string   `json:"vrf,omitempty"`
	Evidence               Evidence `json:"evidence"`
}

type ACL struct {
	Name     string     `json:"name"`
	Entries  []ACLEntry `json:"entries"`
	Evidence Evidence   `json:"evidence"`
}

type ACLEntry struct {
	Action   string   `json:"action"`
	Protocol string   `json:"protocol"`
	Match    string   `json:"match,omitempty"`
	Raw      string   `json:"raw"`
	Evidence Evidence `json:"evidence"`
}

type Services struct {
	NTPServers      []ServiceTarget `json:"ntp_servers,omitempty"`
	SyslogHosts     []ServiceTarget `json:"syslog_hosts,omitempty"`
	SNMPCommunities []ServiceTarget `json:"snmp_communities,omitempty"`
}

type ServiceTarget struct {
	Value    string   `json:"value"`
	Evidence Evidence `json:"evidence"`
}

package ir

type Evidence struct {
	File      string `json:"file"`
	StartLine int    `json:"start_line"`
	EndLine   int    `json:"end_line"`
	RawBlock  string `json:"raw_block"`
	Parser    string `json:"parser"`
}

type Source struct {
	Device  string `json:"device,omitempty"`
	Command string `json:"command,omitempty"`
	Kind    string `json:"kind,omitempty"`
	File    string `json:"file,omitempty"`
}

const (
	StatusCandidate = "candidate"
	StatusConflict  = "conflict"
)

type Neighbor struct {
	LocalDevice     string   `json:"local_device"`
	LocalInterface  string   `json:"local_interface"`
	RemoteDevice    string   `json:"remote_device"`
	RemoteInterface string   `json:"remote_interface,omitempty"`
	Protocol        string   `json:"protocol"`
	Platform        string   `json:"platform,omitempty"`
	Capability      string   `json:"capability,omitempty"`
	Evidence        Evidence `json:"evidence"`
	Source          Source   `json:"source"`
	Confidence      float64  `json:"confidence"`
	Status          string   `json:"status"`
}

type Address struct {
	Device     string   `json:"device"`
	Interface  string   `json:"interface,omitempty"`
	IP         string   `json:"ip,omitempty"`
	MAC        string   `json:"mac,omitempty"`
	VLAN       int      `json:"vlan,omitempty"`
	Kind       string   `json:"kind"`
	Evidence   Evidence `json:"evidence"`
	Source     Source   `json:"source"`
	Confidence float64  `json:"confidence"`
	Status     string   `json:"status"`
}

type LinkEndpoint struct {
	Device    string `json:"device"`
	Interface string `json:"interface"`
}

type Link struct {
	A          LinkEndpoint `json:"a"`
	B          LinkEndpoint `json:"b"`
	Sources    []string     `json:"sources"`
	Evidence   []Evidence   `json:"evidence"`
	Confidence float64      `json:"confidence"`
	Status     string       `json:"status"`
	Conflicts  []Conflict   `json:"conflicts,omitempty"`
}

type Conflict struct {
	Type        string     `json:"type"`
	Description string     `json:"description"`
	Sources     []string   `json:"sources"`
	Evidence    []Evidence `json:"evidence"`
}

type DiscoveryFact struct {
	Type       string    `json:"type"`
	Neighbor   *Neighbor `json:"neighbor,omitempty"`
	Address    *Address  `json:"address,omitempty"`
	Link       *Link     `json:"link,omitempty"`
	Conflict   *Conflict `json:"conflict,omitempty"`
	Source     Source    `json:"source,omitempty"`
	Evidence   Evidence  `json:"evidence,omitempty"`
	Confidence float64   `json:"confidence"`
	Status     string    `json:"status"`
}

type Device struct {
	Hostname         string           `json:"hostname"`
	Vendor           string           `json:"vendor"`
	SourceFile       string           `json:"source_file"`
	ParserVersion    string           `json:"parser_version"`
	Interfaces       []Interface      `json:"interfaces"`
	VLANs            []VLAN           `json:"vlans"`
	Routes           []Route          `json:"routes"`
	ACLs             []ACL            `json:"acls"`
	Zones            []Zone           `json:"zones,omitempty"`
	SecurityPolicies []SecurityPolicy `json:"security_policies,omitempty"`
	NATRules         []NATRule        `json:"nat_rules,omitempty"`
	Services         Services         `json:"services"`
	SNMP             SNMP             `json:"snmp,omitempty"`
	Evidence         Evidence         `json:"evidence"`
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

type Zone struct {
	Name       string   `json:"name"`
	Interfaces []string `json:"interfaces,omitempty"`
	Evidence   Evidence `json:"evidence"`
}

type SecurityPolicy struct {
	Name        string   `json:"name"`
	FromZone    string   `json:"from_zone,omitempty"`
	ToZone      string   `json:"to_zone,omitempty"`
	Application string   `json:"application,omitempty"`
	Service     string   `json:"service,omitempty"`
	Action      string   `json:"action"`
	Evidence    Evidence `json:"evidence"`
}

type NATRule struct {
	Name       string   `json:"name"`
	FromZone   string   `json:"from_zone,omitempty"`
	ToZone     string   `json:"to_zone,omitempty"`
	Kind       string   `json:"kind,omitempty"`
	Translated string   `json:"translated,omitempty"`
	Evidence   Evidence `json:"evidence"`
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

type SNMP struct {
	Communities []ServiceTarget `json:"communities,omitempty"`
	Hosts       []SNMPHost      `json:"hosts,omitempty"`
	Traps       []SNMPTrap      `json:"traps,omitempty"`
	Location    ServiceTarget   `json:"location,omitempty"`
	Contact     ServiceTarget   `json:"contact,omitempty"`
	Statements  []RawStatement  `json:"statements,omitempty"`
}

type SNMPHost struct {
	Host      string   `json:"host"`
	Version   string   `json:"version,omitempty"`
	Community string   `json:"community,omitempty"`
	Options   []string `json:"options,omitempty"`
	Evidence  Evidence `json:"evidence"`
}

type SNMPTrap struct {
	Name     string   `json:"name"`
	Options  []string `json:"options,omitempty"`
	Evidence Evidence `json:"evidence"`
}

type RawStatement struct {
	Kind     string   `json:"kind"`
	Fields   []string `json:"fields,omitempty"`
	Raw      string   `json:"raw"`
	Evidence Evidence `json:"evidence"`
}

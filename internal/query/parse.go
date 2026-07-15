package query

import (
	"fmt"
	"strconv"
	"strings"
	"unicode"
)

// Intent identifies a parsed query kind. Match order is fixed (first match wins):
// help → access_vlan → vlan → default_route → route_dst → trunks → interface →
// acl → device → ntp → syslog → snmp → zones → policies.
type Intent int

const (
	IntentHelp Intent = iota
	IntentAccessVLAN
	IntentVLAN
	IntentDefaultRoute
	IntentRouteDst
	IntentTrunks
	IntentInterface
	IntentACL
	IntentDevice
	IntentNTP
	IntentSyslog
	IntentSNMP
	IntentZones
	IntentPolicies
)

type parsedQuery struct {
	Intent    Intent
	VLANID    int
	VLANMode  string
	Name      string
	RouteDest string
}

// HelpPatterns returns the stable list of supported query patterns.
func HelpPatterns() []string {
	return []string{
		"help | ? | aide | commands",
		"vlan <id> [used|active|declared|trunks|access]",
		"where is vlan <id> | who uses vlan <id> | ou est vlan <id>",
		"access vlan <id> | vlan <id> access ports | interfaces access vlan <id>",
		"trunks | trunk ports | interfaces trunk | interfaces en trunk",
		"interface <name> | intf <name> | port <name>",
		"default route | default gateway | route 0/0 | route par defaut",
		"route to <dest> | routes vers <dest> | route for <dest>",
		"acl <name> | access-list <name>",
		"device <host> | host <host> | switch <host> | equipement <host>",
		"ntp | ntp servers | serveurs ntp",
		"syslog | logging | syslog hosts | serveurs syslog",
		"snmp | snmp communities | communautes snmp",
		"zones | firewall zones",
		"policies | security policies | politiques",
	}
}

func normalizeQuery(q string) string {
	q = strings.TrimSpace(q)
	if q == "?" {
		return "?"
	}
	q = strings.TrimSuffix(q, "?")
	q = strings.ToLower(strings.TrimSpace(q))
	q = stripAccents(q)
	fields := strings.Fields(q)
	q = strings.Join(fields, " ")
	return stripFindPrefix(q)
}

func stripAccents(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		switch r {
		case 'à', 'â', 'ä':
			b.WriteRune('a')
		case 'é', 'è', 'ê', 'ë':
			b.WriteRune('e')
		case 'î', 'ï':
			b.WriteRune('i')
		case 'ô', 'ö':
			b.WriteRune('o')
		case 'ù', 'û', 'ü':
			b.WriteRune('u')
		case 'ç':
			b.WriteRune('c')
		default:
			if unicode.IsLetter(r) || unicode.IsDigit(r) || r == '/' || r == '.' || r == ':' || r == '-' || r == '_' {
				b.WriteRune(r)
			} else if unicode.IsSpace(r) {
				b.WriteRune(' ')
			}
		}
	}
	return b.String()
}

func parseQuery(raw string) (parsedQuery, error) {
	nq := normalizeQuery(raw)
	if nq == "" {
		return parsedQuery{}, fmt.Errorf("requete vide")
	}

	if isHelp(nq) {
		return parsedQuery{Intent: IntentHelp}, nil
	}
	if pq, ok, err := parseAccessVLANIntent(nq); ok || err != nil {
		if err != nil {
			return parsedQuery{}, err
		}
		return pq, nil
	}
	if pq, ok, err := parseVLANIntent(nq); ok || err != nil {
		if err != nil {
			return parsedQuery{}, err
		}
		return pq, nil
	}
	if isDefaultRoute(nq) {
		return parsedQuery{Intent: IntentDefaultRoute}, nil
	}
	if dest, ok := parseRouteDst(nq); ok {
		return parsedQuery{Intent: IntentRouteDst, RouteDest: dest}, nil
	}
	if isTrunks(nq) {
		return parsedQuery{Intent: IntentTrunks}, nil
	}
	if name, ok := parseInterface(nq); ok {
		return parsedQuery{Intent: IntentInterface, Name: name}, nil
	}
	if name, ok := parseACL(nq); ok {
		return parsedQuery{Intent: IntentACL, Name: name}, nil
	}
	if name, ok := parseDevice(nq); ok {
		return parsedQuery{Intent: IntentDevice, Name: name}, nil
	}
	if isNTP(nq) {
		return parsedQuery{Intent: IntentNTP}, nil
	}
	if isSyslog(nq) {
		return parsedQuery{Intent: IntentSyslog}, nil
	}
	if isSNMP(nq) {
		return parsedQuery{Intent: IntentSNMP}, nil
	}
	if isZones(nq) {
		return parsedQuery{Intent: IntentZones}, nil
	}
	if isPolicies(nq) {
		return parsedQuery{Intent: IntentPolicies}, nil
	}
	return parsedQuery{}, fmt.Errorf("requete non reconnue: %q (tapez 'help' pour la liste)", raw)
}

func stripFindPrefix(q string) string {
	fields := strings.Fields(q)
	if len(fields) > 0 && fields[0] == "find" {
		return strings.Join(fields[1:], " ")
	}
	return q
}

func isHelp(nq string) bool {
	switch nq {
	case "help", "?", "aide", "commands":
		return true
	default:
		return false
	}
}

func parseAccessVLANIntent(nq string) (parsedQuery, bool, error) {
	fields := strings.Fields(nq)
	switch {
	case len(fields) == 3 && fields[0] == "access" && fields[1] == "vlan":
		id, err := parseVLANNumber(fields[2])
		if err != nil {
			return parsedQuery{}, true, err
		}
		return parsedQuery{Intent: IntentAccessVLAN, VLANID: id}, true, nil
	case len(fields) == 4 && fields[0] == "vlan" && fields[2] == "access" && fields[3] == "ports":
		id, err := parseVLANNumber(fields[1])
		if err != nil {
			return parsedQuery{}, true, err
		}
		return parsedQuery{Intent: IntentAccessVLAN, VLANID: id}, true, nil
	case len(fields) == 4 && fields[0] == "ports" && fields[1] == "access" && fields[2] == "vlan":
		id, err := parseVLANNumber(fields[3])
		if err != nil {
			return parsedQuery{}, true, err
		}
		return parsedQuery{Intent: IntentAccessVLAN, VLANID: id}, true, nil
	case len(fields) == 4 && fields[0] == "interfaces" && fields[1] == "access" && fields[2] == "vlan":
		id, err := parseVLANNumber(fields[3])
		if err != nil {
			return parsedQuery{}, true, err
		}
		return parsedQuery{Intent: IntentAccessVLAN, VLANID: id}, true, nil
	}
	return parsedQuery{}, false, nil
}

func parseVLANIntent(nq string) (parsedQuery, bool, error) {
	if id, ok := extractNaturalVLAN(nq); ok {
		return parsedQuery{Intent: IntentVLAN, VLANID: id, VLANMode: "used"}, true, nil
	}

	fields := strings.Fields(nq)
	if len(fields) == 0 || fields[0] != "vlan" {
		return parsedQuery{}, false, nil
	}
	if len(fields) < 2 || len(fields) > 3 {
		return parsedQuery{}, true, fmt.Errorf("requete non reconnue: %q (tapez 'help' pour la liste)", nq)
	}
	id, err := parseVLANNumber(fields[1])
	if err != nil {
		return parsedQuery{}, true, err
	}
	mode := "used"
	if len(fields) == 3 {
		switch fields[2] {
		case "used", "active":
			mode = "used"
		case "declared":
			mode = "declared"
		case "trunks":
			mode = "trunks"
		case "access":
			mode = "access"
		default:
			return parsedQuery{}, true, fmt.Errorf("requete non reconnue: %q (tapez 'help' pour la liste)", nq)
		}
	}
	return parsedQuery{Intent: IntentVLAN, VLANID: id, VLANMode: mode}, true, nil
}

func extractNaturalVLAN(nq string) (int, bool) {
	prefixes := []string{
		"where is vlan ",
		"who uses vlan ",
		"ou est vlan ",
	}
	for _, prefix := range prefixes {
		if strings.HasPrefix(nq, prefix) {
			idText := strings.TrimSpace(strings.TrimPrefix(nq, prefix))
			if idText == "" || strings.Contains(idText, " ") {
				return 0, false
			}
			id, err := parseVLANNumber(idText)
			if err != nil {
				return 0, false
			}
			return id, true
		}
	}
	return 0, false
}

func parseVLANNumber(s string) (int, error) {
	id, err := strconv.Atoi(s)
	if err != nil {
		return 0, fmt.Errorf("vlan invalide: %q", s)
	}
	return id, nil
}

func isDefaultRoute(nq string) bool {
	switch nq {
	case "default route", "default gateway", "route 0/0", "route 0.0.0.0/0", "route par defaut", "passerelle par defaut":
		return true
	default:
		return false
	}
}

func parseRouteDst(nq string) (string, bool) {
	prefixes := []string{"route to ", "routes to ", "route for ", "routes for ", "route vers ", "routes vers "}
	for _, prefix := range prefixes {
		if strings.HasPrefix(nq, prefix) {
			dest := strings.TrimSpace(strings.TrimPrefix(nq, prefix))
			if dest != "" && !strings.Contains(dest, " ") {
				return dest, true
			}
		}
	}
	return "", false
}

func isTrunks(nq string) bool {
	switch nq {
	case "trunks", "trunk ports", "ports trunk", "interfaces trunk", "interfaces en trunk":
		return true
	default:
		return false
	}
}

func parseInterface(nq string) (string, bool) {
	fields := strings.Fields(nq)
	if len(fields) != 2 {
		return "", false
	}
	switch fields[0] {
	case "interface", "intf", "port":
		return fields[1], true
	default:
		return "", false
	}
}

func parseACL(nq string) (string, bool) {
	fields := strings.Fields(nq)
	if len(fields) != 2 {
		return "", false
	}
	switch fields[0] {
	case "acl", "access-list":
		return fields[1], true
	default:
		return "", false
	}
}

func parseDevice(nq string) (string, bool) {
	fields := strings.Fields(nq)
	if len(fields) != 2 {
		return "", false
	}
	switch fields[0] {
	case "device", "host", "equipement", "switch":
		return fields[1], true
	default:
		return "", false
	}
}

func isNTP(nq string) bool {
	switch nq {
	case "ntp", "ntp servers", "serveurs ntp":
		return true
	default:
		return false
	}
}

func isSyslog(nq string) bool {
	switch nq {
	case "syslog", "logging", "syslog hosts", "serveurs syslog":
		return true
	default:
		return false
	}
}

func isSNMP(nq string) bool {
	switch nq {
	case "snmp", "snmp communities", "communautes snmp":
		return true
	default:
		return false
	}
}

func isZones(nq string) bool {
	switch nq {
	case "zones", "firewall zones":
		return true
	default:
		return false
	}
}

func isPolicies(nq string) bool {
	switch nq {
	case "policies", "security policies", "politiques":
		return true
	default:
		return false
	}
}

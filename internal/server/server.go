package server

import (
	"encoding/json"
	"io"
	"net/http"
	"sort"
	"strconv"
	"strings"

	"network-compiler/internal/compliance"
	"network-compiler/internal/diag"
	"network-compiler/internal/diff"
	"network-compiler/internal/ir"
	"network-compiler/internal/parser/cisco"
	pathtrace "network-compiler/internal/path"
	"network-compiler/internal/query"
	"network-compiler/internal/report"
)

type Server struct {
	devices        []ir.Device
	policy         compliance.Policy
	vendors        []string
	discoveryFacts []ir.DiscoveryFact
	diag           *diag.Service
}

func New(devices []ir.Device, policies ...compliance.Policy) *Server {
	var policy compliance.Policy
	if len(policies) > 0 {
		policy = policies[0]
	}
	return &Server{devices: devices, policy: policy}
}

func (s *Server) WithVendors(vendors []string) *Server {
	s.vendors = append([]string(nil), vendors...)
	return s
}

func (s *Server) WithDiscoveryFacts(facts []ir.DiscoveryFact) *Server {
	s.discoveryFacts = append([]ir.DiscoveryFact(nil), facts...)
	return s
}

func (s *Server) WithDiag(svc *diag.Service) *Server {
	s.diag = svc
	return s
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/", s.handleIndex)
	mux.HandleFunc("/path", s.handlePathPage)
	mux.HandleFunc("/path/fixtures/", s.handlePathFixture)
	mux.HandleFunc("/api/summary", s.handleSummary)
	mux.HandleFunc("/api/devices", s.handleDevices)
	mux.HandleFunc("/api/device", s.handleDevice)
	mux.HandleFunc("/api/diff", s.handleDiff)
	mux.HandleFunc("/api/policy", s.handlePolicy)
	mux.HandleFunc("/api/path", s.handlePath)
	mux.HandleFunc("/api/path/validate", s.handlePathValidate)
	mux.HandleFunc("/api/diag", s.handleDiag)
	mux.HandleFunc("/api/query", s.handleQuery)
	mux.HandleFunc("/api/vlan-path", s.handleVLANPath)
	mux.HandleFunc("/api/check", s.handleCheck)
	mux.HandleFunc("/api/check/summary", s.handleCheckSummary)
	mux.HandleFunc("/api/vendors", s.handleVendors)
	return mux
}

func (s *Server) handleIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write([]byte(indexHTML))
}

func (s *Server) handleSummary(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, report.Summarize(s.devices))
}

func (s *Server) handleDevices(w http.ResponseWriter, r *http.Request) {
	filter := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("q")))
	type deviceRow struct {
		Hostname    string `json:"hostname"`
		Vendor      string `json:"vendor"`
		SourceFile  string `json:"source_file"`
		Interfaces  int    `json:"interfaces"`
		VLANs       int    `json:"vlans"`
		Routes      int    `json:"routes"`
		ACLs        int    `json:"acls"`
		NTPServers  int    `json:"ntp_servers"`
		SyslogHosts int    `json:"syslog_hosts"`
		SNMPHosts   int    `json:"snmp_hosts"`
	}
	rows := make([]deviceRow, 0, len(s.devices))
	for _, dev := range s.devices {
		if filter != "" && !strings.Contains(strings.ToLower(dev.Hostname), filter) && !strings.Contains(strings.ToLower(dev.SourceFile), filter) {
			continue
		}
		rows = append(rows, deviceRow{
			Hostname:    dev.Hostname,
			Vendor:      dev.Vendor,
			SourceFile:  dev.SourceFile,
			Interfaces:  len(dev.Interfaces),
			VLANs:       len(dev.VLANs),
			Routes:      len(dev.Routes),
			ACLs:        len(dev.ACLs),
			NTPServers:  len(dev.Services.NTPServers),
			SyslogHosts: len(dev.Services.SyslogHosts),
			SNMPHosts:   len(dev.SNMP.Hosts),
		})
	}
	writeJSON(w, rows)
}

func (s *Server) handleDevice(w http.ResponseWriter, r *http.Request) {
	name := strings.TrimSpace(r.URL.Query().Get("name"))
	if name == "" {
		writeError(w, http.StatusBadRequest, "missing name")
		return
	}
	for _, dev := range s.devices {
		if strings.EqualFold(dev.Hostname, name) {
			if r.URL.Query().Get("brief") == "1" {
				writeJSON(w, deviceSummary(dev))
				return
			}
			writeJSON(w, dev)
			return
		}
	}
	writeError(w, http.StatusNotFound, "device not found")
}

type deviceSummaryRow struct {
	Hostname        string   `json:"hostname"`
	Vendor          string   `json:"vendor"`
	SourceFile      string   `json:"source_file"`
	Interfaces      int      `json:"interfaces"`
	VLANs           int      `json:"vlans"`
	Routes          int      `json:"routes"`
	ACLs            int      `json:"acls"`
	NTPServers      []string `json:"ntp_servers"`
	SyslogHosts     []string `json:"syslog_hosts"`
	SNMPCommunities []string `json:"snmp_communities"`
	SNMPHosts       int      `json:"snmp_hosts"`
	SNMPTraps       int      `json:"snmp_traps"`
	SNMPStatements  int      `json:"snmp_statements"`
}

func deviceSummary(dev ir.Device) deviceSummaryRow {
	return deviceSummaryRow{
		Hostname:        dev.Hostname,
		Vendor:          dev.Vendor,
		SourceFile:      dev.SourceFile,
		Interfaces:      len(dev.Interfaces),
		VLANs:           len(dev.VLANs),
		Routes:          len(dev.Routes),
		ACLs:            len(dev.ACLs),
		NTPServers:      serviceValues(dev.Services.NTPServers),
		SyslogHosts:     serviceValues(dev.Services.SyslogHosts),
		SNMPCommunities: serviceValues(dev.Services.SNMPCommunities),
		SNMPHosts:       len(dev.SNMP.Hosts),
		SNMPTraps:       len(dev.SNMP.Traps),
		SNMPStatements:  len(dev.SNMP.Statements),
	}
}

func serviceValues(items []ir.ServiceTarget) []string {
	out := make([]string, 0, len(items))
	for _, item := range items {
		out = append(out, item.Value)
	}
	return out
}

func (s *Server) handleQuery(w http.ResponseWriter, r *http.Request) {
	q := strings.TrimSpace(r.URL.Query().Get("q"))
	if q == "" {
		writeError(w, http.StatusBadRequest, "missing q")
		return
	}
	results, err := query.Run(s.devices, q)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	limit := 50
	if raw := r.URL.Query().Get("limit"); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil || parsed < 0 {
			writeError(w, http.StatusBadRequest, "invalid limit")
			return
		}
		limit = parsed
	}
	if limit > 0 && len(results) > limit {
		results = results[:limit]
	}
	if r.URL.Query().Get("brief") == "1" {
		writeJSON(w, briefResults(results))
		return
	}
	writeJSON(w, results)
}

func (s *Server) handlePath(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	src := strings.TrimSpace(q.Get("src"))
	dst := strings.TrimSpace(q.Get("dst"))
	proto := strings.TrimSpace(q.Get("proto"))
	if src == "" || dst == "" || proto == "" {
		writeError(w, http.StatusBadRequest, "missing src, dst, or proto")
		return
	}
	dport := 0
	if raw := strings.TrimSpace(q.Get("dport")); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil || parsed < 0 || parsed > 65535 {
			writeError(w, http.StatusBadRequest, "invalid dport")
			return
		}
		dport = parsed
	}
	result, err := pathtrace.Trace(s.devices, pathtrace.Flow{Src: src, Dst: dst, Proto: proto, DPort: dport})
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, result)
}

func (s *Server) handleDiag(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	svc := s.diagService()
	body, err := io.ReadAll(r.Body)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	var req diag.DiagRequest
	if err := json.Unmarshal(body, &req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	result, err := svc.Diagnose(r.Context(), req)
	if err != nil && result.Status == "" {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, result)
}

func (s *Server) handlePathValidate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	svc := s.diagService()
	body, err := io.ReadAll(r.Body)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	var req struct {
		pathtrace.Flow
		Runner string `json:"runner,omitempty"`
	}
	if err := json.Unmarshal(body, &req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if req.Src == "" || req.Dst == "" || req.Proto == "" {
		writeError(w, http.StatusBadRequest, "missing src, dst, or proto")
		return
	}
	result, err := svc.ValidatePath(r.Context(), req.Flow, req.Runner)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, result)
}

func (s *Server) diagService() *diag.Service {
	if s.diag != nil {
		return s.diag
	}
	return diag.NewService(s.devices, diag.NewFakeRunner())
}

type vlanPathResponse struct {
	VLAN     int             `json:"vlan"`
	Nodes    []vlanPathNode  `json:"nodes"`
	Edges    []vlanPathEdge  `json:"edges"`
	Rows     []briefResult   `json:"rows"`
	Summary  vlanPathSummary `json:"summary"`
	Warnings []string        `json:"warnings,omitempty"`
}

type vlanPathNode struct {
	Device     string   `json:"device"`
	Access     int      `json:"access"`
	Trunks     int      `json:"trunks"`
	Broad      int      `json:"broad"`
	Declared   bool     `json:"declared"`
	Interfaces []string `json:"interfaces"`
}

type vlanPathEdge struct {
	A          ir.LinkEndpoint `json:"a"`
	B          ir.LinkEndpoint `json:"b"`
	Sources    []string        `json:"sources"`
	Confidence float64         `json:"confidence"`
	Status     string          `json:"status"`
	Evidence   []ir.Evidence   `json:"evidence,omitempty"`
}

type vlanPathSummary struct {
	Devices       int `json:"devices"`
	Access        int `json:"access"`
	Trunks        int `json:"trunks"`
	Broad         int `json:"broad"`
	Declared      int `json:"declared"`
	PhysicalLinks int `json:"physical_links"`
}

func (s *Server) handleVLANPath(w http.ResponseWriter, r *http.Request) {
	raw := strings.TrimSpace(r.URL.Query().Get("vlan"))
	if raw == "" {
		writeError(w, http.StatusBadRequest, "missing vlan")
		return
	}
	vlan, err := strconv.Atoi(raw)
	if err != nil || vlan < 1 || vlan > 4094 {
		writeError(w, http.StatusBadRequest, "invalid vlan")
		return
	}
	includeBroad := r.URL.Query().Get("include_broad") != "0"
	writeJSON(w, s.vlanPath(vlan, includeBroad))
}

func (s *Server) vlanPath(vlan int, includeBroad bool) vlanPathResponse {
	nodesByDevice := map[string]*vlanPathNode{}
	interfaceRoles := map[string]string{}
	var rows []briefResult
	summary := vlanPathSummary{}

	for _, dev := range s.devices {
		node := &vlanPathNode{Device: dev.Hostname, Interfaces: []string{}}
		for _, intf := range dev.Interfaces {
			role := vlanInterfaceRole(intf, vlan)
			if role == "" || (role == "trunk_broad" && !includeBroad) {
				continue
			}
			interfaceRoles[endpointKey(dev.Hostname, intf.Name)] = role
			node.Interfaces = append(node.Interfaces, intf.Name)
			switch role {
			case "access":
				node.Access++
				summary.Access++
			case "trunk":
				node.Trunks++
				summary.Trunks++
			case "trunk_broad":
				node.Broad++
				summary.Broad++
			}
			rows = append(rows, briefResult{
				Type:     "interface",
				Device:   dev.Hostname,
				Role:     role,
				Summary:  vlanInterfaceSummary(intf, vlan, role),
				Evidence: intf.Evidence,
			})
		}
		for _, item := range dev.VLANs {
			if item.ID != vlan {
				continue
			}
			node.Declared = true
			summary.Declared++
			rows = append(rows, briefResult{
				Type:     "vlan",
				Device:   dev.Hostname,
				Role:     "declared",
				Summary:  "vlan " + strconv.Itoa(item.ID) + " declare " + item.Name,
				Evidence: item.Evidence,
			})
		}
		if node.Access > 0 || node.Trunks > 0 || node.Broad > 0 || node.Declared {
			sort.Strings(node.Interfaces)
			nodesByDevice[strings.ToLower(dev.Hostname)] = node
		}
	}

	edges := s.vlanPathEdges(interfaceRoles)
	summary.PhysicalLinks = len(edges)
	nodes := make([]vlanPathNode, 0, len(nodesByDevice))
	for _, node := range nodesByDevice {
		nodes = append(nodes, *node)
	}
	sort.Slice(nodes, func(i, j int) bool { return nodes[i].Device < nodes[j].Device })
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].Device != rows[j].Device {
			return rows[i].Device < rows[j].Device
		}
		if rows[i].Role != rows[j].Role {
			return rows[i].Role < rows[j].Role
		}
		return rows[i].Summary < rows[j].Summary
	})
	summary.Devices = len(nodes)

	var warnings []string
	if len(edges) == 0 {
		warnings = append(warnings, "aucun lien physique LLDP/CDP charge pour ce VLAN")
	}
	return vlanPathResponse{VLAN: vlan, Nodes: nodes, Edges: edges, Rows: rows, Summary: summary, Warnings: warnings}
}

func (s *Server) vlanPathEdges(interfaceRoles map[string]string) []vlanPathEdge {
	var edges []vlanPathEdge
	seen := map[string]bool{}
	for _, fact := range s.discoveryFacts {
		if fact.Type != "link" || fact.Link == nil || fact.Link.Status == ir.StatusConflict {
			continue
		}
		link := fact.Link
		if _, ok := interfaceRoles[endpointKey(link.A.Device, link.A.Interface)]; !ok {
			continue
		}
		if _, ok := interfaceRoles[endpointKey(link.B.Device, link.B.Interface)]; !ok {
			continue
		}
		key := linkEndpointKey(link.A) + "\x00" + linkEndpointKey(link.B)
		if linkEndpointKey(link.B) < linkEndpointKey(link.A) {
			key = linkEndpointKey(link.B) + "\x00" + linkEndpointKey(link.A)
		}
		if seen[key] {
			continue
		}
		seen[key] = true
		edges = append(edges, vlanPathEdge{
			A:          link.A,
			B:          link.B,
			Sources:    append([]string(nil), link.Sources...),
			Confidence: link.Confidence,
			Status:     link.Status,
			Evidence:   append([]ir.Evidence(nil), link.Evidence...),
		})
	}
	sort.Slice(edges, func(i, j int) bool {
		if edges[i].A.Device != edges[j].A.Device {
			return edges[i].A.Device < edges[j].A.Device
		}
		if edges[i].A.Interface != edges[j].A.Interface {
			return edges[i].A.Interface < edges[j].A.Interface
		}
		if edges[i].B.Device != edges[j].B.Device {
			return edges[i].B.Device < edges[j].B.Device
		}
		return edges[i].B.Interface < edges[j].B.Interface
	})
	return edges
}

func vlanInterfaceRole(intf ir.Interface, vlan int) string {
	if intf.Mode == "access" && intf.AccessVLAN == vlan {
		return "access"
	}
	if intf.Mode != "trunk" || !trunkAllowsVLAN(intf, vlan) {
		return ""
	}
	if trunkAllowanceIsBroad(intf, vlan) {
		return "trunk_broad"
	}
	return "trunk"
}

func vlanInterfaceSummary(intf ir.Interface, vlan int, role string) string {
	switch role {
	case "access":
		return intf.Name + " access vlan " + strconv.Itoa(vlan)
	case "trunk":
		return intf.Name + " trunk autorise explicitement vlan " + strconv.Itoa(vlan)
	default:
		return intf.Name + " trunk autorise vlan " + strconv.Itoa(vlan) + " via liste large/all"
	}
}

func trunkAllowsVLAN(intf ir.Interface, vlan int) bool {
	for _, item := range intf.TrunkVLANs {
		if item == vlan {
			return true
		}
	}
	raw := strings.ToLower(intf.Evidence.RawBlock)
	return strings.Contains(raw, "allowed vlan all") || strings.Contains(raw, "allowed all")
}

func trunkAllowanceIsBroad(intf ir.Interface, vlan int) bool {
	raw := strings.ToLower(intf.Evidence.RawBlock)
	if strings.Contains(raw, "allowed vlan all") || strings.Contains(raw, "allowed all") || len(intf.TrunkVLANs) >= 256 {
		return true
	}
	for _, field := range strings.FieldsFunc(raw, func(r rune) bool { return r == ',' || r == ' ' || r == '\t' }) {
		if !strings.Contains(field, "-") {
			continue
		}
		bounds := strings.SplitN(field, "-", 2)
		start, err1 := strconv.Atoi(strings.TrimSpace(bounds[0]))
		end, err2 := strconv.Atoi(strings.TrimSpace(bounds[1]))
		if err1 == nil && err2 == nil && start <= vlan && vlan <= end && end-start+1 >= 256 {
			return true
		}
	}
	return false
}

func endpointKey(device, intf string) string {
	return strings.ToLower(strings.TrimSpace(device)) + "\x00" + strings.ToLower(strings.TrimSpace(intf))
}

func linkEndpointKey(endpoint ir.LinkEndpoint) string {
	return endpointKey(endpoint.Device, endpoint.Interface)
}

func (s *Server) handleCheckSummary(w http.ResponseWriter, r *http.Request) {
	findings := compliance.Check(s.devices, s.policyFromRequest(r))
	writeJSON(w, compliance.Summarize(findings))
}

func (s *Server) handleCheck(w http.ResponseWriter, r *http.Request) {
	findings := compliance.Check(s.devices, s.policyFromRequest(r))
	limit := 100
	if raw := r.URL.Query().Get("limit"); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil || parsed < 0 {
			writeError(w, http.StatusBadRequest, "invalid limit")
			return
		}
		limit = parsed
	}
	if limit > 0 && len(findings) > limit {
		findings = findings[:limit]
	}
	writeJSON(w, findings)
}

func (s *Server) handleDiff(w http.ResponseWriter, r *http.Request) {
	beforePath := strings.TrimSpace(r.URL.Query().Get("before"))
	afterPath := strings.TrimSpace(r.URL.Query().Get("after"))
	if beforePath == "" || afterPath == "" {
		writeError(w, http.StatusBadRequest, "missing before or after")
		return
	}
	parser := cisco.New()
	before, err := parser.ParseFile(beforePath)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	after, err := parser.ParseFile(afterPath)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	changes := diff.Devices(before, after)
	if changes == nil {
		changes = []diff.Change{}
	}
	writeJSON(w, changes)
}

func (s *Server) handlePolicy(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, s.policy)
}

func (s *Server) handleVendors(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, s.vendors)
}

func (s *Server) policyFromRequest(r *http.Request) compliance.Policy {
	policy := s.policy
	if values := splitCSV(r.URL.Query().Get("ntp")); len(values) > 0 {
		policy.RequiredNTPServers = values
	}
	if values := splitCSV(r.URL.Query().Get("syslog")); len(values) > 0 {
		policy.RequiredSyslogHosts = values
	}
	if values := splitCSV(r.URL.Query().Get("forbid_snmp")); len(values) > 0 {
		policy.ForbiddenSNMPCommunities = values
	}
	return policy
}

func splitCSV(s string) []string {
	var out []string
	for _, item := range strings.Split(s, ",") {
		item = strings.TrimSpace(item)
		if item != "" {
			out = append(out, item)
		}
	}
	return out
}

type briefResult struct {
	Type     string      `json:"type"`
	Device   string      `json:"device"`
	Role     string      `json:"role,omitempty"`
	Summary  string      `json:"summary"`
	Evidence ir.Evidence `json:"evidence"`
}

func briefResults(results []query.Result) []briefResult {
	out := make([]briefResult, 0, len(results))
	for _, result := range results {
		out = append(out, briefResult{
			Type:     result.Type,
			Device:   result.Device,
			Role:     result.Role,
			Summary:  result.Summary,
			Evidence: result.Evidence,
		})
	}
	return out
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(v)
}

func writeError(w http.ResponseWriter, code int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": message})
}

package server

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"

	"network-compiler/internal/compliance"
	"network-compiler/internal/diff"
	"network-compiler/internal/ir"
	"network-compiler/internal/parser/cisco"
	"network-compiler/internal/query"
	"network-compiler/internal/report"
)

type Server struct {
	devices []ir.Device
	policy  compliance.Policy
}

func New(devices []ir.Device, policies ...compliance.Policy) *Server {
	var policy compliance.Policy
	if len(policies) > 0 {
		policy = policies[0]
	}
	return &Server{devices: devices, policy: policy}
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/", s.handleIndex)
	mux.HandleFunc("/api/summary", s.handleSummary)
	mux.HandleFunc("/api/devices", s.handleDevices)
	mux.HandleFunc("/api/device", s.handleDevice)
	mux.HandleFunc("/api/diff", s.handleDiff)
	mux.HandleFunc("/api/policy", s.handlePolicy)
	mux.HandleFunc("/api/query", s.handleQuery)
	mux.HandleFunc("/api/check", s.handleCheck)
	mux.HandleFunc("/api/check/summary", s.handleCheckSummary)
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
	Summary  string      `json:"summary"`
	Evidence ir.Evidence `json:"evidence"`
}

func briefResults(results []query.Result) []briefResult {
	out := make([]briefResult, 0, len(results))
	for _, result := range results {
		out = append(out, briefResult{
			Type:     result.Type,
			Device:   result.Device,
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

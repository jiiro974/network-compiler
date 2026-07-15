package server

import (
	"embed"
	"net/http"
	"strings"
)

//go:embed assets/path.html assets/fixtures/*.json assets/fixtures/diag/*.json
var pathAssets embed.FS

func (s *Server) handlePathPage(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/path" {
		http.NotFound(w, r)
		return
	}
	data, err := pathAssets.ReadFile("assets/path.html")
	if err != nil {
		http.Error(w, "path page not found", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write(data)
}

func (s *Server) handlePathFixture(w http.ResponseWriter, r *http.Request) {
	rel := strings.TrimPrefix(r.URL.Path, "/path/fixtures/")
	if rel == "" || strings.Contains(rel, "..") {
		http.NotFound(w, r)
		return
	}
	if !validPathFixture(rel) {
		http.NotFound(w, r)
		return
	}
	data, err := pathAssets.ReadFile("assets/fixtures/" + rel)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_, _ = w.Write(data)
}

func validPathFixture(rel string) bool {
	switch strings.TrimSpace(rel) {
	case "delivered.json", "no_route.json", "dropped_acl.json", "dropped_policy.json", "loop.json":
		return true
	case "diag/ping_ok.json",
		"diag/exec_needs_approval.json",
		"diag/config_denied.json",
		"diag/path_validate_match.json",
		"diag/path_validate_mismatch.json":
		return true
	default:
		return false
	}
}

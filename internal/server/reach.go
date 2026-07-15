package server

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"
)

type reachContextResponse struct {
	ClientIP  string `json:"client_ip"`
	UserAgent string `json:"user_agent"`
	ServerTS  string `json:"server_time"`
}

type reachTCPRequest struct {
	Host      string `json:"host"`
	Port      int    `json:"port"`
	TimeoutMS int    `json:"timeout_ms,omitempty"`
}

type reachTCPResponse struct {
	Status    string  `json:"status"`
	ConnectMS float64 `json:"connect_ms"`
	Error     string  `json:"error,omitempty"`
	From      string  `json:"from"`
}

func (s *Server) handleReachPage(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/reach" {
		http.NotFound(w, r)
		return
	}
	data, err := pathAssets.ReadFile("assets/reach.html")
	if err != nil {
		http.Error(w, "reach page not found", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write(data)
}

func (s *Server) handleReachContext(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, reachContextResponse{
		ClientIP:  clientIP(r),
		UserAgent: r.UserAgent(),
		ServerTS:  time.Now().UTC().Format(time.RFC3339),
	})
}

func (s *Server) handleReachTCP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	var req reachTCPRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	host := strings.TrimSpace(req.Host)
	if host == "" || req.Port <= 0 || req.Port > 65535 {
		writeError(w, http.StatusBadRequest, "invalid host or port")
		return
	}
	timeout := 5 * time.Second
	if req.TimeoutMS > 0 {
		timeout = time.Duration(req.TimeoutMS) * time.Millisecond
		if timeout > 30*time.Second {
			timeout = 30 * time.Second
		}
	}

	start := time.Now()
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(host, fmt.Sprintf("%d", req.Port)), timeout)
	elapsed := time.Since(start).Seconds() * 1000
	out := reachTCPResponse{From: "netc-server", ConnectMS: elapsed}
	if err != nil {
		if ne, ok := err.(net.Error); ok && ne.Timeout() {
			out.Status = "timeout"
		} else {
			out.Status = "unreachable"
		}
		out.Error = err.Error()
		writeJSON(w, out)
		return
	}
	_ = conn.Close()
	out.Status = "reachable"
	writeJSON(w, out)
}

func clientIP(r *http.Request) string {
	if xff := strings.TrimSpace(r.Header.Get("X-Forwarded-For")); xff != "" {
		parts := strings.Split(xff, ",")
		return strings.TrimSpace(parts[0])
	}
	if xri := strings.TrimSpace(r.Header.Get("X-Real-IP")); xri != "" {
		return xri
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

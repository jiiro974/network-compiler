package server

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestReachPageServed(t *testing.T) {
	ts := httptest.NewServer(New(nil).Handler())
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/reach")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	body := readBody(t, resp)
	if !strings.Contains(body, "Reach test") || !strings.Contains(body, "/api/path/validate") {
		t.Fatalf("unexpected reach page body")
	}
}

func TestReachContextAPI(t *testing.T) {
	ts := httptest.NewServer(New(nil).Handler())
	defer ts.Close()

	req, _ := http.NewRequest(http.MethodGet, ts.URL+"/api/reach/context", nil)
	req.Header.Set("X-Forwarded-For", "203.0.113.10, 10.0.0.1")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var out reachContextResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	if out.ClientIP != "203.0.113.10" {
		t.Fatalf("client_ip = %q", out.ClientIP)
	}
	if out.ServerTS == "" {
		t.Fatal("missing server_time")
	}
}

func TestReachTCPProbeInvalid(t *testing.T) {
	ts := httptest.NewServer(New(nil).Handler())
	defer ts.Close()

	resp, err := http.Post(ts.URL+"/api/reach/tcp", "application/json", strings.NewReader(`{"host":"","port":0}`))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d", resp.StatusCode)
	}
}

func TestReachTCPProbeUnreachable(t *testing.T) {
	ts := httptest.NewServer(New(nil).Handler())
	defer ts.Close()

	body := `{"host":"127.0.0.1","port":1,"timeout_ms":200}`
	resp, err := http.Post(ts.URL+"/api/reach/tcp", "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	var out reachTCPResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	if out.Status != "unreachable" && out.Status != "timeout" {
		t.Fatalf("status = %q", out.Status)
	}
	if out.From != "netc-server" {
		t.Fatalf("from = %q", out.From)
	}
}

func readBody(t *testing.T, resp *http.Response) string {
	t.Helper()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

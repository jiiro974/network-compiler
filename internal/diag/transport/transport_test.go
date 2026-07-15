package transport

import (
	"testing"
	"time"

	"network-compiler/internal/diag"
)

func TestLocalShellPing(t *testing.T) {
	got := localShell("ping", "ping 10.0.0.1 repeat 3")
	if got != "ping -c 3 10.0.0.1" {
		t.Fatalf("got %q", got)
	}
}

func TestIsLocalTarget(t *testing.T) {
	if !isLocalTarget(diag.Target{Host: "ip:1.2.3.4"}) {
		t.Fatal("expected local")
	}
	if isLocalTarget(diag.Target{Host: "edge-sw1"}) {
		t.Fatal("expected remote")
	}
}

func TestNewSSHRunnerDefaults(t *testing.T) {
	r := NewSSHRunner(SSHConfig{})
	if r.Config.ConnectTimeout != 10*time.Second {
		t.Fatalf("timeout = %v", r.Config.ConnectTimeout)
	}
}

func TestNewExecRunner(t *testing.T) {
	r := NewExecRunner()
	if r.SSHBinary != "ssh" {
		t.Fatalf("binary = %q", r.SSHBinary)
	}
}

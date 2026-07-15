package secretredact

import "testing"

func TestRedact(t *testing.T) {
	if got := Redact("enable secret verysecret"); got != "[REDACTED]" {
		t.Fatalf("got %q", got)
	}
	if got := Redact("description uplink"); got != "description uplink" {
		t.Fatalf("got %q", got)
	}
}

package secretredact

import "testing"

func TestRedact(t *testing.T) {
	tests := []struct {
		in   string
		want string
	}{
		{in: "enable secret verysecret", want: "enable secret [REDACTED]"},
		{in: "enable secret 5 $1$abc", want: "enable secret 5 [REDACTED]"},
		{in: "username admin password 7 0822455D0A16", want: "username admin password 7 [REDACTED]"},
		{in: "username admin secret 5 $1$abc", want: "username admin secret 5 [REDACTED]"},
		{in: "snmp-server community public RO", want: "snmp-server community [REDACTED] RO"},
		{in: "set snmp community public authorization read-only", want: "set snmp community [REDACTED] authorization read-only"},
		{in: "set system login user admin authentication encrypted-password \"$6$abc\"", want: "set system login user admin authentication encrypted-password [REDACTED]"},
		{in: "description uplink", want: "description uplink"},
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			if got := Redact(tt.in); got != tt.want {
				t.Fatalf("got %q, want %q", got, tt.want)
			}
		})
	}
}

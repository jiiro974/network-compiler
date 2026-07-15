package secretredact

import "testing"

func TestRedact(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		// Existing B cases (positional / token-based expectations preserved).
		{name: "enable secret plain", in: "enable secret verysecret", want: "enable secret [REDACTED]"},
		{name: "enable secret type5", in: "enable secret 5 $1$abc", want: "enable secret 5 [REDACTED]"},
		{name: "username password type7", in: "username admin password 7 0822455D0A16", want: "username admin password 7 [REDACTED]"},
		{name: "username secret type5", in: "username admin secret 5 $1$abc", want: "username admin secret 5 [REDACTED]"},
		{name: "snmp community", in: "snmp-server community public RO", want: "snmp-server community [REDACTED] RO"},
		{name: "snmp host version 2c", in: "snmp-server host 172.16.24.10 version 2c chm_public", want: "snmp-server host 172.16.24.10 version 2c [REDACTED]"},
		{name: "snmp host informs version 2c", in: "snmp-server host 172.16.24.11 informs version 2c other_public", want: "snmp-server host 172.16.24.11 informs version 2c [REDACTED]"},
		{name: "juniper snmp community", in: "set snmp community public authorization read-only", want: "set snmp community [REDACTED] authorization read-only"},
		{name: "juniper encrypted password", in: "set system login user admin authentication encrypted-password \"$6$abc\"", want: "set system login user admin authentication encrypted-password [REDACTED]"},
		{name: "description unchanged", in: "description uplink", want: "description uplink"},

		// Cases from repo A regex redactor.
		{name: "enable secret hashed", in: "enable secret 5 $1$abcd$hashedsecretvalue", want: "enable secret 5 [REDACTED]"},
		{name: "username password plain", in: "username admin password SuperSecret123", want: "username admin password [REDACTED]"},
		{name: "non secret interface", in: "interface GigabitEthernet1/0/24", want: "interface GigabitEthernet1/0/24"},

		// Additional coverage / edge cases.
		{name: "empty line", in: "", want: ""},
		{name: "indented enable secret", in: "  enable secret 5 $1$abc", want: "  enable secret 5 [REDACTED]"},
		{name: "snmp host community fallback", in: "snmp-server host 10.0.0.1 private", want: "snmp-server host 10.0.0.1 [REDACTED]"},
		{name: "juniper plain text password", in: "set system login user ops authentication plain-text-password cleartext", want: "set system login user ops authentication plain-text-password [REDACTED]"},
		{name: "generic password", in: "crypto isakmp key mypreshared address 0.0.0.0", want: "crypto isakmp key [REDACTED]"},
		{name: "generic secret", in: "some-context secret value123 trailing", want: "some-context secret [REDACTED]"},
		{name: "generic token", in: "api token abcdef extra", want: "api token [REDACTED]"},
		{name: "description with password word", in: "description password policy for guests", want: "description password policy for guests"},
		{name: "password in description context skipped", in: "\tdescription reset password info", want: "\tdescription reset password info"},
		{name: "description keyword only", in: "description", want: "description"},
		{name: "whitespace only", in: "   \t  ", want: "   \t  "},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := Redact(tt.in); got != tt.want {
				t.Fatalf("Redact(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

func TestIsDescriptionLine(t *testing.T) {
	if !isDescriptionLine("description uplink") {
		t.Fatal("expected description line")
	}
	if !isDescriptionLine("  description") {
		t.Fatal("expected indented description line")
	}
	if isDescriptionLine("") {
		t.Fatal("empty line is not a description")
	}
	if isDescriptionLine("interface Gi1/0/1") {
		t.Fatal("interface line is not a description")
	}
	if isDescriptionLine("   \t  ") {
		t.Fatal("whitespace-only is not a description")
	}
}

func TestRedactDoesNotMutateSecretsInNonSecretLines(t *testing.T) {
	in := "interface GigabitEthernet1/0/24"
	if got := Redact(in); got != in {
		t.Fatalf("non-secret line changed: got %q", got)
	}
}

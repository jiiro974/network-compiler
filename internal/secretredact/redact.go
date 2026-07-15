package secretredact

import "strings"

var sensitiveMarkers = []string{
	"password",
	"secret",
	"key",
	"community",
	"token",
	"authorization",
	"enable secret",
	"snmp-server community",
}

func Redact(s string) string {
	lower := strings.ToLower(s)
	for _, marker := range sensitiveMarkers {
		if strings.Contains(lower, marker) {
			return "[REDACTED]"
		}
	}
	return s
}

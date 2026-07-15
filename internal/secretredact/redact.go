package secretredact

import (
	"regexp"
	"strings"
)

const marker = "[REDACTED]"

type ruleKind int

const (
	truncateAfterValue ruleKind = iota
	replaceValueKeepTail
)

type rule struct {
	re   *regexp.Regexp
	kind ruleKind
}

// rules are applied in order; first match wins.
var rules = []rule{
	// enable secret [5] <hash|plain>
	{regexp.MustCompile(`(?i)^(\s*enable\s+secret(?:\s+\d+)?)\s+\S+`), truncateAfterValue},
	// username <u> password [7] <v>
	{regexp.MustCompile(`(?i)^(\s*username\s+\S+\s+password(?:\s+\d+)?)\s+\S+`), truncateAfterValue},
	// username <u> secret [5] <v>
	{regexp.MustCompile(`(?i)^(\s*username\s+\S+\s+secret(?:\s+\d+)?)\s+\S+`), truncateAfterValue},
	// snmp-server community <v> ...
	{regexp.MustCompile(`(?i)^(\s*snmp-server\s+community)\s+\S+(\s.*)?$`), replaceValueKeepTail},
	// snmp-server host ... version 2c <community>
	{regexp.MustCompile(`(?i)^(\s*snmp-server\s+host\s+\S+(?:\s+\S+)*?\s+version\s+2c)\s+\S+`), truncateAfterValue},
	// set snmp community <v> ...
	{regexp.MustCompile(`(?i)^(\s*set\s+snmp\s+community)\s+\S+(\s.*)?$`), replaceValueKeepTail},
	// Juniper login user encrypted/plain password
	{regexp.MustCompile(`(?i)^(\s*set\s+system\s+login\s+user\b.*?(?:encrypted-password|plain-text-password))\s+(?:"[^"]*"|\S+)`), truncateAfterValue},
}

var (
	snmpHostCommunity = regexp.MustCompile(`(?i)^(\s*snmp-server\s+host\s+\S+)\s+\S+(\s.*)?$`)
	genericSecret     = regexp.MustCompile(`(?i)^(.*?\b(?:password|secret|token|key)\b(?:\s+\d+)?)\s+\S+`)
)

// Redact masks secrets in a single configuration or command output line.
func Redact(line string) string {
	if line == "" || isDescriptionLine(line) {
		return line
	}
	for _, r := range rules {
		switch r.kind {
		case truncateAfterValue:
			if out, ok := applyTruncate(r.re, line); ok {
				return out
			}
		case replaceValueKeepTail:
			if out, ok := applyKeepTail(r.re, line); ok {
				return out
			}
		}
	}
	if !strings.Contains(strings.ToLower(line), "version") {
		if out, ok := applyKeepTail(snmpHostCommunity, line); ok {
			return out
		}
	}
	if out, ok := applyTruncate(genericSecret, line); ok {
		return out
	}
	return line
}

func isDescriptionLine(line string) bool {
	trimmed := strings.TrimLeft(line, " \t")
	if trimmed == "" {
		return false
	}
	fields := strings.Fields(trimmed)
	return strings.EqualFold(fields[0], "description")
}

func applyTruncate(re *regexp.Regexp, line string) (string, bool) {
	loc := re.FindStringSubmatchIndex(line)
	if loc == nil {
		return line, false
	}
	prefix := strings.TrimRight(line[loc[2]:loc[3]], " \t")
	return prefix + " " + marker, true
}

func applyKeepTail(re *regexp.Regexp, line string) (string, bool) {
	sub := re.FindStringSubmatch(line)
	if sub == nil {
		return line, false
	}
	prefix := sub[1]
	tail := ""
	if len(sub) >= 3 {
		tail = sub[2]
	}
	return prefix + " " + marker + tail, true
}

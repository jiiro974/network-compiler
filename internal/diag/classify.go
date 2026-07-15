package diag

import (
	"strings"
)

var configDenyPatterns = []string{
	"configure terminal",
	"configure ",
	"conf t",
	"conf ter",
	"set ",
	"edit ",
	"commit",
	"delete ",
	"write ",
	"write-memory",
	"copy run",
	"copy running",
	"erase ",
	"reload",
	"request system",
	"no ",
}

func classifyCommand(command, raw string) string {
	cmd := strings.TrimSpace(strings.ToLower(raw))
	if cmd == "" {
		cmd = strings.TrimSpace(strings.ToLower(command))
	}
	if isConfigCommand(cmd) {
		return ClassConfig
	}
	switch strings.ToLower(command) {
	case "ping", "traceroute", "show":
		return ClassDiagnostic
	case "exec":
		return ClassExec
	default:
		if isDiagnosticRaw(cmd) {
			return ClassDiagnostic
		}
		return ClassExec
	}
}

func isConfigCommand(cmd string) bool {
	if cmd == "" {
		return false
	}
	for _, pattern := range configDenyPatterns {
		if strings.HasPrefix(cmd, pattern) {
			return true
		}
	}
	if cmd == "configure" || cmd == "commit" || cmd == "reload" {
		return true
	}
	return false
}

func isDiagnosticRaw(cmd string) bool {
	if cmd == "" {
		return false
	}
	for _, prefix := range []string{"show ", "display ", "get ", "ping ", "traceroute ", "traceroute6 "} {
		if strings.HasPrefix(cmd, prefix) {
			return true
		}
	}
	return false
}

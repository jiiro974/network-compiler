package diag

import (
	"strings"

	"network-compiler/internal/secretredact"
)

func redactOutput(output string) string {
	if output == "" {
		return ""
	}
	lines := strings.Split(output, "\n")
	for i, line := range lines {
		lines[i] = secretredact.Redact(line)
	}
	return strings.Join(lines, "\n")
}

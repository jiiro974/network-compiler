package secretredact

import (
	"strings"

	"network-compiler/internal/syntax"
)

const marker = "[REDACTED]"

func Redact(line string) string {
	tokens := syntax.Tokens(line)
	if len(tokens) == 0 {
		return line
	}
	lower := lowerTokens(tokens)

	switch {
	case hasPrefix(lower, "enable", "secret"):
		return redactFromToken(line, tokens, secretValueIndex(tokens, 2))
	case hasPrefix(lower, "username"):
		for i := 2; i < len(lower); i++ {
			if lower[i] == "password" || lower[i] == "secret" {
				return redactFromToken(line, tokens, secretValueIndex(tokens, i+1))
			}
		}
	case hasPrefix(lower, "snmp-server", "community"):
		return redactToken(line, tokens, 2)
	case hasPrefix(lower, "set", "snmp", "community"):
		return redactToken(line, tokens, 3)
	case hasPrefix(lower, "set", "system", "login", "user"):
		for i := 0; i < len(lower); i++ {
			if lower[i] == "encrypted-password" || lower[i] == "plain-text-password" {
				return redactFromToken(line, tokens, i+1)
			}
		}
	default:
		for i := 0; i < len(lower); i++ {
			if lower[i] == "password" || lower[i] == "secret" || lower[i] == "token" || lower[i] == "key" {
				return redactFromToken(line, tokens, i+1)
			}
		}
	}
	return line
}

func secretValueIndex(tokens []syntax.Token, start int) int {
	if start < len(tokens) && isSecretType(tokens[start].Text) {
		return start + 1
	}
	return start
}

func isSecretType(s string) bool {
	if s == "" {
		return false
	}
	for _, ch := range s {
		if ch < '0' || ch > '9' {
			return false
		}
	}
	return true
}

func redactToken(line string, tokens []syntax.Token, index int) string {
	if index >= len(tokens) {
		return line
	}
	return line[:tokens[index].Start] + marker + line[tokens[index].End:]
}

func redactFromToken(line string, tokens []syntax.Token, index int) string {
	if index >= len(tokens) {
		return line
	}
	return strings.TrimRight(line[:tokens[index].Start], " \t") + " " + marker
}

func lowerTokens(tokens []syntax.Token) []string {
	out := make([]string, 0, len(tokens))
	for _, token := range tokens {
		out = append(out, strings.ToLower(token.Text))
	}
	return out
}

func hasPrefix(tokens []string, want ...string) bool {
	if len(tokens) < len(want) {
		return false
	}
	for i := range want {
		if tokens[i] != want[i] {
			return false
		}
	}
	return true
}

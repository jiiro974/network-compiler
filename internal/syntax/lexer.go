package syntax

import "strings"

type Token struct {
	Text  string
	Start int
	End   int
}

func Tokens(line string) []Token {
	var out []Token
	for i := 0; i < len(line); {
		for i < len(line) && isSpace(line[i]) {
			i++
		}
		if i >= len(line) {
			break
		}
		start := i
		switch line[i] {
		case '"', '\'':
			quote := line[i]
			i++
			for i < len(line) {
				if line[i] == '\\' && i+1 < len(line) {
					i += 2
					continue
				}
				if line[i] == quote {
					i++
					break
				}
				i++
			}
		case '[', ']':
			i++
		default:
			for i < len(line) && !isSpace(line[i]) && line[i] != '[' && line[i] != ']' {
				i++
			}
		}
		out = append(out, Token{Text: strings.Trim(line[start:i], `"'`), Start: start, End: i})
	}
	return out
}

func Fields(line string) []string {
	tokens := Tokens(line)
	out := make([]string, 0, len(tokens))
	for _, token := range tokens {
		out = append(out, token.Text)
	}
	return out
}

func isSpace(b byte) bool {
	return b == ' ' || b == '\t' || b == '\n' || b == '\r'
}

package evidence

import "fmt"

// Span points back to exact source lines used to build an IR fact.
type Span struct {
	File      string
	StartLine int
	EndLine   int
	Text      string
}

func NewSpan(file string, line int, text string) Span {
	return Span{
		File:      file,
		StartLine: line,
		EndLine:   line,
		Text:      text,
	}
}

func (s Span) Ref() string {
	if s.StartLine == s.EndLine {
		return fmt.Sprintf("%s:%d", s.File, s.StartLine)
	}
	return fmt.Sprintf("%s:%d-%d", s.File, s.StartLine, s.EndLine)
}

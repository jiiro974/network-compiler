package ingest

import (
	"os"
	"strings"
)

type Source struct {
	Path  string
	Bytes []byte
	Lines []string
}

func ReadFile(path string) (Source, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return Source{}, err
	}
	text := strings.ReplaceAll(string(b), "\r\n", "\n")
	text = strings.ReplaceAll(text, "\r", "\n")
	return Source{
		Path:  path,
		Bytes: b,
		Lines: strings.Split(text, "\n"),
	}, nil
}

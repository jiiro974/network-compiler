package collect

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type collectAuditEntry struct {
	Timestamp    time.Time `json:"timestamp"`
	Device       string    `json:"device"`
	ManagementIP string    `json:"management_ip"`
	Command      string    `json:"command"`
	Filename     string    `json:"filename"`
	ExitCode     int       `json:"exit_code"`
	Status       string    `json:"status"`
	Error        string    `json:"error,omitempty"`
	Simulate     bool      `json:"simulate"`
}

type auditWriter struct {
	file *os.File
	enc  *json.Encoder
}

func openAudit(path string) (*auditWriter, error) {
	if strings.TrimSpace(path) == "" {
		return &auditWriter{}, nil
	}
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil && filepath.Dir(path) != "." {
		return nil, err
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		return nil, err
	}
	return &auditWriter{file: f, enc: json.NewEncoder(f)}, nil
}

func (a *auditWriter) append(entry collectAuditEntry) {
	if a == nil || a.file == nil {
		return
	}
	if entry.Timestamp.IsZero() {
		entry.Timestamp = time.Now().UTC()
	}
	_ = a.enc.Encode(entry)
}

func (a *auditWriter) Close() error {
	if a == nil || a.file == nil {
		return nil
	}
	return a.file.Close()
}

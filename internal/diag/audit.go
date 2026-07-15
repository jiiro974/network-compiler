package diag

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"sync/atomic"
	"time"
)

type AuditEntry struct {
	ID        string    `json:"id"`
	Timestamp time.Time `json:"timestamp"`
	Target    string    `json:"target"`
	Vendor    string    `json:"vendor"`
	Command   string    `json:"command"`
	Class     string    `json:"class"`
	Rendered  string    `json:"rendered_command"`
	Runner    string    `json:"runner"`
	Status    string    `json:"status"`
	Approval  *Approval `json:"approval,omitempty"`
	ExitCode  int       `json:"exit_code"`
	Actor     string    `json:"actor,omitempty"`
}

type AuditLog struct {
	seq     uint64
	entries []AuditEntry
}

func (a *AuditLog) Append(entry AuditEntry) string {
	if entry.ID == "" {
		entry.ID = newAuditID(&a.seq)
	}
	if entry.Timestamp.IsZero() {
		entry.Timestamp = time.Now().UTC()
	}
	a.entries = append(a.entries, entry)
	return entry.ID
}

func (a *AuditLog) Entries() []AuditEntry {
	out := make([]AuditEntry, len(a.entries))
	copy(out, a.entries)
	return out
}

func newAuditID(seq *uint64) string {
	n := atomic.AddUint64(seq, 1)
	var rnd [4]byte
	_, _ = rand.Read(rnd[:])
	return fmt.Sprintf("01J%012X%s", n, hex.EncodeToString(rnd[:]))
}

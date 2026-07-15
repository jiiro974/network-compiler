package diag

import (
	"fmt"
	"strings"
)

type ApprovalRecord struct {
	Token    string
	Target   string
	Command  string
	ID       string
	Approver string
	Ticket   string
}

type ApprovalProvider interface {
	Check(token string, cmd string, target Target) (Approval, error)
}

type StaticApprovals struct {
	records map[string]ApprovalRecord
}

func NewStaticApprovals(records ...ApprovalRecord) *StaticApprovals {
	m := make(map[string]ApprovalRecord, len(records))
	for _, rec := range records {
		m[strings.TrimSpace(rec.Token)] = rec
	}
	return &StaticApprovals{records: m}
}

func (s *StaticApprovals) Check(token string, cmd string, target Target) (Approval, error) {
	token = strings.TrimSpace(token)
	if token == "" {
		return Approval{
			Required: true,
			Granted:  false,
			Reason:   "commande hors allowlist diagnostique — approbation requise",
		}, nil
	}
	rec, ok := s.records[token]
	if !ok {
		return Approval{
			Required: true,
			Granted:  false,
			Reason:   fmt.Sprintf("jeton d'approbation invalide: %s", token),
		}, nil
	}
	if rec.Target != "" && !strings.EqualFold(rec.Target, target.Host) {
		return Approval{
			Required: true,
			Granted:  false,
			Reason:   fmt.Sprintf("jeton non valide pour la cible %s", target.Host),
		}, nil
	}
	return Approval{
		Required: true,
		Granted:  true,
		ID:       rec.ID,
		Approver: rec.Approver,
		Ticket:   rec.Ticket,
	}, nil
}

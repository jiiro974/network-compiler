package diag

import (
	"time"

	pathtrace "network-compiler/internal/path"
)

const (
	ClassDiagnostic = "diagnostic"
	ClassExec       = "exec"
	ClassConfig     = "config"

	StatusOK             = "ok"
	StatusUnreachable    = "unreachable"
	StatusTimeout        = "timeout"
	StatusDenied         = "denied"
	StatusNeedsApproval  = "needs_approval"
	StatusError          = "error"
	ObservedReachable    = "reachable"
	ObservedUnreachable  = "unreachable"
	ObservedInconclusive = "inconclusive"
	VerdictReachable     = "reachable"
	VerdictUnreachable   = "unreachable"
	VerdictPartial       = "partial"
	VerdictInconclusive  = "inconclusive"
	AgreementMatch       = "match"
	AgreementMismatch    = "mismatch"

	DefaultTimeout = 10 * time.Second
)

type CredRef struct {
	Username string `json:"username,omitempty"`
	Secret   string `json:"secret,omitempty"`
	KeyFile  string `json:"key_file,omitempty"`
}

type Target struct {
	Host    string
	Address string
	Vendor  string
	Creds   CredRef
}

type RenderedCommand struct {
	Shell string
	Kind  string
}

type RawResult struct {
	Output   string
	ExitCode int
	Err      error
}

type DiagArgs struct {
	Dst    string `json:"dst,omitempty"`
	Count  int    `json:"count,omitempty"`
	Source string `json:"source,omitempty"`
	VRF    string `json:"vrf,omitempty"`
	Raw    string `json:"raw,omitempty"`
}

type DiagRequest struct {
	Target        string   `json:"target"`
	Command       string   `json:"command"`
	Args          DiagArgs `json:"args"`
	Runner        string   `json:"runner,omitempty"`
	ApprovalToken string   `json:"approval_token,omitempty"`
}

type Approval struct {
	Required bool   `json:"required"`
	Granted  bool   `json:"granted"`
	ID       string `json:"id"`
	Approver string `json:"approver"`
	Ticket   string `json:"ticket"`
	Reason   string `json:"reason"`
}

type ParsedPing struct {
	Sent     int     `json:"sent"`
	Received int     `json:"received"`
	LossPct  float64 `json:"loss_pct"`
	RTTMinMs float64 `json:"rtt_min_ms,omitempty"`
	RTTAvgMs float64 `json:"rtt_avg_ms,omitempty"`
	RTTMaxMs float64 `json:"rtt_max_ms,omitempty"`
}

type ParsedHop struct {
	TTL   int     `json:"ttl"`
	Host  string  `json:"host"`
	RTTMs float64 `json:"rtt_ms,omitempty"`
}

type ParsedTraceroute struct {
	Hops []ParsedHop `json:"hops"`
}

type Parsed struct {
	Ping       *ParsedPing       `json:"ping,omitempty"`
	Traceroute *ParsedTraceroute `json:"traceroute,omitempty"`
}

type DiagResult struct {
	Target          string    `json:"target"`
	Vendor          string    `json:"vendor"`
	Command         string    `json:"command"`
	Class           string    `json:"class"`
	RenderedCommand string    `json:"rendered_command"`
	Runner          string    `json:"runner"`
	Status          string    `json:"status"`
	Approval        *Approval `json:"approval"`
	StartedAt       time.Time `json:"started_at"`
	DurationMs      int64     `json:"duration_ms"`
	ExitCode        int       `json:"exit_code"`
	RawOutput       string    `json:"raw_output"`
	Parsed          *Parsed   `json:"parsed,omitempty"`
	AuditID         string    `json:"audit_id"`
}

type CheckResult struct {
	LossPct  float64 `json:"loss_pct"`
	RTTAvgMs float64 `json:"rtt_avg_ms"`
	AuditID  string  `json:"audit_id"`
}

type ValidationCheck struct {
	FromDevice string      `json:"from_device"`
	Type       string      `json:"type"`
	Target     string      `json:"target"`
	Observed   string      `json:"observed"`
	Result     CheckResult `json:"result"`
}

type PathValidation struct {
	Flow             pathtrace.Flow    `json:"flow"`
	PredictedVerdict pathtrace.Verdict `json:"predicted_verdict"`
	Checks           []ValidationCheck `json:"checks"`
	ObservedVerdict  string            `json:"observed_verdict"`
	Agreement        string            `json:"agreement"`
}

type ValidateRequest struct {
	Flow   pathtrace.Flow `json:"flow"`
	Runner string         `json:"runner,omitempty"`
}

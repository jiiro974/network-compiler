package diag

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"network-compiler/internal/ir"
	pathtrace "network-compiler/internal/path"
)

type Service struct {
	Devices        []ir.Device
	Runner         Runner
	Approvals      ApprovalProvider
	Audit          AuditLog
	Timeout        time.Duration
	DefaultRunner  string
	ConfigWriteCap bool
	Actor          string
	ManagementIPs  map[string]string
	DefaultCreds   CredRef
}

func NewService(devices []ir.Device, runner Runner, opts ...Option) *Service {
	s := &Service{
		Devices:       devices,
		Runner:        runner,
		Approvals:     NewStaticApprovals(),
		Timeout:       DefaultTimeout,
		DefaultRunner: "ssh",
	}
	for _, opt := range opts {
		opt(s)
	}
	return s
}

type Option func(*Service)

func WithApprovals(p ApprovalProvider) Option {
	return func(s *Service) { s.Approvals = p }
}

func WithTimeout(d time.Duration) Option {
	return func(s *Service) { s.Timeout = d }
}

func WithDefaultRunner(name string) Option {
	return func(s *Service) { s.DefaultRunner = name }
}

func WithConfigWriteCap(enabled bool) Option {
	return func(s *Service) { s.ConfigWriteCap = enabled }
}

func WithActor(actor string) Option {
	return func(s *Service) { s.Actor = actor }
}

func WithManagementIPs(m map[string]string) Option {
	return func(s *Service) {
		if len(m) == 0 {
			return
		}
		s.ManagementIPs = make(map[string]string, len(m))
		for host, ip := range m {
			host = strings.TrimSpace(host)
			ip = strings.TrimSpace(ip)
			if host == "" || ip == "" {
				continue
			}
			s.ManagementIPs[strings.ToLower(host)] = ip
		}
	}
}

func WithDefaultCreds(creds CredRef) Option {
	return func(s *Service) { s.DefaultCreds = creds }
}

func (s *Service) Diagnose(ctx context.Context, req DiagRequest) (DiagResult, error) {
	started := time.Now().UTC()
	runnerName := req.Runner
	if runnerName == "" {
		runnerName = s.DefaultRunner
	}

	target, err := s.resolveTarget(req.Target)
	if err != nil {
		return DiagResult{}, err
	}

	rendered, err := renderCommand(target.Vendor, req.Command, req.Args)
	if err != nil {
		return DiagResult{}, err
	}

	class := classifyCommand(req.Command, rendered)
	result := DiagResult{
		Target:          target.Host,
		Vendor:          target.Vendor,
		Command:         req.Command,
		Class:           class,
		RenderedCommand: rendered,
		Runner:          runnerName,
		StartedAt:       started,
		ExitCode:        -1,
	}

	switch class {
	case ClassConfig:
		if !s.ConfigWriteCap {
			approval := &Approval{
				Required: true,
				Granted:  false,
				Reason:   "classe config refusée : capacité config-write absente (charte read-only)",
			}
			result.Status = StatusDenied
			result.Approval = approval
			result.AuditID = s.audit(result, approval, -1)
			return result, nil
		}
	case ClassExec:
		approval, err := s.Approvals.Check(req.ApprovalToken, rendered, target)
		if err != nil {
			return result, err
		}
		if !approval.Granted {
			result.Status = StatusNeedsApproval
			result.Approval = &approval
			result.AuditID = s.audit(result, &approval, -1)
			return result, nil
		}
		result.Approval = &approval
	}

	if s.Runner == nil {
		result.Status = StatusError
		result.AuditID = s.audit(result, result.Approval, -1)
		return result, fmt.Errorf("no runner configured")
	}

	runCtx, cancel := context.WithTimeout(ctx, s.Timeout)
	defer cancel()

	raw, runErr := s.Runner.Run(runCtx, target, RenderedCommand{Shell: rendered, Kind: req.Command})
	result.DurationMs = time.Since(started).Milliseconds()
	result.RawOutput = redactOutput(raw.Output)
	result.ExitCode = raw.ExitCode
	if result.ExitCode == 0 && raw.ExitCode != 0 {
		result.ExitCode = raw.ExitCode
	}
	if result.ExitCode == 0 && runErr == nil {
		result.ExitCode = 0
	} else if result.ExitCode == 0 {
		result.ExitCode = -1
	}

	result.Status = statusFromRun(runCtx, runErr, raw, req.Command)
	if parsed := parseOutput(req.Command, raw.Output); parsed != nil {
		result.Parsed = parsed
	}
	result.AuditID = s.audit(result, result.Approval, result.ExitCode)
	return result, runErr
}

func (s *Service) audit(result DiagResult, approval *Approval, exitCode int) string {
	return s.Audit.Append(AuditEntry{
		Target:   result.Target,
		Vendor:   result.Vendor,
		Command:  result.Command,
		Class:    result.Class,
		Rendered: result.RenderedCommand,
		Runner:   result.Runner,
		Status:   result.Status,
		Approval: approval,
		ExitCode: exitCode,
		Actor:    s.Actor,
	})
}

func statusFromRun(ctx context.Context, err error, raw RawResult, command string) string {
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return StatusTimeout
	}
	if err != nil {
		msg := strings.ToLower(err.Error())
		if strings.Contains(msg, "timeout") || strings.Contains(msg, "deadline") {
			return StatusTimeout
		}
		if strings.Contains(msg, "unreachable") || strings.Contains(msg, "no route") {
			return StatusUnreachable
		}
		return StatusError
	}
	if raw.ExitCode != 0 && command == "ping" {
		return StatusUnreachable
	}
	if raw.ExitCode != 0 {
		return StatusError
	}
	return StatusOK
}

func (s *Service) resolveTarget(name string) (Target, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return Target{}, fmt.Errorf("missing target")
	}
	if strings.HasPrefix(strings.ToLower(name), "ip:") {
		addr := strings.TrimPrefix(name, "ip:")
		addr = strings.TrimPrefix(addr, "IP:")
		return Target{Host: name, Address: strings.TrimSpace(addr), Vendor: "generic"}, nil
	}
	for _, dev := range s.Devices {
		if strings.EqualFold(dev.Hostname, name) {
			addr := deviceAddress(dev)
			if mgmt := s.managementIP(dev.Hostname); mgmt != "" {
				addr = mgmt
			}
			return Target{
				Host:    dev.Hostname,
				Address: addr,
				Vendor:  dev.Vendor,
				Creds:   s.DefaultCreds,
			}, nil
		}
	}
	return Target{}, fmt.Errorf("target not found: %s", name)
}

func (s *Service) managementIP(hostname string) string {
	if len(s.ManagementIPs) == 0 {
		return ""
	}
	return s.ManagementIPs[strings.ToLower(strings.TrimSpace(hostname))]
}

func deviceAddress(dev ir.Device) string {
	for _, intf := range dev.Interfaces {
		if intf.IPv4 != "" {
			parts := strings.Fields(intf.IPv4)
			if len(parts) > 0 {
				return parts[0]
			}
		}
	}
	return dev.Hostname
}

func (s *Service) ValidatePath(ctx context.Context, flow pathtrace.Flow, runnerName string) (PathValidation, error) {
	predicted, err := pathtrace.Trace(s.Devices, flow)
	if err != nil {
		return PathValidation{}, err
	}
	if runnerName == "" {
		runnerName = s.DefaultRunner
	}

	out := PathValidation{
		Flow:             predicted.Flow,
		PredictedVerdict: predicted.Verdict,
		Checks:           []ValidationCheck{},
	}

	if len(predicted.Hops) == 0 {
		out.ObservedVerdict = VerdictInconclusive
		out.Agreement = computeAgreement(predicted.Verdict, out.ObservedVerdict)
		return out, nil
	}

	for i, hop := range predicted.Hops {
		target := hop.NextHop
		if i == len(predicted.Hops)-1 && flow.Dst != "" {
			target = flow.Dst
		}
		check, err := s.pingCheck(ctx, hop.Device, hop.Vendor, target, runnerName)
		if err != nil {
			return out, err
		}
		out.Checks = append(out.Checks, check)
	}

	out.ObservedVerdict = observedVerdict(out.Checks)
	out.Agreement = computeAgreement(predicted.Verdict, out.ObservedVerdict)
	return out, nil
}

func (s *Service) pingCheck(ctx context.Context, device, vendor, dst, runnerName string) (ValidationCheck, error) {
	req := DiagRequest{
		Target:  device,
		Command: "ping",
		Args:    DiagArgs{Dst: dst, Count: 3},
		Runner:  runnerName,
	}
	res, err := s.Diagnose(ctx, req)
	if err != nil && res.Status == "" {
		return ValidationCheck{}, err
	}
	observed := ObservedInconclusive
	loss := 100.0
	var rtt float64
	if res.Parsed != nil && res.Parsed.Ping != nil {
		observed = observedFromPing(res.Parsed.Ping)
		loss = res.Parsed.Ping.LossPct
		rtt = res.Parsed.Ping.RTTAvgMs
	} else if res.Status == StatusOK {
		observed = ObservedReachable
		loss = 0
	} else if res.Status == StatusUnreachable {
		observed = ObservedUnreachable
	}
	return ValidationCheck{
		FromDevice: device,
		Type:       "ping",
		Target:     dst,
		Observed:   observed,
		Result: CheckResult{
			LossPct:  loss,
			RTTAvgMs: rtt,
			AuditID:  res.AuditID,
		},
	}, nil
}

func observedVerdict(checks []ValidationCheck) string {
	if len(checks) == 0 {
		return VerdictInconclusive
	}
	if checks[len(checks)-1].Observed == ObservedUnreachable {
		return VerdictUnreachable
	}
	reachable, unreachable, inconclusive := 0, 0, 0
	for _, c := range checks {
		switch c.Observed {
		case ObservedReachable:
			reachable++
		case ObservedUnreachable:
			unreachable++
		default:
			inconclusive++
		}
	}
	if unreachable > 0 {
		if reachable > 0 {
			return VerdictPartial
		}
		return VerdictUnreachable
	}
	if reachable == len(checks) {
		return VerdictReachable
	}
	if inconclusive > 0 {
		return VerdictInconclusive
	}
	return VerdictInconclusive
}

func computeAgreement(predicted pathtrace.Verdict, observed string) string {
	predictedReachable := predicted == pathtrace.VerdictDelivered
	observedReachable := observed == VerdictReachable
	if predictedReachable == observedReachable {
		return AgreementMatch
	}
	if !predictedReachable && (observed == VerdictUnreachable || observed == VerdictPartial) {
		return AgreementMatch
	}
	return AgreementMismatch
}

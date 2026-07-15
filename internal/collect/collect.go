package collect

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"network-compiler/internal/diag"
	"network-compiler/internal/guard"
)

// Options controls a collect run.
type Options struct {
	OutDir          string
	Simulate        bool
	User            string
	Creds           diag.CredRef
	KnownHosts      string
	InsecureHostKey bool
	Timeout         time.Duration
	PlanVerified    bool
	DefaultVendor   string
	AuditLog        string
	Runner          diag.Runner
	UseExecRunner   bool
}

// Result summarizes a collect run.
type Result struct {
	OutDir   string         `json:"out_dir"`
	Targets  []TargetResult `json:"targets"`
	Commands int            `json:"commands"`
	Errors   int            `json:"errors"`
}

// TargetResult records output for one device.
type TargetResult struct {
	Device       string          `json:"device"`
	ManagementIP string          `json:"management_ip"`
	Commands     []CommandResult `json:"commands"`
	Error        string          `json:"error,omitempty"`
}

// CommandResult records one command execution.
type CommandResult struct {
	Command  string `json:"command"`
	Filename string `json:"filename"`
	ExitCode int    `json:"exit_code"`
	Status   string `json:"status"`
	Error    string `json:"error,omitempty"`
}

type deviceMetadata struct {
	Hostname string `json:"hostname"`
	Vendor   string `json:"vendor"`
	Source   string `json:"source"`
}

// Run executes allowed targets and commands from a verified guard plan.
func Run(ctx context.Context, plan guard.Plan, opts Options) (Result, error) {
	if strings.TrimSpace(opts.OutDir) == "" {
		return Result{}, fmt.Errorf("out dir is required")
	}
	if !opts.PlanVerified {
		return Result{}, fmt.Errorf("plan hash not verified")
	}
	if opts.Timeout <= 0 {
		opts.Timeout = 20 * time.Second
	}
	if strings.TrimSpace(opts.DefaultVendor) == "" {
		opts.DefaultVendor = "cisco-ios"
	}
	if strings.TrimSpace(opts.User) == "" {
		opts.User = "admin"
	}
	opts.Creds = mergeCreds(opts.User, opts.Creds)

	runner, err := selectRunner(opts)
	if err != nil {
		return Result{}, err
	}
	if err := os.MkdirAll(opts.OutDir, 0755); err != nil {
		return Result{}, err
	}

	result := Result{OutDir: opts.OutDir}
	audit, err := openAudit(opts.AuditLog)
	if err != nil {
		return Result{}, err
	}
	defer audit.Close()

	targets := allowedTargets(plan)
	for _, decision := range targets {
		tr, err := runTarget(ctx, runner, decision, opts, audit)
		if err != nil {
			result.Errors++
			tr.Error = err.Error()
		}
		result.Targets = append(result.Targets, tr)
		result.Commands += len(tr.Commands)
		for _, cmd := range tr.Commands {
			if cmd.Status != "ok" {
				result.Errors++
			}
		}
	}
	sort.Slice(result.Targets, func(i, j int) bool {
		return result.Targets[i].Device < result.Targets[j].Device
	})
	return result, nil
}

func allowedTargets(plan guard.Plan) []guard.Decision {
	var out []guard.Decision
	for _, decision := range plan.Targets {
		if decision.Allowed {
			out = append(out, decision)
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		return decisionKey(out[i]) < decisionKey(out[j])
	})
	return out
}

func decisionKey(d guard.Decision) string {
	return strings.Join([]string{d.Target.Device, d.Target.ManagementIP}, "\x00")
}

func runTarget(ctx context.Context, runner diag.Runner, decision guard.Decision, opts Options, audit *auditWriter) (TargetResult, error) {
	device := strings.TrimSpace(decision.Target.Device)
	if device == "" {
		return TargetResult{}, fmt.Errorf("missing device id")
	}
	deviceDir := filepath.Join(opts.OutDir, device)
	if err := os.MkdirAll(deviceDir, 0755); err != nil {
		return TargetResult{}, err
	}
	md := deviceMetadata{
		Hostname: device,
		Vendor:   opts.DefaultVendor,
		Source:   "collect",
	}
	if err := writeMetadata(deviceDir, md); err != nil {
		return TargetResult{}, err
	}

	tr := TargetResult{
		Device:       device,
		ManagementIP: decision.Target.ManagementIP,
	}
	commands := allowedCommands(decision.Commands)
	target := diag.Target{
		Host:    device,
		Address: strings.TrimSpace(decision.Target.ManagementIP),
		Vendor:  opts.DefaultVendor,
		Creds:   opts.Creds,
	}
	for _, cd := range commands {
		cr := runCommand(ctx, runner, target, cd.Command, deviceDir, opts.Timeout)
		tr.Commands = append(tr.Commands, cr)
		audit.append(collectAuditEntry{
			Device:       device,
			ManagementIP: target.Address,
			Command:      cd.Command,
			Filename:     cr.Filename,
			ExitCode:     cr.ExitCode,
			Status:       cr.Status,
			Error:        cr.Error,
			Simulate:     opts.Simulate,
		})
	}
	return tr, nil
}

func allowedCommands(commands []guard.CommandDecision) []guard.CommandDecision {
	var out []guard.CommandDecision
	for _, cd := range commands {
		if cd.Allowed {
			out = append(out, cd)
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		return out[i].Command < out[j].Command
	})
	return out
}

func runCommand(ctx context.Context, runner diag.Runner, target diag.Target, command, deviceDir string, timeout time.Duration) CommandResult {
	filename := commandOutputName(command)
	cr := CommandResult{Command: command, Filename: filename}
	cmdCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	rendered := diag.RenderedCommand{Shell: command, Kind: "show"}
	raw, err := runner.Run(cmdCtx, target, rendered)
	output := redactOutput(raw.Output)
	if err != nil {
		cr.Status = "error"
		cr.ExitCode = raw.ExitCode
		cr.Error = err.Error()
		if output != "" {
			_ = os.WriteFile(filepath.Join(deviceDir, filename), []byte(output), 0644)
		}
		return cr
	}
	if err := os.WriteFile(filepath.Join(deviceDir, filename), []byte(output), 0644); err != nil {
		cr.Status = "error"
		cr.ExitCode = raw.ExitCode
		cr.Error = err.Error()
		return cr
	}
	cr.Status = "ok"
	cr.ExitCode = raw.ExitCode
	return cr
}

func writeMetadata(deviceDir string, md deviceMetadata) error {
	data, err := json.Marshal(md)
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(deviceDir, "metadata.json"), data, 0644)
}

var commandFilenames = map[string]string{
	"show lldp neighbors detail": "show-lldp-neighbors-detail.txt",
	"show cdp neighbors detail":  "show-cdp-neighbors-detail.txt",
	"show arp":                   "show-arp.txt",
	"show mac address-table":     "show-mac-address-table.txt",
	"show ip interface brief":    "show-ip-interface-brief.txt",
	"show vlan":                  "show-vlan.txt",
	"show running-config":        "show-running-config.txt",
}

var filenameCommands map[string]string

func init() {
	filenameCommands = make(map[string]string, len(commandFilenames))
	for command, filename := range commandFilenames {
		filenameCommands[filename] = command
	}
}

func commandOutputName(command string) string {
	command = strings.TrimSpace(command)
	if name, ok := commandFilenames[command]; ok {
		return name
	}
	return strings.ReplaceAll(command, " ", "-") + ".txt"
}

func filenameToCommand(filename string) (string, bool) {
	if command, ok := filenameCommands[filename]; ok {
		return command, true
	}
	if !strings.HasSuffix(filename, ".txt") {
		return "", false
	}
	base := strings.TrimSuffix(filename, ".txt")
	if base == "" {
		return "", false
	}
	return strings.ReplaceAll(base, "-", " "), true
}

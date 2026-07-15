package transport

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"

	"network-compiler/internal/diag"
)

type ExecRunner struct {
	SSHBinary string
}

func NewExecRunner() *ExecRunner {
	return &ExecRunner{SSHBinary: "ssh"}
}

func (e *ExecRunner) Run(ctx context.Context, target diag.Target, cmd diag.RenderedCommand) (diag.RawResult, error) {
	if isLocalTarget(target) && (cmd.Kind == "ping" || cmd.Kind == "traceroute") {
		return e.runLocal(ctx, localShell(cmd.Kind, cmd.Shell))
	}
	if target.Address == "" {
		return diag.RawResult{ExitCode: -1}, fmt.Errorf("exec runner requires target address for remote commands")
	}
	return e.runSSH(ctx, target, cmd.Shell)
}

func isLocalTarget(target diag.Target) bool {
	return strings.HasPrefix(strings.ToLower(target.Host), "ip:")
}

func localShell(kind, rendered string) string {
	if kind != "ping" {
		return rendered
	}
	fields := strings.Fields(rendered)
	if len(fields) >= 2 && fields[0] == "ping" {
		dst := fields[1]
		count := "5"
		for i := 2; i < len(fields)-1; i++ {
			if fields[i] == "repeat" || fields[i] == "count" || fields[i] == "-c" {
				count = fields[i+1]
				break
			}
		}
		return fmt.Sprintf("ping -c %s %s", count, dst)
	}
	return rendered
}

func (e *ExecRunner) runLocal(ctx context.Context, shell string) (diag.RawResult, error) {
	fields := strings.Fields(shell)
	if len(fields) == 0 {
		return diag.RawResult{ExitCode: -1}, fmt.Errorf("empty command")
	}
	c := exec.CommandContext(ctx, fields[0], fields[1:]...)
	var buf bytes.Buffer
	c.Stdout = &buf
	c.Stderr = &buf
	err := c.Run()
	exitCode := 0
	if err != nil {
		var exitErr *exec.ExitError
		if ok := asExit(err, &exitErr); ok {
			exitCode = exitErr.ExitCode()
		} else {
			exitCode = -1
		}
	}
	return diag.RawResult{Output: buf.String(), ExitCode: exitCode, Err: err}, err
}

func (e *ExecRunner) runSSH(ctx context.Context, target diag.Target, shell string) (diag.RawResult, error) {
	bin := e.SSHBinary
	if bin == "" {
		bin = "ssh"
	}
	args := []string{"-o", "BatchMode=yes", "-o", "ConnectTimeout=10"}
	if target.Creds.KeyFile != "" {
		args = append(args, "-i", target.Creds.KeyFile)
	}
	if target.Creds.Username != "" {
		args = append(args, "-l", target.Creds.Username)
	}
	args = append(args, target.Address, shell)
	c := exec.CommandContext(ctx, bin, args...)
	var buf bytes.Buffer
	c.Stdout = &buf
	c.Stderr = &buf
	err := c.Run()
	exitCode := 0
	if err != nil {
		var exitErr *exec.ExitError
		if ok := asExit(err, &exitErr); ok {
			exitCode = exitErr.ExitCode()
		} else {
			exitCode = -1
		}
	}
	return diag.RawResult{Output: buf.String(), ExitCode: exitCode, Err: err}, err
}

func asExit(err error, out **exec.ExitError) bool {
	if err == nil {
		return false
	}
	if ee, ok := err.(*exec.ExitError); ok {
		*out = ee
		return true
	}
	return false
}

type SSHConfig struct {
	KnownHostsFile  string
	InsecureHostKey bool
	ConnectTimeout  time.Duration
}

type SSHRunner struct {
	Config SSHConfig
}

func NewSSHRunner(cfg SSHConfig) *SSHRunner {
	if cfg.ConnectTimeout == 0 {
		cfg.ConnectTimeout = 10 * time.Second
	}
	return &SSHRunner{Config: cfg}
}

func (s *SSHRunner) Run(ctx context.Context, target diag.Target, cmd diag.RenderedCommand) (diag.RawResult, error) {
	if target.Address == "" {
		return diag.RawResult{ExitCode: -1}, fmt.Errorf("ssh runner requires target address")
	}
	client, err := s.dial(ctx, target)
	if err != nil {
		return diag.RawResult{ExitCode: -1, Err: err}, err
	}
	defer client.Close()

	sess, err := client.NewSession()
	if err != nil {
		return diag.RawResult{ExitCode: -1, Err: err}, err
	}
	defer sess.Close()

	var buf bytes.Buffer
	sess.Stdout = &buf
	sess.Stderr = &buf
	runErr := sess.Run(cmd.Shell)
	exitCode := 0
	if runErr != nil {
		var ee *ssh.ExitError
		if errors.As(runErr, &ee) {
			exitCode = ee.ExitStatus()
		} else {
			exitCode = -1
		}
	}
	return diag.RawResult{Output: buf.String(), ExitCode: exitCode, Err: runErr}, runErr
}

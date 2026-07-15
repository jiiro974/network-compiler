package collect

import (
	"embed"
	"fmt"
	"io/fs"
	"strings"

	"network-compiler/internal/diag"
	"network-compiler/internal/diag/transport"
)

//go:embed simulate/*
var simulateFS embed.FS

func selectRunner(opts Options) (diag.Runner, error) {
	if opts.Runner != nil {
		return opts.Runner, nil
	}
	if opts.Simulate {
		return newSimulateRunner()
	}
	if opts.UseExecRunner {
		return transport.NewExecRunner(), nil
	}
	return transport.NewSSHRunner(transport.SSHConfig{
		KnownHostsFile:  opts.KnownHosts,
		InsecureHostKey: opts.InsecureHostKey,
		ConnectTimeout:  opts.Timeout,
	}), nil
}

func newSimulateRunner() (diag.Runner, error) {
	runner := diag.NewFakeRunner()
	err := fs.WalkDir(simulateFS, "simulate", func(filePath string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		rel := strings.TrimPrefix(filePath, "simulate/")
		parts := strings.Split(rel, "/")
		if len(parts) != 2 {
			return fmt.Errorf("simulate script path %q: want simulate/<device>/<file>", filePath)
		}
		device := parts[0]
		filename := parts[1]
		command, ok := filenameToCommand(filename)
		if !ok {
			return fmt.Errorf("simulate script %q: unknown command filename", filename)
		}
		data, err := simulateFS.ReadFile(filePath)
		if err != nil {
			return err
		}
		runner.Set(device, command, diag.RawResult{Output: string(data), ExitCode: 0})
		return nil
	})
	if err != nil {
		return nil, err
	}
	return runner, nil
}

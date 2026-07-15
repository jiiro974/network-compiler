package diag

import (
	"context"
	"fmt"
	"strings"
	"sync"
)

type FakeRunner struct {
	mu       sync.Mutex
	scripts  map[string]RawResult
	Calls    []fakeCall
	FailNext error
}

type fakeCall struct {
	Target Target
	Cmd    RenderedCommand
}

func NewFakeRunner() *FakeRunner {
	return &FakeRunner{scripts: map[string]RawResult{}}
}

func (f *FakeRunner) Set(host, shell string, result RawResult) {
	key := fakeKey(host, shell)
	f.mu.Lock()
	defer f.mu.Unlock()
	f.scripts[key] = result
}

func (f *FakeRunner) SetDefault(host string, result RawResult) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.scripts["*:"+strings.ToLower(host)] = result
}

func fakeKey(host, shell string) string {
	return strings.ToLower(strings.TrimSpace(host)) + ":" + strings.TrimSpace(shell)
}

func (f *FakeRunner) Run(ctx context.Context, target Target, cmd RenderedCommand) (RawResult, error) {
	if err := ctx.Err(); err != nil {
		return RawResult{ExitCode: -1, Err: err}, err
	}
	f.mu.Lock()
	if f.FailNext != nil {
		err := f.FailNext
		f.FailNext = nil
		f.mu.Unlock()
		return RawResult{ExitCode: -1, Err: err}, err
	}
	f.Calls = append(f.Calls, fakeCall{Target: target, Cmd: cmd})
	key := fakeKey(target.Host, cmd.Shell)
	result, ok := f.scripts[key]
	if !ok {
		result, ok = f.scripts["*:"+strings.ToLower(target.Host)]
	}
	f.mu.Unlock()
	if !ok {
		return RawResult{}, fmt.Errorf("fake runner: no script for %s %q", target.Host, cmd.Shell)
	}
	out := result
	if out.Err != nil {
		return out, out.Err
	}
	return out, nil
}

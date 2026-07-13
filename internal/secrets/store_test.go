package secrets

import (
	"context"
	"errors"
	"path/filepath"
	"reflect"
	"testing"
	"time"
)

func TestNewStoreChoosesNativeBackendWhenExecutableExists(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name           string
		goos           string
		wantLookup     string
		resolved       string
		backend        string
		probeArguments []string
	}{
		{name: "macOS Keychain", goos: "darwin", wantLookup: "/usr/bin/security", resolved: "/usr/bin/security", backend: BackendMacOSKeychain, probeArguments: []string{"list-keychains"}},
		{name: "Linux Secret Service", goos: "linux", wantLookup: "secret-tool", resolved: "/usr/bin/secret-tool", backend: BackendLinuxSecretService, probeArguments: []string{"search", "--all", "service", nativeServiceName}},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			var lookedUp string
			lookup := func(name string) (string, error) {
				lookedUp = name
				return test.resolved, nil
			}
			runner := &deadlineRecordingRunner{}
			store, info, err := newStore(test.goos, t.TempDir(), lookup, runner)
			if err != nil {
				t.Fatalf("newStore() returned an unexpected error: %v", err)
			}
			if store == nil {
				t.Fatal("newStore() returned nil store")
			}
			defer store.Close()
			if lookedUp != test.wantLookup {
				t.Fatalf("looked up executable %q, want %q", lookedUp, test.wantLookup)
			}
			if info.Name != test.backend || info.Warning != "" {
				t.Fatalf("backend info = %#v, want native backend without warning", info)
			}
			commands := runner.commands()
			if len(commands) != 1 {
				t.Fatalf("probe commands = %#v, want one direct command", commands)
			}
			if commands[0].executable != test.resolved || !reflect.DeepEqual(commands[0].arguments, test.probeArguments) || commands[0].stdin != "" {
				t.Fatalf("probe command = %#v, want executable %q with arguments %#v and empty stdin", commands[0], test.resolved, test.probeArguments)
			}
			if !runner.hasDeadline || time.Until(runner.deadline) <= 0 || time.Until(runner.deadline) > 5*time.Second {
				t.Fatalf("probe deadline = %v, present %t; want a short active bound", runner.deadline, runner.hasDeadline)
			}
		})
	}
}

func TestNewStoreFallsBackToFileWhenNativeProbeFails(t *testing.T) {
	t.Parallel()

	directory := filepath.Join(t.TempDir(), "nested", "secrets")
	runner := &recordingRunner{err: errors.New("credential service unavailable")}
	store, info, err := newStore("linux", directory, func(string) (string, error) {
		return "/usr/bin/secret-tool", nil
	}, runner)
	if err != nil {
		t.Fatalf("newStore() returned an unexpected error: %v", err)
	}
	defer store.Close()
	if info.Name != BackendFile || info.Warning == "" {
		t.Fatalf("backend info = %#v, want file backend with warning", info)
	}
	if _, native := store.(*commandStore); native {
		t.Fatal("newStore() selected native backend after a failed operational probe")
	}
	commands := runner.commands()
	wantArguments := []string{"search", "--all", "service", nativeServiceName}
	if len(commands) != 1 || commands[0].executable != "/usr/bin/secret-tool" || !reflect.DeepEqual(commands[0].arguments, wantArguments) {
		t.Fatalf("probe commands = %#v, want one direct Secret Service search", commands)
	}
}

func TestNewStoreFallsBackToFileAndExposesWarning(t *testing.T) {
	t.Parallel()

	directory := filepath.Join(t.TempDir(), "nested", "secrets")
	store, info, err := newStore("linux", directory, func(string) (string, error) {
		return "", errors.New("not found")
	}, &recordingRunner{})
	if err != nil {
		t.Fatalf("newStore() returned an unexpected error: %v", err)
	}
	defer store.Close()
	if info.Name != BackendFile || info.Warning == "" {
		t.Fatalf("backend info = %#v, want file backend with warning", info)
	}
	if err := store.Set(context.Background(), "subscription-1", "https://example.com/private"); err != nil {
		t.Fatalf("fallback Set() returned an unexpected error: %v", err)
	}
	value, err := store.Get(context.Background(), "subscription-1")
	if err != nil {
		t.Fatalf("fallback Get() returned an unexpected error: %v", err)
	}
	if value != "https://example.com/private" {
		t.Fatalf("fallback value = %q, want stored URL", value)
	}
}

type deadlineRecordingRunner struct {
	recordingRunner
	deadline    time.Time
	hasDeadline bool
}

func (runner *deadlineRecordingRunner) Run(ctx context.Context, executable string, arguments []string, stdin string) (CommandResult, error) {
	runner.deadline, runner.hasDeadline = ctx.Deadline()
	return runner.recordingRunner.Run(ctx, executable, arguments, stdin)
}

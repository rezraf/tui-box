package secrets

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestMacOSKeychainInvokesSecurityWithSafeArguments(t *testing.T) {
	t.Parallel()

	const secret = "https://user:password@example.com/private?token=query-secret"
	runner := &recordingRunner{result: CommandResult{Stdout: []byte(secret + "\n")}}
	store := newMacOSKeychainStore(runner)
	defer store.Close()

	if err := store.Set(context.Background(), "subscription-1", secret); err != nil {
		t.Fatalf("Set() returned an unexpected error: %v", err)
	}
	got, err := store.Get(context.Background(), "subscription-1")
	if err != nil {
		t.Fatalf("Get() returned an unexpected error: %v", err)
	}
	if got != secret {
		t.Fatalf("Get() = %q, want original secret", got)
	}
	if err := store.Delete(context.Background(), "subscription-1"); err != nil {
		t.Fatalf("Delete() returned an unexpected error: %v", err)
	}

	want := []recordedCommand{
		{
			executable: "/usr/bin/security",
			arguments:  []string{"add-generic-password", "-U", "-a", "subscription-1", "-s", nativeServiceName, "-w"},
			stdin:      secret,
		},
		{
			executable: "/usr/bin/security",
			arguments:  []string{"find-generic-password", "-a", "subscription-1", "-s", nativeServiceName, "-w"},
		},
		{
			executable: "/usr/bin/security",
			arguments:  []string{"delete-generic-password", "-a", "subscription-1", "-s", nativeServiceName},
		},
	}
	assertRecordedCommands(t, runner.commands(), want, secret)
}

func TestMacOSKeychainPasswordPromptFlagIsLastAndSecretUsesStdin(t *testing.T) {
	t.Parallel()

	const secret = "https://user:password@example.com/private?token=query-secret"
	runner := &recordingRunner{}
	store := newMacOSKeychainStore(runner)
	defer store.Close()

	if err := store.Set(context.Background(), "subscription-1", secret); err != nil {
		t.Fatalf("Set() returned an unexpected error: %v", err)
	}
	commands := runner.commands()
	if len(commands) != 1 {
		t.Fatalf("recorded %d commands, want 1", len(commands))
	}
	command := commands[0]
	if len(command.arguments) == 0 || command.arguments[len(command.arguments)-1] != "-w" {
		t.Fatalf("arguments = %#v, want -w as the final option", command.arguments)
	}
	if command.stdin != secret {
		t.Fatalf("stdin did not contain the secret")
	}
	for _, argument := range command.arguments {
		if strings.Contains(argument, secret) {
			t.Fatalf("secret appeared in argv: %#v", command.arguments)
		}
	}
}

func TestLinuxSecretServiceInvokesSecretToolWithSafeArguments(t *testing.T) {
	t.Parallel()

	const secret = "https://user:password@example.com/private?token=query-secret"
	runner := &recordingRunner{result: CommandResult{Stdout: []byte(secret + "\n")}}
	store := newLinuxSecretServiceStore("/usr/bin/secret-tool", runner)
	defer store.Close()

	if err := store.Set(context.Background(), "subscription-1", secret); err != nil {
		t.Fatalf("Set() returned an unexpected error: %v", err)
	}
	got, err := store.Get(context.Background(), "subscription-1")
	if err != nil {
		t.Fatalf("Get() returned an unexpected error: %v", err)
	}
	if got != secret {
		t.Fatalf("Get() = %q, want original secret", got)
	}
	if err := store.Delete(context.Background(), "subscription-1"); err != nil {
		t.Fatalf("Delete() returned an unexpected error: %v", err)
	}

	want := []recordedCommand{
		{
			executable: "/usr/bin/secret-tool",
			arguments:  []string{"store", "--label", "TuiBox subscription", "service", nativeServiceName, "account", "subscription-1"},
			stdin:      secret,
		},
		{
			executable: "/usr/bin/secret-tool",
			arguments:  []string{"lookup", "service", nativeServiceName, "account", "subscription-1"},
		},
		{
			executable: "/usr/bin/secret-tool",
			arguments:  []string{"clear", "service", nativeServiceName, "account", "subscription-1"},
		},
	}
	assertRecordedCommands(t, runner.commands(), want, secret)
}

func TestCommandStoreNormalizesMissingSecretsAcrossBackends(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		store  func(CommandRunner) Store
		result CommandResult
	}{
		{
			name:  "macOS",
			store: func(runner CommandRunner) Store { return newMacOSKeychainStore(runner) },
			result: CommandResult{
				ExitCode: 44,
				Stderr:   []byte("security: SecKeychainSearchCopyNext: The specified item could not be found in the keychain."),
			},
		},
		{
			name:   "Linux",
			store:  func(runner CommandRunner) Store { return newLinuxSecretServiceStore("/usr/bin/secret-tool", runner) },
			result: CommandResult{ExitCode: 1},
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			runner := &recordingRunner{result: test.result, err: errors.New("native command failed")}
			store := test.store(runner)
			defer store.Close()
			if _, err := store.Get(context.Background(), "subscription-1"); !errors.Is(err, ErrSecretNotFound) {
				t.Fatalf("Get() error = %v, want ErrSecretNotFound", err)
			}
			if err := store.Delete(context.Background(), "subscription-1"); err != nil {
				t.Fatalf("Delete() missing secret returned an unexpected error: %v", err)
			}
		})
	}
}

func TestCommandStoreRedactsRunnerErrors(t *testing.T) {
	t.Parallel()

	const secret = "https://user:password@example.com/private?token=query-secret"
	for _, operation := range []struct {
		name string
		run  func(Store) error
	}{
		{name: "Get", run: func(store Store) error { _, err := store.Get(context.Background(), "subscription-1"); return err }},
		{name: "Set", run: func(store Store) error { return store.Set(context.Background(), "subscription-1", secret) }},
		{name: "Delete", run: func(store Store) error { return store.Delete(context.Background(), "subscription-1") }},
	} {
		operation := operation
		t.Run(operation.name, func(t *testing.T) {
			t.Parallel()
			runner := &recordingRunner{
				result: CommandResult{ExitCode: 2, Stderr: []byte("failed with " + secret)},
				err:    errors.New("failed with " + secret),
			}
			store := newLinuxSecretServiceStore("/usr/bin/secret-tool", runner)
			defer store.Close()
			err := operation.run(store)
			if err == nil {
				t.Fatalf("%s() returned nil error, want runner failure", operation.name)
			}
			for _, sensitive := range []string{secret, "password", "example.com", "query-secret"} {
				if strings.Contains(err.Error(), sensitive) {
					t.Fatalf("command error leaked %q: %v", sensitive, err)
				}
			}
		})
	}
}

func TestCommandStorePreservesContextErrorIdentity(t *testing.T) {
	t.Parallel()

	for _, contextErr := range []error{context.Canceled, context.DeadlineExceeded} {
		runner := &recordingRunner{result: CommandResult{ExitCode: 1}, err: contextErr}
		store := newLinuxSecretServiceStore("/usr/bin/secret-tool", runner)
		defer store.Close()
		if _, err := store.Get(context.Background(), "subscription-1"); !errors.Is(err, contextErr) {
			t.Fatalf("Get() error = %v, want %v identity", err, contextErr)
		}
		if err := store.Set(context.Background(), "subscription-1", "secret"); !errors.Is(err, contextErr) {
			t.Fatalf("Set() error = %v, want %v identity", err, contextErr)
		}
		if err := store.Delete(context.Background(), "subscription-1"); !errors.Is(err, contextErr) {
			t.Fatalf("Delete() error = %v, want %v identity", err, contextErr)
		}
	}
}

func TestCommandStoreRejectsUnsafeKeysBeforeExecution(t *testing.T) {
	t.Parallel()

	runner := &recordingRunner{}
	store := newLinuxSecretServiceStore("/usr/bin/secret-tool", runner)
	defer store.Close()
	if err := store.Set(context.Background(), "--unsafe\nkey", "secret"); err == nil {
		t.Fatal("Set() returned nil error, want unsafe key rejection")
	}
	if len(runner.commands()) != 0 {
		t.Fatal("runner was invoked for an unsafe key")
	}
}

func TestCommandStoreCloseWaitsForInFlightCommand(t *testing.T) {
	runner := &blockingRunner{
		started: make(chan struct{}),
		release: make(chan struct{}),
		result:  CommandResult{Stdout: []byte("secret\n")},
	}
	store := newLinuxSecretServiceStore("/usr/bin/secret-tool", runner)

	commandDone := make(chan error, 1)
	go func() {
		_, err := store.Get(context.Background(), "subscription-1")
		commandDone <- err
	}()
	<-runner.started

	closeDone := make(chan error, 1)
	go func() { closeDone <- store.Close() }()
	select {
	case err := <-closeDone:
		close(runner.release)
		<-commandDone
		t.Fatalf("Close() returned before the in-flight command completed: %v", err)
	case <-time.After(25 * time.Millisecond):
	}

	close(runner.release)
	if err := <-commandDone; err != nil {
		t.Fatalf("Get() returned an unexpected error: %v", err)
	}
	if err := <-closeDone; err != nil {
		t.Fatalf("Close() returned an unexpected error: %v", err)
	}
}

func TestCommandStoreCloseIsIdempotent(t *testing.T) {
	store := newLinuxSecretServiceStore("/usr/bin/secret-tool", &recordingRunner{})
	if err := store.Close(); err != nil {
		t.Fatalf("Close() returned an unexpected error: %v", err)
	}
	if err := store.Close(); err != nil {
		t.Fatalf("second Close() returned an unexpected error: %v", err)
	}
}

func TestCommandStoreOperationsAfterCloseReturnStableErrorWithoutInvokingRunner(t *testing.T) {
	runner := &recordingRunner{result: CommandResult{Stdout: []byte("secret\n")}}
	store := newLinuxSecretServiceStore("/usr/bin/secret-tool", runner)
	if err := store.Close(); err != nil {
		t.Fatalf("Close() returned an unexpected error: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	operations := []struct {
		name string
		run  func() error
	}{
		{name: "Get", run: func() error { _, err := store.Get(ctx, "subscription-1"); return err }},
		{name: "Set", run: func() error { return store.Set(ctx, "subscription-1", "secret") }},
		{name: "Delete", run: func() error { return store.Delete(ctx, "subscription-1") }},
	}
	for _, operation := range operations {
		if err := operation.run(); err != ErrSecretStoreClosed {
			t.Errorf("%s() error = %v, want stable ErrSecretStoreClosed", operation.name, err)
		}
	}
	if commands := runner.commands(); len(commands) != 0 {
		t.Fatalf("runner was invoked %d times after Close(), want 0", len(commands))
	}
}

type blockingRunner struct {
	started chan struct{}
	release chan struct{}
	result  CommandResult
}

func (runner *blockingRunner) Run(context.Context, string, []string, string) (CommandResult, error) {
	close(runner.started)
	<-runner.release
	return runner.result, nil
}

type recordedCommand struct {
	executable string
	arguments  []string
	stdin      string
}

type recordingRunner struct {
	mu       sync.Mutex
	recorded []recordedCommand
	result   CommandResult
	err      error
}

func (runner *recordingRunner) Run(_ context.Context, executable string, arguments []string, stdin string) (CommandResult, error) {
	runner.mu.Lock()
	defer runner.mu.Unlock()
	runner.recorded = append(runner.recorded, recordedCommand{
		executable: executable,
		arguments:  append([]string(nil), arguments...),
		stdin:      stdin,
	})
	result := runner.result
	result.Stdout = append([]byte(nil), result.Stdout...)
	result.Stderr = append([]byte(nil), result.Stderr...)
	return result, runner.err
}

func (runner *recordingRunner) commands() []recordedCommand {
	runner.mu.Lock()
	defer runner.mu.Unlock()
	commands := make([]recordedCommand, len(runner.recorded))
	copy(commands, runner.recorded)
	return commands
}

func assertRecordedCommands(t *testing.T, got, want []recordedCommand, secret string) {
	t.Helper()
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("recorded commands = %#v, want %#v", got, want)
	}
	for _, command := range got {
		if command.executable == "/bin/sh" || command.executable == "/bin/bash" {
			t.Fatalf("command used a shell: %#v", command)
		}
		for _, argument := range command.arguments {
			if strings.Contains(argument, secret) {
				t.Fatalf("secret appeared in argv: %#v", command.arguments)
			}
		}
	}
}

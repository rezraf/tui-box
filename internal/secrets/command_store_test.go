package secrets

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"sync"
	"testing"
)

func TestMacOSKeychainInvokesSecurityWithSafeArguments(t *testing.T) {
	t.Parallel()

	const secret = "https://user:password@example.com/private?token=query-secret"
	runner := &recordingRunner{output: []byte(secret + "\n")}
	store := newMacOSKeychainStore(runner)

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
	runner := &recordingRunner{output: []byte(secret + "\n")}
	store := newLinuxSecretServiceStore("/usr/bin/secret-tool", runner)

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

func TestCommandStoreRedactsRunnerErrors(t *testing.T) {
	t.Parallel()

	const secret = "https://user:password@example.com/private?token=query-secret"
	runner := &recordingRunner{err: errors.New("failed with " + secret)}
	store := newLinuxSecretServiceStore("/usr/bin/secret-tool", runner)

	err := store.Set(context.Background(), "subscription-1", secret)
	if err == nil {
		t.Fatal("Set() returned nil error, want runner failure")
	}
	for _, sensitive := range []string{secret, "password", "example.com", "query-secret"} {
		if strings.Contains(err.Error(), sensitive) {
			t.Fatalf("command error leaked %q: %v", sensitive, err)
		}
	}
}

func TestCommandStoreRejectsUnsafeKeysBeforeExecution(t *testing.T) {
	t.Parallel()

	runner := &recordingRunner{}
	store := newLinuxSecretServiceStore("/usr/bin/secret-tool", runner)
	if err := store.Set(context.Background(), "--unsafe\nkey", "secret"); err == nil {
		t.Fatal("Set() returned nil error, want unsafe key rejection")
	}
	if len(runner.commands()) != 0 {
		t.Fatal("runner was invoked for an unsafe key")
	}
}

type recordedCommand struct {
	executable string
	arguments  []string
	stdin      string
}

type recordingRunner struct {
	mu       sync.Mutex
	recorded []recordedCommand
	output   []byte
	err      error
}

func (runner *recordingRunner) Run(_ context.Context, executable string, arguments []string, stdin string) ([]byte, error) {
	runner.mu.Lock()
	defer runner.mu.Unlock()
	runner.recorded = append(runner.recorded, recordedCommand{
		executable: executable,
		arguments:  append([]string(nil), arguments...),
		stdin:      stdin,
	})
	return append([]byte(nil), runner.output...), runner.err
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

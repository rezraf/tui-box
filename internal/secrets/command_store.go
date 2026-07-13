package secrets

import (
	"bytes"
	"context"
	"errors"
	"os/exec"
	"strings"
	"sync"
)

const (
	macOSSecurityExecutable = "/usr/bin/security"
	nativeServiceName       = "io.github.rezraf.tuibox"
	maxSecretKeyLength      = 128
)

var errSecretCommandFailed = errors.New("credential store operation failed")

type CommandResult struct {
	Stdout   []byte
	Stderr   []byte
	ExitCode int
}

type CommandRunner interface {
	Run(context.Context, string, []string, string) (CommandResult, error)
}

type execCommandRunner struct{}

func (execCommandRunner) Run(ctx context.Context, executable string, arguments []string, stdin string) (CommandResult, error) {
	command := exec.CommandContext(ctx, executable, arguments...)
	command.Stdin = strings.NewReader(stdin)
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	command.Stdout = &stdout
	command.Stderr = &stderr

	err := command.Run()
	result := CommandResult{Stdout: stdout.Bytes(), Stderr: stderr.Bytes()}
	if err == nil {
		return result, nil
	}
	result.ExitCode = -1
	var exitError *exec.ExitError
	if errors.As(err, &exitError) {
		result.ExitCode = exitError.ExitCode()
	}
	if ctxErr := ctx.Err(); ctxErr != nil {
		return result, ctxErr
	}
	return result, err
}

type commandBackend int

const (
	commandBackendMacOS commandBackend = iota
	commandBackendLinux
)

type commandStore struct {
	lifecycle  sync.RWMutex
	backend    commandBackend
	executable string
	runner     CommandRunner
	closed     bool
}

func newMacOSKeychainStore(runner CommandRunner) Store {
	return newCommandStore(commandBackendMacOS, macOSSecurityExecutable, runner)
}

func newLinuxSecretServiceStore(executable string, runner CommandRunner) Store {
	return newCommandStore(commandBackendLinux, executable, runner)
}

func newCommandStore(backend commandBackend, executable string, runner CommandRunner) Store {
	return &commandStore{backend: backend, executable: executable, runner: runner}
}

func (store *commandStore) Get(ctx context.Context, key string) (string, error) {
	if err := store.beginOperation(); err != nil {
		return "", err
	}
	defer store.endOperation()

	if !validSecretKey(key) {
		return "", errors.New("secret key is invalid")
	}
	result, err := store.runner.Run(ctx, store.executable, store.getArguments(key), "")
	if err != nil {
		if contextErr := contextOperationError(ctx, err); contextErr != nil {
			return "", contextErr
		}
		if store.isNotFound(result) {
			return "", ErrSecretNotFound
		}
		return "", errSecretCommandFailed
	}
	return strings.TrimSuffix(strings.TrimSuffix(string(result.Stdout), "\n"), "\r"), nil
}

func (store *commandStore) Set(ctx context.Context, key, secret string) error {
	if err := store.beginOperation(); err != nil {
		return err
	}
	defer store.endOperation()

	if !validSecretKey(key) {
		return errors.New("secret key is invalid")
	}
	_, err := store.runner.Run(ctx, store.executable, store.setArguments(key), secret)
	if err == nil {
		return nil
	}
	if contextErr := contextOperationError(ctx, err); contextErr != nil {
		return contextErr
	}
	return errSecretCommandFailed
}

func (store *commandStore) Delete(ctx context.Context, key string) error {
	if err := store.beginOperation(); err != nil {
		return err
	}
	defer store.endOperation()

	if !validSecretKey(key) {
		return errors.New("secret key is invalid")
	}
	result, err := store.runner.Run(ctx, store.executable, store.deleteArguments(key), "")
	if err == nil {
		return nil
	}
	if contextErr := contextOperationError(ctx, err); contextErr != nil {
		return contextErr
	}
	if store.isNotFound(result) {
		return nil
	}
	return errSecretCommandFailed
}

func (store *commandStore) Close() error {
	store.lifecycle.Lock()
	defer store.lifecycle.Unlock()
	if store.closed {
		return nil
	}
	store.closed = true
	return nil
}

func (store *commandStore) beginOperation() error {
	store.lifecycle.RLock()
	if store.closed {
		store.lifecycle.RUnlock()
		return ErrSecretStoreClosed
	}
	return nil
}

func (store *commandStore) endOperation() {
	store.lifecycle.RUnlock()
}

func (store *commandStore) isNotFound(result CommandResult) bool {
	if store.backend == commandBackendMacOS {
		return result.ExitCode == 44
	}
	return result.ExitCode == 1 && len(bytes.TrimSpace(result.Stdout)) == 0 && len(bytes.TrimSpace(result.Stderr)) == 0
}

func (store *commandStore) getArguments(key string) []string {
	if store.backend == commandBackendMacOS {
		return []string{"find-generic-password", "-a", key, "-s", nativeServiceName, "-w"}
	}
	return []string{"lookup", "service", nativeServiceName, "account", key}
}

func (store *commandStore) setArguments(key string) []string {
	if store.backend == commandBackendMacOS {
		// security(1) requires -w last to prompt on stdin without exposing the secret in argv.
		return []string{"add-generic-password", "-U", "-a", key, "-s", nativeServiceName, "-w"}
	}
	return []string{"store", "--label", "TuiBox subscription", "service", nativeServiceName, "account", key}
}

func (store *commandStore) deleteArguments(key string) []string {
	if store.backend == commandBackendMacOS {
		return []string{"delete-generic-password", "-a", key, "-s", nativeServiceName}
	}
	return []string{"clear", "service", nativeServiceName, "account", key}
}

func validSecretKey(key string) bool {
	if key == "" || len(key) > maxSecretKeyLength {
		return false
	}
	for index, character := range key {
		if character >= 'a' && character <= 'z' ||
			character >= 'A' && character <= 'Z' ||
			character >= '0' && character <= '9' ||
			(index > 0 && (character == '-' || character == '_' || character == '.')) {
			continue
		}
		return false
	}
	return true
}

func contextOperationError(ctx context.Context, err error) error {
	if ctxErr := ctx.Err(); ctxErr != nil {
		return ctxErr
	}
	if errors.Is(err, context.Canceled) {
		return context.Canceled
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return context.DeadlineExceeded
	}
	return nil
}

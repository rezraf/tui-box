package secrets

import (
	"context"
	"errors"
	"os/exec"
	"strings"
)

const (
	macOSSecurityExecutable = "/usr/bin/security"
	nativeServiceName       = "io.github.rezraf.tuibox"
	maxSecretKeyLength      = 128
)

var errSecretCommandFailed = errors.New("credential store operation failed")

type CommandRunner interface {
	Run(context.Context, string, []string, string) ([]byte, error)
}

type execCommandRunner struct{}

func (execCommandRunner) Run(ctx context.Context, executable string, arguments []string, stdin string) ([]byte, error) {
	command := exec.CommandContext(ctx, executable, arguments...)
	command.Stdin = strings.NewReader(stdin)
	return command.Output()
}

type commandBackend int

const (
	commandBackendMacOS commandBackend = iota
	commandBackendLinux
)

type commandStore struct {
	backend    commandBackend
	executable string
	runner     CommandRunner
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
	if !validSecretKey(key) {
		return "", errors.New("secret key is invalid")
	}
	output, err := store.runner.Run(ctx, store.executable, store.getArguments(key), "")
	if err != nil {
		return "", errSecretCommandFailed
	}
	return strings.TrimSuffix(strings.TrimSuffix(string(output), "\n"), "\r"), nil
}

func (store *commandStore) Set(ctx context.Context, key, secret string) error {
	if !validSecretKey(key) {
		return errors.New("secret key is invalid")
	}
	if _, err := store.runner.Run(ctx, store.executable, store.setArguments(key), secret); err != nil {
		return errSecretCommandFailed
	}
	return nil
}

func (store *commandStore) Delete(ctx context.Context, key string) error {
	if !validSecretKey(key) {
		return errors.New("secret key is invalid")
	}
	if _, err := store.runner.Run(ctx, store.executable, store.deleteArguments(key), ""); err != nil {
		return errSecretCommandFailed
	}
	return nil
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

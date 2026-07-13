package secrets

import (
	"context"
	"errors"
	"os/exec"
	"runtime"
	"time"
)

const (
	BackendMacOSKeychain      = "macos-keychain"
	BackendLinuxSecretService = "linux-secret-service"
	BackendFile               = "file"

	fallbackWarning           = "OS credential storage is unavailable; subscription URLs are stored in a restricted local file"
	nativeBackendProbeTimeout = 2 * time.Second
)

var ErrSecretNotFound = errors.New("secret was not found")

type Store interface {
	Get(context.Context, string) (string, error)
	Set(context.Context, string, string) error
	Delete(context.Context, string) error
}

type BackendInfo struct {
	Name    string
	Warning string
}

type executableLookup func(string) (string, error)

func Open(directory string) (Store, BackendInfo, error) {
	return newStore(runtime.GOOS, directory, exec.LookPath, execCommandRunner{})
}

func newStore(goos, directory string, lookup executableLookup, runner CommandRunner) (Store, BackendInfo, error) {
	switch goos {
	case "darwin":
		if executable, err := lookup(macOSSecurityExecutable); err == nil && probeNativeBackend(commandBackendMacOS, executable, runner) {
			return newCommandStore(commandBackendMacOS, executable, runner), BackendInfo{Name: BackendMacOSKeychain}, nil
		}
	case "linux":
		if executable, err := lookup("secret-tool"); err == nil && probeNativeBackend(commandBackendLinux, executable, runner) {
			return newCommandStore(commandBackendLinux, executable, runner), BackendInfo{Name: BackendLinuxSecretService}, nil
		}
	}

	store, err := newFileStore(directory)
	if err != nil {
		return nil, BackendInfo{}, err
	}
	return store, BackendInfo{Name: BackendFile, Warning: fallbackWarning}, nil
}

func probeNativeBackend(backend commandBackend, executable string, runner CommandRunner) bool {
	ctx, cancel := context.WithTimeout(context.Background(), nativeBackendProbeTimeout)
	defer cancel()

	arguments := []string{"search", "--all", "service", nativeServiceName}
	if backend == commandBackendMacOS {
		arguments = []string{"list-keychains"}
	}
	_, err := runner.Run(ctx, executable, arguments, "")
	return err == nil
}

package secrets

import (
	"context"
	"errors"
	"os/exec"
	"runtime"
)

const (
	BackendMacOSKeychain      = "macos-keychain"
	BackendLinuxSecretService = "linux-secret-service"
	BackendFile               = "file"

	fallbackWarning = "OS credential storage is unavailable; subscription URLs are stored in a restricted local file"
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
		if executable, err := lookup(macOSSecurityExecutable); err == nil {
			return newCommandStore(commandBackendMacOS, executable, runner), BackendInfo{Name: BackendMacOSKeychain}, nil
		}
	case "linux":
		if executable, err := lookup("secret-tool"); err == nil {
			return newCommandStore(commandBackendLinux, executable, runner), BackendInfo{Name: BackendLinuxSecretService}, nil
		}
	}

	store, err := newFileStore(directory)
	if err != nil {
		return nil, BackendInfo{}, err
	}
	return store, BackendInfo{Name: BackendFile, Warning: fallbackWarning}, nil
}

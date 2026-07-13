//go:build darwin || linux

package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"syscall"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/rezraf/tui-box/internal/app"
	"github.com/rezraf/tui-box/internal/cli"
	"github.com/rezraf/tui-box/internal/latency"
	"github.com/rezraf/tui-box/internal/rpc"
	"github.com/rezraf/tui-box/internal/secrets"
	"github.com/rezraf/tui-box/internal/state"
	"github.com/rezraf/tui-box/internal/subscription"
	"github.com/rezraf/tui-box/internal/tui"
	"github.com/rezraf/tui-box/internal/update"
)

const (
	defaultLinuxSocketPath    = "/run/tuibox/tuiboxd.sock"
	defaultDarwinSocketPath   = "/private/var/run/tuibox/tuiboxd.sock"
	socketEnvironmentVariable = "TUIBOX_SOCKET"
	applicationDirectoryName  = "tuibox"
	latencyTimeout            = 5 * time.Second
	latencyParallelism        = 16
	rpcTimeout                = 10 * time.Second
	releaseRepository         = "rezraf/tui-box"
)

var (
	version = "dev"
	build   = "unknown"

	errInvalidClientConfiguration = errors.New("client configuration is invalid")
)

type stateStoreCloser interface {
	app.StateStore
	Close() error
}

type applicationDependencies struct {
	userDataDir    func() (string, error)
	userConfigDir  func() (string, error)
	getenv         func(string) string
	openState      func(string) (stateStoreCloser, error)
	openSecrets    func(string) (secrets.Store, secrets.BackendInfo, error)
	newFetcher     func() app.SubscriptionFetcher
	newLatency     func() (app.LatencyChecker, error)
	newDaemon      func(string) (app.DaemonClient, error)
	currentVersion string
	newUpdater     func(string) (app.Updater, error)
	newApplication func(app.Config) (cli.Service, error)
}

type runDependencies struct {
	openService    cli.ServiceOpener
	runTUI         cli.TUIRunner
	applyInstalled func(context.Context, string) error
	version        string
	build          string
}

type tuiLauncher func(context.Context, tui.RunConfig) error

func main() {
	ctx, stopSignals := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	code := run(ctx, os.Args[1:], os.Stdout, os.Stderr, defaultRunDependencies())
	stopSignals()
	os.Exit(code)
}

func run(ctx context.Context, arguments []string, stdout, stderr io.Writer, dependencies runDependencies) int {
	if len(arguments) > 0 && arguments[0] == update.InternalApplyArgument {
		if len(arguments) != 2 || dependencies.applyInstalled == nil || dependencies.applyInstalled(ctx, arguments[1]) != nil {
			_, _ = fmt.Fprintln(stderr, "update failed")
			return 1
		}
		return 0
	}
	command, err := cli.New(cli.Config{
		OpenService: dependencies.openService,
		RunTUI:      dependencies.runTUI,
		Version:     dependencies.version,
		Build:       dependencies.build,
		Stdout:      stdout,
		Stderr:      stderr,
	})
	if err != nil {
		_, _ = fmt.Fprintln(stderr, cli.ErrOperationFailed)
		return 1
	}
	command.SetArgs(arguments)
	if err := command.ExecuteContext(ctx); err != nil {
		_, _ = fmt.Fprintln(stderr, cli.ErrorMessage(err))
		return cli.ExitCode(err)
	}
	return 0
}

func defaultRunDependencies() runDependencies {
	applicationDeps := defaultApplicationDependencies()
	return runDependencies{
		openService: func(ctx context.Context) (cli.Service, func() error, error) {
			return openApplicationService(ctx, applicationDeps)
		},
		runTUI: newTUIRunner(os.Stdin, applicationDeps, nil, tui.Run),
		applyInstalled: func(ctx context.Context, requestedVersion string) error {
			helperPath, err := os.Executable()
			if err != nil {
				return errInvalidClientConfiguration
			}
			return update.ApplyInstalled(ctx, update.Config{
				CurrentVersion: version,
				Repository:     releaseRepository,
				Stdin:          os.Stdin,
				Stdout:         os.Stdout,
				Stderr:         os.Stderr,
			}, requestedVersion, helperPath, os.Geteuid())
		},
		version: version,
		build:   build,
	}
}

func defaultApplicationDependencies() applicationDependencies {
	return applicationDependencies{
		userDataDir: func() (string, error) {
			return resolveUserDataDirectory(runtime.GOOS, os.Getenv, os.UserHomeDir)
		},
		userConfigDir: os.UserConfigDir,
		getenv:        os.Getenv,
		openState: func(directory string) (stateStoreCloser, error) {
			return state.NewStore(directory)
		},
		openSecrets: secrets.Open,
		newFetcher: func() app.SubscriptionFetcher {
			return subscription.NewFetcher(&http.Client{Timeout: subscription.DefaultSubscriptionTimeout})
		},
		newLatency: func() (app.LatencyChecker, error) {
			return latency.NewChecker(latency.Config{Timeout: latencyTimeout, MaxParallel: latencyParallelism})
		},
		newDaemon: func(socketPath string) (app.DaemonClient, error) {
			return rpc.NewClient(socketPath, rpcTimeout)
		},
		currentVersion: version,
		newUpdater: func(currentVersion string) (app.Updater, error) {
			if currentVersion == "dev" {
				return nil, nil
			}
			return update.New(update.Config{
				CurrentVersion: currentVersion,
				Repository:     releaseRepository,
				Stdin:          os.Stdin,
				Stdout:         os.Stdout,
				Stderr:         os.Stderr,
			})
		},
		newApplication: func(config app.Config) (cli.Service, error) {
			return app.NewService(config)
		},
	}
}

func openApplicationService(ctx context.Context, dependencies applicationDependencies) (cli.Service, func() error, error) {
	if err := validateApplicationDependencies(dependencies); err != nil {
		return nil, nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, nil, err
	}

	socketPath, err := resolveSocketPath(dependencies.getenv)
	if err != nil {
		return nil, nil, err
	}
	dataDirectory, err := applicationDirectory(dependencies.userDataDir)
	if err != nil {
		return nil, nil, err
	}
	configDirectory, err := applicationDirectory(dependencies.userConfigDir)
	if err != nil {
		return nil, nil, err
	}

	stateStore, err := dependencies.openState(dataDirectory)
	if err != nil {
		if stateStore != nil {
			return nil, nil, errors.Join(err, stateStore.Close())
		}
		return nil, nil, err
	}
	if stateStore == nil {
		return nil, nil, errInvalidClientConfiguration
	}
	secretStore, backend, err := dependencies.openSecrets(configDirectory)
	if err != nil {
		if secretStore != nil {
			return nil, nil, errors.Join(err, secretStore.Close(), stateStore.Close())
		}
		return nil, nil, errors.Join(err, stateStore.Close())
	}
	if secretStore == nil {
		return nil, nil, errors.Join(errInvalidClientConfiguration, stateStore.Close())
	}
	closeStores := func() error {
		secretErr := secretStore.Close()
		stateErr := stateStore.Close()
		return errors.Join(secretErr, stateErr)
	}

	latencyChecker, err := dependencies.newLatency()
	if err != nil {
		return nil, nil, errors.Join(err, closeStores())
	}
	daemonClient, err := dependencies.newDaemon(socketPath)
	if err != nil {
		return nil, nil, errors.Join(err, closeStores())
	}
	updater, err := dependencies.newUpdater(dependencies.currentVersion)
	if err != nil {
		return nil, nil, errors.Join(err, closeStores())
	}
	service, err := dependencies.newApplication(app.Config{
		State:         stateStore,
		Secrets:       secretStore,
		SecretBackend: backend,
		Fetcher:       dependencies.newFetcher(),
		Latency:       latencyChecker,
		Daemon:        daemonClient,
		Updater:       updater,
	})
	if err != nil {
		return nil, nil, errors.Join(err, closeStores())
	}
	return service, closeStores, nil
}

func validateApplicationDependencies(dependencies applicationDependencies) error {
	if dependencies.userDataDir == nil || dependencies.userConfigDir == nil || dependencies.getenv == nil ||
		dependencies.openState == nil || dependencies.openSecrets == nil || dependencies.newFetcher == nil ||
		dependencies.newLatency == nil || dependencies.newDaemon == nil || dependencies.newUpdater == nil ||
		dependencies.currentVersion == "" || dependencies.newApplication == nil {
		return errInvalidClientConfiguration
	}
	return nil
}

func resolveUserDataDirectory(goos string, getenv func(string) string, userHomeDir func() (string, error)) (string, error) {
	if getenv == nil || userHomeDir == nil {
		return "", errInvalidClientConfiguration
	}
	if goos == "linux" {
		if directory := getenv("XDG_DATA_HOME"); directory != "" {
			if !validAbsolutePath(directory) {
				return "", errInvalidClientConfiguration
			}
			return directory, nil
		}
	}
	home, err := userHomeDir()
	if err != nil || !validAbsolutePath(home) {
		return "", errInvalidClientConfiguration
	}
	switch goos {
	case "linux":
		return filepath.Join(home, ".local", "share"), nil
	case "darwin":
		return filepath.Join(home, "Library", "Application Support"), nil
	default:
		return "", errInvalidClientConfiguration
	}
}

func applicationDirectory(resolve func() (string, error)) (string, error) {
	base, err := resolve()
	if err != nil || !validAbsolutePath(base) {
		return "", errInvalidClientConfiguration
	}
	return filepath.Join(base, applicationDirectoryName), nil
}

func resolveSocketPath(getenv func(string) string) (string, error) {
	return resolveSocketPathForOS(runtime.GOOS, getenv)
}

func resolveSocketPathForOS(goos string, getenv func(string) string) (string, error) {
	if getenv == nil {
		return "", errInvalidClientConfiguration
	}
	path := getenv(socketEnvironmentVariable)
	if path == "" {
		switch goos {
		case "linux":
			path = defaultLinuxSocketPath
		case "darwin":
			path = defaultDarwinSocketPath
		default:
			return "", errInvalidClientConfiguration
		}
	}
	if !validAbsolutePath(path) {
		return "", errInvalidClientConfiguration
	}
	return path, nil
}

func validAbsolutePath(path string) bool {
	if path == "" || !filepath.IsAbs(path) || filepath.Clean(path) != path || !utf8.ValidString(path) {
		return false
	}
	for _, character := range path {
		if unicode.IsControl(character) {
			return false
		}
	}
	return true
}

func newTUIRunner(input io.Reader, dependencies applicationDependencies, terminalCheck tui.TerminalCheck, launch tuiLauncher) cli.TUIRunner {
	return func(ctx context.Context, stdout, stderr io.Writer) error {
		if input == nil || launch == nil {
			return errInvalidClientConfiguration
		}
		return launch(ctx, tui.RunConfig{
			OpenService: func(ctx context.Context) (tui.Application, func() error, error) {
				service, closeService, err := openApplicationService(ctx, dependencies)
				return service, closeService, err
			},
			Input:       input,
			Output:      stdout,
			ErrorOutput: stderr,
			IsTerminal:  terminalCheck,
		})
	}
}

func defaultTUIRunner(ctx context.Context, stdout, stderr io.Writer) error {
	return newTUIRunner(os.Stdin, defaultApplicationDependencies(), nil, tui.Run)(ctx, stdout, stderr)
}

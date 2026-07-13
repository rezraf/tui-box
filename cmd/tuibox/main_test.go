//go:build darwin || linux

package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/rezraf/tui-box/internal/app"
	"github.com/rezraf/tui-box/internal/cli"
	"github.com/rezraf/tui-box/internal/domain"
	"github.com/rezraf/tui-box/internal/latency"
	"github.com/rezraf/tui-box/internal/rpc"
	"github.com/rezraf/tui-box/internal/secrets"
	"github.com/rezraf/tui-box/internal/state"
	"github.com/rezraf/tui-box/internal/subscription"
	"github.com/rezraf/tui-box/internal/tui"
	"github.com/rezraf/tui-box/internal/update"
)

func TestRunKeepsHelpVersionCompletionUsageAndBareTUILazy(t *testing.T) {
	tests := []struct {
		name       string
		args       []string
		wantCode   int
		wantStdout string
		wantStderr string
		wantTUI    int
	}{
		{name: "help", args: []string{"--help"}, wantStdout: "Usage:"},
		{name: "version", args: []string{"version"}, wantStdout: "tuibox v0.1.0 (test-build)"},
		{name: "completion", args: []string{"completion", "bash"}, wantStdout: "bash completion"},
		{name: "usage error", args: []string{"connect", "endpoint", "--mode", "invalid", "--route", "global"}, wantCode: 2, wantStderr: "invalid command usage"},
		{name: "bare TUI", wantStdout: "placeholder TUI", wantTUI: 1},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			opened := 0
			tuiCalls := 0
			deps := runDependencies{
				openService: func(context.Context) (cli.Service, func() error, error) {
					opened++
					return nil, nil, errors.New("must not open")
				},
				runTUI: func(_ context.Context, stdout, _ io.Writer) error {
					tuiCalls++
					_, err := io.WriteString(stdout, "placeholder TUI\n")
					return err
				},
				version: "v0.1.0",
				build:   "test-build",
			}
			var stdout bytes.Buffer
			var stderr bytes.Buffer

			code := run(context.Background(), test.args, &stdout, &stderr, deps)
			if code != test.wantCode {
				t.Fatalf("exit code = %d, want %d; stderr=%q", code, test.wantCode, stderr.String())
			}
			if opened != 0 {
				t.Fatalf("service opens = %d, want 0", opened)
			}
			if tuiCalls != test.wantTUI {
				t.Fatalf("TUI calls = %d, want %d", tuiCalls, test.wantTUI)
			}
			if !strings.Contains(stdout.String(), test.wantStdout) {
				t.Fatalf("stdout = %q, want fragment %q", stdout.String(), test.wantStdout)
			}
			if !strings.Contains(stderr.String(), test.wantStderr) {
				t.Fatalf("stderr = %q, want fragment %q", stderr.String(), test.wantStderr)
			}
		})
	}
}

func TestRunInternalUpdateUsesPrivilegedUpdaterWithoutOpeningApplication(t *testing.T) {
	opened := 0
	var appliedVersion string
	deps := runDependencies{
		openService: func(context.Context) (cli.Service, func() error, error) {
			opened++
			return nil, nil, errors.New("must not open")
		},
		runTUI:  defaultTUIRunner,
		version: "v0.1.0",
		build:   "test-build",
		applyInstalled: func(_ context.Context, requestedVersion string) error {
			appliedVersion = requestedVersion
			return nil
		},
	}
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	code := run(context.Background(), []string{update.InternalApplyArgument, "v0.2.0"}, &stdout, &stderr, deps)
	if code != 0 || stdout.Len() != 0 || stderr.Len() != 0 {
		t.Fatalf("run internal update = code %d stdout %q stderr %q", code, stdout.String(), stderr.String())
	}
	if opened != 0 || appliedVersion != "v0.2.0" {
		t.Fatalf("open calls = %d, applied version = %q", opened, appliedVersion)
	}
}

func TestRunInternalUpdateRejectsMalformedOrFailedRequestsWithoutDetails(t *testing.T) {
	secret := "https://release.example/private-token"
	for _, test := range []struct {
		name string
		args []string
		fail bool
	}{
		{name: "missing version", args: []string{update.InternalApplyArgument}},
		{name: "extra argument", args: []string{update.InternalApplyArgument, "v0.2.0", "extra"}},
		{name: "apply failure", args: []string{update.InternalApplyArgument, "v0.2.0"}, fail: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			deps := runDependencies{
				openService: func(context.Context) (cli.Service, func() error, error) { return nil, nil, errors.New("must not open") },
				runTUI:      defaultTUIRunner,
				version:     "v0.1.0",
				build:       "test-build",
				applyInstalled: func(context.Context, string) error {
					if test.fail {
						return errors.New(secret)
					}
					return nil
				},
			}
			var stdout bytes.Buffer
			var stderr bytes.Buffer
			if code := run(context.Background(), test.args, &stdout, &stderr, deps); code != 1 {
				t.Fatalf("exit code = %d, want 1", code)
			}
			combined := stdout.String() + stderr.String()
			if !strings.Contains(stderr.String(), "update failed") || strings.Contains(combined, secret) || strings.Contains(combined, "private-token") {
				t.Fatalf("unsafe output: %q", combined)
			}
		})
	}
}

func TestTUIRunnerDelegatesToRealRunnerWithLazyApplicationOpener(t *testing.T) {
	var events []string
	application := &noopService{}
	deps := validApplicationDependencies(&events)
	deps.newApplication = func(app.Config) (cli.Service, error) {
		events = append(events, "new-application")
		return application, nil
	}
	input := strings.NewReader("q")
	terminalCheck := func(io.Reader, io.Writer) bool { return true }
	launcherCalls := 0
	launcher := func(ctx context.Context, config tui.RunConfig) error {
		launcherCalls++
		if config.Input != input || config.Output == nil || config.ErrorOutput == nil || config.IsTerminal == nil {
			t.Fatalf("incomplete TUI config: %#v", config)
		}
		service, closeService, err := config.OpenService(ctx)
		if err != nil {
			t.Fatalf("open TUI service: %v", err)
		}
		if service != application {
			t.Fatalf("service = %T, want application", service)
		}
		return closeService()
	}
	runner := newTUIRunner(input, deps, terminalCheck, launcher)
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	if err := runner(context.Background(), &stdout, &stderr); err != nil {
		t.Fatalf("run TUI: %v", err)
	}
	if launcherCalls != 1 {
		t.Fatalf("launcher calls = %d, want 1", launcherCalls)
	}
	want := []string{"new-application", "close-secrets", "close-state"}
	if !reflect.DeepEqual(events, want) {
		t.Fatalf("events = %v, want %v", events, want)
	}
}

func TestRunMapsHostileServiceOpeningFailureToSafeOperationalError(t *testing.T) {
	secret := "https://provider.example/private-token endpoint-password"
	deps := runDependencies{
		openService: func(context.Context) (cli.Service, func() error, error) {
			return nil, nil, errors.New(secret)
		},
		runTUI:  defaultTUIRunner,
		version: "dev",
		build:   "unknown",
	}
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	code := run(context.Background(), []string{"status"}, &stdout, &stderr, deps)
	if code != 1 {
		t.Fatalf("exit code = %d, want 1", code)
	}
	combined := stdout.String() + stderr.String()
	if !strings.Contains(stderr.String(), "operation failed") {
		t.Fatalf("stderr = %q", stderr.String())
	}
	for _, forbidden := range []string{"https://", "provider.example", "private-token", "endpoint-password"} {
		if strings.Contains(combined, forbidden) {
			t.Fatalf("output leaked %q: %q", forbidden, combined)
		}
	}
}

func TestResolveUserDataDirectoryUsesPlatformDataLocation(t *testing.T) {
	tests := []struct {
		name  string
		goos  string
		xdg   string
		home  string
		want  string
		isErr bool
	}{
		{name: "linux XDG", goos: "linux", xdg: "/xdg/data", home: "/home/user", want: "/xdg/data"},
		{name: "linux default", goos: "linux", home: "/home/user", want: "/home/user/.local/share"},
		{name: "macOS", goos: "darwin", home: "/Users/user", want: "/Users/user/Library/Application Support"},
		{name: "unsupported", goos: "windows", home: "C:/Users/user", isErr: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := resolveUserDataDirectory(test.goos, func(key string) string {
				if key == "XDG_DATA_HOME" {
					return test.xdg
				}
				return ""
			}, func() (string, error) { return test.home, nil })
			if test.isErr {
				if !errors.Is(err, errInvalidClientConfiguration) {
					t.Fatalf("error = %v", err)
				}
				return
			}
			if err != nil || got != test.want {
				t.Fatalf("directory = %q, %v; want %q", got, err, test.want)
			}
		})
	}
}

func TestResolveSocketPathUsesCanonicalPlatformDefaultAndValidatesOverride(t *testing.T) {
	for _, test := range []struct {
		goos string
		want string
	}{
		{goos: "linux", want: "/run/tuibox/tuiboxd.sock"},
		{goos: "darwin", want: "/private/var/run/tuibox/tuiboxd.sock"},
	} {
		got, err := resolveSocketPathForOS(test.goos, func(string) string { return "" })
		if err != nil || got != test.want {
			t.Fatalf("default %s socket = %q, %v; want %q", test.goos, got, err, test.want)
		}
	}
	if got, err := resolveSocketPath(func(string) string { return "/tmp/tuibox.sock" }); err != nil || got != "/tmp/tuibox.sock" {
		t.Fatalf("override socket = %q, %v", got, err)
	}

	for _, invalid := range []string{"relative.sock", "/tmp/../tmp/tuibox.sock", "/tmp/socket\nname"} {
		t.Run(invalid, func(t *testing.T) {
			if _, err := resolveSocketPath(func(string) string { return invalid }); !errors.Is(err, errInvalidClientConfiguration) {
				t.Fatalf("error = %v, want invalid configuration", err)
			}
		})
	}
}

func TestOpenApplicationServiceWiresBoundedDependenciesAndClosesSecretsBeforeState(t *testing.T) {
	var events []string
	stateStore := &fakeStateStore{close: func() error { events = append(events, "close-state"); return nil }}
	secretStore := &fakeSecretStore{close: func() error { events = append(events, "close-secrets"); return nil }}
	application := &noopService{}
	updater := &fakeUpdater{}
	var captured app.Config
	var statePath, secretsPath, socketPath string
	deps := applicationDependencies{
		userDataDir:   func() (string, error) { return "/user/data", nil },
		userConfigDir: func() (string, error) { return "/user/config", nil },
		getenv: func(key string) string {
			if key == socketEnvironmentVariable {
				return "/tmp/custom-tuibox.sock"
			}
			return ""
		},
		openState: func(path string) (stateStoreCloser, error) {
			statePath = path
			return stateStore, nil
		},
		openSecrets: func(path string) (secrets.Store, secrets.BackendInfo, error) {
			secretsPath = path
			return secretStore, secrets.BackendInfo{Name: secrets.BackendFile, Warning: "fallback"}, nil
		},
		newFetcher: func() app.SubscriptionFetcher { return &fakeFetcher{} },
		newLatency: func() (app.LatencyChecker, error) { return &fakeLatency{}, nil },
		newDaemon: func(path string) (app.DaemonClient, error) {
			socketPath = path
			return &fakeDaemon{}, nil
		},
		currentVersion: "v0.1.0",
		newUpdater: func(currentVersion string) (app.Updater, error) {
			if currentVersion != "v0.1.0" {
				t.Fatalf("updater current version = %q", currentVersion)
			}
			return updater, nil
		},
		newApplication: func(config app.Config) (cli.Service, error) {
			captured = config
			return application, nil
		},
	}

	service, closeService, err := openApplicationService(context.Background(), deps)
	if err != nil {
		t.Fatalf("openApplicationService: %v", err)
	}
	if service != application {
		t.Fatalf("service = %T, want application", service)
	}
	if statePath != filepath.Join("/user/data", "tuibox") || secretsPath != filepath.Join("/user/config", "tuibox") {
		t.Fatalf("paths = state %q secrets %q", statePath, secretsPath)
	}
	if socketPath != "/tmp/custom-tuibox.sock" {
		t.Fatalf("daemon socket = %q", socketPath)
	}
	if captured.State != stateStore || captured.Secrets != secretStore || captured.Fetcher == nil || captured.Latency == nil || captured.Daemon == nil {
		t.Fatalf("incomplete app wiring: %#v", captured)
	}
	if captured.Updater != updater {
		t.Fatalf("updater = %T, want wired updater", captured.Updater)
	}
	if captured.SecretBackend.Name != secrets.BackendFile || captured.SecretBackend.Warning != "fallback" {
		t.Fatalf("secret backend = %#v", captured.SecretBackend)
	}
	if err := closeService(); err != nil {
		t.Fatalf("close service: %v", err)
	}
	if want := []string{"close-secrets", "close-state"}; !reflect.DeepEqual(events, want) {
		t.Fatalf("close order = %v, want %v", events, want)
	}
}

func TestOpenApplicationServiceClosesOpenedResourcesOnEveryFailurePath(t *testing.T) {
	tests := []struct {
		name string
		deps func(*[]string) applicationDependencies
	}{
		{
			name: "secret open failure",
			deps: func(events *[]string) applicationDependencies {
				deps := validApplicationDependencies(events)
				deps.openSecrets = func(string) (secrets.Store, secrets.BackendInfo, error) {
					return nil, secrets.BackendInfo{}, errors.New("secret open failed")
				}
				return deps
			},
		},
		{
			name: "latency construction failure",
			deps: func(events *[]string) applicationDependencies {
				deps := validApplicationDependencies(events)
				deps.newLatency = func() (app.LatencyChecker, error) { return nil, errors.New("latency failed") }
				return deps
			},
		},
		{
			name: "daemon construction failure",
			deps: func(events *[]string) applicationDependencies {
				deps := validApplicationDependencies(events)
				deps.newDaemon = func(string) (app.DaemonClient, error) { return nil, errors.New("daemon failed") }
				return deps
			},
		},
		{
			name: "updater construction failure",
			deps: func(events *[]string) applicationDependencies {
				deps := validApplicationDependencies(events)
				deps.newUpdater = func(string) (app.Updater, error) { return nil, errors.New("updater failed") }
				return deps
			},
		},
		{
			name: "application construction failure",
			deps: func(events *[]string) applicationDependencies {
				deps := validApplicationDependencies(events)
				deps.newApplication = func(app.Config) (cli.Service, error) { return nil, errors.New("app failed") }
				return deps
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var events []string
			service, closeService, err := openApplicationService(context.Background(), test.deps(&events))
			if err == nil || service != nil || closeService != nil {
				t.Fatalf("result = service %T, close set %t, error %v; want nil, false, error", service, closeService != nil, err)
			}
			want := []string{"close-state"}
			if test.name != "secret open failure" {
				want = []string{"close-secrets", "close-state"}
			}
			if !reflect.DeepEqual(events, want) {
				t.Fatalf("close order = %v, want %v", events, want)
			}
		})
	}
}

func TestOpenApplicationServiceClosesResourcesReturnedWithErrors(t *testing.T) {
	tests := []struct {
		name string
		deps func(*[]string) applicationDependencies
		want []string
	}{
		{
			name: "state returned with error",
			deps: func(events *[]string) applicationDependencies {
				deps := validApplicationDependencies(events)
				deps.openState = func(string) (stateStoreCloser, error) {
					return &fakeStateStore{close: func() error { *events = append(*events, "close-state"); return nil }}, errors.New("state open failed")
				}
				return deps
			},
			want: []string{"close-state"},
		},
		{
			name: "secret store returned with error",
			deps: func(events *[]string) applicationDependencies {
				deps := validApplicationDependencies(events)
				deps.openSecrets = func(string) (secrets.Store, secrets.BackendInfo, error) {
					return &fakeSecretStore{close: func() error { *events = append(*events, "close-secrets"); return nil }}, secrets.BackendInfo{}, errors.New("secret open failed")
				}
				return deps
			},
			want: []string{"close-secrets", "close-state"},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var events []string
			service, closeService, err := openApplicationService(context.Background(), test.deps(&events))
			if err == nil || service != nil || closeService != nil {
				t.Fatalf("result = service %T, close set %t, error %v; want nil, false, error", service, closeService != nil, err)
			}
			if !reflect.DeepEqual(events, test.want) {
				t.Fatalf("close order = %v, want %v", events, test.want)
			}
		})
	}
}

func TestOpenApplicationServiceRejectsNilStoresWithoutPanicking(t *testing.T) {
	tests := []struct {
		name string
		deps func(*[]string) applicationDependencies
		want []string
	}{
		{
			name: "nil state store",
			deps: func(events *[]string) applicationDependencies {
				deps := validApplicationDependencies(events)
				deps.openState = func(string) (stateStoreCloser, error) { return nil, nil }
				return deps
			},
		},
		{
			name: "nil secret store",
			deps: func(events *[]string) applicationDependencies {
				deps := validApplicationDependencies(events)
				deps.openSecrets = func(string) (secrets.Store, secrets.BackendInfo, error) {
					return nil, secrets.BackendInfo{}, nil
				}
				return deps
			},
			want: []string{"close-state"},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var events []string
			service, closeService, err, panicValue := openApplicationServiceSafely(test.deps(&events))
			if panicValue != nil {
				t.Fatalf("openApplicationService panicked: %v", panicValue)
			}
			if !errors.Is(err, errInvalidClientConfiguration) || service != nil || closeService != nil {
				t.Fatalf("result = service %T, close set %t, error %v; want nil, false, invalid configuration", service, closeService != nil, err)
			}
			if !reflect.DeepEqual(events, test.want) {
				t.Fatalf("close order = %v, want %v", events, test.want)
			}
		})
	}
}

func openApplicationServiceSafely(dependencies applicationDependencies) (service cli.Service, closeService func() error, err error, panicValue any) {
	defer func() {
		panicValue = recover()
	}()
	service, closeService, err = openApplicationService(context.Background(), dependencies)
	return service, closeService, err, nil
}

func validApplicationDependencies(events *[]string) applicationDependencies {
	return applicationDependencies{
		userDataDir:   func() (string, error) { return "/data", nil },
		userConfigDir: func() (string, error) { return "/config", nil },
		getenv:        func(string) string { return "" },
		openState: func(string) (stateStoreCloser, error) {
			return &fakeStateStore{close: func() error { *events = append(*events, "close-state"); return nil }}, nil
		},
		openSecrets: func(string) (secrets.Store, secrets.BackendInfo, error) {
			return &fakeSecretStore{close: func() error { *events = append(*events, "close-secrets"); return nil }}, secrets.BackendInfo{}, nil
		},
		newFetcher:     func() app.SubscriptionFetcher { return &fakeFetcher{} },
		newLatency:     func() (app.LatencyChecker, error) { return &fakeLatency{}, nil },
		newDaemon:      func(string) (app.DaemonClient, error) { return &fakeDaemon{}, nil },
		currentVersion: "v0.1.0",
		newUpdater:     func(string) (app.Updater, error) { return &fakeUpdater{}, nil },
		newApplication: func(app.Config) (cli.Service, error) {
			return &noopService{}, nil
		},
	}
}

type fakeStateStore struct {
	close func() error
}

func (*fakeStateStore) LoadContext(context.Context) (state.Snapshot, error) {
	return state.Snapshot{SchemaVersion: state.CurrentSchemaVersion}, nil
}

func (*fakeStateStore) UpdateContext(context.Context, func(*state.Snapshot) error) error { return nil }
func (store *fakeStateStore) Close() error                                               { return store.close() }

type fakeSecretStore struct {
	close func() error
}

func (*fakeSecretStore) Get(context.Context, string) (string, error) {
	return "", secrets.ErrSecretNotFound
}
func (*fakeSecretStore) Set(context.Context, string, string) error { return nil }
func (*fakeSecretStore) Delete(context.Context, string) error      { return nil }
func (store *fakeSecretStore) Close() error                        { return store.close() }

type fakeFetcher struct{}

func (*fakeFetcher) Fetch(context.Context, string) ([]byte, error) { return nil, nil }

type fakeLatency struct{}

func (*fakeLatency) Check(context.Context, []domain.Endpoint) []latency.Result { return nil }

type fakeDaemon struct{}

func (*fakeDaemon) Connect(context.Context, rpc.ConnectPayload) (rpc.SessionStatus, error) {
	return rpc.SessionStatus{}, nil
}
func (*fakeDaemon) Disconnect(context.Context) (rpc.SessionStatus, error) {
	return rpc.SessionStatus{}, nil
}
func (*fakeDaemon) Status(context.Context) (rpc.SessionStatus, error) {
	return rpc.SessionStatus{}, nil
}
func (*fakeDaemon) Health(context.Context) error { return nil }

type fakeUpdater struct{}

func (*fakeUpdater) Check(context.Context) (app.UpdateInfo, error) {
	return app.UpdateInfo{CurrentVersion: "v0.1.0", LatestVersion: "v0.1.0"}, nil
}
func (*fakeUpdater) Apply(context.Context, app.UpdateInfo) error { return nil }

type noopService struct{}

func (*noopService) AddSubscription(context.Context, string, string) (app.SubscriptionView, []subscription.Warning, error) {
	return app.SubscriptionView{}, nil, nil
}
func (*noopService) ListSubscriptions(context.Context) ([]app.SubscriptionView, error) {
	return nil, nil
}
func (*noopService) UpdateSubscriptions(context.Context, string) ([]app.RefreshResult, error) {
	return nil, nil
}
func (*noopService) RemoveSubscription(context.Context, string) error      { return nil }
func (*noopService) ListServers(context.Context) ([]app.ServerView, error) { return nil, nil }
func (*noopService) CheckLatency(context.Context, string, bool) ([]latency.Result, error) {
	return nil, nil
}
func (*noopService) Connect(context.Context, string, domain.ConnectionMode, domain.RouteMode) (rpc.SessionStatus, error) {
	return rpc.SessionStatus{}, nil
}
func (*noopService) Disconnect(context.Context) (rpc.SessionStatus, error) {
	return rpc.SessionStatus{}, nil
}
func (*noopService) Status(context.Context) (rpc.SessionStatus, error) {
	return rpc.SessionStatus{}, nil
}
func (*noopService) SetTelemetry(context.Context, bool) error       { return nil }
func (*noopService) TelemetryEnabled(context.Context) (bool, error) { return false, nil }
func (*noopService) Doctor(context.Context) []app.Diagnostic        { return nil }
func (*noopService) CheckUpdate(context.Context) (app.UpdateInfo, error) {
	return app.UpdateInfo{}, nil
}
func (*noopService) ApplyUpdate(context.Context, app.UpdateInfo) error { return nil }

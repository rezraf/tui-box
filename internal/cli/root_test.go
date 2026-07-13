package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/rezraf/tui-box/internal/app"
	"github.com/rezraf/tui-box/internal/domain"
	"github.com/rezraf/tui-box/internal/latency"
	"github.com/rezraf/tui-box/internal/rpc"
	"github.com/rezraf/tui-box/internal/subscription"
)

func TestCommandDispatchesFrozenSurface(t *testing.T) {
	tests := []struct {
		name string
		args []string
		want string
	}{
		{name: "subscription add", args: []string{"subscription", "add", "Primary", "https://provider.example/token"}, want: "add:Primary:https://provider.example/token"},
		{name: "subscription list", args: []string{"subscription", "list"}, want: "list-subscriptions"},
		{name: "subscription update all", args: []string{"subscription", "update"}, want: "update-subscriptions:"},
		{name: "subscription update one", args: []string{"subscription", "update", "subscription-id"}, want: "update-subscriptions:subscription-id"},
		{name: "subscription remove", args: []string{"subscription", "remove", "subscription-id"}, want: "remove:subscription-id"},
		{name: "server list", args: []string{"server", "list"}, want: "list-servers"},
		{name: "server latency one", args: []string{"server", "latency", "endpoint-id"}, want: "latency:endpoint-id:false"},
		{name: "server latency all", args: []string{"server", "latency", "--all"}, want: "latency::true"},
		{name: "connect", args: []string{"connect", "endpoint-id", "--mode", "tun", "--route", "rule"}, want: "connect:endpoint-id:tun:rule"},
		{name: "disconnect", args: []string{"disconnect"}, want: "disconnect"},
		{name: "status", args: []string{"status"}, want: "status"},
		{name: "telemetry enable", args: []string{"telemetry", "enable"}, want: "telemetry:true"},
		{name: "telemetry disable", args: []string{"telemetry", "disable"}, want: "telemetry:false"},
		{name: "telemetry status", args: []string{"telemetry", "status"}, want: "telemetry-status"},
		{name: "doctor", args: []string{"doctor"}, want: "doctor"},
		{name: "update check", args: []string{"update", "--check"}, want: "check-update"},
		{name: "update apply", args: []string{"update"}, want: "check-update,apply-update:v0.2.0"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			service := newFakeService()
			opener := &fakeOpener{service: service}
			stdout, stderr, err := execute(t, opener, nil, test.args...)
			if err != nil {
				t.Fatalf("execute: %v (stderr=%q)", err, stderr)
			}
			if opener.calls != 1 || opener.closes != 1 {
				t.Fatalf("service lifecycle = open %d close %d, want 1/1", opener.calls, opener.closes)
			}
			if actual := strings.Join(service.calls, ","); actual != test.want {
				t.Fatalf("dispatch = %q, want %q", actual, test.want)
			}
			if stdout == "" {
				t.Fatal("normal command produced no stdout")
			}
			if stderr != "" {
				t.Fatalf("normal command wrote stderr: %q", stderr)
			}
		})
	}
}

func TestCLIJSONEscapesTerminalUnsafeUnicodeAtTheOutputSink(t *testing.T) {
	service := newFakeService()
	service.servers = []app.ServerView{{
		ID:             "endpoint-id",
		SubscriptionID: "subscription-id",
		Name:           "Safe" + string(rune(0x202e)) + "txt\x1b]52;c;payload\a",
		Protocol:       domain.ProtocolVLESS,
	}}
	stdout, stderr, err := execute(t, &fakeOpener{service: service}, nil, "server", "list")
	if err != nil || stderr != "" {
		t.Fatalf("server list = %v stderr=%q", err, stderr)
	}
	if strings.ContainsRune(stdout, rune(0x202e)) || strings.Contains(stdout, "\x1b") || strings.Contains(stdout, "\a") {
		t.Fatalf("terminal-unsafe text reached CLI output: %q", stdout)
	}
	if !json.Valid([]byte(strings.TrimSpace(stdout))) {
		t.Fatalf("sanitized CLI output is not valid JSON: %q", stdout)
	}
}

func TestInvalidArgumentsAndEnumsFailBeforeServiceOpen(t *testing.T) {
	tests := []struct {
		name string
		args []string
	}{
		{name: "root positional", args: []string{"unexpected"}},
		{name: "subscription add missing URL", args: []string{"subscription", "add", "name"}},
		{name: "subscription list extra", args: []string{"subscription", "list", "extra"}},
		{name: "subscription update extra", args: []string{"subscription", "update", "one", "two"}},
		{name: "subscription remove missing", args: []string{"subscription", "remove"}},
		{name: "server latency missing selector", args: []string{"server", "latency"}},
		{name: "server latency conflicting selector", args: []string{"server", "latency", "endpoint", "--all"}},
		{name: "connect missing mode", args: []string{"connect", "endpoint", "--route", "global"}},
		{name: "connect missing route", args: []string{"connect", "endpoint", "--mode", "proxy"}},
		{name: "connect invalid mode", args: []string{"connect", "endpoint", "--mode", "wireguard", "--route", "global"}},
		{name: "connect invalid route", args: []string{"connect", "endpoint", "--mode", "proxy", "--route", "private"}},
		{name: "disconnect extra", args: []string{"disconnect", "extra"}},
		{name: "telemetry unknown action", args: []string{"telemetry", "maybe"}},
		{name: "doctor extra", args: []string{"doctor", "extra"}},
		{name: "update extra", args: []string{"update", "extra"}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			opener := &fakeOpener{service: newFakeService()}
			_, _, err := execute(t, opener, nil, test.args...)
			if err == nil || !IsUsageError(err) {
				t.Fatalf("error = %v, want usage error", err)
			}
			if code := ExitCode(err); code != 2 {
				t.Fatalf("exit code = %d, want 2", code)
			}
			if opener.calls != 0 || opener.closes != 0 {
				t.Fatalf("invalid command opened service: open=%d close=%d", opener.calls, opener.closes)
			}
		})
	}
}

func TestHelpVersionCompletionAndBareTUIAvoidServiceOpen(t *testing.T) {
	tests := []struct {
		name       string
		args       []string
		tui        *fakeTUI
		wantOutput string
	}{
		{name: "root help", args: []string{"--help"}, wantOutput: "Usage:"},
		{name: "nested help", args: []string{"subscription", "add", "--help"}, wantOutput: "tuibox subscription add"},
		{name: "version", args: []string{"version"}, wantOutput: "tuibox v0.1.0 (test-build)"},
		{name: "completion", args: []string{"completion", "bash"}, wantOutput: "bash completion"},
		{name: "bare TUI", tui: &fakeTUI{output: "TUI placeholder\n"}, wantOutput: "TUI placeholder"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			opener := &fakeOpener{service: newFakeService()}
			stdout, stderr, err := execute(t, opener, test.tui, test.args...)
			if err != nil {
				t.Fatalf("execute: %v", err)
			}
			if opener.calls != 0 || opener.closes != 0 {
				t.Fatalf("side-effect-free command opened service: open=%d close=%d", opener.calls, opener.closes)
			}
			if !strings.Contains(stdout, test.wantOutput) {
				t.Fatalf("stdout = %q, want fragment %q", stdout, test.wantOutput)
			}
			if stderr != "" {
				t.Fatalf("stderr = %q", stderr)
			}
			if test.tui != nil && test.tui.calls != 1 {
				t.Fatalf("TUI calls = %d, want 1", test.tui.calls)
			}
		})
	}
}

func TestMalformedServiceOpenStillClosesAcquiredResources(t *testing.T) {
	opener := &fakeOpener{}
	_, _, err := execute(t, opener, nil, "status")
	if !errors.Is(err, ErrOperationFailed) {
		t.Fatalf("error = %v, want operation failed", err)
	}
	if opener.calls != 1 || opener.closes != 1 {
		t.Fatalf("service lifecycle = open %d close %d, want 1/1", opener.calls, opener.closes)
	}
}

func TestOperationalFailuresAreStableAndSecretFree(t *testing.T) {
	secret := "https://provider.example/private-token endpoint-password"
	service := newFakeService()
	service.err = errors.New(secret)
	opener := &fakeOpener{service: service}

	stdout, stderr, err := execute(t, opener, nil, "status")
	if err == nil {
		t.Fatal("expected operational failure")
	}
	if ExitCode(err) != 1 {
		t.Fatalf("exit code = %d, want 1", ExitCode(err))
	}
	combined := stdout + stderr + ErrorMessage(err)
	for _, forbidden := range []string{"https://", "provider.example", "private-token", "endpoint-password"} {
		if strings.Contains(combined, forbidden) {
			t.Fatalf("output leaked %q: %q", forbidden, combined)
		}
	}
	if ErrorMessage(err) != ErrOperationFailed.Error() {
		t.Fatalf("error message = %q, want %q", ErrorMessage(err), ErrOperationFailed)
	}
	if opener.calls != 1 || opener.closes != 1 {
		t.Fatalf("service lifecycle = open %d close %d, want 1/1", opener.calls, opener.closes)
	}
}

func TestUpdateChecksWithoutApplyingAndAppliesOnlyAvailableUpdate(t *testing.T) {
	t.Run("check only", func(t *testing.T) {
		service := newFakeService()
		opener := &fakeOpener{service: service}
		stdout, _, err := execute(t, opener, nil, "update", "--check")
		if err != nil {
			t.Fatalf("update --check: %v", err)
		}
		if got := strings.Join(service.calls, ","); got != "check-update" {
			t.Fatalf("calls = %q", got)
		}
		if !strings.Contains(stdout, `"available":true`) || !strings.Contains(stdout, `"latest_version":"v0.2.0"`) || !strings.Contains(stdout, `"applied":false`) {
			t.Fatalf("stdout = %q", stdout)
		}
		if strings.Contains(stdout, `"daemon_restart_required":true`) {
			t.Fatalf("check-only output claimed a daemon restart requirement: %q", stdout)
		}
	})

	t.Run("successful apply is explicit", func(t *testing.T) {
		service := newFakeService()
		opener := &fakeOpener{service: service}
		stdout, _, err := execute(t, opener, nil, "update")
		if err != nil {
			t.Fatalf("update: %v", err)
		}
		if !strings.Contains(stdout, `"applied":true`) || !strings.Contains(stdout, `"daemon_restart_required":true`) {
			t.Fatalf("stdout = %q", stdout)
		}
	})

	t.Run("no update available", func(t *testing.T) {
		service := newFakeService()
		service.updateInfo = app.UpdateInfo{CurrentVersion: "v0.1.0", LatestVersion: "v0.1.0", Available: false}
		opener := &fakeOpener{service: service}
		if _, _, err := execute(t, opener, nil, "update"); err != nil {
			t.Fatalf("update: %v", err)
		}
		if got := strings.Join(service.calls, ","); got != "check-update" {
			t.Fatalf("calls = %q, update must not apply", got)
		}
	})
}

func TestDoctorPrintsDiagnosticsAndFailsWhenAnErrorIsReported(t *testing.T) {
	service := newFakeService()
	service.diagnostics = []app.Diagnostic{
		{Code: "state_ready", Severity: app.DiagnosticInfo, Message: "state store is ready"},
		{Code: "daemon_unavailable", Severity: app.DiagnosticError, Message: "daemon is unavailable"},
	}
	opener := &fakeOpener{service: service}

	stdout, stderr, err := execute(t, opener, nil, "doctor")
	if !errors.Is(err, ErrDoctorFailed) || ExitCode(err) != 1 {
		t.Fatalf("doctor error = %v, exit=%d", err, ExitCode(err))
	}
	if !strings.Contains(stdout, `"code":"state_ready"`) || !strings.Contains(stdout, `"code":"daemon_unavailable"`) {
		t.Fatalf("stdout = %q", stdout)
	}
	if stderr != "" {
		t.Fatalf("stderr = %q", stderr)
	}
}

func TestKnownApplicationErrorsRemainStable(t *testing.T) {
	service := newFakeService()
	service.err = app.ErrSubscriptionNotFound
	opener := &fakeOpener{service: service}

	_, _, err := execute(t, opener, nil, "subscription", "remove", "missing")
	if !errors.Is(err, app.ErrSubscriptionNotFound) {
		t.Fatalf("error = %v, want subscription not found", err)
	}
	if ErrorMessage(err) != app.ErrSubscriptionNotFound.Error() {
		t.Fatalf("message = %q", ErrorMessage(err))
	}
}

func execute(t *testing.T, opener *fakeOpener, tui *fakeTUI, args ...string) (string, string, error) {
	t.Helper()
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	if tui == nil {
		tui = &fakeTUI{output: "TUI placeholder\n"}
	}
	command, err := New(Config{
		OpenService: opener.Open,
		RunTUI:      tui.Run,
		Version:     "v0.1.0",
		Build:       "test-build",
		Stdout:      &stdout,
		Stderr:      &stderr,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	command.SetArgs(args)
	err = command.ExecuteContext(context.Background())
	return stdout.String(), stderr.String(), err
}

type fakeOpener struct {
	service Service
	err     error
	calls   int
	closes  int
}

func (opener *fakeOpener) Open(context.Context) (Service, func() error, error) {
	opener.calls++
	if opener.err != nil {
		return nil, nil, opener.err
	}
	return opener.service, func() error {
		opener.closes++
		return nil
	}, nil
}

type fakeTUI struct {
	calls  int
	output string
	err    error
}

func (runner *fakeTUI) Run(_ context.Context, stdout, _ io.Writer) error {
	runner.calls++
	if _, err := io.WriteString(stdout, runner.output); err != nil {
		return err
	}
	return runner.err
}

type fakeService struct {
	calls       []string
	err         error
	updateInfo  app.UpdateInfo
	diagnostics []app.Diagnostic
	servers     []app.ServerView
}

func newFakeService() *fakeService {
	return &fakeService{
		updateInfo:  app.UpdateInfo{CurrentVersion: "v0.1.0", LatestVersion: "v0.2.0", Available: true},
		diagnostics: []app.Diagnostic{{Code: "state_ready", Severity: app.DiagnosticInfo, Message: "state store is ready"}},
	}
}

func (service *fakeService) AddSubscription(_ context.Context, name, url string) (app.SubscriptionView, []subscription.Warning, error) {
	service.calls = append(service.calls, "add:"+name+":"+url)
	return app.SubscriptionView{ID: "subscription-id", Name: name, Format: domain.SubscriptionFormatURIList, ServerCount: 1}, nil, service.err
}

func (service *fakeService) ListSubscriptions(context.Context) ([]app.SubscriptionView, error) {
	service.calls = append(service.calls, "list-subscriptions")
	return []app.SubscriptionView{{ID: "subscription-id", Name: "Primary", Format: domain.SubscriptionFormatURIList, ServerCount: 1}}, service.err
}

func (service *fakeService) UpdateSubscriptions(_ context.Context, id string) ([]app.RefreshResult, error) {
	service.calls = append(service.calls, "update-subscriptions:"+id)
	return []app.RefreshResult{{SubscriptionID: "subscription-id", Format: domain.SubscriptionFormatURIList, ServerCount: 1}}, service.err
}

func (service *fakeService) RemoveSubscription(_ context.Context, id string) error {
	service.calls = append(service.calls, "remove:"+id)
	return service.err
}

func (service *fakeService) ListServers(context.Context) ([]app.ServerView, error) {
	service.calls = append(service.calls, "list-servers")
	if service.servers != nil {
		return append([]app.ServerView(nil), service.servers...), service.err
	}
	return []app.ServerView{{ID: "endpoint-id", SubscriptionID: "subscription-id", Name: "Server", Protocol: domain.ProtocolVLESS}}, service.err
}

func (service *fakeService) CheckLatency(_ context.Context, id string, all bool) ([]latency.Result, error) {
	service.calls = append(service.calls, fmt.Sprintf("latency:%s:%t", id, all))
	return []latency.Result{{EndpointID: "endpoint-id", Protocol: domain.ProtocolVLESS, Duration: time.Millisecond, Status: latency.StatusSuccess}}, service.err
}

func (service *fakeService) Connect(_ context.Context, target string, mode domain.ConnectionMode, route domain.RouteMode) (rpc.SessionStatus, error) {
	service.calls = append(service.calls, fmt.Sprintf("connect:%s:%s:%s", target, mode, route))
	return rpc.SessionStatus{State: domain.ConnectionStatusConnected, Mode: mode, Route: route}, service.err
}

func (service *fakeService) Disconnect(context.Context) (rpc.SessionStatus, error) {
	service.calls = append(service.calls, "disconnect")
	return rpc.SessionStatus{State: domain.ConnectionStatusDisconnected}, service.err
}

func (service *fakeService) Status(context.Context) (rpc.SessionStatus, error) {
	service.calls = append(service.calls, "status")
	return rpc.SessionStatus{State: domain.ConnectionStatusConnected, Mode: domain.ConnectionModeProxy, Route: domain.RouteModeGlobal}, service.err
}

func (service *fakeService) SetTelemetry(_ context.Context, enabled bool) error {
	service.calls = append(service.calls, fmt.Sprintf("telemetry:%t", enabled))
	return service.err
}

func (service *fakeService) TelemetryEnabled(context.Context) (bool, error) {
	service.calls = append(service.calls, "telemetry-status")
	return true, service.err
}

func (service *fakeService) Doctor(context.Context) []app.Diagnostic {
	service.calls = append(service.calls, "doctor")
	return append([]app.Diagnostic(nil), service.diagnostics...)
}

func (service *fakeService) CheckUpdate(context.Context) (app.UpdateInfo, error) {
	service.calls = append(service.calls, "check-update")
	return service.updateInfo, service.err
}

func (service *fakeService) ApplyUpdate(_ context.Context, info app.UpdateInfo) error {
	service.calls = append(service.calls, "apply-update:"+info.LatestVersion)
	return service.err
}

//go:build darwin || linux

package daemon

import (
	"context"
	"errors"
	"os"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/rezraf/tui-box/internal/core"
	"github.com/rezraf/tui-box/internal/domain"
	"github.com/rezraf/tui-box/internal/rpc"
)

func TestQueuedExpiredRequestsNeverMutateState(t *testing.T) {
	operations := []struct {
		name string
		call func(*Service, context.Context) error
	}{
		{
			name: "connect",
			call: func(service *Service, ctx context.Context) error {
				_, err := service.Connect(ctx, connectionRequest(domain.ConnectionModeTUN, domain.RouteModeRule))
				return err
			},
		},
		{
			name: "disconnect",
			call: func(service *Service, ctx context.Context) error {
				_, err := service.Disconnect(ctx)
				return err
			},
		},
		{
			name: "status",
			call: func(service *Service, ctx context.Context) error {
				_, err := service.Status(ctx)
				return err
			},
		},
		{
			name: "health",
			call: func(service *Service, ctx context.Context) error {
				return service.Health(ctx)
			},
		},
	}

	for _, operation := range operations {
		operation := operation
		t.Run(operation.name, func(t *testing.T) {
			checkEntered := make(chan struct{})
			releaseCheck := make(chan struct{})
			runner := newFakeRunner()
			runner.check = func(call int, ctx context.Context, _ *core.PreparedConfig) error {
				if call != 1 {
					return nil
				}
				close(checkEntered)
				select {
				case <-releaseCheck:
					return nil
				case <-ctx.Done():
					return ctx.Err()
				}
			}
			service := newTestService(t, runner, 100*time.Millisecond)

			firstDone := make(chan error, 1)
			go func() {
				_, err := service.Connect(context.Background(), connectionRequest(domain.ConnectionModeTUN, domain.RouteModeGlobal))
				firstDone <- err
			}()
			select {
			case <-checkEntered:
			case <-time.After(time.Second):
				t.Fatal("first request did not acquire service serialization")
			}

			baseContext, cancel := context.WithCancel(context.Background())
			queuedContext := newObservedContext(baseContext)
			queuedDone := make(chan error, 1)
			go func() { queuedDone <- operation.call(service, queuedContext) }()
			select {
			case <-queuedContext.checked:
			case <-time.After(time.Second):
				close(releaseCheck)
				t.Fatal("queued request did not inspect its context")
			}
			cancel()
			close(releaseCheck)

			if err := <-firstDone; err != nil {
				t.Fatalf("first Connect() failed: %v", err)
			}
			if err := <-queuedDone; !errors.Is(err, context.Canceled) {
				t.Fatalf("queued %s error = %v, want context.Canceled", operation.name, err)
			}
			if got := runner.prepareCount(); got != 1 {
				t.Fatalf("Prepare calls after expired %s = %d, want 1", operation.name, got)
			}
			status := mustServiceStatus(t, service)
			if status.State != domain.ConnectionStatusConnected || status.Route != domain.RouteModeGlobal {
				t.Fatalf("status after expired %s = %#v, want original connected session", operation.name, status)
			}
		})
	}
}

func TestConnectChecksReplacementBeforeStoppingActiveProcess(t *testing.T) {
	oldProcess := newFakeProcess(true)
	newProcess := newFakeProcess(true)
	checkEntered := make(chan struct{})
	releaseCheck := make(chan struct{})
	runner := newFakeRunner()
	runner.start = func(call int, _ context.Context, _ *core.PreparedConfig) (core.Process, error) {
		if call == 1 {
			return oldProcess, nil
		}
		return newProcess, nil
	}
	runner.check = func(call int, ctx context.Context, _ *core.PreparedConfig) error {
		if call != 2 {
			return nil
		}
		close(checkEntered)
		select {
		case <-releaseCheck:
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	service := newTestService(t, runner, 100*time.Millisecond)
	if _, err := service.Connect(context.Background(), connectionRequest(domain.ConnectionModeTUN, domain.RouteModeGlobal)); err != nil {
		t.Fatal(err)
	}

	done := make(chan error, 1)
	go func() {
		_, err := service.Connect(context.Background(), connectionRequest(domain.ConnectionModeTUN, domain.RouteModeRule))
		done <- err
	}()
	select {
	case <-checkEntered:
	case <-time.After(time.Second):
		t.Fatal("replacement check was not reached")
	}
	if got := oldProcess.signalCount(); got != 0 {
		t.Fatalf("old process received %d signals before replacement check passed", got)
	}
	if got := runner.startCount(); got != 1 {
		t.Fatalf("Start calls before check completion = %d, want 1", got)
	}
	close(releaseCheck)
	if err := <-done; err != nil {
		t.Fatalf("replacement Connect() failed: %v", err)
	}
	if got := oldProcess.signalsSnapshot(); len(got) != 1 || got[0] != syscall.SIGTERM {
		t.Fatalf("old process signals = %v, want SIGTERM after check", got)
	}
	if got := runner.startCount(); got != 2 {
		t.Fatalf("Start calls = %d, want old and replacement", got)
	}
}

func TestCanceledReplacementAfterCheckPreservesOldSession(t *testing.T) {
	oldProcess := newFakeProcess(true)
	runner := newFakeRunner()
	runner.start = func(int, context.Context, *core.PreparedConfig) (core.Process, error) { return oldProcess, nil }
	ctx, cancel := context.WithCancel(context.Background())
	runner.check = func(call int, _ context.Context, _ *core.PreparedConfig) error {
		if call == 2 {
			cancel()
		}
		return nil
	}
	service := newTestService(t, runner, 50*time.Millisecond)
	if _, err := service.Connect(context.Background(), connectionRequest(domain.ConnectionModeTUN, domain.RouteModeGlobal)); err != nil {
		t.Fatal(err)
	}

	if _, err := service.Connect(ctx, connectionRequest(domain.ConnectionModeTUN, domain.RouteModeRule)); !errors.Is(err, context.Canceled) {
		t.Fatalf("replacement error = %v, want context.Canceled", err)
	}
	if oldProcess.signalCount() != 0 || runner.startCount() != 1 {
		t.Fatal("canceled replacement disturbed active process")
	}
	status := mustServiceStatus(t, service)
	if status.State != domain.ConnectionStatusConnected || status.Route != domain.RouteModeGlobal {
		t.Fatalf("status after cancellation = %#v, want old connected session", status)
	}
}

func TestFailedReplacementCheckPreservesOldSession(t *testing.T) {
	oldProcess := newFakeProcess(true)
	runner := newFakeRunner()
	runner.start = func(int, context.Context, *core.PreparedConfig) (core.Process, error) { return oldProcess, nil }
	runner.check = func(call int, _ context.Context, _ *core.PreparedConfig) error {
		if call == 2 {
			return core.ErrCoreCheckFailed
		}
		return nil
	}
	service := newTestService(t, runner, 50*time.Millisecond)
	oldRequest := connectionRequest(domain.ConnectionModeTUN, domain.RouteModeGlobal)
	if _, err := service.Connect(context.Background(), oldRequest); err != nil {
		t.Fatal(err)
	}

	if _, err := service.Connect(context.Background(), connectionRequest(domain.ConnectionModeTUN, domain.RouteModeRule)); !errors.Is(err, rpc.ErrCoreValidation) {
		t.Fatalf("replacement error = %v, want ErrCoreValidation", err)
	}
	if got := oldProcess.signalCount(); got != 0 {
		t.Fatalf("old process received %d signals after failed check", got)
	}
	if got := runner.startCount(); got != 1 {
		t.Fatalf("Start calls = %d, want no replacement start", got)
	}
	status := mustServiceStatus(t, service)
	if status.State != domain.ConnectionStatusConnected || status.Mode != oldRequest.Mode || status.Route != oldRequest.Route {
		t.Fatalf("status after failed check = %#v, want old connected session", status)
	}
}

func TestFailedReplacementStartRollsBackCheckedOldConfig(t *testing.T) {
	oldProcess := newFakeProcess(true)
	rollbackProcess := newFakeProcess(true)
	runner := newFakeRunner()
	runner.start = func(call int, _ context.Context, _ *core.PreparedConfig) (core.Process, error) {
		switch call {
		case 1:
			return oldProcess, nil
		case 2:
			return nil, core.ErrCoreStartFailed
		case 3:
			return rollbackProcess, nil
		default:
			return nil, errors.New("unexpected start")
		}
	}
	service := newTestService(t, runner, 50*time.Millisecond)
	oldRequest := connectionRequest(domain.ConnectionModeTUN, domain.RouteModeGlobal)
	if _, err := service.Connect(context.Background(), oldRequest); err != nil {
		t.Fatal(err)
	}

	if _, err := service.Connect(context.Background(), connectionRequest(domain.ConnectionModeTUN, domain.RouteModeRule)); !errors.Is(err, rpc.ErrProcessFailure) {
		t.Fatalf("replacement error = %v, want ErrProcessFailure", err)
	}
	starts := runner.startedPrepared()
	if len(starts) != 3 || starts[0] != starts[2] || starts[0] == starts[1] {
		t.Fatalf("Start prepared sequence = %v, want old, new, old rollback", starts)
	}
	status := mustServiceStatus(t, service)
	if status.State != domain.ConnectionStatusConnected || status.Mode != oldRequest.Mode || status.Route != oldRequest.Route {
		t.Fatalf("rollback status = %#v, want preserved old status", status)
	}
	if rollbackProcess.signalCount() != 0 {
		t.Fatal("rollback process was unexpectedly stopped")
	}
}

func TestFailedReplacementAndRollbackLeavesFailedStatus(t *testing.T) {
	oldProcess := newFakeProcess(true)
	runner := newFakeRunner()
	runner.start = func(call int, _ context.Context, _ *core.PreparedConfig) (core.Process, error) {
		if call == 1 {
			return oldProcess, nil
		}
		return nil, core.ErrCoreStartFailed
	}
	service := newTestService(t, runner, 50*time.Millisecond)
	if _, err := service.Connect(context.Background(), connectionRequest(domain.ConnectionModeTUN, domain.RouteModeGlobal)); err != nil {
		t.Fatal(err)
	}
	if _, err := service.Connect(context.Background(), connectionRequest(domain.ConnectionModeTUN, domain.RouteModeRule)); !errors.Is(err, rpc.ErrProcessFailure) {
		t.Fatalf("replacement error = %v, want ErrProcessFailure", err)
	}
	if status := mustServiceStatus(t, service); status.State != domain.ConnectionStatusFailed {
		t.Fatalf("status = %#v, want failed", status)
	}
}

func TestStopSessionReturnsCallerCancellationWhenDoneIsAlsoReady(t *testing.T) {
	service := &Service{stopTimeout: 100 * time.Millisecond}
	for iteration := 0; iteration < 32; iteration++ {
		process := newFakeProcess(false)
		ctx, cancel := context.WithCancel(context.Background())
		process.signalHook = func(signal os.Signal) {
			if signal == syscall.SIGTERM {
				cancel()
			}
		}
		done := make(chan struct{})
		close(done)
		stopped, err := service.stopSession(ctx, &session{process: process, done: done})
		if !stopped || !errors.Is(err, context.Canceled) {
			t.Fatalf("iteration %d: stopSession() = %v, %v, want stopped with context.Canceled", iteration, stopped, err)
		}
	}
}

func TestDisconnectCancellationKillsAndReturnsImmediately(t *testing.T) {
	process := newStubbornFakeProcess()
	process.termObserved = make(chan struct{})
	process.killObserved = make(chan struct{})
	runner := newFakeRunner()
	runner.start = func(int, context.Context, *core.PreparedConfig) (core.Process, error) { return process, nil }
	service := newTestService(t, runner, 500*time.Millisecond)
	if _, err := service.Connect(context.Background(), connectionRequest(domain.ConnectionModeTUN, domain.RouteModeGlobal)); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	type result struct {
		status rpc.SessionStatus
		err    error
	}
	done := make(chan result, 1)
	go func() {
		status, err := service.Disconnect(ctx)
		done <- result{status: status, err: err}
	}()
	select {
	case <-process.termObserved:
	case <-time.After(time.Second):
		process.exit(nil)
		t.Fatal("Disconnect() did not send SIGTERM")
	}
	cancel()
	select {
	case <-process.killObserved:
	case <-time.After(100 * time.Millisecond):
		process.exit(nil)
		<-done
		t.Fatal("Disconnect() did not kill promptly after caller cancellation")
	}
	select {
	case result := <-done:
		if !errors.Is(result.err, context.Canceled) {
			t.Fatalf("Disconnect() error = %v, want context.Canceled", result.err)
		}
		if result.status.State != domain.ConnectionStatusDisconnected {
			t.Fatalf("Disconnect() status = %#v, want disconnected", result.status)
		}
	case <-time.After(100 * time.Millisecond):
		process.exit(nil)
		<-done
		t.Fatal("Disconnect() waited after killing a canceled session")
	}
	if process.killCount() != 1 {
		t.Fatalf("Kill calls = %d, want 1", process.killCount())
	}
	process.exit(nil)
}

func TestDisconnectReturnsImmediatelyAfterStopTimeoutKill(t *testing.T) {
	process := newStubbornFakeProcess()
	process.termObserved = make(chan struct{})
	process.killObserved = make(chan struct{})
	runner := newFakeRunner()
	runner.start = func(int, context.Context, *core.PreparedConfig) (core.Process, error) { return process, nil }
	stopTimeout := 100 * time.Millisecond
	service := newTestService(t, runner, stopTimeout)
	if _, err := service.Connect(context.Background(), connectionRequest(domain.ConnectionModeTUN, domain.RouteModeGlobal)); err != nil {
		t.Fatal(err)
	}

	type result struct {
		status rpc.SessionStatus
		err    error
	}
	done := make(chan result, 1)
	go func() {
		status, err := service.Disconnect(context.Background())
		done <- result{status: status, err: err}
	}()
	select {
	case <-process.termObserved:
	case <-time.After(time.Second):
		process.exit(nil)
		t.Fatal("Disconnect() did not send SIGTERM")
	}
	select {
	case <-process.killObserved:
	case <-time.After(2 * stopTimeout):
		process.exit(nil)
		<-done
		t.Fatal("Disconnect() did not kill after the stop timeout")
	}
	select {
	case result := <-done:
		if result.err != nil {
			t.Fatalf("Disconnect() error = %v, want successful kill dispatch", result.err)
		}
		if result.status.State != domain.ConnectionStatusDisconnected {
			t.Fatalf("Disconnect() status = %#v, want disconnected", result.status)
		}
	case <-time.After(40 * time.Millisecond):
		process.exit(nil)
		<-done
		t.Fatal("Disconnect() started a second wait after Kill")
	}
	if process.killCount() != 1 {
		t.Fatalf("Kill calls = %d, want 1", process.killCount())
	}
	process.exit(nil)
}

func TestDisconnectTermsWaitsThenKillsAndIsIdempotent(t *testing.T) {
	process := newFakeProcess(false)
	runner := newFakeRunner()
	runner.start = func(int, context.Context, *core.PreparedConfig) (core.Process, error) { return process, nil }
	stopTimeout := 25 * time.Millisecond
	service := newTestService(t, runner, stopTimeout)
	if _, err := service.Connect(context.Background(), connectionRequest(domain.ConnectionModeTUN, domain.RouteModeGlobal)); err != nil {
		t.Fatal(err)
	}

	started := time.Now()
	status, err := service.Disconnect(context.Background())
	if err != nil {
		t.Fatalf("Disconnect() failed: %v", err)
	}
	if time.Since(started) < stopTimeout {
		t.Fatal("Disconnect() killed before graceful timeout elapsed")
	}
	if status.State != domain.ConnectionStatusDisconnected {
		t.Fatalf("Disconnect() status = %#v, want disconnected", status)
	}
	if got := process.signalsSnapshot(); len(got) != 1 || got[0] != syscall.SIGTERM {
		t.Fatalf("signals = %v, want SIGTERM", got)
	}
	if process.killCount() != 1 {
		t.Fatalf("Kill calls = %d, want 1", process.killCount())
	}
	if _, err := service.Disconnect(context.Background()); err != nil {
		t.Fatalf("second Disconnect() failed: %v", err)
	}
	if process.signalCount() != 1 || process.killCount() != 1 {
		t.Fatal("idempotent Disconnect() signaled process again")
	}
}

func TestUnexpectedExitUpdatesStatusWithoutLeakingOutput(t *testing.T) {
	process := newFakeProcess(false)
	process.output = []byte("secret.example credential-value Sensitive Endpoint Name")
	runner := newFakeRunner()
	runner.start = func(int, context.Context, *core.PreparedConfig) (core.Process, error) { return process, nil }
	service := newTestService(t, runner, 50*time.Millisecond)
	if _, err := service.Connect(context.Background(), connectionRequest(domain.ConnectionModeTUN, domain.RouteModeGlobal)); err != nil {
		t.Fatal(err)
	}

	process.exit(errors.New("secret.example process failure"))
	waitForStatus(t, service, domain.ConnectionStatusFailed)
	status := mustServiceStatus(t, service)
	if status.Mode != domain.ConnectionModeTUN || status.Route != domain.RouteModeGlobal {
		t.Fatalf("failed status lost safe mode/route: %#v", status)
	}
}

func TestOldGenerationExitCannotClobberReplacementStatus(t *testing.T) {
	oldProcess := newStubbornFakeProcess()
	newProcess := newFakeProcess(false)
	runner := newFakeRunner()
	runner.start = func(call int, _ context.Context, _ *core.PreparedConfig) (core.Process, error) {
		if call == 1 {
			return oldProcess, nil
		}
		return newProcess, nil
	}
	service := newTestService(t, runner, 50*time.Millisecond)
	if _, err := service.Connect(context.Background(), connectionRequest(domain.ConnectionModeTUN, domain.RouteModeGlobal)); err != nil {
		t.Fatal(err)
	}
	if _, err := service.Connect(context.Background(), connectionRequest(domain.ConnectionModeTUN, domain.RouteModeRule)); err != nil {
		t.Fatal(err)
	}
	oldProcess.exit(errors.New("late old generation exit"))
	time.Sleep(20 * time.Millisecond)
	status := mustServiceStatus(t, service)
	if status.State != domain.ConnectionStatusConnected || status.Route != domain.RouteModeRule {
		t.Fatalf("stale process exit changed replacement status: %#v", status)
	}
}

func TestStartedProcessUsesServiceLifetimeContext(t *testing.T) {
	process := newFakeProcess(true)
	var startedContext context.Context
	runner := newFakeRunner()
	runner.start = func(_ int, ctx context.Context, _ *core.PreparedConfig) (core.Process, error) {
		startedContext = ctx
		return process, nil
	}
	service := newTestService(t, runner, 50*time.Millisecond)
	requestContext, cancel := context.WithCancel(context.Background())
	if _, err := service.Connect(requestContext, connectionRequest(domain.ConnectionModeTUN, domain.RouteModeGlobal)); err != nil {
		t.Fatal(err)
	}
	cancel()
	select {
	case <-startedContext.Done():
		t.Fatal("successful process was tied to request context")
	case <-time.After(20 * time.Millisecond):
	}
	if err := service.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-startedContext.Done():
	case <-time.After(time.Second):
		t.Fatal("service lifetime context was not canceled on Close")
	}
}

func TestServiceHealthCloseAndConcurrentStatusAreSafe(t *testing.T) {
	process := newFakeProcess(false)
	runner := newFakeRunner()
	runner.start = func(int, context.Context, *core.PreparedConfig) (core.Process, error) { return process, nil }
	service := newTestService(t, runner, 20*time.Millisecond)
	if err := service.Health(context.Background()); err != nil {
		t.Fatalf("Health() failed: %v", err)
	}
	if _, err := service.Connect(context.Background(), connectionRequest(domain.ConnectionModeTUN, domain.RouteModeGlobal)); err != nil {
		t.Fatal(err)
	}

	var wait sync.WaitGroup
	for index := 0; index < 50; index++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			for iteration := 0; iteration < 20; iteration++ {
				_, _ = service.Status(context.Background())
				_ = service.Health(context.Background())
			}
		}()
	}
	process.exit(errors.New("unexpected exit"))
	wait.Wait()
	waitForStatus(t, service, domain.ConnectionStatusFailed)

	if err := service.Close(); err != nil {
		t.Fatalf("Close() failed: %v", err)
	}
	if err := service.Close(); err != nil {
		t.Fatalf("second Close() failed: %v", err)
	}
	if runner.closeCount() != 1 {
		t.Fatalf("runner Close calls = %d, want 1", runner.closeCount())
	}
	if err := service.Health(context.Background()); !errors.Is(err, rpc.ErrUnavailable) {
		t.Fatalf("Health() after close = %v, want ErrUnavailable", err)
	}
	if _, err := service.Connect(context.Background(), connectionRequest(domain.ConnectionModeTUN, domain.RouteModeGlobal)); !errors.Is(err, rpc.ErrUnavailable) {
		t.Fatalf("Connect() after close = %v, want ErrUnavailable", err)
	}
}

func connectionRequest(mode domain.ConnectionMode, route domain.RouteMode) core.ConnectionRequest {
	request := core.ConnectionRequest{
		Mode:  mode,
		Route: route,
		UID:   501,
		GID:   20,
	}
	if route != domain.RouteModeDirect {
		request.Endpoint = &domain.Endpoint{
			ID:             "endpoint-id",
			SubscriptionID: "subscription-id",
			Name:           "Sensitive Endpoint Name",
			Protocol:       domain.ProtocolShadowsocks,
			Host:           "secret.example.com",
			Port:           443,
			Password:       "credential-value",
			Method:         "aes-128-gcm",
		}
	}
	return request
}

func newTestService(t *testing.T, runner core.Runner, timeout time.Duration) *Service {
	t.Helper()
	service, err := NewService(runner, timeout)
	if err != nil {
		t.Fatalf("NewService() failed: %v", err)
	}
	t.Cleanup(func() { _ = service.Close() })
	return service
}

func mustServiceStatus(t *testing.T, service *Service) rpc.SessionStatus {
	t.Helper()
	status, err := service.Status(context.Background())
	if err != nil {
		t.Fatalf("Status() failed: %v", err)
	}
	return status
}

func waitForStatus(t *testing.T, service *Service, want domain.ConnectionStatus) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if mustServiceStatus(t, service).State == want {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("status = %#v, want %s", mustServiceStatus(t, service), want)
}

type observedContext struct {
	context.Context
	checked chan struct{}
	once    sync.Once
}

func newObservedContext(ctx context.Context) *observedContext {
	return &observedContext{Context: ctx, checked: make(chan struct{})}
}

func (ctx *observedContext) Done() <-chan struct{} {
	ctx.once.Do(func() { close(ctx.checked) })
	return ctx.Context.Done()
}

func (ctx *observedContext) Err() error {
	return ctx.Context.Err()
}

type fakeRunner struct {
	mu sync.Mutex

	prepareCalls int
	checkCalls   int
	startCalls   int
	closeCalls   int
	prepared     []*core.PreparedConfig
	started      []*core.PreparedConfig

	check func(int, context.Context, *core.PreparedConfig) error
	start func(int, context.Context, *core.PreparedConfig) (core.Process, error)
}

func newFakeRunner() *fakeRunner { return &fakeRunner{} }

func (runner *fakeRunner) Prepare(core.ConnectionRequest) (*core.PreparedConfig, error) {
	runner.mu.Lock()
	defer runner.mu.Unlock()
	runner.prepareCalls++
	prepared := &core.PreparedConfig{}
	runner.prepared = append(runner.prepared, prepared)
	return prepared, nil
}

func (runner *fakeRunner) Check(ctx context.Context, prepared *core.PreparedConfig) error {
	runner.mu.Lock()
	runner.checkCalls++
	call := runner.checkCalls
	check := runner.check
	runner.mu.Unlock()
	if check != nil {
		return check(call, ctx, prepared)
	}
	return nil
}

func (runner *fakeRunner) Start(ctx context.Context, prepared *core.PreparedConfig) (core.Process, error) {
	runner.mu.Lock()
	runner.startCalls++
	call := runner.startCalls
	runner.started = append(runner.started, prepared)
	start := runner.start
	runner.mu.Unlock()
	if start != nil {
		return start(call, ctx, prepared)
	}
	return newFakeProcess(true), nil
}

func (runner *fakeRunner) Close() error {
	runner.mu.Lock()
	defer runner.mu.Unlock()
	runner.closeCalls++
	return nil
}

func (runner *fakeRunner) prepareCount() int {
	runner.mu.Lock()
	defer runner.mu.Unlock()
	return runner.prepareCalls
}

func (runner *fakeRunner) startCount() int {
	runner.mu.Lock()
	defer runner.mu.Unlock()
	return runner.startCalls
}

func (runner *fakeRunner) closeCount() int {
	runner.mu.Lock()
	defer runner.mu.Unlock()
	return runner.closeCalls
}

func (runner *fakeRunner) startedPrepared() []*core.PreparedConfig {
	runner.mu.Lock()
	defer runner.mu.Unlock()
	return append([]*core.PreparedConfig(nil), runner.started...)
}

type fakeProcess struct {
	mu sync.Mutex

	autoExitOnTERM bool
	autoExitOnKill bool
	signalHook     func(os.Signal)
	termObserved   chan struct{}
	killObserved   chan struct{}
	signals        []os.Signal
	kills          int
	waitErr        error
	output         []byte
	done           chan struct{}
	exitOnce       sync.Once
	termOnce       sync.Once
	killOnce       sync.Once
}

func newFakeProcess(autoExitOnTERM bool) *fakeProcess {
	return &fakeProcess{autoExitOnTERM: autoExitOnTERM, autoExitOnKill: true, done: make(chan struct{})}
}

func newStubbornFakeProcess() *fakeProcess {
	process := newFakeProcess(false)
	process.autoExitOnKill = false
	return process
}

func (process *fakeProcess) Signal(signal os.Signal) error {
	process.mu.Lock()
	process.signals = append(process.signals, signal)
	autoExit := process.autoExitOnTERM && signal == syscall.SIGTERM
	signalHook := process.signalHook
	termObserved := process.termObserved
	process.mu.Unlock()
	if signalHook != nil {
		signalHook(signal)
	}
	if signal == syscall.SIGTERM && termObserved != nil {
		process.termOnce.Do(func() { close(termObserved) })
	}
	if autoExit {
		process.exit(nil)
	}
	return nil
}

func (process *fakeProcess) Kill() error {
	process.mu.Lock()
	process.kills++
	autoExit := process.autoExitOnKill
	killObserved := process.killObserved
	process.mu.Unlock()
	if killObserved != nil {
		process.killOnce.Do(func() { close(killObserved) })
	}
	if autoExit {
		process.exit(errors.New("killed"))
	}
	return nil
}

func (process *fakeProcess) Wait() error {
	<-process.done
	process.mu.Lock()
	defer process.mu.Unlock()
	return process.waitErr
}

func (process *fakeProcess) Output() []byte {
	process.mu.Lock()
	defer process.mu.Unlock()
	return append([]byte(nil), process.output...)
}

func (process *fakeProcess) exit(err error) {
	process.exitOnce.Do(func() {
		process.mu.Lock()
		process.waitErr = err
		process.mu.Unlock()
		close(process.done)
	})
}

func (process *fakeProcess) signalCount() int {
	process.mu.Lock()
	defer process.mu.Unlock()
	return len(process.signals)
}

func (process *fakeProcess) signalsSnapshot() []os.Signal {
	process.mu.Lock()
	defer process.mu.Unlock()
	return append([]os.Signal(nil), process.signals...)
}

func (process *fakeProcess) killCount() int {
	process.mu.Lock()
	defer process.mu.Unlock()
	return process.kills
}

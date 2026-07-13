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

func TestCanceledInitialStartStopsProcessBeforeReturning(t *testing.T) {
	process := newFakeProcess(true)
	ctx, cancel := context.WithCancel(context.Background())
	runner := newFakeRunner()
	runner.start = func(int, context.Context, *core.PreparedConfig) (core.Process, error) {
		cancel()
		return process, nil
	}
	service := newTestService(t, runner, 80*time.Millisecond)

	status, err := service.Connect(ctx, connectionRequest(domain.ConnectionModeTUN, domain.RouteModeGlobal))
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Connect() error = %v, want context.Canceled", err)
	}
	if status.State != domain.ConnectionStatusDisconnected || service.active != nil {
		t.Fatalf("canceled Connect() status = %#v, want no active session", status)
	}
	if process.signalCount() != 1 {
		t.Fatalf("canceled process signals = %d, want process retired before return", process.signalCount())
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

func TestCanceledReplacementAfterStoppingOldRestartsCheckedOldConfig(t *testing.T) {
	oldProcess := newFakeProcess(true)
	rollbackProcess := newFakeProcess(true)
	ctx, cancel := context.WithCancel(context.Background())
	oldProcess.signalHook = func(signal os.Signal) {
		if signal == syscall.SIGTERM {
			cancel()
		}
	}
	runner := newFakeRunner()
	runner.start = func(call int, _ context.Context, _ *core.PreparedConfig) (core.Process, error) {
		switch call {
		case 1:
			return oldProcess, nil
		case 2:
			return rollbackProcess, nil
		default:
			return nil, errors.New("unexpected start")
		}
	}
	service := newTestService(t, runner, 100*time.Millisecond)
	oldRequest := connectionRequest(domain.ConnectionModeTUN, domain.RouteModeGlobal)
	if _, err := service.Connect(context.Background(), oldRequest); err != nil {
		t.Fatal(err)
	}

	if _, err := service.Connect(ctx, connectionRequest(domain.ConnectionModeTUN, domain.RouteModeRule)); !errors.Is(err, context.Canceled) {
		t.Fatalf("replacement error = %v, want context.Canceled", err)
	}
	starts := runner.startedPrepared()
	if len(starts) != 2 || starts[0] != starts[1] {
		t.Fatalf("Start prepared sequence = %v, want old then checked-old rollback", starts)
	}
	status := mustServiceStatus(t, service)
	if status.State != domain.ConnectionStatusConnected || status.Mode != oldRequest.Mode || status.Route != oldRequest.Route {
		t.Fatalf("status after canceled replacement = %#v, want restored old session", status)
	}
	if service.active == nil || service.active.process != rollbackProcess {
		t.Fatal("canceled replacement did not track rollback process")
	}
}

func TestCanceledReplacementDuringKillWaitRestartsCheckedOldConfig(t *testing.T) {
	oldProcess := newStubbornFakeProcess()
	oldProcess.killObserved = make(chan struct{})
	rollbackProcess := newFakeProcess(true)
	runner := newFakeRunner()
	runner.start = func(call int, _ context.Context, _ *core.PreparedConfig) (core.Process, error) {
		switch call {
		case 1:
			return oldProcess, nil
		case 2:
			return rollbackProcess, nil
		default:
			return nil, errors.New("unexpected start")
		}
	}
	service := newTestService(t, runner, 160*time.Millisecond)
	oldRequest := connectionRequest(domain.ConnectionModeTUN, domain.RouteModeGlobal)
	if _, err := service.Connect(context.Background(), oldRequest); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		_, err := service.Connect(ctx, connectionRequest(domain.ConnectionModeTUN, domain.RouteModeRule))
		done <- err
	}()
	select {
	case <-oldProcess.killObserved:
	case <-time.After(time.Second):
		oldProcess.exit(nil)
		t.Fatal("replacement did not enter post-kill wait")
	}
	cancel()
	oldProcess.exit(nil)
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("replacement error = %v, want context.Canceled", err)
		}
	case <-time.After(time.Second):
		t.Fatal("replacement did not return after old Wait completed")
	}
	starts := runner.startedPrepared()
	if len(starts) != 2 || starts[0] != starts[1] {
		t.Fatalf("Start prepared sequence = %v, want old then checked-old rollback", starts)
	}
	status := mustServiceStatus(t, service)
	if status.State != domain.ConnectionStatusConnected || status.Mode != oldRequest.Mode || status.Route != oldRequest.Route {
		t.Fatalf("status after cancellation during kill wait = %#v, want restored old session", status)
	}
}

func TestCanceledReplacementStartStopsNewAndRestoresOldConfig(t *testing.T) {
	oldProcess := newFakeProcess(true)
	newProcess := newFakeProcess(true)
	rollbackProcess := newFakeProcess(true)
	ctx, cancel := context.WithCancel(context.Background())
	runner := newFakeRunner()
	runner.start = func(call int, _ context.Context, _ *core.PreparedConfig) (core.Process, error) {
		switch call {
		case 1:
			return oldProcess, nil
		case 2:
			cancel()
			return newProcess, nil
		case 3:
			return rollbackProcess, nil
		default:
			return nil, errors.New("unexpected start")
		}
	}
	service := newTestService(t, runner, 120*time.Millisecond)
	oldRequest := connectionRequest(domain.ConnectionModeTUN, domain.RouteModeGlobal)
	if _, err := service.Connect(context.Background(), oldRequest); err != nil {
		t.Fatal(err)
	}

	if _, err := service.Connect(ctx, connectionRequest(domain.ConnectionModeTUN, domain.RouteModeRule)); !errors.Is(err, context.Canceled) {
		t.Fatalf("replacement error = %v, want context.Canceled", err)
	}
	starts := runner.startedPrepared()
	if len(starts) != 3 || starts[0] == starts[1] || starts[0] != starts[2] {
		t.Fatalf("Start prepared sequence = %v, want old, new, checked-old rollback", starts)
	}
	if newProcess.signalCount() != 1 {
		t.Fatalf("new process signals = %d, want canceled replacement stopped", newProcess.signalCount())
	}
	status := mustServiceStatus(t, service)
	if status.State != domain.ConnectionStatusConnected || status.Mode != oldRequest.Mode || status.Route != oldRequest.Route {
		t.Fatalf("status after canceled Start = %#v, want restored old session", status)
	}
}

func TestCanceledReplacementStartFailureRestoresOldConfig(t *testing.T) {
	oldProcess := newFakeProcess(true)
	rollbackProcess := newFakeProcess(true)
	ctx, cancel := context.WithCancel(context.Background())
	runner := newFakeRunner()
	runner.start = func(call int, _ context.Context, _ *core.PreparedConfig) (core.Process, error) {
		switch call {
		case 1:
			return oldProcess, nil
		case 2:
			cancel()
			return nil, core.ErrCoreStartFailed
		case 3:
			return rollbackProcess, nil
		default:
			return nil, errors.New("unexpected start")
		}
	}
	service := newTestService(t, runner, 80*time.Millisecond)
	oldRequest := connectionRequest(domain.ConnectionModeTUN, domain.RouteModeGlobal)
	if _, err := service.Connect(context.Background(), oldRequest); err != nil {
		t.Fatal(err)
	}

	if _, err := service.Connect(ctx, connectionRequest(domain.ConnectionModeTUN, domain.RouteModeRule)); !errors.Is(err, context.Canceled) {
		t.Fatalf("replacement error = %v, want context.Canceled", err)
	}
	starts := runner.startedPrepared()
	if len(starts) != 3 || starts[0] == starts[1] || starts[0] != starts[2] {
		t.Fatalf("Start prepared sequence = %v, want old, failed new, old rollback", starts)
	}
	status := mustServiceStatus(t, service)
	if status.State != domain.ConnectionStatusConnected || status.Mode != oldRequest.Mode || status.Route != oldRequest.Route {
		t.Fatalf("status after canceled Start failure = %#v, want restored old session", status)
	}
}

func TestCanceledStuckReplacementRestoresOldAfterLateExit(t *testing.T) {
	oldProcess := newFakeProcess(true)
	newProcess := newStubbornFakeProcess()
	rollbackProcess := newFakeProcess(true)
	ctx, cancel := context.WithCancel(context.Background())
	runner := newFakeRunner()
	runner.start = func(call int, _ context.Context, _ *core.PreparedConfig) (core.Process, error) {
		switch call {
		case 1:
			return oldProcess, nil
		case 2:
			cancel()
			return newProcess, nil
		case 3:
			return rollbackProcess, nil
		default:
			return nil, errors.New("unexpected start")
		}
	}
	service := newTestService(t, runner, 60*time.Millisecond)
	oldRequest := connectionRequest(domain.ConnectionModeTUN, domain.RouteModeGlobal)
	if _, err := service.Connect(context.Background(), oldRequest); err != nil {
		t.Fatal(err)
	}

	status, err := service.Connect(ctx, connectionRequest(domain.ConnectionModeTUN, domain.RouteModeRule))
	if !errors.Is(err, rpc.ErrProcessStuck) || !errors.Is(err, context.Canceled) {
		newProcess.exit(nil)
		t.Fatalf("replacement error = %v, want canceled ErrProcessStuck", err)
	}
	if status.State != domain.ConnectionStatusDisconnecting || service.active == nil || service.active.process != newProcess {
		newProcess.exit(nil)
		t.Fatalf("stuck new process status = %#v, want tracked disconnecting session", status)
	}
	if runner.startCount() != 2 {
		newProcess.exit(nil)
		t.Fatalf("Start calls before new Wait completes = %d, want 2", runner.startCount())
	}

	newProcess.exit(nil)
	waitForStatus(t, service, domain.ConnectionStatusConnected)
	starts := runner.startedPrepared()
	if len(starts) != 3 || starts[0] == starts[1] || starts[0] != starts[2] {
		t.Fatalf("Start prepared sequence = %v, want old, canceled new, old rollback", starts)
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

func TestStuckReplacementRestartsOldConfigAfterLateExit(t *testing.T) {
	oldProcess := newStubbornFakeProcess()
	rollbackProcess := newFakeProcess(true)
	runner := newFakeRunner()
	runner.start = func(call int, _ context.Context, _ *core.PreparedConfig) (core.Process, error) {
		switch call {
		case 1:
			return oldProcess, nil
		case 2:
			return rollbackProcess, nil
		default:
			return nil, errors.New("unexpected start")
		}
	}
	service := newTestService(t, runner, 60*time.Millisecond)
	oldRequest := connectionRequest(domain.ConnectionModeTUN, domain.RouteModeGlobal)
	if _, err := service.Connect(context.Background(), oldRequest); err != nil {
		t.Fatal(err)
	}

	status, err := service.Connect(context.Background(), connectionRequest(domain.ConnectionModeTUN, domain.RouteModeRule))
	if !errors.Is(err, rpc.ErrProcessStuck) {
		oldProcess.exit(nil)
		t.Fatalf("replacement error = %v, want ErrProcessStuck", err)
	}
	if status.State != domain.ConnectionStatusDisconnecting || runner.startCount() != 1 {
		oldProcess.exit(nil)
		t.Fatalf("stuck replacement = %#v with %d starts, want tracked old only", status, runner.startCount())
	}

	oldProcess.exit(nil)
	waitForStatus(t, service, domain.ConnectionStatusConnected)
	starts := runner.startedPrepared()
	if len(starts) != 2 || starts[0] != starts[1] {
		t.Fatalf("Start prepared sequence = %v, want old then late rollback", starts)
	}
	status = mustServiceStatus(t, service)
	if status.Mode != oldRequest.Mode || status.Route != oldRequest.Route || service.active == nil || service.active.process != rollbackProcess {
		t.Fatalf("late rollback status = %#v, want restored old session", status)
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

func TestFailedReplacementAndRollbackReportsStableFailure(t *testing.T) {
	oldProcess := newFakeProcess(true)
	runner := newFakeRunner()
	runner.start = func(call int, _ context.Context, _ *core.PreparedConfig) (core.Process, error) {
		if call == 1 {
			return oldProcess, nil
		}
		return nil, core.ErrCoreStartFailed
	}
	service := newTestService(t, runner, 50*time.Millisecond)
	oldRequest := connectionRequest(domain.ConnectionModeTUN, domain.RouteModeGlobal)
	if _, err := service.Connect(context.Background(), oldRequest); err != nil {
		t.Fatal(err)
	}
	if _, err := service.Connect(context.Background(), connectionRequest(domain.ConnectionModeTUN, domain.RouteModeRule)); !errors.Is(err, rpc.ErrRollbackFailure) {
		t.Fatalf("replacement error = %v, want ErrRollbackFailure", err)
	}
	status := mustServiceStatus(t, service)
	if status.State != domain.ConnectionStatusFailed || status.Mode != oldRequest.Mode || status.Route != oldRequest.Route {
		t.Fatalf("status = %#v, want failed previous-session identity", status)
	}
}

func TestReplacementRollbackContextIsServiceBounded(t *testing.T) {
	oldProcess := newFakeProcess(true)
	stopTimeout := 40 * time.Millisecond
	runner := newFakeRunner()
	runner.start = func(call int, ctx context.Context, _ *core.PreparedConfig) (core.Process, error) {
		switch call {
		case 1:
			return oldProcess, nil
		case 2:
			return nil, core.ErrCoreStartFailed
		case 3:
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(4 * stopTimeout):
				return nil, errors.New("rollback context was not bounded")
			}
		default:
			return nil, errors.New("unexpected start")
		}
	}
	service := newTestService(t, runner, stopTimeout)
	if _, err := service.Connect(context.Background(), connectionRequest(domain.ConnectionModeTUN, domain.RouteModeGlobal)); err != nil {
		t.Fatal(err)
	}

	started := time.Now()
	if _, err := service.Connect(context.Background(), connectionRequest(domain.ConnectionModeTUN, domain.RouteModeRule)); !errors.Is(err, rpc.ErrRollbackFailure) {
		t.Fatalf("replacement error = %v, want ErrRollbackFailure", err)
	}
	if elapsed := time.Since(started); elapsed > 2*stopTimeout+50*time.Millisecond {
		t.Fatalf("rollback returned after %s, want bounded by service timeout %s", elapsed, stopTimeout)
	}
}

func TestTimedOutRollbackProcessRemainsTrackedUntilWait(t *testing.T) {
	oldProcess := newFakeProcess(true)
	lateRollback := newStubbornFakeProcess()
	runner := newFakeRunner()
	runner.start = func(call int, ctx context.Context, _ *core.PreparedConfig) (core.Process, error) {
		switch call {
		case 1:
			return oldProcess, nil
		case 2:
			return nil, core.ErrCoreStartFailed
		case 3:
			<-ctx.Done()
			return lateRollback, nil
		default:
			return nil, errors.New("unexpected start")
		}
	}
	service := newTestService(t, runner, 50*time.Millisecond)
	oldRequest := connectionRequest(domain.ConnectionModeTUN, domain.RouteModeGlobal)
	if _, err := service.Connect(context.Background(), oldRequest); err != nil {
		t.Fatal(err)
	}

	status, err := service.Connect(context.Background(), connectionRequest(domain.ConnectionModeTUN, domain.RouteModeRule))
	if !errors.Is(err, rpc.ErrRollbackFailure) || !errors.Is(err, rpc.ErrProcessStuck) {
		lateRollback.exit(nil)
		t.Fatalf("replacement error = %v, want rollback failure and process stuck", err)
	}
	if status.State != domain.ConnectionStatusDisconnecting || status.Mode != oldRequest.Mode || status.Route != oldRequest.Route {
		lateRollback.exit(nil)
		t.Fatalf("timed-out rollback status = %#v, want previous session disconnecting", status)
	}
	if service.active == nil || service.active.process != lateRollback {
		lateRollback.exit(nil)
		t.Fatal("timed-out rollback process was not tracked")
	}

	lateRollback.exit(nil)
	waitForStatus(t, service, domain.ConnectionStatusFailed)
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

func TestDisconnectCancellationWaitsForProcessExitBeforeRetiring(t *testing.T) {
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
		process.exit(nil)
		t.Fatalf("Disconnect() retired before Wait completed: %#v, %v", result.status, result.err)
	case <-time.After(30 * time.Millisecond):
	}

	process.exit(nil)
	select {
	case result := <-done:
		if !errors.Is(result.err, context.Canceled) {
			t.Fatalf("Disconnect() error = %v, want context.Canceled", result.err)
		}
		if result.status.State != domain.ConnectionStatusDisconnected {
			t.Fatalf("Disconnect() status = %#v, want disconnected after Wait", result.status)
		}
	case <-time.After(time.Second):
		t.Fatal("Disconnect() did not return after Wait completed")
	}
	if process.killCount() != 1 {
		t.Fatalf("Kill calls = %d, want 1", process.killCount())
	}
}

func TestDisconnectReturnsProcessStuckAndKeepsTrackingSession(t *testing.T) {
	process := newStubbornFakeProcess()
	runner := newFakeRunner()
	runner.start = func(int, context.Context, *core.PreparedConfig) (core.Process, error) { return process, nil }
	stopTimeout := 80 * time.Millisecond
	service := newTestService(t, runner, stopTimeout)
	if _, err := service.Connect(context.Background(), connectionRequest(domain.ConnectionModeTUN, domain.RouteModeGlobal)); err != nil {
		t.Fatal(err)
	}

	started := time.Now()
	status, err := service.Disconnect(context.Background())
	elapsed := time.Since(started)
	if !errors.Is(err, rpc.ErrProcessStuck) {
		process.exit(nil)
		t.Fatalf("Disconnect() error = %v, want ErrProcessStuck", err)
	}
	if elapsed < stopTimeout || elapsed > stopTimeout+150*time.Millisecond {
		process.exit(nil)
		t.Fatalf("Disconnect() elapsed = %s, want one total deadline near %s", elapsed, stopTimeout)
	}
	if status.State != domain.ConnectionStatusDisconnecting {
		process.exit(nil)
		t.Fatalf("Disconnect() status = %#v, want disconnecting while Wait remains open", status)
	}
	if service.active == nil || service.active.process != process {
		process.exit(nil)
		t.Fatal("Disconnect() stopped tracking process before Wait completed")
	}
	if process.killCount() != 1 {
		process.exit(nil)
		t.Fatalf("Kill calls = %d, want 1", process.killCount())
	}

	if _, err := service.Connect(context.Background(), connectionRequest(domain.ConnectionModeTUN, domain.RouteModeRule)); !errors.Is(err, rpc.ErrProcessStuck) {
		process.exit(nil)
		t.Fatalf("replacement while old Wait is open = %v, want ErrProcessStuck", err)
	}
	if got := runner.startCount(); got != 1 {
		process.exit(nil)
		t.Fatalf("Start calls while old Wait is open = %d, want 1", got)
	}

	process.exit(nil)
	waitForStatus(t, service, domain.ConnectionStatusDisconnected)
}

func TestDisconnectUsesGraceAndKillWithinOneTotalDeadline(t *testing.T) {
	process := newFakeProcess(false)
	runner := newFakeRunner()
	runner.start = func(int, context.Context, *core.PreparedConfig) (core.Process, error) { return process, nil }
	stopTimeout := 40 * time.Millisecond
	service := newTestService(t, runner, stopTimeout)
	if _, err := service.Connect(context.Background(), connectionRequest(domain.ConnectionModeTUN, domain.RouteModeGlobal)); err != nil {
		t.Fatal(err)
	}

	started := time.Now()
	status, err := service.Disconnect(context.Background())
	elapsed := time.Since(started)
	if err != nil {
		t.Fatalf("Disconnect() failed: %v", err)
	}
	if elapsed < stopTimeout/2 || elapsed > stopTimeout+100*time.Millisecond {
		t.Fatalf("Disconnect() elapsed = %s, want graceful phase and total deadline %s", elapsed, stopTimeout)
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

func TestReplacementWaitsForOldExitAndOldMonitorCannotClobberStatus(t *testing.T) {
	oldProcess := newStubbornFakeProcess()
	oldProcess.killObserved = make(chan struct{})
	newProcess := newFakeProcess(false)
	runner := newFakeRunner()
	runner.start = func(call int, _ context.Context, _ *core.PreparedConfig) (core.Process, error) {
		if call == 1 {
			return oldProcess, nil
		}
		return newProcess, nil
	}
	service := newTestService(t, runner, 120*time.Millisecond)
	if _, err := service.Connect(context.Background(), connectionRequest(domain.ConnectionModeTUN, domain.RouteModeGlobal)); err != nil {
		t.Fatal(err)
	}

	done := make(chan error, 1)
	go func() {
		_, err := service.Connect(context.Background(), connectionRequest(domain.ConnectionModeTUN, domain.RouteModeRule))
		done <- err
	}()
	select {
	case <-oldProcess.killObserved:
	case <-time.After(time.Second):
		oldProcess.exit(nil)
		t.Fatal("replacement did not reach kill phase")
	}
	time.Sleep(20 * time.Millisecond)
	if got := runner.startCount(); got != 1 {
		oldProcess.exit(nil)
		t.Fatalf("Start calls before old Wait completed = %d, want 1", got)
	}
	select {
	case err := <-done:
		oldProcess.exit(nil)
		t.Fatalf("replacement returned before old Wait completed: %v", err)
	default:
	}

	oldProcess.exit(errors.New("old generation exit"))
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("replacement Connect() failed: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("replacement did not start after old Wait completed")
	}
	status := mustServiceStatus(t, service)
	if status.State != domain.ConnectionStatusConnected || status.Route != domain.RouteModeRule {
		t.Fatalf("old monitor changed replacement status: %#v", status)
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

func TestServiceCloseWaitsForMonitorBeforeClosingRunner(t *testing.T) {
	process := newFakeProcess(true)
	runner := newFakeRunner()
	runner.start = func(int, context.Context, *core.PreparedConfig) (core.Process, error) { return process, nil }
	var service *Service
	runner.close = func() error {
		select {
		case <-service.gate:
			service.gate <- struct{}{}
			return nil
		default:
			return errors.New("runner closed while monitor was blocked by service gate")
		}
	}
	service = newTestService(t, runner, 80*time.Millisecond)
	if _, err := service.Connect(context.Background(), connectionRequest(domain.ConnectionModeTUN, domain.RouteModeGlobal)); err != nil {
		t.Fatal(err)
	}

	if err := service.Close(); err != nil {
		t.Fatalf("Close() failed: %v", err)
	}
	if runner.closeCount() != 1 {
		t.Fatalf("runner Close calls = %d, want 1 after monitor completion", runner.closeCount())
	}
}

func TestServiceCloseBoundsMonitorWaitAndDefersRunnerClose(t *testing.T) {
	process := newStubbornFakeProcess()
	runner := newFakeRunner()
	runner.start = func(int, context.Context, *core.PreparedConfig) (core.Process, error) { return process, nil }
	stopTimeout := 80 * time.Millisecond
	service := newTestService(t, runner, stopTimeout)
	if _, err := service.Connect(context.Background(), connectionRequest(domain.ConnectionModeTUN, domain.RouteModeGlobal)); err != nil {
		t.Fatal(err)
	}

	started := time.Now()
	if err := service.Close(); !errors.Is(err, rpc.ErrProcessStuck) {
		process.exit(nil)
		t.Fatalf("Close() error = %v, want ErrProcessStuck", err)
	}
	if elapsed := time.Since(started); elapsed > stopTimeout+50*time.Millisecond {
		process.exit(nil)
		t.Fatalf("Close() took %s, want the single total stop deadline %s", elapsed, stopTimeout)
	}
	if got := runner.closeCount(); got != 0 {
		process.exit(nil)
		t.Fatalf("runner Close calls before monitor exit = %d, want 0", got)
	}
	if service.active == nil || service.active.process != process {
		process.exit(nil)
		t.Fatal("Close() stopped tracking process whose Wait is still open")
	}

	process.exit(nil)
	deadline := time.Now().Add(time.Second)
	for runner.closeCount() == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if got := runner.closeCount(); got != 1 {
		t.Fatalf("runner Close calls after late monitor exit = %d, want 1", got)
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
	close func() error
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
	runner.closeCalls++
	closeRunner := runner.close
	runner.mu.Unlock()
	if closeRunner != nil {
		return closeRunner()
	}
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

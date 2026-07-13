//go:build darwin || linux

package daemon

import (
	"context"
	"errors"
	"os"
	"sync"
	"syscall"
	"time"

	"github.com/rezraf/tui-box/internal/core"
	"github.com/rezraf/tui-box/internal/domain"
	"github.com/rezraf/tui-box/internal/rpc"
)

const maxStopTimeout = 5 * time.Minute

type Service struct {
	runner      core.Runner
	stopTimeout time.Duration
	lifetime    context.Context
	cancel      context.CancelFunc

	gate       chan struct{}
	closed     bool
	generation uint64
	active     *session
	status     rpc.SessionStatus

	closeOnce sync.Once
	closeErr  error
}

type session struct {
	generation uint64
	mode       domain.ConnectionMode
	route      domain.RouteMode
	prepared   *core.PreparedConfig
	process    core.Process
	done       chan struct{}
	stopping   bool
}

func NewService(runner core.Runner, stopTimeout time.Duration) (*Service, error) {
	if runner == nil || stopTimeout <= 0 || stopTimeout > maxStopTimeout {
		return nil, rpc.ErrInvalidRequest
	}
	lifetime, cancel := context.WithCancel(context.Background())
	gate := make(chan struct{}, 1)
	gate <- struct{}{}
	return &Service{
		runner:      runner,
		stopTimeout: stopTimeout,
		lifetime:    lifetime,
		cancel:      cancel,
		gate:        gate,
		status:      rpc.SessionStatus{State: domain.ConnectionStatusDisconnected},
	}, nil
}

func (service *Service) acquire(ctx context.Context) (func(), error) {
	if service == nil || ctx == nil {
		return nil, rpc.ErrInvalidRequest
	}
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-service.gate:
	}
	if err := ctx.Err(); err != nil {
		service.gate <- struct{}{}
		return nil, err
	}
	return func() { service.gate <- struct{}{} }, nil
}

func (service *Service) Connect(ctx context.Context, request core.ConnectionRequest) (rpc.SessionStatus, error) {
	release, err := service.acquire(ctx)
	if err != nil {
		return rpc.SessionStatus{}, err
	}
	defer release()
	if service.closed {
		return service.status, rpc.ErrUnavailable
	}

	old := service.active
	oldStatus := service.status
	prepared, err := service.runner.Prepare(request)
	if err != nil || prepared == nil {
		service.recordConnectFailureLocked(old, request)
		return service.status, rpc.ErrCoreValidation
	}
	if err := service.runner.Check(ctx, prepared); err != nil {
		_ = prepared.Close()
		if contextErr := ctx.Err(); contextErr != nil {
			return service.status, contextErr
		}
		service.recordConnectFailureLocked(old, request)
		return service.status, rpc.ErrCoreValidation
	}
	if err := ctx.Err(); err != nil {
		_ = prepared.Close()
		return service.status, err
	}

	if old != nil {
		if err := ctx.Err(); err != nil {
			_ = prepared.Close()
			return service.status, err
		}
		old.stopping = true
		service.status.State = domain.ConnectionStatusDisconnecting
		stopped, stopErr := service.stopSession(ctx, old)
		if stopped {
			service.active = nil
		}
		if stopErr != nil {
			_ = prepared.Close()
			if stopped {
				_ = old.prepared.Close()
				service.status = rpc.SessionStatus{State: domain.ConnectionStatusDisconnected}
			} else {
				old.stopping = false
				service.status.State = domain.ConnectionStatusFailed
			}
			return service.status, stopErr
		}
	}
	service.status = rpc.SessionStatus{
		State: domain.ConnectionStatusConnecting,
		Mode:  request.Mode,
		Route: request.Route,
	}
	process, err := service.runner.Start(service.lifetime, prepared)
	if err != nil || process == nil {
		_ = prepared.Close()
		if old != nil {
			rollback, rollbackErr := service.runner.Start(service.lifetime, old.prepared)
			if rollbackErr == nil && rollback != nil {
				service.installSessionLocked(old.mode, old.route, old.prepared, rollback, oldStatus)
				return service.status, rpc.ErrProcessFailure
			}
			_ = old.prepared.Close()
		}
		service.status = rpc.SessionStatus{
			State: domain.ConnectionStatusFailed,
			Mode:  request.Mode,
			Route: request.Route,
		}
		return service.status, rpc.ErrProcessFailure
	}

	service.installSessionLocked(request.Mode, request.Route, prepared, process, rpc.SessionStatus{
		State: domain.ConnectionStatusConnected,
		Mode:  request.Mode,
		Route: request.Route,
	})
	if old != nil {
		_ = old.prepared.Close()
	}
	return service.status, nil
}

func (service *Service) recordConnectFailureLocked(old *session, request core.ConnectionRequest) {
	if old != nil {
		return
	}
	service.status = rpc.SessionStatus{
		State: domain.ConnectionStatusFailed,
		Mode:  request.Mode,
		Route: request.Route,
	}
}

func (service *Service) installSessionLocked(mode domain.ConnectionMode, route domain.RouteMode, prepared *core.PreparedConfig, process core.Process, status rpc.SessionStatus) {
	service.generation++
	current := &session{
		generation: service.generation,
		mode:       mode,
		route:      route,
		prepared:   prepared,
		process:    process,
		done:       make(chan struct{}),
	}
	service.active = current
	service.status = status
	go service.monitor(current)
}

func (service *Service) monitor(current *session) {
	_ = current.process.Wait()
	close(current.done)

	release, err := service.acquire(context.Background())
	if err != nil {
		return
	}
	defer release()
	if service.closed || service.active != current || service.generation != current.generation || current.stopping {
		return
	}
	service.active = nil
	service.status = rpc.SessionStatus{
		State: domain.ConnectionStatusFailed,
		Mode:  current.mode,
		Route: current.route,
	}
	_ = current.prepared.Close()
}

func (service *Service) Disconnect(ctx context.Context) (rpc.SessionStatus, error) {
	release, err := service.acquire(ctx)
	if err != nil {
		return rpc.SessionStatus{}, err
	}
	defer release()
	if service.closed {
		return service.status, rpc.ErrUnavailable
	}
	if service.active == nil {
		service.status = rpc.SessionStatus{State: domain.ConnectionStatusDisconnected}
		return service.status, nil
	}

	if err := ctx.Err(); err != nil {
		return service.status, err
	}
	current := service.active
	current.stopping = true
	service.status.State = domain.ConnectionStatusDisconnecting
	stopped, stopErr := service.stopSession(ctx, current)
	if stopped {
		service.active = nil
		_ = current.prepared.Close()
		service.status = rpc.SessionStatus{State: domain.ConnectionStatusDisconnected}
		return service.status, stopErr
	}
	current.stopping = false
	service.status.State = domain.ConnectionStatusFailed
	return service.status, stopErr
}

func (service *Service) stopSession(ctx context.Context, current *session) (bool, error) {
	timer := time.NewTimer(service.stopTimeout)
	defer timer.Stop()

	signalErr := current.process.Signal(syscall.SIGTERM)
	if signalErr != nil && !errors.Is(signalErr, os.ErrProcessDone) {
		// Continue to the single bounded wait and kill path.
	}

	select {
	case <-current.done:
		return true, ctx.Err()
	case <-ctx.Done():
		return killStoppedSession(current, ctx.Err())
	case <-timer.C:
		return killStoppedSession(current, ctx.Err())
	}
}

func killStoppedSession(current *session, cause error) (bool, error) {
	killErr := current.process.Kill()
	if killErr != nil && !errors.Is(killErr, os.ErrProcessDone) {
		if cause != nil {
			return false, cause
		}
		return false, rpc.ErrProcessFailure
	}
	return true, cause
}

func (service *Service) Status(ctx context.Context) (rpc.SessionStatus, error) {
	release, err := service.acquire(ctx)
	if err != nil {
		return rpc.SessionStatus{}, err
	}
	defer release()
	if service.closed {
		return service.status, rpc.ErrUnavailable
	}
	return service.status, nil
}

func (service *Service) Health(ctx context.Context) error {
	release, err := service.acquire(ctx)
	if err != nil {
		return err
	}
	defer release()
	if service.closed {
		return rpc.ErrUnavailable
	}
	return nil
}

func (service *Service) Close() error {
	if service == nil {
		return nil
	}
	service.closeOnce.Do(func() {
		release, err := service.acquire(context.Background())
		if err != nil {
			service.closeErr = err
			return
		}
		defer release()
		service.closed = true
		var closeErrors []error
		if service.active != nil {
			current := service.active
			current.stopping = true
			service.status.State = domain.ConnectionStatusDisconnecting
			stopped, stopErr := service.stopSession(context.Background(), current)
			if stopErr != nil {
				closeErrors = append(closeErrors, stopErr)
				service.status.State = domain.ConnectionStatusFailed
			} else {
				service.status = rpc.SessionStatus{State: domain.ConnectionStatusDisconnected}
			}
			if stopped {
				service.active = nil
			}
			if err := current.prepared.Close(); err != nil {
				closeErrors = append(closeErrors, err)
			}
		}
		service.cancel()
		if err := service.runner.Close(); err != nil {
			closeErrors = append(closeErrors, err)
		}
		service.closeErr = errors.Join(closeErrors...)
	})
	return service.closeErr
}

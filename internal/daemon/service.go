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

	mu         sync.Mutex
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
	done       chan error
	stopping   bool
}

func NewService(runner core.Runner, stopTimeout time.Duration) (*Service, error) {
	if runner == nil || stopTimeout <= 0 || stopTimeout > maxStopTimeout {
		return nil, rpc.ErrInvalidRequest
	}
	lifetime, cancel := context.WithCancel(context.Background())
	return &Service{
		runner:      runner,
		stopTimeout: stopTimeout,
		lifetime:    lifetime,
		cancel:      cancel,
		status:      rpc.SessionStatus{State: domain.ConnectionStatusDisconnected},
	}, nil
}

func (service *Service) Connect(ctx context.Context, request core.ConnectionRequest) (rpc.SessionStatus, error) {
	if service == nil || ctx == nil {
		return rpc.SessionStatus{}, rpc.ErrInvalidRequest
	}
	if err := ctx.Err(); err != nil {
		return rpc.SessionStatus{}, err
	}

	service.mu.Lock()
	defer service.mu.Unlock()
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
		old.stopping = true
		service.status.State = domain.ConnectionStatusDisconnecting
		if err := service.stopSessionLocked(old); err != nil {
			old.stopping = false
			_ = prepared.Close()
			service.status.State = domain.ConnectionStatusFailed
			return service.status, rpc.ErrProcessFailure
		}
		service.active = nil
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
		done:       make(chan error, 1),
	}
	service.active = current
	service.status = status
	go service.monitor(current)
}

func (service *Service) monitor(current *session) {
	waitErr := current.process.Wait()
	current.done <- waitErr
	close(current.done)

	service.mu.Lock()
	defer service.mu.Unlock()
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
	if service == nil || ctx == nil {
		return rpc.SessionStatus{}, rpc.ErrInvalidRequest
	}
	if err := ctx.Err(); err != nil {
		return rpc.SessionStatus{}, err
	}

	service.mu.Lock()
	defer service.mu.Unlock()
	if service.closed {
		return service.status, rpc.ErrUnavailable
	}
	if service.active == nil {
		service.status = rpc.SessionStatus{State: domain.ConnectionStatusDisconnected}
		return service.status, nil
	}

	current := service.active
	current.stopping = true
	service.status.State = domain.ConnectionStatusDisconnecting
	if err := service.stopSessionLocked(current); err != nil {
		current.stopping = false
		service.status.State = domain.ConnectionStatusFailed
		return service.status, rpc.ErrProcessFailure
	}
	service.active = nil
	_ = current.prepared.Close()
	service.status = rpc.SessionStatus{State: domain.ConnectionStatusDisconnected}
	return service.status, nil
}

func (service *Service) stopSessionLocked(current *session) error {
	signalErr := current.process.Signal(syscall.SIGTERM)
	if signalErr != nil && !errors.Is(signalErr, os.ErrProcessDone) {
		// Continue to the bounded wait and kill path.
	}

	timer := time.NewTimer(service.stopTimeout)
	defer timer.Stop()
	select {
	case <-current.done:
		return nil
	case <-timer.C:
	}

	killErr := current.process.Kill()
	if killErr != nil && !errors.Is(killErr, os.ErrProcessDone) {
		return rpc.ErrProcessFailure
	}
	killTimer := time.NewTimer(service.stopTimeout)
	defer killTimer.Stop()
	select {
	case <-current.done:
		return nil
	case <-killTimer.C:
		return rpc.ErrProcessFailure
	}
}

func (service *Service) Status(context.Context) rpc.SessionStatus {
	if service == nil {
		return rpc.SessionStatus{State: domain.ConnectionStatusFailed}
	}
	service.mu.Lock()
	defer service.mu.Unlock()
	return service.status
}

func (service *Service) Health(ctx context.Context) error {
	if service == nil || ctx == nil {
		return rpc.ErrInvalidRequest
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	service.mu.Lock()
	defer service.mu.Unlock()
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
		service.mu.Lock()
		service.closed = true
		var closeErrors []error
		if service.active != nil {
			current := service.active
			current.stopping = true
			service.status.State = domain.ConnectionStatusDisconnecting
			if err := service.stopSessionLocked(current); err != nil {
				closeErrors = append(closeErrors, err)
				service.status.State = domain.ConnectionStatusFailed
			} else {
				service.status = rpc.SessionStatus{State: domain.ConnectionStatusDisconnected}
			}
			service.active = nil
			if err := current.prepared.Close(); err != nil {
				closeErrors = append(closeErrors, err)
			}
		}
		service.cancel()
		if err := service.runner.Close(); err != nil {
			closeErrors = append(closeErrors, err)
		}
		service.closeErr = errors.Join(closeErrors...)
		service.mu.Unlock()
	})
	return service.closeErr
}

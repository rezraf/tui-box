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

	monitorWait sync.WaitGroup

	closeOnce       sync.Once
	runnerCloseOnce sync.Once
	closeErr        error
	runnerCloseErr  error
}

type session struct {
	generation       uint64
	mode             domain.ConnectionMode
	route            domain.RouteMode
	prepared         *core.PreparedConfig
	process          core.Process
	done             chan struct{}
	cancel           context.CancelFunc
	stopping         bool
	rollbackPrevious *session
	rollbackStatus   rpc.SessionStatus
	failedOnExit     bool
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

	if service.active != nil && service.active.stopping {
		return service.status, rpc.ErrProcessStuck
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
		old.rollbackPrevious = old
		old.rollbackStatus = oldStatus
		service.status.State = domain.ConnectionStatusDisconnecting
		reaped, stopErr := service.stopSession(ctx, old)
		if !reaped {
			_ = prepared.Close()
			return service.status, stopErr
		}
		service.active = nil
		old.rollbackPrevious = nil
		if old.cancel != nil {
			old.cancel()
		}
		if stopErr != nil {
			_ = prepared.Close()
			if rollbackErr := service.rollbackLocked(old, oldStatus); rollbackErr != nil {
				return service.status, errors.Join(stopErr, rollbackErr)
			}
			return service.status, stopErr
		}
	}
	service.status = rpc.SessionStatus{
		State: domain.ConnectionStatusConnecting,
		Mode:  request.Mode,
		Route: request.Route,
	}
	if old != nil {
		if contextErr := ctx.Err(); contextErr != nil {
			_ = prepared.Close()
			if rollbackErr := service.rollbackLocked(old, oldStatus); rollbackErr != nil {
				return service.status, errors.Join(contextErr, rollbackErr)
			}
			return service.status, contextErr
		}
	}
	process, err := service.runner.Start(service.lifetime, prepared)
	if err != nil || process == nil {
		_ = prepared.Close()
		startErr := error(rpc.ErrProcessFailure)
		if contextErr := ctx.Err(); contextErr != nil {
			startErr = contextErr
		}
		if old != nil {
			if rollbackErr := service.rollbackLocked(old, oldStatus); rollbackErr == nil {
				return service.status, startErr
			} else {
				return service.status, errors.Join(startErr, rollbackErr)
			}
		}
		service.status = rpc.SessionStatus{
			State: domain.ConnectionStatusFailed,
			Mode:  request.Mode,
			Route: request.Route,
		}
		return service.status, startErr
	}

	if contextErr := ctx.Err(); contextErr != nil {
		service.installSessionLocked(request.Mode, request.Route, prepared, process, nil, service.status)
		current := service.active
		current.stopping = true
		current.rollbackPrevious = old
		current.rollbackStatus = oldStatus
		service.status.State = domain.ConnectionStatusDisconnecting
		reaped, stopErr := service.stopSession(ctx, current)
		if !reaped {
			return service.status, stopErr
		}
		service.active = nil
		current.rollbackPrevious = nil
		_ = current.prepared.Close()
		if old != nil {
			if rollbackErr := service.rollbackLocked(old, oldStatus); rollbackErr != nil {
				return service.status, errors.Join(contextErr, stopErr, rollbackErr)
			}
		} else {
			service.status = rpc.SessionStatus{State: domain.ConnectionStatusDisconnected}
		}
		return service.status, errors.Join(contextErr, stopErr)
	}
	service.installSessionLocked(request.Mode, request.Route, prepared, process, nil, rpc.SessionStatus{
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

func (service *Service) rollbackLocked(previous *session, previousStatus rpc.SessionStatus) error {
	rollbackContext, rollbackCancel := context.WithCancel(service.lifetime)
	timer := time.AfterFunc(service.stopTimeout, rollbackCancel)
	process, err := service.runner.Start(rollbackContext, previous.prepared)
	if !timer.Stop() || rollbackContext.Err() != nil || err != nil || process == nil {
		if process != nil {
			rollbackCancel()
			service.installSessionLocked(previous.mode, previous.route, previous.prepared, process, rollbackCancel, rpc.SessionStatus{
				State: domain.ConnectionStatusDisconnecting,
				Mode:  previous.mode,
				Route: previous.route,
			})
			service.active.stopping = true
			service.active.failedOnExit = true
			_ = process.Kill()
			return errors.Join(rpc.ErrRollbackFailure, rpc.ErrProcessStuck)
		}
		rollbackCancel()
		_ = previous.prepared.Close()
		service.status = rpc.SessionStatus{
			State: domain.ConnectionStatusFailed,
			Mode:  previous.mode,
			Route: previous.route,
		}
		return rpc.ErrRollbackFailure
	}
	service.installSessionLocked(previous.mode, previous.route, previous.prepared, process, rollbackCancel, previousStatus)
	return nil
}

func (service *Service) installSessionLocked(mode domain.ConnectionMode, route domain.RouteMode, prepared *core.PreparedConfig, process core.Process, processCancel context.CancelFunc, status rpc.SessionStatus) {
	service.generation++
	current := &session{
		generation: service.generation,
		mode:       mode,
		route:      route,
		prepared:   prepared,
		process:    process,
		done:       make(chan struct{}),
		cancel:     processCancel,
	}
	service.active = current
	service.status = status
	service.monitorWait.Add(1)
	go service.monitor(current)
}

func (service *Service) monitor(current *session) {
	defer service.monitorWait.Done()
	_ = current.process.Wait()
	close(current.done)

	release, err := service.acquire(context.Background())
	if err != nil {
		return
	}
	defer release()
	if service.active != current || service.generation != current.generation {
		return
	}
	service.active = nil
	if current.cancel != nil {
		current.cancel()
	}
	if current.stopping && current.rollbackPrevious != nil && !service.closed {
		previous := current.rollbackPrevious
		current.rollbackPrevious = nil
		if current != previous {
			_ = current.prepared.Close()
		}
		_ = service.rollbackLocked(previous, current.rollbackStatus)
		return
	}
	if current.failedOnExit {
		service.status = rpc.SessionStatus{
			State: domain.ConnectionStatusFailed,
			Mode:  current.mode,
			Route: current.route,
		}
	} else if service.closed || current.stopping {
		service.status = rpc.SessionStatus{State: domain.ConnectionStatusDisconnected}
	} else {
		service.status = rpc.SessionStatus{
			State: domain.ConnectionStatusFailed,
			Mode:  current.mode,
			Route: current.route,
		}
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
	if service.active.stopping {
		return service.status, rpc.ErrProcessStuck
	}
	if err := ctx.Err(); err != nil {
		return service.status, err
	}
	current := service.active
	current.stopping = true
	service.status.State = domain.ConnectionStatusDisconnecting
	reaped, stopErr := service.stopSession(ctx, current)
	if !reaped {
		return service.status, stopErr
	}
	service.active = nil
	if current.cancel != nil {
		current.cancel()
	}
	_ = current.prepared.Close()
	service.status = rpc.SessionStatus{State: domain.ConnectionStatusDisconnected}
	return service.status, stopErr
}

func (service *Service) stopSession(ctx context.Context, current *session) (bool, error) {
	return service.stopSessionUntil(ctx, current, time.Now().Add(service.stopTimeout))
}

func (service *Service) stopSessionUntil(ctx context.Context, current *session, deadline time.Time) (bool, error) {
	graceTimer := time.NewTimer(max(time.Until(deadline)/2, 0))
	defer graceTimer.Stop()

	var stopErr error
	if err := current.process.Signal(syscall.SIGTERM); err != nil && !errors.Is(err, os.ErrProcessDone) {
		stopErr = rpc.ErrProcessFailure
	}

	select {
	case <-current.done:
		return true, errors.Join(stopErr, ctx.Err())
	case <-ctx.Done():
		stopErr = errors.Join(stopErr, ctx.Err())
	case <-graceTimer.C:
	}

	if err := current.process.Kill(); err != nil && !errors.Is(err, os.ErrProcessDone) {
		stopErr = errors.Join(stopErr, rpc.ErrProcessFailure)
	}
	remaining := time.Until(deadline)
	if remaining <= 0 {
		select {
		case <-current.done:
			return true, errors.Join(stopErr, ctx.Err())
		default:
			return false, errors.Join(stopErr, ctx.Err(), rpc.ErrProcessStuck)
		}
	}

	killTimer := time.NewTimer(remaining)
	defer killTimer.Stop()
	select {
	case <-current.done:
		return true, errors.Join(stopErr, ctx.Err())
	case <-killTimer.C:
		return false, errors.Join(stopErr, ctx.Err(), rpc.ErrProcessStuck)
	}
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

		service.closed = true
		stopDeadline := time.Now().Add(service.stopTimeout)
		var closeErrors []error
		if service.active != nil {
			current := service.active
			current.stopping = true
			current.rollbackPrevious = nil
			service.status.State = domain.ConnectionStatusDisconnecting
			reaped, stopErr := service.stopSessionUntil(context.Background(), current, stopDeadline)
			if stopErr != nil {
				closeErrors = append(closeErrors, stopErr)
			}
			if reaped {
				service.active = nil
				if current.cancel != nil {
					current.cancel()
				}
				if err := current.prepared.Close(); err != nil {
					closeErrors = append(closeErrors, err)
				}
				service.status = rpc.SessionStatus{State: domain.ConnectionStatusDisconnected}
			}
		}
		service.cancel()
		release()

		monitorsDone := make(chan struct{})
		go func() {
			service.monitorWait.Wait()
			close(monitorsDone)
		}()
		monitorsFinished := false
		if remaining := time.Until(stopDeadline); remaining > 0 {
			timer := time.NewTimer(remaining)
			select {
			case <-monitorsDone:
				monitorsFinished = true
			case <-timer.C:
			}
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
		} else {
			select {
			case <-monitorsDone:
				monitorsFinished = true
			default:
			}
		}
		if monitorsFinished {
			if err := service.closeRunner(); err != nil {
				closeErrors = append(closeErrors, err)
			}
		} else {
			closeErrors = append(closeErrors, rpc.ErrProcessStuck)
			go func() {
				<-monitorsDone
				_ = service.closeRunner()
			}()
		}
		service.closeErr = errors.Join(closeErrors...)
	})
	return service.closeErr
}

func (service *Service) closeRunner() error {
	service.runnerCloseOnce.Do(func() {
		service.runnerCloseErr = service.runner.Close()
	})
	return service.runnerCloseErr
}

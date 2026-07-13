package tui

import (
	"context"
	"errors"
	"strings"

	"github.com/rezraf/tui-box/internal/app"
	"github.com/rezraf/tui-box/internal/domain"
	"github.com/rezraf/tui-box/internal/latency"
	"github.com/rezraf/tui-box/internal/redact"
	"github.com/rezraf/tui-box/internal/rpc"
	"github.com/rezraf/tui-box/internal/subscription"
	"github.com/rezraf/tui-box/internal/terminaltext"
)

var (
	ErrInvalidConfiguration = errors.New("TUI configuration is invalid")
	ErrOperationFailed      = errors.New("operation failed")
)

type Application interface {
	AddSubscription(context.Context, string, string) (app.SubscriptionView, []subscription.Warning, error)
	UpdateSubscriptions(context.Context, string) ([]app.RefreshResult, error)
	ListServers(context.Context) ([]app.ServerView, error)
	CheckLatency(context.Context, string, bool) ([]latency.Result, error)
	Connect(context.Context, string, domain.ConnectionMode, domain.RouteMode) (rpc.SessionStatus, error)
	Disconnect(context.Context) (rpc.SessionStatus, error)
	Status(context.Context) (rpc.SessionStatus, error)
}

type backend interface {
	Snapshot(context.Context) (snapshot, error)
	AddSubscription(context.Context, string, string) ([]Server, error)
	Refresh(context.Context) ([]Server, error)
	CheckLatency(context.Context) ([]Server, error)
	Connect(context.Context, string, domain.ConnectionMode, domain.RouteMode) (rpc.SessionStatus, error)
	Disconnect(context.Context) (rpc.SessionStatus, error)
}

type Adapter struct {
	application Application
}

func NewAdapter(application Application) (*Adapter, error) {
	if application == nil {
		return nil, ErrInvalidConfiguration
	}
	return &Adapter{application: application}, nil
}

func (adapter *Adapter) Snapshot(ctx context.Context) (snapshot, error) {
	servers, err := adapter.servers(ctx)
	if err != nil {
		return snapshot{}, err
	}
	status, err := adapter.application.Status(ctx)
	return snapshot{Servers: servers, Status: safeStatus(status)}, err
}

func (adapter *Adapter) AddSubscription(ctx context.Context, name, url string) ([]Server, error) {
	if _, _, err := adapter.application.AddSubscription(ctx, name, url); err != nil {
		return nil, err
	}
	return adapter.servers(ctx)
}

func (adapter *Adapter) Refresh(ctx context.Context) ([]Server, error) {
	if _, err := adapter.application.UpdateSubscriptions(ctx, ""); err != nil {
		return nil, err
	}
	return adapter.servers(ctx)
}

func (adapter *Adapter) CheckLatency(ctx context.Context) ([]Server, error) {
	if _, err := adapter.application.CheckLatency(ctx, "", true); err != nil {
		return nil, err
	}
	return adapter.servers(ctx)
}

func (adapter *Adapter) Connect(ctx context.Context, target string, mode domain.ConnectionMode, route domain.RouteMode) (rpc.SessionStatus, error) {
	status, err := adapter.application.Connect(ctx, target, mode, route)
	return safeStatus(status), err
}

func (adapter *Adapter) Disconnect(ctx context.Context) (rpc.SessionStatus, error) {
	status, err := adapter.application.Disconnect(ctx)
	return safeStatus(status), err
}

func (adapter *Adapter) servers(ctx context.Context) ([]Server, error) {
	views, err := adapter.application.ListServers(ctx)
	if err != nil {
		return nil, err
	}
	servers := make([]Server, 0, len(views))
	for _, view := range views {
		if !validIdentifier(view.ID) {
			continue
		}
		servers = append(servers, Server{
			ID:       view.ID,
			Name:     safeLabel(view.Name, "Endpoint"),
			Protocol: safeProtocol(view.Protocol),
			Latency:  safeLatency(view.Latency),
		})
	}
	return servers, nil
}

func validIdentifier(value string) bool {
	if value == "" || len(value) > domain.MaxIDLength {
		return false
	}
	for _, character := range value {
		if character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z' ||
			character >= '0' && character <= '9' || character == '-' || character == '_' || character == '.' {
			continue
		}
		return false
	}
	return true
}

func safeLabel(value, fallback string) string {
	value = strings.TrimSpace(value)
	if value == "" || len(value) > domain.MaxNameLength || !terminaltext.Valid(value) {
		return fallback
	}
	lower := strings.ToLower(value)
	for _, marker := range []string{"secretref", "secret_ref", "credential", "password", "token", "transport", "tls", "rpc"} {
		if strings.Contains(lower, marker) {
			return fallback
		}
	}
	if redact.String(value) != value {
		return fallback
	}
	return value
}

func safeProtocol(protocol domain.Protocol) domain.Protocol {
	switch protocol {
	case domain.ProtocolVLESS, domain.ProtocolVMess, domain.ProtocolTrojan, domain.ProtocolShadowsocks, domain.ProtocolHysteria2, domain.ProtocolTUIC:
		return protocol
	default:
		return ""
	}
}

func safeLatency(result *latency.Result) *latency.Result {
	if result == nil {
		return nil
	}
	projected := &latency.Result{Status: result.Status}
	switch result.Status {
	case latency.StatusSuccess:
		if result.Duration < 0 {
			projected.Status = latency.StatusUnavailable
		} else {
			projected.Duration = result.Duration
		}
	case latency.StatusUnavailable, latency.StatusUnsupported:
	default:
		projected.Status = latency.StatusUnavailable
	}
	return projected
}

var safeErrors = []error{
	context.Canceled,
	context.DeadlineExceeded,
	app.ErrInvalidConfiguration,
	app.ErrInvalidInput,
	app.ErrSubscriptionNotFound,
	app.ErrServerNotFound,
	app.ErrStateOperation,
	app.ErrSecretOperation,
	app.ErrRefreshFailed,
	app.ErrUpdaterUnavailable,
	rpc.ErrInvalidRequest,
	rpc.ErrUnsupportedVersion,
	rpc.ErrAccessDenied,
	rpc.ErrCoreValidation,
	rpc.ErrProcessFailure,
	rpc.ErrProcessStuck,
	rpc.ErrRollbackFailure,
	rpc.ErrUnavailable,
	rpc.ErrTimeout,
	rpc.ErrInternal,
	rpc.ErrInvalidResponse,
}

func safeError(source error) error {
	for _, known := range safeErrors {
		if errors.Is(source, known) {
			return known
		}
	}
	return ErrOperationFailed
}

func safeErrorMessage(source error) string {
	return safeError(source).Error()
}

func safeStatus(status rpc.SessionStatus) rpc.SessionStatus {
	projected := rpc.SessionStatus{State: status.State}
	switch status.State {
	case domain.ConnectionStatusDisconnected, domain.ConnectionStatusConnecting, domain.ConnectionStatusConnected,
		domain.ConnectionStatusDisconnecting, domain.ConnectionStatusFailed:
	default:
		projected.State = domain.ConnectionStatusFailed
	}
	if status.Mode == domain.ConnectionModeTUN || status.Mode == domain.ConnectionModeProxy {
		projected.Mode = status.Mode
	}
	if status.Route == domain.RouteModeGlobal || status.Route == domain.RouteModeRule || status.Route == domain.RouteModeDirect {
		projected.Route = status.Route
	}
	return projected
}

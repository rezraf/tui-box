package app

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/rezraf/tui-box/internal/domain"
	"github.com/rezraf/tui-box/internal/latency"
	"github.com/rezraf/tui-box/internal/redact"
	"github.com/rezraf/tui-box/internal/rpc"
	"github.com/rezraf/tui-box/internal/secrets"
	"github.com/rezraf/tui-box/internal/state"
	"github.com/rezraf/tui-box/internal/subscription"
	"github.com/rezraf/tui-box/internal/terminaltext"
)

const (
	AutoTarget               = "auto"
	compensationTimeout      = 2 * time.Second
	maxVersionBytes          = 128
	endpointIdentityKeyBytes = 32
)

var (
	ErrInvalidConfiguration = errors.New("app configuration is invalid")
	ErrInvalidInput         = errors.New("input is invalid")
	ErrSubscriptionNotFound = errors.New("subscription was not found")
	ErrServerNotFound       = errors.New("server was not found")
	ErrStateOperation       = errors.New("application state operation failed")
	ErrSecretOperation      = errors.New("subscription credential operation failed")
	ErrRefreshFailed        = errors.New("subscription refresh failed")
	ErrRefreshStale         = errors.New("subscription refresh was superseded")
	ErrUpdaterUnavailable   = errors.New("updater is unavailable")

	safeDaemonErrors = [...]error{
		rpc.ErrInvalidRequest, rpc.ErrUnsupportedVersion, rpc.ErrAccessDenied, rpc.ErrCoreValidation,
		rpc.ErrProcessFailure, rpc.ErrProcessStuck, rpc.ErrRollbackFailure, rpc.ErrUnavailable,
		rpc.ErrTimeout, rpc.ErrInternal, rpc.ErrInvalidResponse,
	}
)

type StateStore interface {
	LoadContext(context.Context) (state.Snapshot, error)
	UpdateContext(context.Context, func(*state.Snapshot) error) error
}

type SecretStore interface {
	Get(context.Context, string) (string, error)
	Set(context.Context, string, string) error
	Delete(context.Context, string) error
}

type SubscriptionFetcher interface {
	Fetch(context.Context, string) ([]byte, error)
}

type LatencyChecker interface {
	Check(context.Context, []domain.Endpoint) []latency.Result
}

type DaemonClient interface {
	Connect(context.Context, rpc.ConnectPayload) (rpc.SessionStatus, error)
	Disconnect(context.Context) (rpc.SessionStatus, error)
	Status(context.Context) (rpc.SessionStatus, error)
	Health(context.Context) error
}

type Updater interface {
	Check(context.Context) (UpdateInfo, error)
	Apply(context.Context, UpdateInfo) error
}

type ParseFunc func(string, []byte) (subscription.ParseResult, error)
type IDGenerator func() (string, error)
type IdentityKeyGenerator func() ([]byte, error)
type Clock func() time.Time

type Config struct {
	State                StateStore
	Secrets              SecretStore
	SecretBackend        secrets.BackendInfo
	Fetcher              SubscriptionFetcher
	Parse                ParseFunc
	Latency              LatencyChecker
	Daemon               DaemonClient
	Updater              Updater
	GenerateID           IDGenerator
	GenerateIdentityKey  IdentityKeyGenerator
	GenerateRefreshToken IDGenerator
	Now                  Clock
	OperatingSystem      string
}

type Service struct {
	state                StateStore
	secrets              SecretStore
	secretBackend        secrets.BackendInfo
	fetcher              SubscriptionFetcher
	parse                ParseFunc
	latency              LatencyChecker
	daemon               DaemonClient
	updater              Updater
	generateID           IDGenerator
	generateRefreshToken IDGenerator
	identityKeyCandidate []byte
	now                  Clock
	operatingSystem      string

	latencyMu sync.RWMutex
	latencies map[string]latency.Result
}

type SubscriptionView struct {
	ID                     string                    `json:"id"`
	Name                   string                    `json:"name"`
	Format                 domain.SubscriptionFormat `json:"format"`
	RefreshIntervalSeconds int                       `json:"refresh_interval_seconds"`
	LastRefresh            *time.Time                `json:"last_refresh,omitempty"`
	LastError              string                    `json:"last_error,omitempty"`
	ServerCount            int                       `json:"server_count"`
}

type ServerView struct {
	ID             string          `json:"id"`
	SubscriptionID string          `json:"subscription_id"`
	Name           string          `json:"name"`
	Protocol       domain.Protocol `json:"protocol"`
	Latency        *latency.Result `json:"latency,omitempty"`
}

type RefreshResult struct {
	SubscriptionID string                    `json:"subscription_id"`
	Format         domain.SubscriptionFormat `json:"format,omitempty"`
	RefreshedAt    *time.Time                `json:"refreshed_at,omitempty"`
	ServerCount    int                       `json:"server_count"`
	Warnings       []subscription.Warning    `json:"warnings,omitempty"`
	Error          string                    `json:"error,omitempty"`
}

type DiagnosticSeverity string

const (
	DiagnosticInfo    DiagnosticSeverity = "info"
	DiagnosticWarning DiagnosticSeverity = "warning"
	DiagnosticError   DiagnosticSeverity = "error"
)

type Diagnostic struct {
	Code     string             `json:"code"`
	Severity DiagnosticSeverity `json:"severity"`
	Message  string             `json:"message"`
}

type UpdateInfo struct {
	CurrentVersion string `json:"current_version,omitempty"`
	LatestVersion  string `json:"latest_version,omitempty"`
	Available      bool   `json:"available"`
}

func NewService(config Config) (*Service, error) {
	if config.State == nil || config.Secrets == nil || config.Fetcher == nil || config.Latency == nil || config.Daemon == nil {
		return nil, ErrInvalidConfiguration
	}
	if config.Parse == nil {
		config.Parse = subscription.Parse
	}
	if config.GenerateID == nil {
		config.GenerateID = randomID
	}
	if config.GenerateIdentityKey == nil {
		config.GenerateIdentityKey = randomIdentityKey
	}
	if config.GenerateRefreshToken == nil {
		config.GenerateRefreshToken = randomID
	}
	identityKeyCandidate, err := config.GenerateIdentityKey()
	if err != nil || len(identityKeyCandidate) != endpointIdentityKeyBytes {
		return nil, ErrInvalidConfiguration
	}
	if config.Now == nil {
		config.Now = time.Now
	}
	if config.OperatingSystem == "" {
		config.OperatingSystem = runtime.GOOS
	}
	return &Service{
		state:                config.State,
		secrets:              config.Secrets,
		secretBackend:        config.SecretBackend,
		fetcher:              config.Fetcher,
		parse:                config.Parse,
		latency:              config.Latency,
		daemon:               config.Daemon,
		updater:              config.Updater,
		generateID:           config.GenerateID,
		generateRefreshToken: config.GenerateRefreshToken,
		identityKeyCandidate: append([]byte(nil), identityKeyCandidate...),
		now:                  config.Now,
		operatingSystem:      config.OperatingSystem,
		latencies:            make(map[string]latency.Result),
	}, nil
}

func (service *Service) AddSubscription(ctx context.Context, name, url string) (SubscriptionView, []subscription.Warning, error) {
	if !validText(name, domain.MaxNameLength, true) || strings.TrimSpace(url) == "" || !utf8.ValidString(url) {
		return SubscriptionView{}, nil, ErrInvalidInput
	}
	id, err := service.generateID()
	if err != nil || !validIdentifier(id) {
		return SubscriptionView{}, nil, ErrInvalidInput
	}
	secretRef := "subscription-" + id
	if len(secretRef) > 128 {
		return SubscriptionView{}, nil, ErrInvalidInput
	}
	if _, err := service.secrets.Get(ctx, secretRef); err == nil || !errors.Is(err, secrets.ErrSecretNotFound) {
		if err == nil {
			return SubscriptionView{}, nil, ErrInvalidInput
		}
		return SubscriptionView{}, nil, operationError(ctx, err, ErrSecretOperation)
	}
	document, err := service.fetcher.Fetch(ctx, url)
	if err != nil {
		return SubscriptionView{}, nil, operationError(ctx, err, ErrRefreshFailed)
	}
	parsed, err := service.parse(id, document)
	if err != nil || len(parsed.Endpoints) == 0 || !validSubscriptionFormat(parsed.Format) {
		return SubscriptionView{}, safeWarnings(id, parsed.Warnings), operationError(ctx, err, ErrRefreshFailed)
	}
	if validateParsedEndpoints(id, parsed.Endpoints) != nil {
		return SubscriptionView{}, safeWarnings(id, parsed.Warnings), ErrRefreshFailed
	}
	if err := ctx.Err(); err != nil {
		return SubscriptionView{}, nil, err
	}
	if err := service.secrets.Set(ctx, secretRef, url); err != nil {
		return SubscriptionView{}, nil, operationError(ctx, err, ErrSecretOperation)
	}
	now := service.now().UTC()
	sub := domain.Subscription{ID: id, Name: name, SecretRef: secretRef, Format: parsed.Format, LastRefresh: &now}
	var preparedEndpoints []domain.Endpoint
	err = service.state.UpdateContext(ctx, func(snapshot *state.Snapshot) error {
		for _, existing := range snapshot.Subscriptions {
			if existing.ID == id {
				return ErrInvalidInput
			}
		}
		identityKey, keyErr := ensureEndpointIdentityKey(snapshot, service.identityKeyCandidate)
		if keyErr != nil {
			return keyErr
		}
		preparedEndpoints, keyErr = prepareEndpoints(identityKey, id, parsed.Endpoints)
		if keyErr != nil {
			return keyErr
		}
		snapshot.Subscriptions = append(snapshot.Subscriptions, sub)
		snapshot.Endpoints = append(snapshot.Endpoints, cloneEndpoints(preparedEndpoints)...)
		return nil
	})
	if err != nil {
		primaryError := operationError(ctx, err, ErrStateOperation)
		if errors.Is(err, ErrInvalidInput) {
			primaryError = ErrInvalidInput
		} else if errors.Is(err, ErrRefreshFailed) {
			primaryError = ErrRefreshFailed
		}
		rollbackContext, cancelRollback := context.WithTimeout(context.Background(), compensationTimeout)
		defer cancelRollback()
		current, loadErr := service.state.LoadContext(rollbackContext)
		if loadErr != nil {
			return SubscriptionView{}, nil, errors.Join(primaryError, ErrSecretOperation)
		}
		currentSubscription, committed := findSubscription(current.Subscriptions, id)
		if committed && currentSubscription.SecretRef == secretRef {
			return SubscriptionView{}, nil, primaryError
		}
		if rollbackErr := service.secrets.Delete(rollbackContext, secretRef); rollbackErr != nil {
			return SubscriptionView{}, nil, errors.Join(primaryError, ErrSecretOperation)
		}
		return SubscriptionView{}, nil, primaryError
	}
	return subscriptionView(sub, len(preparedEndpoints)), safeWarnings(id, parsed.Warnings), nil
}

func (service *Service) ListSubscriptions(ctx context.Context) ([]SubscriptionView, error) {
	snapshot, err := service.state.LoadContext(ctx)
	if err != nil {
		return nil, operationError(ctx, err, ErrStateOperation)
	}
	counts := make(map[string]int, len(snapshot.Subscriptions))
	for _, endpoint := range snapshot.Endpoints {
		counts[endpoint.SubscriptionID]++
	}
	views := make([]SubscriptionView, 0, len(snapshot.Subscriptions))
	for _, sub := range snapshot.Subscriptions {
		views = append(views, subscriptionView(sub, counts[sub.ID]))
	}
	sort.Slice(views, func(i, j int) bool {
		if views[i].Name == views[j].Name {
			return views[i].ID < views[j].ID
		}
		return views[i].Name < views[j].Name
	})
	return views, nil
}

func (service *Service) UpdateSubscriptions(ctx context.Context, id string) ([]RefreshResult, error) {
	snapshot, err := service.state.LoadContext(ctx)
	if err != nil {
		return nil, operationError(ctx, err, ErrStateOperation)
	}
	ids := make([]string, 0, len(snapshot.Subscriptions))
	if id != "" {
		if _, found := findSubscription(snapshot.Subscriptions, id); !found {
			return nil, ErrSubscriptionNotFound
		}
		ids = append(ids, id)
	} else {
		for _, sub := range snapshot.Subscriptions {
			ids = append(ids, sub.ID)
		}
	}
	results := make([]RefreshResult, 0, len(ids))
	for _, subscriptionID := range ids {
		if err := ctx.Err(); err != nil {
			return results, err
		}
		result, err := service.refreshSubscription(ctx, subscriptionID)
		if err != nil {
			return results, err
		}
		results = append(results, result)
	}
	return results, nil
}

func (service *Service) refreshSubscription(ctx context.Context, id string) (RefreshResult, error) {
	refreshToken, err := service.generateRefreshToken()
	if err != nil || !validIdentifier(refreshToken) {
		return RefreshResult{}, ErrRefreshFailed
	}
	var sub domain.Subscription
	var oldEndpoints []domain.Endpoint
	err = service.state.UpdateContext(ctx, func(snapshot *state.Snapshot) error {
		index := subscriptionIndex(snapshot.Subscriptions, id)
		if index < 0 {
			return ErrSubscriptionNotFound
		}
		snapshot.Subscriptions[index].RefreshToken = refreshToken
		sub = snapshot.Subscriptions[index]
		oldEndpoints = cloneEndpoints(snapshot.Endpoints)
		return nil
	})
	if err != nil {
		if errors.Is(err, ErrSubscriptionNotFound) {
			return RefreshResult{}, ErrSubscriptionNotFound
		}
		return RefreshResult{}, operationError(ctx, err, ErrStateOperation)
	}
	url, err := service.secrets.Get(ctx, sub.SecretRef)
	if err != nil {
		if contextErr := contextError(ctx, err); contextErr != nil {
			return RefreshResult{}, contextErr
		}
		return service.recordRefreshFailure(ctx, id, sub.SecretRef, refreshToken)
	}
	document, err := service.fetcher.Fetch(ctx, url)
	if err != nil {
		if contextErr := contextError(ctx, err); contextErr != nil {
			return RefreshResult{}, contextErr
		}
		return service.recordRefreshFailure(ctx, id, sub.SecretRef, refreshToken)
	}
	parsed, err := service.parse(id, document)
	if err != nil || len(parsed.Endpoints) == 0 || !validSubscriptionFormat(parsed.Format) {
		return service.recordRefreshFailure(ctx, id, sub.SecretRef, refreshToken)
	}
	if validateParsedEndpoints(id, parsed.Endpoints) != nil {
		return service.recordRefreshFailure(ctx, id, sub.SecretRef, refreshToken)
	}
	if err := ctx.Err(); err != nil {
		return RefreshResult{}, err
	}
	now := service.now().UTC()
	var preparedEndpoints []domain.Endpoint
	err = service.state.UpdateContext(ctx, func(snapshot *state.Snapshot) error {
		index := subscriptionIndex(snapshot.Subscriptions, id)
		if index < 0 || snapshot.Subscriptions[index].SecretRef != sub.SecretRef {
			return ErrSubscriptionNotFound
		}
		if snapshot.Subscriptions[index].RefreshToken != refreshToken {
			return ErrRefreshStale
		}
		identityKey, keyErr := ensureEndpointIdentityKey(snapshot, service.identityKeyCandidate)
		if keyErr != nil {
			return keyErr
		}
		preparedEndpoints, keyErr = prepareEndpoints(identityKey, id, parsed.Endpoints)
		if keyErr != nil {
			return keyErr
		}
		kept := make([]domain.Endpoint, 0, len(snapshot.Endpoints)+len(preparedEndpoints))
		for _, endpoint := range snapshot.Endpoints {
			if endpoint.SubscriptionID != id {
				kept = append(kept, endpoint)
			}
		}
		snapshot.Endpoints = append(kept, cloneEndpoints(preparedEndpoints)...)
		snapshot.Subscriptions[index].Format = parsed.Format
		snapshot.Subscriptions[index].LastRefresh = &now
		snapshot.Subscriptions[index].LastError = ""
		snapshot.Subscriptions[index].RefreshToken = ""
		return nil
	})
	if err != nil {
		if errors.Is(err, ErrSubscriptionNotFound) {
			return RefreshResult{}, ErrSubscriptionNotFound
		}
		if errors.Is(err, ErrRefreshStale) {
			return RefreshResult{}, ErrRefreshStale
		}
		if errors.Is(err, ErrRefreshFailed) {
			return service.recordRefreshFailure(ctx, id, sub.SecretRef, refreshToken)
		}
		return RefreshResult{}, operationError(ctx, err, ErrStateOperation)
	}
	service.clearLatenciesForSubscription(id, oldEndpoints)
	return RefreshResult{SubscriptionID: id, Format: parsed.Format, RefreshedAt: &now, ServerCount: len(preparedEndpoints), Warnings: safeWarnings(id, parsed.Warnings)}, nil
}

func (service *Service) recordRefreshFailure(ctx context.Context, id, secretRef, refreshToken string) (RefreshResult, error) {
	message := ErrRefreshFailed.Error()
	err := service.state.UpdateContext(ctx, func(snapshot *state.Snapshot) error {
		index := subscriptionIndex(snapshot.Subscriptions, id)
		if index < 0 || snapshot.Subscriptions[index].SecretRef != secretRef {
			return ErrSubscriptionNotFound
		}
		if snapshot.Subscriptions[index].RefreshToken != refreshToken {
			return ErrRefreshStale
		}
		snapshot.Subscriptions[index].LastError = message
		snapshot.Subscriptions[index].RefreshToken = ""
		return nil
	})
	if err != nil {
		if errors.Is(err, ErrSubscriptionNotFound) {
			return RefreshResult{}, ErrSubscriptionNotFound
		}
		if errors.Is(err, ErrRefreshStale) {
			return RefreshResult{}, ErrRefreshStale
		}
		return RefreshResult{}, operationError(ctx, err, ErrStateOperation)
	}
	return RefreshResult{SubscriptionID: id, Error: message}, nil
}

func (service *Service) RemoveSubscription(ctx context.Context, id string) error {
	if !validIdentifier(id) {
		return ErrInvalidInput
	}
	snapshot, err := service.state.LoadContext(ctx)
	if err != nil {
		return operationError(ctx, err, ErrStateOperation)
	}
	sub, found := findSubscription(snapshot.Subscriptions, id)
	if !found {
		return ErrSubscriptionNotFound
	}
	url, err := service.secrets.Get(ctx, sub.SecretRef)
	urlAvailable := err == nil
	if err != nil && !errors.Is(err, secrets.ErrSecretNotFound) {
		return operationError(ctx, err, ErrSecretOperation)
	}
	if urlAvailable {
		if err := service.secrets.Delete(ctx, sub.SecretRef); err != nil && !errors.Is(err, secrets.ErrSecretNotFound) {
			return operationError(ctx, err, ErrSecretOperation)
		}
	}
	err = service.state.UpdateContext(ctx, func(snapshot *state.Snapshot) error {
		index := subscriptionIndex(snapshot.Subscriptions, id)
		if index < 0 || snapshot.Subscriptions[index].SecretRef != sub.SecretRef {
			return ErrSubscriptionNotFound
		}
		snapshot.Subscriptions = append(snapshot.Subscriptions[:index], snapshot.Subscriptions[index+1:]...)
		kept := snapshot.Endpoints[:0]
		for _, endpoint := range snapshot.Endpoints {
			if endpoint.SubscriptionID != id {
				kept = append(kept, endpoint)
			}
		}
		snapshot.Endpoints = kept
		return nil
	})
	if err != nil {
		primaryError := operationError(ctx, err, ErrStateOperation)
		if errors.Is(err, ErrSubscriptionNotFound) {
			primaryError = ErrSubscriptionNotFound
		}
		compensationContext, cancelCompensation := context.WithTimeout(context.Background(), compensationTimeout)
		defer cancelCompensation()
		current, loadErr := service.state.LoadContext(compensationContext)
		if loadErr != nil {
			return errors.Join(primaryError, ErrSecretOperation)
		}
		currentSubscription, stillOwned := findSubscription(current.Subscriptions, id)
		if !stillOwned || currentSubscription.SecretRef != sub.SecretRef {
			return primaryError
		}
		if !urlAvailable {
			return errors.Join(primaryError, ErrSecretOperation)
		}
		if restoreErr := service.secrets.Set(compensationContext, sub.SecretRef, url); restoreErr != nil {
			return errors.Join(primaryError, ErrSecretOperation)
		}
		return primaryError
	}
	service.clearLatenciesForSubscription(id, snapshot.Endpoints)
	return nil
}

func (service *Service) loadEndpointSnapshot(ctx context.Context) (state.Snapshot, error) {
	snapshot, err := service.state.LoadContext(ctx)
	if err != nil || len(snapshot.Endpoints) == 0 || snapshot.Settings.EndpointIdentityKey != "" {
		return snapshot, err
	}
	err = service.state.UpdateContext(ctx, func(current *state.Snapshot) error {
		identityKey, keyErr := ensureEndpointIdentityKey(current, service.identityKeyCandidate)
		if keyErr != nil {
			return keyErr
		}
		rekeyed := make([]domain.Endpoint, 0, len(current.Endpoints))
		seen := make(map[string]struct{}, len(current.Endpoints))
		for _, endpoint := range current.Endpoints {
			fingerprint, fingerprintErr := subscription.EndpointFingerprint(endpoint)
			if fingerprintErr != nil {
				return ErrRefreshFailed
			}
			endpoint.ID = keyedEndpointID(identityKey, endpoint.SubscriptionID, fingerprint)
			if endpoint.Validate() != nil {
				return ErrRefreshFailed
			}
			if _, duplicate := seen[endpoint.ID]; duplicate {
				return ErrRefreshFailed
			}
			seen[endpoint.ID] = struct{}{}
			rekeyed = append(rekeyed, endpoint)
		}
		current.Endpoints = rekeyed
		return nil
	})
	if err != nil {
		return state.Snapshot{}, err
	}
	service.latencyMu.Lock()
	service.latencies = make(map[string]latency.Result)
	service.latencyMu.Unlock()
	return service.state.LoadContext(ctx)
}

func (service *Service) ListServers(ctx context.Context) ([]ServerView, error) {
	snapshot, err := service.loadEndpointSnapshot(ctx)
	if err != nil {
		return nil, operationError(ctx, err, ErrStateOperation)
	}
	service.latencyMu.RLock()
	defer service.latencyMu.RUnlock()
	views := make([]ServerView, 0, len(snapshot.Endpoints))
	for _, endpoint := range snapshot.Endpoints {
		view := ServerView{ID: endpoint.ID, SubscriptionID: endpoint.SubscriptionID, Name: safeEndpointName(endpoint), Protocol: endpoint.Protocol}
		if result, ok := service.latencies[endpoint.ID]; ok {
			copy := safeLatencyResult(result)
			view.Latency = &copy
		}
		views = append(views, view)
	}
	sort.Slice(views, func(i, j int) bool {
		if views[i].Name == views[j].Name {
			return views[i].ID < views[j].ID
		}
		return views[i].Name < views[j].Name
	})
	return views, nil
}

func (service *Service) CheckLatency(ctx context.Context, id string, all bool) ([]latency.Result, error) {
	snapshot, err := service.loadEndpointSnapshot(ctx)
	if err != nil {
		return nil, operationError(ctx, err, ErrStateOperation)
	}
	var endpoints []domain.Endpoint
	if all {
		endpoints = cloneEndpoints(snapshot.Endpoints)
	} else {
		endpoint, found := findEndpoint(snapshot.Endpoints, id)
		if !found {
			return nil, ErrServerNotFound
		}
		endpoints = []domain.Endpoint{endpoint}
	}
	results := service.latency.Check(ctx, endpoints)
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	projected := projectLatencyResults(endpoints, results)
	service.cacheLatencyResults(projected)
	return projected, nil
}

func (service *Service) Connect(ctx context.Context, target string, mode domain.ConnectionMode, route domain.RouteMode) (rpc.SessionStatus, error) {
	if !validConnectionMode(mode) || !validRouteMode(route) {
		return rpc.SessionStatus{}, ErrInvalidInput
	}
	if route == domain.RouteModeDirect {
		status, err := service.daemon.Connect(ctx, rpc.ConnectPayload{Mode: mode, Route: route})
		return status, daemonOperationError(ctx, err)
	}
	if target == "" {
		return rpc.SessionStatus{}, ErrInvalidInput
	}
	snapshot, err := service.loadEndpointSnapshot(ctx)
	if err != nil {
		return rpc.SessionStatus{}, operationError(ctx, err, ErrStateOperation)
	}
	for _, storedEndpoint := range snapshot.Endpoints {
		if err := storedEndpoint.Validate(); err != nil {
			return rpc.SessionStatus{}, ErrStateOperation
		}
	}
	var endpoint domain.Endpoint
	if target == AutoTarget {
		endpoints := cloneEndpoints(snapshot.Endpoints)
		results := projectLatencyResults(endpoints, service.latency.Check(ctx, endpoints))
		service.cacheLatencyResults(results)
		best, err := latency.Best(results)
		if err != nil {
			if contextErr := contextError(ctx, err); contextErr != nil {
				return rpc.SessionStatus{}, contextErr
			}
			return rpc.SessionStatus{}, ErrServerNotFound
		}
		var found bool
		endpoint, found = findEndpoint(snapshot.Endpoints, best.EndpointID)
		if !found {
			return rpc.SessionStatus{}, ErrServerNotFound
		}
	} else {
		var found bool
		endpoint, found = findEndpoint(snapshot.Endpoints, target)
		if !found {
			return rpc.SessionStatus{}, ErrServerNotFound
		}
	}
	status, err := service.daemon.Connect(ctx, rpc.ConnectPayload{Endpoint: &endpoint, Mode: mode, Route: route})
	return status, daemonOperationError(ctx, err)
}

func (service *Service) Disconnect(ctx context.Context) (rpc.SessionStatus, error) {
	status, err := service.daemon.Disconnect(ctx)
	return status, daemonOperationError(ctx, err)
}

func (service *Service) Status(ctx context.Context) (rpc.SessionStatus, error) {
	status, err := service.daemon.Status(ctx)
	return status, daemonOperationError(ctx, err)
}

func (service *Service) SetTelemetry(ctx context.Context, enabled bool) error {
	if err := service.state.UpdateContext(ctx, func(snapshot *state.Snapshot) error {
		snapshot.Settings.TelemetryEnabled = enabled
		return nil
	}); err != nil {
		return operationError(ctx, err, ErrStateOperation)
	}
	return nil
}

func (service *Service) TelemetryEnabled(ctx context.Context) (bool, error) {
	snapshot, err := service.state.LoadContext(ctx)
	if err != nil {
		return false, operationError(ctx, err, ErrStateOperation)
	}
	return snapshot.Settings.TelemetryEnabled, nil
}

func (service *Service) Doctor(ctx context.Context) []Diagnostic {
	diagnostics := make([]Diagnostic, 0, 4)
	if service.operatingSystem != "darwin" && service.operatingSystem != "linux" {
		diagnostics = append(diagnostics, Diagnostic{Code: "unsupported_os", Severity: DiagnosticError, Message: "operating system is unsupported"})
	}
	if _, err := service.state.LoadContext(ctx); err != nil {
		diagnostics = append(diagnostics, Diagnostic{Code: "state_unavailable", Severity: DiagnosticError, Message: "state store is unavailable"})
	} else {
		diagnostics = append(diagnostics, Diagnostic{Code: "state_ready", Severity: DiagnosticInfo, Message: "state store is ready"})
	}
	if strings.TrimSpace(service.secretBackend.Warning) != "" {
		diagnostics = append(diagnostics, Diagnostic{Code: "secret_backend_warning", Severity: DiagnosticWarning, Message: "credential storage fallback is active"})
	} else {
		diagnostics = append(diagnostics, Diagnostic{Code: "secret_backend_ready", Severity: DiagnosticInfo, Message: "secret backend is ready"})
	}
	if err := service.daemon.Health(ctx); err != nil {
		code, message := daemonDiagnostic(err)
		diagnostics = append(diagnostics, Diagnostic{Code: code, Severity: DiagnosticError, Message: message})
	} else {
		diagnostics = append(diagnostics, Diagnostic{Code: "daemon_ready", Severity: DiagnosticInfo, Message: "daemon is ready"})
	}
	return diagnostics
}

func (service *Service) CheckUpdate(ctx context.Context) (UpdateInfo, error) {
	if service.updater == nil {
		return UpdateInfo{}, ErrUpdaterUnavailable
	}
	update, err := service.updater.Check(ctx)
	if err != nil {
		return UpdateInfo{}, operationError(ctx, err, ErrUpdaterUnavailable)
	}
	if !validUpdateInfo(update) {
		return UpdateInfo{}, ErrUpdaterUnavailable
	}
	return update, nil
}

func (service *Service) ApplyUpdate(ctx context.Context, update UpdateInfo) error {
	if service.updater == nil {
		return ErrUpdaterUnavailable
	}
	if !validUpdateInfo(update) {
		return ErrInvalidInput
	}
	if err := service.updater.Apply(ctx, update); err != nil {
		return operationError(ctx, err, ErrUpdaterUnavailable)
	}
	return nil
}

func randomID() (string, error) {
	bytes := make([]byte, 16)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}

func randomIdentityKey() ([]byte, error) {
	key := make([]byte, endpointIdentityKeyBytes)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
	return key, nil
}

func subscriptionView(sub domain.Subscription, serverCount int) SubscriptionView {
	view := SubscriptionView{
		ID:                     sub.ID,
		Name:                   safeDisplayName(sub.Name, "Subscription"),
		Format:                 sub.Format,
		RefreshIntervalSeconds: sub.RefreshIntervalSeconds,
		ServerCount:            serverCount,
	}
	if sub.LastError != "" {
		view.LastError = ErrRefreshFailed.Error()
	}
	if sub.LastRefresh != nil {
		copy := *sub.LastRefresh
		view.LastRefresh = &copy
	}
	return view
}

func safeEndpointName(endpoint domain.Endpoint) string {
	return safeDisplayName(endpoint.Name, "Endpoint", endpointSensitiveValues(endpoint)...)
}

func safeDisplayName(name, fallback string, sensitive ...string) string {
	if !validText(name, domain.MaxNameLength, true) {
		return fallback
	}
	lowerName := strings.ToLower(name)
	for _, value := range sensitive {
		if strings.Contains(lowerName, strings.ToLower(value)) {
			return fallback
		}
	}
	redacted := redact.StringSensitive(name, sensitive...)
	if redacted != name || strings.Contains(redacted, "[redacted]") {
		return fallback
	}
	return name
}

func endpointSensitiveValues(endpoint domain.Endpoint) []string {
	values := []string{
		endpoint.Host, strconv.Itoa(endpoint.Port), endpoint.UUID, endpoint.Password, endpoint.Method,
		endpoint.TLS.ServerName, string(endpoint.TLS.UTLSFingerprint),
		endpoint.Transport.Path, endpoint.Transport.Host, endpoint.Transport.ServiceName,
	}
	values = append(values, endpoint.TLS.ALPN...)
	if endpoint.TLS.Reality != nil {
		values = append(values, endpoint.TLS.Reality.PublicKey, endpoint.TLS.Reality.ShortID)
	}
	if endpoint.Hysteria2Options != nil {
		values = append(values, endpoint.Hysteria2Options.ObfsPassword)
	}
	return nonEmptyStrings(values)
}

func nonEmptyStrings(values []string) []string {
	filtered := values[:0]
	for _, value := range values {
		if value != "" {
			filtered = append(filtered, value)
		}
	}
	return filtered
}

func safeWarnings(subscriptionID string, warnings []subscription.Warning) []subscription.Warning {
	projected := make([]subscription.Warning, 0, len(warnings))
	for _, warning := range warnings {
		code := "entry_skipped"
		message := "entry " + strconv.Itoa(warning.Entry) + " was skipped because it is malformed or unsupported"
		if warning.Code == "entry_too_large" {
			code = "entry_too_large"
			message = "entry " + strconv.Itoa(warning.Entry) + " was skipped because it exceeds the size limit"
		}
		projected = append(projected, subscription.Warning{SubscriptionID: subscriptionID, Entry: warning.Entry, Code: code, Message: message})
	}
	return projected
}

func safeLatencyResult(result latency.Result) latency.Result {
	projected := result
	switch result.Status {
	case latency.StatusSuccess:
		projected.Error = ""
	case latency.StatusUnsupported:
		projected.Error = "latency check is unsupported for this protocol"
	default:
		projected.Error = "latency check failed"
	}
	return projected
}

func projectLatencyResults(endpoints []domain.Endpoint, results []latency.Result) []latency.Result {
	projected := make([]latency.Result, 0, len(endpoints))
	for index, endpoint := range endpoints {
		result := latency.Result{
			EndpointID: endpoint.ID,
			Protocol:   endpoint.Protocol,
			Status:     latency.StatusUnavailable,
			Error:      "latency check failed",
		}
		if index < len(results) && validLatencyResult(endpoint.ID, results[index]) {
			result = safeLatencyResult(results[index])
			result.EndpointID = endpoint.ID
			result.Protocol = endpoint.Protocol
		}
		projected = append(projected, result)
	}
	return projected
}

func validLatencyResult(endpointID string, result latency.Result) bool {
	if result.EndpointID != endpointID || result.Duration < 0 {
		return false
	}
	switch result.Status {
	case latency.StatusSuccess, latency.StatusUnavailable, latency.StatusUnsupported:
		return true
	default:
		return false
	}
}

func (service *Service) cacheLatencyResults(results []latency.Result) {
	service.latencyMu.Lock()
	defer service.latencyMu.Unlock()
	for _, result := range results {
		service.latencies[result.EndpointID] = result
	}
}

func findSubscription(subscriptions []domain.Subscription, id string) (domain.Subscription, bool) {
	index := subscriptionIndex(subscriptions, id)
	if index < 0 {
		return domain.Subscription{}, false
	}
	return subscriptions[index], true
}

func subscriptionIndex(subscriptions []domain.Subscription, id string) int {
	for index := range subscriptions {
		if subscriptions[index].ID == id {
			return index
		}
	}
	return -1
}

func findEndpoint(endpoints []domain.Endpoint, id string) (domain.Endpoint, bool) {
	for _, endpoint := range endpoints {
		if endpoint.ID == id {
			return endpoint, true
		}
	}
	return domain.Endpoint{}, false
}

func cloneEndpoints(endpoints []domain.Endpoint) []domain.Endpoint {
	return append([]domain.Endpoint(nil), endpoints...)
}

func validateParsedEndpoints(subscriptionID string, endpoints []domain.Endpoint) error {
	seen := make(map[string]struct{}, len(endpoints))
	for _, endpoint := range endpoints {
		if endpoint.SubscriptionID != subscriptionID || endpoint.ID == "" || endpoint.Validate() != nil {
			return ErrRefreshFailed
		}
		if _, duplicate := seen[endpoint.ID]; duplicate {
			return ErrRefreshFailed
		}
		seen[endpoint.ID] = struct{}{}
	}
	return nil
}

func prepareEndpoints(identityKey []byte, subscriptionID string, endpoints []domain.Endpoint) ([]domain.Endpoint, error) {
	if len(identityKey) != endpointIdentityKeyBytes {
		return nil, ErrRefreshFailed
	}
	scoped := cloneEndpoints(endpoints)
	seen := make(map[string]struct{}, len(scoped))
	for index := range scoped {
		if scoped[index].SubscriptionID != subscriptionID {
			return nil, ErrRefreshFailed
		}
		if err := scoped[index].Validate(); err != nil {
			return nil, ErrRefreshFailed
		}
		fingerprint := scoped[index].ID
		scoped[index].ID = keyedEndpointID(identityKey, subscriptionID, fingerprint)
		if err := scoped[index].Validate(); err != nil {
			return nil, ErrRefreshFailed
		}
		if _, duplicate := seen[scoped[index].ID]; duplicate {
			return nil, ErrRefreshFailed
		}
		seen[scoped[index].ID] = struct{}{}
	}
	return scoped, nil
}

func keyedEndpointID(identityKey []byte, subscriptionID, fingerprint string) string {
	digest := hmac.New(sha256.New, identityKey)
	_, _ = digest.Write([]byte("tuibox-endpoint-public-v1\x00"))
	_, _ = digest.Write([]byte(subscriptionID))
	_, _ = digest.Write([]byte{'\x00'})
	_, _ = digest.Write([]byte(fingerprint))
	return hex.EncodeToString(digest.Sum(nil))
}

func ensureEndpointIdentityKey(snapshot *state.Snapshot, candidate []byte) ([]byte, error) {
	if snapshot == nil {
		return nil, ErrRefreshFailed
	}
	if snapshot.Settings.EndpointIdentityKey != "" {
		key, err := hex.DecodeString(snapshot.Settings.EndpointIdentityKey)
		if err != nil || len(key) != endpointIdentityKeyBytes {
			return nil, ErrRefreshFailed
		}
		return key, nil
	}
	if len(candidate) != endpointIdentityKeyBytes {
		return nil, ErrRefreshFailed
	}
	key := append([]byte(nil), candidate...)
	seen := make(map[string]struct{}, len(snapshot.Endpoints))
	for index := range snapshot.Endpoints {
		fingerprint, err := subscription.EndpointFingerprint(snapshot.Endpoints[index])
		if err != nil {
			return nil, ErrRefreshFailed
		}
		snapshot.Endpoints[index].ID = keyedEndpointID(key, snapshot.Endpoints[index].SubscriptionID, fingerprint)
		if snapshot.Endpoints[index].Validate() != nil {
			return nil, ErrRefreshFailed
		}
		if _, duplicate := seen[snapshot.Endpoints[index].ID]; duplicate {
			return nil, ErrRefreshFailed
		}
		seen[snapshot.Endpoints[index].ID] = struct{}{}
	}
	snapshot.Settings.EndpointIdentityKey = hex.EncodeToString(key)
	return key, nil
}

func validText(value string, maxBytes int, required bool) bool {
	if required && strings.TrimSpace(value) == "" || !utf8.ValidString(value) || len(value) > maxBytes {
		return false
	}
	return terminaltext.Valid(value)
}

func contextError(ctx context.Context, err error) error {
	if ctxErr := ctx.Err(); ctxErr != nil {
		return ctxErr
	}
	if errors.Is(err, context.Canceled) {
		return context.Canceled
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return context.DeadlineExceeded
	}
	return nil
}

func daemonOperationError(ctx context.Context, err error) error {
	if err == nil {
		return nil
	}
	if contextErr := contextError(ctx, err); contextErr != nil {
		return contextErr
	}
	for _, safeError := range safeDaemonErrors {
		if errors.Is(err, safeError) {
			return safeError
		}
	}
	return rpc.ErrInternal
}

func daemonDiagnostic(err error) (string, string) {
	switch {
	case errors.Is(err, rpc.ErrAccessDenied):
		return "daemon_access_denied", rpc.ErrAccessDenied.Error()
	case errors.Is(err, rpc.ErrTimeout), errors.Is(err, context.DeadlineExceeded), errors.Is(err, context.Canceled):
		return "daemon_timeout", rpc.ErrTimeout.Error()
	case errors.Is(err, rpc.ErrUnavailable):
		return "daemon_unavailable", rpc.ErrUnavailable.Error()
	default:
		return "daemon_unavailable", rpc.ErrUnavailable.Error()
	}
}

func (service *Service) clearLatenciesForSubscription(subscriptionID string, oldEndpoints []domain.Endpoint) {
	service.latencyMu.Lock()
	defer service.latencyMu.Unlock()
	for _, endpoint := range oldEndpoints {
		if endpoint.SubscriptionID == subscriptionID {
			delete(service.latencies, endpoint.ID)
		}
	}
}

func validUpdateInfo(update UpdateInfo) bool {
	versions := []string{update.CurrentVersion, update.LatestVersion}
	for _, version := range versions {
		if !validText(version, maxVersionBytes, false) || redact.String(version) != version {
			return false
		}
	}
	return true
}

func validSubscriptionFormat(format domain.SubscriptionFormat) bool {
	switch format {
	case domain.SubscriptionFormatURIList, domain.SubscriptionFormatBase64, domain.SubscriptionFormatClash, domain.SubscriptionFormatSingBox:
		return true
	default:
		return false
	}
}

func validConnectionMode(mode domain.ConnectionMode) bool {
	return mode == domain.ConnectionModeTUN || mode == domain.ConnectionModeProxy
}

func validRouteMode(route domain.RouteMode) bool {
	return route == domain.RouteModeGlobal || route == domain.RouteModeRule || route == domain.RouteModeDirect
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

func operationError(ctx context.Context, err, fallback error) error {
	if err == nil {
		return fallback
	}
	if contextErr := contextError(ctx, err); contextErr != nil {
		return contextErr
	}
	return fallback
}

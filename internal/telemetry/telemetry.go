package telemetry

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"runtime"
	"strings"
	"time"

	"github.com/rezraf/tui-box/internal/domain"
)

const (
	DefaultTimeout   = 5 * time.Second
	MaxRequestBytes  = 4 << 10
	MaxResponseBytes = 4 << 10
	UserAgent        = "TuiBox-Telemetry/0.1"
	maxVersionBytes  = 64
)

var (
	ErrEndpointInvalid  = errors.New("telemetry endpoint is invalid")
	ErrHTTPSRequired    = errors.New("telemetry endpoint must use HTTPS")
	ErrEventInvalid     = errors.New("telemetry event is invalid")
	ErrRequestTooLarge  = errors.New("telemetry request exceeds the size limit")
	ErrSendFailed       = errors.New("telemetry send failed")
	ErrStatus           = errors.New("telemetry server returned an unsuccessful status")
	ErrResponseTooLarge = errors.New("telemetry response exceeds the size limit")
	ErrRedirectRejected = errors.New("telemetry redirect was rejected")
)

type EventName string

const (
	EventAppStart     EventName = "app_start"
	EventSubscription EventName = "subscription"
	EventServer       EventName = "server"
	EventConnect      EventName = "connect"
	EventDisconnect   EventName = "disconnect"
	EventStatus       EventName = "status"
	EventTelemetry    EventName = "telemetry"
	EventDoctor       EventName = "doctor"
	EventUpdate       EventName = "update"
	EventVersion      EventName = "version"
)

type DurationBucket string

const (
	DurationUnder100Milliseconds DurationBucket = "under_100ms"
	DurationUnder1Second         DurationBucket = "100ms_to_1s"
	DurationUnder10Seconds       DurationBucket = "1s_to_10s"
	Duration10SecondsOrMore      DurationBucket = "10s_or_more"
)

type Config struct {
	Enabled    bool
	Endpoint   string
	AppVersion string
	Client     *http.Client
}

type Record struct {
	Event    EventName
	Protocol domain.Protocol
	Mode     domain.ConnectionMode
	Route    domain.RouteMode
	Success  bool
	Duration time.Duration
}

// Event is the complete telemetry wire schema. It is intentionally closed:
// callers cannot attach arbitrary fields, identifiers, logs, or metadata.
type Event struct {
	AppVersion     string                `json:"app_version"`
	OS             string                `json:"os"`
	Arch           string                `json:"arch"`
	Event          EventName             `json:"event"`
	Protocol       domain.Protocol       `json:"protocol"`
	Mode           domain.ConnectionMode `json:"mode"`
	Route          domain.RouteMode      `json:"route"`
	Success        bool                  `json:"success"`
	DurationBucket DurationBucket        `json:"duration_bucket"`
}

type Sender struct {
	enabled    bool
	endpoint   string
	appVersion string
	client     *http.Client
}

func NewSender(config Config) (*Sender, error) {
	client := config.Client
	if client == nil {
		client = &http.Client{}
	}
	configured := *client
	configured.Jar = nil
	if configured.Timeout <= 0 || configured.Timeout > DefaultTimeout {
		configured.Timeout = DefaultTimeout
	}
	configured.CheckRedirect = rejectRedirect

	sender := &Sender{
		enabled:    config.Enabled,
		endpoint:   config.Endpoint,
		appVersion: config.AppVersion,
		client:     &configured,
	}
	if config.Endpoint == "" {
		return sender, nil
	}

	parsed, err := url.Parse(config.Endpoint)
	if err != nil || parsed.Host == "" || parsed.User != nil || parsed.Fragment != "" {
		return nil, ErrEndpointInvalid
	}
	if parsed.Scheme != "https" {
		return nil, ErrHTTPSRequired
	}
	return sender, nil
}

func (sender *Sender) Send(ctx context.Context, record Record) error {
	if sender == nil || !sender.enabled || sender.endpoint == "" {
		return nil
	}

	event, err := sender.event(record)
	if err != nil {
		return err
	}
	body, err := json.Marshal(event)
	if err != nil {
		return ErrEventInvalid
	}
	if len(body) > MaxRequestBytes {
		return ErrRequestTooLarge
	}

	request, err := http.NewRequestWithContext(ctx, http.MethodPost, sender.endpoint, bytes.NewReader(body))
	if err != nil {
		return ErrEndpointInvalid
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("User-Agent", UserAgent)

	response, err := sender.client.Do(request)
	if err != nil {
		if response != nil && response.Body != nil {
			_ = response.Body.Close()
		}
		if contextErr := contextError(ctx, err); contextErr != nil {
			return contextErr
		}
		if errors.Is(err, ErrRedirectRejected) {
			return ErrRedirectRejected
		}
		return ErrSendFailed
	}
	defer response.Body.Close()

	responseBody, err := io.ReadAll(io.LimitReader(response.Body, MaxResponseBytes+1))
	if err != nil {
		if contextErr := contextError(ctx, err); contextErr != nil {
			return contextErr
		}
		return ErrSendFailed
	}
	if len(responseBody) > MaxResponseBytes {
		return ErrResponseTooLarge
	}
	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		return ErrStatus
	}
	return nil
}

func BucketDuration(duration time.Duration) DurationBucket {
	switch {
	case duration < 100*time.Millisecond:
		return DurationUnder100Milliseconds
	case duration < time.Second:
		return DurationUnder1Second
	case duration < 10*time.Second:
		return DurationUnder10Seconds
	default:
		return Duration10SecondsOrMore
	}
}

func (sender *Sender) event(record Record) (Event, error) {
	if !validVersion(sender.appVersion) || !validEvent(record.Event) || record.Duration < 0 ||
		!validProtocol(record.Protocol) || !validMode(record.Mode) || !validRoute(record.Route) {
		return Event{}, ErrEventInvalid
	}

	return Event{
		AppVersion:     sender.appVersion,
		OS:             runtime.GOOS,
		Arch:           runtime.GOARCH,
		Event:          record.Event,
		Protocol:       record.Protocol,
		Mode:           record.Mode,
		Route:          record.Route,
		Success:        record.Success,
		DurationBucket: BucketDuration(record.Duration),
	}, nil
}

func validVersion(version string) bool {
	if version == "" || len(version) > maxVersionBytes || strings.TrimSpace(version) != version {
		return false
	}
	for _, character := range version {
		if character >= 'a' && character <= 'z' ||
			character >= 'A' && character <= 'Z' ||
			character >= '0' && character <= '9' ||
			strings.ContainsRune(".-+_", character) {
			continue
		}
		return false
	}
	return true
}

func validEvent(event EventName) bool {
	switch event {
	case EventAppStart, EventSubscription, EventServer, EventConnect, EventDisconnect,
		EventStatus, EventTelemetry, EventDoctor, EventUpdate, EventVersion:
		return true
	default:
		return false
	}
}

func validProtocol(protocol domain.Protocol) bool {
	switch protocol {
	case "", domain.ProtocolVLESS, domain.ProtocolVMess, domain.ProtocolTrojan,
		domain.ProtocolShadowsocks, domain.ProtocolHysteria2, domain.ProtocolTUIC:
		return true
	default:
		return false
	}
}

func validMode(mode domain.ConnectionMode) bool {
	switch mode {
	case "", domain.ConnectionModeTUN, domain.ConnectionModeProxy:
		return true
	default:
		return false
	}
}

func validRoute(route domain.RouteMode) bool {
	switch route {
	case "", domain.RouteModeGlobal, domain.RouteModeRule, domain.RouteModeDirect:
		return true
	default:
		return false
	}
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

func rejectRedirect(*http.Request, []*http.Request) error {
	return ErrRedirectRejected
}

package telemetry

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/rezraf/tui-box/internal/domain"
)

func TestSenderDisabledByDefault(t *testing.T) {
	t.Parallel()

	var requests atomic.Int32
	sender, err := NewSender(Config{
		Endpoint:   "https://telemetry.invalid/private?token=secret",
		AppVersion: "0.1.0",
		Client: &http.Client{Transport: roundTripperFunc(func(*http.Request) (*http.Response, error) {
			requests.Add(1)
			return nil, errors.New("unexpected request")
		})},
	})
	if err != nil {
		t.Fatalf("NewSender() error = %v", err)
	}
	if err := sender.Send(context.Background(), Record{Event: EventConnect}); err != nil {
		t.Fatalf("Send() error = %v, want no-op", err)
	}
	if requests.Load() != 0 {
		t.Fatalf("requests = %d, want 0", requests.Load())
	}
}

func TestSenderWithEmptyEndpointIsTrueNoOp(t *testing.T) {
	t.Parallel()

	var requests atomic.Int32
	sender, err := NewSender(Config{
		Enabled: true,
		Client: &http.Client{Transport: roundTripperFunc(func(*http.Request) (*http.Response, error) {
			requests.Add(1)
			return nil, errors.New("unexpected request")
		})},
	})
	if err != nil {
		t.Fatalf("NewSender() error = %v", err)
	}
	if err := sender.Send(context.Background(), Record{Event: "not-allowlisted", Duration: -time.Second}); err != nil {
		t.Fatalf("Send() error = %v, want no-op", err)
	}
	if requests.Load() != 0 {
		t.Fatalf("requests = %d, want 0", requests.Load())
	}
}

func TestSenderRejectsNonHTTPSEndpointBeforeRequest(t *testing.T) {
	t.Parallel()

	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		requests.Add(1)
	}))
	defer server.Close()

	_, err := NewSender(Config{Enabled: true, Endpoint: server.URL + "/private?token=secret", AppVersion: "0.1.0"})
	if !errors.Is(err, ErrHTTPSRequired) {
		t.Fatalf("NewSender() error = %v, want ErrHTTPSRequired", err)
	}
	if requests.Load() != 0 {
		t.Fatalf("requests = %d, want 0", requests.Load())
	}
	assertErrorExcludes(t, err, server.URL, "private", "token", "secret")
}

func TestSenderRejectsMalformedEndpointWithoutExposingIt(t *testing.T) {
	t.Parallel()

	endpoint := "https://user:secret@example.com/collector#private"
	_, err := NewSender(Config{Enabled: true, Endpoint: endpoint, AppVersion: "0.1.0"})
	if !errors.Is(err, ErrEndpointInvalid) {
		t.Fatalf("NewSender() error = %v, want ErrEndpointInvalid", err)
	}
	assertErrorExcludes(t, err, endpoint, "user", "secret", "private", "example.com")
}

func TestSenderEmitsExactAllowlistedSchema(t *testing.T) {
	t.Parallel()

	var requestBody []byte
	var contentType string
	var userAgent string
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		contentType = request.Header.Get("Content-Type")
		userAgent = request.Header.Get("User-Agent")
		var err error
		requestBody, err = io.ReadAll(io.LimitReader(request.Body, MaxRequestBytes+1))
		if err != nil {
			t.Errorf("read request: %v", err)
		}
		writer.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	sender, err := NewSender(Config{
		Enabled:    true,
		Endpoint:   server.URL + "/collect",
		AppVersion: "0.1.0-test+1",
		Client:     server.Client(),
	})
	if err != nil {
		t.Fatalf("NewSender() error = %v", err)
	}
	err = sender.Send(context.Background(), Record{
		Event:    EventConnect,
		Protocol: domain.ProtocolVLESS,
		Mode:     domain.ConnectionModeTUN,
		Route:    domain.RouteModeRule,
		Success:  true,
		Duration: 1500 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("Send() error = %v", err)
	}
	if len(requestBody) > MaxRequestBytes {
		t.Fatalf("request bytes = %d, want at most %d", len(requestBody), MaxRequestBytes)
	}
	if contentType != "application/json" {
		t.Fatalf("Content-Type = %q, want application/json", contentType)
	}
	if userAgent != UserAgent {
		t.Fatalf("User-Agent = %q, want %q", userAgent, UserAgent)
	}

	var got map[string]any
	if err := json.Unmarshal(requestBody, &got); err != nil {
		t.Fatalf("decode request: %v", err)
	}
	want := map[string]any{
		"app_version":     "0.1.0-test+1",
		"os":              runtime.GOOS,
		"arch":            runtime.GOARCH,
		"event":           "connect",
		"protocol":        "vless",
		"mode":            "tun",
		"route":           "rule",
		"success":         true,
		"duration_bucket": "1s_to_10s",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("payload = %#v, want %#v", got, want)
	}
	for _, forbidden := range []string{
		"stable_id", "installation_id", "timestamp", "endpoint", "url", "host",
		"ip", "token", "credential", "destination", "log", "error", "duration",
	} {
		if _, exists := got[forbidden]; exists {
			t.Fatalf("payload contains forbidden field %q", forbidden)
		}
	}
}

func TestEventStructHasOnlyAllowlistedFields(t *testing.T) {
	t.Parallel()

	typeOfEvent := reflect.TypeOf(Event{})
	var got []string
	for index := 0; index < typeOfEvent.NumField(); index++ {
		got = append(got, strings.Split(typeOfEvent.Field(index).Tag.Get("json"), ",")[0])
	}
	want := []string{"app_version", "os", "arch", "event", "protocol", "mode", "route", "success", "duration_bucket"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("Event JSON fields = %v, want %v", got, want)
	}
}

func TestSenderAcceptsOnlyAllowlistedValues(t *testing.T) {
	t.Parallel()

	validEvents := []EventName{
		EventAppStart, EventSubscription, EventServer, EventConnect, EventDisconnect,
		EventStatus, EventTelemetry, EventDoctor, EventUpdate, EventVersion,
	}
	validProtocols := []domain.Protocol{
		"", domain.ProtocolVLESS, domain.ProtocolVMess, domain.ProtocolTrojan,
		domain.ProtocolShadowsocks, domain.ProtocolHysteria2, domain.ProtocolTUIC,
	}
	validModes := []domain.ConnectionMode{"", domain.ConnectionModeTUN, domain.ConnectionModeProxy}
	validRoutes := []domain.RouteMode{"", domain.RouteModeGlobal, domain.RouteModeRule, domain.RouteModeDirect}

	for _, event := range validEvents {
		if err := sendWithRecord(t, Record{Event: event}); err != nil {
			t.Errorf("event %q: %v", event, err)
		}
	}
	for _, protocol := range validProtocols {
		if err := sendWithRecord(t, Record{Event: EventConnect, Protocol: protocol}); err != nil {
			t.Errorf("protocol %q: %v", protocol, err)
		}
	}
	for _, mode := range validModes {
		if err := sendWithRecord(t, Record{Event: EventConnect, Mode: mode}); err != nil {
			t.Errorf("mode %q: %v", mode, err)
		}
	}
	for _, route := range validRoutes {
		if err := sendWithRecord(t, Record{Event: EventConnect, Route: route}); err != nil {
			t.Errorf("route %q: %v", route, err)
		}
	}

	invalid := []Record{
		{Event: "connect_with_server_name"},
		{Event: EventConnect, Protocol: "custom-protocol"},
		{Event: EventConnect, Mode: "custom-mode"},
		{Event: EventConnect, Route: "custom-route"},
		{Event: EventConnect, Duration: -time.Nanosecond},
	}
	for _, record := range invalid {
		if err := sendWithRecord(t, record); !errors.Is(err, ErrEventInvalid) {
			t.Errorf("record %#v error = %v, want ErrEventInvalid", record, err)
		}
	}
}

func TestDurationBucketsAreCoarseAndBounded(t *testing.T) {
	t.Parallel()

	tests := []struct {
		duration time.Duration
		want     DurationBucket
	}{
		{duration: 0, want: DurationUnder100Milliseconds},
		{duration: 99 * time.Millisecond, want: DurationUnder100Milliseconds},
		{duration: 100 * time.Millisecond, want: DurationUnder1Second},
		{duration: 999 * time.Millisecond, want: DurationUnder1Second},
		{duration: time.Second, want: DurationUnder10Seconds},
		{duration: 9999 * time.Millisecond, want: DurationUnder10Seconds},
		{duration: 10 * time.Second, want: Duration10SecondsOrMore},
		{duration: 24 * time.Hour, want: Duration10SecondsOrMore},
	}
	for _, test := range tests {
		if got := BucketDuration(test.duration); got != test.want {
			t.Errorf("BucketDuration(%s) = %q, want %q", test.duration, got, test.want)
		}
	}
}

func TestSenderValidatesAppVersionWithoutLeakingIt(t *testing.T) {
	t.Parallel()

	for _, version := range []string{"", " version", "version/private", strings.Repeat("x", maxVersionBytes+1)} {
		version := version
		t.Run(fmt.Sprintf("length-%d", len(version)), func(t *testing.T) {
			err := sendWithVersion(t, version)
			if !errors.Is(err, ErrEventInvalid) {
				t.Fatalf("Send() error = %v, want ErrEventInvalid", err)
			}
			assertErrorExcludes(t, err, version)
		})
	}
}

func TestSenderClampsClientTimeout(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		in   time.Duration
		want time.Duration
	}{
		{name: "zero", in: 0, want: DefaultTimeout},
		{name: "negative", in: -time.Second, want: DefaultTimeout},
		{name: "shorter", in: 25 * time.Millisecond, want: 25 * time.Millisecond},
		{name: "maximum", in: DefaultTimeout, want: DefaultTimeout},
		{name: "too long", in: DefaultTimeout + time.Second, want: DefaultTimeout},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			sender, err := NewSender(Config{Client: &http.Client{Timeout: test.in}})
			if err != nil {
				t.Fatalf("NewSender() error = %v", err)
			}
			if sender.client.Timeout != test.want {
				t.Fatalf("timeout = %s, want %s", sender.client.Timeout, test.want)
			}
		})
	}
}

func TestSenderDoesNotInheritOrUseClientCookieJar(t *testing.T) {
	t.Parallel()

	jar := &spyingCookieJar{}
	var cookieHeader string
	client := &http.Client{
		Jar: jar,
		Transport: roundTripperFunc(func(request *http.Request) (*http.Response, error) {
			cookieHeader = request.Header.Get("Cookie")
			return successResponse(request)
		}),
	}
	sender := mustSender(t, client, "https://telemetry.invalid/collect", "0.1.0")
	if sender.client.Jar != nil {
		t.Fatal("copied telemetry client retained the caller's CookieJar")
	}
	if err := sender.Send(context.Background(), Record{Event: EventStatus}); err != nil {
		t.Fatalf("Send() error = %v", err)
	}
	if calls := jar.calls.Load(); calls != 0 {
		t.Fatalf("CookieJar.Cookies() calls = %d, want 0", calls)
	}
	if cookieHeader != "" {
		t.Fatalf("Cookie header = %q, want empty", cookieHeader)
	}
}

func TestSenderPreservesContextErrors(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		name string
		ctx  func() (context.Context, context.CancelFunc)
		want error
	}{
		{
			name: "canceled",
			ctx: func() (context.Context, context.CancelFunc) {
				ctx, cancel := context.WithCancel(context.Background())
				cancel()
				return ctx, func() {}
			},
			want: context.Canceled,
		},
		{
			name: "deadline",
			ctx: func() (context.Context, context.CancelFunc) {
				return context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
			},
			want: context.DeadlineExceeded,
		},
	} {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			ctx, cancel := test.ctx()
			defer cancel()
			client := &http.Client{Transport: roundTripperFunc(func(request *http.Request) (*http.Response, error) {
				<-request.Context().Done()
				return nil, request.Context().Err()
			})}
			sender := mustSender(t, client, "https://telemetry.invalid/private?token=secret", "0.1.0")
			err := sender.Send(ctx, Record{Event: EventStatus})
			if !errors.Is(err, test.want) {
				t.Fatalf("Send() error = %v, want %v", err, test.want)
			}
			assertErrorExcludes(t, err, "telemetry.invalid", "private", "token", "secret")
		})
	}
}

func TestSenderBoundsResponseAndClosesBody(t *testing.T) {
	t.Parallel()

	body := &trackingBody{Reader: io.LimitReader(zeroReader{}, MaxResponseBytes+1)}
	client := &http.Client{Transport: roundTripperFunc(func(request *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     make(http.Header),
			Body:       body,
			Request:    request,
		}, nil
	})}
	sender := mustSender(t, client, "https://telemetry.invalid/collect", "0.1.0")
	err := sender.Send(context.Background(), Record{Event: EventStatus})
	if !errors.Is(err, ErrResponseTooLarge) {
		t.Fatalf("Send() error = %v, want ErrResponseTooLarge", err)
	}
	if !body.closed.Load() {
		t.Fatal("response body was not closed")
	}
}

func TestSenderReturnsStableErrorsWithoutPayloads(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		status    int
		body      string
		transport error
		want      error
	}{
		{name: "status", status: http.StatusUnauthorized, body: "provider secret response", want: ErrStatus},
		{name: "transport", transport: errors.New("dial telemetry.invalid/private?token=secret"), want: ErrSendFailed},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			client := &http.Client{Transport: roundTripperFunc(func(request *http.Request) (*http.Response, error) {
				if test.transport != nil {
					return nil, test.transport
				}
				return &http.Response{
					StatusCode: test.status,
					Header:     make(http.Header),
					Body:       io.NopCloser(strings.NewReader(test.body)),
					Request:    request,
				}, nil
			})}
			sender := mustSender(t, client, "https://telemetry.invalid/private?token=secret", "0.1.0-private")
			err := sender.Send(context.Background(), Record{Event: EventConnect, Protocol: domain.ProtocolVLESS})
			if !errors.Is(err, test.want) {
				t.Fatalf("Send() error = %v, want %v", err, test.want)
			}
			assertErrorExcludes(t, err, "telemetry.invalid", "private", "token", "secret", test.body, "vless", "0.1.0-private")
		})
	}
}

func TestSenderRejectsRedirectWithoutForwardingPayload(t *testing.T) {
	t.Parallel()

	var targetRequests atomic.Int32
	target := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		targetRequests.Add(1)
	}))
	defer target.Close()

	source := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		http.Redirect(writer, request, target.URL+"/private?token=secret", http.StatusTemporaryRedirect)
	}))
	defer source.Close()

	sender := mustSender(t, source.Client(), source.URL, "0.1.0")
	err := sender.Send(context.Background(), Record{Event: EventConnect})
	if !errors.Is(err, ErrRedirectRejected) {
		t.Fatalf("Send() error = %v, want ErrRedirectRejected", err)
	}
	if targetRequests.Load() != 0 {
		t.Fatalf("redirect target requests = %d, want 0", targetRequests.Load())
	}
	assertErrorExcludes(t, err, source.URL, target.URL, "private", "token", "secret")
}

func sendWithRecord(t *testing.T, record Record) error {
	t.Helper()
	client := &http.Client{Transport: roundTripperFunc(successResponse)}
	sender := mustSender(t, client, "https://telemetry.invalid/collect", "0.1.0")
	return sender.Send(context.Background(), record)
}

func sendWithVersion(t *testing.T, version string) error {
	t.Helper()
	client := &http.Client{Transport: roundTripperFunc(successResponse)}
	sender := mustSender(t, client, "https://telemetry.invalid/collect", version)
	return sender.Send(context.Background(), Record{Event: EventStatus})
}

func mustSender(t *testing.T, client *http.Client, endpoint, version string) *Sender {
	t.Helper()
	sender, err := NewSender(Config{
		Enabled:    true,
		Endpoint:   endpoint,
		AppVersion: version,
		Client:     client,
	})
	if err != nil {
		t.Fatalf("NewSender() error = %v", err)
	}
	return sender
}

func successResponse(request *http.Request) (*http.Response, error) {
	return &http.Response{
		StatusCode: http.StatusNoContent,
		Header:     make(http.Header),
		Body:       http.NoBody,
		Request:    request,
	}, nil
}

func assertErrorExcludes(t *testing.T, err error, values ...string) {
	t.Helper()
	message := err.Error()
	for _, value := range values {
		if value != "" && strings.Contains(message, value) {
			t.Fatalf("error %q exposes %q", message, value)
		}
	}
}

type roundTripperFunc func(*http.Request) (*http.Response, error)

func (function roundTripperFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return function(request)
}

type spyingCookieJar struct {
	calls atomic.Int32
}

func (jar *spyingCookieJar) Cookies(*url.URL) []*http.Cookie {
	jar.calls.Add(1)
	return []*http.Cookie{{Name: "session", Value: "private"}}
}

func (*spyingCookieJar) SetCookies(*url.URL, []*http.Cookie) {}

type trackingBody struct {
	io.Reader
	closed atomic.Bool
}

func (body *trackingBody) Close() error {
	body.closed.Store(true)
	return nil
}

type zeroReader struct{}

func (zeroReader) Read(buffer []byte) (int, error) {
	for index := range buffer {
		buffer[index] = 0
	}
	return len(buffer), nil
}

package subscription

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestFetcherUsesHTTPSWithFixedUserAgent(t *testing.T) {
	t.Parallel()

	var gotUserAgent string
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		gotUserAgent = request.Header.Get("User-Agent")
		_, _ = io.WriteString(writer, "subscription")
	}))
	defer server.Close()

	fetcher := NewFetcher(server.Client())
	body, err := fetcher.Fetch(context.Background(), server.URL+"/private?token=secret")
	if err != nil {
		t.Fatalf("Fetch() returned an unexpected error: %v", err)
	}
	if string(body) != "subscription" {
		t.Fatalf("Fetch() body = %q, want subscription", body)
	}
	if gotUserAgent != SubscriptionUserAgent {
		t.Fatalf("User-Agent = %q, want %q", gotUserAgent, SubscriptionUserAgent)
	}
	for _, sensitive := range []string{"private", "token", "secret"} {
		if strings.Contains(gotUserAgent, sensitive) {
			t.Fatalf("User-Agent leaked request value %q: %q", sensitive, gotUserAgent)
		}
	}
}

func TestFetcherRejectsNonHTTPSBeforeRequest(t *testing.T) {
	t.Parallel()

	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		requests.Add(1)
	}))
	defer server.Close()

	_, err := NewFetcher(nil).Fetch(context.Background(), server.URL+"/private?token=secret")
	if err == nil {
		t.Fatal("Fetch() returned nil error, want HTTP rejection")
	}
	if requests.Load() != 0 {
		t.Fatalf("server received %d requests, want none", requests.Load())
	}
	assertFetchErrorRedacted(t, err, server.URL, "private", "token", "secret")
}

func TestFetcherRejectsHTTPSRedirectDowngrade(t *testing.T) {
	t.Parallel()

	var downgradedRequests atomic.Int32
	httpServer := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		downgradedRequests.Add(1)
	}))
	defer httpServer.Close()

	httpsServer := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		http.Redirect(writer, request, httpServer.URL+"/downgraded?token=secret", http.StatusFound)
	}))
	defer httpsServer.Close()

	_, err := NewFetcher(httpsServer.Client()).Fetch(context.Background(), httpsServer.URL+"/source?credential=private")
	if err == nil {
		t.Fatal("Fetch() returned nil error, want redirect downgrade rejection")
	}
	if downgradedRequests.Load() != 0 {
		t.Fatalf("downgraded server received %d requests, want none", downgradedRequests.Load())
	}
	assertFetchErrorRedacted(t, err, httpsServer.URL, httpServer.URL, "downgraded", "credential", "private", "token", "secret")
}

func TestFetcherRejectsUnsupportedRedirectScheme(t *testing.T) {
	t.Parallel()

	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Location", "file:///private/subscription?token=secret")
		writer.WriteHeader(http.StatusFound)
	}))
	defer server.Close()

	_, err := NewFetcher(server.Client()).Fetch(context.Background(), server.URL)
	if err == nil {
		t.Fatal("Fetch() returned nil error, want unsupported redirect rejection")
	}
	assertFetchErrorRedacted(t, err, server.URL, "file", "private", "token", "secret")
}

func TestFetcherRejectsCrossOriginRedirectsToSpecialUseNetworksBeforeRoundTrip(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		targetHost string
		addresses  []netip.Addr
	}{
		{name: "literal loopback IPv4", targetHost: "127.0.0.1"},
		{name: "literal RFC1918", targetHost: "192.168.10.20"},
		{name: "literal link local", targetHost: "169.254.10.20"},
		{name: "literal unspecified", targetHost: "0.0.0.0"},
		{name: "literal multicast", targetHost: "224.0.0.1"},
		{name: "literal loopback IPv6", targetHost: "[::1]"},
		{name: "literal ULA", targetHost: "[fd00::1]"},
		{name: "literal link local IPv6", targetHost: "[fe80::1]"},
		{name: "literal unspecified IPv6", targetHost: "[::]"},
		{name: "literal multicast IPv6", targetHost: "[ff02::1]"},
		{name: "DNS loopback", targetHost: "loopback.example", addresses: []netip.Addr{netip.MustParseAddr("127.0.0.1")}},
		{name: "DNS RFC1918", targetHost: "private.example", addresses: []netip.Addr{netip.MustParseAddr("10.10.10.10")}},
		{name: "DNS ULA", targetHost: "ula.example", addresses: []netip.Addr{netip.MustParseAddr("fd00::10")}},
		{name: "DNS link local", targetHost: "link.example", addresses: []netip.Addr{netip.MustParseAddr("169.254.10.10")}},
		{name: "DNS unspecified", targetHost: "unspecified.example", addresses: []netip.Addr{netip.MustParseAddr("::")}},
		{name: "DNS multicast", targetHost: "multicast.example", addresses: []netip.Addr{netip.MustParseAddr("ff02::1")}},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			var requests atomic.Int32
			transport := roundTripperFunc(func(request *http.Request) (*http.Response, error) {
				requestNumber := requests.Add(1)
				if requestNumber == 1 {
					return redirectResponse(request, "https://"+test.targetHost+":8443/admin"), nil
				}
				return textResponse(request, "reached private target"), nil
			})
			resolver := &staticResolver{addresses: map[string][]netip.Addr{strings.Trim(test.targetHost, "[]"): test.addresses}}
			fetcher := newFetcherWithResolver(&http.Client{Transport: transport}, resolver)
			_, err := fetcher.Fetch(context.Background(), "https://provider.example/subscription")
			if !errors.Is(err, errSubscriptionRedirectRejected) {
				t.Fatalf("Fetch() error = %v, want redirect rejection", err)
			}
			if requests.Load() != 1 {
				t.Fatalf("RoundTrip calls = %d, want 1", requests.Load())
			}
		})
	}
}

func TestFetcherRedirectPolicyAllowsSameOriginAndPublicCrossOriginButRejectsLaterPrivateHop(t *testing.T) {
	t.Parallel()

	resolver := &staticResolver{addresses: map[string][]netip.Addr{
		"public.example":  {netip.MustParseAddr("93.184.216.34")},
		"private.example": {netip.MustParseAddr("10.0.0.8")},
	}}
	for _, test := range []struct {
		name         string
		firstTarget  string
		secondTarget string
		wantBody     string
		wantErr      error
		wantRequests int32
	}{
		{name: "same origin private provider", firstTarget: "/same-origin", wantBody: "ok", wantRequests: 2},
		{name: "public cross origin", firstTarget: "https://public.example/subscription", wantBody: "ok", wantRequests: 2},
		{name: "multi-hop private target", firstTarget: "https://public.example/next", secondTarget: "https://private.example/admin", wantErr: errSubscriptionRedirectRejected, wantRequests: 2},
	} {
		test := test
		t.Run(test.name, func(t *testing.T) {
			var requests atomic.Int32
			transport := roundTripperFunc(func(request *http.Request) (*http.Response, error) {
				switch requests.Add(1) {
				case 1:
					return redirectResponse(request, test.firstTarget), nil
				case 2:
					if test.secondTarget != "" {
						return redirectResponse(request, test.secondTarget), nil
					}
					return textResponse(request, test.wantBody), nil
				default:
					return textResponse(request, "unexpected"), nil
				}
			})
			fetcher := newFetcherWithResolver(&http.Client{Transport: transport}, resolver)
			body, err := fetcher.Fetch(context.Background(), "https://provider.example/start")
			if !errors.Is(err, test.wantErr) {
				t.Fatalf("Fetch() error = %v, want %v", err, test.wantErr)
			}
			if string(body) != test.wantBody {
				t.Fatalf("Fetch() body = %q, want %q", body, test.wantBody)
			}
			if requests.Load() != test.wantRequests {
				t.Fatalf("RoundTrip calls = %d, want %d", requests.Load(), test.wantRequests)
			}
		})
	}
}

func TestResolvedRedirectDialTargetPinsTheValidatedAddressAgainstDNSRebinding(t *testing.T) {
	t.Parallel()

	resolver := &rebindingResolver{
		first:  []netip.Addr{netip.MustParseAddr("93.184.216.34")},
		second: []netip.Addr{netip.MustParseAddr("127.0.0.1")},
	}
	target, err := resolveDialTarget(context.Background(), "rebind.example:443", true, resolver)
	if err != nil {
		t.Fatalf("resolveDialTarget: %v", err)
	}
	var dialed string
	sentinel := errors.New("stop after recording dial")
	_, err = target.dial(context.Background(), "tcp", func(_ context.Context, _, address string) (net.Conn, error) {
		dialed = address
		return nil, sentinel
	})
	if !errors.Is(err, sentinel) {
		t.Fatalf("dial error = %v, want sentinel", err)
	}
	if dialed != "93.184.216.34:443" {
		t.Fatalf("dialed address = %q, want pinned public address", dialed)
	}
	if resolver.calls.Load() != 1 {
		t.Fatalf("DNS lookups = %d, want 1", resolver.calls.Load())
	}
}

func TestFetcherBoundsRedirects(t *testing.T) {
	t.Parallel()

	var requests atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		requests.Add(1)
		http.Redirect(writer, request, "/loop?token=secret", http.StatusFound)
	}))
	defer server.Close()

	_, err := NewFetcher(server.Client()).Fetch(context.Background(), server.URL+"/loop?token=secret")
	if err == nil {
		t.Fatal("Fetch() returned nil error, want redirect limit rejection")
	}
	if got := requests.Load(); got > int32(MaxSubscriptionRedirects+1) {
		t.Fatalf("server received %d requests, want at most %d", got, MaxSubscriptionRedirects+1)
	}
	assertFetchErrorRedacted(t, err, server.URL, "loop", "token", "secret")
}

func TestFetcherEnforcesHardResponseLimit(t *testing.T) {
	t.Parallel()

	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Content-Length", fmt.Sprint(MaxSubscriptionResponseBytes+1))
		_, _ = io.CopyN(writer, zeroReader{}, MaxSubscriptionResponseBytes+1)
	}))
	defer server.Close()

	body, err := NewFetcher(server.Client()).Fetch(context.Background(), server.URL)
	if err == nil {
		t.Fatal("Fetch() returned nil error, want oversized response rejection")
	}
	if body != nil {
		t.Fatalf("Fetch() returned %d bytes, want no partial body", len(body))
	}
	assertFetchErrorRedacted(t, err, server.URL)
}

func TestFetcherAcceptsResponseAtHardLimit(t *testing.T) {
	t.Parallel()

	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		_, _ = io.CopyN(writer, zeroReader{}, MaxSubscriptionResponseBytes)
	}))
	defer server.Close()

	body, err := NewFetcher(server.Client()).Fetch(context.Background(), server.URL)
	if err != nil {
		t.Fatalf("Fetch() returned an unexpected error: %v", err)
	}
	if len(body) != MaxSubscriptionResponseBytes {
		t.Fatalf("len(body) = %d, want %d", len(body), MaxSubscriptionResponseBytes)
	}
}

func TestFetcherClampsUnsafeTimeoutsAndPreservesShorterPositiveTimeouts(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		client *http.Client
		want   time.Duration
	}{
		{name: "nil client", client: nil, want: DefaultSubscriptionTimeout},
		{name: "zero", client: &http.Client{}, want: DefaultSubscriptionTimeout},
		{name: "negative", client: &http.Client{Timeout: -time.Second}, want: DefaultSubscriptionTimeout},
		{name: "short positive", client: &http.Client{Timeout: 25 * time.Millisecond}, want: 25 * time.Millisecond},
		{name: "exact maximum", client: &http.Client{Timeout: DefaultSubscriptionTimeout}, want: DefaultSubscriptionTimeout},
		{name: "above maximum", client: &http.Client{Timeout: DefaultSubscriptionTimeout + time.Millisecond}, want: DefaultSubscriptionTimeout},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if got := NewFetcher(test.client).client.Timeout; got != test.want {
				t.Fatalf("client timeout = %s, want %s", got, test.want)
			}
		})
	}
}

func TestFetcherHonorsShortPositiveTimeout(t *testing.T) {
	t.Parallel()

	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		<-request.Context().Done()
	}))
	defer server.Close()

	client := server.Client()
	client.Timeout = 25 * time.Millisecond
	started := time.Now()
	_, err := NewFetcher(client).Fetch(context.Background(), server.URL+"/slow?token=secret")
	if err == nil {
		t.Fatal("Fetch() returned nil error, want timeout")
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Fetch() error = %v, want context.DeadlineExceeded identity", err)
	}
	if elapsed := time.Since(started); elapsed > time.Second {
		t.Fatalf("Fetch() took %s, want configured short timeout", elapsed)
	}
	assertFetchErrorRedacted(t, err, server.URL, "slow", "token", "secret")
}

func TestFetcherPreservesContextErrorIdentity(t *testing.T) {
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
			name: "deadline exceeded",
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
			_, err := NewFetcher(nil).Fetch(ctx, "https://example.com/private?token=secret")
			if !errors.Is(err, test.want) {
				t.Fatalf("Fetch() error = %v, want %v identity", err, test.want)
			}
			assertFetchErrorRedacted(t, err, "example.com", "private", "token", "secret")
		})
	}
}

func TestFetcherReturnsGenericNonSuccessErrorAndClosesBody(t *testing.T) {
	t.Parallel()

	body := &trackingBody{Reader: strings.NewReader("provider body secret-token")}
	client := &http.Client{Transport: roundTripperFunc(func(request *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusUnauthorized,
			Header:     make(http.Header),
			Body:       body,
			Request:    request,
		}, nil
	})}

	_, err := NewFetcher(client).Fetch(context.Background(), "https://user:password@example.com/private?token=query-secret")
	if err == nil {
		t.Fatal("Fetch() returned nil error, want non-2xx rejection")
	}
	if !body.closed.Load() {
		t.Fatal("response body was not closed")
	}
	assertFetchErrorRedacted(t, err, "example.com", "user", "password", "private", "token", "query-secret", "provider body", "secret-token")
}

func TestFetcherRedactsMalformedURLFromErrors(t *testing.T) {
	t.Parallel()

	sensitiveURL := "https://user:password@%zz/private?token=query-secret"
	_, err := NewFetcher(nil).Fetch(context.Background(), sensitiveURL)
	if err == nil {
		t.Fatal("Fetch() returned nil error, want malformed URL rejection")
	}
	assertFetchErrorRedacted(t, err, sensitiveURL, "user", "password", "private", "token", "query-secret")
}

type zeroReader struct{}

func (zeroReader) Read(buffer []byte) (int, error) {
	for index := range buffer {
		buffer[index] = 0
	}
	return len(buffer), nil
}

type roundTripperFunc func(*http.Request) (*http.Response, error)

func (function roundTripperFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return function(request)
}

type trackingBody struct {
	io.Reader
	closed atomic.Bool
}

func (body *trackingBody) Close() error {
	body.closed.Store(true)
	return nil
}

type staticResolver struct {
	addresses map[string][]netip.Addr
}

func (resolver *staticResolver) LookupNetIP(_ context.Context, network, host string) ([]netip.Addr, error) {
	if network != "ip" {
		return nil, errors.New("unexpected network")
	}
	addresses, ok := resolver.addresses[host]
	if !ok {
		return nil, errors.New("host not found")
	}
	return append([]netip.Addr(nil), addresses...), nil
}

type rebindingResolver struct {
	first  []netip.Addr
	second []netip.Addr
	calls  atomic.Int32
}

func (resolver *rebindingResolver) LookupNetIP(context.Context, string, string) ([]netip.Addr, error) {
	if resolver.calls.Add(1) == 1 {
		return append([]netip.Addr(nil), resolver.first...), nil
	}
	return append([]netip.Addr(nil), resolver.second...), nil
}

func redirectResponse(request *http.Request, location string) *http.Response {
	return &http.Response{
		StatusCode: http.StatusFound,
		Header:     http.Header{"Location": []string{location}},
		Body:       io.NopCloser(strings.NewReader("")),
		Request:    request,
	}
}

func textResponse(request *http.Request, body string) *http.Response {
	return &http.Response{
		StatusCode: http.StatusOK,
		Header:     make(http.Header),
		Body:       io.NopCloser(strings.NewReader(body)),
		Request:    request,
	}
}

func assertFetchErrorRedacted(t *testing.T, err error, sensitive ...string) {
	t.Helper()
	message := err.Error()
	for _, value := range sensitive {
		if value != "" && strings.Contains(message, value) {
			t.Fatalf("fetch error leaked %q: %v", value, err)
		}
	}
}

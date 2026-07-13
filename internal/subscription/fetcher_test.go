package subscription

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
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
	if elapsed := time.Since(started); elapsed > time.Second {
		t.Fatalf("Fetch() took %s, want configured short timeout", elapsed)
	}
	assertFetchErrorRedacted(t, err, server.URL, "slow", "token", "secret")
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

func assertFetchErrorRedacted(t *testing.T, err error, sensitive ...string) {
	t.Helper()
	message := err.Error()
	for _, value := range sensitive {
		if value != "" && strings.Contains(message, value) {
			t.Fatalf("fetch error leaked %q: %v", value, err)
		}
	}
}

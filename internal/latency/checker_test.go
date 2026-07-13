package latency

import (
	"context"
	"errors"
	"net"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/rezraf/tui-box/internal/domain"
)

func TestCheckerUsesTCPOnlyForStreamProtocolsAndMarksQUICUnsupported(t *testing.T) {
	t.Parallel()

	dialer := &recordingDialer{}
	checker, err := NewChecker(Config{Dialer: dialer, Timeout: time.Second, MaxParallel: 3})
	if err != nil {
		t.Fatalf("NewChecker() error = %v", err)
	}
	endpoints := []domain.Endpoint{
		latencyEndpoint("vless", domain.ProtocolVLESS),
		latencyEndpoint("vmess", domain.ProtocolVMess),
		latencyEndpoint("trojan", domain.ProtocolTrojan),
		latencyEndpoint("shadowsocks", domain.ProtocolShadowsocks),
		latencyEndpoint("hysteria2", domain.ProtocolHysteria2),
		latencyEndpoint("tuic", domain.ProtocolTUIC),
	}

	results := checker.Check(context.Background(), endpoints)
	if len(results) != len(endpoints) {
		t.Fatalf("len(Check()) = %d, want %d", len(results), len(endpoints))
	}
	for index := 0; index < 4; index++ {
		if results[index].Status != StatusSuccess {
			t.Errorf("result %q status = %q, want success", results[index].EndpointID, results[index].Status)
		}
	}
	for index := 4; index < len(results); index++ {
		if results[index].Status != StatusUnsupported || !strings.Contains(results[index].Error, "unsupported") {
			t.Errorf("result %q = %#v, want clearly unsupported", results[index].EndpointID, results[index])
		}
	}

	networks, addresses := dialer.calls()
	if !slices.Equal(networks, []string{"tcp", "tcp", "tcp", "tcp"}) {
		t.Fatalf("dial networks = %v, want TCP only", networks)
	}
	for _, address := range addresses {
		if address != "stream.example.com:443" {
			t.Errorf("dial address = %q, want stream.example.com:443", address)
		}
	}
}

func TestCheckerBoundsParallelismAndPreservesInputOrder(t *testing.T) {
	t.Parallel()

	dialer := newBlockingDialer()
	checker, err := NewChecker(Config{Dialer: dialer, Timeout: time.Second, MaxParallel: 2})
	if err != nil {
		t.Fatalf("NewChecker() error = %v", err)
	}
	endpoints := make([]domain.Endpoint, 8)
	for index := range endpoints {
		endpoints[index] = latencyEndpoint(string(rune('a'+index)), domain.ProtocolVLESS)
	}

	done := make(chan []Result, 1)
	go func() { done <- checker.Check(context.Background(), endpoints) }()
	dialer.waitForActive(t, 2)
	if got := dialer.maximum(); got != 2 {
		t.Fatalf("maximum active dials = %d, want 2", got)
	}
	dialer.releaseAll()

	select {
	case results := <-done:
		for index, result := range results {
			if result.EndpointID != endpoints[index].ID {
				t.Fatalf("result %d ID = %q, want %q", index, result.EndpointID, endpoints[index].ID)
			}
		}
	case <-time.After(time.Second):
		t.Fatal("Check() did not complete")
	}
	if got := dialer.maximum(); got > 2 {
		t.Fatalf("maximum active dials = %d, exceeded 2", got)
	}
}

func TestCheckerAppliesPerProbeTimeoutAndHonorsParentCancellation(t *testing.T) {
	t.Parallel()

	dialer := &contextDialer{entered: make(chan time.Time, 1)}
	checker, err := NewChecker(Config{Dialer: dialer, Timeout: 35 * time.Millisecond, MaxParallel: 1})
	if err != nil {
		t.Fatalf("NewChecker() error = %v", err)
	}
	started := time.Now()
	results := checker.Check(context.Background(), []domain.Endpoint{latencyEndpoint("timeout", domain.ProtocolVLESS)})
	if elapsed := time.Since(started); elapsed > 500*time.Millisecond {
		t.Fatalf("timeout probe took %s", elapsed)
	}
	if len(results) != 1 || results[0].Status != StatusUnavailable || !strings.Contains(results[0].Error, "deadline") {
		t.Fatalf("timeout result = %#v", results)
	}
	deadline := <-dialer.entered
	if deadline.Before(started) || deadline.After(started.Add(100*time.Millisecond)) {
		t.Fatalf("probe deadline = %s, want bounded deadline", deadline)
	}

	parent, cancel := context.WithCancel(context.Background())
	cancel()
	started = time.Now()
	results = checker.Check(parent, []domain.Endpoint{latencyEndpoint("canceled", domain.ProtocolVLESS)})
	if elapsed := time.Since(started); elapsed > 100*time.Millisecond {
		t.Fatalf("canceled probe took %s", elapsed)
	}
	if len(results) != 1 || results[0].Status != StatusUnavailable || !strings.Contains(results[0].Error, "canceled") {
		t.Fatalf("canceled result = %#v, want unavailable cancellation error", results)
	}
}

func TestCheckerCancellationStopsUntouchedProbesAndPreservesOrder(t *testing.T) {
	t.Parallel()

	dialer := &cancelRecordingDialer{entered: make(chan struct{})}
	checker, err := NewChecker(Config{Dialer: dialer, Timeout: time.Second, MaxParallel: 1})
	if err != nil {
		t.Fatalf("NewChecker() error = %v", err)
	}
	endpoints := []domain.Endpoint{
		latencyEndpoint("first", domain.ProtocolVLESS),
		latencyEndpoint("second", domain.ProtocolVMess),
		latencyEndpoint("third", domain.ProtocolTrojan),
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan []Result, 1)
	go func() { done <- checker.Check(ctx, endpoints) }()
	<-dialer.entered
	cancel()

	results := <-done
	if got := dialer.callCount.Load(); got != 1 {
		t.Fatalf("dial calls = %d, want only the in-flight probe", got)
	}
	for index, result := range results {
		if result.EndpointID != endpoints[index].ID {
			t.Fatalf("result %d ID = %q, want %q", index, result.EndpointID, endpoints[index].ID)
		}
		if result.Status != StatusUnavailable || !strings.Contains(result.Error, "canceled") {
			t.Fatalf("result %d = %#v, want canceled unavailable result", index, result)
		}
	}
}

func TestCheckerClosesConnectionReturnedAfterCancellation(t *testing.T) {
	t.Parallel()

	dialer := newLateConnectionDialer()
	checker, err := NewChecker(Config{Dialer: dialer, Timeout: time.Second, MaxParallel: 1})
	if err != nil {
		t.Fatalf("NewChecker() error = %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan []Result, 1)
	go func() {
		done <- checker.Check(ctx, []domain.Endpoint{latencyEndpoint("late", domain.ProtocolVLESS)})
	}()
	<-dialer.entered
	cancel()
	close(dialer.release)

	result := (<-done)[0]
	if result.Status != StatusUnavailable || !strings.Contains(result.Error, "canceled") {
		t.Fatalf("late result = %#v, want canceled unavailable result", result)
	}
	if !dialer.connection.closed.Load() {
		t.Fatal("connection returned after cancellation was not closed")
	}
}

func TestCheckerPrefersCancellationOverLateDialError(t *testing.T) {
	t.Parallel()

	dialer := &lateErrorDialer{entered: make(chan struct{}), release: make(chan struct{})}
	checker, err := NewChecker(Config{Dialer: dialer, Timeout: time.Second, MaxParallel: 1})
	if err != nil {
		t.Fatalf("NewChecker() error = %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan []Result, 1)
	go func() {
		done <- checker.Check(ctx, []domain.Endpoint{latencyEndpoint("late-error", domain.ProtocolVLESS)})
	}()
	<-dialer.entered
	cancel()
	close(dialer.release)

	result := (<-done)[0]
	if result.Status != StatusUnavailable || !strings.Contains(result.Error, "canceled") {
		t.Fatalf("late error result = %#v, want canceled unavailable result", result)
	}
	if strings.Contains(result.Error, "private") {
		t.Fatalf("late error leaked dial failure: %q", result.Error)
	}
}

func TestCheckerHandlesNilConnectionWithoutPanic(t *testing.T) {
	t.Parallel()

	checker, err := NewChecker(Config{Dialer: nilConnectionDialer{}, Timeout: time.Second, MaxParallel: 1})
	if err != nil {
		t.Fatalf("NewChecker() error = %v", err)
	}

	results := checker.Check(context.Background(), []domain.Endpoint{latencyEndpoint("nil-connection", domain.ProtocolVLESS)})
	if len(results) != 1 || results[0].Status != StatusUnavailable || !strings.Contains(results[0].Error, "nil connection") {
		t.Fatalf("nil connection result = %#v, want unavailable error", results)
	}
}

func TestCheckerReturnsEmptyResultsForEmptyInput(t *testing.T) {
	t.Parallel()

	checker, err := NewChecker(Config{Timeout: time.Second, MaxParallel: 1})
	if err != nil {
		t.Fatalf("NewChecker() error = %v", err)
	}

	results := checker.Check(context.Background(), nil)
	if results == nil || len(results) != 0 {
		t.Fatalf("Check(nil) = %#v, want non-nil empty results", results)
	}
}

func TestCheckerRedactsDialErrors(t *testing.T) {
	t.Parallel()

	dialer := errorDialer{err: errors.New(`dial tcp edge.private.example:443: token=super-secret-value`)}
	checker, err := NewChecker(Config{Dialer: dialer, Timeout: time.Second, MaxParallel: 1})
	if err != nil {
		t.Fatalf("NewChecker() error = %v", err)
	}
	result := checker.Check(context.Background(), []domain.Endpoint{latencyEndpoint("private", domain.ProtocolVLESS)})[0]
	if result.Status != StatusUnavailable {
		t.Fatalf("status = %q, want unavailable", result.Status)
	}
	for _, private := range []string{"edge.private.example:443", "edge.private.example", ":443", "super-secret-value"} {
		if strings.Contains(result.Error, private) {
			t.Fatalf("error retained %q: %q", private, result.Error)
		}
	}
}

func TestBestChoosesLowestSuccessfulLatencyWithIDTieBreak(t *testing.T) {
	t.Parallel()

	results := []Result{
		{EndpointID: "z", Status: StatusSuccess, Duration: 20 * time.Millisecond},
		{EndpointID: "b", Status: StatusSuccess, Duration: 10 * time.Millisecond},
		{EndpointID: "a", Status: StatusSuccess, Duration: 10 * time.Millisecond},
		{EndpointID: "failed", Status: StatusUnavailable, Duration: time.Millisecond},
	}
	best, err := Best(results)
	if err != nil {
		t.Fatalf("Best() error = %v", err)
	}
	if best.EndpointID != "a" {
		t.Fatalf("Best() ID = %q, want a", best.EndpointID)
	}

	for name, failed := range map[string][]Result{
		"empty": nil,
		"all failed": {
			{EndpointID: "unavailable", Status: StatusUnavailable, Duration: time.Millisecond},
			{EndpointID: "unsupported", Status: StatusUnsupported},
		},
	} {
		t.Run(name, func(t *testing.T) {
			if got, err := Best(failed); got != (Result{}) || !errors.Is(err, ErrNoAvailableEndpoint) {
				t.Fatalf("Best() = %#v, %v, want zero result and ErrNoAvailableEndpoint", got, err)
			}
		})
	}
}

func TestNewCheckerRejectsUnboundedConfiguration(t *testing.T) {
	t.Parallel()

	for _, config := range []Config{
		{Timeout: 0, MaxParallel: 1},
		{Timeout: -time.Second, MaxParallel: 1},
		{Timeout: 31 * time.Second, MaxParallel: 1},
		{Timeout: time.Second, MaxParallel: 0},
		{Timeout: time.Second, MaxParallel: 129},
	} {
		if checker, err := NewChecker(config); checker != nil || err == nil {
			t.Fatalf("NewChecker(%#v) = %#v, %v, want rejection", config, checker, err)
		}
	}
}

type recordingDialer struct {
	mu        sync.Mutex
	networks  []string
	addresses []string
}

func (dialer *recordingDialer) DialContext(_ context.Context, network, address string) (net.Conn, error) {
	dialer.mu.Lock()
	dialer.networks = append(dialer.networks, network)
	dialer.addresses = append(dialer.addresses, address)
	dialer.mu.Unlock()
	client, server := net.Pipe()
	_ = server.Close()
	return client, nil
}

func (dialer *recordingDialer) calls() ([]string, []string) {
	dialer.mu.Lock()
	defer dialer.mu.Unlock()
	return append([]string(nil), dialer.networks...), append([]string(nil), dialer.addresses...)
}

type blockingDialer struct {
	mu        sync.Mutex
	active    int
	maxActive int
	changed   chan struct{}
	release   chan struct{}
}

func newBlockingDialer() *blockingDialer {
	return &blockingDialer{changed: make(chan struct{}, 32), release: make(chan struct{})}
}

func (dialer *blockingDialer) DialContext(ctx context.Context, _, _ string) (net.Conn, error) {
	dialer.mu.Lock()
	dialer.active++
	if dialer.active > dialer.maxActive {
		dialer.maxActive = dialer.active
	}
	dialer.mu.Unlock()
	dialer.changed <- struct{}{}
	select {
	case <-dialer.release:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	dialer.mu.Lock()
	dialer.active--
	dialer.mu.Unlock()
	client, server := net.Pipe()
	_ = server.Close()
	return client, nil
}

func (dialer *blockingDialer) waitForActive(t *testing.T, want int) {
	t.Helper()
	deadline := time.After(time.Second)
	for {
		dialer.mu.Lock()
		active := dialer.active
		dialer.mu.Unlock()
		if active >= want {
			return
		}
		select {
		case <-dialer.changed:
		case <-deadline:
			t.Fatalf("active dials never reached %d", want)
		}
	}
}

func (dialer *blockingDialer) maximum() int {
	dialer.mu.Lock()
	defer dialer.mu.Unlock()
	return dialer.maxActive
}

func (dialer *blockingDialer) releaseAll() { close(dialer.release) }

type contextDialer struct {
	entered chan time.Time
}

func (dialer *contextDialer) DialContext(ctx context.Context, _, _ string) (net.Conn, error) {
	deadline, _ := ctx.Deadline()
	dialer.entered <- deadline
	<-ctx.Done()
	return nil, ctx.Err()
}

type cancelRecordingDialer struct {
	entered   chan struct{}
	callCount atomic.Int32
}

func (dialer *cancelRecordingDialer) DialContext(ctx context.Context, _, _ string) (net.Conn, error) {
	if dialer.callCount.Add(1) == 1 {
		close(dialer.entered)
	}
	<-ctx.Done()
	return nil, ctx.Err()
}

type lateConnectionDialer struct {
	entered    chan struct{}
	release    chan struct{}
	connection *trackingConnection
}

func newLateConnectionDialer() *lateConnectionDialer {
	client, server := net.Pipe()
	_ = server.Close()
	return &lateConnectionDialer{
		entered:    make(chan struct{}),
		release:    make(chan struct{}),
		connection: &trackingConnection{Conn: client},
	}
}

func (dialer *lateConnectionDialer) DialContext(context.Context, string, string) (net.Conn, error) {
	close(dialer.entered)
	<-dialer.release
	return dialer.connection, nil
}

type trackingConnection struct {
	net.Conn
	closed atomic.Bool
}

func (connection *trackingConnection) Close() error {
	connection.closed.Store(true)
	return connection.Conn.Close()
}

type lateErrorDialer struct {
	entered chan struct{}
	release chan struct{}
}

func (dialer *lateErrorDialer) DialContext(context.Context, string, string) (net.Conn, error) {
	close(dialer.entered)
	<-dialer.release
	return nil, errors.New("late private dial failure")
}

type nilConnectionDialer struct{}

func (nilConnectionDialer) DialContext(context.Context, string, string) (net.Conn, error) {
	return nil, nil
}

type errorDialer struct{ err error }

func (dialer errorDialer) DialContext(context.Context, string, string) (net.Conn, error) {
	return nil, dialer.err
}

func latencyEndpoint(id string, protocol domain.Protocol) domain.Endpoint {
	endpoint := domain.Endpoint{
		ID:             id,
		SubscriptionID: "subscription",
		Name:           id,
		Protocol:       protocol,
		Host:           "stream.example.com",
		Port:           443,
	}
	switch protocol {
	case domain.ProtocolVLESS, domain.ProtocolVMess:
		endpoint.UUID = "123e4567-e89b-12d3-a456-426614174000"
		endpoint.Transport.Type = domain.TransportTCP
	case domain.ProtocolTrojan:
		endpoint.Password = "password"
		endpoint.TLS.Enabled = true
		endpoint.Transport.Type = domain.TransportTCP
	case domain.ProtocolShadowsocks:
		endpoint.Password = "password"
		endpoint.Method = "aes-128-gcm"
	case domain.ProtocolHysteria2:
		endpoint.Password = "password"
		endpoint.TLS.Enabled = true
	case domain.ProtocolTUIC:
		endpoint.UUID = "123e4567-e89b-12d3-a456-426614174000"
		endpoint.Password = "password"
		endpoint.TLS.Enabled = true
	}
	return endpoint
}

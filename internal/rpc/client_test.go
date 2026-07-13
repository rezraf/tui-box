//go:build darwin || linux

package rpc

import (
	"bufio"
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

func TestClientSupportsAllFixedOperations(t *testing.T) {
	handler := &testHandler{}
	server, socketPath := newTestServer(t, handler, ServerConfig{})
	defer server.Close()
	client, err := NewClient(socketPath, time.Second)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := client.Connect(context.Background(), *validRequest().Connect); err != nil {
		t.Fatalf("Connect() failed: %v", err)
	}
	if _, err := client.Status(context.Background()); err != nil {
		t.Fatalf("Status() failed: %v", err)
	}
	if err := client.Health(context.Background()); err != nil {
		t.Fatalf("Health() failed: %v", err)
	}
	if _, err := client.Disconnect(context.Background()); err != nil {
		t.Fatalf("Disconnect() failed: %v", err)
	}
}

func TestClientContextDeadlineInterruptsRequest(t *testing.T) {
	entered := make(chan struct{})
	handler := &testHandler{health: func(ctx context.Context) error {
		close(entered)
		<-ctx.Done()
		return ctx.Err()
	}}
	server, socketPath := newTestServer(t, handler, ServerConfig{OperationTimeout: time.Second})
	defer server.Close()
	client, err := NewClient(socketPath, time.Second)
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Millisecond)
	defer cancel()
	start := time.Now()
	err = client.Health(ctx)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Health() error = %v, want context deadline exceeded", err)
	}
	if elapsed := time.Since(start); elapsed > 500*time.Millisecond {
		t.Fatalf("Health() returned after %s, want prompt context cancellation", elapsed)
	}
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("handler was never entered")
	}
}

func TestClientCancellationCancelsServerHandlerBeforeFurtherWork(t *testing.T) {
	entered := make(chan struct{})
	canceled := make(chan struct{})
	allowMutation := make(chan struct{})
	var mutated atomic.Bool
	handler := &testHandler{health: func(ctx context.Context) error {
		close(entered)
		select {
		case <-ctx.Done():
			close(canceled)
			return ctx.Err()
		case <-allowMutation:
			mutated.Store(true)
			return nil
		}
	}}
	server, socketPath := newTestServer(t, handler, ServerConfig{OperationTimeout: time.Second})
	defer server.Close()
	client, err := NewClient(socketPath, time.Second)
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	clientDone := make(chan error, 1)
	go func() { clientDone <- client.Health(ctx) }()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("handler was never entered")
	}
	cancel()
	select {
	case err := <-clientDone:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("Health() error = %v, want context.Canceled", err)
		}
	case <-time.After(200 * time.Millisecond):
		t.Fatal("client did not return promptly after cancellation")
	}
	select {
	case <-canceled:
	case <-time.After(200 * time.Millisecond):
		close(allowMutation)
		t.Fatal("server handler did not observe peer cancellation")
	}
	close(allowMutation)
	time.Sleep(20 * time.Millisecond)
	if mutated.Load() {
		t.Fatal("handler mutated state after canceled client returned")
	}
}

func TestClientRejectsMalformedOversizedAndMismatchedResponses(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		response func(requestID string) []byte
	}{
		{name: "duplicate key", response: func(id string) []byte {
			return []byte(`{"version":1,"id":"` + id + `","ok":true,"ok":true,"health":{"ready":true}}` + "\n")
		}},
		{name: "unknown field", response: func(id string) []byte {
			return []byte(`{"version":1,"id":"` + id + `","ok":true,"health":{"ready":true},"body":"secret"}` + "\n")
		}},
		{name: "trailing data", response: func(id string) []byte {
			return []byte(`{"version":1,"id":"` + id + `","ok":true,"health":{"ready":true}} {}` + "\n")
		}},
		{name: "mismatched ID", response: func(string) []byte {
			return []byte(`{"version":1,"id":"other","ok":true,"health":{"ready":true}}` + "\n")
		}},
		{name: "oversized", response: func(string) []byte {
			return append(make([]byte, MaxMessageBytes+1), '\n')
		}},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			path, stop := maliciousSocket(t, test.response)
			defer stop()
			client, err := NewClient(path, time.Second)
			if err != nil {
				t.Fatal(err)
			}
			if err := client.Health(context.Background()); !errors.Is(err, ErrInvalidResponse) {
				t.Fatalf("Health() error = %v, want ErrInvalidResponse", err)
			}
		})
	}
}

func TestClientValidatesConnectPayloadBeforeDial(t *testing.T) {
	path := filepath.Join(privateSocketDirectory(t), "missing.sock")
	client, err := NewClient(path, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	payload := *validRequest().Connect
	payload.Endpoint = nil
	if _, err := client.Connect(context.Background(), payload); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("Connect(invalid payload) error = %v, want ErrInvalidRequest before dialing", err)
	}
}

func TestClientRejectsResponseShapeForDifferentOperation(t *testing.T) {
	path, stop := maliciousSocket(t, func(id string) []byte {
		return []byte(`{"version":1,"id":"` + id + `","ok":true,"status":{"state":"disconnected"}}` + "\n")
	})
	defer stop()
	client, err := NewClient(path, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if err := client.Health(context.Background()); !errors.Is(err, ErrInvalidResponse) {
		t.Fatalf("Health(status response) error = %v, want ErrInvalidResponse", err)
	}
}

func TestClientRejectsResponseWithoutNewlineFrame(t *testing.T) {
	path, stop := maliciousSocket(t, func(id string) []byte {
		return []byte(`{"version":1,"id":"` + id + `","ok":true,"health":{"ready":true}}`)
	})
	defer stop()
	client, err := NewClient(path, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if err := client.Health(context.Background()); !errors.Is(err, ErrInvalidResponse) {
		t.Fatalf("Health(unterminated response) error = %v, want ErrInvalidResponse", err)
	}
}

func TestClientMapsSocketPermissionErrorsToAccessDenied(t *testing.T) {
	err := mapClientNetworkError(context.Background(), &net.OpError{Op: "dial", Net: "unix", Err: syscall.EACCES})
	if !errors.Is(err, ErrAccessDenied) {
		t.Fatalf("mapClientNetworkError(EACCES) = %v, want ErrAccessDenied", err)
	}
}

func TestClientMapsUnavailableWithoutLeakingSocketPath(t *testing.T) {
	path := filepath.Join(privateSocketDirectory(t), "sensitive-name.sock")
	client, err := NewClient(path, 50*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	if err := client.Health(context.Background()); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("Health() error = %v, want ErrUnavailable", err)
	} else if strings.Contains(err.Error(), path) || strings.Contains(err.Error(), "sensitive-name") {
		t.Fatalf("Health() leaked socket path: %v", err)
	}
}

func TestNewClientRejectsUnsafeConfiguration(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		name    string
		path    string
		timeout time.Duration
	}{
		{name: "relative path", path: "socket", timeout: time.Second},
		{name: "empty path", path: "", timeout: time.Second},
		{name: "control character", path: "/tmp/socket\nsecret", timeout: time.Second},
		{name: "zero timeout", path: "/tmp/socket", timeout: 0},
		{name: "negative timeout", path: "/tmp/socket", timeout: -time.Second},
	} {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if client, err := NewClient(test.path, test.timeout); client != nil || !errors.Is(err, ErrInvalidRequest) {
				t.Fatalf("NewClient() = %#v, %v, want ErrInvalidRequest", client, err)
			}
		})
	}
}

func maliciousSocket(t *testing.T, response func(string) []byte) (string, func()) {
	t.Helper()
	directory := privateSocketDirectory(t)
	path := filepath.Join(directory, "malicious.sock")
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		connection, err := listener.AcceptUnix()
		if err != nil {
			return
		}
		defer connection.Close()
		line, err := bufio.NewReader(connection).ReadBytes('\n')
		if err != nil {
			return
		}
		request, err := decodeRequest(line[:len(line)-1])
		if err != nil {
			return
		}
		_, _ = connection.Write(response(request.ID))
	}()
	stop := func() {
		_ = listener.Close()
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Error("malicious socket did not stop")
		}
		_ = os.Remove(path)
	}
	return path, stop
}

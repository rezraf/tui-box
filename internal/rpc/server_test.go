//go:build darwin || linux

package rpc

import (
	"bufio"
	"context"
	"errors"
	"io"
	"math"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/rezraf/tui-box/internal/core"
	"github.com/rezraf/tui-box/internal/domain"
)

func TestServerClientIntegrationDerivesKernelPeerIdentity(t *testing.T) {
	handler := &testHandler{}
	server, socketPath := newTestServer(t, handler, ServerConfig{})

	info, err := os.Lstat(socketPath)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode()&os.ModeSocket == 0 || info.Mode().Perm() != 0o660 {
		t.Fatalf("socket mode = %v, want Unix socket 0660", info.Mode())
	}
	if _, gid, ok := fileIdentity(info); !ok || gid != os.Getegid() {
		t.Fatalf("socket GID = %d, %v, want %d", gid, ok, os.Getegid())
	}

	client, err := NewClient(socketPath, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	status, err := client.Connect(context.Background(), *validRequest().Connect)
	if err != nil {
		t.Fatalf("Connect() failed: %v", err)
	}
	if status.State != domain.ConnectionStatusConnected {
		t.Fatalf("Connect() status = %#v, want connected", status)
	}

	request := handler.lastRequest()
	if request.UID != os.Geteuid() || request.GID != os.Getegid() {
		t.Fatalf("handler identity = %d:%d, want kernel peer %d:%d", request.UID, request.GID, os.Geteuid(), os.Getegid())
	}
	if request.Endpoint == nil || request.Endpoint.Host != validRequest().Connect.Endpoint.Host {
		t.Fatal("handler did not receive typed endpoint")
	}

	if err := server.Close(); err != nil {
		t.Fatalf("Close() failed: %v", err)
	}
	if _, err := os.Lstat(socketPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("socket still exists after Close(): %v", err)
	}
}

func TestServerAuthorizesOnlyExplicitUIDs(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		name    string
		allowed map[int]struct{}
		peer    PeerCredentials
		want    bool
	}{
		{name: "root omitted", allowed: map[int]struct{}{501: {}}, peer: PeerCredentials{UID: 0, GID: 0}, want: false},
		{name: "root explicit", allowed: map[int]struct{}{0: {}}, peer: PeerCredentials{UID: 0, GID: 0}, want: true},
		{name: "allowlisted", allowed: map[int]struct{}{501: {}}, peer: PeerCredentials{UID: 501, GID: 20}, want: true},
		{name: "same group only", allowed: map[int]struct{}{501: {}}, peer: PeerCredentials{UID: 502, GID: 20}, want: false},
		{name: "other", allowed: map[int]struct{}{501: {}}, peer: PeerCredentials{UID: 65534, GID: 65534}, want: false},
	} {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if got := peerAuthorized(test.peer, test.allowed); got != test.want {
				t.Fatalf("peerAuthorized(%#v) = %v, want %v", test.peer, got, test.want)
			}
		})
	}
}

func TestServerConfigRejectsKernelIdentitySentinels(t *testing.T) {
	t.Parallel()

	base := ServerConfig{
		SocketPath:  "/var/run/tuibox/tuiboxd.sock",
		SocketGID:   20,
		AllowedUIDs: []int{501},
		Handler:     &testHandler{},
	}
	for _, test := range []struct {
		name    string
		mutate  func(*ServerConfig)
		wantErr error
	}{
		{name: "socket GID", mutate: func(config *ServerConfig) { config.SocketGID = int(math.MaxUint32) }, wantErr: ErrUnsafeSocketPath},
		{name: "allowed UID", mutate: func(config *ServerConfig) { config.AllowedUIDs = []int{int(math.MaxUint32)} }, wantErr: ErrInvalidRequest},
	} {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			config := base
			test.mutate(&config)
			if _, _, err := validateServerConfig(config); !errors.Is(err, test.wantErr) {
				t.Fatalf("validateServerConfig(%s sentinel) error = %v, want %v", test.name, err, test.wantErr)
			}
		})
	}
}

func TestNewServerRejectsEmptyUIDAllowlist(t *testing.T) {
	directory := privateSocketDirectory(t)
	server, err := NewServer(ServerConfig{
		SocketPath:  filepath.Join(directory, "tuiboxd.sock"),
		SocketGID:   os.Getegid(),
		AllowedUIDs: nil,
		Handler:     &testHandler{},
	})
	if server != nil {
		_ = server.Close()
	}
	if !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("NewServer(empty allowlist) = %#v, %v, want ErrInvalidRequest", server, err)
	}
}

func TestServerRejectsUnauthorizedActualPeer(t *testing.T) {
	directory := privateSocketDirectory(t)
	server, err := NewServer(ServerConfig{
		SocketPath:   filepath.Join(directory, "tuiboxd.sock"),
		SocketGID:    os.Getegid(),
		AllowedUIDs:  []int{os.Geteuid() + 1},
		Handler:      &testHandler{},
		ReadTimeout:  time.Second,
		WriteTimeout: time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	startServer(t, server)
	defer server.Close()

	client, err := NewClient(server.SocketPath(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if err := client.Health(context.Background()); !errors.Is(err, ErrAccessDenied) {
		t.Fatalf("Health() error = %v, want ErrAccessDenied", err)
	}
}

func TestSaturatedServerAuthenticatesBeforeRejectingUnauthorizedPeer(t *testing.T) {
	entered := make(chan struct{})
	release := make(chan struct{})
	handler := &testHandler{health: func(ctx context.Context) error {
		close(entered)
		select {
		case <-release:
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	}}
	directory := privateSocketDirectory(t)
	server, err := NewServer(ServerConfig{
		SocketPath:       filepath.Join(directory, "tuiboxd.sock"),
		SocketGID:        os.Getegid(),
		AllowedUIDs:      []int{os.Geteuid()},
		Handler:          handler,
		ReadTimeout:      time.Second,
		WriteTimeout:     time.Second,
		OperationTimeout: time.Second,
		MaxConcurrent:    1,
	})
	if err != nil {
		t.Fatal(err)
	}
	unauthorizedUID := 0
	if os.Geteuid() == 0 {
		unauthorizedUID = 1
	}
	var credentialCalls atomic.Int32
	server.peerCredentials = func(*net.UnixConn) (PeerCredentials, error) {
		if credentialCalls.Add(1) == 1 {
			return PeerCredentials{UID: os.Geteuid(), GID: os.Getegid()}, nil
		}
		return PeerCredentials{UID: unauthorizedUID, GID: os.Getegid()}, nil
	}
	startServer(t, server)
	defer server.Close()
	client, err := NewClient(server.SocketPath(), time.Second)
	if err != nil {
		t.Fatal(err)
	}

	firstDone := make(chan error, 1)
	go func() { firstDone <- client.Health(context.Background()) }()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("first request did not saturate the admitted peer slot")
	}

	unauthorized := dialUnix(t, server.SocketPath())
	defer unauthorized.Close()
	if err := unauthorized.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	response, err := bufio.NewReader(unauthorized).ReadBytes('\n')
	if err != nil {
		close(release)
		<-firstDone
		t.Fatalf("unauthorized peer was rejected as saturation before authentication: %v", err)
	}
	if !strings.Contains(string(response), string(CodeAccessDenied)) {
		close(release)
		<-firstDone
		t.Fatalf("unauthorized saturated response = %s, want access_denied", response)
	}

	close(release)
	if err := <-firstDone; err != nil {
		t.Fatalf("first request failed: %v", err)
	}
}

func TestAdmittedPeerUsesNormalDeadlineAfterShortAuthenticationDeadline(t *testing.T) {
	server, socketPath := newTestServer(t, &testHandler{}, ServerConfig{
		AuthTimeout: 20 * time.Millisecond,
		ReadTimeout: 250 * time.Millisecond,
	})
	defer server.Close()

	connection := dialUnix(t, socketPath)
	defer connection.Close()
	time.Sleep(60 * time.Millisecond)
	request, err := encodeLine(Request{Version: ProtocolVersion, ID: "delayed", Operation: OperationHealth})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := connection.Write(request); err != nil {
		t.Fatalf("write after authentication deadline failed: %v", err)
	}
	if err := connection.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	body, err := bufio.NewReader(connection).ReadBytes('\n')
	if err != nil {
		t.Fatalf("read after authentication deadline failed: %v", err)
	}
	response, err := decodeResponse(bytesTrimSuffix(body, '\n'))
	if err != nil || !response.OK || response.Health == nil {
		t.Fatalf("delayed admitted response = %#v, %v", response, err)
	}
}

func TestServerEnforcesReadDeadlineAndMessageLimit(t *testing.T) {
	handler := &testHandler{}
	server, socketPath := newTestServer(t, handler, ServerConfig{ReadTimeout: 40 * time.Millisecond})
	defer server.Close()

	t.Run("deadline", func(t *testing.T) {
		connection := dialUnix(t, socketPath)
		defer connection.Close()
		if _, err := connection.Write([]byte(`{"version":1`)); err != nil {
			t.Fatal(err)
		}
		if err := connection.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
			t.Fatal(err)
		}
		response, err := bufio.NewReader(connection).ReadBytes('\n')
		if err != nil {
			t.Fatalf("read deadline response failed: %v", err)
		}
		if !strings.Contains(string(response), string(CodeInvalidRequest)) {
			t.Fatalf("deadline response = %s, want invalid_request", response)
		}
	})

	t.Run("oversize", func(t *testing.T) {
		connection := dialUnix(t, socketPath)
		defer connection.Close()
		body := append([]byte(`{"padding":"`), make([]byte, MaxMessageBytes)...)
		body = append(body, []byte(`"}`)...)
		body = append(body, '\n')
		if _, err := connection.Write(body); err != nil {
			t.Fatal(err)
		}
		response, err := bufio.NewReader(connection).ReadBytes('\n')
		if err != nil {
			t.Fatalf("read oversize response failed: %v", err)
		}
		if !strings.Contains(string(response), string(CodeInvalidRequest)) {
			t.Fatalf("oversize response = %s, want invalid_request", response)
		}
	})
}

func TestReadFrameReturnsImmediatelyWhenMessageLimitIsCrossed(t *testing.T) {
	reader := newBlockingFrameReader(MaxMessageBytes + 1)
	defer close(reader.release)
	done := make(chan error, 1)
	go func() {
		_, err := readFrame(reader)
		done <- err
	}()

	select {
	case err := <-done:
		if !errors.Is(err, ErrInvalidRequest) {
			t.Fatalf("readFrame() error = %v, want ErrInvalidRequest", err)
		}
	case <-time.After(200 * time.Millisecond):
		t.Fatal("readFrame() kept draining after crossing MaxMessageBytes")
	}
	if got := reader.bytesRead.Load(); got != MaxMessageBytes+1 {
		t.Fatalf("source bytes read = %d, want exactly %d", got, MaxMessageBytes+1)
	}
	select {
	case <-reader.blocked:
		t.Fatal("readFrame() attempted another source read after crossing the limit")
	default:
	}
}

func TestServerProcessesOneRequestPerConnection(t *testing.T) {
	server, socketPath := newTestServer(t, &testHandler{}, ServerConfig{})
	defer server.Close()

	connection := dialUnix(t, socketPath)
	request := Request{Version: ProtocolVersion, ID: "first", Operation: OperationHealth}
	first, err := encodeLine(request)
	if err != nil {
		t.Fatal(err)
	}
	request.ID = "second"
	second, err := encodeLine(request)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := connection.Write(append(first, second...)); err != nil {
		t.Fatal(err)
	}
	if err := connection.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	response, err := io.ReadAll(connection)
	if err != nil {
		t.Fatal(err)
	}
	if got := bytesCount(response, '\n'); got != 1 {
		t.Fatalf("response frame count = %d, want one: %s", got, response)
	}
	if strings.Contains(string(response), "second") {
		t.Fatalf("server processed second request on same connection: %s", response)
	}
}

func TestServerCapsConcurrentConnections(t *testing.T) {
	entered := make(chan struct{})
	release := make(chan struct{})
	handler := &testHandler{health: func(ctx context.Context) error {
		close(entered)
		select {
		case <-release:
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	}}
	server, socketPath := newTestServer(t, handler, ServerConfig{MaxConcurrent: 1, OperationTimeout: time.Second})
	defer server.Close()
	client, err := NewClient(socketPath, time.Second)
	if err != nil {
		t.Fatal(err)
	}

	firstDone := make(chan error, 1)
	go func() { firstDone <- client.Health(context.Background()) }()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("first request did not enter handler")
	}

	start := time.Now()
	if err := client.Health(context.Background()); err == nil {
		t.Fatal("second request unexpectedly entered a saturated server")
	}
	if time.Since(start) > 500*time.Millisecond {
		t.Fatal("saturated connection was not rejected promptly")
	}
	close(release)
	if err := <-firstDone; err != nil {
		t.Fatalf("first request failed: %v", err)
	}
}

func TestServerAcceptsPrivateConfiguredGroupSocketDirectory(t *testing.T) {
	directory := privateSocketDirectory(t)
	if err := os.Chmod(directory, 0o750); err != nil {
		t.Fatal(err)
	}
	info, err := os.Lstat(directory)
	if err != nil {
		t.Fatal(err)
	}
	_, directoryGID, ok := fileIdentity(info)
	if !ok {
		t.Fatal("could not read directory identity")
	}
	server, err := NewServer(ServerConfig{
		SocketPath:  filepath.Join(directory, "tuiboxd.sock"),
		SocketGID:   directoryGID,
		AllowedUIDs: []int{os.Geteuid()},
		Handler:     &testHandler{},
	})
	if err != nil {
		t.Fatalf("NewServer(private group directory gid=%d mode=%o) failed: %v", directoryGID, info.Mode().Perm(), err)
	}
	if err := server.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestInstallerCreatedSocketDirectorySupportsAuthorizedClient(t *testing.T) {
	directory := os.Getenv("TUIBOX_TEST_INSTALLER_RUN_DIR")
	if directory == "" {
		t.Skip("installer runtime directory not provided")
	}
	info, err := os.Lstat(directory)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o750 {
		t.Fatalf("installer runtime directory mode = %o, want 750", info.Mode().Perm())
	}
	_, directoryGID, ok := fileIdentity(info)
	if !ok || directoryGID != os.Getegid() {
		t.Fatalf("installer runtime directory GID = %d, %v; want %d", directoryGID, ok, os.Getegid())
	}

	server, err := NewServer(ServerConfig{
		SocketPath:  filepath.Join(directory, "tuiboxd.sock"),
		SocketGID:   os.Getegid(),
		AllowedUIDs: []int{os.Geteuid()},
		Handler:     &testHandler{},
	})
	if err != nil {
		t.Fatalf("NewServer(installer directory) failed: %v", err)
	}
	startServer(t, server)

	socketInfo, err := os.Lstat(server.SocketPath())
	if err != nil {
		t.Fatal(err)
	}
	_, socketGID, ok := fileIdentity(socketInfo)
	if socketInfo.Mode().Perm() != 0o660 || !ok || socketGID != os.Getegid() {
		t.Fatalf("socket mode/GID = %o/%d (%v), want 660/%d", socketInfo.Mode().Perm(), socketGID, ok, os.Getegid())
	}
	client, err := NewClient(server.SocketPath(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if err := client.Health(context.Background()); err != nil {
		t.Fatalf("authorized client traversal failed: %v", err)
	}
}

func TestServerRejectsUnsafeSocketPathsAndPreservesFiles(t *testing.T) {
	t.Parallel()

	validConfig := func(path string) ServerConfig {
		return ServerConfig{
			SocketPath:  path,
			SocketGID:   os.Getegid(),
			AllowedUIDs: []int{os.Geteuid()},
			Handler:     &testHandler{},
		}
	}

	t.Run("relative path", func(t *testing.T) {
		t.Parallel()
		if server, err := NewServer(validConfig("tuiboxd.sock")); server != nil || !errors.Is(err, ErrUnsafeSocketPath) {
			t.Fatalf("NewServer(relative) = %#v, %v, want ErrUnsafeSocketPath", server, err)
		}
	})

	t.Run("public directory", func(t *testing.T) {
		t.Parallel()
		directory := privateSocketDirectory(t)
		if err := os.Chmod(directory, 0o755); err != nil {
			t.Fatal(err)
		}
		if server, err := NewServer(validConfig(filepath.Join(directory, "socket"))); server != nil || !errors.Is(err, ErrUnsafeSocketPath) {
			t.Fatalf("NewServer(public parent) = %#v, %v, want ErrUnsafeSocketPath", server, err)
		}
	})

	t.Run("group-writable directory", func(t *testing.T) {
		t.Parallel()
		directory := privateSocketDirectory(t)
		if err := os.Chmod(directory, 0o770); err != nil {
			t.Fatal(err)
		}
		if server, err := NewServer(validConfig(filepath.Join(directory, "socket"))); server != nil || !errors.Is(err, ErrUnsafeSocketPath) {
			t.Fatalf("NewServer(group-writable parent) = %#v, %v, want ErrUnsafeSocketPath", server, err)
		}
	})

	t.Run("writable canonical ancestor", func(t *testing.T) {
		t.Parallel()
		base := privateSocketDirectory(t)
		writable := filepath.Join(base, "writable")
		private := filepath.Join(writable, "private")
		if err := os.MkdirAll(private, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(writable, 0o777); err != nil {
			t.Fatal(err)
		}
		if server, err := NewServer(validConfig(filepath.Join(private, "socket"))); server != nil || !errors.Is(err, ErrUnsafeSocketPath) {
			if server != nil {
				_ = server.Close()
			}
			t.Fatalf("NewServer(writable ancestor) = %#v, %v, want ErrUnsafeSocketPath", server, err)
		}
	})

	t.Run("canonical socket directory", func(t *testing.T) {
		t.Parallel()
		target := privateSocketDirectory(t)
		link := target + "-link"
		if err := os.Symlink(target, link); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.Remove(link) })
		server, err := NewServer(validConfig(filepath.Join(link, "socket")))
		if err != nil {
			t.Fatalf("NewServer(canonical parent) failed: %v", err)
		}
		canonicalTarget, err := filepath.EvalSymlinks(target)
		if err != nil {
			_ = server.Close()
			t.Fatal(err)
		}
		if got, want := server.SocketPath(), filepath.Join(canonicalTarget, "socket"); got != want {
			_ = server.Close()
			t.Fatalf("SocketPath() = %q, want canonical %q", got, want)
		}
		if err := server.Close(); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("existing regular file", func(t *testing.T) {
		t.Parallel()
		path := filepath.Join(privateSocketDirectory(t), "socket")
		if err := os.WriteFile(path, []byte("do not replace"), 0o600); err != nil {
			t.Fatal(err)
		}
		if server, err := NewServer(validConfig(path)); server != nil || !errors.Is(err, ErrUnsafeSocketPath) {
			t.Fatalf("NewServer(regular file) = %#v, %v, want ErrUnsafeSocketPath", server, err)
		}
		content, err := os.ReadFile(path)
		if err != nil || string(content) != "do not replace" {
			t.Fatalf("existing file changed: %q, %v", content, err)
		}
	})
}

func TestServerRejectsOwnedSocketThatIsStillActive(t *testing.T) {
	directory := privateSocketDirectory(t)
	path := filepath.Join(directory, "tuiboxd.sock")
	active, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	active.SetUnlinkOnClose(false)
	defer func() {
		_ = active.Close()
		_ = os.Remove(path)
	}()

	server, err := NewServer(ServerConfig{
		SocketPath:  path,
		SocketGID:   os.Getegid(),
		AllowedUIDs: []int{os.Geteuid()},
		Handler:     &testHandler{},
	})
	if server != nil {
		_ = server.Close()
	}
	if !errors.Is(err, ErrUnsafeSocketPath) {
		t.Fatalf("NewServer(active socket) = %#v, %v, want ErrUnsafeSocketPath", server, err)
	}
}

func TestServerReplacesOnlyOwnedUnixSocketAndUnlinksOnlyItsOwn(t *testing.T) {
	directory := privateSocketDirectory(t)
	path := filepath.Join(directory, "tuiboxd.sock")
	stale, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	stale.SetUnlinkOnClose(false)
	if err := stale.Close(); err != nil {
		t.Fatal(err)
	}

	server, err := NewServer(ServerConfig{
		SocketPath:  path,
		SocketGID:   os.Getegid(),
		AllowedUIDs: []int{os.Geteuid()},
		Handler:     &testHandler{},
	})
	if err != nil {
		t.Fatalf("NewServer() did not safely replace stale socket: %v", err)
	}
	backup := path + ".owned"
	if err := os.Rename(path, backup); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("replacement"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := server.Close(); err != nil {
		t.Fatalf("Close() failed: %v", err)
	}
	content, err := os.ReadFile(path)
	if err != nil || string(content) != "replacement" {
		t.Fatalf("Close removed replacement path: %q, %v", content, err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(backup); err != nil {
		t.Fatal(err)
	}
}

func TestServerCleanupUsesHeldRootAfterDirectoryReplacement(t *testing.T) {
	directory := privateSocketDirectory(t)
	path := filepath.Join(directory, "tuiboxd.sock")
	server, err := NewServer(ServerConfig{
		SocketPath:  path,
		SocketGID:   os.Getegid(),
		AllowedUIDs: []int{os.Geteuid()},
		Handler:     &testHandler{},
	})
	if err != nil {
		t.Fatal(err)
	}

	moved := directory + ".moved"
	if err := os.Rename(directory, moved); err != nil {
		_ = server.Close()
		t.Fatal(err)
	}
	if err := os.Mkdir(directory, 0o700); err != nil {
		_ = server.Close()
		t.Fatal(err)
	}
	replacement := filepath.Join(directory, filepath.Base(path))
	if err := os.WriteFile(replacement, []byte("replacement"), 0o600); err != nil {
		_ = server.Close()
		t.Fatal(err)
	}
	if err := server.Close(); err != nil {
		t.Fatalf("Close() failed: %v", err)
	}
	content, err := os.ReadFile(replacement)
	if err != nil || string(content) != "replacement" {
		t.Fatalf("cleanup changed replacement path: %q, %v", content, err)
	}
	if _, err := os.Lstat(filepath.Join(moved, filepath.Base(path))); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("held-root socket remains after Close(): %v", err)
	}
	if err := os.Remove(replacement); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(directory); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(moved); err != nil {
		t.Fatal(err)
	}
}

func TestServerOperationErrorsAreStableAndRedacted(t *testing.T) {
	var handlerError atomic.Pointer[errorBox]
	handlerError.Store(&errorBox{err: ErrCoreValidation})
	handler := &testHandler{connect: func(context.Context, core.ConnectionRequest) (SessionStatus, error) {
		return SessionStatus{}, handlerError.Load().err
	}}
	server, socketPath := newTestServer(t, handler, ServerConfig{})
	defer server.Close()
	client, err := NewClient(socketPath, time.Second)
	if err != nil {
		t.Fatal(err)
	}

	for _, test := range []struct {
		handlerErr error
		want       error
	}{
		{handlerErr: ErrCoreValidation, want: ErrCoreValidation},
		{handlerErr: ErrProcessFailure, want: ErrProcessFailure},
		{handlerErr: context.DeadlineExceeded, want: ErrTimeout},
		{handlerErr: errors.New("secret.example credential-value Sensitive Endpoint Name"), want: ErrInternal},
	} {
		handlerError.Store(&errorBox{err: test.handlerErr})
		_, err := client.Connect(context.Background(), *validRequest().Connect)
		if !errors.Is(err, test.want) {
			t.Errorf("Connect() error = %v, want %v", err, test.want)
		}
		if err != nil && (strings.Contains(err.Error(), "secret.example") || strings.Contains(err.Error(), "credential-value") || strings.Contains(err.Error(), "Sensitive")) {
			t.Fatalf("Connect() leaked handler details: %v", err)
		}
	}
}

type blockingFrameReader struct {
	remaining []byte
	release   chan struct{}
	blocked   chan struct{}
	blockOnce sync.Once
	bytesRead atomic.Int64
}

func newBlockingFrameReader(size int) *blockingFrameReader {
	return &blockingFrameReader{
		remaining: make([]byte, size),
		release:   make(chan struct{}),
		blocked:   make(chan struct{}),
	}
}

func (reader *blockingFrameReader) Read(output []byte) (int, error) {
	if len(reader.remaining) != 0 {
		count := min(len(output), len(reader.remaining))
		copy(output, reader.remaining[:count])
		reader.remaining = reader.remaining[count:]
		reader.bytesRead.Add(int64(count))
		return count, nil
	}
	reader.blockOnce.Do(func() { close(reader.blocked) })
	<-reader.release
	return 0, io.EOF
}

type errorBox struct {
	err error
}

type testHandler struct {
	mu         sync.Mutex
	request    core.ConnectionRequest
	connect    func(context.Context, core.ConnectionRequest) (SessionStatus, error)
	disconnect func(context.Context) (SessionStatus, error)
	status     func(context.Context) (SessionStatus, error)
	health     func(context.Context) error
}

func (handler *testHandler) Connect(ctx context.Context, request core.ConnectionRequest) (SessionStatus, error) {
	handler.mu.Lock()
	handler.request = request
	handler.mu.Unlock()
	if handler.connect != nil {
		return handler.connect(ctx, request)
	}
	return SessionStatus{State: domain.ConnectionStatusConnected, Mode: request.Mode, Route: request.Route}, nil
}

func (handler *testHandler) Disconnect(ctx context.Context) (SessionStatus, error) {
	if handler.disconnect != nil {
		return handler.disconnect(ctx)
	}
	return SessionStatus{State: domain.ConnectionStatusDisconnected}, nil
}

func (handler *testHandler) Status(ctx context.Context) (SessionStatus, error) {
	if handler.status != nil {
		return handler.status(ctx)
	}
	return SessionStatus{State: domain.ConnectionStatusDisconnected}, nil
}

func (handler *testHandler) Health(ctx context.Context) error {
	if handler.health != nil {
		return handler.health(ctx)
	}
	return nil
}

func (handler *testHandler) lastRequest() core.ConnectionRequest {
	handler.mu.Lock()
	defer handler.mu.Unlock()
	return handler.request
}

func newTestServer(t *testing.T, handler Handler, overrides ServerConfig) (*Server, string) {
	t.Helper()
	directory := privateSocketDirectory(t)
	config := ServerConfig{
		SocketPath:       filepath.Join(directory, "tuiboxd.sock"),
		SocketGID:        os.Getegid(),
		AllowedUIDs:      []int{os.Geteuid()},
		Handler:          handler,
		ReadTimeout:      time.Second,
		WriteTimeout:     time.Second,
		OperationTimeout: time.Second,
		MaxConcurrent:    8,
	}
	if overrides.AuthTimeout != 0 {
		config.AuthTimeout = overrides.AuthTimeout
	}
	if overrides.ReadTimeout != 0 {
		config.ReadTimeout = overrides.ReadTimeout
	}
	if overrides.WriteTimeout != 0 {
		config.WriteTimeout = overrides.WriteTimeout
	}
	if overrides.OperationTimeout != 0 {
		config.OperationTimeout = overrides.OperationTimeout
	}
	if overrides.MaxConcurrent != 0 {
		config.MaxConcurrent = overrides.MaxConcurrent
	}
	server, err := NewServer(config)
	if err != nil {
		t.Fatalf("NewServer() failed: %v", err)
	}
	startServer(t, server)
	return server, config.SocketPath
}

func startServer(t *testing.T, server *Server) {
	t.Helper()
	done := make(chan error, 1)
	go func() { done <- server.Serve() }()
	t.Cleanup(func() {
		_ = server.Close()
		select {
		case err := <-done:
			if err != nil && !errors.Is(err, net.ErrClosed) {
				t.Errorf("Serve() failed: %v", err)
			}
		case <-time.After(time.Second):
			t.Error("Serve() did not stop")
		}
	})
}

func privateSocketDirectory(t *testing.T) string {
	t.Helper()
	homeDirectory, err := os.UserHomeDir()
	if err != nil {
		t.Fatal(err)
	}
	directory, err := os.MkdirTemp(homeDirectory, ".tb-rpc-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(directory) })
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	return directory
}

func dialUnix(t *testing.T, path string) *net.UnixConn {
	t.Helper()
	connection, err := net.DialUnix("unix", nil, &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	return connection
}

func bytesTrimSuffix(input []byte, suffix byte) []byte {
	if len(input) > 0 && input[len(input)-1] == suffix {
		return input[:len(input)-1]
	}
	return input
}

func bytesCount(input []byte, value byte) int {
	count := 0
	for _, current := range input {
		if current == value {
			count++
		}
	}
	return count
}

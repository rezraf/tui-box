//go:build darwin || linux

package rpc

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"math"
	"net"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"github.com/rezraf/tui-box/internal/core"
)

const (
	defaultReadTimeout      = 5 * time.Second
	defaultWriteTimeout     = 5 * time.Second
	defaultOperationTimeout = 30 * time.Second
	defaultMaxConcurrent    = 32
	maxConcurrentLimit      = 1024
	maxUnixSocketPathBytes  = 100
)

var ErrUnsafeSocketPath = errors.New("unsafe Unix socket path")

type Handler interface {
	Connect(context.Context, core.ConnectionRequest) (SessionStatus, error)
	Disconnect(context.Context) (SessionStatus, error)
	Status(context.Context) SessionStatus
	Health(context.Context) error
}

type ServerConfig struct {
	SocketPath       string
	SocketGID        int
	AllowedUIDs      []int
	Handler          Handler
	ReadTimeout      time.Duration
	WriteTimeout     time.Duration
	OperationTimeout time.Duration
	MaxConcurrent    int
}

type Server struct {
	listener         *net.UnixListener
	socketPath       string
	socketInfo       os.FileInfo
	handler          Handler
	allowedUIDs      map[int]struct{}
	readTimeout      time.Duration
	writeTimeout     time.Duration
	operationTimeout time.Duration
	semaphore        chan struct{}
	ctx              context.Context
	cancel           context.CancelFunc

	mu          sync.Mutex
	connections map[*net.UnixConn]struct{}
	serveCalled bool
	closed      bool
	wait        sync.WaitGroup
	closeOnce   sync.Once
	closeErr    error
}

func NewServer(config ServerConfig) (*Server, error) {
	normalized, allowedUIDs, err := validateServerConfig(config)
	if err != nil {
		return nil, err
	}
	directoryInfo, err := inspectSocketDirectory(normalized.SocketPath, normalized.SocketGID)
	if err != nil {
		return nil, err
	}
	if err := removeOwnedStaleSocket(normalized.SocketPath); err != nil {
		return nil, err
	}

	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: normalized.SocketPath, Net: "unix"})
	if err != nil {
		return nil, ErrUnsafeSocketPath
	}
	listener.SetUnlinkOnClose(false)
	createdInfo, err := os.Lstat(normalized.SocketPath)
	if err != nil || createdInfo.Mode()&os.ModeSocket == 0 || createdInfo.Mode()&os.ModeSymlink != 0 {
		_ = listener.Close()
		return nil, ErrUnsafeSocketPath
	}
	cleanup := true
	defer func() {
		if cleanup {
			_ = listener.Close()
			_ = removeOwnedSocket(normalized.SocketPath, createdInfo)
		}
	}()
	if err := os.Chown(normalized.SocketPath, os.Geteuid(), normalized.SocketGID); err != nil {
		return nil, ErrUnsafeSocketPath
	}
	if err := os.Chmod(normalized.SocketPath, 0o660); err != nil {
		return nil, ErrUnsafeSocketPath
	}
	info, err := os.Lstat(normalized.SocketPath)
	if err != nil || info.Mode()&os.ModeSocket == 0 || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0o660 || !os.SameFile(info, createdInfo) {
		return nil, ErrUnsafeSocketPath
	}
	currentDirectoryInfo, err := os.Lstat(filepath.Dir(normalized.SocketPath))
	if err != nil || !os.SameFile(currentDirectoryInfo, directoryInfo) {
		return nil, ErrUnsafeSocketPath
	}
	uid, gid, ok := fileIdentity(info)
	if !ok || uid != os.Geteuid() || gid != normalized.SocketGID {
		return nil, ErrUnsafeSocketPath
	}

	ctx, cancel := context.WithCancel(context.Background())
	server := &Server{
		listener:         listener,
		socketPath:       normalized.SocketPath,
		socketInfo:       info,
		handler:          normalized.Handler,
		allowedUIDs:      allowedUIDs,
		readTimeout:      normalized.ReadTimeout,
		writeTimeout:     normalized.WriteTimeout,
		operationTimeout: normalized.OperationTimeout,
		semaphore:        make(chan struct{}, normalized.MaxConcurrent),
		ctx:              ctx,
		cancel:           cancel,
		connections:      make(map[*net.UnixConn]struct{}),
	}
	cleanup = false
	return server, nil
}

func validateServerConfig(config ServerConfig) (ServerConfig, map[int]struct{}, error) {
	if config.Handler == nil || !validSocketPathString(config.SocketPath) || config.SocketGID < 0 || uint64(config.SocketGID) > math.MaxUint32 {
		return ServerConfig{}, nil, ErrUnsafeSocketPath
	}
	if config.ReadTimeout == 0 {
		config.ReadTimeout = defaultReadTimeout
	}
	if config.WriteTimeout == 0 {
		config.WriteTimeout = defaultWriteTimeout
	}
	if config.OperationTimeout == 0 {
		config.OperationTimeout = defaultOperationTimeout
	}
	if config.MaxConcurrent == 0 {
		config.MaxConcurrent = defaultMaxConcurrent
	}
	if config.ReadTimeout < 0 || config.ReadTimeout > maxRPCDuration || config.WriteTimeout < 0 || config.WriteTimeout > maxRPCDuration ||
		config.OperationTimeout < 0 || config.OperationTimeout > maxRPCDuration || config.MaxConcurrent < 1 || config.MaxConcurrent > maxConcurrentLimit {
		return ServerConfig{}, nil, ErrInvalidRequest
	}
	allowed := make(map[int]struct{}, len(config.AllowedUIDs))
	for _, uid := range config.AllowedUIDs {
		if uid < 0 || uint64(uid) > math.MaxUint32 {
			return ServerConfig{}, nil, ErrInvalidRequest
		}
		allowed[uid] = struct{}{}
	}
	return config, allowed, nil
}

func inspectSocketDirectory(socketPath string, socketGID int) (os.FileInfo, error) {
	directory := filepath.Dir(socketPath)
	info, err := os.Lstat(directory)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return nil, ErrUnsafeSocketPath
	}
	uid, gid, ok := fileIdentity(info)
	if !ok || uid != 0 && uid != os.Geteuid() {
		return nil, ErrUnsafeSocketPath
	}
	permissions := info.Mode().Perm()
	if permissions&0o700 != 0o700 || permissions&0o027 != 0 {
		return nil, ErrUnsafeSocketPath
	}
	if permissions&0o050 != 0 && gid != socketGID {
		return nil, ErrUnsafeSocketPath
	}
	return info, nil
}

func removeOwnedStaleSocket(path string) error {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil || info.Mode()&os.ModeSocket == 0 || info.Mode()&os.ModeSymlink != 0 {
		return ErrUnsafeSocketPath
	}
	uid, _, ok := fileIdentity(info)
	if !ok || uid != os.Geteuid() {
		return ErrUnsafeSocketPath
	}
	probe, probeErr := net.DialTimeout("unix", path, 100*time.Millisecond)
	if probeErr == nil {
		_ = probe.Close()
		return ErrUnsafeSocketPath
	}
	if !errors.Is(probeErr, syscall.ECONNREFUSED) {
		return ErrUnsafeSocketPath
	}
	if err := os.Remove(path); err != nil {
		return ErrUnsafeSocketPath
	}
	return nil
}

func (server *Server) SocketPath() string {
	if server == nil {
		return ""
	}
	return server.socketPath
}

func (server *Server) Serve() error {
	server.mu.Lock()
	if server.closed || server.serveCalled {
		server.mu.Unlock()
		return net.ErrClosed
	}
	server.serveCalled = true
	server.mu.Unlock()

	for {
		connection, err := server.listener.AcceptUnix()
		if err != nil {
			server.mu.Lock()
			closed := server.closed
			server.mu.Unlock()
			if closed || errors.Is(err, net.ErrClosed) {
				return nil
			}
			return err
		}
		select {
		case server.semaphore <- struct{}{}:
			if server.beginConnection(connection) {
				go server.serveConnection(connection)
			} else {
				<-server.semaphore
				_ = connection.Close()
			}
		default:
			_ = connection.Close()
		}
	}
}

func (server *Server) beginConnection(connection *net.UnixConn) bool {
	server.mu.Lock()
	defer server.mu.Unlock()
	if server.closed {
		return false
	}
	server.connections[connection] = struct{}{}
	server.wait.Add(1)
	return true
}

func (server *Server) serveConnection(connection *net.UnixConn) {
	defer func() {
		server.mu.Lock()
		delete(server.connections, connection)
		server.mu.Unlock()
		_ = connection.Close()
		<-server.semaphore
		server.wait.Done()
	}()

	_ = connection.SetReadDeadline(time.Now().Add(server.readTimeout))
	body, err := readFrame(connection)
	if err != nil {
		server.writeResponse(connection, responseForError("", ErrInvalidRequest))
		return
	}
	request, err := decodeRequest(body)
	if err != nil {
		server.writeResponse(connection, responseForError("", ErrInvalidRequest))
		return
	}
	responseID := ""
	if validRequestID(request.ID) {
		responseID = request.ID
	}
	if err := validateRequest(request); err != nil {
		server.writeResponse(connection, responseForError(responseID, err))
		return
	}
	peer, err := kernelPeerCredentials(connection)
	if err != nil || !peerAuthorized(peer, server.allowedUIDs) {
		server.writeResponse(connection, responseForError(request.ID, ErrAccessDenied))
		return
	}

	operationContext, cancel := context.WithTimeout(server.ctx, server.operationTimeout)
	defer cancel()
	response := server.dispatch(operationContext, request, peer)
	server.writeResponse(connection, response)
}

func (server *Server) dispatch(ctx context.Context, request Request, peer PeerCredentials) (response Response) {
	defer func() {
		if recover() != nil {
			response = responseForError(request.ID, ErrInternal)
		}
	}()

	response = Response{Version: ProtocolVersion, ID: request.ID, OK: true}
	switch request.Operation {
	case OperationConnect:
		coreRequest, err := request.Connect.coreRequest(peer)
		if err != nil {
			return responseForError(request.ID, err)
		}
		status, err := server.handler.Connect(ctx, coreRequest)
		if err != nil {
			return responseForError(request.ID, err)
		}
		if !validSessionStatus(status) {
			return responseForError(request.ID, ErrInternal)
		}
		response.Status = &status
	case OperationDisconnect:
		status, err := server.handler.Disconnect(ctx)
		if err != nil {
			return responseForError(request.ID, err)
		}
		if !validSessionStatus(status) {
			return responseForError(request.ID, ErrInternal)
		}
		response.Status = &status
	case OperationStatus:
		status := server.handler.Status(ctx)
		if !validSessionStatus(status) {
			return responseForError(request.ID, ErrInternal)
		}
		response.Status = &status
	case OperationHealth:
		if err := server.handler.Health(ctx); err != nil {
			return responseForError(request.ID, err)
		}
		response.Health = &HealthStatus{Ready: true}
	default:
		return responseForError(request.ID, ErrInvalidRequest)
	}
	return response
}

func (server *Server) writeResponse(connection *net.UnixConn, response Response) {
	_ = connection.SetWriteDeadline(time.Now().Add(server.writeTimeout))
	encoded, err := json.Marshal(response)
	if err != nil || len(encoded) > MaxMessageBytes {
		encoded, _ = json.Marshal(responseForError(response.ID, ErrInternal))
	}
	encoded = append(encoded, '\n')
	_ = writeAll(connection, encoded)
}

func readFrame(reader io.Reader) ([]byte, error) {
	buffered := bufio.NewReaderSize(reader, 32*1024)
	var body bytes.Buffer
	total := 0
	oversized := false
	for {
		fragment, err := buffered.ReadSlice('\n')
		total += len(fragment)
		payloadFragment := fragment
		if len(fragment) > 0 && fragment[len(fragment)-1] == '\n' {
			payloadFragment = fragment[:len(fragment)-1]
		}
		if !oversized {
			if body.Len()+len(payloadFragment) > MaxMessageBytes {
				oversized = true
			} else {
				_, _ = body.Write(payloadFragment)
			}
		}
		if err == nil {
			if oversized || total > MaxMessageBytes+1 {
				return nil, ErrInvalidRequest
			}
			return body.Bytes(), nil
		}
		if errors.Is(err, bufio.ErrBufferFull) {
			continue
		}
		if errors.Is(err, io.EOF) {
			return nil, ErrInvalidRequest
		}
		return nil, err
	}
}

func peerAuthorized(peer PeerCredentials, allowed map[int]struct{}) bool {
	if peer.UID == 0 {
		return true
	}
	_, exists := allowed[peer.UID]
	return exists
}

func (server *Server) Close() error {
	if server == nil {
		return nil
	}
	server.closeOnce.Do(func() {
		server.mu.Lock()
		server.closed = true
		connections := make([]*net.UnixConn, 0, len(server.connections))
		for connection := range server.connections {
			connections = append(connections, connection)
		}
		server.mu.Unlock()

		server.cancel()
		var closeErrors []error
		if err := server.listener.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			closeErrors = append(closeErrors, err)
		}
		for _, connection := range connections {
			_ = connection.Close()
		}
		server.wait.Wait()
		if err := removeOwnedSocket(server.socketPath, server.socketInfo); err != nil {
			closeErrors = append(closeErrors, err)
		}
		server.closeErr = errors.Join(closeErrors...)
	})
	return server.closeErr
}

func removeOwnedSocket(path string, expected os.FileInfo) error {
	current, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil || current.Mode()&os.ModeSocket == 0 || current.Mode()&os.ModeSymlink != 0 {
		return nil
	}
	uid, _, ok := fileIdentity(current)
	if !ok || uid != os.Geteuid() || expected != nil && !os.SameFile(current, expected) {
		return nil
	}
	return os.Remove(path)
}

func fileIdentity(info os.FileInfo) (int, int, bool) {
	status, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, 0, false
	}
	return int(status.Uid), int(status.Gid), true
}

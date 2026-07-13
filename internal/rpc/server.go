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
	"golang.org/x/sys/unix"
)

const (
	defaultAuthTimeout      = 250 * time.Millisecond
	maxAuthTimeout          = 5 * time.Second
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
	Status(context.Context) (SessionStatus, error)
	Health(context.Context) error
}

type ServerConfig struct {
	SocketPath       string
	SocketGID        int
	AllowedUIDs      []int
	Handler          Handler
	AuthTimeout      time.Duration
	ReadTimeout      time.Duration
	WriteTimeout     time.Duration
	OperationTimeout time.Duration
	MaxConcurrent    int
}

type Server struct {
	listener         *net.UnixListener
	socketPath       string
	socketRoot       *os.Root
	socketName       string
	socketInfo       os.FileInfo
	handler          Handler
	allowedUIDs      map[int]struct{}
	peerCredentials  func(*net.UnixConn) (PeerCredentials, error)
	authTimeout      time.Duration
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
	canonicalPath, socketName, socketRoot, directoryInfo, err := openSocketRoot(normalized.SocketPath, normalized.SocketGID)
	if err != nil {
		return nil, err
	}
	cleanupRoot := true
	defer func() {
		if cleanupRoot {
			_ = socketRoot.Close()
		}
	}()
	if err := removeOwnedStaleSocket(socketRoot, socketName, canonicalPath); err != nil {
		return nil, err
	}

	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: canonicalPath, Net: "unix"})
	if err != nil {
		return nil, ErrUnsafeSocketPath
	}
	listener.SetUnlinkOnClose(false)
	createdInfo, err := socketRoot.Lstat(socketName)
	if err != nil || !validSocketInfo(createdInfo) {
		_ = listener.Close()
		return nil, ErrUnsafeSocketPath
	}
	cleanupSocket := true
	defer func() {
		if cleanupSocket {
			_ = listener.Close()
			_ = removeOwnedSocket(socketRoot, socketName, createdInfo)
		}
	}()
	if err := configureSocket(socketRoot, socketName, createdInfo, normalized.SocketGID); err != nil {
		return nil, err
	}
	info, err := socketRoot.Lstat(socketName)
	if err != nil || !validSocketInfo(info) || info.Mode().Perm() != 0o660 || !os.SameFile(info, createdInfo) {
		return nil, ErrUnsafeSocketPath
	}
	currentDirectoryInfo, err := socketRoot.Stat(".")
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
		socketPath:       canonicalPath,
		socketRoot:       socketRoot,
		socketName:       socketName,
		socketInfo:       info,
		handler:          normalized.Handler,
		allowedUIDs:      allowedUIDs,
		peerCredentials:  kernelPeerCredentials,
		authTimeout:      normalized.AuthTimeout,
		readTimeout:      normalized.ReadTimeout,
		writeTimeout:     normalized.WriteTimeout,
		operationTimeout: normalized.OperationTimeout,
		semaphore:        make(chan struct{}, normalized.MaxConcurrent),
		ctx:              ctx,
		cancel:           cancel,
		connections:      make(map[*net.UnixConn]struct{}),
	}
	cleanupSocket = false
	cleanupRoot = false
	return server, nil
}

func validateServerConfig(config ServerConfig) (ServerConfig, map[int]struct{}, error) {
	if config.Handler == nil || !validSocketPathString(config.SocketPath) || config.SocketGID < 0 || uint64(config.SocketGID) >= math.MaxUint32 {
		return ServerConfig{}, nil, ErrUnsafeSocketPath
	}
	if len(config.AllowedUIDs) == 0 {
		return ServerConfig{}, nil, ErrInvalidRequest
	}
	if config.AuthTimeout == 0 {
		config.AuthTimeout = defaultAuthTimeout
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
	if config.AuthTimeout < 0 || config.AuthTimeout > maxAuthTimeout || config.ReadTimeout < 0 || config.ReadTimeout > maxRPCDuration || config.WriteTimeout < 0 || config.WriteTimeout > maxRPCDuration ||
		config.OperationTimeout < 0 || config.OperationTimeout > maxRPCDuration || config.MaxConcurrent < 1 || config.MaxConcurrent > maxConcurrentLimit {
		return ServerConfig{}, nil, ErrInvalidRequest
	}
	allowed := make(map[int]struct{}, len(config.AllowedUIDs))
	for _, uid := range config.AllowedUIDs {
		if uid < 0 || uint64(uid) >= math.MaxUint32 {
			return ServerConfig{}, nil, ErrInvalidRequest
		}
		allowed[uid] = struct{}{}
	}
	return config, allowed, nil
}

func openSocketRoot(socketPath string, socketGID int) (string, string, *os.Root, os.FileInfo, error) {
	canonicalDirectory, err := filepath.EvalSymlinks(filepath.Dir(socketPath))
	if err != nil || !filepath.IsAbs(canonicalDirectory) {
		return "", "", nil, nil, ErrUnsafeSocketPath
	}
	canonicalDirectory = filepath.Clean(canonicalDirectory)
	canonicalPath := filepath.Join(canonicalDirectory, filepath.Base(socketPath))
	if !validSocketPathString(canonicalPath) {
		return "", "", nil, nil, ErrUnsafeSocketPath
	}
	if err := inspectSocketAncestors(canonicalDirectory); err != nil {
		return "", "", nil, nil, err
	}
	before, err := os.Lstat(canonicalDirectory)
	if err != nil || !validPrivateSocketDirectory(before, socketGID) {
		return "", "", nil, nil, ErrUnsafeSocketPath
	}
	root, err := os.OpenRoot(canonicalDirectory)
	if err != nil {
		return "", "", nil, nil, ErrUnsafeSocketPath
	}
	after, err := root.Stat(".")
	if err != nil || !validPrivateSocketDirectory(after, socketGID) || !os.SameFile(before, after) {
		_ = root.Close()
		return "", "", nil, nil, ErrUnsafeSocketPath
	}
	return canonicalPath, filepath.Base(socketPath), root, after, nil
}

func inspectSocketAncestors(directory string) error {
	for {
		info, err := os.Lstat(directory)
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o022 != 0 {
			return ErrUnsafeSocketPath
		}
		uid, _, ok := fileIdentity(info)
		if !ok || uid != 0 && uid != os.Geteuid() {
			return ErrUnsafeSocketPath
		}
		parent := filepath.Dir(directory)
		if parent == directory {
			return nil
		}
		directory = parent
	}
}

func validPrivateSocketDirectory(info os.FileInfo, socketGID int) bool {
	if info == nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return false
	}
	uid, gid, ok := fileIdentity(info)
	if !ok || uid != 0 && uid != os.Geteuid() {
		return false
	}
	permissions := info.Mode().Perm()
	if permissions&0o700 != 0o700 || permissions&0o027 != 0 {
		return false
	}
	return permissions&0o050 == 0 || gid == socketGID
}

func validSocketInfo(info os.FileInfo) bool {
	return info != nil && info.Mode()&os.ModeSocket != 0 && info.Mode()&os.ModeSymlink == 0
}

func configureSocket(root *os.Root, name string, expected os.FileInfo, socketGID int) error {
	directory, err := root.Open(".")
	if err != nil {
		return ErrUnsafeSocketPath
	}
	defer directory.Close()
	if err := unix.Fchownat(int(directory.Fd()), name, os.Geteuid(), socketGID, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return ErrUnsafeSocketPath
	}
	if err := unix.Fchmodat(int(directory.Fd()), name, 0o660, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		if !errors.Is(err, unix.EOPNOTSUPP) {
			return ErrUnsafeSocketPath
		}
		current, statErr := root.Lstat(name)
		if statErr != nil || !validSocketInfo(current) || !os.SameFile(current, expected) {
			return ErrUnsafeSocketPath
		}
		if err := unix.Fchmodat(int(directory.Fd()), name, 0o660, 0); err != nil {
			return ErrUnsafeSocketPath
		}
	}
	current, err := root.Lstat(name)
	if err != nil || !validSocketInfo(current) || !os.SameFile(current, expected) {
		return ErrUnsafeSocketPath
	}
	return nil
}

func removeOwnedStaleSocket(root *os.Root, name, path string) error {
	info, err := root.Lstat(name)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil || !validSocketInfo(info) {
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
	current, err := root.Lstat(name)
	if err != nil || !validSocketInfo(current) || !os.SameFile(current, info) {
		return ErrUnsafeSocketPath
	}
	if err := root.Remove(name); err != nil {
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
		if !server.beginConnection(connection) {
			_ = connection.Close()
			continue
		}
		peer, authorized := server.authenticateConnection(connection)
		if !authorized {
			server.endConnection(connection, false)
			continue
		}
		select {
		case server.semaphore <- struct{}{}:
			go server.serveConnection(connection, peer)
		default:
			server.endConnection(connection, false)
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

func (server *Server) authenticateConnection(connection *net.UnixConn) (PeerCredentials, bool) {
	if err := connection.SetDeadline(time.Now().Add(server.authTimeout)); err != nil {
		return PeerCredentials{}, false
	}
	peer, err := server.peerCredentials(connection)
	if err != nil || !peerAuthorized(peer, server.allowedUIDs) {
		server.writeResponseFrame(connection, responseForError("", ErrAccessDenied))
		return PeerCredentials{}, false
	}
	if err := connection.SetDeadline(time.Time{}); err != nil {
		return PeerCredentials{}, false
	}
	return peer, true
}

func (server *Server) endConnection(connection *net.UnixConn, admitted bool) {
	server.mu.Lock()
	delete(server.connections, connection)
	server.mu.Unlock()
	_ = connection.Close()
	if admitted {
		<-server.semaphore
	}
	server.wait.Done()
}

func (server *Server) serveConnection(connection *net.UnixConn, peer PeerCredentials) {
	defer server.endConnection(connection, true)

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
	operationContext, cancel := context.WithTimeout(server.ctx, server.operationTimeout)
	disconnected := make(chan struct{})
	if deadline, ok := operationContext.Deadline(); ok {
		_ = connection.SetReadDeadline(deadline)
	}
	go watchClientDisconnect(connection, cancel, disconnected)
	response := server.dispatch(operationContext, request, peer)
	cancel()
	_ = connection.SetReadDeadline(time.Now())
	<-disconnected
	server.writeResponse(connection, response)
}

func watchClientDisconnect(connection *net.UnixConn, cancel context.CancelFunc, done chan<- struct{}) {
	defer close(done)
	var buffer [1]byte
	for {
		if _, err := connection.Read(buffer[:]); err != nil {
			cancel()
			return
		}
	}
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
		status, err := server.handler.Status(ctx)
		if err != nil {
			return responseForError(request.ID, err)
		}
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
	server.writeResponseFrame(connection, response)
}

func (server *Server) writeResponseFrame(connection *net.UnixConn, response Response) {
	encoded, err := json.Marshal(response)
	if err != nil || len(encoded) > MaxMessageBytes {
		encoded, _ = json.Marshal(responseForError(response.ID, ErrInternal))
	}
	encoded = append(encoded, '\n')
	_ = writeAll(connection, encoded)
}

func readFrame(reader io.Reader) ([]byte, error) {
	limited := &io.LimitedReader{R: reader, N: MaxMessageBytes + 1}
	buffered := bufio.NewReaderSize(limited, 32*1024)
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
		if err := removeOwnedSocket(server.socketRoot, server.socketName, server.socketInfo); err != nil {
			closeErrors = append(closeErrors, err)
		}
		if err := server.socketRoot.Close(); err != nil {
			closeErrors = append(closeErrors, err)
		}
		server.closeErr = errors.Join(closeErrors...)
	})
	return server.closeErr
}

func removeOwnedSocket(root *os.Root, name string, expected os.FileInfo) error {
	current, err := root.Lstat(name)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil || !validSocketInfo(current) {
		return nil
	}
	uid, _, ok := fileIdentity(current)
	if !ok || uid != os.Geteuid() || expected != nil && !os.SameFile(current, expected) {
		return nil
	}
	return root.Remove(name)
}

func fileIdentity(info os.FileInfo) (int, int, bool) {
	status, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, 0, false
	}
	return int(status.Uid), int(status.Gid), true
}

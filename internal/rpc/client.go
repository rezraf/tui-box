//go:build darwin || linux

package rpc

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"net"
	"path/filepath"
	"syscall"
	"time"
	"unicode"
	"unicode/utf8"
)

const maxRPCDuration = 5 * time.Minute

type Client struct {
	socketPath string
	timeout    time.Duration
}

func NewClient(socketPath string, timeout time.Duration) (*Client, error) {
	if !validSocketPathString(socketPath) || timeout <= 0 || timeout > maxRPCDuration {
		return nil, ErrInvalidRequest
	}
	return &Client{socketPath: socketPath, timeout: timeout}, nil
}

func (client *Client) Connect(ctx context.Context, payload ConnectPayload) (SessionStatus, error) {
	if _, err := payload.coreRequest(PeerCredentials{UID: 1, GID: 1}); err != nil {
		return SessionStatus{}, ErrInvalidRequest
	}
	response, err := client.call(ctx, OperationConnect, &payload)
	if err != nil {
		return SessionStatus{}, err
	}
	return *response.Status, nil
}

func (client *Client) Disconnect(ctx context.Context) (SessionStatus, error) {
	response, err := client.call(ctx, OperationDisconnect, nil)
	if err != nil {
		return SessionStatus{}, err
	}
	return *response.Status, nil
}

func (client *Client) Status(ctx context.Context) (SessionStatus, error) {
	response, err := client.call(ctx, OperationStatus, nil)
	if err != nil {
		return SessionStatus{}, err
	}
	return *response.Status, nil
}

func (client *Client) Health(ctx context.Context) error {
	_, err := client.call(ctx, OperationHealth, nil)
	return err
}

func (client *Client) call(ctx context.Context, operation Operation, payload *ConnectPayload) (Response, error) {
	if client == nil || ctx == nil {
		return Response{}, ErrInvalidRequest
	}
	if err := ctx.Err(); err != nil {
		return Response{}, err
	}
	requestID, err := newRequestID()
	if err != nil {
		return Response{}, ErrInternal
	}
	request := Request{Version: ProtocolVersion, ID: requestID, Operation: operation, Connect: payload}
	if err := validateRequest(request); err != nil {
		return Response{}, err
	}
	line, err := encodeLine(request)
	if err != nil {
		return Response{}, ErrInvalidRequest
	}

	dialer := net.Dialer{Timeout: client.timeout}
	connection, err := dialer.DialContext(ctx, "unix", client.socketPath)
	if err != nil {
		return Response{}, mapClientNetworkError(ctx, err)
	}
	defer connection.Close()
	deadline := time.Now().Add(client.timeout)
	if contextDeadline, ok := ctx.Deadline(); ok && contextDeadline.Before(deadline) {
		deadline = contextDeadline
	}
	if err := connection.SetDeadline(deadline); err != nil {
		return Response{}, ErrUnavailable
	}
	stopCancellation := context.AfterFunc(ctx, func() {
		_ = connection.SetDeadline(time.Now())
		_ = connection.Close()
	})
	defer stopCancellation()

	if err := writeAll(connection, line); err != nil {
		return Response{}, mapClientNetworkError(ctx, err)
	}
	body, err := readFrame(connection)
	if err != nil {
		if errors.Is(err, ErrInvalidRequest) {
			return Response{}, ErrInvalidResponse
		}
		return Response{}, mapClientNetworkError(ctx, err)
	}
	response, err := decodeResponse(body)
	if err != nil {
		return Response{}, ErrInvalidResponse
	}
	if isPreAuthAccessDenied(response) {
		return Response{}, ErrAccessDenied
	}
	if err := validateResponse(response, requestID); err != nil {
		return Response{}, err
	}
	if !response.OK {
		return Response{}, errorForCode(response.Error.Code)
	}
	if operation == OperationHealth && response.Health == nil || operation != OperationHealth && response.Status == nil {
		return Response{}, ErrInvalidResponse
	}
	return response, nil
}

func isPreAuthAccessDenied(response Response) bool {
	return response.Version == ProtocolVersion && response.ID == "" && !response.OK && response.Status == nil && response.Health == nil &&
		response.Error != nil && response.Error.Code == CodeAccessDenied && response.Error.Message == messageForCode(CodeAccessDenied)
}

func newRequestID() (string, error) {
	var random [16]byte
	if _, err := rand.Read(random[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(random[:]), nil
}

func writeAll(connection net.Conn, data []byte) error {
	for len(data) > 0 {
		written, err := connection.Write(data)
		if err != nil {
			return err
		}
		if written <= 0 {
			return net.ErrClosed
		}
		data = data[written:]
	}
	return nil
}

func mapClientNetworkError(ctx context.Context, err error) error {
	if contextErr := ctx.Err(); contextErr != nil {
		return contextErr
	}
	if errors.Is(err, syscall.EACCES) || errors.Is(err, syscall.EPERM) {
		return ErrAccessDenied
	}
	var networkError net.Error
	if errors.As(err, &networkError) && networkError.Timeout() {
		if deadline, ok := ctx.Deadline(); ok && !deadline.After(time.Now()) {
			<-ctx.Done()
			return ctx.Err()
		}
		return ErrTimeout
	}
	return ErrUnavailable
}

func validSocketPathString(path string) bool {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || len(path) > maxUnixSocketPathBytes || !utf8.ValidString(path) {
		return false
	}
	for _, character := range path {
		if unicode.IsControl(character) {
			return false
		}
	}
	return true
}

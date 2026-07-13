package rpc

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"math"
	"net/netip"
	"strings"
	"unicode/utf8"

	"github.com/rezraf/tui-box/internal/core"
	"github.com/rezraf/tui-box/internal/domain"
)

const (
	ProtocolVersion     = 1
	MaxMessageBytes     = 256 * 1024
	MaxRequestIDBytes   = 64
	MaxDirectRules      = 64
	maxJSONNestingDepth = 32
	maxResponseMessage  = 128
)

type Operation string

const (
	OperationConnect    Operation = "connect"
	OperationDisconnect Operation = "disconnect"
	OperationStatus     Operation = "status"
	OperationHealth     Operation = "health"
)

type Code string

const (
	CodeInvalidRequest     Code = "invalid_request"
	CodeUnsupportedVersion Code = "unsupported_version"
	CodeAccessDenied       Code = "access_denied"
	CodeCoreValidation     Code = "core_validation_failed"
	CodeProcessFailure     Code = "process_failed"
	CodeProcessStuck       Code = "process_stuck"
	CodeRollbackFailure    Code = "rollback_failed"
	CodeUnavailable        Code = "unavailable"
	CodeTimeout            Code = "timeout"
	CodeInternal           Code = "internal"
)

var (
	ErrInvalidRequest     = errors.New("request is invalid")
	ErrUnsupportedVersion = errors.New("protocol version is unsupported")
	ErrAccessDenied       = errors.New("access is denied")
	ErrCoreValidation     = errors.New("core configuration was rejected")
	ErrProcessFailure     = errors.New("core process operation failed")
	ErrProcessStuck       = errors.New("core process did not exit")
	ErrRollbackFailure    = errors.New("previous core session could not be restored")
	ErrUnavailable        = errors.New("daemon is unavailable")
	ErrTimeout            = errors.New("operation timed out")
	ErrInternal           = errors.New("internal daemon error")
	ErrInvalidResponse    = errors.New("daemon response is invalid")
)

type Request struct {
	Version   int             `json:"version"`
	ID        string          `json:"id"`
	Operation Operation       `json:"operation"`
	Connect   *ConnectPayload `json:"connect,omitempty"`

	connectPresent bool
}

type ConnectPayload struct {
	Endpoint             *domain.Endpoint      `json:"endpoint,omitempty"`
	Mode                 domain.ConnectionMode `json:"mode"`
	Route                domain.RouteMode      `json:"route"`
	DirectDomainSuffixes []string              `json:"direct_domain_suffixes,omitempty"`
	DirectCIDRs          []netip.Prefix        `json:"direct_cidrs,omitempty"`
}

type PeerCredentials struct {
	UID int
	GID int
}

type SessionStatus struct {
	State domain.ConnectionStatus `json:"state"`
	Mode  domain.ConnectionMode   `json:"mode,omitempty"`
	Route domain.RouteMode        `json:"route,omitempty"`
}

type HealthStatus struct {
	Ready bool `json:"ready"`
}

type ResponseError struct {
	Code    Code   `json:"code"`
	Message string `json:"message"`
}

type Response struct {
	Version int            `json:"version"`
	ID      string         `json:"id"`
	OK      bool           `json:"ok"`
	Status  *SessionStatus `json:"status,omitempty"`
	Health  *HealthStatus  `json:"health,omitempty"`
	Error   *ResponseError `json:"error,omitempty"`
}

func encodeLine(value any) ([]byte, error) {
	encoded, err := json.Marshal(value)
	if err != nil || len(encoded) > MaxMessageBytes {
		return nil, ErrInvalidRequest
	}
	return append(encoded, '\n'), nil
}

func decodeRequest(data []byte) (Request, error) {
	var request Request
	if err := decodeStrict(data, &request); err != nil {
		return Request{}, ErrInvalidRequest
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil {
		return Request{}, ErrInvalidRequest
	}
	_, request.connectPresent = fields["connect"]
	return request, nil
}

func decodeResponse(data []byte) (Response, error) {
	var response Response
	if err := decodeStrict(data, &response); err != nil {
		return Response{}, ErrInvalidResponse
	}
	return response, nil
}

func decodeStrict(data []byte, destination any) error {
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 || len(data) > MaxMessageBytes || !utf8.Valid(data) || trimmed[0] != '{' || trimmed[len(trimmed)-1] != '}' {
		return ErrInvalidRequest
	}
	if err := rejectDuplicateKeys(data); err != nil {
		return ErrInvalidRequest
	}

	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return ErrInvalidRequest
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return ErrInvalidRequest
	}
	return nil
}

func rejectDuplicateKeys(data []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	if err := consumeJSONValue(decoder, 0); err != nil {
		return err
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return ErrInvalidRequest
	}
	return nil
}

func consumeJSONValue(decoder *json.Decoder, depth int) error {
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delimiter, isDelimiter := token.(json.Delim)
	if !isDelimiter {
		return nil
	}
	depth++
	if depth > maxJSONNestingDepth {
		return ErrInvalidRequest
	}

	switch delimiter {
	case '{':
		seen := make(map[string]struct{})
		for decoder.More() {
			keyToken, err := decoder.Token()
			if err != nil {
				return err
			}
			key, ok := keyToken.(string)
			if !ok {
				return ErrInvalidRequest
			}
			canonicalKey := strings.ToLower(key)
			if _, duplicate := seen[canonicalKey]; duplicate {
				return ErrInvalidRequest
			}
			seen[canonicalKey] = struct{}{}
			if key != canonicalKey {
				return ErrInvalidRequest
			}
			if err := consumeJSONValue(decoder, depth); err != nil {
				return err
			}
		}
		closing, err := decoder.Token()
		if err != nil || closing != json.Delim('}') {
			return ErrInvalidRequest
		}
	case '[':
		for decoder.More() {
			if err := consumeJSONValue(decoder, depth); err != nil {
				return err
			}
		}
		closing, err := decoder.Token()
		if err != nil || closing != json.Delim(']') {
			return ErrInvalidRequest
		}
	default:
		return ErrInvalidRequest
	}
	return nil
}

func validateRequest(request Request) error {
	if request.Version != ProtocolVersion {
		return ErrUnsupportedVersion
	}
	if !validRequestID(request.ID) {
		return ErrInvalidRequest
	}
	connectPresent := request.connectPresent || request.Connect != nil
	switch request.Operation {
	case OperationConnect:
		if !connectPresent || request.Connect == nil {
			return ErrInvalidRequest
		}
	case OperationDisconnect, OperationStatus, OperationHealth:
		if connectPresent {
			return ErrInvalidRequest
		}
	default:
		return ErrInvalidRequest
	}
	return nil
}

func validRequestID(value string) bool {
	if len(value) == 0 || len(value) > MaxRequestIDBytes {
		return false
	}
	for _, character := range value {
		if character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z' ||
			character >= '0' && character <= '9' || character == '-' || character == '_' || character == '.' {
			continue
		}
		return false
	}
	return true
}

func (payload *ConnectPayload) coreRequest(peer PeerCredentials) (core.ConnectionRequest, error) {
	if payload == nil || peer.UID < 0 || uint64(peer.UID) >= math.MaxUint32 || peer.GID < 0 || uint64(peer.GID) >= math.MaxUint32 ||
		len(payload.DirectDomainSuffixes) > MaxDirectRules || len(payload.DirectCIDRs) > MaxDirectRules {
		return core.ConnectionRequest{}, ErrInvalidRequest
	}
	for _, prefix := range payload.DirectCIDRs {
		if !prefix.IsValid() || prefix != prefix.Masked() {
			return core.ConnectionRequest{}, ErrInvalidRequest
		}
	}
	request := core.ConnectionRequest{
		Mode:                     payload.Mode,
		Route:                    payload.Route,
		Endpoint:                 payload.Endpoint,
		UID:                      peer.UID,
		GID:                      peer.GID,
		RuleDirectDomainSuffixes: append([]string(nil), payload.DirectDomainSuffixes...),
		RuleDirectCIDRs:          append([]netip.Prefix(nil), payload.DirectCIDRs...),
	}
	if _, err := core.GenerateConfig(request); err != nil {
		return core.ConnectionRequest{}, ErrInvalidRequest
	}
	return request, nil
}

func responseForError(id string, err error) Response {
	code := codeForError(err)
	return Response{
		Version: ProtocolVersion,
		ID:      id,
		OK:      false,
		Error: &ResponseError{
			Code:    code,
			Message: messageForCode(code),
		},
	}
}

func codeForError(err error) Code {
	switch {
	case errors.Is(err, ErrUnsupportedVersion):
		return CodeUnsupportedVersion
	case errors.Is(err, ErrInvalidRequest):
		return CodeInvalidRequest
	case errors.Is(err, ErrAccessDenied):
		return CodeAccessDenied
	case errors.Is(err, ErrCoreValidation):
		return CodeCoreValidation
	case errors.Is(err, ErrProcessStuck):
		return CodeProcessStuck
	case errors.Is(err, ErrRollbackFailure):
		return CodeRollbackFailure
	case errors.Is(err, ErrProcessFailure):
		return CodeProcessFailure
	case errors.Is(err, ErrUnavailable):
		return CodeUnavailable
	case errors.Is(err, ErrTimeout), errors.Is(err, context.DeadlineExceeded), errors.Is(err, context.Canceled):
		return CodeTimeout
	default:
		return CodeInternal
	}
}

func messageForCode(code Code) string {
	switch code {
	case CodeInvalidRequest:
		return ErrInvalidRequest.Error()
	case CodeUnsupportedVersion:
		return ErrUnsupportedVersion.Error()
	case CodeAccessDenied:
		return ErrAccessDenied.Error()
	case CodeCoreValidation:
		return ErrCoreValidation.Error()
	case CodeProcessFailure:
		return ErrProcessFailure.Error()
	case CodeProcessStuck:
		return ErrProcessStuck.Error()
	case CodeRollbackFailure:
		return ErrRollbackFailure.Error()
	case CodeUnavailable:
		return ErrUnavailable.Error()
	case CodeTimeout:
		return ErrTimeout.Error()
	case CodeInternal:
		return ErrInternal.Error()
	default:
		return ""
	}
}

func errorForCode(code Code) error {
	switch code {
	case CodeInvalidRequest:
		return ErrInvalidRequest
	case CodeUnsupportedVersion:
		return ErrUnsupportedVersion
	case CodeAccessDenied:
		return ErrAccessDenied
	case CodeCoreValidation:
		return ErrCoreValidation
	case CodeProcessFailure:
		return ErrProcessFailure
	case CodeProcessStuck:
		return ErrProcessStuck
	case CodeRollbackFailure:
		return ErrRollbackFailure
	case CodeUnavailable:
		return ErrUnavailable
	case CodeTimeout:
		return ErrTimeout
	case CodeInternal:
		return ErrInternal
	default:
		return ErrInvalidResponse
	}
}

func validateResponse(response Response, requestID string) error {
	if response.Version != ProtocolVersion || response.ID != requestID || !validRequestID(response.ID) {
		return ErrInvalidResponse
	}
	if response.OK {
		if response.Error != nil || (response.Status == nil) == (response.Health == nil) {
			return ErrInvalidResponse
		}
		if response.Status != nil && !validSessionStatus(*response.Status) {
			return ErrInvalidResponse
		}
		if response.Health != nil && !response.Health.Ready {
			return ErrInvalidResponse
		}
		return nil
	}
	if response.Status != nil || response.Health != nil || response.Error == nil {
		return ErrInvalidResponse
	}
	if len(response.Error.Message) == 0 || len(response.Error.Message) > maxResponseMessage ||
		response.Error.Message != messageForCode(response.Error.Code) || errorForCode(response.Error.Code) == ErrInvalidResponse {
		return ErrInvalidResponse
	}
	return nil
}

func validSessionStatus(status SessionStatus) bool {
	switch status.State {
	case domain.ConnectionStatusDisconnected, domain.ConnectionStatusConnecting, domain.ConnectionStatusConnected,
		domain.ConnectionStatusDisconnecting, domain.ConnectionStatusFailed:
	default:
		return false
	}
	if status.Mode != "" && status.Mode != domain.ConnectionModeProxy && status.Mode != domain.ConnectionModeTUN {
		return false
	}
	if status.Route != "" && status.Route != domain.RouteModeGlobal && status.Route != domain.RouteModeRule && status.Route != domain.RouteModeDirect {
		return false
	}
	return true
}

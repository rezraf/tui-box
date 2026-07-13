package rpc

import (
	"bytes"
	"errors"
	"math"
	"net/netip"
	"reflect"
	"strings"
	"testing"

	"github.com/rezraf/tui-box/internal/domain"
)

func TestDecodeRequestAcceptsOnlyOneStrictJSONValue(t *testing.T) {
	t.Parallel()

	valid := validRequest()
	encoded, err := encodeLine(valid)
	if err != nil {
		t.Fatalf("encodeLine() failed: %v", err)
	}
	decoded, err := decodeRequest(bytes.TrimSuffix(encoded, []byte{'\n'}))
	if err != nil {
		t.Fatalf("decodeRequest() rejected valid request: %v", err)
	}
	if decoded.ID != valid.ID || decoded.Operation != OperationConnect || decoded.Connect == nil {
		t.Fatalf("decodeRequest() = %#v, want connect request", decoded)
	}

	tests := []struct {
		name string
		body []byte
	}{
		{name: "invalid UTF-8", body: []byte("{\"version\":1,\"id\":\"\xff\",\"operation\":\"health\"}")},
		{name: "unknown top-level field", body: []byte(`{"version":1,"id":"request-1","operation":"health","extra":true}`)},
		{name: "unknown nested field", body: []byte(`{"version":1,"id":"request-1","operation":"connect","connect":{"mode":"tun","route":"direct","extra":true}}`)},
		{name: "unknown endpoint field", body: []byte(`{"version":1,"id":"request-1","operation":"connect","connect":{"mode":"tun","route":"global","endpoint":{"id":"id","subscription_id":"sub","name":"name","protocol":"shadowsocks","host":"example.com","port":443,"password":"secret","method":"aes-128-gcm","tls":{"enabled":false},"transport":{},"uid":501}}}`)},
		{name: "duplicate top-level key", body: []byte(`{"version":1,"version":1,"id":"request-1","operation":"health"}`)},
		{name: "case-insensitive duplicate top-level key", body: []byte(`{"version":1,"Version":1,"id":"request-1","operation":"health"}`)},
		{name: "duplicate nested key", body: []byte(`{"version":1,"id":"request-1","operation":"connect","connect":{"mode":"tun","mode":"proxy","route":"direct"}}`)},
		{name: "case-insensitive duplicate endpoint key", body: []byte(`{"version":1,"id":"request-1","operation":"connect","connect":{"mode":"tun","route":"global","endpoint":{"host":"example.com","HOST":"other.example"}}}`)},
		{name: "case-insensitive duplicate deep key", body: []byte(`{"version":1,"id":"request-1","operation":"connect","connect":{"mode":"tun","route":"global","endpoint":{"tls":{"reality":{"public_key":"one","PUBLIC_KEY":"two"}}}}}`)},
		{name: "mixed-case top-level schema key", body: []byte(`{"Version":1,"id":"request-1","operation":"health"}`)},
		{name: "mixed-case nested schema key", body: []byte(`{"version":1,"id":"request-1","operation":"connect","connect":{"Mode":"tun","route":"direct"}}`)},
		{name: "trailing JSON", body: []byte(`{"version":1,"id":"request-1","operation":"health"} {}`)},
		{name: "empty", body: nil},
		{name: "null", body: []byte(`null`)},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if _, err := decodeRequest(test.body); !errors.Is(err, ErrInvalidRequest) {
				t.Fatalf("decodeRequest() error = %v, want ErrInvalidRequest", err)
			}
		})
	}
}

func TestDuplicateKeyScannerEnforcesMaximumNestingDepth(t *testing.T) {
	t.Parallel()

	atLimit := strings.Repeat("[", maxJSONNestingDepth) + "0" + strings.Repeat("]", maxJSONNestingDepth)
	if err := rejectDuplicateKeys([]byte(atLimit)); err != nil {
		t.Fatalf("rejectDuplicateKeys(depth=%d) failed: %v", maxJSONNestingDepth, err)
	}
	overLimit := "[" + atLimit + "]"
	if err := rejectDuplicateKeys([]byte(overLimit)); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("rejectDuplicateKeys(depth=%d) error = %v, want ErrInvalidRequest", maxJSONNestingDepth+1, err)
	}
}

func TestDecodedRequestDistinguishesMissingNullAndPresentConnect(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		body    string
		wantErr error
	}{
		{
			name:    "connect missing field",
			body:    `{"version":1,"id":"request-1","operation":"connect"}`,
			wantErr: ErrInvalidRequest,
		},
		{
			name:    "connect null field",
			body:    `{"version":1,"id":"request-1","operation":"connect","connect":null}`,
			wantErr: ErrInvalidRequest,
		},
		{
			name: "health omits field",
			body: `{"version":1,"id":"request-1","operation":"health"}`,
		},
		{
			name:    "health forbids null field",
			body:    `{"version":1,"id":"request-1","operation":"health","connect":null}`,
			wantErr: ErrInvalidRequest,
		},
		{
			name:    "disconnect forbids null field",
			body:    `{"version":1,"id":"request-1","operation":"disconnect","connect":null}`,
			wantErr: ErrInvalidRequest,
		},
		{
			name:    "status forbids null field",
			body:    `{"version":1,"id":"request-1","operation":"status","connect":null}`,
			wantErr: ErrInvalidRequest,
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			request, err := decodeRequest([]byte(test.body))
			if err != nil {
				t.Fatalf("decodeRequest() failed before semantic validation: %v", err)
			}
			err = validateRequest(request)
			if !errors.Is(err, test.wantErr) {
				t.Fatalf("validateRequest() error = %v, want %v", err, test.wantErr)
			}
		})
	}
}

func TestDecodeResponseRequiresExactLowerCaseKeysAtEveryDepth(t *testing.T) {
	t.Parallel()

	for _, body := range []string{
		`{"Version":1,"id":"request-1","ok":true,"health":{"ready":true}}`,
		`{"version":1,"id":"request-1","ok":true,"health":{"Ready":true}}`,
		`{"version":1,"id":"request-1","ok":false,"error":{"code":"access_denied","Code":"access_denied","message":"access is denied"}}`,
	} {
		if _, err := decodeResponse([]byte(body)); !errors.Is(err, ErrInvalidResponse) {
			t.Fatalf("decodeResponse(%s) error = %v, want ErrInvalidResponse", body, err)
		}
	}
}

func TestValidateRequestEnforcesVersionIDOperationAndPayload(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		mutate  func(*Request)
		wantErr error
	}{
		{name: "unsupported version", mutate: func(request *Request) { request.Version++ }, wantErr: ErrUnsupportedVersion},
		{name: "empty ID", mutate: func(request *Request) { request.ID = "" }, wantErr: ErrInvalidRequest},
		{name: "oversized ID", mutate: func(request *Request) { request.ID = strings.Repeat("a", MaxRequestIDBytes+1) }, wantErr: ErrInvalidRequest},
		{name: "unsafe ID characters", mutate: func(request *Request) { request.ID = "host.example/secret" }, wantErr: ErrInvalidRequest},
		{name: "unknown operation", mutate: func(request *Request) { request.Operation = "exec" }, wantErr: ErrInvalidRequest},
		{name: "missing connect payload", mutate: func(request *Request) { request.Connect = nil }, wantErr: ErrInvalidRequest},
		{name: "payload on disconnect", mutate: func(request *Request) { request.Operation = OperationDisconnect }, wantErr: ErrInvalidRequest},
		{name: "payload on status", mutate: func(request *Request) { request.Operation = OperationStatus }, wantErr: ErrInvalidRequest},
		{name: "payload on health", mutate: func(request *Request) { request.Operation = OperationHealth }, wantErr: ErrInvalidRequest},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			request := validRequest()
			test.mutate(&request)
			if err := validateRequest(request); !errors.Is(err, test.wantErr) {
				t.Fatalf("validateRequest() error = %v, want %v", err, test.wantErr)
			}
		})
	}

	for _, operation := range []Operation{OperationConnect, OperationDisconnect, OperationStatus, OperationHealth} {
		request := validRequest()
		request.Operation = operation
		if operation != OperationConnect {
			request.Connect = nil
		}
		if err := validateRequest(request); err != nil {
			t.Errorf("validateRequest(%q) failed: %v", operation, err)
		}
	}
}

func TestConnectPayloadContainsOnlyTypedConnectionFields(t *testing.T) {
	t.Parallel()

	payloadType := reflect.TypeOf(ConnectPayload{})
	wantFields := []string{"Endpoint", "Mode", "Route", "DirectDomainSuffixes", "DirectCIDRs"}
	if payloadType.NumField() != len(wantFields) {
		t.Fatalf("ConnectPayload has %d fields, want exactly %d", payloadType.NumField(), len(wantFields))
	}
	for index, want := range wantFields {
		if got := payloadType.Field(index).Name; got != want {
			t.Fatalf("ConnectPayload field %d = %q, want %q", index, got, want)
		}
	}

	payload := validRequest().Connect
	encoded, err := encodeLine(payload)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"uid", "gid", "config", "executable", "environment", "args"} {
		if bytes.Contains(bytes.ToLower(encoded), []byte(forbidden)) {
			t.Fatalf("connect payload exposes forbidden field %q: %s", forbidden, encoded)
		}
	}

	request, err := payload.coreRequest(PeerCredentials{UID: 501, GID: 20})
	if err != nil {
		t.Fatalf("coreRequest() failed: %v", err)
	}
	if request.UID != 501 || request.GID != 20 {
		t.Fatalf("core identity = %d:%d, want kernel peer 501:20", request.UID, request.GID)
	}
	if request.Endpoint != payload.Endpoint || request.Mode != payload.Mode || request.Route != payload.Route {
		t.Fatalf("core request lost typed payload fields: %#v", request)
	}
}

func TestConnectPayloadRejectsKernelIdentitySentinels(t *testing.T) {
	t.Parallel()

	payload := validRequest().Connect
	for _, peer := range []PeerCredentials{
		{UID: int(math.MaxUint32), GID: 20},
		{UID: 501, GID: int(math.MaxUint32)},
	} {
		if _, err := payload.coreRequest(peer); !errors.Is(err, ErrInvalidRequest) {
			t.Fatalf("coreRequest(%#v) error = %v, want ErrInvalidRequest", peer, err)
		}
	}
}

func TestConnectPayloadBoundsCollectionsAndCanonicalCIDRs(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		mutate func(*ConnectPayload)
	}{
		{name: "too many domain suffixes", mutate: func(payload *ConnectPayload) {
			payload.DirectDomainSuffixes = make([]string, MaxDirectRules+1)
			for index := range payload.DirectDomainSuffixes {
				payload.DirectDomainSuffixes[index] = "example.com"
			}
		}},
		{name: "too many CIDRs", mutate: func(payload *ConnectPayload) {
			payload.DirectCIDRs = make([]netip.Prefix, MaxDirectRules+1)
			for index := range payload.DirectCIDRs {
				payload.DirectCIDRs[index] = netip.MustParsePrefix("192.0.2.0/24")
			}
		}},
		{name: "non-canonical CIDR", mutate: func(payload *ConnectPayload) {
			payload.DirectCIDRs = []netip.Prefix{netip.MustParsePrefix("192.0.2.1/24")}
		}},
		{name: "rules outside rule mode", mutate: func(payload *ConnectPayload) {
			payload.Route = domain.RouteModeGlobal
		}},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			payload := *validRequest().Connect
			payload.DirectDomainSuffixes = []string{"internal.example"}
			payload.DirectCIDRs = []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24")}
			test.mutate(&payload)
			if _, err := payload.coreRequest(PeerCredentials{UID: 501, GID: 20}); !errors.Is(err, ErrInvalidRequest) {
				t.Fatalf("coreRequest() error = %v, want ErrInvalidRequest", err)
			}
		})
	}
}

func TestProcessLifecycleErrorsUseStableRedactedCodes(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		err  error
		code Code
	}{
		{err: ErrProcessStuck, code: CodeProcessStuck},
		{err: ErrRollbackFailure, code: CodeRollbackFailure},
	} {
		response := responseForError("request-1", test.err)
		if response.Error == nil || response.Error.Code != test.code || response.Error.Message != messageForCode(test.code) {
			t.Fatalf("responseForError(%v) = %#v, want stable %q", test.err, response, test.code)
		}
		if err := validateResponse(response, "request-1"); err != nil {
			t.Fatalf("validateResponse(%q) failed: %v", test.code, err)
		}
		if err := errorForCode(test.code); !errors.Is(err, test.err) {
			t.Fatalf("errorForCode(%q) = %v, want %v", test.code, err, test.err)
		}
	}
}

func TestJoinedRollbackFailureTakesPrecedenceOverProcessStuck(t *testing.T) {
	t.Parallel()

	joined := errors.Join(ErrRollbackFailure, ErrProcessStuck)
	response := responseForError("request-1", joined)
	if response.Error == nil || response.Error.Code != CodeRollbackFailure {
		t.Fatalf("responseForError(joined rollback failure) = %#v, want %q", response, CodeRollbackFailure)
	}
}

func TestResponseValidationRequiresStableRedactedShape(t *testing.T) {
	t.Parallel()

	success := Response{
		Version: ProtocolVersion,
		ID:      "request-1",
		OK:      true,
		Status:  &SessionStatus{State: domain.ConnectionStatusConnected, Mode: domain.ConnectionModeTUN, Route: domain.RouteModeGlobal},
	}
	if err := validateResponse(success, "request-1"); err != nil {
		t.Fatalf("validateResponse(success) failed: %v", err)
	}

	failure := responseForError("request-1", ErrAccessDenied)
	if err := validateResponse(failure, "request-1"); err != nil {
		t.Fatalf("validateResponse(failure) failed: %v", err)
	}
	if failure.Error == nil || failure.Error.Code != CodeAccessDenied || failure.Error.Message != messageForCode(CodeAccessDenied) {
		t.Fatalf("failure response = %#v, want stable access denied response", failure)
	}

	bad := failure
	bad.Error = &ResponseError{Code: CodeAccessDenied, Message: "denied for secret.example"}
	if err := validateResponse(bad, "request-1"); !errors.Is(err, ErrInvalidResponse) {
		t.Fatalf("validateResponse(unredacted message) error = %v, want ErrInvalidResponse", err)
	}
}

func validRequest() Request {
	return Request{
		Version:   ProtocolVersion,
		ID:        "request-1",
		Operation: OperationConnect,
		Connect: &ConnectPayload{
			Endpoint: &domain.Endpoint{
				ID:             "endpoint-id",
				SubscriptionID: "subscription-id",
				Name:           "Sensitive Endpoint Name",
				Protocol:       domain.ProtocolShadowsocks,
				Host:           "secret.example.com",
				Port:           443,
				Password:       "credential-value",
				Method:         "aes-128-gcm",
			},
			Mode:                 domain.ConnectionModeTUN,
			Route:                domain.RouteModeRule,
			DirectDomainSuffixes: []string{"internal.example"},
			DirectCIDRs:          []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24")},
		},
	}
}

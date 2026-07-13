package redact

import (
	"errors"
	"strings"
	"testing"
)

func TestStringRemovesURLsAndShareLinks(t *testing.T) {
	t.Parallel()

	input := strings.Join([]string{
		`fetch https://alice:secret@provider.example/sub/path?token=top-secret#private failed`,
		`vless://123e4567-e89b-12d3-a456-426614174000@edge.example.com:443?security=tls#name`,
		`vmess://eyJpZCI6InNlY3JldCJ9`,
		`trojan://password@edge.example.com:443`,
		`ss://cipher:password@edge.example.com:8388`,
		`hysteria2://password@edge.example.com:443`,
		`tuic://uuid:password@edge.example.com:443`,
	}, "\n")

	got := String(input)
	for _, secret := range []string{
		"alice", "secret", "provider.example", "sub/path", "top-secret", "private",
		"123e4567-e89b-12d3-a456-426614174000", "edge.example.com", "password",
		"eyJpZCI6InNlY3JldCJ9", "cipher", "uuid",
	} {
		if strings.Contains(got, secret) {
			t.Errorf("String() retained %q in %q", secret, got)
		}
	}
	if got != "fetch [redacted-url] failed\n[redacted-share-link]\n[redacted-share-link]\n[redacted-share-link]\n[redacted-share-link]\n[redacted-share-link]\n[redacted-share-link]" {
		t.Fatalf("String() = %q", got)
	}
}

func TestStringRemovesCredentialAndTokenLikeValues(t *testing.T) {
	t.Parallel()

	input := `password=hunter2 passwd: "quoted secret" pwd='single secret' token=abc.def.ghi api_key: sk_live_12345678901234567890 Authorization: Bearer deadbeefdeadbeefdeadbeefdeadbeef opaque=0123456789abcdef0123456789abcdef`
	got := String(input)

	for _, secret := range []string{"hunter2", "quoted secret", "single secret", "abc.def.ghi", "sk_live_12345678901234567890", "deadbeefdeadbeefdeadbeefdeadbeef", "0123456789abcdef0123456789abcdef"} {
		if strings.Contains(got, secret) {
			t.Errorf("String() retained %q in %q", secret, got)
		}
	}
	if strings.Count(got, "[redacted]") < 7 {
		t.Fatalf("String() did not mark every credential: %q", got)
	}
}

func TestStringRemovesUUIDsAndEndpointAddresses(t *testing.T) {
	t.Parallel()

	input := `endpoint edge.example.com:443 resolved to 203.0.113.42 and [2001:db8::1]:8443 for 123e4567-e89b-12d3-a456-426614174000`
	got := String(input)

	for _, sensitive := range []string{"edge.example.com", "203.0.113.42", "2001:db8::1", "8443", "123e4567-e89b-12d3-a456-426614174000"} {
		if strings.Contains(got, sensitive) {
			t.Errorf("String() retained %q in %q", sensitive, got)
		}
	}
	if got != `endpoint [redacted-address] resolved to [redacted-address] and [redacted-address] for [redacted-uuid]` {
		t.Fatalf("String() = %q", got)
	}
}

func TestStringRemovesExplicitSensitiveValuesAndKeepsOrdinaryText(t *testing.T) {
	t.Parallel()

	input := "connection to private-origin.example failed: temporary timeout"
	got := StringSensitive(input, "private-origin.example", "", "private-origin.example")
	if got != "connection to [redacted] failed: temporary timeout" {
		t.Fatalf("StringSensitive() = %q", got)
	}

	ordinary := "subscription refresh failed because the response was empty"
	if got := String(ordinary); got != ordinary {
		t.Fatalf("String() changed ordinary text to %q", got)
	}
}

func TestErrorReturnsAPlainRedactedError(t *testing.T) {
	t.Parallel()

	if Error(nil) != nil {
		t.Fatal("Error(nil) returned a non-nil error")
	}
	private := errors.New(`Get "https://user:pass@example.com/sub?token=secret": dial edge.example.com:443`)
	public := Error(private)
	if public == nil {
		t.Fatal("Error() returned nil")
	}
	for _, secret := range []string{"user", "pass", "example.com", "token", "secret", "edge.example.com"} {
		if strings.Contains(public.Error(), secret) {
			t.Errorf("Error() retained %q in %q", secret, public)
		}
	}
	if errors.Is(public, private) {
		t.Fatal("Error() retained the private error in its unwrap chain")
	}
}

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

func TestStringRedactsQuotedJSONCredentialsWithoutLeakingRPCPayload(t *testing.T) {
	t.Parallel()

	input := `rpc failed: {"password":"p\\\"rivate","token":"rpc-token","api_key":"rpc-key","authorization":"Bearer rpc-secret","endpoint":"9edge.private.example:443"}`
	got := String(input)
	for _, secret := range []string{`p\\\"rivate`, "rpc-token", "rpc-key", "rpc-secret", "9edge.private.example:443"} {
		if strings.Contains(got, secret) {
			t.Errorf("String() retained %q in %q", secret, got)
		}
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

func TestStringRedactsCompleteIPv4AndDigitLeadingHostnamePorts(t *testing.T) {
	t.Parallel()

	input := "dial 203.0.113.42:8443 then 9edge.private.example:443"
	want := "dial [redacted-address] then [redacted-address]"
	if got := String(input); got != want {
		t.Fatalf("String(%q) = %q, want %q", input, got, want)
	}
}

func TestStringRemovesIPv6Forms(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		input string
		want  string
	}{
		{name: "compressed", input: "dial 2001:db8::1 failed", want: "dial [redacted-address] failed"},
		{name: "loopback", input: "dial ::1 failed", want: "dial [redacted-address] failed"},
		{name: "full", input: "dial 2001:0db8:0000:0000:0000:ff00:0042:8329 failed", want: "dial [redacted-address] failed"},
		{name: "zone", input: "dial fe80::1%en0 failed", want: "dial [redacted-address] failed"},
		{name: "IPv4-mapped", input: "dial ::ffff:192.0.2.128 failed", want: "dial [redacted-address] failed"},
		{name: "bracketed", input: "dial [2001:db8::1] failed", want: "dial [redacted-address] failed"},
		{name: "bracketed with port", input: "dial [fe80::1%en0]:443 failed", want: "dial [redacted-address] failed"},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if got := String(test.input); got != test.want {
				t.Fatalf("String(%q) = %q, want %q", test.input, got, test.want)
			}
		})
	}
}

func TestStringHandlesRedactionEdgesWithoutChangingSurroundingText(t *testing.T) {
	t.Parallel()

	input := "Authorization: Bearer short.jwt, see https://example.com/path, then retry at 12:34."
	want := "[redacted], see [redacted-url], then retry at 12:34."
	if got := String(input); got != want {
		t.Fatalf("String() = %q, want %q", got, want)
	}
}

func TestStringPreservesOrdinaryTimesAndLongWords(t *testing.T) {
	t.Parallel()

	input := "retry at 09:45 after antidisestablishmentarianism"
	if got := String(input); got != input {
		t.Fatalf("String(%q) = %q", input, got)
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

func FuzzStringNoPanic(f *testing.F) {
	for _, seed := range []string{
		"",
		"ordinary text",
		"Authorization: Bearer short.jwt",
		"https://example.com/path?token=secret",
		"2001:db8::1 [fe80::1%en0]:443",
		string([]byte{0xff, 0xfe, 0xfd}),
	} {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, input string) {
		_ = String(input)
		_ = StringSensitive(input, input, "", "duplicate", "duplicate")
		_ = Error(errors.New(input), input)
	})
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

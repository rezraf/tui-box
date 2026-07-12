package subscription

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"strings"
	"testing"

	"github.com/rezraf/tui-box/internal/domain"
)

const testSubscriptionID = "subscription-1"

func TestParseIndividualShareLinks(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		fixture  string
		protocol domain.Protocol
		host     string
		display  string
		check    func(*testing.T, domain.Endpoint)
	}{
		{
			name: "vless reality websocket", fixture: "vless.txt", protocol: domain.ProtocolVLESS,
			host: "vless.example.com", display: "VLESS Reality",
			check: func(t *testing.T, endpoint domain.Endpoint) {
				assertTLS(t, endpoint, "front.example.com", false, []string{"h2", "http/1.1"})
				if endpoint.Transport != (domain.TransportOptions{Type: domain.TransportWebSocket, Path: "/ws", Host: "cdn.example.com"}) {
					t.Fatalf("Transport = %#v, want websocket fields", endpoint.Transport)
				}
			},
		},
		{
			name: "vmess base64 JSON", fixture: "vmess.txt", protocol: domain.ProtocolVMess,
			host: "vmess.example.com", display: "VMess WS",
			check: func(t *testing.T, endpoint domain.Endpoint) {
				assertTLS(t, endpoint, "front.example.com", false, []string{"h2", "http/1.1"})
				if endpoint.Transport != (domain.TransportOptions{Type: domain.TransportWebSocket, Path: "/vmess", Host: "cdn.example.com"}) {
					t.Fatalf("Transport = %#v, want websocket fields", endpoint.Transport)
				}
				if endpoint.VMessOptions == nil || endpoint.VMessOptions.Security != domain.VMessSecurityAuto || endpoint.VMessOptions.AlterID != 0 {
					t.Fatalf("VMessOptions = %#v, want auto security and alter ID 0", endpoint.VMessOptions)
				}
			},
		},
		{
			name: "trojan grpc", fixture: "trojan.txt", protocol: domain.ProtocolTrojan,
			host: "trojan.example.com", display: "Trojan gRPC",
			check: func(t *testing.T, endpoint domain.Endpoint) {
				if endpoint.Password != "trojan-secret" {
					t.Fatalf("Password = %q, want parsed credential", endpoint.Password)
				}
				assertTLS(t, endpoint, "trojan-sni.example.com", false, []string{"h2"})
				if endpoint.Transport != (domain.TransportOptions{Type: domain.TransportGRPC, ServiceName: "trojan.Service"}) {
					t.Fatalf("Transport = %#v, want gRPC fields", endpoint.Transport)
				}
			},
		},
		{
			name: "shadowsocks SIP002", fixture: "shadowsocks.txt", protocol: domain.ProtocolShadowsocks,
			host: "ss.example.com", display: "Shadowsocks Node",
			check: func(t *testing.T, endpoint domain.Endpoint) {
				if endpoint.Method != "aes-256-gcm" || endpoint.Password != "ss-secret" {
					t.Fatalf("Shadowsocks credentials were not parsed")
				}
			},
		},
		{
			name: "hysteria2 alias", fixture: "hysteria2.txt", protocol: domain.ProtocolHysteria2,
			host: "hy2.example.com", display: "Hysteria 2",
			check: func(t *testing.T, endpoint domain.Endpoint) {
				assertTLS(t, endpoint, "hy-sni.example.com", true, []string{"h3"})
				want := &domain.Hysteria2Options{ObfsType: domain.Hysteria2ObfsSalamander, ObfsPassword: "obfs-secret", UpMbps: 100, DownMbps: 200}
				if endpoint.Hysteria2Options == nil || *endpoint.Hysteria2Options != *want {
					t.Fatalf("Hysteria2Options = %#v, want %#v", endpoint.Hysteria2Options, want)
				}
			},
		},
		{
			name: "tuic", fixture: "tuic.txt", protocol: domain.ProtocolTUIC,
			host: "tuic.example.com", display: "TUIC Node",
			check: func(t *testing.T, endpoint domain.Endpoint) {
				assertTLS(t, endpoint, "tuic-sni.example.com", false, []string{"h3"})
				want := &domain.TUICOptions{CongestionControl: domain.TUICCongestionBBR, UDPRelayMode: domain.TUICUDPRelayQUIC, ZeroRTT: true}
				if endpoint.TUICOptions == nil || *endpoint.TUICOptions != *want {
					t.Fatalf("TUICOptions = %#v, want %#v", endpoint.TUICOptions, want)
				}
			},
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			result, err := Parse(testSubscriptionID, readFixture(t, test.fixture))
			if err != nil {
				t.Fatalf("Parse() returned an unexpected error: %v", err)
			}
			if result.Format != domain.SubscriptionFormatURIList {
				t.Fatalf("Format = %q, want %q", result.Format, domain.SubscriptionFormatURIList)
			}
			if len(result.Endpoints) != 1 {
				t.Fatalf("len(Endpoints) = %d, want 1", len(result.Endpoints))
			}
			if len(result.Warnings) != 0 {
				t.Fatalf("Warnings = %#v, want none", result.Warnings)
			}
			endpoint := result.Endpoints[0]
			if endpoint.Protocol != test.protocol || endpoint.Host != test.host || endpoint.Name != test.display {
				t.Fatalf("Endpoint identity = (%q, %q, %q), want (%q, %q, %q)", endpoint.Protocol, endpoint.Host, endpoint.Name, test.protocol, test.host, test.display)
			}
			if endpoint.SubscriptionID != testSubscriptionID {
				t.Fatalf("SubscriptionID = %q, want %q", endpoint.SubscriptionID, testSubscriptionID)
			}
			if err := endpoint.Validate(); err != nil {
				t.Fatalf("parsed endpoint did not validate: %v", err)
			}
			test.check(t, endpoint)
		})
	}
}

func TestParseURIListCoversAllSupportedProtocols(t *testing.T) {
	t.Parallel()

	result, err := Parse(testSubscriptionID, readFixture(t, "uri-list.txt"))
	if err != nil {
		t.Fatalf("Parse() returned an unexpected error: %v", err)
	}
	assertSixProtocols(t, result.Endpoints)
	if result.Format != domain.SubscriptionFormatURIList {
		t.Fatalf("Format = %q, want URI list", result.Format)
	}
}

func TestParseWholeDocumentBase64Variants(t *testing.T) {
	t.Parallel()

	for _, fixture := range []string{
		"base64-standard.txt",
		"base64-raw-standard.txt",
		"base64-url.txt",
		"base64-raw-url.txt",
	} {
		fixture := fixture
		t.Run(fixture, func(t *testing.T) {
			t.Parallel()
			result, err := Parse(testSubscriptionID, readFixture(t, fixture))
			if err != nil {
				t.Fatalf("Parse() returned an unexpected error: %v", err)
			}
			if result.Format != domain.SubscriptionFormatBase64 {
				t.Fatalf("Format = %q, want Base64", result.Format)
			}
			assertSixProtocols(t, result.Endpoints)
		})
	}
}

func TestParseClashYAML(t *testing.T) {
	t.Parallel()

	result, err := Parse(testSubscriptionID, readFixture(t, "clash.yaml"))
	if err != nil {
		t.Fatalf("Parse() returned an unexpected error: %v", err)
	}
	if result.Format != domain.SubscriptionFormatClash {
		t.Fatalf("Format = %q, want Clash", result.Format)
	}
	assertSixProtocols(t, result.Endpoints)

	vless := endpointByProtocol(t, result.Endpoints, domain.ProtocolVLESS)
	if vless.VLESSOptions == nil || vless.VLESSOptions.Flow != domain.VLESSFlowXTLSRPRXVision || vless.VLESSOptions.PacketEncoding != domain.PacketEncodingXUDP {
		t.Fatalf("VLESSOptions = %#v, want Clash flow and packet encoding", vless.VLESSOptions)
	}
	if vless.Transport.Type != domain.TransportTCP || !vless.TLS.Enabled || vless.TLS.ServerName != "reality.example.com" {
		t.Fatalf("VLESS TLS/transport mapping is incomplete: %#v", vless)
	}
	vmess := endpointByProtocol(t, result.Endpoints, domain.ProtocolVMess)
	if vmess.Transport != (domain.TransportOptions{Type: domain.TransportGRPC, ServiceName: "clash.Service"}) {
		t.Fatalf("VMess transport = %#v, want Clash gRPC mapping", vmess.Transport)
	}
	trojan := endpointByProtocol(t, result.Endpoints, domain.ProtocolTrojan)
	if trojan.Transport != (domain.TransportOptions{Type: domain.TransportHTTPUpgrade, Path: "/upgrade", Host: "upgrade.example.com"}) {
		t.Fatalf("Trojan transport = %#v, want Clash HTTPUpgrade mapping", trojan.Transport)
	}
}

func TestParseSingBoxJSON(t *testing.T) {
	t.Parallel()

	result, err := Parse(testSubscriptionID, readFixture(t, "singbox.json"))
	if err != nil {
		t.Fatalf("Parse() returned an unexpected error: %v", err)
	}
	if result.Format != domain.SubscriptionFormatSingBox {
		t.Fatalf("Format = %q, want sing-box", result.Format)
	}
	assertSixProtocols(t, result.Endpoints)
	if len(result.Warnings) != 1 {
		t.Fatalf("len(Warnings) = %d, want one skipped direct outbound", len(result.Warnings))
	}

	vless := endpointByProtocol(t, result.Endpoints, domain.ProtocolVLESS)
	if vless.Transport != (domain.TransportOptions{Type: domain.TransportHTTPUpgrade, Path: "/upgrade", Host: "upgrade.example.com"}) {
		t.Fatalf("VLESS transport = %#v, want sing-box HTTPUpgrade mapping", vless.Transport)
	}
	trojan := endpointByProtocol(t, result.Endpoints, domain.ProtocolTrojan)
	if trojan.Transport != (domain.TransportOptions{Type: domain.TransportWebSocket, Path: "/trojan", Host: "cdn.example.com"}) {
		t.Fatalf("Trojan transport = %#v, want bounded Host header only", trojan.Transport)
	}

	encoded, err := json.Marshal(result.Endpoints)
	if err != nil {
		t.Fatalf("json.Marshal() failed: %v", err)
	}
	if strings.Contains(string(encoded), "ignored") || strings.Contains(string(encoded), "X-Secret") {
		t.Fatalf("parsed endpoints preserved unsupported provider configuration: %s", encoded)
	}
}

func TestParseShadowsocksSIP002Variants(t *testing.T) {
	t.Parallel()

	encodedPadded := base64.URLEncoding.EncodeToString([]byte("aes-128-gcm:padded-secret"))
	legacy := base64.RawStdEncoding.EncodeToString([]byte("chacha20-ietf-poly1305:legacy-secret@legacy.example.com:8389"))
	tests := []struct {
		name     string
		link     string
		method   string
		password string
		host     string
	}{
		{name: "base64url userinfo without padding", link: strings.TrimSpace(string(readFixture(t, "shadowsocks.txt"))), method: "aes-256-gcm", password: "ss-secret", host: "ss.example.com"},
		{name: "base64url userinfo with padding", link: "ss://" + encodedPadded + "@padded.example.com:8388#Padded", method: "aes-128-gcm", password: "padded-secret", host: "padded.example.com"},
		{name: "percent encoded userinfo", link: "ss://aes-256-gcm:plain%20secret@plain.example.com:8388#Plain", method: "aes-256-gcm", password: "plain secret", host: "plain.example.com"},
		{name: "legacy whole authority", link: "ss://" + legacy + "#Legacy", method: "chacha20-ietf-poly1305", password: "legacy-secret", host: "legacy.example.com"},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			result, err := Parse(testSubscriptionID, []byte(test.link))
			if err != nil {
				t.Fatalf("Parse() returned an unexpected error: %v", err)
			}
			endpoint := result.Endpoints[0]
			if endpoint.Method != test.method || endpoint.Password != test.password || endpoint.Host != test.host {
				t.Fatalf("Endpoint = %#v, want method %q, password %q, host %q", endpoint, test.method, test.password, test.host)
			}
		})
	}
}

func TestParseDerivesStableCredentialSafeIDsAndDeduplicates(t *testing.T) {
	t.Parallel()

	document := readFixture(t, "deduplicate.txt")
	first, err := Parse("subscription-a", document)
	if err != nil {
		t.Fatalf("first Parse() failed: %v", err)
	}
	second, err := Parse("subscription-b", document)
	if err != nil {
		t.Fatalf("second Parse() failed: %v", err)
	}
	if len(first.Endpoints) != 1 || len(second.Endpoints) != 1 {
		t.Fatalf("duplicate identities were not collapsed: %d and %d", len(first.Endpoints), len(second.Endpoints))
	}
	if first.Endpoints[0].ID != second.Endpoints[0].ID {
		t.Fatalf("IDs differ across subscription/name context: %q != %q", first.Endpoints[0].ID, second.Endpoints[0].ID)
	}
	if !regexp.MustCompile(`^[0-9a-f]{64}$`).MatchString(first.Endpoints[0].ID) {
		t.Fatalf("ID = %q, want a SHA-256 hex digest", first.Endpoints[0].ID)
	}
	for _, sensitive := range []string{"550e8400", "dedup.example.com"} {
		if strings.Contains(first.Endpoints[0].ID, sensitive) {
			t.Fatalf("ID contains source content %q", sensitive)
		}
	}
}

func TestParseRejectsEmptyAndMalformedDocuments(t *testing.T) {
	t.Parallel()

	for _, fixture := range []string{"empty.txt", "malformed.txt"} {
		fixture := fixture
		t.Run(fixture, func(t *testing.T) {
			t.Parallel()
			result, err := Parse(testSubscriptionID, readFixture(t, fixture))
			if err == nil {
				t.Fatal("Parse() returned nil error, want rejection")
			}
			if len(result.Endpoints) != 0 {
				t.Fatalf("Parse() returned %d endpoints for malformed input", len(result.Endpoints))
			}
		})
	}
}

func TestParseRejectsOversizedDocument(t *testing.T) {
	t.Parallel()

	document := make([]byte, MaxDocumentBytes+1)
	result, err := Parse(testSubscriptionID, document)
	if err == nil {
		t.Fatal("Parse() returned nil error, want size rejection")
	}
	if len(result.Endpoints) != 0 {
		t.Fatalf("Parse() returned %d endpoints for oversized input", len(result.Endpoints))
	}
}

func TestParseCapsEntryCountAcrossFormats(t *testing.T) {
	t.Parallel()

	link := strings.TrimSpace(string(readFixture(t, "shadowsocks.txt")))
	uriDocument := []byte(strings.Repeat(link+"\n", MaxEntries+1))

	outbounds := make([]string, MaxEntries+1)
	for index := range outbounds {
		outbounds[index] = `{"type":"direct"}`
	}
	jsonDocument := []byte(`{"outbounds":[` + strings.Join(outbounds, ",") + `]}`)

	for name, document := range map[string][]byte{"URI list": uriDocument, "sing-box JSON": jsonDocument} {
		name, document := name, document
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if len(document) > MaxDocumentBytes {
				t.Fatalf("test input exceeds document cap before exercising entry cap")
			}
			_, err := Parse(testSubscriptionID, document)
			if err == nil {
				t.Fatal("Parse() returned nil error, want entry-count rejection")
			}
		})
	}
}

func TestParseSkipsOversizedEntryAndKeepsValidEntries(t *testing.T) {
	t.Parallel()

	result, err := Parse(testSubscriptionID, readFixture(t, "oversized-entry.txt"))
	if err != nil {
		t.Fatalf("Parse() returned an unexpected error: %v", err)
	}
	if len(result.Endpoints) != 1 || result.Endpoints[0].Protocol != domain.ProtocolShadowsocks {
		t.Fatalf("Endpoints = %#v, want only valid Shadowsocks entry", result.Endpoints)
	}
	if len(result.Warnings) != 1 {
		t.Fatalf("len(Warnings) = %d, want one oversized-entry warning", len(result.Warnings))
	}
}

func TestParseWarningsAreRedacted(t *testing.T) {
	t.Parallel()

	document := readFixture(t, "redacted-warnings.txt")
	result, err := Parse(testSubscriptionID, document)
	if err != nil {
		t.Fatalf("Parse() returned an unexpected error: %v", err)
	}
	if len(result.Endpoints) != 1 || len(result.Warnings) != 2 {
		t.Fatalf("got %d endpoints and %d warnings, want 1 and 2", len(result.Endpoints), len(result.Warnings))
	}

	encoded, err := json.Marshal(result.Warnings)
	if err != nil {
		t.Fatalf("json.Marshal() failed: %v", err)
	}
	warningText := string(encoded)
	for _, sensitive := range []string{
		"vless://", "wireguard://", "secret-address.example.com", "private-address.example.com",
		"550e8400-e29b-41d4-a716-446655440000", "source-password", "private-credential",
		"top-secret-query", "private-query", "token=", "secret=",
	} {
		if strings.Contains(warningText, sensitive) {
			t.Fatalf("warnings leaked sensitive source value %q: %s", sensitive, warningText)
		}
	}
	for index, warning := range result.Warnings {
		if warning.Entry < 1 || warning.Message == "" {
			t.Fatalf("warning %d is not actionable: %#v", index, warning)
		}
	}
}

func TestParseDoesNotLeakMalformedDocumentInError(t *testing.T) {
	t.Parallel()

	sensitive := "vless://550e8400-e29b-41d4-a716-446655440000:password@secret.example.com:99999?token=query-secret"
	_, err := Parse(testSubscriptionID, []byte(sensitive))
	if err == nil {
		t.Fatal("Parse() returned nil error, want rejection")
	}
	for _, value := range []string{sensitive, "550e8400", "password", "secret.example.com", "query-secret"} {
		if strings.Contains(err.Error(), value) {
			t.Fatalf("error leaked %q: %v", value, err)
		}
	}
}

func TestParseRejectsInvalidSubscriptionIDWithoutLeakingIt(t *testing.T) {
	t.Parallel()

	sensitiveID := strings.Repeat("sensitive-id-", 20)
	_, err := Parse(sensitiveID, readFixture(t, "shadowsocks.txt"))
	if err == nil {
		t.Fatal("Parse() returned nil error, want invalid subscription ID rejection")
	}
	if strings.Contains(err.Error(), sensitiveID) {
		t.Fatalf("error leaked subscription ID: %v", err)
	}
}

func assertTLS(t *testing.T, endpoint domain.Endpoint, serverName string, insecure bool, alpn []string) {
	t.Helper()
	if !endpoint.TLS.Enabled || endpoint.TLS.ServerName != serverName || endpoint.TLS.InsecureSkipVerify != insecure || fmt.Sprint(endpoint.TLS.ALPN) != fmt.Sprint(alpn) {
		t.Fatalf("TLS = %#v, want enabled, server name %q, insecure %t, ALPN %v", endpoint.TLS, serverName, insecure, alpn)
	}
}

func assertSixProtocols(t *testing.T, endpoints []domain.Endpoint) {
	t.Helper()
	if len(endpoints) != 6 {
		t.Fatalf("len(Endpoints) = %d, want 6", len(endpoints))
	}
	seen := make(map[domain.Protocol]bool, len(endpoints))
	for _, endpoint := range endpoints {
		if err := endpoint.Validate(); err != nil {
			t.Fatalf("endpoint %q did not validate: %v", endpoint.Name, err)
		}
		seen[endpoint.Protocol] = true
	}
	for _, protocol := range []domain.Protocol{
		domain.ProtocolVLESS,
		domain.ProtocolVMess,
		domain.ProtocolTrojan,
		domain.ProtocolShadowsocks,
		domain.ProtocolHysteria2,
		domain.ProtocolTUIC,
	} {
		if !seen[protocol] {
			t.Errorf("supported protocol %q was not parsed", protocol)
		}
	}
}

func endpointByProtocol(t *testing.T, endpoints []domain.Endpoint, protocol domain.Protocol) domain.Endpoint {
	t.Helper()
	for _, endpoint := range endpoints {
		if endpoint.Protocol == protocol {
			return endpoint
		}
	}
	t.Fatalf("protocol %q not found", protocol)
	return domain.Endpoint{}
}

func readFixture(t *testing.T, name string) []byte {
	t.Helper()
	content, err := os.ReadFile("testdata/" + name)
	if err != nil {
		t.Fatalf("read fixture %q: %v", name, err)
	}
	return content
}

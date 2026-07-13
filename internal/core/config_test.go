package core

import (
	"bytes"
	"encoding/json"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rezraf/tui-box/internal/domain"
)

func TestGenerateConfigMatchesCompleteModeRouteGoldens(t *testing.T) {
	t.Parallel()

	for _, mode := range []domain.ConnectionMode{domain.ConnectionModeProxy, domain.ConnectionModeTUN} {
		for _, route := range []domain.RouteMode{domain.RouteModeGlobal, domain.RouteModeRule, domain.RouteModeDirect} {
			mode, route := mode, route
			t.Run(string(mode)+"/"+string(route), func(t *testing.T) {
				t.Parallel()
				request := validConnectionRequest(mode, route)
				if route == domain.RouteModeDirect {
					request.Endpoint = nil
				}
				if route == domain.RouteModeRule {
					request.RuleDirectDomainSuffixes = []string{"Example.COM", "internal.example"}
					request.RuleDirectCIDRs = []netip.Prefix{
						netip.MustParsePrefix("192.0.2.0/24"),
						netip.MustParsePrefix("2001:db8::/32"),
					}
				}

				golden := string(mode) + "-" + string(route) + ".json"
				want, err := os.ReadFile(filepath.Join("testdata", "golden", golden))
				if err != nil {
					t.Fatal(err)
				}
				got := generateConfig(t, request)
				if !bytes.Equal(got, want) {
					t.Fatalf("generated config does not match %s\ngot:\n%s\nwant:\n%s", golden, got, want)
				}
			})
		}
	}
}

func TestGenerateConfigBuildsFixedProxyAndTUNInbounds(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		mode domain.ConnectionMode
		want map[string]any
	}{
		{
			name: "proxy",
			mode: domain.ConnectionModeProxy,
			want: map[string]any{
				"type":        "mixed",
				"tag":         inboundTag,
				"listen":      proxyListenAddress,
				"listen_port": float64(proxyListenPort),
			},
		},
		{
			name: "TUN",
			mode: domain.ConnectionModeTUN,
			want: map[string]any{
				"type":           "tun",
				"tag":            inboundTag,
				"interface_name": tunInterfaceName,
				"address":        []any{tunAddress},
				"auto_route":     true,
				"strict_route":   true,
			},
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			request := validConnectionRequest(test.mode, domain.RouteModeGlobal)
			config := decodeConfig(t, generateConfig(t, request))
			inbounds := config["inbounds"].([]any)
			if len(inbounds) != 1 {
				t.Fatalf("inbound count = %d, want 1", len(inbounds))
			}
			inbound := inbounds[0].(map[string]any)
			for key, want := range test.want {
				if got := inbound[key]; !valuesEqual(got, want) {
					t.Errorf("inbound[%q] = %#v, want %#v", key, got, want)
				}
			}
			if test.mode == domain.ConnectionModeProxy && inbound["listen"] != "127.0.0.1" {
				t.Fatalf("proxy listen = %#v, want loopback", inbound["listen"])
			}
		})
	}
}

func TestGenerateConfigMapsRouteModesAndFixedDNS(t *testing.T) {
	t.Parallel()

	tests := []struct {
		route         domain.RouteMode
		wantFinal     string
		wantOutbounds int
	}{
		{route: domain.RouteModeGlobal, wantFinal: proxyOutboundTag, wantOutbounds: 2},
		{route: domain.RouteModeRule, wantFinal: proxyOutboundTag, wantOutbounds: 2},
		{route: domain.RouteModeDirect, wantFinal: directOutboundTag, wantOutbounds: 1},
	}

	for _, test := range tests {
		test := test
		t.Run(string(test.route), func(t *testing.T) {
			t.Parallel()
			request := validConnectionRequest(domain.ConnectionModeProxy, test.route)
			if test.route == domain.RouteModeDirect {
				request.Endpoint = nil
			}
			config := decodeConfig(t, generateConfig(t, request))
			route := config["route"].(map[string]any)
			if got := route["final"]; got != test.wantFinal {
				t.Errorf("route final = %#v, want %q", got, test.wantFinal)
			}
			outbounds := config["outbounds"].([]any)
			if len(outbounds) != test.wantOutbounds {
				t.Errorf("outbound count = %d, want %d", len(outbounds), test.wantOutbounds)
			}
			assertPrivateAndLANDirect(t, route["rules"].([]any))
			dns := config["dns"].(map[string]any)
			if dns["final"] != dnsServerTag {
				t.Errorf("DNS final = %#v, want %q", dns["final"], dnsServerTag)
			}
			servers := dns["servers"].([]any)
			server := servers[0].(map[string]any)
			if server["server"] != dnsServerAddress || server["detour"] != directOutboundTag {
				t.Errorf("DNS server = %#v, want fixed direct resolver", server)
			}
		})
	}
}

func TestGenerateConfigEmitsDistinctRuleModeDirectRules(t *testing.T) {
	t.Parallel()

	request := validConnectionRequest(domain.ConnectionModeProxy, domain.RouteModeRule)
	request.RuleDirectDomainSuffixes = []string{"Example.COM", "internal.example"}
	request.RuleDirectCIDRs = []netip.Prefix{
		netip.MustParsePrefix("192.0.2.0/24"),
		netip.MustParsePrefix("2001:db8::/32"),
	}

	config := decodeConfig(t, generateConfig(t, request))
	rules := config["route"].(map[string]any)["rules"].([]any)
	var domainRule, cidrRule map[string]any
	for _, raw := range rules {
		rule := raw.(map[string]any)
		if _, ok := rule["domain_suffix"]; ok {
			if suffixes := rule["domain_suffix"].([]any); len(suffixes) == 2 {
				domainRule = rule
			}
		}
		if _, ok := rule["ip_cidr"]; ok {
			cidrRule = rule
		}
	}
	if domainRule == nil || cidrRule == nil {
		t.Fatalf("custom Rule routes are missing: %#v", rules)
	}
	if !valuesEqual(domainRule["domain_suffix"], []any{"example.com", "internal.example"}) {
		t.Errorf("domain suffixes = %#v", domainRule["domain_suffix"])
	}
	if _, mixed := domainRule["ip_cidr"]; mixed {
		t.Fatal("domain and CIDR values must be emitted as distinct rules")
	}
	if !valuesEqual(cidrRule["ip_cidr"], []any{"192.0.2.0/24", "2001:db8::/32"}) {
		t.Errorf("CIDRs = %#v", cidrRule["ip_cidr"])
	}
	if _, mixed := cidrRule["domain_suffix"]; mixed {
		t.Fatal("CIDR and domain values must be emitted as distinct rules")
	}
}

func TestGenerateConfigRejectsInvalidRuleModeDirectFields(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		mutate func(*ConnectionRequest)
	}{
		{
			name: "domains outside Rule mode",
			mutate: func(request *ConnectionRequest) {
				request.Route = domain.RouteModeGlobal
				request.RuleDirectDomainSuffixes = []string{"example.com"}
			},
		},
		{
			name: "CIDRs outside Rule mode",
			mutate: func(request *ConnectionRequest) {
				request.Route = domain.RouteModeDirect
				request.Endpoint = nil
				request.RuleDirectCIDRs = []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24")}
			},
		},
		{
			name: "too many domains",
			mutate: func(request *ConnectionRequest) {
				request.RuleDirectDomainSuffixes = make([]string, maxRuleDirectDomainSuffixes+1)
				for i := range request.RuleDirectDomainSuffixes {
					request.RuleDirectDomainSuffixes[i] = "example.com"
				}
			},
		},
		{
			name: "too many CIDRs",
			mutate: func(request *ConnectionRequest) {
				request.RuleDirectCIDRs = make([]netip.Prefix, maxRuleDirectCIDRs+1)
				for i := range request.RuleDirectCIDRs {
					request.RuleDirectCIDRs[i] = netip.MustParsePrefix("192.0.2.0/24")
				}
			},
		},
		{
			name: "empty domain",
			mutate: func(request *ConnectionRequest) {
				request.RuleDirectDomainSuffixes = []string{""}
			},
		},
		{
			name: "domain whitespace",
			mutate: func(request *ConnectionRequest) {
				request.RuleDirectDomainSuffixes = []string{" example.com"}
			},
		},
		{
			name: "domain leading dot",
			mutate: func(request *ConnectionRequest) {
				request.RuleDirectDomainSuffixes = []string{".example.com"}
			},
		},
		{
			name: "domain empty label",
			mutate: func(request *ConnectionRequest) {
				request.RuleDirectDomainSuffixes = []string{"example..com"}
			},
		},
		{
			name: "domain IP literal",
			mutate: func(request *ConnectionRequest) {
				request.RuleDirectDomainSuffixes = []string{"192.0.2.1"}
			},
		},
		{
			name: "duplicate normalized domain",
			mutate: func(request *ConnectionRequest) {
				request.RuleDirectDomainSuffixes = []string{"example.com", "Example.COM"}
			},
		},
		{
			name: "invalid prefix",
			mutate: func(request *ConnectionRequest) {
				request.RuleDirectCIDRs = []netip.Prefix{{}}
			},
		},
		{
			name: "noncanonical prefix",
			mutate: func(request *ConnectionRequest) {
				request.RuleDirectCIDRs = []netip.Prefix{netip.MustParsePrefix("192.0.2.1/24")}
			},
		},
		{
			name: "duplicate prefix",
			mutate: func(request *ConnectionRequest) {
				prefix := netip.MustParsePrefix("192.0.2.0/24")
				request.RuleDirectCIDRs = []netip.Prefix{prefix, prefix}
			},
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			request := validConnectionRequest(domain.ConnectionModeProxy, domain.RouteModeRule)
			test.mutate(&request)
			if output, err := GenerateConfig(request); output != nil || err == nil {
				t.Fatalf("GenerateConfig() = %q, %v, want rejection", output, err)
			}
		})
	}
}

func TestGenerateConfigGlobalDoesNotEmitRuleModeDirectFields(t *testing.T) {
	t.Parallel()

	request := validConnectionRequest(domain.ConnectionModeProxy, domain.RouteModeGlobal)
	config := decodeConfig(t, generateConfig(t, request))
	encoded, err := json.Marshal(config["route"])
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(encoded, []byte("example.com")) || bytes.Contains(encoded, []byte("192.0.2.0/24")) {
		t.Fatalf("Global route contains Rule-only values: %s", encoded)
	}
}

func TestGenerateConfigMapsAllProtocolOutbounds(t *testing.T) {
	t.Parallel()

	realityKey := "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	tests := []struct {
		name       string
		endpoint   domain.Endpoint
		wantFields map[string]any
		absent     []string
	}{
		{
			name: "VLESS flow packet encoding TLS uTLS Reality",
			endpoint: func() domain.Endpoint {
				endpoint := validEndpoint()
				endpoint.VLESSOptions = &domain.VLESSOptions{
					Flow:           domain.VLESSFlowXTLSRPRXVision,
					PacketEncoding: domain.PacketEncodingXUDP,
				}
				endpoint.TLS.ALPN = []string{"h2", "http/1.1"}
				endpoint.TLS.UTLSFingerprint = domain.UTLSFingerprintChrome
				endpoint.TLS.Reality = &domain.RealityClientOptions{PublicKey: realityKey, ShortID: "abcd"}
				return endpoint
			}(),
			wantFields: map[string]any{
				"type":            "vless",
				"uuid":            "11111111-1111-4111-8111-111111111111",
				"flow":            "xtls-rprx-vision",
				"packet_encoding": "xudp",
			},
			absent: []string{"password", "method", "security", "transport"},
		},
		{
			name: "VMess",
			endpoint: func() domain.Endpoint {
				endpoint := validEndpoint()
				endpoint.Protocol = domain.ProtocolVMess
				endpoint.VLESSOptions = nil
				endpoint.VMessOptions = &domain.VMessOptions{
					Security:       domain.VMessSecurityAES128GCM,
					AlterID:        7,
					PacketEncoding: domain.PacketEncodingPacketAddr,
				}
				endpoint.Transport = domain.TransportOptions{Type: domain.TransportWebSocket, Path: "/vmess", Host: "ws.example.com"}
				return endpoint
			}(),
			wantFields: map[string]any{
				"type":            "vmess",
				"security":        "aes-128-gcm",
				"alter_id":        float64(7),
				"packet_encoding": "packetaddr",
			},
			absent: []string{"password", "method", "flow", "obfs", "congestion_control"},
		},
		{
			name: "Trojan",
			endpoint: func() domain.Endpoint {
				endpoint := validEndpoint()
				endpoint.Protocol = domain.ProtocolTrojan
				endpoint.UUID = ""
				endpoint.Password = "trojan-password"
				endpoint.Transport = domain.TransportOptions{Type: domain.TransportGRPC, ServiceName: "trojan-service"}
				return endpoint
			}(),
			wantFields: map[string]any{"type": "trojan", "password": "trojan-password"},
			absent:     []string{"uuid", "method", "flow", "security", "packet_encoding"},
		},
		{
			name: "Shadowsocks",
			endpoint: func() domain.Endpoint {
				endpoint := validEndpoint()
				endpoint.Protocol = domain.ProtocolShadowsocks
				endpoint.UUID = ""
				endpoint.Password = "shadowsocks-password"
				endpoint.Method = "aes-256-gcm"
				endpoint.TLS = domain.TLSOptions{}
				endpoint.Transport = domain.TransportOptions{}
				return endpoint
			}(),
			wantFields: map[string]any{
				"type":     "shadowsocks",
				"password": "shadowsocks-password",
				"method":   "aes-256-gcm",
			},
			absent: []string{"uuid", "tls", "transport", "flow", "security", "packet_encoding"},
		},
		{
			name: "Hysteria2",
			endpoint: func() domain.Endpoint {
				endpoint := validEndpoint()
				endpoint.Protocol = domain.ProtocolHysteria2
				endpoint.UUID = ""
				endpoint.Password = "hysteria-password"
				endpoint.Transport = domain.TransportOptions{}
				endpoint.Hysteria2Options = &domain.Hysteria2Options{
					ObfsType:     domain.Hysteria2ObfsSalamander,
					ObfsPassword: "obfs-password",
					UpMbps:       100,
					DownMbps:     500,
				}
				return endpoint
			}(),
			wantFields: map[string]any{
				"type":      "hysteria2",
				"password":  "hysteria-password",
				"up_mbps":   float64(100),
				"down_mbps": float64(500),
				"obfs": map[string]any{
					"type":     "salamander",
					"password": "obfs-password",
				},
			},
			absent: []string{"uuid", "method", "transport", "flow", "security", "packet_encoding"},
		},
		{
			name: "TUIC",
			endpoint: func() domain.Endpoint {
				endpoint := validEndpoint()
				endpoint.Protocol = domain.ProtocolTUIC
				endpoint.Password = "tuic-password"
				endpoint.Transport = domain.TransportOptions{}
				endpoint.TUICOptions = &domain.TUICOptions{
					CongestionControl: domain.TUICCongestionBBR,
					UDPRelayMode:      domain.TUICUDPRelayQUIC,
					ZeroRTT:           true,
				}
				return endpoint
			}(),
			wantFields: map[string]any{
				"type":               "tuic",
				"password":           "tuic-password",
				"congestion_control": "bbr",
				"udp_relay_mode":     "quic",
				"zero_rtt_handshake": true,
			},
			absent: []string{"method", "transport", "flow", "security", "packet_encoding", "obfs"},
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			request := validConnectionRequest(domain.ConnectionModeProxy, domain.RouteModeGlobal)
			request.Endpoint = &test.endpoint
			config := decodeConfig(t, generateConfig(t, request))
			outbound := config["outbounds"].([]any)[0].(map[string]any)
			if outbound["tag"] != proxyOutboundTag {
				t.Errorf("tag = %#v, want %q", outbound["tag"], proxyOutboundTag)
			}
			if outbound["server"] != test.endpoint.Host || outbound["server_port"] != float64(test.endpoint.Port) {
				t.Errorf("server mapping = %#v:%#v", outbound["server"], outbound["server_port"])
			}
			for key, want := range test.wantFields {
				if got := outbound[key]; !valuesEqual(got, want) {
					t.Errorf("outbound[%q] = %#v, want %#v", key, got, want)
				}
			}
			for _, key := range test.absent {
				if value, exists := outbound[key]; exists {
					t.Errorf("incompatible field %q is present with %#v", key, value)
				}
			}
			assertNoEmptyJSONValues(t, outbound, "outbound")
		})
	}
}

func TestGenerateConfigMapsVLESSStreamTransports(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		transport domain.TransportOptions
		want      map[string]any
	}{
		{name: "TCP omitted as native stream", transport: domain.TransportOptions{Type: domain.TransportTCP}},
		{
			name:      "WebSocket",
			transport: domain.TransportOptions{Type: domain.TransportWebSocket, Path: "/websocket", Host: "ws.example.com"},
			want: map[string]any{
				"type":    "ws",
				"path":    "/websocket",
				"headers": map[string]any{"Host": "ws.example.com"},
			},
		},
		{
			name:      "gRPC",
			transport: domain.TransportOptions{Type: domain.TransportGRPC, ServiceName: "grpc-service"},
			want:      map[string]any{"type": "grpc", "service_name": "grpc-service"},
		},
		{
			name:      "HTTPUpgrade",
			transport: domain.TransportOptions{Type: domain.TransportHTTPUpgrade, Path: "/upgrade", Host: "upgrade.example.com"},
			want:      map[string]any{"type": "httpupgrade", "path": "/upgrade", "host": "upgrade.example.com"},
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			request := validConnectionRequest(domain.ConnectionModeProxy, domain.RouteModeGlobal)
			request.Endpoint.Transport = test.transport
			config := decodeConfig(t, generateConfig(t, request))
			outbound := config["outbounds"].([]any)[0].(map[string]any)
			got, exists := outbound["transport"]
			if test.want == nil {
				if exists {
					t.Fatalf("transport = %#v, want field omitted", got)
				}
				return
			}
			if !exists || !valuesEqual(got, test.want) {
				t.Fatalf("transport = %#v, want %#v", got, test.want)
			}
		})
	}
}

func TestGenerateConfigMapsTLSNestedOptions(t *testing.T) {
	t.Parallel()

	request := validConnectionRequest(domain.ConnectionModeProxy, domain.RouteModeGlobal)
	request.Endpoint.TLS = domain.TLSOptions{
		Enabled:            true,
		ServerName:         "tls.example.com",
		InsecureSkipVerify: true,
		ALPN:               []string{"h2"},
		UTLSFingerprint:    domain.UTLSFingerprintSafari,
		Reality: &domain.RealityClientOptions{
			PublicKey: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
			ShortID:   "0123abcd",
		},
	}
	config := decodeConfig(t, generateConfig(t, request))
	outbound := config["outbounds"].([]any)[0].(map[string]any)
	tls := outbound["tls"].(map[string]any)
	want := map[string]any{
		"enabled":     true,
		"server_name": "tls.example.com",
		"insecure":    true,
		"alpn":        []any{"h2"},
		"utls": map[string]any{
			"enabled":     true,
			"fingerprint": "safari",
		},
		"reality": map[string]any{
			"enabled":    true,
			"public_key": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
			"short_id":   "0123abcd",
		},
	}
	if !valuesEqual(tls, want) {
		t.Fatalf("TLS = %#v, want %#v", tls, want)
	}
}

func TestGenerateConfigExcludesEndpointMetadataAndDirectEndpoint(t *testing.T) {
	t.Parallel()

	request := validConnectionRequest(domain.ConnectionModeProxy, domain.RouteModeGlobal)
	request.Endpoint.ID = "provider-id-must-not-appear"
	request.Endpoint.SubscriptionID = "provider-subscription-must-not-appear"
	request.Endpoint.Name = "provider-name-must-not-appear"
	output := generateConfig(t, request)
	for _, forbidden := range []string{request.Endpoint.ID, request.Endpoint.SubscriptionID, request.Endpoint.Name} {
		if bytes.Contains(output, []byte(forbidden)) {
			t.Errorf("generated config contains provider metadata %q", forbidden)
		}
	}

	direct := request
	direct.Route = domain.RouteModeDirect
	directOutput := generateConfig(t, direct)
	if bytes.Contains(directOutput, []byte(request.Endpoint.Host)) || bytes.Contains(directOutput, []byte(request.Endpoint.UUID)) {
		t.Fatalf("direct config contains endpoint values: %s", directOutput)
	}
}

func TestGenerateConfigIsDeterministic(t *testing.T) {
	t.Parallel()

	request := validConnectionRequest(domain.ConnectionModeProxy, domain.RouteModeGlobal)
	first := generateConfig(t, request)
	second := generateConfig(t, request)
	if !bytes.Equal(first, second) {
		t.Fatalf("GenerateConfig() is not deterministic:\nfirst: %s\nsecond: %s", first, second)
	}
	if len(first) == 0 || first[len(first)-1] != '\n' {
		t.Fatalf("GenerateConfig() must return newline-terminated JSON: %q", first)
	}
}

func TestGenerateConfigRejectsInvalidRequestsWithoutLeakingSecrets(t *testing.T) {
	t.Parallel()

	const secret = "do-not-leak-this-password"
	invalidEndpoint := validEndpoint()
	invalidEndpoint.Password = secret

	tests := []struct {
		name    string
		mutate  func(*ConnectionRequest)
		wantErr string
	}{
		{name: "mode", mutate: func(request *ConnectionRequest) { request.Mode = "provider-mode" }, wantErr: "connection mode"},
		{name: "route", mutate: func(request *ConnectionRequest) { request.Route = "provider-route" }, wantErr: "route mode"},
		{name: "port", mutate: func(request *ConnectionRequest) { request.Endpoint.Port = 0 }, wantErr: "endpoint"},
		{name: "UID negative", mutate: func(request *ConnectionRequest) { request.UID = -1 }, wantErr: "UID"},
		{name: "GID negative", mutate: func(request *ConnectionRequest) { request.GID = -1 }, wantErr: "GID"},
		{name: "proxy root UID", mutate: func(request *ConnectionRequest) { request.UID = 0 }, wantErr: "UID"},
		{name: "proxy root GID", mutate: func(request *ConnectionRequest) { request.GID = 0 }, wantErr: "GID"},
		{name: "missing endpoint", mutate: func(request *ConnectionRequest) { request.Endpoint = nil }, wantErr: "endpoint"},
		{name: "invalid endpoint", mutate: func(request *ConnectionRequest) { request.Endpoint = &invalidEndpoint }, wantErr: "endpoint"},
		{name: "invalid direct endpoint", mutate: func(request *ConnectionRequest) {
			request.Route = domain.RouteModeDirect
			request.Endpoint = &invalidEndpoint
		}, wantErr: "endpoint"},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			request := validConnectionRequest(domain.ConnectionModeProxy, domain.RouteModeGlobal)
			test.mutate(&request)
			output, err := GenerateConfig(request)
			if err == nil {
				t.Fatal("GenerateConfig() returned nil error")
			}
			if output != nil {
				t.Fatalf("GenerateConfig() output = %q, want nil", output)
			}
			if !strings.Contains(err.Error(), test.wantErr) {
				t.Errorf("error = %q, want text %q", err, test.wantErr)
			}
			if strings.Contains(err.Error(), secret) {
				t.Fatalf("error leaked secret: %q", err)
			}
		})
	}
}

func generateConfig(t *testing.T, request ConnectionRequest) []byte {
	t.Helper()
	output, err := GenerateConfig(request)
	if err != nil {
		t.Fatalf("GenerateConfig() returned an unexpected error: %v", err)
	}
	return output
}

func decodeConfig(t *testing.T, data []byte) map[string]any {
	t.Helper()
	var config map[string]any
	if err := json.Unmarshal(data, &config); err != nil {
		t.Fatalf("decode generated config: %v", err)
	}
	return config
}

func validConnectionRequest(mode domain.ConnectionMode, route domain.RouteMode) ConnectionRequest {
	endpoint := validEndpoint()
	return ConnectionRequest{
		Mode:     mode,
		Route:    route,
		Endpoint: &endpoint,
		UID:      501,
		GID:      20,
	}
}

func validEndpoint() domain.Endpoint {
	return domain.Endpoint{
		ID:             "endpoint-1",
		SubscriptionID: "subscription-1",
		Name:           "Test endpoint",
		Protocol:       domain.ProtocolVLESS,
		Host:           "proxy.example.com",
		Port:           443,
		UUID:           "11111111-1111-4111-8111-111111111111",
		TLS: domain.TLSOptions{
			Enabled:    true,
			ServerName: "proxy.example.com",
		},
		Transport: domain.TransportOptions{Type: domain.TransportTCP},
	}
}

func assertPrivateAndLANDirect(t *testing.T, rules []any) {
	t.Helper()
	var hasPrivate, hasLAN bool
	for _, rawRule := range rules {
		rule := rawRule.(map[string]any)
		if rule["outbound"] != directOutboundTag {
			continue
		}
		if rule["ip_is_private"] == true {
			hasPrivate = true
		}
		if _, exists := rule["domain_suffix"]; exists {
			hasLAN = true
		}
	}
	if !hasPrivate || !hasLAN {
		t.Fatalf("rules do not route private and LAN traffic directly: %#v", rules)
	}
}

func valuesEqual(got, want any) bool {
	gotJSON, _ := json.Marshal(got)
	wantJSON, _ := json.Marshal(want)
	return bytes.Equal(gotJSON, wantJSON)
}

func assertNoEmptyJSONValues(t *testing.T, value any, path string) {
	t.Helper()
	switch typed := value.(type) {
	case map[string]any:
		for key, child := range typed {
			assertNoEmptyJSONValues(t, child, path+"."+key)
		}
	case []any:
		if len(typed) == 0 {
			t.Errorf("%s is an empty array", path)
		}
		for index, child := range typed {
			assertNoEmptyJSONValues(t, child, path+"["+string(rune(index+'0'))+"]")
		}
	case string:
		if typed == "" {
			t.Errorf("%s is an empty string", path)
		}
	case nil:
		t.Errorf("%s is null", path)
	}
}

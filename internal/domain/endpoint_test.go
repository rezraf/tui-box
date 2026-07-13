package domain

import (
	"encoding/json"
	"strings"
	"testing"
)

const (
	validUUID             = "550e8400-e29b-41d4-a716-446655440000"
	validRealityPublicKey = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8"
)

func TestEndpointValidateAcceptsSupportedProtocols(t *testing.T) {
	t.Parallel()

	for _, protocol := range []Protocol{
		ProtocolVLESS,
		ProtocolVMess,
		ProtocolTrojan,
		ProtocolShadowsocks,
		ProtocolHysteria2,
		ProtocolTUIC,
	} {
		protocol := protocol
		t.Run(string(protocol), func(t *testing.T) {
			t.Parallel()
			endpoint := validEndpointFor(protocol)

			if err := endpoint.Validate(); err != nil {
				t.Fatalf("Validate() returned an unexpected error: %v", err)
			}
		})
	}
}

func TestEndpointValidateAcceptsProtocolSpecificOptions(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		protocol  Protocol
		configure func(*Endpoint)
	}{
		{name: "vless", protocol: ProtocolVLESS, configure: func(endpoint *Endpoint) {
			endpoint.TLS.Enabled = true
			endpoint.Transport = TransportOptions{Type: TransportTCP}
			endpoint.VLESSOptions = &VLESSOptions{
				Flow:           VLESSFlowXTLSRPRXVision,
				PacketEncoding: PacketEncodingXUDP,
			}
		}},
		{name: "vmess", protocol: ProtocolVMess, configure: func(endpoint *Endpoint) {
			endpoint.VMessOptions = &VMessOptions{
				Security:       VMessSecurityAES128GCM,
				AlterID:        MaxVMessAlterID,
				PacketEncoding: PacketEncodingPacketAddr,
			}
		}},
		{name: "hysteria2", protocol: ProtocolHysteria2, configure: func(endpoint *Endpoint) {
			endpoint.Hysteria2Options = &Hysteria2Options{
				ObfsType:     Hysteria2ObfsSalamander,
				ObfsPassword: "obfs-secret",
				UpMbps:       MaxHysteria2Mbps,
				DownMbps:     MaxHysteria2Mbps,
			}
		}},
		{name: "tuic", protocol: ProtocolTUIC, configure: func(endpoint *Endpoint) {
			endpoint.TUICOptions = &TUICOptions{
				CongestionControl: TUICCongestionBBR,
				UDPRelayMode:      TUICUDPRelayQUIC,
				ZeroRTT:           true,
			}
		}},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			endpoint := validEndpointFor(test.protocol)
			test.configure(&endpoint)

			if err := endpoint.Validate(); err != nil {
				t.Fatalf("Validate() returned an unexpected error: %v", err)
			}
		})
	}
}

func TestEndpointValidateRejectsVLESSVisionWithoutTLS(t *testing.T) {
	t.Parallel()

	endpoint := validEndpointFor(ProtocolVLESS)
	endpoint.VLESSOptions = &VLESSOptions{Flow: VLESSFlowXTLSRPRXVision}

	err := endpoint.Validate()
	if err == nil {
		t.Fatal("Validate() returned nil, want an error")
	}
	if want := "xtls-rprx-vision flow requires TLS"; !strings.Contains(err.Error(), want) {
		t.Fatalf("Validate() error = %q, want it to contain %q", err, want)
	}
}

func TestEndpointValidateRejectsVLESSVisionWithNonTCPTransport(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		transport TransportOptions
	}{
		{name: "websocket", transport: TransportOptions{Type: TransportWebSocket, Path: "/proxy"}},
		{name: "grpc", transport: TransportOptions{Type: TransportGRPC, ServiceName: "proxy.Service"}},
		{name: "http upgrade", transport: TransportOptions{Type: TransportHTTPUpgrade, Path: "/upgrade"}},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			endpoint := validEndpointFor(ProtocolVLESS)
			endpoint.TLS.Enabled = true
			endpoint.Transport = test.transport
			endpoint.VLESSOptions = &VLESSOptions{Flow: VLESSFlowXTLSRPRXVision}

			err := endpoint.Validate()
			if err == nil {
				t.Fatal("Validate() returned nil, want an error")
			}
			if want := "xtls-rprx-vision flow requires TCP transport"; !strings.Contains(err.Error(), want) {
				t.Fatalf("Validate() error = %q, want it to contain %q", err, want)
			}
		})
	}
}

func TestEndpointValidateAcceptsSupportedTransports(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		transport TransportOptions
	}{
		{name: "tcp", transport: TransportOptions{Type: TransportTCP}},
		{name: "websocket", transport: TransportOptions{Type: TransportWebSocket, Path: "/proxy", Host: "cdn.example.com"}},
		{name: "grpc", transport: TransportOptions{Type: TransportGRPC, ServiceName: "proxy.Service"}},
		{name: "http upgrade", transport: TransportOptions{Type: TransportHTTPUpgrade, Path: "/upgrade", Host: "cdn.example.com"}},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			endpoint := validEndpoint()
			endpoint.Transport = test.transport

			if err := endpoint.Validate(); err != nil {
				t.Fatalf("Validate() returned an unexpected error: %v", err)
			}
		})
	}
}

func TestEndpointValidateAcceptsTLSOptions(t *testing.T) {
	t.Parallel()

	endpoint := validEndpoint()
	endpoint.TLS = TLSOptions{
		Enabled:            true,
		ServerName:         "edge.example.com",
		InsecureSkipVerify: true,
		ALPN:               []string{"h2", "http/1.1"},
		Reality: &RealityClientOptions{
			PublicKey: validRealityPublicKey,
			ShortID:   "0123456789abcdef",
		},
		UTLSFingerprint: UTLSFingerprintChrome,
	}

	if err := endpoint.Validate(); err != nil {
		t.Fatalf("Validate() returned an unexpected error: %v", err)
	}
}

func TestEndpointTLSRealityJSONRoundTrip(t *testing.T) {
	t.Parallel()

	original := validEndpoint()
	original.TLS = TLSOptions{
		Enabled: true,
		Reality: &RealityClientOptions{
			PublicKey: validRealityPublicKey,
			ShortID:   "abcd",
		},
		UTLSFingerprint: UTLSFingerprintFirefox,
	}

	encoded, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("json.Marshal() returned an unexpected error: %v", err)
	}
	var roundTripped Endpoint
	if err := json.Unmarshal(encoded, &roundTripped); err != nil {
		t.Fatalf("json.Unmarshal() returned an unexpected error: %v", err)
	}
	if roundTripped.TLS.Reality == nil {
		t.Fatal("TLS.Reality = nil, want Reality client options")
	}
	if *roundTripped.TLS.Reality != *original.TLS.Reality {
		t.Fatalf("TLS.Reality = %#v, want %#v", roundTripped.TLS.Reality, original.TLS.Reality)
	}
	if roundTripped.TLS.UTLSFingerprint != original.TLS.UTLSFingerprint {
		t.Fatalf("TLS.UTLSFingerprint = %q, want %q", roundTripped.TLS.UTLSFingerprint, original.TLS.UTLSFingerprint)
	}
	if err := roundTripped.Validate(); err != nil {
		t.Fatalf("round-tripped endpoint did not validate: %v", err)
	}
}

func TestEndpointValidateRejectsInvalidRealityAndUTLSOptions(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		mutate func(*Endpoint)
	}{
		{name: "Reality without TLS", mutate: func(endpoint *Endpoint) {
			endpoint.TLS.Reality = &RealityClientOptions{PublicKey: validRealityPublicKey}
		}},
		{name: "uTLS without TLS", mutate: func(endpoint *Endpoint) {
			endpoint.TLS.UTLSFingerprint = UTLSFingerprintChrome
		}},
		{name: "Reality without public key", mutate: func(endpoint *Endpoint) {
			endpoint.TLS = TLSOptions{Enabled: true, Reality: &RealityClientOptions{ShortID: "abcd"}}
		}},
		{name: "malformed Reality public key", mutate: func(endpoint *Endpoint) {
			endpoint.TLS = TLSOptions{Enabled: true, Reality: &RealityClientOptions{PublicKey: "not-a-key"}}
		}},
		{name: "wrong-size Reality public key", mutate: func(endpoint *Endpoint) {
			endpoint.TLS = TLSOptions{Enabled: true, Reality: &RealityClientOptions{PublicKey: "YQ"}}
		}},
		{name: "non-hex Reality short ID", mutate: func(endpoint *Endpoint) {
			endpoint.TLS = TLSOptions{Enabled: true, Reality: &RealityClientOptions{PublicKey: validRealityPublicKey, ShortID: "not-hex"}}
		}},
		{name: "odd-length Reality short ID", mutate: func(endpoint *Endpoint) {
			endpoint.TLS = TLSOptions{Enabled: true, Reality: &RealityClientOptions{PublicKey: validRealityPublicKey, ShortID: "abc"}}
		}},
		{name: "oversized Reality public key", mutate: func(endpoint *Endpoint) {
			endpoint.TLS = TLSOptions{Enabled: true, Reality: &RealityClientOptions{PublicKey: strings.Repeat("a", MaxRealityPublicKeyLength+1)}}
		}},
		{name: "oversized Reality short ID", mutate: func(endpoint *Endpoint) {
			endpoint.TLS = TLSOptions{Enabled: true, Reality: &RealityClientOptions{PublicKey: validRealityPublicKey, ShortID: strings.Repeat("a", MaxRealityShortIDLength+1)}}
		}},
		{name: "unsupported uTLS fingerprint", mutate: func(endpoint *Endpoint) {
			endpoint.TLS = TLSOptions{Enabled: true, UTLSFingerprint: UTLSFingerprint("netscape")}
		}},
		{name: "oversized uTLS fingerprint", mutate: func(endpoint *Endpoint) {
			endpoint.TLS = TLSOptions{Enabled: true, UTLSFingerprint: UTLSFingerprint(strings.Repeat("a", MaxUTLSFingerprintLength+1))}
		}},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			endpoint := validEndpoint()
			test.mutate(&endpoint)

			if err := endpoint.Validate(); err == nil {
				t.Fatal("Validate() returned nil, want an error")
			}
		})
	}
}

func TestEndpointValidateRejectsInvalidEndpoints(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		mutate func(*Endpoint)
	}{
		{name: "unknown protocol", mutate: func(endpoint *Endpoint) { endpoint.Protocol = Protocol("wireguard") }},
		{name: "empty host", mutate: func(endpoint *Endpoint) { endpoint.Host = "" }},
		{name: "malformed host", mutate: func(endpoint *Endpoint) { endpoint.Host = "bad host" }},
		{name: "zero port", mutate: func(endpoint *Endpoint) { endpoint.Port = 0 }},
		{name: "port above maximum", mutate: func(endpoint *Endpoint) { endpoint.Port = 65536 }},
		{name: "vless missing UUID", mutate: func(endpoint *Endpoint) { endpoint.UUID = "" }},
		{name: "vless malformed UUID", mutate: func(endpoint *Endpoint) { endpoint.UUID = "not-a-uuid" }},
		{name: "unsupported transport", mutate: func(endpoint *Endpoint) {
			endpoint.Transport.Type = TransportType("quic")
		}},
		{name: "TLS options while disabled", mutate: func(endpoint *Endpoint) {
			endpoint.TLS.ServerName = "edge.example.com"
		}},
		{name: "malformed TLS server name", mutate: func(endpoint *Endpoint) {
			endpoint.TLS.Enabled = true
			endpoint.TLS.ServerName = "bad server"
		}},
		{name: "empty TLS ALPN", mutate: func(endpoint *Endpoint) {
			endpoint.TLS.Enabled = true
			endpoint.TLS.ALPN = []string{""}
		}},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			endpoint := validEndpoint()
			test.mutate(&endpoint)

			if err := endpoint.Validate(); err == nil {
				t.Fatal("Validate() returned nil, want an error")
			}
		})
	}
}

func TestEndpointValidateRejectsInvalidProtocolCredentials(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		protocol Protocol
		mutate   func(*Endpoint)
	}{
		{name: "vless missing UUID", protocol: ProtocolVLESS, mutate: func(endpoint *Endpoint) { endpoint.UUID = "" }},
		{name: "vmess missing UUID", protocol: ProtocolVMess, mutate: func(endpoint *Endpoint) { endpoint.UUID = "" }},
		{name: "trojan missing password", protocol: ProtocolTrojan, mutate: func(endpoint *Endpoint) { endpoint.Password = "" }},
		{name: "shadowsocks missing method", protocol: ProtocolShadowsocks, mutate: func(endpoint *Endpoint) { endpoint.Method = "" }},
		{name: "shadowsocks missing password", protocol: ProtocolShadowsocks, mutate: func(endpoint *Endpoint) { endpoint.Password = "" }},
		{name: "hysteria2 missing password", protocol: ProtocolHysteria2, mutate: func(endpoint *Endpoint) { endpoint.Password = "" }},
		{name: "tuic missing UUID", protocol: ProtocolTUIC, mutate: func(endpoint *Endpoint) { endpoint.UUID = "" }},
		{name: "tuic missing password", protocol: ProtocolTUIC, mutate: func(endpoint *Endpoint) { endpoint.Password = "" }},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			endpoint := validEndpointFor(test.protocol)
			test.mutate(&endpoint)

			if err := endpoint.Validate(); err == nil {
				t.Fatal("Validate() returned nil, want an error")
			}
		})
	}
}

func TestEndpointValidateRejectsIncompatibleExtraCredentials(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		protocol Protocol
		mutate   func(*Endpoint)
	}{
		{name: "vless password", protocol: ProtocolVLESS, mutate: func(endpoint *Endpoint) { endpoint.Password = "extra" }},
		{name: "vless method", protocol: ProtocolVLESS, mutate: func(endpoint *Endpoint) { endpoint.Method = "extra" }},
		{name: "vmess password", protocol: ProtocolVMess, mutate: func(endpoint *Endpoint) { endpoint.Password = "extra" }},
		{name: "vmess method", protocol: ProtocolVMess, mutate: func(endpoint *Endpoint) { endpoint.Method = "extra" }},
		{name: "trojan UUID", protocol: ProtocolTrojan, mutate: func(endpoint *Endpoint) { endpoint.UUID = validUUID }},
		{name: "trojan method", protocol: ProtocolTrojan, mutate: func(endpoint *Endpoint) { endpoint.Method = "extra" }},
		{name: "shadowsocks UUID", protocol: ProtocolShadowsocks, mutate: func(endpoint *Endpoint) { endpoint.UUID = validUUID }},
		{name: "hysteria2 UUID", protocol: ProtocolHysteria2, mutate: func(endpoint *Endpoint) { endpoint.UUID = validUUID }},
		{name: "hysteria2 method", protocol: ProtocolHysteria2, mutate: func(endpoint *Endpoint) { endpoint.Method = "extra" }},
		{name: "tuic method", protocol: ProtocolTUIC, mutate: func(endpoint *Endpoint) { endpoint.Method = "extra" }},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			endpoint := validEndpointFor(test.protocol)
			test.mutate(&endpoint)

			if err := endpoint.Validate(); err == nil {
				t.Fatal("Validate() returned nil, want an error")
			}
		})
	}
}

func TestEndpointValidateRejectsMismatchedProtocolOptions(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		protocol Protocol
		mutate   func(*Endpoint)
	}{
		{name: "vless with vmess options", protocol: ProtocolVLESS, mutate: func(endpoint *Endpoint) {
			endpoint.VMessOptions = &VMessOptions{}
		}},
		{name: "vmess with vless options", protocol: ProtocolVMess, mutate: func(endpoint *Endpoint) {
			endpoint.VLESSOptions = &VLESSOptions{}
		}},
		{name: "trojan with vless options", protocol: ProtocolTrojan, mutate: func(endpoint *Endpoint) {
			endpoint.VLESSOptions = &VLESSOptions{}
		}},
		{name: "shadowsocks with hysteria2 options", protocol: ProtocolShadowsocks, mutate: func(endpoint *Endpoint) {
			endpoint.Hysteria2Options = &Hysteria2Options{}
		}},
		{name: "hysteria2 with tuic options", protocol: ProtocolHysteria2, mutate: func(endpoint *Endpoint) {
			endpoint.TUICOptions = &TUICOptions{}
		}},
		{name: "tuic with hysteria2 options", protocol: ProtocolTUIC, mutate: func(endpoint *Endpoint) {
			endpoint.Hysteria2Options = &Hysteria2Options{}
		}},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			endpoint := validEndpointFor(test.protocol)
			test.mutate(&endpoint)

			if err := endpoint.Validate(); err == nil {
				t.Fatal("Validate() returned nil, want an error")
			}
		})
	}
}

func TestEndpointValidateEnforcesProtocolTLSAndTransportCombinations(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		protocol Protocol
		mutate   func(*Endpoint)
	}{
		{name: "vless requires stream transport", protocol: ProtocolVLESS, mutate: func(endpoint *Endpoint) {
			endpoint.Transport = TransportOptions{}
		}},
		{name: "vmess requires stream transport", protocol: ProtocolVMess, mutate: func(endpoint *Endpoint) {
			endpoint.Transport = TransportOptions{}
		}},
		{name: "trojan requires TLS", protocol: ProtocolTrojan, mutate: func(endpoint *Endpoint) {
			endpoint.TLS = TLSOptions{}
		}},
		{name: "trojan requires stream transport", protocol: ProtocolTrojan, mutate: func(endpoint *Endpoint) {
			endpoint.Transport = TransportOptions{}
		}},
		{name: "shadowsocks rejects TLS", protocol: ProtocolShadowsocks, mutate: func(endpoint *Endpoint) {
			endpoint.TLS.Enabled = true
		}},
		{name: "shadowsocks rejects stream transport", protocol: ProtocolShadowsocks, mutate: func(endpoint *Endpoint) {
			endpoint.Transport = TransportOptions{Type: TransportTCP}
		}},
		{name: "hysteria2 requires TLS", protocol: ProtocolHysteria2, mutate: func(endpoint *Endpoint) {
			endpoint.TLS = TLSOptions{}
		}},
		{name: "hysteria2 rejects stream transport", protocol: ProtocolHysteria2, mutate: func(endpoint *Endpoint) {
			endpoint.Transport = TransportOptions{Type: TransportTCP}
		}},
		{name: "tuic requires TLS", protocol: ProtocolTUIC, mutate: func(endpoint *Endpoint) {
			endpoint.TLS = TLSOptions{}
		}},
		{name: "tuic rejects stream transport", protocol: ProtocolTUIC, mutate: func(endpoint *Endpoint) {
			endpoint.Transport = TransportOptions{Type: TransportTCP}
		}},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			endpoint := validEndpointFor(test.protocol)
			test.mutate(&endpoint)

			if err := endpoint.Validate(); err == nil {
				t.Fatal("Validate() returned nil, want an error")
			}
		})
	}
}

func TestEndpointValidateRejectsInvalidTransportFieldCombinations(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		transport TransportOptions
	}{
		{name: "tcp path", transport: TransportOptions{Type: TransportTCP, Path: "/proxy"}},
		{name: "tcp host", transport: TransportOptions{Type: TransportTCP, Host: "cdn.example.com"}},
		{name: "tcp service name", transport: TransportOptions{Type: TransportTCP, ServiceName: "proxy.Service"}},
		{name: "websocket service name", transport: TransportOptions{Type: TransportWebSocket, ServiceName: "proxy.Service"}},
		{name: "http upgrade service name", transport: TransportOptions{Type: TransportHTTPUpgrade, ServiceName: "proxy.Service"}},
		{name: "grpc path", transport: TransportOptions{Type: TransportGRPC, Path: "/proxy"}},
		{name: "grpc host", transport: TransportOptions{Type: TransportGRPC, Host: "cdn.example.com"}},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			endpoint := validEndpoint()
			endpoint.Transport = test.transport

			if err := endpoint.Validate(); err == nil {
				t.Fatal("Validate() returned nil, want an error")
			}
		})
	}
}

func TestEndpointValidateRejectsInvalidProtocolOptions(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		protocol Protocol
		mutate   func(*Endpoint)
	}{
		{name: "unsupported vless flow", protocol: ProtocolVLESS, mutate: func(endpoint *Endpoint) {
			endpoint.VLESSOptions = &VLESSOptions{Flow: VLESSFlow("unsupported")}
		}},
		{name: "unsupported vless packet encoding", protocol: ProtocolVLESS, mutate: func(endpoint *Endpoint) {
			endpoint.VLESSOptions = &VLESSOptions{PacketEncoding: PacketEncoding("unsupported")}
		}},
		{name: "unsupported vmess security", protocol: ProtocolVMess, mutate: func(endpoint *Endpoint) {
			endpoint.VMessOptions = &VMessOptions{Security: VMessSecurity("unsupported")}
		}},
		{name: "negative vmess alter ID", protocol: ProtocolVMess, mutate: func(endpoint *Endpoint) {
			endpoint.VMessOptions = &VMessOptions{AlterID: -1}
		}},
		{name: "vmess alter ID above maximum", protocol: ProtocolVMess, mutate: func(endpoint *Endpoint) {
			endpoint.VMessOptions = &VMessOptions{AlterID: MaxVMessAlterID + 1}
		}},
		{name: "unsupported vmess packet encoding", protocol: ProtocolVMess, mutate: func(endpoint *Endpoint) {
			endpoint.VMessOptions = &VMessOptions{PacketEncoding: PacketEncoding("unsupported")}
		}},
		{name: "unsupported hysteria2 obfs type", protocol: ProtocolHysteria2, mutate: func(endpoint *Endpoint) {
			endpoint.Hysteria2Options = &Hysteria2Options{ObfsType: Hysteria2ObfsType("unsupported")}
		}},
		{name: "hysteria2 obfs password without type", protocol: ProtocolHysteria2, mutate: func(endpoint *Endpoint) {
			endpoint.Hysteria2Options = &Hysteria2Options{ObfsPassword: "secret"}
		}},
		{name: "hysteria2 obfs type without password", protocol: ProtocolHysteria2, mutate: func(endpoint *Endpoint) {
			endpoint.Hysteria2Options = &Hysteria2Options{ObfsType: Hysteria2ObfsSalamander}
		}},
		{name: "negative hysteria2 upload", protocol: ProtocolHysteria2, mutate: func(endpoint *Endpoint) {
			endpoint.Hysteria2Options = &Hysteria2Options{UpMbps: -1}
		}},
		{name: "hysteria2 upload above maximum", protocol: ProtocolHysteria2, mutate: func(endpoint *Endpoint) {
			endpoint.Hysteria2Options = &Hysteria2Options{UpMbps: MaxHysteria2Mbps + 1}
		}},
		{name: "negative hysteria2 download", protocol: ProtocolHysteria2, mutate: func(endpoint *Endpoint) {
			endpoint.Hysteria2Options = &Hysteria2Options{DownMbps: -1}
		}},
		{name: "hysteria2 download above maximum", protocol: ProtocolHysteria2, mutate: func(endpoint *Endpoint) {
			endpoint.Hysteria2Options = &Hysteria2Options{DownMbps: MaxHysteria2Mbps + 1}
		}},
		{name: "unsupported tuic congestion control", protocol: ProtocolTUIC, mutate: func(endpoint *Endpoint) {
			endpoint.TUICOptions = &TUICOptions{CongestionControl: TUICCongestionControl("unsupported")}
		}},
		{name: "unsupported tuic UDP relay mode", protocol: ProtocolTUIC, mutate: func(endpoint *Endpoint) {
			endpoint.TUICOptions = &TUICOptions{UDPRelayMode: TUICUDPRelayMode("unsupported")}
		}},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			endpoint := validEndpointFor(test.protocol)
			test.mutate(&endpoint)

			if err := endpoint.Validate(); err == nil {
				t.Fatal("Validate() returned nil, want an error")
			}
		})
	}
}

func TestEndpointValidateRejectsInvalidUTF8(t *testing.T) {
	t.Parallel()

	invalidUTF8 := string([]byte{0xff})
	tests := []struct {
		name     string
		protocol Protocol
		mutate   func(*Endpoint)
	}{
		{name: "ID", protocol: ProtocolVLESS, mutate: func(endpoint *Endpoint) { endpoint.ID = invalidUTF8 }},
		{name: "subscription ID", protocol: ProtocolVLESS, mutate: func(endpoint *Endpoint) { endpoint.SubscriptionID = invalidUTF8 }},
		{name: "name", protocol: ProtocolVLESS, mutate: func(endpoint *Endpoint) { endpoint.Name = invalidUTF8 }},
		{name: "host", protocol: ProtocolVLESS, mutate: func(endpoint *Endpoint) { endpoint.Host = invalidUTF8 }},
		{name: "UUID", protocol: ProtocolVLESS, mutate: func(endpoint *Endpoint) { endpoint.UUID = invalidUTF8 }},
		{name: "password", protocol: ProtocolTrojan, mutate: func(endpoint *Endpoint) { endpoint.Password = invalidUTF8 }},
		{name: "method", protocol: ProtocolShadowsocks, mutate: func(endpoint *Endpoint) { endpoint.Method = invalidUTF8 }},
		{name: "TLS server name", protocol: ProtocolVLESS, mutate: func(endpoint *Endpoint) {
			endpoint.TLS = TLSOptions{Enabled: true, ServerName: invalidUTF8}
		}},
		{name: "TLS ALPN", protocol: ProtocolVLESS, mutate: func(endpoint *Endpoint) {
			endpoint.TLS = TLSOptions{Enabled: true, ALPN: []string{invalidUTF8}}
		}},
		{name: "transport path", protocol: ProtocolVLESS, mutate: func(endpoint *Endpoint) {
			endpoint.Transport = TransportOptions{Type: TransportWebSocket, Path: invalidUTF8}
		}},
		{name: "transport host", protocol: ProtocolVLESS, mutate: func(endpoint *Endpoint) {
			endpoint.Transport = TransportOptions{Type: TransportWebSocket, Host: invalidUTF8}
		}},
		{name: "transport service name", protocol: ProtocolVLESS, mutate: func(endpoint *Endpoint) {
			endpoint.Transport = TransportOptions{Type: TransportGRPC, ServiceName: invalidUTF8}
		}},
		{name: "VLESS flow", protocol: ProtocolVLESS, mutate: func(endpoint *Endpoint) {
			endpoint.VLESSOptions = &VLESSOptions{Flow: VLESSFlow(invalidUTF8)}
		}},
		{name: "VLESS packet encoding", protocol: ProtocolVLESS, mutate: func(endpoint *Endpoint) {
			endpoint.VLESSOptions = &VLESSOptions{PacketEncoding: PacketEncoding(invalidUTF8)}
		}},
		{name: "VMess security", protocol: ProtocolVMess, mutate: func(endpoint *Endpoint) {
			endpoint.VMessOptions = &VMessOptions{Security: VMessSecurity(invalidUTF8)}
		}},
		{name: "VMess packet encoding", protocol: ProtocolVMess, mutate: func(endpoint *Endpoint) {
			endpoint.VMessOptions = &VMessOptions{PacketEncoding: PacketEncoding(invalidUTF8)}
		}},
		{name: "Hysteria2 obfuscation type", protocol: ProtocolHysteria2, mutate: func(endpoint *Endpoint) {
			endpoint.Hysteria2Options = &Hysteria2Options{ObfsType: Hysteria2ObfsType(invalidUTF8)}
		}},
		{name: "Hysteria2 obfuscation password", protocol: ProtocolHysteria2, mutate: func(endpoint *Endpoint) {
			endpoint.Hysteria2Options = &Hysteria2Options{
				ObfsType:     Hysteria2ObfsSalamander,
				ObfsPassword: invalidUTF8,
			}
		}},
		{name: "TUIC congestion control", protocol: ProtocolTUIC, mutate: func(endpoint *Endpoint) {
			endpoint.TUICOptions = &TUICOptions{CongestionControl: TUICCongestionControl(invalidUTF8)}
		}},
		{name: "TUIC UDP relay mode", protocol: ProtocolTUIC, mutate: func(endpoint *Endpoint) {
			endpoint.TUICOptions = &TUICOptions{UDPRelayMode: TUICUDPRelayMode(invalidUTF8)}
		}},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			endpoint := validEndpointFor(test.protocol)
			test.mutate(&endpoint)

			err := endpoint.Validate()
			if err == nil {
				t.Fatal("Validate() returned nil, want an error")
			}
			if want := "valid UTF-8"; !strings.Contains(err.Error(), want) {
				t.Fatalf("Validate() error = %q, want it to contain %q", err, want)
			}
		})
	}
}

func TestEndpointValidateRejectsStringsThatCannotRoundTripThroughJSON(t *testing.T) {
	t.Parallel()

	endpoint := validEndpoint()
	endpoint.Name = "invalid-" + string([]byte{0xff})

	if err := endpoint.Validate(); err == nil {
		t.Fatal("Validate() returned nil, want an error")
	}

	encoded, err := json.Marshal(endpoint)
	if err != nil {
		t.Fatalf("json.Marshal() returned an unexpected error: %v", err)
	}
	var roundTripped Endpoint
	if err := json.Unmarshal(encoded, &roundTripped); err != nil {
		t.Fatalf("json.Unmarshal() returned an unexpected error: %v", err)
	}
	if roundTripped.Name == endpoint.Name {
		t.Fatal("invalid UTF-8 unexpectedly survived a JSON round trip")
	}
}

func TestEndpointValidateRejectsWhitespaceOnlyIdentityFields(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		mutate func(*Endpoint)
	}{
		{name: "ID", mutate: func(endpoint *Endpoint) { endpoint.ID = "   " }},
		{name: "subscription ID", mutate: func(endpoint *Endpoint) { endpoint.SubscriptionID = "   " }},
		{name: "name", mutate: func(endpoint *Endpoint) { endpoint.Name = "   " }},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			endpoint := validEndpoint()
			test.mutate(&endpoint)

			if err := endpoint.Validate(); err == nil {
				t.Fatal("Validate() returned nil, want an error")
			}
		})
	}
}

func TestEndpointValidatePreservesCredentialWhitespace(t *testing.T) {
	t.Parallel()

	endpoint := validEndpointFor(ProtocolTrojan)
	endpoint.Password = "   "

	if err := endpoint.Validate(); err != nil {
		t.Fatalf("Validate() returned an unexpected error: %v", err)
	}
	if endpoint.Password != "   " {
		t.Fatalf("Password = %q, want credential whitespace unchanged", endpoint.Password)
	}
}

func TestEndpointValidateRejectsControlCharacters(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		mutate func(*Endpoint)
	}{
		{name: "name", mutate: func(endpoint *Endpoint) { endpoint.Name = "unsafe\nname" }},
		{name: "credential", mutate: func(endpoint *Endpoint) { endpoint.UUID = validUUID + "\x00" }},
		{name: "TLS ALPN", mutate: func(endpoint *Endpoint) {
			endpoint.TLS.Enabled = true
			endpoint.TLS.ALPN = []string{"h2\r"}
		}},
		{name: "transport path", mutate: func(endpoint *Endpoint) {
			endpoint.Transport = TransportOptions{Type: TransportWebSocket, Path: "/proxy\tunsafe"}
		}},
		{name: "protocol option", mutate: func(endpoint *Endpoint) {
			endpoint.VLESSOptions = &VLESSOptions{Flow: VLESSFlow("unsafe\n")}
		}},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			endpoint := validEndpoint()
			test.mutate(&endpoint)

			if err := endpoint.Validate(); err == nil {
				t.Fatal("Validate() returned nil, want an error")
			}
		})
	}
}

func TestEndpointValidateRejectsTerminalUnsafeUnicodeAndPreservesRTLText(t *testing.T) {
	t.Parallel()

	for _, character := range []rune{
		rune(0x200e), rune(0x200f), rune(0x202a), rune(0x202b), rune(0x202c), rune(0x202d), rune(0x202e),
		rune(0x2066), rune(0x2067), rune(0x2068), rune(0x2069), rune(0x2028), rune(0x2029), rune(0x200b), rune(0xfeff),
	} {
		endpoint := validEndpoint()
		endpoint.Name = "Safe" + string(character) + "txt"
		if err := endpoint.Validate(); err == nil {
			t.Fatalf("Validate() accepted terminal-unsafe rune U+%04X", character)
		}
	}

	endpoint := validEndpoint()
	endpoint.Name = "خادم آمن"
	if err := endpoint.Validate(); err != nil {
		t.Fatalf("Validate() rejected ordinary RTL letters: %v", err)
	}
}

func TestEndpointValidateRejectsOversizedFields(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		protocol Protocol
		mutate   func(*Endpoint)
	}{
		{name: "ID", protocol: ProtocolVLESS, mutate: func(endpoint *Endpoint) {
			endpoint.ID = strings.Repeat("a", MaxIDLength+1)
		}},
		{name: "subscription ID", protocol: ProtocolVLESS, mutate: func(endpoint *Endpoint) {
			endpoint.SubscriptionID = strings.Repeat("a", MaxIDLength+1)
		}},
		{name: "name", protocol: ProtocolVLESS, mutate: func(endpoint *Endpoint) {
			endpoint.Name = strings.Repeat("a", MaxNameLength+1)
		}},
		{name: "host", protocol: ProtocolVLESS, mutate: func(endpoint *Endpoint) {
			endpoint.Host = strings.Repeat("a", MaxHostLength+1)
		}},
		{name: "UUID", protocol: ProtocolVLESS, mutate: func(endpoint *Endpoint) {
			endpoint.UUID = strings.Repeat("a", MaxUUIDLength+1)
		}},
		{name: "password", protocol: ProtocolTrojan, mutate: func(endpoint *Endpoint) {
			endpoint.Password = strings.Repeat("a", MaxCredentialLength+1)
		}},
		{name: "method", protocol: ProtocolShadowsocks, mutate: func(endpoint *Endpoint) {
			endpoint.Method = strings.Repeat("a", MaxMethodLength+1)
		}},
		{name: "TLS server name", protocol: ProtocolVLESS, mutate: func(endpoint *Endpoint) {
			endpoint.TLS.Enabled = true
			endpoint.TLS.ServerName = strings.Repeat("a", MaxHostLength+1)
		}},
		{name: "TLS ALPN count", protocol: ProtocolVLESS, mutate: func(endpoint *Endpoint) {
			endpoint.TLS.Enabled = true
			endpoint.TLS.ALPN = make([]string, MaxALPNValues+1)
			for index := range endpoint.TLS.ALPN {
				endpoint.TLS.ALPN[index] = "h2"
			}
		}},
		{name: "TLS ALPN value", protocol: ProtocolVLESS, mutate: func(endpoint *Endpoint) {
			endpoint.TLS.Enabled = true
			endpoint.TLS.ALPN = []string{strings.Repeat("a", MaxTLSFieldLength+1)}
		}},
		{name: "transport path", protocol: ProtocolVLESS, mutate: func(endpoint *Endpoint) {
			endpoint.Transport = TransportOptions{Type: TransportWebSocket, Path: strings.Repeat("a", MaxTransportFieldLength+1)}
		}},
		{name: "transport host", protocol: ProtocolVLESS, mutate: func(endpoint *Endpoint) {
			endpoint.Transport = TransportOptions{Type: TransportWebSocket, Host: strings.Repeat("a", MaxTransportFieldLength+1)}
		}},
		{name: "transport service name", protocol: ProtocolVLESS, mutate: func(endpoint *Endpoint) {
			endpoint.Transport = TransportOptions{Type: TransportGRPC, ServiceName: strings.Repeat("a", MaxTransportFieldLength+1)}
		}},
		{name: "vless flow", protocol: ProtocolVLESS, mutate: func(endpoint *Endpoint) {
			endpoint.VLESSOptions = &VLESSOptions{Flow: VLESSFlow(strings.Repeat("a", MaxProtocolOptionLength+1))}
		}},
		{name: "vless packet encoding", protocol: ProtocolVLESS, mutate: func(endpoint *Endpoint) {
			endpoint.VLESSOptions = &VLESSOptions{PacketEncoding: PacketEncoding(strings.Repeat("a", MaxProtocolOptionLength+1))}
		}},
		{name: "vmess security", protocol: ProtocolVMess, mutate: func(endpoint *Endpoint) {
			endpoint.VMessOptions = &VMessOptions{Security: VMessSecurity(strings.Repeat("a", MaxProtocolOptionLength+1))}
		}},
		{name: "vmess packet encoding", protocol: ProtocolVMess, mutate: func(endpoint *Endpoint) {
			endpoint.VMessOptions = &VMessOptions{PacketEncoding: PacketEncoding(strings.Repeat("a", MaxProtocolOptionLength+1))}
		}},
		{name: "hysteria2 obfs type", protocol: ProtocolHysteria2, mutate: func(endpoint *Endpoint) {
			endpoint.Hysteria2Options = &Hysteria2Options{ObfsType: Hysteria2ObfsType(strings.Repeat("a", MaxProtocolOptionLength+1))}
		}},
		{name: "hysteria2 obfs password", protocol: ProtocolHysteria2, mutate: func(endpoint *Endpoint) {
			endpoint.Hysteria2Options = &Hysteria2Options{
				ObfsType:     Hysteria2ObfsSalamander,
				ObfsPassword: strings.Repeat("a", MaxCredentialLength+1),
			}
		}},
		{name: "tuic congestion control", protocol: ProtocolTUIC, mutate: func(endpoint *Endpoint) {
			endpoint.TUICOptions = &TUICOptions{CongestionControl: TUICCongestionControl(strings.Repeat("a", MaxProtocolOptionLength+1))}
		}},
		{name: "tuic UDP relay mode", protocol: ProtocolTUIC, mutate: func(endpoint *Endpoint) {
			endpoint.TUICOptions = &TUICOptions{UDPRelayMode: TUICUDPRelayMode(strings.Repeat("a", MaxProtocolOptionLength+1))}
		}},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			endpoint := validEndpointFor(test.protocol)
			test.mutate(&endpoint)

			err := endpoint.Validate()
			if err == nil {
				t.Fatal("Validate() returned nil, want an error")
			}
			want := "exceeds"
			if test.name == "TLS ALPN count" {
				want = "too many"
			}
			if !strings.Contains(err.Error(), want) {
				t.Fatalf("Validate() error = %q, want it to contain %q", err, want)
			}
		})
	}
}

func validEndpoint() Endpoint {
	return validEndpointFor(ProtocolVLESS)
}

func validEndpointFor(protocol Protocol) Endpoint {
	endpoint := Endpoint{
		ID:             "endpoint-1",
		SubscriptionID: "subscription-1",
		Name:           "Example endpoint",
		Protocol:       protocol,
		Host:           "server.example.com",
		Port:           443,
	}

	switch protocol {
	case ProtocolVLESS, ProtocolVMess:
		endpoint.UUID = validUUID
		endpoint.Transport = TransportOptions{Type: TransportTCP}
	case ProtocolTrojan:
		endpoint.Password = "secret"
		endpoint.TLS.Enabled = true
		endpoint.Transport = TransportOptions{Type: TransportTCP}
	case ProtocolShadowsocks:
		endpoint.Method = "aes-256-gcm"
		endpoint.Password = "secret"
	case ProtocolHysteria2:
		endpoint.Password = "secret"
		endpoint.TLS.Enabled = true
	case ProtocolTUIC:
		endpoint.UUID = validUUID
		endpoint.Password = "secret"
		endpoint.TLS.Enabled = true
	}

	return endpoint
}

package domain

import (
	"strings"
	"testing"
)

const validUUID = "550e8400-e29b-41d4-a716-446655440000"

func TestEndpointValidateAcceptsSupportedProtocols(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		protocol  Protocol
		configure func(*Endpoint)
	}{
		{name: "vless", protocol: ProtocolVLESS, configure: func(endpoint *Endpoint) { endpoint.UUID = validUUID }},
		{name: "vmess", protocol: ProtocolVMess, configure: func(endpoint *Endpoint) { endpoint.UUID = validUUID }},
		{name: "trojan", protocol: ProtocolTrojan, configure: func(endpoint *Endpoint) { endpoint.Password = "secret" }},
		{name: "shadowsocks", protocol: ProtocolShadowsocks, configure: func(endpoint *Endpoint) {
			endpoint.Method = "aes-256-gcm"
			endpoint.Password = "secret"
		}},
		{name: "hysteria2", protocol: ProtocolHysteria2, configure: func(endpoint *Endpoint) { endpoint.Password = "secret" }},
		{name: "tuic", protocol: ProtocolTUIC, configure: func(endpoint *Endpoint) {
			endpoint.UUID = validUUID
			endpoint.Password = "secret"
		}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			endpoint := validEndpoint()
			endpoint.Protocol = test.protocol
			test.configure(&endpoint)

			if err := endpoint.Validate(); err != nil {
				t.Fatalf("Validate() returned an unexpected error: %v", err)
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
	}

	if err := endpoint.Validate(); err != nil {
		t.Fatalf("Validate() returned an unexpected error: %v", err)
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
		{name: "vmess missing UUID", mutate: func(endpoint *Endpoint) {
			endpoint.Protocol = ProtocolVMess
			endpoint.UUID = ""
		}},
		{name: "trojan missing password", mutate: func(endpoint *Endpoint) {
			endpoint.Protocol = ProtocolTrojan
			endpoint.Password = ""
		}},
		{name: "shadowsocks missing method", mutate: func(endpoint *Endpoint) {
			endpoint.Protocol = ProtocolShadowsocks
			endpoint.Method = ""
		}},
		{name: "shadowsocks missing password", mutate: func(endpoint *Endpoint) {
			endpoint.Protocol = ProtocolShadowsocks
			endpoint.Password = ""
		}},
		{name: "hysteria2 missing password", mutate: func(endpoint *Endpoint) {
			endpoint.Protocol = ProtocolHysteria2
			endpoint.Password = ""
		}},
		{name: "tuic missing UUID", mutate: func(endpoint *Endpoint) {
			endpoint.Protocol = ProtocolTUIC
			endpoint.UUID = ""
		}},
		{name: "tuic missing password", mutate: func(endpoint *Endpoint) {
			endpoint.Protocol = ProtocolTUIC
			endpoint.Password = ""
		}},
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
	}

	for _, test := range tests {
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

func TestEndpointValidateRejectsOversizedFields(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		mutate func(*Endpoint)
	}{
		{name: "name", mutate: func(endpoint *Endpoint) { endpoint.Name = strings.Repeat("a", MaxNameLength+1) }},
		{name: "host", mutate: func(endpoint *Endpoint) { endpoint.Host = strings.Repeat("a", MaxHostLength+1) }},
		{name: "credential", mutate: func(endpoint *Endpoint) {
			endpoint.Protocol = ProtocolTrojan
			endpoint.Password = strings.Repeat("a", MaxCredentialLength+1)
		}},
		{name: "transport path", mutate: func(endpoint *Endpoint) {
			endpoint.Transport = TransportOptions{Type: TransportWebSocket, Path: "/" + strings.Repeat("a", MaxTransportFieldLength)}
		}},
	}

	for _, test := range tests {
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

func validEndpoint() Endpoint {
	return Endpoint{
		ID:             "endpoint-1",
		SubscriptionID: "subscription-1",
		Name:           "Example endpoint",
		Protocol:       ProtocolVLESS,
		Host:           "server.example.com",
		Port:           443,
		UUID:           validUUID,
		Transport:      TransportOptions{Type: TransportTCP},
	}
}

package domain

import (
	"fmt"
	"net"
	"strings"
	"unicode"
)

const (
	MaxIDLength             = 128
	MaxNameLength           = 256
	MaxHostLength           = 253
	MaxCredentialLength     = 1024
	MaxMethodLength         = 128
	MaxTLSFieldLength       = 255
	MaxTransportFieldLength = 2048
	MaxALPNValues           = 16
)

type Protocol string

const (
	ProtocolVLESS       Protocol = "vless"
	ProtocolVMess       Protocol = "vmess"
	ProtocolTrojan      Protocol = "trojan"
	ProtocolShadowsocks Protocol = "shadowsocks"
	ProtocolHysteria2   Protocol = "hysteria2"
	ProtocolTUIC        Protocol = "tuic"
)

type TLSOptions struct {
	Enabled            bool     `json:"enabled"`
	ServerName         string   `json:"server_name,omitempty"`
	InsecureSkipVerify bool     `json:"insecure_skip_verify,omitempty"`
	ALPN               []string `json:"alpn,omitempty"`
}

type TransportType string

const (
	TransportTCP         TransportType = "tcp"
	TransportWebSocket   TransportType = "ws"
	TransportGRPC        TransportType = "grpc"
	TransportHTTPUpgrade TransportType = "httpupgrade"
)

type TransportOptions struct {
	Type        TransportType `json:"type"`
	Path        string        `json:"path,omitempty"`
	Host        string        `json:"host,omitempty"`
	ServiceName string        `json:"service_name,omitempty"`
}

type Endpoint struct {
	ID             string           `json:"id"`
	SubscriptionID string           `json:"subscription_id"`
	Name           string           `json:"name"`
	Protocol       Protocol         `json:"protocol"`
	Host           string           `json:"host"`
	Port           int              `json:"port"`
	UUID           string           `json:"uuid,omitempty"`
	Password       string           `json:"password,omitempty"`
	Method         string           `json:"method,omitempty"`
	TLS            TLSOptions       `json:"tls"`
	Transport      TransportOptions `json:"transport"`
}

func (endpoint Endpoint) Validate() error {
	if err := endpoint.validateStrings(); err != nil {
		return err
	}
	if !endpoint.Protocol.isSupported() {
		return fmt.Errorf("unsupported protocol")
	}
	if err := validateHost("host", endpoint.Host); err != nil {
		return err
	}
	if endpoint.Port < 1 || endpoint.Port > 65535 {
		return fmt.Errorf("port must be between 1 and 65535")
	}
	if err := endpoint.validateCredentials(); err != nil {
		return err
	}
	if err := endpoint.TLS.validate(); err != nil {
		return err
	}
	return endpoint.Transport.validate()
}

func (endpoint Endpoint) validateStrings() error {
	fields := []struct {
		name     string
		value    string
		maxBytes int
		required bool
	}{
		{name: "ID", value: endpoint.ID, maxBytes: MaxIDLength, required: true},
		{name: "subscription ID", value: endpoint.SubscriptionID, maxBytes: MaxIDLength, required: true},
		{name: "name", value: endpoint.Name, maxBytes: MaxNameLength, required: true},
		{name: "UUID", value: endpoint.UUID, maxBytes: MaxCredentialLength},
		{name: "password", value: endpoint.Password, maxBytes: MaxCredentialLength},
		{name: "method", value: endpoint.Method, maxBytes: MaxMethodLength},
	}
	for _, field := range fields {
		if err := validateString(field.name, field.value, field.maxBytes, field.required); err != nil {
			return err
		}
	}
	return nil
}

func (endpoint Endpoint) validateCredentials() error {
	switch endpoint.Protocol {
	case ProtocolVLESS, ProtocolVMess:
		return validateUUID(endpoint.UUID)
	case ProtocolTrojan, ProtocolHysteria2:
		return requireCredential("password", endpoint.Password)
	case ProtocolShadowsocks:
		if err := requireCredential("method", endpoint.Method); err != nil {
			return err
		}
		return requireCredential("password", endpoint.Password)
	case ProtocolTUIC:
		if err := validateUUID(endpoint.UUID); err != nil {
			return err
		}
		return requireCredential("password", endpoint.Password)
	default:
		return nil
	}
}

func (protocol Protocol) isSupported() bool {
	switch protocol {
	case ProtocolVLESS, ProtocolVMess, ProtocolTrojan, ProtocolShadowsocks, ProtocolHysteria2, ProtocolTUIC:
		return true
	default:
		return false
	}
}

func (options TLSOptions) validate() error {
	if !options.Enabled {
		if options.ServerName != "" || options.InsecureSkipVerify || len(options.ALPN) != 0 {
			return fmt.Errorf("TLS options require TLS to be enabled")
		}
		return nil
	}
	if options.ServerName != "" {
		if err := validateHost("TLS server name", options.ServerName); err != nil {
			return err
		}
	}
	if len(options.ALPN) > MaxALPNValues {
		return fmt.Errorf("TLS ALPN has too many values")
	}
	for _, protocol := range options.ALPN {
		if err := validateString("TLS ALPN", protocol, MaxTLSFieldLength, true); err != nil {
			return err
		}
	}
	return nil
}

func (options TransportOptions) validate() error {
	switch options.Type {
	case TransportTCP, TransportWebSocket, TransportGRPC, TransportHTTPUpgrade:
	default:
		return fmt.Errorf("unsupported transport")
	}
	fields := []struct {
		name  string
		value string
	}{
		{name: "transport path", value: options.Path},
		{name: "transport host", value: options.Host},
		{name: "transport service name", value: options.ServiceName},
	}
	for _, field := range fields {
		if err := validateString(field.name, field.value, MaxTransportFieldLength, false); err != nil {
			return err
		}
	}
	return nil
}

func validateHost(name, value string) error {
	if err := validateString(name, value, MaxHostLength, true); err != nil {
		return err
	}
	if net.ParseIP(value) != nil {
		return nil
	}
	if strings.HasSuffix(value, ".") {
		value = strings.TrimSuffix(value, ".")
	}
	labels := strings.Split(value, ".")
	for _, label := range labels {
		if !validHostLabel(label) {
			return fmt.Errorf("%s is invalid", name)
		}
	}
	return nil
}

func validHostLabel(label string) bool {
	if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
		return false
	}
	for _, character := range label {
		if (character < 'a' || character > 'z') &&
			(character < 'A' || character > 'Z') &&
			(character < '0' || character > '9') && character != '-' {
			return false
		}
	}
	return true
}

func validateUUID(value string) error {
	if len(value) != 36 || value[8] != '-' || value[13] != '-' || value[18] != '-' || value[23] != '-' {
		return fmt.Errorf("UUID is invalid")
	}
	for index, character := range value {
		if index == 8 || index == 13 || index == 18 || index == 23 {
			continue
		}
		if !isHex(character) {
			return fmt.Errorf("UUID is invalid")
		}
	}
	return nil
}

func isHex(character rune) bool {
	return character >= '0' && character <= '9' ||
		character >= 'a' && character <= 'f' ||
		character >= 'A' && character <= 'F'
}

func requireCredential(name, value string) error {
	if value == "" {
		return fmt.Errorf("%s is required", name)
	}
	return nil
}

func validateString(name, value string, maxBytes int, required bool) error {
	if required && value == "" {
		return fmt.Errorf("%s is required", name)
	}
	if len(value) > maxBytes {
		return fmt.Errorf("%s exceeds %d bytes", name, maxBytes)
	}
	for _, character := range value {
		if unicode.IsControl(character) {
			return fmt.Errorf("%s contains control characters", name)
		}
	}
	return nil
}

package domain

import (
	"encoding/base64"
	"fmt"
	"net"
	"strings"
	"unicode/utf8"

	"github.com/rezraf/tui-box/internal/terminaltext"
)

const (
	MaxIDLength               = 128
	MaxNameLength             = 256
	MaxHostLength             = 253
	MaxUUIDLength             = 36
	MaxCredentialLength       = 1024
	MaxMethodLength           = 128
	MaxTLSFieldLength         = 255
	MaxRealityPublicKeyLength = 64
	MaxRealityShortIDLength   = 16
	MaxUTLSFingerprintLength  = 32
	MaxTransportFieldLength   = 2048
	MaxALPNValues             = 16
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

type UTLSFingerprint string

const (
	UTLSFingerprintChrome     UTLSFingerprint = "chrome"
	UTLSFingerprintFirefox    UTLSFingerprint = "firefox"
	UTLSFingerprintEdge       UTLSFingerprint = "edge"
	UTLSFingerprintSafari     UTLSFingerprint = "safari"
	UTLSFingerprint360        UTLSFingerprint = "360"
	UTLSFingerprintQQ         UTLSFingerprint = "qq"
	UTLSFingerprintIOS        UTLSFingerprint = "ios"
	UTLSFingerprintAndroid    UTLSFingerprint = "android"
	UTLSFingerprintRandom     UTLSFingerprint = "random"
	UTLSFingerprintRandomized UTLSFingerprint = "randomized"
)

type RealityClientOptions struct {
	PublicKey string `json:"public_key"`
	ShortID   string `json:"short_id,omitempty"`
}

type TLSOptions struct {
	Enabled            bool                  `json:"enabled"`
	ServerName         string                `json:"server_name,omitempty"`
	InsecureSkipVerify bool                  `json:"insecure_skip_verify,omitempty"`
	ALPN               []string              `json:"alpn,omitempty"`
	Reality            *RealityClientOptions `json:"reality,omitempty"`
	UTLSFingerprint    UTLSFingerprint       `json:"utls_fingerprint,omitempty"`
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
	ID               string            `json:"id"`
	SubscriptionID   string            `json:"subscription_id"`
	Name             string            `json:"name"`
	Protocol         Protocol          `json:"protocol"`
	Host             string            `json:"host"`
	Port             int               `json:"port"`
	UUID             string            `json:"uuid,omitempty"`
	Password         string            `json:"password,omitempty"`
	Method           string            `json:"method,omitempty"`
	TLS              TLSOptions        `json:"tls"`
	Transport        TransportOptions  `json:"transport"`
	VLESSOptions     *VLESSOptions     `json:"vless_options,omitempty"`
	VMessOptions     *VMessOptions     `json:"vmess_options,omitempty"`
	Hysteria2Options *Hysteria2Options `json:"hysteria2_options,omitempty"`
	TUICOptions      *TUICOptions      `json:"tuic_options,omitempty"`
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
	if err := endpoint.TLS.validate(); err != nil {
		return err
	}
	if err := endpoint.Transport.validateFields(); err != nil {
		return err
	}
	if err := endpoint.validateProtocolOptions(); err != nil {
		return err
	}
	return endpoint.validateProtocolCombination()
}

func (endpoint Endpoint) validateStrings() error {
	fields := []struct {
		name     string
		value    string
		maxBytes int
		nonBlank bool
	}{
		{name: "ID", value: endpoint.ID, maxBytes: MaxIDLength, nonBlank: true},
		{name: "subscription ID", value: endpoint.SubscriptionID, maxBytes: MaxIDLength, nonBlank: true},
		{name: "name", value: endpoint.Name, maxBytes: MaxNameLength, nonBlank: true},
		{name: "UUID", value: endpoint.UUID, maxBytes: MaxUUIDLength},
		{name: "password", value: endpoint.Password, maxBytes: MaxCredentialLength},
		{name: "method", value: endpoint.Method, maxBytes: MaxMethodLength},
	}
	for _, field := range fields {
		if err := validateString(field.name, field.value, field.maxBytes, field.nonBlank); err != nil {
			return err
		}
		if field.nonBlank && strings.TrimSpace(field.value) == "" {
			return fmt.Errorf("%s is required", field.name)
		}
	}
	return nil
}

func (endpoint Endpoint) validateProtocolCombination() error {
	switch endpoint.Protocol {
	case ProtocolVLESS, ProtocolVMess:
		if err := validateUUID(endpoint.UUID); err != nil {
			return err
		}
		if err := rejectCredential("password", endpoint.Password); err != nil {
			return err
		}
		if err := rejectCredential("method", endpoint.Method); err != nil {
			return err
		}
		if err := endpoint.Transport.validate(); err != nil {
			return err
		}
		return endpoint.validateVLESSFlowCombination()
	case ProtocolTrojan:
		if err := rejectCredential("UUID", endpoint.UUID); err != nil {
			return err
		}
		if err := rejectCredential("method", endpoint.Method); err != nil {
			return err
		}
		if err := requireCredential("password", endpoint.Password); err != nil {
			return err
		}
		if err := requireTLS(endpoint.TLS); err != nil {
			return err
		}
		return endpoint.Transport.validate()
	case ProtocolShadowsocks:
		if err := rejectCredential("UUID", endpoint.UUID); err != nil {
			return err
		}
		if err := requireCredential("method", endpoint.Method); err != nil {
			return err
		}
		if err := requireCredential("password", endpoint.Password); err != nil {
			return err
		}
		if err := rejectTLS(endpoint.TLS); err != nil {
			return err
		}
		return rejectStreamTransport(endpoint.Transport)
	case ProtocolHysteria2:
		if err := rejectCredential("UUID", endpoint.UUID); err != nil {
			return err
		}
		if err := rejectCredential("method", endpoint.Method); err != nil {
			return err
		}
		if err := requireCredential("password", endpoint.Password); err != nil {
			return err
		}
		if err := requireTLS(endpoint.TLS); err != nil {
			return err
		}
		return rejectStreamTransport(endpoint.Transport)
	case ProtocolTUIC:
		if err := validateUUID(endpoint.UUID); err != nil {
			return err
		}
		if err := rejectCredential("method", endpoint.Method); err != nil {
			return err
		}
		if err := requireCredential("password", endpoint.Password); err != nil {
			return err
		}
		if err := requireTLS(endpoint.TLS); err != nil {
			return err
		}
		return rejectStreamTransport(endpoint.Transport)
	default:
		return nil
	}
}

func (endpoint Endpoint) validateVLESSFlowCombination() error {
	if endpoint.Protocol != ProtocolVLESS || endpoint.VLESSOptions == nil || endpoint.VLESSOptions.Flow != VLESSFlowXTLSRPRXVision {
		return nil
	}
	if !endpoint.TLS.Enabled {
		return fmt.Errorf("VLESS xtls-rprx-vision flow requires TLS")
	}
	if endpoint.Transport.Type != TransportTCP {
		return fmt.Errorf("VLESS xtls-rprx-vision flow requires TCP transport")
	}
	return nil
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
		if options.ServerName != "" || options.InsecureSkipVerify || len(options.ALPN) != 0 || options.Reality != nil || options.UTLSFingerprint != "" {
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
	if options.Reality != nil {
		if err := options.Reality.validate(); err != nil {
			return err
		}
	}
	return options.UTLSFingerprint.validate()
}

func (options RealityClientOptions) validate() error {
	if err := validateString("Reality public key", options.PublicKey, MaxRealityPublicKeyLength, true); err != nil {
		return err
	}
	decoded, err := base64.RawURLEncoding.DecodeString(options.PublicKey)
	if err != nil || len(decoded) != 32 {
		return fmt.Errorf("Reality public key is invalid")
	}
	if err := validateString("Reality short ID", options.ShortID, MaxRealityShortIDLength, false); err != nil {
		return err
	}
	if len(options.ShortID)%2 != 0 {
		return fmt.Errorf("Reality short ID is invalid")
	}
	for _, character := range options.ShortID {
		if !isHex(character) {
			return fmt.Errorf("Reality short ID is invalid")
		}
	}
	return nil
}

func (fingerprint UTLSFingerprint) validate() error {
	if err := validateString("uTLS fingerprint", string(fingerprint), MaxUTLSFingerprintLength, false); err != nil {
		return err
	}
	switch fingerprint {
	case "", UTLSFingerprintChrome, UTLSFingerprintFirefox, UTLSFingerprintEdge, UTLSFingerprintSafari,
		UTLSFingerprint360, UTLSFingerprintQQ, UTLSFingerprintIOS, UTLSFingerprintAndroid,
		UTLSFingerprintRandom, UTLSFingerprintRandomized:
		return nil
	default:
		return fmt.Errorf("unsupported uTLS fingerprint")
	}
}

func (options TransportOptions) validate() error {
	switch options.Type {
	case TransportTCP:
		if options.Path != "" || options.Host != "" || options.ServiceName != "" {
			return fmt.Errorf("TCP transport does not accept path, host, or service name")
		}
	case TransportWebSocket, TransportHTTPUpgrade:
		if options.ServiceName != "" {
			return fmt.Errorf("%s transport does not accept service name", options.Type)
		}
	case TransportGRPC:
		if options.Path != "" || options.Host != "" {
			return fmt.Errorf("gRPC transport does not accept path or host")
		}
	default:
		return fmt.Errorf("unsupported transport")
	}
	return nil
}

func (options TransportOptions) validateFields() error {
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

func (options TransportOptions) isZero() bool {
	return options.Type == "" && options.Path == "" && options.Host == "" && options.ServiceName == ""
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

func rejectCredential(name, value string) error {
	if value != "" {
		return fmt.Errorf("%s is not applicable to this protocol", name)
	}
	return nil
}

func requireTLS(options TLSOptions) error {
	if !options.Enabled {
		return fmt.Errorf("TLS is required for this protocol")
	}
	return nil
}

func rejectTLS(options TLSOptions) error {
	if options.Enabled {
		return fmt.Errorf("TLS is not supported for this protocol")
	}
	return nil
}

func rejectStreamTransport(options TransportOptions) error {
	if !options.isZero() {
		return fmt.Errorf("stream transport is not supported for this protocol")
	}
	return nil
}

func validateString(name, value string, maxBytes int, required bool) error {
	if required && value == "" {
		return fmt.Errorf("%s is required", name)
	}
	if !utf8.ValidString(value) {
		return fmt.Errorf("%s is not valid UTF-8", name)
	}
	if len(value) > maxBytes {
		return fmt.Errorf("%s exceeds %d bytes", name, maxBytes)
	}
	if !terminaltext.Valid(value) {
		return fmt.Errorf("%s contains terminal-unsafe characters", name)
	}
	return nil
}

package subscription

import (
	"encoding/json"
	"strings"

	"github.com/rezraf/tui-box/internal/domain"
)

type singBoxDocument struct {
	Outbounds []json.RawMessage `json:"outbounds"`
}

type singBoxOutbound struct {
	Type              string            `json:"type"`
	Tag               string            `json:"tag"`
	Server            string            `json:"server"`
	ServerPort        int               `json:"server_port"`
	UUID              string            `json:"uuid"`
	Password          string            `json:"password"`
	Method            string            `json:"method"`
	Security          string            `json:"security"`
	AlterID           int               `json:"alter_id"`
	PacketEncoding    string            `json:"packet_encoding"`
	Flow              string            `json:"flow"`
	TLS               *singBoxTLS       `json:"tls"`
	Transport         *singBoxTransport `json:"transport"`
	Obfs              *singBoxObfs      `json:"obfs"`
	UpMbps            int               `json:"up_mbps"`
	DownMbps          int               `json:"down_mbps"`
	CongestionControl string            `json:"congestion_control"`
	UDPRelayMode      string            `json:"udp_relay_mode"`
	ZeroRTT           bool              `json:"zero_rtt_handshake"`
}

type singBoxTLS struct {
	Enabled    bool            `json:"enabled"`
	ServerName string          `json:"server_name"`
	Insecure   bool            `json:"insecure"`
	ALPN       []string        `json:"alpn"`
	Reality    *singBoxReality `json:"reality"`
	UTLS       *singBoxUTLS    `json:"utls"`
}

type singBoxReality struct {
	Enabled   bool   `json:"enabled"`
	PublicKey string `json:"public_key"`
	ShortID   string `json:"short_id"`
}

type singBoxUTLS struct {
	Enabled     bool   `json:"enabled"`
	Fingerprint string `json:"fingerprint"`
}

type singBoxTransport struct {
	Type        string             `json:"type"`
	Path        string             `json:"path"`
	Host        string             `json:"host"`
	ServiceName string             `json:"service_name"`
	Headers     singBoxHostHeaders `json:"headers"`
}

type singBoxHostHeaders struct {
	Host string `json:"Host"`
}

type singBoxObfs struct {
	Type     string `json:"type"`
	Password string `json:"password"`
}

func parseSingBox(subscriptionID string, content []byte) (ParseResult, error) {
	if err := validateStrictJSON(content); err != nil {
		return ParseResult{}, errMalformedDocument
	}
	var document singBoxDocument
	if err := json.Unmarshal(content, &document); err != nil {
		return ParseResult{}, errMalformedDocument
	}
	if len(document.Outbounds) > MaxEntries {
		return ParseResult{}, errTooManyEntries
	}
	result := ParseResult{Format: domain.SubscriptionFormatSingBox}
	seen := make(map[string]struct{})
	for index, raw := range document.Outbounds {
		entryNumber := index + 1
		if len(raw) > MaxEntryBytes {
			result.Warnings = append(result.Warnings, oversizedWarning(subscriptionID, entryNumber))
			continue
		}
		var outbound singBoxOutbound
		if err := json.Unmarshal(raw, &outbound); err != nil {
			result.Warnings = append(result.Warnings, invalidWarning(subscriptionID, entryNumber))
			continue
		}
		endpoint, err := outbound.endpoint()
		if err != nil {
			result.Warnings = append(result.Warnings, invalidWarning(subscriptionID, entryNumber))
			continue
		}
		addEndpoint(&result, endpoint, subscriptionID, entryNumber, seen)
	}
	return result, nil
}

func (outbound singBoxOutbound) endpoint() (domain.Endpoint, error) {
	protocol, err := singBoxProtocol(outbound.Type)
	if err != nil {
		return domain.Endpoint{}, err
	}
	endpoint := domain.Endpoint{
		Name:     outbound.Tag,
		Protocol: protocol,
		Host:     outbound.Server,
		Port:     outbound.ServerPort,
	}
	if outbound.TLS != nil {
		endpoint.TLS = domain.TLSOptions{
			Enabled:            outbound.TLS.Enabled,
			ServerName:         outbound.TLS.ServerName,
			InsecureSkipVerify: outbound.TLS.Insecure,
			ALPN:               outbound.TLS.ALPN,
		}
		if outbound.TLS.Reality != nil && outbound.TLS.Reality.Enabled {
			endpoint.TLS.Reality = &domain.RealityClientOptions{
				PublicKey: outbound.TLS.Reality.PublicKey,
				ShortID:   outbound.TLS.Reality.ShortID,
			}
		}
		if outbound.TLS.UTLS != nil && outbound.TLS.UTLS.Enabled {
			endpoint.TLS.UTLSFingerprint = domain.UTLSFingerprint(outbound.TLS.UTLS.Fingerprint)
		}
	}

	switch protocol {
	case domain.ProtocolVLESS:
		endpoint.UUID = outbound.UUID
		endpoint.Transport, err = outbound.streamTransport()
		endpoint.VLESSOptions = &domain.VLESSOptions{Flow: domain.VLESSFlow(outbound.Flow), PacketEncoding: domain.PacketEncoding(outbound.PacketEncoding)}
	case domain.ProtocolVMess:
		endpoint.UUID = outbound.UUID
		endpoint.Transport, err = outbound.streamTransport()
		endpoint.VMessOptions = &domain.VMessOptions{
			Security: domain.VMessSecurity(outbound.Security), AlterID: outbound.AlterID,
			PacketEncoding: domain.PacketEncoding(outbound.PacketEncoding),
		}
	case domain.ProtocolTrojan:
		endpoint.Password = outbound.Password
		endpoint.Transport, err = outbound.streamTransport()
	case domain.ProtocolShadowsocks:
		endpoint.Method = outbound.Method
		endpoint.Password = outbound.Password
	case domain.ProtocolHysteria2:
		endpoint.Password = outbound.Password
		endpoint.Hysteria2Options = &domain.Hysteria2Options{UpMbps: outbound.UpMbps, DownMbps: outbound.DownMbps}
		if outbound.Obfs != nil {
			endpoint.Hysteria2Options.ObfsType = domain.Hysteria2ObfsType(outbound.Obfs.Type)
			endpoint.Hysteria2Options.ObfsPassword = outbound.Obfs.Password
		}
	case domain.ProtocolTUIC:
		endpoint.UUID = outbound.UUID
		endpoint.Password = outbound.Password
		endpoint.TUICOptions = &domain.TUICOptions{
			CongestionControl: domain.TUICCongestionControl(outbound.CongestionControl),
			UDPRelayMode:      domain.TUICUDPRelayMode(outbound.UDPRelayMode),
			ZeroRTT:           outbound.ZeroRTT,
		}
	}
	if err != nil {
		return domain.Endpoint{}, err
	}
	return endpoint, nil
}

func (outbound singBoxOutbound) streamTransport() (domain.TransportOptions, error) {
	if outbound.Transport == nil {
		return domain.TransportOptions{Type: domain.TransportTCP}, nil
	}
	host := outbound.Transport.Host
	if host == "" {
		host = outbound.Transport.Headers.Host
	}
	return transportFromValues(
		outbound.Transport.Type,
		outbound.Transport.Path,
		host,
		outbound.Transport.ServiceName,
	)
}

func singBoxProtocol(value string) (domain.Protocol, error) {
	switch strings.ToLower(value) {
	case "vless":
		return domain.ProtocolVLESS, nil
	case "vmess":
		return domain.ProtocolVMess, nil
	case "trojan":
		return domain.ProtocolTrojan, nil
	case "shadowsocks", "ss":
		return domain.ProtocolShadowsocks, nil
	case "hysteria2", "hy2":
		return domain.ProtocolHysteria2, nil
	case "tuic":
		return domain.ProtocolTUIC, nil
	default:
		return "", errUnsupportedEntry
	}
}

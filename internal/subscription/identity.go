package subscription

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"

	"github.com/rezraf/tui-box/internal/domain"
)

const endpointIdentityVersion = 1

type endpointIdentityV1 struct {
	Version          int                         `json:"version"`
	Protocol         domain.Protocol             `json:"protocol"`
	Host             string                      `json:"host"`
	Port             int                         `json:"port"`
	UUIDSHA256       string                      `json:"uuid_sha256,omitempty"`
	PasswordSHA256   string                      `json:"password_sha256,omitempty"`
	Method           string                      `json:"method,omitempty"`
	TLS              endpointTLSIdentityV1       `json:"tls"`
	Transport        endpointTransportIdentityV1 `json:"transport"`
	VLESSOptions     *vlessIdentityV1            `json:"vless_options,omitempty"`
	VMessOptions     *vmessIdentityV1            `json:"vmess_options,omitempty"`
	Hysteria2Options *hysteria2IdentityV1        `json:"hysteria2_options,omitempty"`
	TUICOptions      *tuicIdentityV1             `json:"tuic_options,omitempty"`
}

type endpointTLSIdentityV1 struct {
	Enabled            bool                       `json:"enabled"`
	ServerName         string                     `json:"server_name,omitempty"`
	InsecureSkipVerify bool                       `json:"insecure_skip_verify,omitempty"`
	ALPN               []string                   `json:"alpn,omitempty"`
	Reality            *endpointRealityIdentityV1 `json:"reality,omitempty"`
	UTLSFingerprint    domain.UTLSFingerprint     `json:"utls_fingerprint,omitempty"`
}

type endpointRealityIdentityV1 struct {
	PublicKeySHA256 string `json:"public_key_sha256,omitempty"`
	ShortIDSHA256   string `json:"short_id_sha256,omitempty"`
}

type endpointTransportIdentityV1 struct {
	Type        domain.TransportType `json:"type"`
	Path        string               `json:"path,omitempty"`
	Host        string               `json:"host,omitempty"`
	ServiceName string               `json:"service_name,omitempty"`
}

type vlessIdentityV1 struct {
	Flow           domain.VLESSFlow      `json:"flow,omitempty"`
	PacketEncoding domain.PacketEncoding `json:"packet_encoding,omitempty"`
}

type vmessIdentityV1 struct {
	Security       domain.VMessSecurity  `json:"security,omitempty"`
	AlterID        int                   `json:"alter_id,omitempty"`
	PacketEncoding domain.PacketEncoding `json:"packet_encoding,omitempty"`
}

type hysteria2IdentityV1 struct {
	ObfsType           domain.Hysteria2ObfsType `json:"obfs_type,omitempty"`
	ObfsPasswordSHA256 string                   `json:"obfs_password_sha256,omitempty"`
	UpMbps             int                      `json:"up_mbps,omitempty"`
	DownMbps           int                      `json:"down_mbps,omitempty"`
}

type tuicIdentityV1 struct {
	CongestionControl domain.TUICCongestionControl `json:"congestion_control,omitempty"`
	UDPRelayMode      domain.TUICUDPRelayMode      `json:"udp_relay_mode,omitempty"`
	ZeroRTT           bool                         `json:"zero_rtt,omitempty"`
}

func endpointID(endpoint domain.Endpoint) (string, error) {
	encoded, err := json.Marshal(canonicalEndpointIdentityV1(endpoint))
	if err != nil {
		return "", fmt.Errorf("marshal endpoint identity: %w", err)
	}
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:]), nil
}

func canonicalEndpointIdentityV1(endpoint domain.Endpoint) endpointIdentityV1 {
	identity := endpointIdentityV1{
		Version:        endpointIdentityVersion,
		Protocol:       endpoint.Protocol,
		Host:           endpoint.Host,
		Port:           endpoint.Port,
		UUIDSHA256:     sensitiveIdentityDigest(endpoint.UUID),
		PasswordSHA256: sensitiveIdentityDigest(endpoint.Password),
		Method:         endpoint.Method,
		TLS: endpointTLSIdentityV1{
			Enabled:            endpoint.TLS.Enabled,
			ServerName:         endpoint.TLS.ServerName,
			InsecureSkipVerify: endpoint.TLS.InsecureSkipVerify,
			ALPN:               endpoint.TLS.ALPN,
			UTLSFingerprint:    endpoint.TLS.UTLSFingerprint,
		},
		Transport: endpointTransportIdentityV1{
			Type:        endpoint.Transport.Type,
			Path:        endpoint.Transport.Path,
			Host:        endpoint.Transport.Host,
			ServiceName: endpoint.Transport.ServiceName,
		},
	}
	if endpoint.TLS.Reality != nil {
		identity.TLS.Reality = &endpointRealityIdentityV1{
			PublicKeySHA256: sensitiveIdentityDigest(endpoint.TLS.Reality.PublicKey),
			ShortIDSHA256:   sensitiveIdentityDigest(endpoint.TLS.Reality.ShortID),
		}
	}
	if endpoint.VLESSOptions != nil {
		identity.VLESSOptions = &vlessIdentityV1{
			Flow:           endpoint.VLESSOptions.Flow,
			PacketEncoding: endpoint.VLESSOptions.PacketEncoding,
		}
	}
	if endpoint.VMessOptions != nil {
		identity.VMessOptions = &vmessIdentityV1{
			Security:       endpoint.VMessOptions.Security,
			AlterID:        endpoint.VMessOptions.AlterID,
			PacketEncoding: endpoint.VMessOptions.PacketEncoding,
		}
	}
	if endpoint.Hysteria2Options != nil {
		identity.Hysteria2Options = &hysteria2IdentityV1{
			ObfsType:           endpoint.Hysteria2Options.ObfsType,
			ObfsPasswordSHA256: sensitiveIdentityDigest(endpoint.Hysteria2Options.ObfsPassword),
			UpMbps:             endpoint.Hysteria2Options.UpMbps,
			DownMbps:           endpoint.Hysteria2Options.DownMbps,
		}
	}
	if endpoint.TUICOptions != nil {
		identity.TUICOptions = &tuicIdentityV1{
			CongestionControl: endpoint.TUICOptions.CongestionControl,
			UDPRelayMode:      endpoint.TUICOptions.UDPRelayMode,
			ZeroRTT:           endpoint.TUICOptions.ZeroRTT,
		}
	}
	return identity
}

func sensitiveIdentityDigest(value string) string {
	if value == "" {
		return ""
	}
	digest := sha256.Sum256([]byte(value))
	return hex.EncodeToString(digest[:])
}

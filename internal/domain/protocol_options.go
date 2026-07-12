package domain

import "fmt"

const (
	MaxProtocolOptionLength = 128
	MaxVMessAlterID         = 65535
	MaxHysteria2Mbps        = 1_000_000
)

type PacketEncoding string

const (
	PacketEncodingXUDP       PacketEncoding = "xudp"
	PacketEncodingPacketAddr PacketEncoding = "packetaddr"
)

type VLESSFlow string

const (
	VLESSFlowXTLSRPRXVision VLESSFlow = "xtls-rprx-vision"
)

type VLESSOptions struct {
	Flow           VLESSFlow      `json:"flow,omitempty"`
	PacketEncoding PacketEncoding `json:"packet_encoding,omitempty"`
}

type VMessSecurity string

const (
	VMessSecurityAuto             VMessSecurity = "auto"
	VMessSecurityNone             VMessSecurity = "none"
	VMessSecurityZero             VMessSecurity = "zero"
	VMessSecurityAES128GCM        VMessSecurity = "aes-128-gcm"
	VMessSecurityChaCha20Poly1305 VMessSecurity = "chacha20-poly1305"
)

type VMessOptions struct {
	Security       VMessSecurity  `json:"security,omitempty"`
	AlterID        int            `json:"alter_id,omitempty"`
	PacketEncoding PacketEncoding `json:"packet_encoding,omitempty"`
}

type Hysteria2ObfsType string

const (
	Hysteria2ObfsSalamander Hysteria2ObfsType = "salamander"
)

type Hysteria2Options struct {
	ObfsType     Hysteria2ObfsType `json:"obfs_type,omitempty"`
	ObfsPassword string            `json:"obfs_password,omitempty"`
	UpMbps       int               `json:"up_mbps,omitempty"`
	DownMbps     int               `json:"down_mbps,omitempty"`
}

type TUICCongestionControl string

const (
	TUICCongestionCubic   TUICCongestionControl = "cubic"
	TUICCongestionNewReno TUICCongestionControl = "new_reno"
	TUICCongestionBBR     TUICCongestionControl = "bbr"
)

type TUICUDPRelayMode string

const (
	TUICUDPRelayNative TUICUDPRelayMode = "native"
	TUICUDPRelayQUIC   TUICUDPRelayMode = "quic"
)

type TUICOptions struct {
	CongestionControl TUICCongestionControl `json:"congestion_control,omitempty"`
	UDPRelayMode      TUICUDPRelayMode      `json:"udp_relay_mode,omitempty"`
	ZeroRTT           bool                  `json:"zero_rtt,omitempty"`
}

func (endpoint Endpoint) validateProtocolOptions() error {
	switch endpoint.Protocol {
	case ProtocolVLESS:
		if endpoint.VMessOptions != nil || endpoint.Hysteria2Options != nil || endpoint.TUICOptions != nil {
			return fmt.Errorf("protocol options do not match vless")
		}
		if endpoint.VLESSOptions != nil {
			return endpoint.VLESSOptions.validate()
		}
	case ProtocolVMess:
		if endpoint.VLESSOptions != nil || endpoint.Hysteria2Options != nil || endpoint.TUICOptions != nil {
			return fmt.Errorf("protocol options do not match vmess")
		}
		if endpoint.VMessOptions != nil {
			return endpoint.VMessOptions.validate()
		}
	case ProtocolHysteria2:
		if endpoint.VLESSOptions != nil || endpoint.VMessOptions != nil || endpoint.TUICOptions != nil {
			return fmt.Errorf("protocol options do not match hysteria2")
		}
		if endpoint.Hysteria2Options != nil {
			return endpoint.Hysteria2Options.validate()
		}
	case ProtocolTUIC:
		if endpoint.VLESSOptions != nil || endpoint.VMessOptions != nil || endpoint.Hysteria2Options != nil {
			return fmt.Errorf("protocol options do not match tuic")
		}
		if endpoint.TUICOptions != nil {
			return endpoint.TUICOptions.validate()
		}
	case ProtocolTrojan, ProtocolShadowsocks:
		if endpoint.VLESSOptions != nil || endpoint.VMessOptions != nil || endpoint.Hysteria2Options != nil || endpoint.TUICOptions != nil {
			return fmt.Errorf("protocol options are not applicable to %s", endpoint.Protocol)
		}
	}
	return nil
}

func (options VLESSOptions) validate() error {
	if err := validateString("VLESS flow", string(options.Flow), MaxProtocolOptionLength, false); err != nil {
		return err
	}
	switch options.Flow {
	case "", VLESSFlowXTLSRPRXVision:
	default:
		return fmt.Errorf("unsupported VLESS flow")
	}
	return validatePacketEncoding(options.PacketEncoding)
}

func (options VMessOptions) validate() error {
	if err := validateString("VMess security", string(options.Security), MaxProtocolOptionLength, false); err != nil {
		return err
	}
	switch options.Security {
	case "", VMessSecurityAuto, VMessSecurityNone, VMessSecurityZero, VMessSecurityAES128GCM, VMessSecurityChaCha20Poly1305:
	default:
		return fmt.Errorf("unsupported VMess security")
	}
	if options.AlterID < 0 || options.AlterID > MaxVMessAlterID {
		return fmt.Errorf("VMess alter ID must be between 0 and %d", MaxVMessAlterID)
	}
	return validatePacketEncoding(options.PacketEncoding)
}

func (options Hysteria2Options) validate() error {
	if err := validateString("Hysteria2 obfuscation type", string(options.ObfsType), MaxProtocolOptionLength, false); err != nil {
		return err
	}
	if err := validateString("Hysteria2 obfuscation password", options.ObfsPassword, MaxCredentialLength, false); err != nil {
		return err
	}
	switch options.ObfsType {
	case "":
		if options.ObfsPassword != "" {
			return fmt.Errorf("Hysteria2 obfuscation password requires an obfuscation type")
		}
	case Hysteria2ObfsSalamander:
		if options.ObfsPassword == "" {
			return fmt.Errorf("Hysteria2 obfuscation password is required")
		}
	default:
		return fmt.Errorf("unsupported Hysteria2 obfuscation type")
	}
	if err := validateMbps("Hysteria2 upload", options.UpMbps); err != nil {
		return err
	}
	return validateMbps("Hysteria2 download", options.DownMbps)
}

func (options TUICOptions) validate() error {
	if err := validateString("TUIC congestion control", string(options.CongestionControl), MaxProtocolOptionLength, false); err != nil {
		return err
	}
	switch options.CongestionControl {
	case "", TUICCongestionCubic, TUICCongestionNewReno, TUICCongestionBBR:
	default:
		return fmt.Errorf("unsupported TUIC congestion control")
	}
	if err := validateString("TUIC UDP relay mode", string(options.UDPRelayMode), MaxProtocolOptionLength, false); err != nil {
		return err
	}
	switch options.UDPRelayMode {
	case "", TUICUDPRelayNative, TUICUDPRelayQUIC:
	default:
		return fmt.Errorf("unsupported TUIC UDP relay mode")
	}
	return nil
}

func validatePacketEncoding(encoding PacketEncoding) error {
	if err := validateString("packet encoding", string(encoding), MaxProtocolOptionLength, false); err != nil {
		return err
	}
	switch encoding {
	case "", PacketEncodingXUDP, PacketEncodingPacketAddr:
		return nil
	default:
		return fmt.Errorf("unsupported packet encoding")
	}
}

func validateMbps(name string, value int) error {
	if value < 0 || value > MaxHysteria2Mbps {
		return fmt.Errorf("%s Mbps must be between 0 and %d", name, MaxHysteria2Mbps)
	}
	return nil
}

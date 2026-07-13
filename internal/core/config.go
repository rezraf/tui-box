package core

import (
	"encoding/json"
	"fmt"
	"math"
	"net/netip"
	"strings"

	"github.com/rezraf/tui-box/internal/domain"
)

const (
	inboundTag        = "tuibox-inbound"
	proxyOutboundTag  = "tuibox-proxy"
	directOutboundTag = "tuibox-direct"
	dnsServerTag      = "tuibox-dns"

	proxyListenAddress = "127.0.0.1"
	proxyListenPort    = 2080
	tunInterfaceName   = "tuibox0"
	tunAddress         = "172.19.0.1/30"
	dnsServerAddress   = "1.1.1.1"

	maxRuleDirectDomainSuffixes = 64
	maxRuleDirectCIDRs          = 64
	maxDomainSuffixBytes        = 253
)

type ConnectionRequest struct {
	Mode                     domain.ConnectionMode
	Route                    domain.RouteMode
	Endpoint                 *domain.Endpoint
	UID                      int
	GID                      int
	RuleDirectDomainSuffixes []string
	RuleDirectCIDRs          []netip.Prefix
}

func GenerateConfig(request ConnectionRequest) ([]byte, error) {
	if err := request.validate(); err != nil {
		return nil, err
	}

	config := singBoxConfig{
		Log:       logOptions{Disabled: true},
		DNS:       fixedDNSOptions(),
		Inbounds:  []inbound{buildInbound(request.Mode)},
		Outbounds: []outbound{{Type: "direct", Tag: directOutboundTag}},
		Route:     fixedRouteOptions(request),
	}
	if request.Route != domain.RouteModeDirect {
		proxy := mapEndpoint(*request.Endpoint)
		config.Outbounds = append([]outbound{proxy}, config.Outbounds...)
	}

	output, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("encode sing-box config")
	}
	return append(output, '\n'), nil
}

func (request ConnectionRequest) validate() error {
	switch request.Mode {
	case domain.ConnectionModeProxy, domain.ConnectionModeTUN:
	default:
		return fmt.Errorf("unsupported connection mode")
	}
	switch request.Route {
	case domain.RouteModeGlobal, domain.RouteModeRule, domain.RouteModeDirect:
	default:
		return fmt.Errorf("unsupported route mode")
	}
	if err := validateIdentity("UID", request.UID); err != nil {
		return err
	}
	if err := validateIdentity("GID", request.GID); err != nil {
		return err
	}
	if request.Mode == domain.ConnectionModeProxy && request.UID == 0 {
		return fmt.Errorf("proxy UID must be non-root")
	}
	if request.Mode == domain.ConnectionModeProxy && request.GID == 0 {
		return fmt.Errorf("proxy GID must be non-root")
	}
	if err := request.validateRuleDirectFields(); err != nil {
		return err
	}
	if request.Endpoint == nil {
		if request.Route == domain.RouteModeDirect {
			return nil
		}
		return fmt.Errorf("endpoint is required")
	}
	if err := request.Endpoint.Validate(); err != nil {
		return fmt.Errorf("invalid endpoint: %w", err)
	}
	return nil
}

func validateIdentity(name string, value int) error {
	if value < 0 || uint64(value) >= math.MaxUint32 {
		return fmt.Errorf("%s is invalid", name)
	}
	return nil
}

func (request ConnectionRequest) validateRuleDirectFields() error {
	if request.Route != domain.RouteModeRule {
		if len(request.RuleDirectDomainSuffixes) != 0 || len(request.RuleDirectCIDRs) != 0 {
			return fmt.Errorf("direct rule fields require Rule route mode")
		}
		return nil
	}
	if len(request.RuleDirectDomainSuffixes) > maxRuleDirectDomainSuffixes {
		return fmt.Errorf("too many direct domain suffixes")
	}
	if len(request.RuleDirectCIDRs) > maxRuleDirectCIDRs {
		return fmt.Errorf("too many direct CIDRs")
	}

	seenDomains := make(map[string]struct{}, len(request.RuleDirectDomainSuffixes))
	for _, suffix := range request.RuleDirectDomainSuffixes {
		normalized := strings.ToLower(suffix)
		if !validDomainSuffix(suffix) {
			return fmt.Errorf("invalid direct domain suffix")
		}
		if _, exists := seenDomains[normalized]; exists {
			return fmt.Errorf("duplicate direct domain suffix")
		}
		seenDomains[normalized] = struct{}{}
	}

	seenCIDRs := make(map[netip.Prefix]struct{}, len(request.RuleDirectCIDRs))
	for _, prefix := range request.RuleDirectCIDRs {
		if !prefix.IsValid() || prefix != prefix.Masked() {
			return fmt.Errorf("invalid direct CIDR")
		}
		if _, exists := seenCIDRs[prefix]; exists {
			return fmt.Errorf("duplicate direct CIDR")
		}
		seenCIDRs[prefix] = struct{}{}
	}
	return nil
}

func validDomainSuffix(value string) bool {
	if value == "" || len(value) > maxDomainSuffixBytes || value != strings.TrimSpace(value) || strings.HasPrefix(value, ".") || strings.HasSuffix(value, ".") {
		return false
	}
	if _, err := netip.ParseAddr(value); err == nil {
		return false
	}
	for _, label := range strings.Split(value, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, character := range label {
			if character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z' || character >= '0' && character <= '9' || character == '-' {
				continue
			}
			return false
		}
	}
	return true
}

type singBoxConfig struct {
	Log       logOptions   `json:"log"`
	DNS       dnsOptions   `json:"dns"`
	Inbounds  []inbound    `json:"inbounds"`
	Outbounds []outbound   `json:"outbounds"`
	Route     routeOptions `json:"route"`
}

type logOptions struct {
	Disabled bool `json:"disabled"`
}

type dnsOptions struct {
	Servers  []dnsServer `json:"servers"`
	Final    string      `json:"final"`
	Strategy string      `json:"strategy"`
}

type dnsServer struct {
	Type       string `json:"type"`
	Tag        string `json:"tag"`
	Server     string `json:"server"`
	ServerPort int    `json:"server_port"`
	Detour     string `json:"detour"`
}

func fixedDNSOptions() dnsOptions {
	return dnsOptions{
		Servers: []dnsServer{{
			Type:       "udp",
			Tag:        dnsServerTag,
			Server:     dnsServerAddress,
			ServerPort: 53,
			Detour:     directOutboundTag,
		}},
		Final:    dnsServerTag,
		Strategy: "prefer_ipv4",
	}
}

type inbound struct {
	Type          string   `json:"type"`
	Tag           string   `json:"tag"`
	Listen        string   `json:"listen,omitempty"`
	ListenPort    int      `json:"listen_port,omitempty"`
	InterfaceName string   `json:"interface_name,omitempty"`
	Address       []string `json:"address,omitempty"`
	AutoRoute     bool     `json:"auto_route,omitempty"`
	StrictRoute   bool     `json:"strict_route,omitempty"`
}

func buildInbound(mode domain.ConnectionMode) inbound {
	if mode == domain.ConnectionModeProxy {
		return inbound{
			Type:       "mixed",
			Tag:        inboundTag,
			Listen:     proxyListenAddress,
			ListenPort: proxyListenPort,
		}
	}
	return inbound{
		Type:          "tun",
		Tag:           inboundTag,
		InterfaceName: tunInterfaceName,
		Address:       []string{tunAddress},
		AutoRoute:     true,
		StrictRoute:   true,
	}
}

type routeOptions struct {
	Rules                 []routeRule           `json:"rules"`
	Final                 string                `json:"final"`
	AutoDetectInterface   bool                  `json:"auto_detect_interface"`
	DefaultDomainResolver domainResolverOptions `json:"default_domain_resolver"`
}

type domainResolverOptions struct {
	Server   string `json:"server"`
	Strategy string `json:"strategy"`
}

type routeRule struct {
	Protocol     string   `json:"protocol,omitempty"`
	IPIsPrivate  bool     `json:"ip_is_private,omitempty"`
	DomainSuffix []string `json:"domain_suffix,omitempty"`
	IPCIDR       []string `json:"ip_cidr,omitempty"`
	Action       string   `json:"action"`
	Outbound     string   `json:"outbound,omitempty"`
}

func fixedRouteOptions(request ConnectionRequest) routeOptions {
	final := proxyOutboundTag
	if request.Route == domain.RouteModeDirect {
		final = directOutboundTag
	}
	rules := []routeRule{
		{Protocol: "dns", Action: "hijack-dns"},
		{IPIsPrivate: true, Action: "route", Outbound: directOutboundTag},
		{DomainSuffix: []string{".lan", ".local", ".localhost"}, Action: "route", Outbound: directOutboundTag},
	}
	if len(request.RuleDirectDomainSuffixes) != 0 {
		suffixes := make([]string, len(request.RuleDirectDomainSuffixes))
		for index, suffix := range request.RuleDirectDomainSuffixes {
			suffixes[index] = strings.ToLower(suffix)
		}
		rules = append(rules, routeRule{DomainSuffix: suffixes, Action: "route", Outbound: directOutboundTag})
	}
	if len(request.RuleDirectCIDRs) != 0 {
		prefixes := make([]string, len(request.RuleDirectCIDRs))
		for index, prefix := range request.RuleDirectCIDRs {
			prefixes[index] = prefix.String()
		}
		rules = append(rules, routeRule{IPCIDR: prefixes, Action: "route", Outbound: directOutboundTag})
	}
	return routeOptions{
		Rules:               rules,
		Final:               final,
		AutoDetectInterface: true,
		DefaultDomainResolver: domainResolverOptions{
			Server:   dnsServerTag,
			Strategy: "prefer_ipv4",
		},
	}
}

type outbound struct {
	Type              string                       `json:"type"`
	Tag               string                       `json:"tag"`
	Server            string                       `json:"server,omitempty"`
	ServerPort        int                          `json:"server_port,omitempty"`
	UUID              string                       `json:"uuid,omitempty"`
	Password          string                       `json:"password,omitempty"`
	Method            string                       `json:"method,omitempty"`
	Flow              domain.VLESSFlow             `json:"flow,omitempty"`
	PacketEncoding    domain.PacketEncoding        `json:"packet_encoding,omitempty"`
	Security          domain.VMessSecurity         `json:"security,omitempty"`
	AlterID           int                          `json:"alter_id,omitempty"`
	TLS               *tlsOptions                  `json:"tls,omitempty"`
	Transport         *transportOptions            `json:"transport,omitempty"`
	Obfs              *hysteria2Obfs               `json:"obfs,omitempty"`
	UpMbps            int                          `json:"up_mbps,omitempty"`
	DownMbps          int                          `json:"down_mbps,omitempty"`
	CongestionControl domain.TUICCongestionControl `json:"congestion_control,omitempty"`
	UDPRelayMode      domain.TUICUDPRelayMode      `json:"udp_relay_mode,omitempty"`
	ZeroRTTHandshake  bool                         `json:"zero_rtt_handshake,omitempty"`
}

type tlsOptions struct {
	Enabled    bool            `json:"enabled"`
	ServerName string          `json:"server_name,omitempty"`
	Insecure   bool            `json:"insecure,omitempty"`
	ALPN       []string        `json:"alpn,omitempty"`
	UTLS       *utlsOptions    `json:"utls,omitempty"`
	Reality    *realityOptions `json:"reality,omitempty"`
}

type utlsOptions struct {
	Enabled     bool                   `json:"enabled"`
	Fingerprint domain.UTLSFingerprint `json:"fingerprint"`
}

type realityOptions struct {
	Enabled   bool   `json:"enabled"`
	PublicKey string `json:"public_key"`
	ShortID   string `json:"short_id,omitempty"`
}

type transportOptions struct {
	Type        domain.TransportType `json:"type"`
	Path        string               `json:"path,omitempty"`
	Host        string               `json:"host,omitempty"`
	Headers     *transportHeaders    `json:"headers,omitempty"`
	ServiceName string               `json:"service_name,omitempty"`
}

type transportHeaders struct {
	Host string `json:"Host,omitempty"`
}

type hysteria2Obfs struct {
	Type     domain.Hysteria2ObfsType `json:"type"`
	Password string                   `json:"password"`
}

func mapEndpoint(endpoint domain.Endpoint) outbound {
	mapped := outbound{
		Type:       string(endpoint.Protocol),
		Tag:        proxyOutboundTag,
		Server:     endpoint.Host,
		ServerPort: endpoint.Port,
		UUID:       endpoint.UUID,
		Password:   endpoint.Password,
		Method:     endpoint.Method,
		TLS:        mapTLS(endpoint.TLS),
		Transport:  mapTransport(endpoint.Transport),
	}
	if endpoint.VLESSOptions != nil {
		mapped.Flow = endpoint.VLESSOptions.Flow
		mapped.PacketEncoding = endpoint.VLESSOptions.PacketEncoding
	}
	if endpoint.VMessOptions != nil {
		mapped.Security = endpoint.VMessOptions.Security
		mapped.AlterID = endpoint.VMessOptions.AlterID
		mapped.PacketEncoding = endpoint.VMessOptions.PacketEncoding
	}
	if endpoint.Protocol == domain.ProtocolVMess && mapped.Security == "" {
		mapped.Security = domain.VMessSecurityAuto
	}
	if endpoint.Hysteria2Options != nil {
		mapped.UpMbps = endpoint.Hysteria2Options.UpMbps
		mapped.DownMbps = endpoint.Hysteria2Options.DownMbps
		if endpoint.Hysteria2Options.ObfsType != "" {
			mapped.Obfs = &hysteria2Obfs{
				Type:     endpoint.Hysteria2Options.ObfsType,
				Password: endpoint.Hysteria2Options.ObfsPassword,
			}
		}
	}
	if endpoint.TUICOptions != nil {
		mapped.CongestionControl = endpoint.TUICOptions.CongestionControl
		mapped.UDPRelayMode = endpoint.TUICOptions.UDPRelayMode
		mapped.ZeroRTTHandshake = endpoint.TUICOptions.ZeroRTT
	}
	return mapped
}

func mapTLS(options domain.TLSOptions) *tlsOptions {
	if !options.Enabled {
		return nil
	}
	mapped := &tlsOptions{
		Enabled:    true,
		ServerName: options.ServerName,
		Insecure:   options.InsecureSkipVerify,
		ALPN:       append([]string(nil), options.ALPN...),
	}
	if options.UTLSFingerprint != "" {
		mapped.UTLS = &utlsOptions{Enabled: true, Fingerprint: options.UTLSFingerprint}
	}
	if options.Reality != nil {
		mapped.Reality = &realityOptions{
			Enabled:   true,
			PublicKey: options.Reality.PublicKey,
			ShortID:   options.Reality.ShortID,
		}
	}
	return mapped
}

func mapTransport(options domain.TransportOptions) *transportOptions {
	switch options.Type {
	case domain.TransportTCP, "":
		return nil
	case domain.TransportWebSocket:
		mapped := &transportOptions{Type: options.Type, Path: options.Path}
		if options.Host != "" {
			mapped.Headers = &transportHeaders{Host: options.Host}
		}
		return mapped
	case domain.TransportGRPC:
		return &transportOptions{Type: options.Type, ServiceName: options.ServiceName}
	case domain.TransportHTTPUpgrade:
		return &transportOptions{Type: options.Type, Path: options.Path, Host: options.Host}
	default:
		return nil
	}
}

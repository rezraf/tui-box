package subscription

import (
	"errors"
	"strconv"
	"strings"

	"github.com/rezraf/tui-box/internal/domain"
	"gopkg.in/yaml.v3"
)

type clashDocument struct {
	Proxies []yaml.Node `yaml:"proxies"`
}

type clashProxy struct {
	Name              string                  `yaml:"name"`
	Type              string                  `yaml:"type"`
	Server            string                  `yaml:"server"`
	Port              int                     `yaml:"port"`
	UUID              string                  `yaml:"uuid"`
	Password          string                  `yaml:"password"`
	Cipher            string                  `yaml:"cipher"`
	AlterID           int                     `yaml:"alterId"`
	TLS               bool                    `yaml:"tls"`
	ServerName        string                  `yaml:"servername"`
	SNI               string                  `yaml:"sni"`
	SkipCertVerify    bool                    `yaml:"skip-cert-verify"`
	ALPN              yamlStringList          `yaml:"alpn"`
	Network           string                  `yaml:"network"`
	Flow              string                  `yaml:"flow"`
	PacketEncoding    string                  `yaml:"packet-encoding"`
	ClientFingerprint string                  `yaml:"client-fingerprint"`
	WSOptions         clashWebSocketOptions   `yaml:"ws-opts"`
	GRPCOptions       clashGRPCOptions        `yaml:"grpc-opts"`
	HTTPUpgrade       clashHTTPUpgradeOptions `yaml:"http-upgrade-opts"`
	RealityOptions    *clashRealityOptions    `yaml:"reality-opts"`
	Obfs              string                  `yaml:"obfs"`
	ObfsPassword      string                  `yaml:"obfs-password"`
	UpMbps            yamlMbps                `yaml:"up"`
	DownMbps          yamlMbps                `yaml:"down"`
	Congestion        string                  `yaml:"congestion-controller"`
	UDPRelayMode      string                  `yaml:"udp-relay-mode"`
	ReduceRTT         bool                    `yaml:"reduce-rtt"`
}

type clashRealityOptions struct {
	PublicKey string `yaml:"public-key"`
	ShortID   string `yaml:"short-id"`
}

type clashWebSocketOptions struct {
	Path    string         `yaml:"path"`
	Headers boundedHeaders `yaml:"headers"`
}

type clashGRPCOptions struct {
	ServiceName string `yaml:"grpc-service-name"`
}

type clashHTTPUpgradeOptions struct {
	Path    string         `yaml:"path"`
	Headers boundedHeaders `yaml:"headers"`
}

type boundedHeaders struct {
	Host string
}

func (headers *boundedHeaders) UnmarshalYAML(node *yaml.Node) error {
	if node.Kind == 0 {
		return nil
	}
	if node.Kind != yaml.MappingNode {
		return errors.New("headers must be a mapping")
	}
	for index := 0; index+1 < len(node.Content); index += 2 {
		if strings.EqualFold(node.Content[index].Value, "host") {
			if node.Content[index+1].Kind != yaml.ScalarNode {
				return errors.New("Host header must be scalar")
			}
			headers.Host = node.Content[index+1].Value
		}
	}
	return nil
}

type yamlStringList []string

func (values *yamlStringList) UnmarshalYAML(node *yaml.Node) error {
	switch node.Kind {
	case yaml.ScalarNode:
		*values = splitList(node.Value)
	case yaml.SequenceNode:
		result := make([]string, 0, len(node.Content))
		for _, child := range node.Content {
			if child.Kind != yaml.ScalarNode {
				return errors.New("list value must be scalar")
			}
			result = append(result, child.Value)
		}
		*values = result
	default:
		return errors.New("value must be a string or list")
	}
	return nil
}

type yamlMbps int

func (value *yamlMbps) UnmarshalYAML(node *yaml.Node) error {
	if node.Kind != yaml.ScalarNode {
		return errors.New("bandwidth must be scalar")
	}
	text := strings.TrimSpace(node.Value)
	if text == "" {
		*value = 0
		return nil
	}
	fields := strings.Fields(text)
	parsed, err := strconv.Atoi(fields[0])
	if err != nil {
		return errors.New("bandwidth is invalid")
	}
	*value = yamlMbps(parsed)
	return nil
}

func parseClash(subscriptionID string, content []byte) (ParseResult, error) {
	var document clashDocument
	if err := yaml.Unmarshal(content, &document); err != nil {
		return ParseResult{}, errMalformedDocument
	}
	if len(document.Proxies) > MaxEntries {
		return ParseResult{}, errTooManyEntries
	}
	result := ParseResult{Format: domain.SubscriptionFormatClash}
	seen := make(map[string]struct{})
	for index := range document.Proxies {
		entryNumber := index + 1
		node := &document.Proxies[index]
		encoded, err := yaml.Marshal(node)
		if err != nil || len(encoded) > MaxEntryBytes {
			result.Warnings = append(result.Warnings, oversizedWarning(subscriptionID, entryNumber))
			continue
		}
		if containsYAMLAlias(node) {
			result.Warnings = append(result.Warnings, invalidWarning(subscriptionID, entryNumber))
			continue
		}
		var proxy clashProxy
		if err := node.Decode(&proxy); err != nil {
			result.Warnings = append(result.Warnings, invalidWarning(subscriptionID, entryNumber))
			continue
		}
		endpoint, err := proxy.endpoint()
		if err != nil {
			result.Warnings = append(result.Warnings, invalidWarning(subscriptionID, entryNumber))
			continue
		}
		addEndpoint(&result, endpoint, subscriptionID, entryNumber, seen)
	}
	return result, nil
}

func (proxy clashProxy) endpoint() (domain.Endpoint, error) {
	protocol, err := clashProtocol(proxy.Type)
	if err != nil {
		return domain.Endpoint{}, err
	}
	endpoint := domain.Endpoint{
		Name:     proxy.Name,
		Protocol: protocol,
		Host:     proxy.Server,
		Port:     proxy.Port,
	}
	serverName := proxy.ServerName
	if serverName == "" {
		serverName = proxy.SNI
	}
	tlsRequired := protocol == domain.ProtocolTrojan || protocol == domain.ProtocolHysteria2 || protocol == domain.ProtocolTUIC
	endpoint.TLS = domain.TLSOptions{
		Enabled:            proxy.TLS || proxy.RealityOptions != nil || tlsRequired,
		ServerName:         serverName,
		InsecureSkipVerify: proxy.SkipCertVerify,
		ALPN:               []string(proxy.ALPN),
		UTLSFingerprint:    domain.UTLSFingerprint(proxy.ClientFingerprint),
	}
	if proxy.RealityOptions != nil {
		endpoint.TLS.Reality = &domain.RealityClientOptions{
			PublicKey: proxy.RealityOptions.PublicKey,
			ShortID:   proxy.RealityOptions.ShortID,
		}
	}

	switch protocol {
	case domain.ProtocolVLESS:
		endpoint.UUID = proxy.UUID
		endpoint.Transport, err = proxy.transport()
		endpoint.VLESSOptions = &domain.VLESSOptions{Flow: domain.VLESSFlow(proxy.Flow), PacketEncoding: domain.PacketEncoding(proxy.PacketEncoding)}
	case domain.ProtocolVMess:
		endpoint.UUID = proxy.UUID
		endpoint.Transport, err = proxy.transport()
		endpoint.VMessOptions = &domain.VMessOptions{Security: domain.VMessSecurity(proxy.Cipher), AlterID: proxy.AlterID, PacketEncoding: domain.PacketEncoding(proxy.PacketEncoding)}
	case domain.ProtocolTrojan:
		endpoint.Password = proxy.Password
		endpoint.Transport, err = proxy.transport()
	case domain.ProtocolShadowsocks:
		endpoint.Method = proxy.Cipher
		endpoint.Password = proxy.Password
	case domain.ProtocolHysteria2:
		endpoint.Password = proxy.Password
		endpoint.Hysteria2Options = &domain.Hysteria2Options{
			ObfsType: domain.Hysteria2ObfsType(proxy.Obfs), ObfsPassword: proxy.ObfsPassword,
			UpMbps: int(proxy.UpMbps), DownMbps: int(proxy.DownMbps),
		}
	case domain.ProtocolTUIC:
		endpoint.UUID = proxy.UUID
		endpoint.Password = proxy.Password
		endpoint.TUICOptions = &domain.TUICOptions{
			CongestionControl: domain.TUICCongestionControl(proxy.Congestion),
			UDPRelayMode:      domain.TUICUDPRelayMode(proxy.UDPRelayMode),
			ZeroRTT:           proxy.ReduceRTT,
		}
	}
	if err != nil {
		return domain.Endpoint{}, err
	}
	return endpoint, nil
}

func (proxy clashProxy) transport() (domain.TransportOptions, error) {
	switch strings.ToLower(proxy.Network) {
	case "", "tcp":
		return transportFromValues("tcp", "", "", "")
	case "ws", "websocket":
		return transportFromValues("ws", proxy.WSOptions.Path, proxy.WSOptions.Headers.Host, "")
	case "grpc":
		return transportFromValues("grpc", "", "", proxy.GRPCOptions.ServiceName)
	case "httpupgrade", "http-upgrade":
		return transportFromValues("httpupgrade", proxy.HTTPUpgrade.Path, proxy.HTTPUpgrade.Headers.Host, "")
	default:
		return domain.TransportOptions{}, errInvalidEntry
	}
}

func clashProtocol(value string) (domain.Protocol, error) {
	switch strings.ToLower(value) {
	case "vless":
		return domain.ProtocolVLESS, nil
	case "vmess":
		return domain.ProtocolVMess, nil
	case "trojan":
		return domain.ProtocolTrojan, nil
	case "ss", "shadowsocks":
		return domain.ProtocolShadowsocks, nil
	case "hysteria2", "hy2":
		return domain.ProtocolHysteria2, nil
	case "tuic":
		return domain.ProtocolTUIC, nil
	default:
		return "", errUnsupportedEntry
	}
}

func containsYAMLAlias(node *yaml.Node) bool {
	if node == nil {
		return false
	}
	if node.Kind == yaml.AliasNode {
		return true
	}
	for _, child := range node.Content {
		if containsYAMLAlias(child) {
			return true
		}
	}
	return false
}

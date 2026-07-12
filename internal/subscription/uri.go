package subscription

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"net/url"
	"strconv"
	"strings"

	"github.com/rezraf/tui-box/internal/domain"
)

func parseURIList(subscriptionID string, content []byte) (ParseResult, error) {
	result := ParseResult{Format: domain.SubscriptionFormatURIList}
	seen := make(map[string]struct{})
	entryIndex := 0
	for start := 0; start < len(content); {
		end := bytes.IndexByte(content[start:], '\n')
		if end < 0 {
			end = len(content) - start
		}
		line := content[start : start+end]
		start += end + 1
		entry := strings.TrimSpace(string(line))
		if entry == "" {
			continue
		}
		entryIndex++
		if entryIndex > MaxEntries {
			return ParseResult{}, errTooManyEntries
		}
		if len(entry) > MaxEntryBytes {
			result.Warnings = append(result.Warnings, oversizedWarning(subscriptionID, entryIndex))
			continue
		}
		endpoint, err := parseURIEntry(entry)
		if err != nil {
			result.Warnings = append(result.Warnings, invalidWarning(subscriptionID, entryIndex))
			continue
		}
		addEndpoint(&result, endpoint, subscriptionID, entryIndex, seen)
	}
	return result, nil
}

func parseURIEntry(entry string) (domain.Endpoint, error) {
	schemeEnd := strings.Index(entry, "://")
	if schemeEnd <= 0 {
		return domain.Endpoint{}, errInvalidEntry
	}
	switch strings.ToLower(entry[:schemeEnd]) {
	case "vless":
		return parseVLESS(entry)
	case "vmess":
		return parseVMess(entry)
	case "trojan":
		return parseTrojan(entry)
	case "ss":
		return parseShadowsocks(entry)
	case "hysteria2", "hy2":
		return parseHysteria2(entry)
	case "tuic":
		return parseTUIC(entry)
	default:
		return domain.Endpoint{}, errUnsupportedEntry
	}
}

func parseVLESS(entry string) (domain.Endpoint, error) {
	parsed, err := url.Parse(entry)
	if err != nil || parsed.User == nil {
		return domain.Endpoint{}, errInvalidEntry
	}
	if _, hasPassword := parsed.User.Password(); hasPassword {
		return domain.Endpoint{}, errInvalidEntry
	}
	host, port, err := hostPort(parsed)
	if err != nil {
		return domain.Endpoint{}, errInvalidEntry
	}
	tls, err := queryTLS(parsed.Query(), false)
	if err != nil {
		return domain.Endpoint{}, errInvalidEntry
	}
	transport, err := queryTransport(parsed.Query())
	if err != nil {
		return domain.Endpoint{}, errInvalidEntry
	}
	options := &domain.VLESSOptions{
		Flow:           domain.VLESSFlow(firstValue(parsed.Query(), "flow")),
		PacketEncoding: domain.PacketEncoding(firstValue(parsed.Query(), "packetEncoding", "packet_encoding")),
	}
	return domain.Endpoint{
		Name:         parsed.Fragment,
		Protocol:     domain.ProtocolVLESS,
		Host:         host,
		Port:         port,
		UUID:         parsed.User.Username(),
		TLS:          tls,
		Transport:    transport,
		VLESSOptions: options,
	}, nil
}

type vmessLink struct {
	Name           string          `json:"ps"`
	Host           string          `json:"add"`
	Port           json.RawMessage `json:"port"`
	UUID           string          `json:"id"`
	AlterID        json.RawMessage `json:"aid"`
	Security       string          `json:"scy"`
	Network        string          `json:"net"`
	TransportHost  string          `json:"host"`
	Path           string          `json:"path"`
	TLS            string          `json:"tls"`
	ServerName     string          `json:"sni"`
	AlternateSNI   string          `json:"servername"`
	ALPN           string          `json:"alpn"`
	PacketEncoding string          `json:"packetEncoding"`
}

func parseVMess(entry string) (domain.Endpoint, error) {
	payload := entry[len("vmess://"):]
	if fragment := strings.IndexByte(payload, '#'); fragment >= 0 {
		payload = payload[:fragment]
	}
	decoded, ok := decodeBase64([]byte(strings.TrimSpace(payload)))
	if !ok || len(decoded) > MaxEntryBytes {
		return domain.Endpoint{}, errInvalidEntry
	}
	var link vmessLink
	decoder := json.NewDecoder(bytes.NewReader(decoded))
	if err := decoder.Decode(&link); err != nil {
		return domain.Endpoint{}, errInvalidEntry
	}
	if err := requireJSONEOF(decoder); err != nil {
		return domain.Endpoint{}, errInvalidEntry
	}
	port, err := rawInteger(link.Port, false)
	if err != nil {
		return domain.Endpoint{}, errInvalidEntry
	}
	alterID, err := rawInteger(link.AlterID, true)
	if err != nil {
		return domain.Endpoint{}, errInvalidEntry
	}
	transportPath := link.Path
	serviceName := ""
	if strings.EqualFold(link.Network, "grpc") {
		transportPath = ""
		serviceName = link.Path
	}
	transport, err := transportFromValues(link.Network, transportPath, link.TransportHost, serviceName)
	if err != nil {
		return domain.Endpoint{}, errInvalidEntry
	}
	serverName := link.ServerName
	if serverName == "" {
		serverName = link.AlternateSNI
	}
	tlsEnabled := link.TLS == "tls" || link.TLS == "reality"
	return domain.Endpoint{
		Name:     link.Name,
		Protocol: domain.ProtocolVMess,
		Host:     link.Host,
		Port:     port,
		UUID:     link.UUID,
		TLS: domain.TLSOptions{
			Enabled:    tlsEnabled,
			ServerName: serverName,
			ALPN:       splitList(link.ALPN),
		},
		Transport: transport,
		VMessOptions: &domain.VMessOptions{
			Security:       domain.VMessSecurity(link.Security),
			AlterID:        alterID,
			PacketEncoding: domain.PacketEncoding(link.PacketEncoding),
		},
	}, nil
}

func parseTrojan(entry string) (domain.Endpoint, error) {
	parsed, err := url.Parse(entry)
	if err != nil || parsed.User == nil {
		return domain.Endpoint{}, errInvalidEntry
	}
	host, port, err := hostPort(parsed)
	if err != nil {
		return domain.Endpoint{}, errInvalidEntry
	}
	tls, err := queryTLS(parsed.Query(), true)
	if err != nil {
		return domain.Endpoint{}, errInvalidEntry
	}
	transport, err := queryTransport(parsed.Query())
	if err != nil {
		return domain.Endpoint{}, errInvalidEntry
	}
	return domain.Endpoint{
		Name:      parsed.Fragment,
		Protocol:  domain.ProtocolTrojan,
		Host:      host,
		Port:      port,
		Password:  combinedUserInfo(parsed.User),
		TLS:       tls,
		Transport: transport,
	}, nil
}

func parseShadowsocks(entry string) (domain.Endpoint, error) {
	parsed, err := url.Parse(entry)
	if err != nil {
		return domain.Endpoint{}, errInvalidEntry
	}
	if parsed.User != nil && parsed.Hostname() != "" {
		method, password, ok := shadowsocksUserInfo(parsed.User)
		if !ok {
			return domain.Endpoint{}, errInvalidEntry
		}
		host, port, err := hostPort(parsed)
		if err != nil {
			return domain.Endpoint{}, errInvalidEntry
		}
		return domain.Endpoint{Name: parsed.Fragment, Protocol: domain.ProtocolShadowsocks, Host: host, Port: port, Method: method, Password: password}, nil
	}

	payload := strings.TrimPrefix(entry, "ss://")
	if index := strings.IndexAny(payload, "?#"); index >= 0 {
		payload = payload[:index]
	}
	decoded, ok := decodeBase64([]byte(payload))
	if !ok {
		return domain.Endpoint{}, errInvalidEntry
	}
	legacy, err := url.Parse("ss://" + string(decoded))
	if err != nil || legacy.User == nil {
		return domain.Endpoint{}, errInvalidEntry
	}
	method, password, ok := plainShadowsocksUserInfo(legacy.User)
	if !ok {
		return domain.Endpoint{}, errInvalidEntry
	}
	host, port, err := hostPort(legacy)
	if err != nil {
		return domain.Endpoint{}, errInvalidEntry
	}
	return domain.Endpoint{Name: parsed.Fragment, Protocol: domain.ProtocolShadowsocks, Host: host, Port: port, Method: method, Password: password}, nil
}

func parseHysteria2(entry string) (domain.Endpoint, error) {
	parsed, err := url.Parse(entry)
	if err != nil || parsed.User == nil {
		return domain.Endpoint{}, errInvalidEntry
	}
	host, port, err := hostPort(parsed)
	if err != nil {
		return domain.Endpoint{}, errInvalidEntry
	}
	tls, err := queryTLS(parsed.Query(), true)
	if err != nil {
		return domain.Endpoint{}, errInvalidEntry
	}
	up, err := queryInteger(parsed.Query(), "upmbps", "up_mbps", "up")
	if err != nil {
		return domain.Endpoint{}, errInvalidEntry
	}
	down, err := queryInteger(parsed.Query(), "downmbps", "down_mbps", "down")
	if err != nil {
		return domain.Endpoint{}, errInvalidEntry
	}
	return domain.Endpoint{
		Name:      parsed.Fragment,
		Protocol:  domain.ProtocolHysteria2,
		Host:      host,
		Port:      port,
		Password:  combinedUserInfo(parsed.User),
		TLS:       tls,
		Transport: domain.TransportOptions{},
		Hysteria2Options: &domain.Hysteria2Options{
			ObfsType:     domain.Hysteria2ObfsType(firstValue(parsed.Query(), "obfs")),
			ObfsPassword: firstValue(parsed.Query(), "obfs-password", "obfs_password"),
			UpMbps:       up,
			DownMbps:     down,
		},
	}, nil
}

func parseTUIC(entry string) (domain.Endpoint, error) {
	parsed, err := url.Parse(entry)
	if err != nil || parsed.User == nil {
		return domain.Endpoint{}, errInvalidEntry
	}
	password, ok := parsed.User.Password()
	if !ok {
		return domain.Endpoint{}, errInvalidEntry
	}
	host, port, err := hostPort(parsed)
	if err != nil {
		return domain.Endpoint{}, errInvalidEntry
	}
	tls, err := queryTLS(parsed.Query(), true)
	if err != nil {
		return domain.Endpoint{}, errInvalidEntry
	}
	zeroRTT, err := queryBool(parsed.Query(), false, "zero_rtt", "zero-rtt")
	if err != nil {
		return domain.Endpoint{}, errInvalidEntry
	}
	return domain.Endpoint{
		Name:      parsed.Fragment,
		Protocol:  domain.ProtocolTUIC,
		Host:      host,
		Port:      port,
		UUID:      parsed.User.Username(),
		Password:  password,
		TLS:       tls,
		Transport: domain.TransportOptions{},
		TUICOptions: &domain.TUICOptions{
			CongestionControl: domain.TUICCongestionControl(firstValue(parsed.Query(), "congestion_control", "congestion-controller")),
			UDPRelayMode:      domain.TUICUDPRelayMode(firstValue(parsed.Query(), "udp_relay_mode", "udp-relay-mode")),
			ZeroRTT:           zeroRTT,
		},
	}, nil
}

func queryTLS(query url.Values, required bool) (domain.TLSOptions, error) {
	security := strings.ToLower(firstValue(query, "security"))
	enabled := required
	switch security {
	case "", "none":
	case "tls", "reality":
		enabled = true
	default:
		return domain.TLSOptions{}, errInvalidEntry
	}
	if value := firstValue(query, "tls"); value != "" {
		parsed, err := parseBool(value)
		if err != nil {
			return domain.TLSOptions{}, errInvalidEntry
		}
		enabled = parsed
	}
	insecure, err := queryBool(query, false, "insecure", "allowInsecure", "skip-cert-verify")
	if err != nil {
		return domain.TLSOptions{}, errInvalidEntry
	}
	options := domain.TLSOptions{
		Enabled:            enabled,
		ServerName:         firstValue(query, "sni", "serverName", "peer"),
		InsecureSkipVerify: insecure,
		ALPN:               splitList(firstValue(query, "alpn")),
		UTLSFingerprint:    domain.UTLSFingerprint(firstValue(query, "fp")),
	}
	publicKey := firstValue(query, "pbk")
	shortID := firstValue(query, "sid")
	if security == "reality" {
		options.Reality = &domain.RealityClientOptions{PublicKey: publicKey, ShortID: shortID}
	} else if publicKey != "" || shortID != "" {
		return domain.TLSOptions{}, errInvalidEntry
	}
	return options, nil
}

func queryTransport(query url.Values) (domain.TransportOptions, error) {
	return transportFromValues(
		firstValue(query, "type", "network"),
		firstValue(query, "path"),
		firstValue(query, "host"),
		firstValue(query, "serviceName", "service_name", "grpc-service-name"),
	)
}

func transportFromValues(kind, path, host, serviceName string) (domain.TransportOptions, error) {
	switch strings.ToLower(kind) {
	case "", "tcp":
		return domain.TransportOptions{Type: domain.TransportTCP}, nil
	case "ws", "websocket":
		return domain.TransportOptions{Type: domain.TransportWebSocket, Path: path, Host: host}, nil
	case "grpc":
		return domain.TransportOptions{Type: domain.TransportGRPC, ServiceName: serviceName}, nil
	case "httpupgrade", "http-upgrade":
		return domain.TransportOptions{Type: domain.TransportHTTPUpgrade, Path: path, Host: host}, nil
	default:
		return domain.TransportOptions{}, errInvalidEntry
	}
}

func shadowsocksUserInfo(user *url.Userinfo) (string, string, bool) {
	if password, ok := user.Password(); ok {
		return user.Username(), password, user.Username() != "" && password != ""
	}
	decoded, ok := decodeBase64([]byte(user.Username()))
	if !ok {
		return "", "", false
	}
	parts := strings.SplitN(string(decoded), ":", 2)
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return "", "", false
	}
	return parts[0], parts[1], true
}

func plainShadowsocksUserInfo(user *url.Userinfo) (string, string, bool) {
	password, ok := user.Password()
	if !ok || user.Username() == "" || password == "" {
		return "", "", false
	}
	return user.Username(), password, true
}

func combinedUserInfo(user *url.Userinfo) string {
	password, ok := user.Password()
	if !ok {
		return user.Username()
	}
	return user.Username() + ":" + password
}

func hostPort(parsed *url.URL) (string, int, error) {
	host := parsed.Hostname()
	portText := parsed.Port()
	if host == "" || portText == "" {
		return "", 0, errInvalidEntry
	}
	port, err := strconv.Atoi(portText)
	if err != nil {
		return "", 0, errInvalidEntry
	}
	return host, port, nil
}

func rawInteger(raw json.RawMessage, optional bool) (int, error) {
	if len(raw) == 0 || string(raw) == "null" || string(raw) == `""` {
		if optional {
			return 0, nil
		}
		return 0, errInvalidEntry
	}
	var number int
	if err := json.Unmarshal(raw, &number); err == nil {
		return number, nil
	}
	var text string
	if err := json.Unmarshal(raw, &text); err != nil {
		return 0, errInvalidEntry
	}
	return strconv.Atoi(text)
}

func queryInteger(query url.Values, keys ...string) (int, error) {
	value := firstValue(query, keys...)
	if value == "" {
		return 0, nil
	}
	return strconv.Atoi(value)
}

func queryBool(query url.Values, fallback bool, keys ...string) (bool, error) {
	value := firstValue(query, keys...)
	if value == "" {
		return fallback, nil
	}
	return parseBool(value)
}

func parseBool(value string) (bool, error) {
	switch strings.ToLower(value) {
	case "1", "true", "yes", "on":
		return true, nil
	case "0", "false", "no", "off":
		return false, nil
	default:
		return false, errInvalidEntry
	}
}

func firstValue(values url.Values, keys ...string) string {
	for _, key := range keys {
		if value := values.Get(key); value != "" {
			return value
		}
	}
	return ""
}

func splitList(value string) []string {
	if value == "" {
		return nil
	}
	parts := strings.Split(value, ",")
	result := make([]string, 0, len(parts))
	for _, part := range parts {
		result = append(result, strings.TrimSpace(part))
	}
	return result
}

func decodeBase64(encoded []byte) ([]byte, bool) {
	encoded = bytes.TrimSpace(encoded)
	for _, encoding := range []*base64.Encoding{
		base64.StdEncoding,
		base64.RawStdEncoding,
		base64.URLEncoding,
		base64.RawURLEncoding,
	} {
		decoded, err := encoding.DecodeString(string(encoded))
		if err == nil {
			return decoded, true
		}
	}
	return nil, false
}

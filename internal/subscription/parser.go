package subscription

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/rezraf/tui-box/internal/domain"
)

const (
	MaxDocumentBytes = 10 << 20
	MaxEntries       = 10_000
	MaxEntryBytes    = 64 << 10
)

var (
	errMalformedDocument = errors.New("subscription document is empty or malformed")
	errDocumentTooLarge  = errors.New("subscription document exceeds the size limit")
	errTooManyEntries    = errors.New("subscription document has too many entries")
	errInvalidEntry      = errors.New("entry is malformed or unsupported")
	errUnsupportedEntry  = errors.New("entry protocol is unsupported")
)

type Warning struct {
	SubscriptionID string `json:"subscription_id"`
	Entry          int    `json:"entry"`
	Code           string `json:"code"`
	Message        string `json:"message"`
}

type ParseResult struct {
	Format    domain.SubscriptionFormat `json:"format"`
	Endpoints []domain.Endpoint         `json:"endpoints"`
	Warnings  []Warning                 `json:"warnings,omitempty"`
}

func Parse(subscriptionID string, document []byte) (ParseResult, error) {
	if !validSubscriptionID(subscriptionID) {
		return ParseResult{}, errors.New("subscription identifier is invalid")
	}
	if len(document) > MaxDocumentBytes {
		return ParseResult{}, errDocumentTooLarge
	}
	if !utf8.Valid(document) {
		return ParseResult{}, errMalformedDocument
	}
	content := bytes.TrimSpace(document)
	if len(content) == 0 {
		return ParseResult{}, errMalformedDocument
	}
	return parseDetected(subscriptionID, content, true)
}

func parseDetected(subscriptionID string, content []byte, allowBase64 bool) (ParseResult, error) {
	if content[0] == '{' {
		return finishResult(parseSingBox(subscriptionID, content))
	}
	if looksLikeClash(content) {
		return finishResult(parseClash(subscriptionID, content))
	}
	if looksLikeURIList(content) {
		return finishResult(parseURIList(subscriptionID, content))
	}
	if allowBase64 {
		if decoded, ok := decodeBase64Document(content); ok {
			result, err := parseDetected(subscriptionID, bytes.TrimSpace(decoded), false)
			if err != nil {
				return result, err
			}
			result.Format = domain.SubscriptionFormatBase64
			return result, nil
		}
	}
	return ParseResult{}, errMalformedDocument
}

func looksLikeURIList(content []byte) bool {
	return bytes.Contains(content, []byte("://"))
}

func looksLikeClash(content []byte) bool {
	trimmed := bytes.TrimSpace(content)
	return bytes.HasPrefix(trimmed, []byte("proxies:")) || bytes.Contains(trimmed, []byte("\nproxies:"))
}

func finishResult(result ParseResult, fatal error) (ParseResult, error) {
	if fatal != nil {
		return ParseResult{}, fatal
	}
	if len(result.Endpoints) == 0 {
		return result, errMalformedDocument
	}
	return result, nil
}

func addEndpoint(result *ParseResult, endpoint domain.Endpoint, subscriptionID string, entry int, seen map[string]struct{}) {
	endpoint.SubscriptionID = subscriptionID
	if endpoint.Name == "" {
		endpoint.Name = defaultEndpointName(endpoint.Protocol)
	}
	if err := normalizeEndpoint(&endpoint); err != nil {
		result.Warnings = append(result.Warnings, invalidWarning(subscriptionID, entry))
		return
	}
	id, err := endpointID(endpoint)
	if err != nil {
		result.Warnings = append(result.Warnings, invalidWarning(subscriptionID, entry))
		return
	}
	endpoint.ID = id
	if err := endpoint.Validate(); err != nil {
		result.Warnings = append(result.Warnings, invalidWarning(subscriptionID, entry))
		return
	}
	if _, duplicate := seen[endpoint.ID]; duplicate {
		return
	}
	seen[endpoint.ID] = struct{}{}
	result.Endpoints = append(result.Endpoints, endpoint)
}

func normalizeEndpoint(endpoint *domain.Endpoint) error {
	var err error
	if endpoint.Host, err = normalizeHost(endpoint.Host); err != nil {
		return err
	}
	endpoint.UUID = strings.ToLower(endpoint.UUID)
	if endpoint.TLS.ServerName, err = normalizeHost(endpoint.TLS.ServerName); err != nil {
		return err
	}
	if endpoint.Transport.Host, err = normalizeHost(endpoint.Transport.Host); err != nil {
		return err
	}
	return nil
}

func normalizeHost(host string) (string, error) {
	host = strings.TrimSuffix(host, ".")
	address, err := netip.ParseAddr(host)
	if err != nil {
		if strings.ContainsRune(host, '%') {
			return "", errInvalidEntry
		}
		return strings.ToLower(host), nil
	}
	if address.Zone() != "" {
		return "", errInvalidEntry
	}
	return address.Unmap().String(), nil
}

func defaultEndpointName(protocol domain.Protocol) string {
	switch protocol {
	case domain.ProtocolVLESS:
		return "VLESS endpoint"
	case domain.ProtocolVMess:
		return "VMess endpoint"
	case domain.ProtocolTrojan:
		return "Trojan endpoint"
	case domain.ProtocolShadowsocks:
		return "Shadowsocks endpoint"
	case domain.ProtocolHysteria2:
		return "Hysteria2 endpoint"
	case domain.ProtocolTUIC:
		return "TUIC endpoint"
	default:
		return "Proxy endpoint"
	}
}

func invalidWarning(subscriptionID string, entry int) Warning {
	return Warning{
		SubscriptionID: warningSubscriptionID(subscriptionID),
		Entry:          entry,
		Code:           "entry_skipped",
		Message:        fmt.Sprintf("entry %d was skipped because it is malformed or unsupported", entry),
	}
}

func oversizedWarning(subscriptionID string, entry int) Warning {
	return Warning{
		SubscriptionID: warningSubscriptionID(subscriptionID),
		Entry:          entry,
		Code:           "entry_too_large",
		Message:        fmt.Sprintf("entry %d was skipped because it exceeds the size limit", entry),
	}
}

func warningSubscriptionID(value string) string {
	if len(value) <= domain.MaxIDLength {
		safe := true
		for _, character := range value {
			if !isSafeIdentifierCharacter(character) {
				safe = false
				break
			}
		}
		if safe {
			return value
		}
	}
	digest := sha256.Sum256([]byte(value))
	return "subscription-" + hex.EncodeToString(digest[:8])
}

func isSafeIdentifierCharacter(character rune) bool {
	return character >= 'a' && character <= 'z' ||
		character >= 'A' && character <= 'Z' ||
		character >= '0' && character <= '9' ||
		character == '-' || character == '_' || character == '.'
}

func validSubscriptionID(value string) bool {
	if value == "" || strings.TrimSpace(value) == "" || len(value) > domain.MaxIDLength || !utf8.ValidString(value) {
		return false
	}
	for _, character := range value {
		if unicode.IsControl(character) {
			return false
		}
	}
	return true
}

func decodeBase64Document(content []byte) ([]byte, bool) {
	compact := make([]byte, 0, len(content))
	for _, character := range content {
		if character != ' ' && character != '\n' && character != '\r' && character != '\t' {
			compact = append(compact, character)
		}
	}
	decoded, ok := decodeBase64(compact)
	if !ok || len(bytes.TrimSpace(decoded)) == 0 || len(decoded) > MaxDocumentBytes || !utf8.Valid(decoded) {
		return nil, false
	}
	return decoded, true
}

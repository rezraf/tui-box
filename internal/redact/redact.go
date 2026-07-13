package redact

import (
	"errors"
	"net/netip"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

const (
	redacted          = "[redacted]"
	redactedAddress   = "[redacted-address]"
	redactedShareLink = "[redacted-share-link]"
	redactedURL       = "[redacted-url]"
	redactedUUID      = "[redacted-uuid]"
)

var (
	shareLinkPattern  = regexp.MustCompile(`(?i)\b(?:vless|vmess|trojan|ss|hysteria2|hy2|tuic)://[^\s"'<>]*[^\s"'<>.,;!?)}\]]`)
	webURLPattern     = regexp.MustCompile(`(?i)\bhttps?://[^\s"'<>]*[^\s"'<>.,;!?)}\]]`)
	credentialPattern = regexp.MustCompile(
		`(?i)\b(?:password|passwd|pwd|token|api[_-]?key|secret|authorization)\s*[:=]\s*(?:"[^"]*"|'[^']*'|[^\s,;]+)`,
	)
	jsonCredentialPattern = regexp.MustCompile(
		`(?i)"(?:password|passwd|pwd|token|api[_-]?key|secret|authorization)"\s*:\s*"(?:\\.|[^"\\])*"`,
	)
	bearerPattern         = regexp.MustCompile(`(?i)\bBearer\s+[^\s,;]+`)
	bracketAddressPattern = regexp.MustCompile(`\[[0-9A-Fa-f:.]+(?:%[A-Za-z0-9_.-]+)?\](?::[0-9]{1,5})?`)
	ipv6CandidatePattern  = regexp.MustCompile(`(?:[0-9A-Fa-f]{0,4}:){2,}[0-9A-Fa-f:.]*(?:%[A-Za-z0-9_.-]+)?`)
	hostPortPattern       = regexp.MustCompile(`(?i)\b[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?:[0-9]{1,5}\b`)
	ipv4Pattern           = regexp.MustCompile(`\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b`)
	uuidPattern           = regexp.MustCompile(`(?i)\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b`)
	tokenLikePattern      = regexp.MustCompile(`(?i)\b[0-9a-f]{24,}\b`)
)

// String removes common secret, URL, identifier, and endpoint-address forms.
func String(value string) string {
	value = shareLinkPattern.ReplaceAllString(value, redactedShareLink)
	value = webURLPattern.ReplaceAllString(value, redactedURL)
	value = jsonCredentialPattern.ReplaceAllString(value, redacted)
	value = bearerPattern.ReplaceAllString(value, redacted)
	value = credentialPattern.ReplaceAllString(value, redacted)
	value = bracketAddressPattern.ReplaceAllStringFunc(value, redactBracketAddress)
	value = redactIPv6(value)
	value = hostPortPattern.ReplaceAllStringFunc(value, redactHostPort)
	value = ipv4Pattern.ReplaceAllString(value, redactedAddress)
	value = uuidPattern.ReplaceAllString(value, redactedUUID)
	return tokenLikePattern.ReplaceAllString(value, redacted)
}

func redactBracketAddress(value string) string {
	if strings.Contains(value, "]:") {
		if address, err := netip.ParseAddrPort(value); err == nil && address.Addr().Is6() {
			return redactedAddress
		}
		return value
	}

	address, err := netip.ParseAddr(strings.TrimSuffix(strings.TrimPrefix(value, "["), "]"))
	if err == nil && address.Is6() {
		return redactedAddress
	}
	return value
}

func redactHostPort(value string) string {
	host, portText, found := strings.Cut(value, ":")
	port, err := strconv.Atoi(portText)
	if !found || err != nil || port < 0 || port > 65535 || !isHostnameOrIPv4(host) {
		return value
	}
	return redactedAddress
}

func isHostnameOrIPv4(host string) bool {
	if address, err := netip.ParseAddr(host); err == nil {
		return address.Is4()
	}
	if len(host) == 0 || len(host) > 253 || strings.IndexFunc(host, func(character rune) bool {
		return character < '0' || character > '9'
	}) == -1 {
		return false
	}
	for _, label := range strings.Split(host, ".") {
		if len(label) == 0 || len(label) > 63 || !isAlphaNumeric(label[0]) || !isAlphaNumeric(label[len(label)-1]) {
			return false
		}
		for index := 1; index < len(label)-1; index++ {
			if !isAlphaNumeric(label[index]) && label[index] != '-' {
				return false
			}
		}
	}
	return true
}

func isAlphaNumeric(value byte) bool {
	return value >= '0' && value <= '9' || value >= 'A' && value <= 'Z' || value >= 'a' && value <= 'z'
}

func redactIPv6(value string) string {
	matches := ipv6CandidatePattern.FindAllStringIndex(value, -1)
	if len(matches) == 0 {
		return value
	}

	var result strings.Builder
	result.Grow(len(value))
	last := 0
	for _, match := range matches {
		start, end := match[0], match[1]
		candidate := strings.TrimRight(value[start:end], ".,;!?")
		candidateEnd := start + len(candidate)
		if candidate == "" || !isIPv6(candidate) || hasAddressNeighbor(value, start, end) {
			continue
		}

		result.WriteString(value[last:start])
		result.WriteString(redactedAddress)
		result.WriteString(value[candidateEnd:end])
		last = end
	}
	result.WriteString(value[last:])
	return result.String()
}

func isIPv6(value string) bool {
	address, err := netip.ParseAddr(value)
	return err == nil && address.Is6()
}

func hasAddressNeighbor(value string, start, end int) bool {
	return start > 0 && isAddressByte(value[start-1]) || end < len(value) && isAddressByte(value[end])
}

func isAddressByte(value byte) bool {
	return value >= '0' && value <= '9' || value >= 'A' && value <= 'Z' || value >= 'a' && value <= 'z' || strings.ContainsRune("_.%-", rune(value))
}

// StringSensitive also removes exact values known by the caller.
func StringSensitive(value string, sensitive ...string) string {
	value = String(value)
	values := uniqueNonempty(sensitive)
	sort.Slice(values, func(left, right int) bool {
		if len(values[left]) == len(values[right]) {
			return values[left] < values[right]
		}
		return len(values[left]) > len(values[right])
	})
	for _, secret := range values {
		value = strings.ReplaceAll(value, secret, redacted)
	}
	return value
}

// Error returns an error with no link to the potentially sensitive source error.
func Error(err error, sensitive ...string) error {
	if err == nil {
		return nil
	}
	return errors.New(StringSensitive(err.Error(), sensitive...))
}

func uniqueNonempty(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	result := make([]string, 0, len(values))
	for _, value := range values {
		if value == "" {
			continue
		}
		if _, exists := seen[value]; exists {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	return result
}

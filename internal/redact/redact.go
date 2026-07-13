package redact

import (
	"errors"
	"regexp"
	"sort"
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
	shareLinkPattern  = regexp.MustCompile(`(?i)\b(?:vless|vmess|trojan|ss|hysteria2|hy2|tuic)://[^\s"'<>]+`)
	webURLPattern     = regexp.MustCompile(`(?i)\bhttps?://[^\s"'<>]+`)
	credentialPattern = regexp.MustCompile(
		`(?i)\b(?:password|passwd|pwd|token|api[_-]?key|secret|authorization)\s*[:=]\s*(?:"[^"]*"|'[^']*'|[^\s,;]+)`,
	)
	bearerPattern    = regexp.MustCompile(`(?i)\bBearer\s+[^\s,;]+`)
	bracketAddress   = regexp.MustCompile(`\[[0-9A-Fa-f:.%]+\]:[0-9]{1,5}`)
	hostPortPattern  = regexp.MustCompile(`(?i)\b(?:[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?|[a-z0-9]):[0-9]{1,5}\b`)
	ipv4Pattern      = regexp.MustCompile(`\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b`)
	uuidPattern      = regexp.MustCompile(`(?i)\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b`)
	tokenLikePattern = regexp.MustCompile(`\b(?:[A-Fa-f0-9]{24,}|[A-Za-z0-9_-]{24,})\b`)
)

// String removes common secret, URL, identifier, and endpoint-address forms.
func String(value string) string {
	value = shareLinkPattern.ReplaceAllString(value, redactedShareLink)
	value = webURLPattern.ReplaceAllString(value, redactedURL)
	value = credentialPattern.ReplaceAllString(value, redacted)
	value = bearerPattern.ReplaceAllString(value, redacted)
	value = bracketAddress.ReplaceAllString(value, redactedAddress)
	value = hostPortPattern.ReplaceAllString(value, redactedAddress)
	value = ipv4Pattern.ReplaceAllString(value, redactedAddress)
	value = uuidPattern.ReplaceAllString(value, redactedUUID)
	return tokenLikePattern.ReplaceAllString(value, redacted)
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

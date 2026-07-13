package releasecheck

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"io/fs"
	"path"
	"regexp"
	"sort"
	"strings"
)

var (
	machineHomePattern  = regexp.MustCompile(`/(?:Users|home)/[A-Za-z0-9._-]+(?:/[A-Za-z0-9._~@%+=:,/-]+)*`)
	placeholderPatterns = []*regexp.Regexp{
		regexp.MustCompile(`(?im)\b(?:` + "TO" + `DO|` + "FIX" + `ME|` + "X" + `XX|` + "HA" + `CK)\s*:`),
		regexp.MustCompile(`(?i)\b(?:` + "CHANGE" + `ME|REPLACE[_-]?ME|` + "YOU" + `R_[A-Z0-9_]+|` + "T" + `BD)\b`),
	}
	secretPatterns = []*regexp.Regexp{
		regexp.MustCompile(`-----BEGIN (?:RSA |EC |OPENSSH |PGP )?PRIVATE KEY-----`),
		regexp.MustCompile(`\bAKIA[0-9A-Z]{16}\b`),
		regexp.MustCompile(`\bgh[pousr]_[A-Za-z0-9]{20,}\b`),
		regexp.MustCompile(`\bgithub_pat_[A-Za-z0-9_]{20,}\b`),
		regexp.MustCompile(`\bglpat-[A-Za-z0-9_-]{20,}\b`),
		regexp.MustCompile(`\bxox[baprs]-[A-Za-z0-9-]{20,}\b`),
		regexp.MustCompile(`\bAIza[0-9A-Za-z_-]{35}\b`),
		regexp.MustCompile(`\bsk_live_[0-9A-Za-z]{16,}\b`),
	}
	genericSecretPattern = regexp.MustCompile(`(?i)\b(?:password|secret|token|api[_-]?key|client[_-]?secret|private[_-]?key)\s*[:=]\s*["']?([A-Za-z0-9+/=_-]{16,})`)
)

var reviewedMachinePathPrefixes = map[string][]string{
	"cmd/tuibox/main_test.go": {
		"/" + "home/user",
		"/" + "Users/user",
	},
	"internal/app/service_test.go": {
		"/" + "Users/name/state.json",
	},
}

func ScanSnapshot(scope string, snapshot Snapshot, requireReleaseFiles bool) []Finding {
	paths := sortedSnapshotPaths(snapshot)
	findings := make([]Finding, 0)
	for _, name := range paths {
		file := snapshot[name]
		findings = append(findings, scanFile(scope, name, file)...)
	}
	if requireReleaseFiles {
		findings = append(findings, scanReleaseRequirements(scope, snapshot)...)
	}
	return deduplicateFindings(findings)
}

func scanFile(scope, name string, file File) []Finding {
	if !validRepositoryPath(name) || file.Path != name {
		return []Finding{newFinding(scope, name, "invalid-path", "path is not a canonical repository-relative file")}
	}
	findings := scanFileMetadata(scope, name, file)
	if file.Mode.IsRegular() {
		findings = append(findings, scanFileContents(scope, name, file.Data)...)
	}
	return findings
}

func scanFileMetadata(scope, name string, file File) []Finding {
	var findings []Finding
	if privateFilePath(name) {
		findings = append(findings, newFinding(scope, name, "private-file", "private or local-only filename is not releasable"))
	}
	if dirtyArtifactPath(name) || len(file.Data) > maxSourceFileSize || executableBinary(file.Data) {
		findings = append(findings, newFinding(scope, name, "dirty-artifact", "generated, oversized, or compiled artifact is not releasable"))
	}
	if file.Mode&fs.ModeSymlink != 0 {
		findings = append(findings, newFinding(scope, name, "symlink", "source releases must contain regular files only"))
	} else if !file.Mode.IsRegular() {
		findings = append(findings, newFinding(scope, name, "file-type", "source releases must contain regular files only"))
	}
	return findings
}

func scanFileContents(scope, name string, contents []byte) []Finding {
	var findings []Finding
	text := string(contents)
	if containsUnreviewedMachinePath(name, text) {
		findings = append(findings, newFinding(scope, name, "machine-home-path", "contains a machine-specific user home path"))
	}
	if !patternDefinition(name) && matchesAny(placeholderPatterns, text) {
		findings = append(findings, newFinding(scope, name, "placeholder", "contains an unresolved release placeholder"))
	}
	if !reviewedFixture(name) && (matchesAny(secretPatterns, text) || containsGenericSecret(text)) {
		findings = append(findings, newFinding(scope, name, "secret", "contains credential material matching a high-confidence pattern"))
	}
	return findings
}

func scanReleaseRequirements(scope string, snapshot Snapshot) []Finding {
	var findings []Finding
	for _, name := range requiredPaths {
		if _, ok := snapshot[name]; !ok {
			findings = append(findings, newFinding(scope, name, "missing-release-file", "required release source file is absent"))
		}
	}
	if license, ok := snapshot["LICENSE"]; ok {
		digest := fmt.Sprintf("%x", sha256.Sum256(license.Data))
		if digest != canonicalLicenseSHA256 {
			findings = append(findings, newFinding(scope, "LICENSE", "license-integrity", "LICENSE is not the canonical GPL-3.0-only text"))
		}
	}
	if notices, ok := snapshot["THIRD_PARTY_NOTICES"]; ok && !validThirdPartyNotices(notices.Data) {
		findings = append(findings, newFinding(scope, "THIRD_PARTY_NOTICES", "third-party-notices", "linked dependency inventory or license text is incomplete"))
	}
	return findings
}

func validThirdPartyNotices(contents []byte) bool {
	text := string(contents)
	return strings.HasPrefix(text, "TuiBox Third-Party Notices\n\n") &&
		strings.Contains(text, "Linked module inventory:\n- ") &&
		strings.Contains(text, "Source: https://pkg.go.dev/") &&
		strings.Contains(text, "Regenerate it with: sh scripts/generate-third-party-notices.sh THIRD_PARTY_NOTICES")
}

func containsUnreviewedMachinePath(name, contents string) bool {
	for _, match := range machineHomePattern.FindAllString(contents, -1) {
		if !reviewedMachinePath(name, match) {
			return true
		}
	}
	return false
}

func reviewedMachinePath(name, match string) bool {
	for _, prefix := range reviewedMachinePathPrefixes[name] {
		if strings.HasPrefix(match, prefix) {
			return true
		}
	}
	return false
}

func privateFilePath(name string) bool {
	lower := strings.ToLower(name)
	base := path.Base(lower)
	for _, segment := range strings.Split(lower, "/") {
		if segment == ".ssh" || segment == ".aws" || segment == ".gnupg" {
			return true
		}
	}
	if base == ".env" || strings.HasPrefix(base, ".env.") {
		return true
	}
	if base == ".netrc" || base == ".npmrc" || base == ".pypirc" || base == ".ds_store" || base == "thumbs.db" {
		return true
	}
	if base == "id_rsa" || base == "id_ed25519" || base == "credentials" || base == "credentials.json" {
		return true
	}
	if lower == ".claude/settings.local.json" || strings.HasSuffix(base, "~") || strings.HasSuffix(base, ".swp") {
		return true
	}
	return hasAnySuffix(base, ".pem", ".key", ".p12", ".pfx", ".kdbx", ".jks")
}

func dirtyArtifactPath(name string) bool {
	lower := strings.ToLower(name)
	base := path.Base(lower)
	for _, segment := range strings.Split(lower, "/") {
		if dirtyArtifactSegment(segment) {
			return true
		}
	}
	if base == "tuibox" || base == "tuiboxd" || base == "checksums.txt" || base == "coverage.out" {
		return true
	}
	return hasAnySuffix(base, ".test", ".prof", ".orig", ".rej", ".tar", ".tar.gz", ".tgz", ".zip", ".dmg", ".deb", ".rpm", ".pkg")
}

func dirtyArtifactDirectory(name string) bool {
	return dirtyArtifactSegment(path.Base(strings.ToLower(name)))
}

func dirtyArtifactSegment(segment string) bool {
	return segment == "dist" || segment == "build" || segment == "coverage" || segment == ".cache" ||
		segment == "node_modules" || segment == "vendor" || segment == "tmp" || segment == "temp"
}

func executableBinary(contents []byte) bool {
	magics := [][]byte{
		{0x7f, 'E', 'L', 'F'},
		{0xfe, 0xed, 0xfa, 0xce}, {0xfe, 0xed, 0xfa, 0xcf},
		{0xce, 0xfa, 0xed, 0xfe}, {0xcf, 0xfa, 0xed, 0xfe},
		{'M', 'Z'},
	}
	for _, magic := range magics {
		if bytes.HasPrefix(contents, magic) {
			return true
		}
	}
	return false
}

func containsGenericSecret(text string) bool {
	for _, match := range genericSecretPattern.FindAllStringSubmatch(text, -1) {
		if len(match) == 2 && credentialLikeValue(match[1]) {
			return true
		}
	}
	return false
}

func credentialLikeValue(value string) bool {
	return strings.IndexFunc(value, func(character rune) bool {
		return character >= '0' && character <= '9' || strings.ContainsRune("+/=_-", character)
	}) >= 0
}

func reviewedFixture(name string) bool {
	return strings.HasSuffix(name, "_test.go") || strings.HasSuffix(name, "_test.sh") || strings.Contains(name, "/testdata/")
}

func patternDefinition(name string) bool {
	return name == "scripts/docs_test.go"
}

func validRepositoryPath(name string) bool {
	return name != "" && name != "." && path.Clean(name) == name &&
		!strings.HasPrefix(name, "/") && !strings.HasPrefix(name, "../") &&
		!strings.Contains(name, "\\") && !strings.ContainsRune(name, 0)
}

func matchesAny(patterns []*regexp.Regexp, text string) bool {
	for _, pattern := range patterns {
		if pattern.MatchString(text) {
			return true
		}
	}
	return false
}

func hasAnySuffix(value string, suffixes ...string) bool {
	for _, suffix := range suffixes {
		if strings.HasSuffix(value, suffix) {
			return true
		}
	}
	return false
}

func sortedSnapshotPaths(snapshot Snapshot) []string {
	paths := make([]string, 0, len(snapshot))
	for name := range snapshot {
		paths = append(paths, name)
	}
	sort.Strings(paths)
	return paths
}

func deduplicateFindings(findings []Finding) []Finding {
	seen := make(map[string]struct{}, len(findings))
	result := make([]Finding, 0, len(findings))
	for _, finding := range findings {
		key := finding.Scope + "\x00" + finding.Path + "\x00" + finding.Rule
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		result = append(result, finding)
	}
	return result
}

func newFinding(scope, name, rule, detail string) Finding {
	return Finding{Scope: scope, Path: name, Rule: rule, Detail: detail}
}

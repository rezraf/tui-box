package scripts

import (
	"crypto/sha256"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
)

var documentationFiles = []string{
	"README.md",
	"SECURITY.md",
	"CONTRIBUTING.md",
	"CODE_OF_CONDUCT.md",
	"docs/architecture.md",
	"docs/security-model.md",
	"docs/telemetry.md",
	".github/pull_request_template.md",
}

func TestDocumentationCLICommandsMatchHelp(t *testing.T) {
	repository := repositoryRoot(t)
	binary := buildDocumentationCLI(t, repository)
	rootHelp := runDocumentationHelp(t, binary)

	wantTopLevel := []string{
		"completion", "connect", "disconnect", "doctor", "help", "server",
		"status", "subscription", "telemetry", "update", "version",
	}
	if got := availableCommands(rootHelp); !slices.Equal(got, wantTopLevel) {
		t.Fatalf("top-level help commands = %v, want %v", got, wantTopLevel)
	}

	commandPaths := [][]string{
		{"subscription"}, {"subscription", "add"}, {"subscription", "list"},
		{"subscription", "update"}, {"subscription", "remove"},
		{"server"}, {"server", "list"}, {"server", "latency"},
		{"connect"}, {"disconnect"}, {"status"},
		{"telemetry"}, {"telemetry", "enable"}, {"telemetry", "disable"}, {"telemetry", "status"},
		{"doctor"}, {"update"}, {"version"}, {"completion"},
		{"completion", "bash"}, {"completion", "fish"}, {"completion", "powershell"}, {"completion", "zsh"},
	}
	for _, path := range commandPaths {
		t.Run(strings.Join(path, "_"), func(t *testing.T) {
			runDocumentationHelp(t, binary, path...)
		})
	}

	readme := readDocumentationFile(t, repository, "README.md")
	for _, command := range []string{
		"tuibox subscription add <name> <url>",
		"tuibox subscription list",
		"tuibox subscription update [id]",
		"tuibox subscription remove <id>",
		"tuibox server list",
		"tuibox server latency <id>",
		"tuibox server latency --all",
		"tuibox connect <endpoint-id|auto> --mode tun|proxy --route global|rule|direct",
		"tuibox disconnect",
		"tuibox status",
		"tuibox telemetry enable",
		"tuibox telemetry disable",
		"tuibox telemetry status",
		"tuibox doctor",
		"tuibox update --check",
		"tuibox update",
		"tuibox version",
		"tuibox completion bash|fish|powershell|zsh",
	} {
		if !strings.Contains(readme, command) {
			t.Errorf("README.md does not document %q", command)
		}
	}
}

func TestDocumentationLocalLinksAndRequiredPaths(t *testing.T) {
	repository := repositoryRoot(t)
	required := append([]string{
		"LICENSE",
		".github/ISSUE_TEMPLATE/bug_report.yml",
		".github/ISSUE_TEMPLATE/feature_request.yml",
		".github/ISSUE_TEMPLATE/config.yml",
	}, documentationFiles...)
	for _, name := range required {
		assertRegularDocumentationFile(t, filepath.Join(repository, name))
	}

	linkPattern := regexp.MustCompile(`\[[^]]+\]\(([^)]+)\)`)
	for _, name := range documentationFiles {
		contents := readDocumentationFile(t, repository, name)
		for _, match := range linkPattern.FindAllStringSubmatch(contents, -1) {
			target := strings.TrimSpace(match[1])
			if externalOrAnchor(target) {
				continue
			}
			target = strings.SplitN(target, "#", 2)[0]
			target = strings.SplitN(target, "?", 2)[0]
			resolved := filepath.Clean(filepath.Join(repository, filepath.Dir(name), filepath.FromSlash(target)))
			if resolved != repository && !strings.HasPrefix(resolved, repository+string(filepath.Separator)) {
				t.Errorf("%s link escapes repository: %q", name, match[1])
				continue
			}
			assertRegularDocumentationFile(t, resolved)
		}
	}
}

func TestDocumentationCanonicalGPL3OnlyLicense(t *testing.T) {
	repository := repositoryRoot(t)
	license := readDocumentationFile(t, repository, "LICENSE")
	digest := fmt.Sprintf("%x", sha256.Sum256([]byte(license)))
	const canonicalDigest = "3972dc9744f6499f0f9b2dbf76696f2ae7ad8af9b23dde66d6af86c9dfb36986"
	if digest != canonicalDigest {
		t.Fatalf("LICENSE SHA-256 = %s, want canonical GPL-3.0 digest %s", digest, canonicalDigest)
	}
	readme := readDocumentationFile(t, repository, "README.md")
	if !strings.Contains(readme, "SPDX identifier `GPL-3.0-only`") {
		t.Fatal("README.md does not declare SPDX identifier GPL-3.0-only")
	}
}

func TestDocumentationContainsNoPlaceholdersOrLikelySecrets(t *testing.T) {
	repository := repositoryRoot(t)
	files := append([]string{}, documentationFiles...)
	files = append(files,
		".github/ISSUE_TEMPLATE/bug_report.yml",
		".github/ISSUE_TEMPLATE/feature_request.yml",
		".github/ISSUE_TEMPLATE/config.yml",
	)
	placeholder := regexp.MustCompile(`(?i)\b(?:TODO|CHANGEME|YOUR_[A-Z0-9_]*)\b`)
	secretPatterns := []*regexp.Regexp{
		regexp.MustCompile(`-----BEGIN (?:RSA |EC |OPENSSH |PGP )?PRIVATE KEY-----`),
		regexp.MustCompile(`\bAKIA[0-9A-Z]{16}\b`),
		regexp.MustCompile(`\bgh[pousr]_[A-Za-z0-9]{20,}\b`),
		regexp.MustCompile(`\bgithub_pat_[A-Za-z0-9_]{20,}\b`),
		regexp.MustCompile(`\bxox[baprs]-[A-Za-z0-9-]{20,}\b`),
		regexp.MustCompile(`(?i)\b(?:password|secret|token|api[_-]?key)\s*[:=]\s*["']?[A-Za-z0-9+/=_-]{12,}`),
	}

	for _, name := range files {
		contents := readDocumentationFile(t, repository, name)
		if match := placeholder.FindString(contents); match != "" {
			t.Errorf("%s contains placeholder %q", name, match)
		}
		for _, pattern := range secretPatterns {
			if match := pattern.FindString(contents); match != "" {
				t.Errorf("%s contains likely secret matching %q", name, match)
			}
		}
	}
}

func repositoryRoot(t *testing.T) string {
	t.Helper()
	root, err := filepath.Abs("..")
	if err != nil {
		t.Fatalf("resolve repository root: %v", err)
	}
	return root
}

func buildDocumentationCLI(t *testing.T, repository string) string {
	t.Helper()
	binary := filepath.Join(t.TempDir(), "tuibox")
	command := exec.Command("go", "build", "-o", binary, "./cmd/tuibox")
	command.Dir = repository
	command.Env = append(os.Environ(), "CGO_ENABLED=0")
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("build documentation CLI: %v\n%s", err, output)
	}
	return binary
}

func runDocumentationHelp(t *testing.T, binary string, path ...string) string {
	t.Helper()
	arguments := append(append([]string{}, path...), "--help")
	command := exec.Command(binary, arguments...)
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("%s help failed: %v\n%s", strings.Join(path, " "), err, output)
	}
	return string(output)
}

func availableCommands(help string) []string {
	lines := strings.Split(help, "\n")
	inside := false
	var names []string
	for _, line := range lines {
		if line == "Available Commands:" {
			inside = true
			continue
		}
		if !inside {
			continue
		}
		if strings.TrimSpace(line) == "" {
			break
		}
		fields := strings.Fields(line)
		if len(fields) >= 2 {
			names = append(names, fields[0])
		}
	}
	return names
}

func readDocumentationFile(t *testing.T, repository, name string) string {
	t.Helper()
	contents, err := os.ReadFile(filepath.Join(repository, name))
	if err != nil {
		t.Fatalf("read %s: %v", name, err)
	}
	return string(contents)
}

func assertRegularDocumentationFile(t *testing.T, path string) {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Errorf("documentation path %s: %v", path, err)
		return
	}
	if !info.Mode().IsRegular() {
		t.Errorf("documentation path is not a regular file: %s", path)
	}
}

func externalOrAnchor(target string) bool {
	lower := strings.ToLower(target)
	return strings.HasPrefix(target, "#") || strings.HasPrefix(lower, "http://") ||
		strings.HasPrefix(lower, "https://") || strings.HasPrefix(lower, "mailto:")
}

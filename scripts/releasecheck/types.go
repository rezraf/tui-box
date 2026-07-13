package releasecheck

import (
	"fmt"
	"io/fs"
)

const (
	canonicalLicenseSHA256 = "3972dc9744f6499f0f9b2dbf76696f2ae7ad8af9b23dde66d6af86c9dfb36986"
	maxSourceFileSize      = 8 << 20
	maxSourceArchiveSize   = 64 << 20
)

var requiredPaths = []string{
	".github/release.yml",
	".github/workflows/ci.yml",
	".github/workflows/release.yml",
	".goreleaser.yml",
	"CODE_OF_CONDUCT.md",
	"CONTRIBUTING.md",
	"LICENSE",
	"README.md",
	"SECURITY.md",
	"THIRD_PARTY_NOTICES",
	"cmd/tuibox/main.go",
	"cmd/tuiboxd/main.go",
	"go.mod",
	"go.sum",
	"install.sh",
	"packaging/launchd/io.github.rezraf.tuiboxd.plist",
	"packaging/systemd/tuiboxd.service",
	"scripts/cmd/release-source/main.go",
	"scripts/generate-third-party-notices.sh",
	"scripts/release_snapshot_test.sh",
	"scripts/stable-release.sh",
	"uninstall.sh",
}

type File struct {
	Path string
	Mode fs.FileMode
	Data []byte
}

type Snapshot map[string]File

type Finding struct {
	Scope  string
	Path   string
	Rule   string
	Detail string
}

func (finding Finding) String() string {
	if finding.Path == "" {
		return fmt.Sprintf("%s: %s: %s", finding.Scope, finding.Rule, finding.Detail)
	}
	return fmt.Sprintf("%s: %s: %s: %s", finding.Scope, finding.Path, finding.Rule, finding.Detail)
}

type Report struct {
	TrackedFiles int
	ArchiveFiles int
	Findings     []Finding
}

func RequiredPaths() []string {
	paths := make([]string, len(requiredPaths))
	copy(paths, requiredPaths)
	return paths
}

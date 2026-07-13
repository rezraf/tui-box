package releasecheck

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestScanSnapshotAcceptsReviewedReleaseSource(t *testing.T) {
	files := releaseFixture(t)
	files["cmd/tuibox/main_test.go"] = regularFile(
		"cmd/tuibox/main_test.go",
		"home := \"/"+"home/user\"\nmacHome := \"/"+"Users/user\"\n",
	)

	if findings := ScanSnapshot("archive", files, true); len(findings) != 0 {
		t.Fatalf("reviewed release source findings = %v, want none", findings)
	}
}

func TestScanSnapshotRejectsMachineHomePathsOutsideReviewedFixtures(t *testing.T) {
	for _, value := range []string{
		"worktree: /" + "Users/alice/project\n",
		"cache: /" + "home/alice/.cache/tuibox\n",
	} {
		files := releaseFixture(t)
		files["HANDOFF.md"] = regularFile("HANDOFF.md", value)

		assertFinding(t, ScanSnapshot("tracked", files, false), "machine-home-path", "HANDOFF.md")
	}
}

func TestScanSnapshotRejectsAccidentalPrivateFiles(t *testing.T) {
	for _, path := range []string{".env.production", "id_ed25519", "notes.txt~"} {
		files := releaseFixture(t)
		files[path] = regularFile(path, "private\n")

		assertFinding(t, ScanSnapshot("archive", files, true), "private-file", path)
	}
}

func TestScanSnapshotRejectsUnresolvedPlaceholders(t *testing.T) {
	files := releaseFixture(t)
	files["README.md"] = regularFile("README.md", "release owner: CHANGE"+"ME\n")

	assertFinding(t, ScanSnapshot("archive", files, true), "placeholder", "README.md")
}

func TestScanSnapshotRejectsRealSecrets(t *testing.T) {
	files := releaseFixture(t)
	secret := "github" + "_pat_" + strings.Repeat("A", 32)
	files["config.txt"] = regularFile("config.txt", "token="+secret+"\n")

	assertFinding(t, ScanSnapshot("archive", files, true), "secret", "config.txt")
}

func TestScanSnapshotRejectsDirtyReleaseArtifacts(t *testing.T) {
	for _, path := range []string{"dist/tuibox_linux_arm64.tar.gz", "coverage.out", "tuibox"} {
		files := releaseFixture(t)
		contents := "artifact\n"
		if path == "tuibox" {
			contents = "\x7fELFdirty-binary"
		}
		files[path] = regularFile(path, contents)

		assertFinding(t, ScanSnapshot("archive", files, true), "dirty-artifact", path)
	}
}

func TestScanSnapshotRequiresEveryReleaseCriticalFile(t *testing.T) {
	for _, path := range RequiredPaths() {
		files := releaseFixture(t)
		delete(files, path)

		assertFinding(t, ScanSnapshot("archive", files, true), "missing-release-file", path)
	}
}

func TestScanSnapshotRequiresCanonicalLicense(t *testing.T) {
	files := releaseFixture(t)
	files["LICENSE"] = regularFile("LICENSE", "not the project license\n")

	assertFinding(t, ScanSnapshot("archive", files, true), "license-integrity", "LICENSE")
}

func TestScanSnapshotRequiresGeneratedThirdPartyInventory(t *testing.T) {
	files := releaseFixture(t)
	files["THIRD_PARTY_NOTICES"] = regularFile("THIRD_PARTY_NOTICES", "TuiBox Third-Party Notices\n")

	assertFinding(t, ScanSnapshot("archive", files, true), "third-party-notices", "THIRD_PARTY_NOTICES")
}

func TestSourceArchiveRoundTripPreservesExactFiles(t *testing.T) {
	files := Snapshot{
		"README.md": regularFile("README.md", "read me\n"),
		"install.sh": {
			Path: "install.sh",
			Mode: 0o755,
			Data: []byte("#!/bin/sh\nexit 0\n"),
		},
	}

	archive, err := CreateSourceArchive(files)
	if err != nil {
		t.Fatalf("create source archive: %v", err)
	}
	got, err := ReadSourceArchive(archive)
	if err != nil {
		t.Fatalf("read source archive: %v", err)
	}
	if err := EqualSnapshots(files, got); err != nil {
		t.Fatalf("archive differs from source snapshot: %v", err)
	}
}

func TestScanSnapshotRejectsSymlinks(t *testing.T) {
	files := releaseFixture(t)
	files["LICENSE-link"] = File{
		Path: "LICENSE-link",
		Mode: fs.ModeSymlink | 0o777,
		Data: []byte("LICENSE"),
	}

	assertFinding(t, ScanSnapshot("archive", files, true), "symlink", "LICENSE-link")
}

func TestScanSnapshotAcceptsCredentialFieldIdentifiers(t *testing.T) {
	files := releaseFixture(t)
	files["internal/subscription/uri.go"] = regularFile(
		"internal/subscription/uri.go",
		"Password: combinedUserInfo(parsed.User),\n",
	)

	assertNoFinding(t, ScanSnapshot("archive", files, true), "secret", "internal/subscription/uri.go")
}

func TestWorkspaceScanAcceptsCommandSourceDirectories(t *testing.T) {
	root := t.TempDir()
	for _, directory := range []string{"cmd/tuibox", "cmd/tuiboxd"} {
		if err := os.MkdirAll(filepath.Join(root, directory), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(root, directory, "main.go"), []byte("package main\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	findings, err := scanWorkspaceArtifacts(root)
	if err != nil {
		t.Fatal(err)
	}
	assertNoFinding(t, findings, "dirty-artifact", "cmd/tuibox")
	assertNoFinding(t, findings, "dirty-artifact", "cmd/tuiboxd")
}

func releaseFixture(t *testing.T) Snapshot {
	t.Helper()
	repository := filepath.Clean(filepath.Join("..", ".."))
	files := make(Snapshot, len(RequiredPaths()))
	for _, path := range RequiredPaths() {
		contents, err := os.ReadFile(filepath.Join(repository, filepath.FromSlash(path)))
		if err != nil {
			t.Fatalf("read release fixture %s: %v", path, err)
		}
		info, err := os.Stat(filepath.Join(repository, filepath.FromSlash(path)))
		if err != nil {
			t.Fatalf("stat release fixture %s: %v", path, err)
		}
		files[path] = File{Path: path, Mode: info.Mode(), Data: contents}
	}
	return files
}

func regularFile(path, contents string) File {
	return File{Path: path, Mode: 0o644, Data: []byte(contents)}
}

func assertFinding(t *testing.T, findings []Finding, rule, path string) {
	t.Helper()
	for _, finding := range findings {
		if finding.Rule == rule && finding.Path == path {
			return
		}
	}
	t.Fatalf("findings = %v, want rule %q for %q", findings, rule, path)
}

func assertNoFinding(t *testing.T, findings []Finding, rule, path string) {
	t.Helper()
	for _, finding := range findings {
		if finding.Rule == rule && finding.Path == path {
			t.Fatalf("unexpected finding: %v", finding)
		}
	}
}

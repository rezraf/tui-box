package scripts

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

func TestWorkflowsPinActionsAndAvoidPersistedCheckoutCredentials(t *testing.T) {
	repository := repositoryRoot(t)
	for _, name := range []string{".github/workflows/ci.yml", ".github/workflows/release.yml"} {
		contents := readWorkflow(t, repository, name)
		for _, match := range regexp.MustCompile(`(?m)^\s*uses:\s*([^\s#]+)`).FindAllStringSubmatch(contents, -1) {
			parts := strings.Split(match[1], "@")
			if len(parts) != 2 || !regexp.MustCompile(`^[0-9a-f]{40}$`).MatchString(parts[1]) {
				t.Errorf("%s uses mutable action reference %q", name, match[1])
			}
		}
		checkoutCount := strings.Count(contents, "uses: actions/checkout@")
		if checkoutCount == 0 || strings.Count(contents, "persist-credentials: false") != checkoutCount {
			t.Errorf("%s checkout steps do not all disable persisted credentials", name)
		}
		if strings.Contains(contents, "pull_request_target:") {
			t.Errorf("%s executes repository code through pull_request_target", name)
		}
	}
}

func TestReleaseWorkflowRequiresStableMainlineTag(t *testing.T) {
	contents := readWorkflow(t, repositoryRoot(t), ".github/workflows/release.yml")
	if strings.Contains(contents, "workflow_dispatch:") {
		t.Fatal("release workflow permits manual dispatch without an immutable release tag")
	}
	for _, required := range []string{
		`^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$`,
		`git merge-base --is-ancestor "$GITHUB_SHA" origin/main`,
	} {
		if !strings.Contains(contents, required) {
			t.Errorf("release workflow is missing validation %q", required)
		}
	}
}

func TestReleaseWorkflowSerializesAndRejectsVersionDowngrades(t *testing.T) {
	contents := readWorkflow(t, repositoryRoot(t), ".github/workflows/release.yml")
	for _, required := range []string{
		"concurrency:\n  group: release-publication\n  cancel-in-progress: false",
		`gh api --paginate "repos/$GITHUB_REPOSITORY/releases?per_page=100"`,
		`sh scripts/stable-release.sh require-newer "$GITHUB_REF_NAME"`,
	} {
		if !strings.Contains(contents, required) {
			t.Errorf("release workflow is missing monotonic publication control %q", required)
		}
	}
	assertOrdered(t, contents,
		"name: Validate stable mainline release tag",
		"name: Reject non-monotonic stable release tag",
		"name: Build and upload draft release",
	)
}

func TestReleasePublicationIsDraftAndAttestationGated(t *testing.T) {
	repository := repositoryRoot(t)
	workflow := readWorkflow(t, repository, ".github/workflows/release.yml")
	configuration := readWorkflow(t, repository, ".goreleaser.yml")
	for _, required := range []string{"draft: true", "replace_existing_draft: true", "prerelease: auto", "make_latest: false"} {
		if !strings.Contains(configuration, required) {
			t.Errorf("GoReleaser configuration is missing %q", required)
		}
	}
	if count := strings.Count(workflow, "uses: actions/attest-build-provenance@"); count != 2 {
		t.Fatalf("provenance attestation step count = %d, want 2", count)
	}
	assertOrdered(t, workflow,
		"name: Build and upload draft release",
		"name: Attest release archives",
		"subject-checksums: dist/checksums.txt",
		"name: Attest release checksums",
		"subject-path: dist/checksums.txt",
		"name: Verify release is still draft",
		"name: Publish attested release",
	)
	publish := strings.Index(workflow, "      - name: Publish attested release")
	if publish < 0 || publish != strings.LastIndex(workflow, "      - name: ") {
		t.Fatal("publishing the attested release is not the final workflow step")
	}
	for _, required := range []string{"--json isDraft", `test "$release_is_draft" = true`, "gh api --method PATCH", "-F draft=false", "-F prerelease=false", "-f make_latest=true"} {
		if !strings.Contains(workflow, required) {
			t.Errorf("release workflow is missing atomic publication guard %q", required)
		}
	}
}

func TestInstallerResolvesHighestPublishedStableRelease(t *testing.T) {
	contents := readWorkflow(t, repositoryRoot(t), "install.sh")
	if strings.Contains(contents, "releases/latest") {
		t.Fatal("installer still delegates version choice to GitHub releases/latest")
	}
	for _, required := range []string{
		`release_version=${TUIBOX_VERSION:-}`,
		`release_selector=$script_dir/scripts/stable-release.sh`,
		`https://api.github.com/repos/$repository/releases?per_page=100&page=$release_page`,
		`sh "$release_selector" highest "$release_metadata_pages"`,
		`release_base=https://github.com/$repository/releases/download/$release_version`,
	} {
		if !strings.Contains(contents, required) {
			t.Errorf("installer is missing stable release resolution contract %q", required)
		}
	}
	assertOrdered(t, contents,
		`if test -z "$release_version"; then`,
		`release_version=$(resolve_release_version "$release_metadata_pages")`,
		`release_base=https://github.com/$repository/releases/download/$release_version`,
	)
}

func TestStableReleaseSelectorBehavior(t *testing.T) {
	repository := repositoryRoot(t)
	command := exec.Command("sh", filepath.Join(repository, "scripts", "stable_release_test.sh"))
	command.Dir = repository
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("stable release selector: %v: %s", err, output)
	}
}

func TestReleaseArchivesContainCurrentLicenseInventory(t *testing.T) {
	repository := repositoryRoot(t)
	configuration, err := os.ReadFile(filepath.Join(repository, ".goreleaser.yml"))
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{"- LICENSE", "- THIRD_PARTY_NOTICES", "- scripts/stable-release.sh"} {
		if !bytes.Contains(configuration, []byte(required)) {
			t.Errorf("GoReleaser archive files are missing %q", required)
		}
	}

	generated := filepath.Join(t.TempDir(), "THIRD_PARTY_NOTICES")
	command := exec.Command("sh", filepath.Join(repository, "scripts", "generate-third-party-notices.sh"), generated)
	command.Dir = repository
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("generate third-party notices: %v: %s", err, output)
	}
	want, err := os.ReadFile(filepath.Join(repository, "THIRD_PARTY_NOTICES"))
	if err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(generated)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatal("THIRD_PARTY_NOTICES does not match the pinned linked module inventory")
	}

	readme, err := os.ReadFile(filepath.Join(repository, "README.md"))
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{"Corresponding source", "THIRD_PARTY_NOTICES"} {
		if !bytes.Contains(readme, []byte(required)) {
			t.Errorf("README is missing release-source guidance %q", required)
		}
	}
}

func readWorkflow(t *testing.T, repository, name string) string {
	t.Helper()
	contents, err := os.ReadFile(filepath.Join(repository, name))
	if err != nil {
		t.Fatalf("read %s: %v", name, err)
	}
	return string(contents)
}

func assertOrdered(t *testing.T, contents string, markers ...string) {
	t.Helper()
	position := -1
	for _, marker := range markers {
		next := strings.Index(contents, marker)
		if next < 0 {
			t.Fatalf("missing ordered marker %q", marker)
		}
		if next <= position {
			t.Fatalf("marker %q appears out of order", marker)
		}
		position = next
	}
}

package update

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/rezraf/tui-box/internal/app"
)

func TestCheckSelectsHighestStableSemanticVersionWithoutDownloadingAssets(t *testing.T) {
	t.Parallel()

	var requested []string
	server := newReleaseServer(t, func(writer http.ResponseWriter, request *http.Request) {
		requested = append(requested, request.URL.Path)
		if request.URL.Path != "/repos/rezraf/tui-box/releases" {
			http.NotFound(writer, request)
			return
		}
		writeJSONResponse(t, writer, []release{
			{TagName: "v0.3.0", Draft: true},
			{TagName: "v2.0.0-rc.1", Prerelease: true},
			{TagName: "not-a-version"},
			{TagName: "v0.9.0"},
			{TagName: "v0.10.0"},
		})
	})
	updater := newTestUpdater(t, server, Config{CurrentVersion: "v0.2.0", GOOS: "linux", GOARCH: "amd64"})

	info, err := updater.Check(context.Background())
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	want := app.UpdateInfo{CurrentVersion: "v0.2.0", LatestVersion: "v0.10.0", Available: true}
	if info != want {
		t.Fatalf("Check = %#v, want %#v", info, want)
	}
	if !reflect.DeepEqual(requested, []string{"/repos/rezraf/tui-box/releases"}) {
		t.Fatalf("network requests = %v; --check must fetch metadata only", requested)
	}
}

func TestCheckAcceptsAdditionalGitHubReleaseMetadataFields(t *testing.T) {
	t.Parallel()

	server := newReleaseServer(t, func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/repos/rezraf/tui-box/releases" {
			http.NotFound(writer, request)
			return
		}
		_, _ = io.WriteString(writer, `[{"tag_name":"v1.1.0","draft":false,"prerelease":false,"html_url":"https://github.com/rezraf/tui-box/releases/tag/v1.1.0","assets":[],"author":{"login":"release-bot"}}]`)
	})
	updater := newTestUpdater(t, server, Config{CurrentVersion: "v1.0.0", GOOS: "linux", GOARCH: "amd64"})

	info, err := updater.Check(context.Background())
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if info.LatestVersion != "v1.1.0" || !info.Available {
		t.Fatalf("Check = %#v", info)
	}
}

func TestCheckReportsNoUpdateWhenCurrentVersionIsLatest(t *testing.T) {
	t.Parallel()

	server := releaseListServer(t, []release{{TagName: "v1.2.3"}, {TagName: "v1.2.2"}})
	updater := newTestUpdater(t, server, Config{CurrentVersion: "v1.2.3", GOOS: "darwin", GOARCH: "arm64"})

	info, err := updater.Check(context.Background())
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	want := app.UpdateInfo{CurrentVersion: "v1.2.3", LatestVersion: "v1.2.3", Available: false}
	if info != want {
		t.Fatalf("Check = %#v, want %#v", info, want)
	}
}

func TestSemanticVersionComparisonRejectsAmbiguousVersions(t *testing.T) {
	t.Parallel()

	valid := []struct {
		left  string
		right string
		want  int
	}{
		{left: "v0.9.0", right: "v0.10.0", want: -1},
		{left: "1.2.3", right: "v1.2.3", want: 0},
		{left: "v2.0.0", right: "v1.99.99", want: 1},
	}
	for _, test := range valid {
		if got, ok := compareStableVersions(test.left, test.right); !ok || got != test.want {
			t.Fatalf("compareStableVersions(%q, %q) = %d, %t; want %d, true", test.left, test.right, got, ok, test.want)
		}
	}
	for _, invalid := range []string{"", "dev", "v1", "v1.2", "v1.2.3.4", "v1.2.3-beta", "v01.2.3", "v1.-2.3", "v1.2.3+meta"} {
		if _, ok := compareStableVersions(invalid, "v1.0.0"); ok {
			t.Fatalf("version %q was accepted", invalid)
		}
	}
}

func TestSelectAssetsRequiresExactPlatformArchiveAndChecksums(t *testing.T) {
	t.Parallel()

	for _, target := range []struct {
		goos   string
		goarch string
		name   string
	}{
		{goos: "linux", goarch: "amd64", name: "tuibox_linux_amd64.tar.gz"},
		{goos: "linux", goarch: "arm64", name: "tuibox_linux_arm64.tar.gz"},
		{goos: "darwin", goarch: "amd64", name: "tuibox_darwin_amd64.tar.gz"},
		{goos: "darwin", goarch: "arm64", name: "tuibox_darwin_arm64.tar.gz"},
	} {
		t.Run(target.goos+"-"+target.goarch, func(t *testing.T) {
			release := release{Assets: []releaseAsset{
				{Name: "tuibox_linux_386.tar.gz", URL: "https://example.invalid/wrong"},
				{Name: target.name + ".sig", URL: "https://example.invalid/signature"},
				{Name: target.name, URL: "https://example.invalid/archive"},
				{Name: checksumsAssetName, URL: "https://example.invalid/checksums"},
			}}
			archive, checksums, err := selectAssets(release, target.goos, target.goarch)
			if err != nil {
				t.Fatalf("selectAssets: %v", err)
			}
			if archive.Name != target.name || checksums.Name != checksumsAssetName {
				t.Fatalf("selected archive=%q checksums=%q", archive.Name, checksums.Name)
			}
		})
	}

	if _, _, err := selectAssets(release{Assets: []releaseAsset{{Name: checksumsAssetName, URL: "https://example.invalid/checksums"}}}, "linux", "amd64"); !errors.Is(err, ErrReleaseInvalid) {
		t.Fatalf("missing archive error = %v", err)
	}
	duplicate := release{Assets: []releaseAsset{
		{Name: "tuibox_linux_amd64.tar.gz", URL: "https://example.invalid/one"},
		{Name: "tuibox_linux_amd64.tar.gz", URL: "https://example.invalid/two"},
		{Name: checksumsAssetName, URL: "https://example.invalid/checksums"},
	}}
	if _, _, err := selectAssets(duplicate, "linux", "amd64"); !errors.Is(err, ErrReleaseInvalid) {
		t.Fatalf("duplicate archive error = %v", err)
	}
	if _, _, err := selectAssets(release{}, "windows", "amd64"); !errors.Is(err, ErrUnsupportedPlatform) {
		t.Fatalf("unsupported platform error = %v", err)
	}
}

func TestParseChecksumsAcceptsGoReleaserFormatAndRejectsMalformedOrDuplicateEntries(t *testing.T) {
	t.Parallel()

	archiveName := "tuibox_linux_amd64.tar.gz"
	digest := strings.Repeat("a", sha256.Size*2)
	got, err := parseChecksum([]byte(digest+"  "+archiveName+"\n"+strings.Repeat("b", sha256.Size*2)+"  other.tar.gz\n"), archiveName)
	if err != nil || got != digest {
		t.Fatalf("parseChecksum = %q, %v", got, err)
	}

	for name, input := range map[string]string{
		"missing":   strings.Repeat("b", 64) + "  other.tar.gz\n",
		"malformed": "not-a-digest  " + archiveName + "\n",
		"duplicate": digest + "  " + archiveName + "\n" + digest + "  " + archiveName + "\n",
		"extra":     digest + "  " + archiveName + " unexpected\n",
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := parseChecksum([]byte(input), archiveName); !errors.Is(err, ErrChecksumInvalid) {
				t.Fatalf("parseChecksum error = %v", err)
			}
		})
	}
}

func TestDownloadVerifiedArchiveChecksHTTPSRedirectsBoundsAndDigest(t *testing.T) {
	t.Parallel()

	archive := tarGzip(t, []tarEntry{{name: "tuibox", body: []byte("client")}, {name: "tuiboxd", body: []byte("daemon")}})
	digest := sha256.Sum256(archive)
	var server *httptest.Server
	server = newReleaseServer(t, func(writer http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/archive":
			writer.Header().Set("Content-Type", "application/gzip")
			_, _ = writer.Write(archive)
		case "/redirect":
			http.Redirect(writer, request, server.URL+"/archive", http.StatusFound)
		case "/downgrade":
			http.Redirect(writer, request, "http://example.invalid/archive", http.StatusFound)
		case "/oversized":
			writer.Header().Set("Content-Length", fmt.Sprint(maxArchiveBytes+1))
			_, _ = writer.Write(bytes.Repeat([]byte("x"), 1024))
		default:
			http.NotFound(writer, request)
		}
	})
	updater := newTestUpdater(t, server, Config{CurrentVersion: "v0.1.0", GOOS: "linux", GOARCH: "amd64"})

	got, err := updater.downloadVerifiedArchive(context.Background(), server.URL+"/redirect", hex.EncodeToString(digest[:]))
	if err != nil || !bytes.Equal(got, archive) {
		t.Fatalf("downloadVerifiedArchive = %d bytes, %v", len(got), err)
	}
	if _, err := updater.downloadVerifiedArchive(context.Background(), server.URL+"/archive", strings.Repeat("0", 64)); !errors.Is(err, ErrChecksumMismatch) {
		t.Fatalf("checksum mismatch error = %v", err)
	}
	if _, err := updater.downloadVerifiedArchive(context.Background(), server.URL+"/downgrade", hex.EncodeToString(digest[:])); !errors.Is(err, ErrNetwork) {
		t.Fatalf("downgrade error = %v", err)
	}
	if _, err := updater.downloadVerifiedArchive(context.Background(), server.URL+"/oversized", hex.EncodeToString(digest[:])); !errors.Is(err, ErrResponseTooLarge) {
		t.Fatalf("oversized error = %v", err)
	}
}

func TestHTTPClientBoundsMetadataBodyRedirectCountAndTimeout(t *testing.T) {
	t.Parallel()

	var server *httptest.Server
	server = newReleaseServer(t, func(writer http.ResponseWriter, request *http.Request) {
		switch {
		case request.URL.Path == "/repos/rezraf/tui-box/releases":
			_, _ = writer.Write(bytes.Repeat([]byte("x"), maxMetadataBytes+1))
		case strings.HasPrefix(request.URL.Path, "/loop/"):
			var next int
			_, _ = fmt.Sscanf(strings.TrimPrefix(request.URL.Path, "/loop/"), "%d", &next)
			http.Redirect(writer, request, fmt.Sprintf("%s/loop/%d", server.URL, next+1), http.StatusFound)
		case request.URL.Path == "/slow":
			time.Sleep(200 * time.Millisecond)
			_, _ = writer.Write([]byte("late"))
		default:
			http.NotFound(writer, request)
		}
	})
	updater := newTestUpdater(t, server, Config{CurrentVersion: "v0.1.0", GOOS: "linux", GOARCH: "amd64"})

	if _, err := updater.Check(context.Background()); !errors.Is(err, ErrResponseTooLarge) {
		t.Fatalf("metadata limit error = %v", err)
	}
	if _, err := updater.getBounded(context.Background(), server.URL+"/loop/0", 1024); !errors.Is(err, ErrNetwork) {
		t.Fatalf("redirect limit error = %v", err)
	}

	timeoutUpdater := newTestUpdater(t, server, Config{CurrentVersion: "v0.1.0", GOOS: "linux", GOARCH: "amd64", Timeout: 50 * time.Millisecond})
	if _, err := timeoutUpdater.getBounded(context.Background(), server.URL+"/slow", 1024); !errors.Is(err, ErrNetwork) {
		t.Fatalf("timeout error = %v", err)
	}
}

func TestNewRejectsInsecureOrMalformedProductionConfiguration(t *testing.T) {
	t.Parallel()

	valid := Config{CurrentVersion: "v1.0.0", Repository: defaultRepository, GOOS: "linux", GOARCH: "amd64"}
	for name, mutate := range map[string]func(*Config){
		"http API":        func(config *Config) { config.APIBaseURL = "http://api.github.com" },
		"repository":      func(config *Config) { config.Repository = "owner/repo/private?token=secret" },
		"current version": func(config *Config) { config.CurrentVersion = "dev" },
		"operating system": func(config *Config) {
			config.GOOS = "windows"
		},
		"architecture": func(config *Config) { config.GOARCH = "386" },
	} {
		t.Run(name, func(t *testing.T) {
			config := valid
			mutate(&config)
			if _, err := New(config); !errors.Is(err, ErrInvalidConfiguration) {
				t.Fatalf("New error = %v", err)
			}
		})
	}
}

func TestExtractBinariesRejectsTraversalSymlinksHardlinksDuplicatesAndOversizedFiles(t *testing.T) {
	t.Parallel()

	outsideName := "outside-" + fmt.Sprint(time.Now().UnixNano())
	archives := map[string][]byte{
		"traversal": tarGzip(t, []tarEntry{{name: "../" + outsideName, body: []byte("escape")}, {name: "tuibox", body: []byte("client")}, {name: "tuiboxd", body: []byte("daemon")}}),
		"absolute":  tarGzip(t, []tarEntry{{name: "/tmp/escape", body: []byte("escape")}}),
		"symlink":   tarGzip(t, []tarEntry{{name: "tuibox", typeflag: tar.TypeSymlink, linkname: "/bin/sh"}, {name: "tuiboxd", body: []byte("daemon")}}),
		"hardlink":  tarGzip(t, []tarEntry{{name: "tuibox", typeflag: tar.TypeLink, linkname: "tuiboxd"}, {name: "tuiboxd", body: []byte("daemon")}}),
		"duplicate": tarGzip(t, []tarEntry{{name: "tuibox", body: []byte("one")}, {name: "tuibox", body: []byte("two")}, {name: "tuiboxd", body: []byte("daemon")}}),
		"oversized": tarGzip(t, []tarEntry{{name: "tuibox", body: bytes.Repeat([]byte("x"), maxBinaryBytes+1)}, {name: "tuiboxd", body: []byte("daemon")}}),
	}
	for name, archive := range archives {
		t.Run(name, func(t *testing.T) {
			if _, err := extractBinaries(archive); !errors.Is(err, ErrArchiveInvalid) {
				t.Fatalf("extractBinaries error = %v", err)
			}
		})
	}
}

func TestExtractBinariesReturnsOnlyVerifiedRegularExecutablePayloads(t *testing.T) {
	t.Parallel()

	archive := tarGzip(t, []tarEntry{
		{name: "README.md", body: []byte("documentation")},
		{name: "packaging/", typeflag: tar.TypeDir},
		{name: "tuibox", mode: 0o755, body: []byte("client-binary")},
		{name: "tuiboxd", mode: 0o755, body: []byte("daemon-binary")},
	})
	binaries, err := extractBinaries(archive)
	if err != nil {
		t.Fatalf("extractBinaries: %v", err)
	}
	want := binariesPayload{Client: []byte("client-binary"), Daemon: []byte("daemon-binary")}
	if !reflect.DeepEqual(binaries, want) {
		t.Fatalf("binaries = %#v, want %#v", binaries, want)
	}
}

func TestApplyInvokesOnlyInstalledFixedPathHelperWithoutShellInterpolation(t *testing.T) {
	t.Parallel()

	prefix := t.TempDir()
	clientPath := filepath.Join(prefix, "bin", "tuibox")
	helperPath := filepath.Join(prefix, "libexec", "tuibox", helperBinaryName)
	if err := os.MkdirAll(filepath.Dir(clientPath), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(helperPath), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(clientPath, []byte("client"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(helperPath, []byte("helper"), 0o755); err != nil {
		t.Fatal(err)
	}
	var gotPath string
	var gotArgs []string
	updater, err := New(Config{
		CurrentVersion: "v0.1.0",
		Repository:     defaultRepository,
		GOOS:           "linux",
		GOARCH:         "amd64",
		ExecutablePath: func() (string, error) { return clientPath, nil },
		RunCommand: func(_ context.Context, path string, args []string, _ io.Reader, _, _ io.Writer) error {
			gotPath = path
			gotArgs = append([]string(nil), args...)
			return nil
		},
		validateHelper: func(path string) error {
			if path != helperPath {
				t.Fatalf("validated helper path = %q, want %q", path, helperPath)
			}
			return nil
		},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	info := app.UpdateInfo{CurrentVersion: "v0.1.0", LatestVersion: "v0.2.0", Available: true}
	if err := updater.Apply(context.Background(), info); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if gotPath != sudoPath {
		t.Fatalf("command path = %q, want %q", gotPath, sudoPath)
	}
	wantArgs := []string{"--", helperPath, internalApplyArgument, "v0.2.0"}
	if !reflect.DeepEqual(gotArgs, wantArgs) {
		t.Fatalf("command args = %#v, want %#v", gotArgs, wantArgs)
	}
	for _, argument := range gotArgs {
		if strings.ContainsAny(argument, ";|`$\n") {
			t.Fatalf("unsafe command argument %q", argument)
		}
	}
}

func TestApplyRejectsUserOwnedHelperBeforePrivilegeEscalation(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("requires an unprivileged test user")
	}

	prefix := t.TempDir()
	clientPath := filepath.Join(prefix, "bin", "tuibox")
	helperPath := filepath.Join(prefix, "libexec", "tuibox", helperBinaryName)
	for _, path := range []string{clientPath, helperPath} {
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte("binary"), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	calls := 0
	updater, err := New(Config{
		CurrentVersion: "v0.1.0",
		GOOS:           "linux",
		GOARCH:         "amd64",
		ExecutablePath: func() (string, error) { return clientPath, nil },
		RunCommand: func(context.Context, string, []string, io.Reader, io.Writer, io.Writer) error {
			calls++
			return nil
		},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	info := app.UpdateInfo{CurrentVersion: "v0.1.0", LatestVersion: "v0.2.0", Available: true}
	if err := updater.Apply(context.Background(), info); !errors.Is(err, ErrInvalidInstallation) {
		t.Fatalf("Apply error = %v, want ErrInvalidInstallation", err)
	}
	if calls != 0 {
		t.Fatalf("privileged command calls = %d, want 0", calls)
	}
}

func TestApplyRejectsStaleUnsafeOrUnavailableUpdatesBeforeCommandExecution(t *testing.T) {
	t.Parallel()

	calls := 0
	updater, err := New(Config{
		CurrentVersion: "v1.0.0",
		Repository:     defaultRepository,
		GOOS:           "darwin",
		GOARCH:         "arm64",
		ExecutablePath: func() (string, error) { return "/usr/local/bin/tuibox", nil },
		RunCommand: func(context.Context, string, []string, io.Reader, io.Writer, io.Writer) error {
			calls++
			return nil
		},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	for _, info := range []app.UpdateInfo{
		{CurrentVersion: "v1.0.0", LatestVersion: "v1.0.1", Available: false},
		{CurrentVersion: "v0.9.0", LatestVersion: "v1.0.1", Available: true},
		{CurrentVersion: "v1.0.0", LatestVersion: "https://example.invalid/token", Available: true},
		{CurrentVersion: "v1.0.0", LatestVersion: "v0.9.0", Available: true},
	} {
		if err := updater.Apply(context.Background(), info); !errors.Is(err, ErrInvalidUpdate) {
			t.Fatalf("Apply(%#v) error = %v", info, err)
		}
	}
	if calls != 0 {
		t.Fatalf("command calls = %d, want 0", calls)
	}
}

func TestTrustedParentChainRejectsWritableInstallationAncestors(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	parent := filepath.Join(root, "prefix", "libexec")
	directory := filepath.Join(parent, "tuibox")
	if err := os.MkdirAll(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := trustedParentChain(directory, root, uint32(os.Getuid())); err != nil {
		t.Fatalf("trustedParentChain secure path: %v", err)
	}
	if err := os.Chmod(parent, 0o777); err != nil {
		t.Fatal(err)
	}
	if err := trustedParentChain(directory, root, uint32(os.Getuid())); !errors.Is(err, ErrInvalidInstallation) {
		t.Fatalf("writable parent error = %v, want ErrInvalidInstallation", err)
	}
}

func TestReplaceInstallationUpdatesThreeFixedFilesAndRollsBackOnFailure(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	layout := installationLayout{
		Client: filepath.Join(root, "bin", "tuibox"),
		Daemon: filepath.Join(root, "libexec", "tuibox", "tuiboxd"),
		Helper: filepath.Join(root, "libexec", "tuibox", helperBinaryName),
	}
	for _, path := range []string{layout.Client, layout.Daemon, layout.Helper} {
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte("old-"+filepath.Base(path)), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	payload := binariesPayload{Client: []byte("new-client"), Daemon: []byte("new-daemon")}
	if err := replaceInstallation(layout, payload, fileOperations{}); err != nil {
		t.Fatalf("replaceInstallation: %v", err)
	}
	assertFileContents(t, layout.Client, "new-client")
	assertFileContents(t, layout.Daemon, "new-daemon")
	assertFileContents(t, layout.Helper, "new-client")

	for _, path := range []string{layout.Client, layout.Daemon, layout.Helper} {
		if err := os.WriteFile(path, []byte("rollback-"+filepath.Base(path)), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	operations := fileOperations{
		rename: func(oldPath, newPath string) error {
			if newPath == layout.Client && strings.Contains(filepath.Base(oldPath), ".new-") {
				return errors.New("injected rename failure")
			}
			return os.Rename(oldPath, newPath)
		},
	}
	if err := replaceInstallation(layout, payload, operations); !errors.Is(err, ErrReplaceFailed) {
		t.Fatalf("replaceInstallation failure = %v", err)
	}
	assertFileContents(t, layout.Client, "rollback-tuibox")
	assertFileContents(t, layout.Daemon, "rollback-tuiboxd")
	assertFileContents(t, layout.Helper, "rollback-"+helperBinaryName)
}

func TestReplaceInstallationRestoresOriginalsWhenRollbackRemoveFails(t *testing.T) {
	root := t.TempDir()
	layout := replacementTestLayout(root)
	original := writeReplacementFixture(t, layout)
	payload := binariesPayload{Client: []byte("new-client"), Daemon: []byte("new-daemon")}

	removeFailed := false
	var events []string
	operations := fileOperations{
		rename: func(oldPath, newPath string) error {
			if newPath == layout.Client && strings.Contains(filepath.Base(oldPath), ".new-") {
				return errors.New("injected client forward failure")
			}
			if err := os.Rename(oldPath, newPath); err != nil {
				return err
			}
			events = append(events, "rename:"+filepath.Dir(newPath))
			return nil
		},
		remove: func(path string) error {
			events = append(events, "remove:"+filepath.Dir(path))
			if path == layout.Daemon {
				removeFailed = true
				return errors.New("injected daemon remove failure")
			}
			return os.Remove(path)
		},
		syncDirectory: func(path string) error {
			events = append(events, "sync:"+path)
			return nil
		},
	}

	err := replaceInstallation(layout, payload, operations)
	if !errors.Is(err, ErrReplaceFailed) || errors.Is(err, ErrRollbackIncomplete) {
		t.Fatalf("replaceInstallation error = %v, want complete rollback", err)
	}
	if !removeFailed {
		t.Fatal("rollback did not exercise the injected remove failure")
	}
	for path, contents := range original {
		assertFileContents(t, path, contents)
	}
	assertSuccessfulRenamesSynced(t, events)
	assertNoRecoveryArtifacts(t, filepath.Dir(layout.Helper))
}

func TestReplaceInstallationPreservesEveryRecoverableBackupWhenRollbackIsIncomplete(t *testing.T) {
	root := t.TempDir()
	layout := replacementTestLayout(root)
	original := writeReplacementFixture(t, layout)
	payload := binariesPayload{Client: []byte("new-client"), Daemon: []byte("new-daemon")}

	var events []string
	operations := fileOperations{
		rename: func(oldPath, newPath string) error {
			if newPath == layout.Helper && strings.Contains(filepath.Base(oldPath), ".new-") {
				return errors.New("injected helper forward failure")
			}
			if (newPath == layout.Daemon || newPath == layout.Helper) && strings.Contains(filepath.Base(oldPath), ".backup-") {
				return errors.New("injected backup restoration failure")
			}
			if err := os.Rename(oldPath, newPath); err != nil {
				return err
			}
			events = append(events, "rename:"+filepath.Dir(newPath))
			return nil
		},
		remove: func(path string) error {
			events = append(events, "remove:"+filepath.Dir(path))
			return os.Remove(path)
		},
		syncDirectory: func(path string) error {
			events = append(events, "sync:"+path)
			return nil
		},
	}

	err := replaceInstallation(layout, payload, operations)
	if !errors.Is(err, ErrReplaceFailed) || !errors.Is(err, ErrRollbackIncomplete) {
		t.Fatalf("replaceInstallation error = %v, want replace and incomplete rollback identities", err)
	}
	if strings.Contains(err.Error(), "injected") {
		t.Fatalf("replaceInstallation leaked an internal operation error: %q", err)
	}
	assertFileContents(t, layout.Client, original[layout.Client])
	assertRecoveryBackup(t, layout.Daemon, original[layout.Daemon])
	assertRecoveryBackup(t, layout.Helper, original[layout.Helper])
	assertSuccessfulRenamesSynced(t, events)
	if got, want := countOperationEvents(events, "sync:"), countOperationEvents(events, "rename:")+2; got < want {
		t.Fatalf("directory sync events = %d, want at least %d for renames and recovery markers: %v", got, want, events)
	}
}

func TestReplaceInstallationRollsBackWhenDirectorySyncFails(t *testing.T) {
	root := t.TempDir()
	layout := replacementTestLayout(root)
	original := writeReplacementFixture(t, layout)
	payload := binariesPayload{Client: []byte("new-client"), Daemon: []byte("new-daemon")}

	syncCalls := 0
	operations := fileOperations{
		syncDirectory: func(string) error {
			syncCalls++
			if syncCalls == 2 {
				return errors.New("injected directory sync failure")
			}
			return nil
		},
	}

	err := replaceInstallation(layout, payload, operations)
	if !errors.Is(err, ErrReplaceFailed) || errors.Is(err, ErrRollbackIncomplete) {
		t.Fatalf("replaceInstallation error = %v, want complete rollback after sync failure", err)
	}
	for path, contents := range original {
		assertFileContents(t, path, contents)
	}
	if syncCalls < 3 {
		t.Fatalf("directory sync calls = %d, want forward sync failure plus restored target sync", syncCalls)
	}
	assertNoRecoveryArtifacts(t, filepath.Dir(layout.Helper))
}

func TestPrivilegedApplyIndependentlyDownloadsChecksumsArchiveAndReplacesFixedLayout(t *testing.T) {
	t.Parallel()

	archive := tarGzip(t, []tarEntry{{name: "tuibox", mode: 0o755, body: []byte("new-client")}, {name: "tuiboxd", mode: 0o755, body: []byte("new-daemon")}})
	digest := sha256.Sum256(archive)
	archiveName := "tuibox_linux_amd64.tar.gz"
	var server *httptest.Server
	server = newReleaseServer(t, func(writer http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/repos/rezraf/tui-box/releases":
			writeJSONResponse(t, writer, []release{{
				TagName: "v0.2.0",
				Assets: []releaseAsset{
					{Name: archiveName, URL: server.URL + "/assets/archive"},
					{Name: checksumsAssetName, URL: server.URL + "/assets/checksums"},
				},
			}})
		case "/assets/checksums":
			_, _ = fmt.Fprintf(writer, "%x  %s\n", digest, archiveName)
		case "/assets/archive":
			_, _ = writer.Write(archive)
		default:
			http.NotFound(writer, request)
		}
	})
	root := t.TempDir()
	layout := installationLayout{
		Client: filepath.Join(root, "bin", "tuibox"),
		Daemon: filepath.Join(root, "libexec", "tuibox", "tuiboxd"),
		Helper: filepath.Join(root, "libexec", "tuibox", helperBinaryName),
	}
	for _, path := range []string{layout.Client, layout.Daemon, layout.Helper} {
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte("old"), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	updater := newTestUpdater(t, server, Config{CurrentVersion: "v0.1.0", GOOS: "linux", GOARCH: "amd64"})

	if err := updater.applyPrivileged(context.Background(), "v0.2.0", layout, fileOperations{}); err != nil {
		t.Fatalf("applyPrivileged: %v", err)
	}
	assertFileContents(t, layout.Client, "new-client")
	assertFileContents(t, layout.Daemon, "new-daemon")
	assertFileContents(t, layout.Helper, "new-client")
}

func TestPublicErrorsNeverContainReleaseURLsQueriesOrResponseBodies(t *testing.T) {
	t.Parallel()

	secret := "private-token-123"
	server := newReleaseServer(t, func(writer http.ResponseWriter, request *http.Request) {
		writer.WriteHeader(http.StatusInternalServerError)
		_, _ = fmt.Fprintf(writer, "upstream failed token=%s URL=%s", secret, request.URL.String())
	})
	updater := newTestUpdater(t, server, Config{CurrentVersion: "v0.1.0", GOOS: "linux", GOARCH: "amd64"})

	_, err := updater.Check(context.Background())
	if err == nil {
		t.Fatal("Check unexpectedly succeeded")
	}
	message := err.Error()
	for _, forbidden := range []string{secret, "https://", "token=", server.URL, "/repos/"} {
		if strings.Contains(message, forbidden) {
			t.Fatalf("error leaked %q: %q", forbidden, message)
		}
	}
}

func TestConcurrentChecksAreSafeAndDoNotShareMutableReleaseState(t *testing.T) {
	t.Parallel()

	server := releaseListServer(t, []release{{TagName: "v1.1.0"}})
	updater := newTestUpdater(t, server, Config{CurrentVersion: "v1.0.0", GOOS: "linux", GOARCH: "arm64"})
	var wait sync.WaitGroup
	errorsChannel := make(chan error, 16)
	for range 16 {
		wait.Add(1)
		go func() {
			defer wait.Done()
			info, err := updater.Check(context.Background())
			if err != nil || info.LatestVersion != "v1.1.0" {
				errorsChannel <- fmt.Errorf("info=%#v err=%v", info, err)
			}
		}()
	}
	wait.Wait()
	close(errorsChannel)
	for err := range errorsChannel {
		t.Error(err)
	}
}

func newTestUpdater(t *testing.T, server *httptest.Server, config Config) *Updater {
	t.Helper()
	if config.Repository == "" {
		config.Repository = defaultRepository
	}
	config.APIBaseURL = server.URL
	config.HTTPClient = server.Client()
	config.AllowTestHTTPClient = true
	updater, err := New(config)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return updater
}

func releaseListServer(t *testing.T, releases []release) *httptest.Server {
	t.Helper()
	return newReleaseServer(t, func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/repos/rezraf/tui-box/releases" {
			http.NotFound(writer, request)
			return
		}
		writeJSONResponse(t, writer, releases)
	})
}

func newReleaseServer(t *testing.T, handler http.HandlerFunc) *httptest.Server {
	t.Helper()
	server := httptest.NewTLSServer(handler)
	t.Cleanup(server.Close)
	return server
}

func writeJSONResponse(t *testing.T, writer http.ResponseWriter, value any) {
	t.Helper()
	writer.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(writer).Encode(value); err != nil {
		t.Fatalf("encode response: %v", err)
	}
}

type tarEntry struct {
	name         string
	body         []byte
	typeflag     byte
	linkname     string
	mode         int64
	declaredSize int64
}

func tarGzip(t *testing.T, entries []tarEntry) []byte {
	t.Helper()
	var output bytes.Buffer
	gzipWriter := gzip.NewWriter(&output)
	tarWriter := tar.NewWriter(gzipWriter)
	for _, entry := range entries {
		typeflag := entry.typeflag
		if typeflag == 0 {
			typeflag = tar.TypeReg
		}
		mode := entry.mode
		if mode == 0 {
			mode = 0o644
		}
		size := int64(len(entry.body))
		if entry.declaredSize != 0 {
			size = entry.declaredSize
		}
		header := &tar.Header{Name: entry.name, Typeflag: typeflag, Linkname: entry.linkname, Mode: mode, Size: size}
		if typeflag == tar.TypeDir || typeflag == tar.TypeSymlink || typeflag == tar.TypeLink {
			header.Size = 0
		}
		if err := tarWriter.WriteHeader(header); err != nil {
			t.Fatalf("write tar header: %v", err)
		}
		if header.Size > 0 && int64(len(entry.body)) >= header.Size {
			if _, err := tarWriter.Write(entry.body[:header.Size]); err != nil {
				t.Fatalf("write tar body: %v", err)
			}
		}
	}
	if err := tarWriter.Close(); err != nil {
		t.Fatalf("close tar: %v", err)
	}
	if err := gzipWriter.Close(); err != nil {
		t.Fatalf("close gzip: %v", err)
	}
	return output.Bytes()
}

func replacementTestLayout(root string) installationLayout {
	directory := filepath.Join(root, "libexec", "tuibox")
	return installationLayout{
		Client: filepath.Join(directory, "tuibox"),
		Daemon: filepath.Join(directory, "tuiboxd"),
		Helper: filepath.Join(directory, helperBinaryName),
	}
}

func writeReplacementFixture(t *testing.T, layout installationLayout) map[string]string {
	t.Helper()
	original := make(map[string]string, 3)
	for _, path := range []string{layout.Client, layout.Daemon, layout.Helper} {
		contents := "old-" + filepath.Base(path)
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(contents), 0o755); err != nil {
			t.Fatal(err)
		}
		original[path] = contents
	}
	return original
}

func assertSuccessfulRenamesSynced(t *testing.T, events []string) {
	t.Helper()
	for index, event := range events {
		if !strings.HasPrefix(event, "rename:") {
			continue
		}
		want := "sync:" + strings.TrimPrefix(event, "rename:")
		if index+1 >= len(events) || events[index+1] != want {
			t.Fatalf("successful rename %q was not immediately directory-synced: %v", event, events)
		}
	}
}

func assertNoRecoveryArtifacts(t *testing.T, directory string) {
	t.Helper()
	matches, err := filepath.Glob(filepath.Join(directory, ".*.backup-*"))
	if err != nil {
		t.Fatal(err)
	}
	if len(matches) != 0 {
		t.Fatalf("unexpected recovery artifacts: %v", matches)
	}
}

func assertRecoveryBackup(t *testing.T, target, want string) {
	t.Helper()
	pattern := filepath.Join(filepath.Dir(target), "."+filepath.Base(target)+".backup-*")
	matches, err := filepath.Glob(pattern)
	if err != nil {
		t.Fatal(err)
	}
	var backups []string
	for _, match := range matches {
		if !strings.HasSuffix(match, ".recovery") {
			backups = append(backups, match)
		}
	}
	if len(backups) != 1 {
		t.Fatalf("recoverable backups for %q = %v, want exactly one", target, backups)
	}
	assertFileContents(t, backups[0], want)
	marker := backups[0] + ".recovery"
	info, err := os.Stat(marker)
	if err != nil || !info.Mode().IsRegular() {
		t.Fatalf("recovery marker for %q = %v, %v", target, info, err)
	}
}

func countOperationEvents(events []string, prefix string) int {
	count := 0
	for _, event := range events {
		if strings.HasPrefix(event, prefix) {
			count++
		}
	}
	return count
}

func assertFileContents(t *testing.T, path, want string) {
	t.Helper()
	contents, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	if string(contents) != want {
		t.Fatalf("%s = %q, want %q", path, contents, want)
	}
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	if !info.Mode().IsRegular() || info.Mode().Perm() != 0o755 {
		t.Fatalf("%s mode = %v, want regular 0755", path, info.Mode())
	}
}

func TestMain(m *testing.M) {
	if runtime.GOOS != "darwin" && runtime.GOOS != "linux" {
		os.Exit(0)
	}
	os.Exit(m.Run())
}

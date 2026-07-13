package core

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/rezraf/tui-box/internal/domain"
)

const (
	pinnedSingBoxVersion = "1.13.14"
	maxCoreArchiveBytes  = 64 * 1024 * 1024
	maxCoreExtractBytes  = 256 * 1024 * 1024
)

type coreArtifact struct {
	URL    string
	SHA256 string
}

var pinnedCoreArtifacts = map[string]coreArtifact{
	"darwin/amd64": {
		URL:    "https://github.com/SagerNet/sing-box/releases/download/v1.13.14/sing-box-1.13.14-darwin-amd64.tar.gz",
		SHA256: "5245d645e847f90bb708da74bc020ae078c28489690756419685c04f56b4e3bb",
	},
	"darwin/arm64": {
		URL:    "https://github.com/SagerNet/sing-box/releases/download/v1.13.14/sing-box-1.13.14-darwin-arm64.tar.gz",
		SHA256: "73e8967b0fc08e17bce4263ca56ebc394822401a16497a1c4e02316c888202ab",
	},
	"linux/amd64": {
		URL:    "https://github.com/SagerNet/sing-box/releases/download/v1.13.14/sing-box-1.13.14-linux-amd64.tar.gz",
		SHA256: "f48703461a15476951ac4967cdad339d986f4b8096b4eb3ff0829a500502d697",
	},
	"linux/arm64": {
		URL:    "https://github.com/SagerNet/sing-box/releases/download/v1.13.14/sing-box-1.13.14-linux-arm64.tar.gz",
		SHA256: "4742df6a4314e8ecc41736849fca6d73b8f9e91b6e8b06ee794ff17ba180579e",
	},
}

func TestPinnedSingBoxNativeStdinTokenReadsPipedBytes(t *testing.T) {
	executable := pinnedCoreExecutable(t)
	directory := t.TempDir()
	sameNamePath := filepath.Join(directory, "stdin")

	if err := os.WriteFile(sameNamePath, []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	if output, err := runPinnedCoreStdinCheck(executable, directory, []byte("{}\n")); err != nil {
		t.Fatalf("valid piped config failed with invalid same-name file: %v: %s", err, output)
	}

	if err := os.WriteFile(sameNamePath, []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	output, err := runPinnedCoreStdinCheck(executable, directory, []byte("{"))
	if err == nil {
		t.Fatalf("invalid piped config passed with valid same-name file: %s", output)
	}
	if !strings.Contains(output, "decode config at stdin") {
		t.Fatalf("invalid piped config error = %q, want decode config at stdin", output)
	}
}

func TestGeneratedConfigsPassPinnedSingBoxCheckThroughRunnerNativeStdin(t *testing.T) {
	executable := pinnedCoreExecutable(t)

	runtimeDirectory := privateDirectory(t)
	runner, err := NewRunner(executable, runtimeDirectory)
	if err != nil {
		t.Fatalf("NewRunner() rejected pinned sing-box: %v", err)
	}
	t.Cleanup(func() {
		if err := runner.Close(); err != nil {
			t.Errorf("close integration runner: %v", err)
		}
	})

	uid, gid := os.Getuid(), os.Getgid()
	if uid == 0 || gid == 0 {
		uid, gid = 65534, 65534
	}
	checks := 0
	for _, testEndpoint := range integrationEndpoints() {
		testEndpoint := testEndpoint
		for _, mode := range []domain.ConnectionMode{domain.ConnectionModeProxy, domain.ConnectionModeTUN} {
			mode := mode
			for _, route := range []domain.RouteMode{domain.RouteModeGlobal, domain.RouteModeRule, domain.RouteModeDirect} {
				route := route
				checks++
				name := fmt.Sprintf("%s/%s/%s", testEndpoint.name, mode, route)
				t.Run(name, func(t *testing.T) {
					endpoint := testEndpoint.endpoint
					request := ConnectionRequest{Mode: mode, Route: route, Endpoint: &endpoint, UID: uid, GID: gid}
					if route == domain.RouteModeDirect {
						request.Endpoint = nil
					}
					if route == domain.RouteModeRule {
						request.RuleDirectDomainSuffixes = []string{"updates.example.com"}
						request.RuleDirectCIDRs = []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24")}
					}
					prepared, err := runner.Prepare(request)
					if err != nil {
						t.Fatalf("Prepare() failed: %v", err)
					}
					defer prepared.Close()
					ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
					defer cancel()
					if err := runner.Check(ctx, prepared); err != nil {
						t.Fatalf("sing-box check failed: %v", err)
					}
				})
			}
		}
	}
	if checks != 60 {
		t.Fatalf("core-check matrix ran %d checks, want 60", checks)
	}
}

func TestPinnedCoreIntegrationRequiresExplicitOptIn(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		executable string
		optIn      string
		want       bool
	}{
		{name: "ordinary test"},
		{name: "unrecognized opt-in", optIn: "true"},
		{name: "explicit opt-in", optIn: "1", want: true},
		{name: "explicit executable", executable: "/trusted/sing-box", want: true},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if got := pinnedCoreIntegrationEnabled(test.executable, test.optIn); got != test.want {
				t.Fatalf("pinnedCoreIntegrationEnabled(%q, %q) = %v, want %v", test.executable, test.optIn, got, test.want)
			}
		})
	}
}

func pinnedCoreIntegrationEnabled(executable, optIn string) bool {
	return executable != "" || optIn == "1"
}

func pinnedCoreExecutable(t *testing.T) string {
	t.Helper()
	executable := os.Getenv("TUIBOX_SING_BOX")
	if !pinnedCoreIntegrationEnabled(executable, os.Getenv("TUIBOX_CORE_INTEGRATION")) {
		t.Skip("set TUIBOX_CORE_INTEGRATION=1 or TUIBOX_SING_BOX to run pinned core integration")
	}
	if executable == "" {
		executable = downloadPinnedCore(t)
	}
	trustedPath, _, err := inspectExecutable(executable)
	if err != nil || trustedPath != executable {
		t.Fatalf("pinned sing-box executable is not trusted: %v", err)
	}
	assertPinnedCoreVersion(t, trustedPath)
	return trustedPath
}

func TestVerifyCoreArchivePinsExactBytes(t *testing.T) {
	t.Parallel()

	content := []byte("pinned archive bytes")
	digest := sha256.Sum256(content)
	verified, err := verifyCoreArchive(content, hex.EncodeToString(digest[:]))
	if err != nil {
		t.Fatalf("verifyCoreArchive() rejected exact bytes: %v", err)
	}
	content[0] ^= 0xff
	if got := verified.bytes; bytes.Equal(got, content) || string(got) != "pinned archive bytes" {
		t.Fatalf("verified archive did not retain an immutable exact copy: %q", got)
	}
	if archive, err := verifyCoreArchive(content, hex.EncodeToString(digest[:])); archive.bytes != nil || err == nil {
		t.Fatalf("verifyCoreArchive() accepted changed bytes: %#v, %v", archive, err)
	}
}

func TestFetchCoreArchiveIsHTTPSBoundedAndVerified(t *testing.T) {
	payload := []byte("official archive")
	digest := sha256.Sum256(payload)
	server := httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		response.(http.Flusher).Flush()
		_, _ = response.Write(payload)
	}))
	defer server.Close()

	artifact := coreArtifact{URL: server.URL, SHA256: hex.EncodeToString(digest[:])}
	archive, err := fetchCoreArchiveWithClient(server.Client(), artifact, int64(len(payload)))
	if err != nil {
		t.Fatalf("fetchCoreArchiveWithClient() failed: %v", err)
	}
	if !bytes.Equal(archive.bytes, payload) {
		t.Fatalf("fetched archive = %q, want exact response bytes", archive.bytes)
	}

	if archive, err := fetchCoreArchiveWithClient(server.Client(), artifact, int64(len(payload)-1)); archive.bytes != nil || err == nil {
		t.Fatalf("oversized archive = %#v, %v, want rejection", archive, err)
	}
	artifact.SHA256 = strings.Repeat("0", sha256.Size*2)
	if archive, err := fetchCoreArchiveWithClient(server.Client(), artifact, int64(len(payload))); archive.bytes != nil || err == nil {
		t.Fatalf("checksum-mismatched archive = %#v, %v, want rejection", archive, err)
	}
	artifact.URL = "http://example.com/sing-box.tar.gz"
	if archive, err := fetchCoreArchiveWithClient(server.Client(), artifact, int64(len(payload))); archive.bytes != nil || err == nil {
		t.Fatalf("non-HTTPS archive = %#v, %v, want rejection", archive, err)
	}

	insecureServer := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		_, _ = response.Write(payload)
	}))
	defer insecureServer.Close()
	redirectServer := httptest.NewTLSServer(http.RedirectHandler(insecureServer.URL, http.StatusFound))
	defer redirectServer.Close()
	artifact.URL = redirectServer.URL
	artifact.SHA256 = hex.EncodeToString(digest[:])
	if archive, err := fetchCoreArchiveWithClient(redirectServer.Client(), artifact, int64(len(payload))); archive.bytes != nil || err == nil {
		t.Fatalf("HTTPS downgrade archive = %#v, %v, want rejection", archive, err)
	}
}

func TestExtractPinnedCoreWritesOnlyExpectedPrivateRegularFile(t *testing.T) {
	t.Parallel()

	body := []byte("exact sing-box executable")
	archiveBytes := coreArchiveFixture(t,
		coreArchiveMember{name: "sing-box-" + pinnedSingBoxVersion + "-darwin-arm64/", kind: tar.TypeDir},
		coreArchiveMember{name: "sing-box-" + pinnedSingBoxVersion + "-darwin-arm64/LICENSE", kind: tar.TypeReg, body: []byte("license")},
		coreArchiveMember{name: "sing-box-" + pinnedSingBoxVersion + "-darwin-arm64/sing-box", kind: tar.TypeReg, body: body},
	)
	archive := mustVerifyCoreArchive(t, archiveBytes)
	destination := privateDirectory(t)
	executable, err := extractPinnedCore(archive, destination, "darwin", "arm64")
	if err != nil {
		t.Fatalf("extractPinnedCore() failed: %v", err)
	}
	wantPath := filepath.Join(destination, "sing-box")
	if executable != wantPath {
		t.Fatalf("executable path = %q, want %q", executable, wantPath)
	}
	entries, err := os.ReadDir(destination)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Name() != "sing-box" {
		t.Fatalf("extracted entries = %#v, want only sing-box", entries)
	}
	got, err := os.ReadFile(executable)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, body) {
		t.Fatalf("executable bytes = %q, want %q", got, body)
	}
	info, err := os.Lstat(executable)
	if err != nil {
		t.Fatal(err)
	}
	if !info.Mode().IsRegular() || info.Mode().Perm() != 0o700 {
		t.Fatalf("executable mode = %v, want regular 0700", info.Mode())
	}
}

func TestExtractPinnedCoreRejectsUnsafeMembersAndExistingPaths(t *testing.T) {
	t.Parallel()

	wanted := "sing-box-" + pinnedSingBoxVersion + "-linux-amd64/sing-box"
	tests := []struct {
		name        string
		members     []coreArchiveMember
		preexisting bool
	}{
		{
			name: "path traversal",
			members: []coreArchiveMember{
				{name: "../sing-box", kind: tar.TypeReg, body: []byte("malicious")},
				{name: wanted, kind: tar.TypeReg, body: []byte("expected")},
			},
		},
		{
			name: "expected symlink",
			members: []coreArchiveMember{
				{name: wanted, kind: tar.TypeSymlink, linkName: "/bin/sh"},
			},
		},
		{
			name: "duplicate expected member",
			members: []coreArchiveMember{
				{name: wanted, kind: tar.TypeReg, body: []byte("first")},
				{name: wanted, kind: tar.TypeReg, body: []byte("second")},
			},
		},
		{
			name:        "preexisting destination symlink",
			preexisting: true,
			members: []coreArchiveMember{
				{name: wanted, kind: tar.TypeReg, body: []byte("expected")},
			},
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			destination := privateDirectory(t)
			outside := filepath.Join(privateDirectory(t), "outside")
			if err := os.WriteFile(outside, []byte("unchanged"), 0o600); err != nil {
				t.Fatal(err)
			}
			if test.preexisting {
				if err := os.Symlink(outside, filepath.Join(destination, "sing-box")); err != nil {
					t.Fatal(err)
				}
			}
			archive := mustVerifyCoreArchive(t, coreArchiveFixture(t, test.members...))
			if executable, err := extractPinnedCore(archive, destination, "linux", "amd64"); executable != "" || err == nil {
				t.Fatalf("extractPinnedCore() = %q, %v, want rejection", executable, err)
			}
			outsideBytes, err := os.ReadFile(outside)
			if err != nil {
				t.Fatal(err)
			}
			if string(outsideBytes) != "unchanged" {
				t.Fatalf("outside file changed to %q", outsideBytes)
			}
			entry, err := os.Lstat(filepath.Join(destination, "sing-box"))
			if test.preexisting {
				if err != nil || entry.Mode()&os.ModeSymlink == 0 {
					t.Fatalf("preexisting symlink was replaced: %v, %v", entry, err)
				}
			} else if !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("failed extraction left executable behind: %v, %v", entry, err)
			}
		})
	}
}

type coreArchiveMember struct {
	name     string
	kind     byte
	body     []byte
	linkName string
}

func coreArchiveFixture(t *testing.T, members ...coreArchiveMember) []byte {
	t.Helper()
	var output bytes.Buffer
	compressed := gzip.NewWriter(&output)
	archive := tar.NewWriter(compressed)
	for _, member := range members {
		header := &tar.Header{
			Name:     member.name,
			Mode:     0o777,
			Size:     int64(len(member.body)),
			Typeflag: member.kind,
			Linkname: member.linkName,
		}
		if err := archive.WriteHeader(header); err != nil {
			t.Fatal(err)
		}
		if len(member.body) > 0 {
			if _, err := archive.Write(member.body); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := archive.Close(); err != nil {
		t.Fatal(err)
	}
	if err := compressed.Close(); err != nil {
		t.Fatal(err)
	}
	return output.Bytes()
}

func mustVerifyCoreArchive(t *testing.T, content []byte) verifiedCoreArchive {
	t.Helper()
	digest := sha256.Sum256(content)
	archive, err := verifyCoreArchive(content, hex.EncodeToString(digest[:]))
	if err != nil {
		t.Fatal(err)
	}
	return archive
}

func runPinnedCoreStdinCheck(executable, directory string, config []byte) (string, error) {
	command := exec.Command(executable, "check", "-c", "stdin")
	command.Dir = directory
	command.Env = []string{}
	command.Stdin = bytes.NewReader(config)
	output := newBoundedBuffer(maxCoreOutputBytes)
	command.Stdout = output
	command.Stderr = output
	err := command.Run()
	return string(output.Bytes()), err
}

type verifiedCoreArchive struct {
	bytes  []byte
	digest [sha256.Size]byte
}

func verifyCoreArchive(content []byte, expected string) (verifiedCoreArchive, error) {
	exactBytes := append([]byte(nil), content...)
	digest := sha256.Sum256(exactBytes)
	if hex.EncodeToString(digest[:]) != expected {
		return verifiedCoreArchive{}, fmt.Errorf("SHA-256 mismatch")
	}
	return verifiedCoreArchive{bytes: exactBytes, digest: digest}, nil
}

func downloadPinnedCore(t *testing.T) string {
	t.Helper()
	target := runtime.GOOS + "/" + runtime.GOARCH
	artifact, ok := pinnedCoreArtifacts[target]
	if !ok {
		t.Skipf("no pinned sing-box artifact for %s", target)
	}

	archive, err := fetchCoreArchive(artifact)
	if err != nil {
		t.Fatalf("download pinned sing-box: %v", err)
	}
	extractDirectory := privateCoreIntegrationDirectory(t)
	executable, err := extractPinnedCore(archive, extractDirectory, runtime.GOOS, runtime.GOARCH)
	if err != nil {
		t.Fatalf("extract pinned sing-box: %v", err)
	}
	return executable
}

func privateCoreIntegrationDirectory(t *testing.T) string {
	t.Helper()
	directory := t.TempDir()
	if err := validatePrivateCoreIntegrationDirectory(directory); err == nil {
		return directory
	}

	base, err := os.Getwd()
	if err != nil || !filepath.IsAbs(base) {
		t.Fatalf("locate trusted temporary base: %v", err)
	}
	if err := inspectTrustedParents(base); err != nil {
		t.Fatalf("test working directory is not trusted: %v", err)
	}
	directory, err = os.MkdirTemp(base, ".tuibox-core-integration-*")
	if err != nil {
		t.Fatalf("create private core directory: %v", err)
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(directory); err != nil {
			t.Errorf("remove private core directory: %v", err)
		}
	})
	if err := validatePrivateCoreIntegrationDirectory(directory); err != nil {
		t.Fatalf("private core directory is invalid: %v", err)
	}
	return directory
}

func validatePrivateCoreIntegrationDirectory(directory string) error {
	if err := os.Chmod(directory, 0o700); err != nil {
		return err
	}
	info, err := os.Lstat(directory)
	if err != nil || !validRuntimeRootInfo(info) {
		return ErrInvalidExecutable
	}
	return inspectTrustedParents(directory)
}

func fetchCoreArchive(artifact coreArtifact) (verifiedCoreArchive, error) {
	return fetchCoreArchiveWithClient(&http.Client{}, artifact, maxCoreArchiveBytes)
}

func fetchCoreArchiveWithClient(client *http.Client, artifact coreArtifact, limit int64) (verifiedCoreArchive, error) {
	if client == nil || limit < 1 || limit > maxCoreArchiveBytes {
		return verifiedCoreArchive{}, fmt.Errorf("invalid core archive request")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, artifact.URL, nil)
	if err != nil {
		return verifiedCoreArchive{}, err
	}
	if request.URL.Scheme != "https" {
		return verifiedCoreArchive{}, fmt.Errorf("core archive URL must use HTTPS")
	}

	boundedClient := *client
	boundedClient.Timeout = 2 * time.Minute
	previousRedirectCheck := boundedClient.CheckRedirect
	boundedClient.CheckRedirect = func(request *http.Request, via []*http.Request) error {
		if request.URL.Scheme != "https" {
			return fmt.Errorf("redirected outside HTTPS")
		}
		if previousRedirectCheck != nil {
			return previousRedirectCheck(request, via)
		}
		if len(via) >= 10 {
			return fmt.Errorf("too many redirects")
		}
		return nil
	}
	response, err := boundedClient.Do(request)
	if err != nil {
		return verifiedCoreArchive{}, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return verifiedCoreArchive{}, fmt.Errorf("unexpected HTTP status %d", response.StatusCode)
	}
	if response.ContentLength > limit {
		return verifiedCoreArchive{}, fmt.Errorf("core archive exceeds size limit")
	}
	content, err := io.ReadAll(io.LimitReader(response.Body, limit+1))
	if err != nil {
		return verifiedCoreArchive{}, err
	}
	if int64(len(content)) > limit {
		return verifiedCoreArchive{}, fmt.Errorf("core archive exceeds size limit")
	}
	return verifyCoreArchive(content, artifact.SHA256)
}

func extractPinnedCore(archive verifiedCoreArchive, destination, goos, goarch string) (_ string, returnErr error) {
	if sha256.Sum256(archive.bytes) != archive.digest {
		return "", fmt.Errorf("verified core archive changed")
	}
	before, err := os.Lstat(destination)
	if err != nil || !validRuntimeRootInfo(before) {
		return "", fmt.Errorf("invalid core extraction directory")
	}
	root, err := os.OpenRoot(destination)
	if err != nil {
		return "", err
	}
	defer root.Close()
	after, err := root.Stat(".")
	if err != nil || !validRuntimeRootInfo(after) || !os.SameFile(before, after) {
		return "", fmt.Errorf("core extraction directory changed")
	}

	created := false
	defer func() {
		if returnErr != nil && created {
			_ = root.Remove("sing-box")
		}
	}()
	compressed, err := gzip.NewReader(bytes.NewReader(archive.bytes))
	if err != nil {
		return "", err
	}
	defer compressed.Close()

	wanted := fmt.Sprintf("sing-box-%s-%s-%s/sing-box", pinnedSingBoxVersion, goos, goarch)
	reader := tar.NewReader(compressed)
	var total int64
	extracted := false
	for {
		header, err := reader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return "", err
		}
		entryName := header.Name
		if header.Typeflag == tar.TypeDir {
			entryName = strings.TrimSuffix(entryName, "/")
		}
		clean := path.Clean(entryName)
		if clean == "." || path.IsAbs(entryName) || clean != entryName || clean == ".." || strings.HasPrefix(clean, "../") || strings.Contains(entryName, "\\") {
			return "", fmt.Errorf("unsafe archive path")
		}
		if header.Size < 0 || total > maxCoreExtractBytes-header.Size {
			return "", fmt.Errorf("archive exceeds extraction limit")
		}
		total += header.Size
		switch header.Typeflag {
		case tar.TypeDir, tar.TypeReg:
		default:
			return "", fmt.Errorf("unsupported archive entry")
		}
		if clean != wanted {
			continue
		}
		if header.Typeflag != tar.TypeReg || header.Size < 1 || extracted {
			return "", fmt.Errorf("invalid core archive member")
		}

		output, err := root.OpenFile("sing-box", os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if err != nil {
			return "", err
		}
		created = true
		written, copyErr := io.CopyN(output, reader, header.Size)
		var chmodErr error
		if copyErr == nil && written == header.Size {
			chmodErr = output.Chmod(0o700)
		}
		syncErr := output.Sync()
		closeErr := output.Close()
		if chmodErr != nil || copyErr != nil || syncErr != nil || closeErr != nil || written != header.Size {
			return "", fmt.Errorf("extract core executable")
		}
		extracted = true
	}
	if !extracted {
		return "", fmt.Errorf("core executable missing from archive")
	}
	info, err := root.Lstat("sing-box")
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o700 {
		return "", fmt.Errorf("invalid extracted core executable")
	}
	owner, ok := fileOwnerID(info)
	if !ok || owner != os.Geteuid() {
		return "", fmt.Errorf("invalid extracted core executable owner")
	}
	return filepath.Join(destination, "sing-box"), nil
}

func assertPinnedCoreVersion(t *testing.T, executable string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, executable, "version")
	command.Env = []string{}
	output := newBoundedBuffer(maxCoreOutputBytes)
	command.Stdout = output
	command.Stderr = output
	if err := command.Run(); err != nil {
		t.Fatalf("read sing-box version: %v", err)
	}
	if !strings.Contains(string(output.Bytes()), "sing-box version "+pinnedSingBoxVersion) {
		t.Fatalf("sing-box executable is not pinned version %s", pinnedSingBoxVersion)
	}
}

type namedEndpoint struct {
	name     string
	endpoint domain.Endpoint
}

func integrationEndpoints() []namedEndpoint {
	vless := validEndpoint()

	vlessWebSocket := validEndpoint()
	vlessWebSocket.Transport = domain.TransportOptions{Type: domain.TransportWebSocket, Path: "/vless", Host: "proxy.example.com"}

	vlessGRPC := validEndpoint()
	vlessGRPC.Transport = domain.TransportOptions{Type: domain.TransportGRPC, ServiceName: "vless-service"}

	vlessHTTPUpgrade := validEndpoint()
	vlessHTTPUpgrade.Transport = domain.TransportOptions{Type: domain.TransportHTTPUpgrade, Path: "/upgrade", Host: "proxy.example.com"}

	vlessReality := validEndpoint()
	vlessReality.VLESSOptions = &domain.VLESSOptions{Flow: domain.VLESSFlowXTLSRPRXVision, PacketEncoding: domain.PacketEncodingXUDP}
	vlessReality.TLS.UTLSFingerprint = domain.UTLSFingerprintChrome
	vlessReality.TLS.Reality = &domain.RealityClientOptions{
		PublicKey: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
		ShortID:   "0123abcd",
	}

	vmess := validEndpoint()
	vmess.Protocol = domain.ProtocolVMess
	vmess.VMessOptions = &domain.VMessOptions{Security: domain.VMessSecurityAuto, PacketEncoding: domain.PacketEncodingPacketAddr}

	trojan := validEndpoint()
	trojan.Protocol = domain.ProtocolTrojan
	trojan.UUID = ""
	trojan.Password = "trojan-password"
	trojan.Transport = domain.TransportOptions{Type: domain.TransportWebSocket, Path: "/trojan", Host: "proxy.example.com"}

	shadowsocks := validEndpoint()
	shadowsocks.Protocol = domain.ProtocolShadowsocks
	shadowsocks.UUID = ""
	shadowsocks.Password = "shadowsocks-password"
	shadowsocks.Method = "aes-256-gcm"
	shadowsocks.TLS = domain.TLSOptions{}
	shadowsocks.Transport = domain.TransportOptions{}

	hysteria2 := validEndpoint()
	hysteria2.Protocol = domain.ProtocolHysteria2
	hysteria2.UUID = ""
	hysteria2.Password = "hysteria-password"
	hysteria2.Transport = domain.TransportOptions{}
	hysteria2.Hysteria2Options = &domain.Hysteria2Options{
		ObfsType:     domain.Hysteria2ObfsSalamander,
		ObfsPassword: "hysteria-obfs-password",
		UpMbps:       100,
		DownMbps:     500,
	}

	tuic := validEndpoint()
	tuic.Protocol = domain.ProtocolTUIC
	tuic.Password = "tuic-password"
	tuic.Transport = domain.TransportOptions{}
	tuic.TUICOptions = &domain.TUICOptions{
		CongestionControl: domain.TUICCongestionBBR,
		UDPRelayMode:      domain.TUICUDPRelayQUIC,
		ZeroRTT:           true,
	}

	return []namedEndpoint{
		{name: "vless-tcp", endpoint: vless},
		{name: "vless-websocket", endpoint: vlessWebSocket},
		{name: "vless-grpc", endpoint: vlessGRPC},
		{name: "vless-httpupgrade", endpoint: vlessHTTPUpgrade},
		{name: "vless-reality", endpoint: vlessReality},
		{name: "vmess", endpoint: vmess},
		{name: "trojan", endpoint: trojan},
		{name: "shadowsocks", endpoint: shadowsocks},
		{name: "hysteria2", endpoint: hysteria2},
		{name: "tuic", endpoint: tuic},
	}
}

package core

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
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

func TestGeneratedConfigsPassPinnedSingBoxCheck(t *testing.T) {
	executable := os.Getenv("TUIBOX_SING_BOX")
	if executable == "" {
		if testing.Short() {
			t.Skip("pinned sing-box download disabled by -short")
		}
		executable = downloadPinnedCore(t)
	}
	assertPinnedCoreVersion(t, executable)

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
	if checks < 60 {
		t.Fatalf("core-check matrix ran %d checks, want at least 60", checks)
	}
}

func downloadPinnedCore(t *testing.T) string {
	t.Helper()
	target := runtime.GOOS + "/" + runtime.GOARCH
	artifact, ok := pinnedCoreArtifacts[target]
	if !ok {
		t.Skipf("no pinned sing-box artifact for %s", target)
	}

	cacheRoot, err := os.UserCacheDir()
	if err != nil {
		cacheRoot = os.TempDir()
	}
	cacheDirectory := filepath.Join(cacheRoot, "tuibox", "core-test", pinnedSingBoxVersion)
	if err := os.MkdirAll(cacheDirectory, 0o700); err != nil {
		t.Fatalf("create core cache: %v", err)
	}
	if err := os.Chmod(cacheDirectory, 0o700); err != nil {
		t.Fatalf("secure core cache: %v", err)
	}
	archivePath := filepath.Join(cacheDirectory, filepath.Base(artifact.URL))
	if err := verifyFileSHA256(archivePath, artifact.SHA256); err != nil {
		if err := fetchCoreArchive(archivePath, artifact); err != nil {
			t.Fatalf("download pinned sing-box: %v", err)
		}
	}

	extractDirectory, err := os.MkdirTemp(cacheDirectory, ".extract-*")
	if err != nil {
		t.Fatalf("create core extraction directory: %v", err)
	}
	if err := os.Chmod(extractDirectory, 0o700); err != nil {
		os.RemoveAll(extractDirectory)
		t.Fatalf("secure core extraction directory: %v", err)
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(extractDirectory); err != nil {
			t.Errorf("remove core extraction directory: %v", err)
		}
	})
	executable, err := extractPinnedCore(archivePath, extractDirectory, runtime.GOOS, runtime.GOARCH)
	if err != nil {
		t.Fatalf("extract pinned sing-box: %v", err)
	}
	return executable
}

func fetchCoreArchive(destination string, artifact coreArtifact) error {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, artifact.URL, nil)
	if err != nil {
		return err
	}
	client := &http.Client{
		Timeout: 2 * time.Minute,
		CheckRedirect: func(request *http.Request, _ []*http.Request) error {
			if request.URL.Scheme != "https" {
				return fmt.Errorf("redirected outside HTTPS")
			}
			return nil
		},
	}
	response, err := client.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected HTTP status %d", response.StatusCode)
	}

	temporary, err := os.CreateTemp(filepath.Dir(destination), ".sing-box-download-*")
	if err != nil {
		return err
	}
	temporaryName := temporary.Name()
	defer os.Remove(temporaryName)
	if err := temporary.Chmod(0o600); err != nil {
		temporary.Close()
		return err
	}
	written, copyErr := io.Copy(temporary, io.LimitReader(response.Body, maxCoreArchiveBytes+1))
	syncErr := temporary.Sync()
	closeErr := temporary.Close()
	if copyErr != nil || syncErr != nil || closeErr != nil {
		return fmt.Errorf("write core archive")
	}
	if written > maxCoreArchiveBytes {
		return fmt.Errorf("core archive exceeds size limit")
	}
	if err := verifyFileSHA256(temporaryName, artifact.SHA256); err != nil {
		return err
	}
	return os.Rename(temporaryName, destination)
}

func verifyFileSHA256(name, expected string) error {
	file, err := os.Open(name)
	if err != nil {
		return err
	}
	defer file.Close()
	hash := sha256.New()
	if _, err := io.Copy(hash, io.LimitReader(file, maxCoreArchiveBytes+1)); err != nil {
		return err
	}
	actual := hex.EncodeToString(hash.Sum(nil))
	if actual != expected {
		return fmt.Errorf("SHA-256 mismatch")
	}
	return nil
}

func extractPinnedCore(archivePath, destination, goos, goarch string) (string, error) {
	archive, err := os.Open(archivePath)
	if err != nil {
		return "", err
	}
	defer archive.Close()
	compressed, err := gzip.NewReader(archive)
	if err != nil {
		return "", err
	}
	defer compressed.Close()

	wanted := fmt.Sprintf("sing-box-%s-%s-%s/sing-box", pinnedSingBoxVersion, goos, goarch)
	reader := tar.NewReader(compressed)
	var total int64
	var executable string
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
		if header.Typeflag != tar.TypeReg || executable != "" {
			return "", fmt.Errorf("invalid core archive member")
		}
		executable = filepath.Join(destination, "sing-box")
		output, err := os.OpenFile(executable, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o700)
		if err != nil {
			return "", err
		}
		written, copyErr := io.Copy(output, io.LimitReader(reader, header.Size+1))
		syncErr := output.Sync()
		closeErr := output.Close()
		if copyErr != nil || syncErr != nil || closeErr != nil || written != header.Size {
			return "", fmt.Errorf("extract core executable")
		}
	}
	if executable == "" {
		return "", fmt.Errorf("core executable missing from archive")
	}
	return executable, nil
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

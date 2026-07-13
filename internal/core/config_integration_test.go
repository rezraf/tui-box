package core

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/rezraf/tui-box/internal/domain"
)

const pinnedSingBoxVersion = "1.13.14"

func TestGeneratedConfigsPassPinnedSingBoxCheck(t *testing.T) {
	executable := os.Getenv("TUIBOX_SING_BOX")
	if executable == "" {
		t.Skip("set TUIBOX_SING_BOX to run pinned sing-box compatibility checks")
	}
	runner, err := NewRunner(executable)
	if err != nil {
		t.Fatalf("NewRunner() rejected TUIBOX_SING_BOX: %v", err)
	}
	assertPinnedCoreVersion(t, executable)

	for _, testEndpoint := range integrationEndpoints() {
		testEndpoint := testEndpoint
		for _, mode := range []domain.ConnectionMode{domain.ConnectionModeProxy, domain.ConnectionModeTUN} {
			mode := mode
			for _, route := range []domain.RouteMode{domain.RouteModeGlobal, domain.RouteModeRule, domain.RouteModeDirect} {
				route := route
				name := fmt.Sprintf("%s/%s/%s", testEndpoint.name, mode, route)
				t.Run(name, func(t *testing.T) {
					endpoint := testEndpoint.endpoint
					request := ConnectionRequest{Mode: mode, Route: route, Endpoint: &endpoint, UID: os.Getuid(), GID: os.Getgid()}
					if request.Mode == domain.ConnectionModeProxy && request.UID == 0 {
						t.Skip("proxy identity validation requires a non-root test user")
					}
					if route == domain.RouteModeDirect {
						request.Endpoint = nil
					}
					path := secureConfigPath(t)
					if err := runner.WriteConfig(path, request); err != nil {
						t.Fatalf("WriteConfig() failed: %v", err)
					}
					ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
					defer cancel()
					if err := runner.Check(ctx, path); err != nil {
						t.Fatalf("sing-box check failed: %v", err)
					}
				})
			}
		}
	}
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
		t.Fatalf("TUIBOX_SING_BOX is not pinned version %s", pinnedSingBoxVersion)
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

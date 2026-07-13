package state

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rezraf/tui-box/internal/domain"
)

func TestStoreRejectsDuplicateAndCaseCollidingFieldsAtEveryStructDepthWithoutRewrite(t *testing.T) {
	t.Parallel()

	content, err := json.Marshal(duplicateFieldSnapshot())
	if err != nil {
		t.Fatalf("json.Marshal() fixture error = %v", err)
	}

	targets := []struct {
		name   string
		anchor string
		field  string
		value  string
	}{
		{name: "snapshot", anchor: `"schema_version":1`, field: "schema_version", value: "1"},
		{name: "settings", anchor: `"telemetry_enabled":true`, field: "telemetry_enabled", value: "true"},
		{name: "subscription", anchor: `"id":"subscription-a"`, field: "id", value: `"subscription-a"`},
		{name: "endpoint", anchor: `"id":"vless-endpoint"`, field: "id", value: `"vless-endpoint"`},
		{name: "TLS options", anchor: `"tls":{"enabled":true,"server_name":"vless.example.com"`, field: "enabled", value: "true"},
		{name: "Reality options", anchor: `"reality":{"public_key":"AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8"`, field: "public_key", value: `"AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8"`},
		{name: "transport options", anchor: `"transport":{"type":"tcp"`, field: "type", value: `"tcp"`},
		{name: "VLESS options", anchor: `"vless_options":{"flow":"xtls-rprx-vision"`, field: "flow", value: `"xtls-rprx-vision"`},
		{name: "VMess options", anchor: `"vmess_options":{"security":"auto"`, field: "security", value: `"auto"`},
		{name: "Hysteria2 options", anchor: `"hysteria2_options":{"obfs_type":"salamander"`, field: "obfs_type", value: `"salamander"`},
		{name: "TUIC options", anchor: `"tuic_options":{"congestion_control":"bbr"`, field: "congestion_control", value: `"bbr"`},
	}
	collisions := []struct {
		name string
		key  func(string) string
	}{
		{name: "exact duplicate", key: func(field string) string { return field }},
		{name: "encoding/json case collision", key: strings.ToUpper},
	}

	for _, target := range targets {
		target := target
		t.Run(target.name, func(t *testing.T) {
			t.Parallel()
			for _, collision := range collisions {
				collision := collision
				t.Run(collision.name, func(t *testing.T) {
					t.Parallel()
					duplicate := `,"` + collision.key(target.field) + `":` + target.value
					malformed := insertDuplicateField(t, content, target.anchor, duplicate)
					assertRejectedStateFileIsNotRewritten(t, malformed)
				})
			}
		})
	}
}

func duplicateFieldSnapshot() Snapshot {
	const (
		subscriptionID = "subscription-a"
		uuid           = "550e8400-e29b-41d4-a716-446655440000"
	)
	return Snapshot{
		SchemaVersion: CurrentSchemaVersion,
		Subscriptions: []domain.Subscription{{
			ID: subscriptionID, Name: "Subscription A", SecretRef: "secret-a",
			Format: domain.SubscriptionFormatURIList, RefreshIntervalSeconds: 900,
		}},
		Endpoints: []domain.Endpoint{
			{
				ID: "vless-endpoint", SubscriptionID: subscriptionID, Name: "VLESS",
				Protocol: domain.ProtocolVLESS, Host: "vless.example.com", Port: 443, UUID: uuid,
				TLS: domain.TLSOptions{
					Enabled: true, ServerName: "vless.example.com",
					Reality: &domain.RealityClientOptions{
						PublicKey: "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8",
						ShortID:   "abcd",
					},
				},
				Transport:    domain.TransportOptions{Type: domain.TransportTCP},
				VLESSOptions: &domain.VLESSOptions{Flow: domain.VLESSFlowXTLSRPRXVision, PacketEncoding: domain.PacketEncodingXUDP},
			},
			{
				ID: "vmess-endpoint", SubscriptionID: subscriptionID, Name: "VMess",
				Protocol: domain.ProtocolVMess, Host: "vmess.example.com", Port: 443, UUID: uuid,
				Transport:    domain.TransportOptions{Type: domain.TransportWebSocket, Path: "/vmess"},
				VMessOptions: &domain.VMessOptions{Security: domain.VMessSecurityAuto, AlterID: 1, PacketEncoding: domain.PacketEncodingXUDP},
			},
			{
				ID: "hysteria2-endpoint", SubscriptionID: subscriptionID, Name: "Hysteria2",
				Protocol: domain.ProtocolHysteria2, Host: "hysteria.example.com", Port: 443, Password: "secret",
				TLS: domain.TLSOptions{Enabled: true, ServerName: "hysteria.example.com"},
				Hysteria2Options: &domain.Hysteria2Options{
					ObfsType: domain.Hysteria2ObfsSalamander, ObfsPassword: "obfs-secret", UpMbps: 100, DownMbps: 200,
				},
			},
			{
				ID: "tuic-endpoint", SubscriptionID: subscriptionID, Name: "TUIC",
				Protocol: domain.ProtocolTUIC, Host: "tuic.example.com", Port: 443, UUID: uuid, Password: "secret",
				TLS:         domain.TLSOptions{Enabled: true, ServerName: "tuic.example.com"},
				TUICOptions: &domain.TUICOptions{CongestionControl: domain.TUICCongestionBBR, UDPRelayMode: domain.TUICUDPRelayQUIC, ZeroRTT: true},
			},
		},
		Settings: Settings{TelemetryEnabled: true},
	}
}

func insertDuplicateField(t *testing.T, content []byte, anchor, duplicate string) []byte {
	t.Helper()
	if count := bytes.Count(content, []byte(anchor)); count != 1 {
		t.Fatalf("fixture anchor %q occurs %d times, want 1", anchor, count)
	}
	return bytes.Replace(content, []byte(anchor), []byte(anchor+duplicate), 1)
}

func assertRejectedStateFileIsNotRewritten(t *testing.T, content []byte) {
	t.Helper()
	directory := filepath.Join(t.TempDir(), "state")
	store, err := NewStore(directory)
	if err != nil {
		t.Fatalf("NewStore() error = %v", err)
	}
	defer store.Close()

	path := filepath.Join(directory, StateFileName)
	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	before, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat() before Update error = %v", err)
	}
	callbackCalled := false
	if err := store.Update(func(*Snapshot) error {
		callbackCalled = true
		return nil
	}); err == nil {
		t.Fatal("Update() accepted colliding persisted fields")
	}
	if callbackCalled {
		t.Fatal("Update() decoded colliding persisted fields before rejection")
	}
	after, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat() after Update error = %v", err)
	}
	if !os.SameFile(before, after) {
		t.Fatal("rejected state file was replaced")
	}
	persisted, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile() after Update error = %v", err)
	}
	if !bytes.Equal(persisted, content) {
		t.Fatal("rejected state file content changed")
	}
}

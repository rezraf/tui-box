package tui

import (
	"context"
	"strings"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/rezraf/tui-box/internal/app"
	"github.com/rezraf/tui-box/internal/domain"
	"github.com/rezraf/tui-box/internal/latency"
	"github.com/rezraf/tui-box/internal/rpc"
)

func TestViewKeepsCursorAndStatusVisibleWithinTerminal(t *testing.T) {
	model := modelWithServers(t, "server-0", "server-1", "server-2", "server-3", "server-4", "server-5", "server-6", "server-7", "server-8")
	model.cursor = 7
	model.selection = selectionAuto
	model.mode = domain.ConnectionModeProxy
	model.route = domain.RouteModeRule
	model.status = rpc.SessionStatus{State: domain.ConnectionStatusConnected, Mode: domain.ConnectionModeProxy, Route: domain.RouteModeRule}
	model.servers[7].Latency = &latency.Result{Status: latency.StatusSuccess, Duration: 23 * time.Millisecond}

	updated, _ := model.Update(tea.WindowSizeMsg{Width: 42, Height: 12})
	view := updated.(Model).View()
	if !strings.Contains(view, "server-7") || strings.Contains(view, "server-0") {
		t.Fatalf("viewport did not keep cursor visible:\n%s", view)
	}
	for _, fragment := range []string{"Status: connected", "Selection: Auto Best", "Mode: proxy", "Route: rule", "23ms"} {
		if !strings.Contains(view, fragment) {
			t.Fatalf("view missing %q:\n%s", fragment, view)
		}
	}
	lines := strings.Split(strings.TrimSuffix(view, "\n"), "\n")
	if len(lines) > 12 {
		t.Fatalf("view height = %d, want <= 12:\n%s", len(lines), view)
	}
	for index, line := range lines {
		if width := lipgloss.Width(line); width > 42 {
			t.Fatalf("line %d width = %d, want <= 42: %q", index, width, line)
		}
	}
}

func TestSecretInputViewIsMaskedAndNeverRendersURL(t *testing.T) {
	model := modelWithServers(t)
	model.input = inputURL
	model.inputName = "Primary"
	secret := "https://user:password@provider.example/private?token=value"
	model.secretInput = []rune(secret)
	model.width = 80
	model.height = 20

	view := model.View()
	if strings.Contains(view, secret) || strings.Contains(view, "provider.example") || strings.Contains(view, "password") || strings.Contains(view, "token=value") {
		t.Fatalf("secret input leaked in view: %q", view)
	}
	if !strings.Contains(view, strings.Repeat("•", len([]rune(secret)))) {
		t.Fatalf("view did not render a full masked value: %q", view)
	}
}

func TestHostileProjectedLabelsNeverReachView(t *testing.T) {
	secret := "https://user:password@proxy.example.com:8443/private?token=value SecretRef TLS transport RPC"
	service := &fakeApplication{
		servers: []app.ServerView{{ID: "safe-id", Name: secret, Protocol: domain.ProtocolVLESS}},
		status:  rpc.SessionStatus{State: domain.ConnectionStatusConnected, Mode: domain.ConnectionModeProxy, Route: domain.RouteModeGlobal},
	}
	adapter, err := NewAdapter(service)
	if err != nil {
		t.Fatalf("NewAdapter: %v", err)
	}
	model, err := NewModel(context.Background(), adapter)
	if err != nil {
		t.Fatalf("NewModel: %v", err)
	}
	updated, _ := model.Update(model.Init()())
	model = updated.(Model)
	model.width = 80
	model.height = 20

	view := model.View()
	if !strings.Contains(view, "Endpoint") {
		t.Fatalf("fallback label missing: %q", view)
	}
	for _, forbidden := range []string{"https://", "proxy.example.com", "password", "token=value", "SecretRef", "TLS", "transport", "RPC"} {
		if strings.Contains(view, forbidden) {
			t.Fatalf("view leaked %q: %q", forbidden, view)
		}
	}
}

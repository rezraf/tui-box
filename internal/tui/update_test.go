package tui

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/rezraf/tui-box/internal/app"
	"github.com/rezraf/tui-box/internal/domain"
	"github.com/rezraf/tui-box/internal/rpc"
)

func TestQuitKeysReturnBubbleTeaQuitCommand(t *testing.T) {
	for _, key := range []tea.KeyMsg{keyRune('q'), {Type: tea.KeyCtrlC}} {
		model := modelWithServers(t, "one")
		_, command := model.Update(key)
		if command == nil {
			t.Fatalf("key %q returned no quit command", key.String())
		}
		if _, ok := command().(tea.QuitMsg); !ok {
			t.Fatalf("key %q command did not return QuitMsg", key.String())
		}
	}
}

func TestControlCQuitsAndClearsSecretDuringInput(t *testing.T) {
	model := modelWithServers(t)
	model.input = inputURL
	model.inputName = "Primary"
	model.secretInput = []rune("https://provider.example/private-token")
	secretBuffer := model.secretInput

	updated, command := model.Update(tea.KeyMsg{Type: tea.KeyCtrlC})
	model = updated.(Model)
	if command == nil {
		t.Fatal("Ctrl+C during secret input returned no quit command")
	}
	if _, ok := command().(tea.QuitMsg); !ok {
		t.Fatal("Ctrl+C during secret input did not return QuitMsg")
	}
	if model.input != inputNone || model.inputName != "" || len(model.secretInput) != 0 {
		t.Fatalf("secret input retained on quit: %#v", model)
	}
	for index, character := range secretBuffer {
		if character != 0 {
			t.Fatalf("secret rune %d was not cleared on quit", index)
		}
	}
}

func TestQuitCancelsInFlightActionContext(t *testing.T) {
	parent, cancelParent := context.WithCancel(context.Background())
	defer cancelParent()
	backend := &cancelAwareBackend{
		started:  make(chan struct{}),
		canceled: make(chan struct{}),
	}
	model, err := NewModel(parent, backend)
	if err != nil {
		t.Fatalf("NewModel: %v", err)
	}

	updated, action := model.Update(keyRune('u'))
	model = updated.(Model)
	if action == nil {
		t.Fatal("refresh returned no command")
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = action()
	}()
	select {
	case <-backend.started:
	case <-time.After(time.Second):
		t.Fatal("refresh did not start")
	}

	_, quit := model.Update(keyRune('q'))
	if quit == nil {
		t.Fatal("quit returned no command")
	}
	select {
	case <-backend.canceled:
	case <-time.After(100 * time.Millisecond):
		t.Fatal("quit did not cancel the in-flight refresh")
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("canceled refresh did not return")
	}
}

func TestStatusLineKeepsActiveSessionSeparateFromNextSelection(t *testing.T) {
	model := modelWithServers(t, "one")
	model.status = rpc.SessionStatus{
		State: domain.ConnectionStatusConnected,
		Mode:  domain.ConnectionModeProxy,
		Route: domain.RouteModeRule,
	}
	model.mode = domain.ConnectionModeTUN
	model.route = domain.RouteModeGlobal

	line := model.statusLine()
	for _, fragment := range []string{"Status: connected", "Mode: proxy", "Route: rule", "Next: tun/global"} {
		if !strings.Contains(line, fragment) {
			t.Fatalf("status line %q missing %q", line, fragment)
		}
	}
}

func TestNavigationSupportsArrowsAndJKWithWrapping(t *testing.T) {
	model := modelWithServers(t, "one", "two", "three")

	model = updateKey(t, model, tea.KeyMsg{Type: tea.KeyDown})
	if model.cursor != 1 {
		t.Fatalf("down cursor = %d, want 1", model.cursor)
	}
	model = updateKey(t, model, keyRune('j'))
	if model.cursor != 2 {
		t.Fatalf("j cursor = %d, want 2", model.cursor)
	}
	model = updateKey(t, model, tea.KeyMsg{Type: tea.KeyDown})
	if model.cursor != 0 {
		t.Fatalf("wrapped down cursor = %d, want 0", model.cursor)
	}
	model = updateKey(t, model, tea.KeyMsg{Type: tea.KeyUp})
	if model.cursor != 2 {
		t.Fatalf("wrapped up cursor = %d, want 2", model.cursor)
	}
	model = updateKey(t, model, keyRune('k'))
	if model.cursor != 1 {
		t.Fatalf("k cursor = %d, want 1", model.cursor)
	}
}

func TestSelectionSwitchesBetweenManualAndAutoBest(t *testing.T) {
	model := modelWithServers(t, "one", "two")
	model.cursor = 1

	model = updateKey(t, model, tea.KeyMsg{Type: tea.KeyEnter})
	if model.selection != selectionManual || model.selectedID != "two" {
		t.Fatalf("manual selection = %q %q", model.selection, model.selectedID)
	}
	model = updateKey(t, model, keyRune('a'))
	if model.selection != selectionAuto || model.selectedID != "" {
		t.Fatalf("auto selection = %q %q", model.selection, model.selectedID)
	}
}

func TestModeAndRouteKeysCycleFrozenValues(t *testing.T) {
	model := modelWithServers(t, "one")
	if model.mode != domain.ConnectionModeTUN || model.route != domain.RouteModeGlobal {
		t.Fatalf("defaults = mode %q route %q", model.mode, model.route)
	}

	model = updateKey(t, model, keyRune('m'))
	if model.mode != domain.ConnectionModeProxy {
		t.Fatalf("mode after m = %q", model.mode)
	}
	model = updateKey(t, model, keyRune('m'))
	if model.mode != domain.ConnectionModeTUN {
		t.Fatalf("wrapped mode = %q", model.mode)
	}

	for _, want := range []domain.RouteMode{domain.RouteModeRule, domain.RouteModeDirect, domain.RouteModeGlobal} {
		model = updateKey(t, model, keyRune('r'))
		if model.route != want {
			t.Fatalf("route after r = %q, want %q", model.route, want)
		}
	}
}

func TestServerReloadFallsBackToAutoWhenManualSelectionDisappears(t *testing.T) {
	service := &fakeApplication{servers: []app.ServerView{{ID: "remaining", Name: "Remaining", Protocol: domain.ProtocolVLESS}}}
	model := modelForService(t, service)
	model.servers = []Server{
		{ID: "removed", Name: "Removed", Protocol: domain.ProtocolVLESS},
		{ID: "remaining", Name: "Remaining", Protocol: domain.ProtocolVLESS},
	}
	model.selection = selectionManual
	model.selectedID = "removed"

	updated, command := model.Update(keyRune('u'))
	model = updated.(Model)
	if command == nil {
		t.Fatal("refresh returned no command")
	}
	updated, _ = model.Update(command())
	model = updated.(Model)

	if model.selection != selectionAuto || model.selectedID != "" {
		t.Fatalf("selection after removal = %q %q, want auto with no stale ID", model.selection, model.selectedID)
	}
}

func TestSideEffectActionsSerializeAndIgnoreStaleInitialResults(t *testing.T) {
	service := &fakeApplication{servers: []app.ServerView{{ID: "fresh", Name: "Fresh", Protocol: domain.ProtocolVLESS}}}
	model := modelForService(t, service)

	updated, refreshCommand := model.Update(keyRune('u'))
	model = updated.(Model)
	if refreshCommand == nil || !model.busy {
		t.Fatalf("refresh start = command %v busy %v", refreshCommand != nil, model.busy)
	}
	updated, overlappingCommand := model.Update(keyRune('l'))
	model = updated.(Model)
	if overlappingCommand != nil {
		t.Fatal("overlapping latency action returned a command")
	}

	stale := snapshotMsg{snapshot: snapshot{Servers: []Server{{ID: "stale", Name: "Stale", Protocol: domain.ProtocolVLESS}}}}
	updated, _ = model.Update(stale)
	model = updated.(Model)
	if len(model.servers) != 0 {
		t.Fatalf("stale initial result replaced servers: %#v", model.servers)
	}

	updated, _ = model.Update(refreshCommand())
	model = updated.(Model)
	if model.busy || len(model.servers) != 1 || model.servers[0].ID != "fresh" {
		t.Fatalf("refresh completion = busy %v servers %#v", model.busy, model.servers)
	}
	_, latencyCommand := model.Update(keyRune('l'))
	if latencyCommand == nil {
		t.Fatal("next action remained blocked after completion")
	}
}

func TestHostileServiceErrorsBecomeStableMessages(t *testing.T) {
	secret := "https://user:password@proxy.example.com:8443/private?token=value SecretRef TLS transport RPC"
	tests := []struct {
		name    string
		err     error
		key     rune
		want    string
		initial bool
	}{
		{name: "unknown initial error", err: fmt.Errorf("%s", secret), want: ErrOperationFailed.Error(), initial: true},
		{name: "unknown action error", err: fmt.Errorf("%s", secret), key: 'u', want: ErrOperationFailed.Error()},
		{name: "known wrapped error", err: fmt.Errorf("%s: %w", secret, rpc.ErrAccessDenied), key: 'd', want: rpc.ErrAccessDenied.Error()},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			service := &fakeApplication{err: test.err}
			model := modelForService(t, service)
			var command tea.Cmd
			if test.initial {
				command = model.Init()
			} else {
				updated, nextCommand := model.Update(keyRune(test.key))
				model = updated.(Model)
				command = nextCommand
			}
			if command == nil {
				t.Fatal("operation returned no command")
			}
			updated, _ := model.Update(command())
			model = updated.(Model)
			if model.errorMessage != test.want {
				t.Fatalf("error message = %q, want %q", model.errorMessage, test.want)
			}
			for _, forbidden := range []string{"https://", "proxy.example.com", "password", "token=value", "SecretRef", "TLS", "transport", "RPC"} {
				if strings.Contains(model.errorMessage, forbidden) {
					t.Fatalf("error message leaked %q: %q", forbidden, model.errorMessage)
				}
			}
		})
	}
}

func TestRefreshAndLatencyRemainCommandsAndReloadServers(t *testing.T) {
	tests := []struct {
		name        string
		key         rune
		wantMessage string
		assertCall  func(*testing.T, *fakeApplication)
	}{
		{
			name:        "refresh",
			key:         'u',
			wantMessage: "subscriptions refreshed",
			assertCall: func(t *testing.T, service *fakeApplication) {
				t.Helper()
				if len(service.refreshCalls) != 1 || service.refreshCalls[0] != "" {
					t.Fatalf("refresh calls = %#v", service.refreshCalls)
				}
			},
		},
		{
			name:        "latency",
			key:         'l',
			wantMessage: "latency check completed",
			assertCall: func(t *testing.T, service *fakeApplication) {
				t.Helper()
				if len(service.latencyCalls) != 1 || service.latencyCalls[0] != (latencyCall{all: true}) {
					t.Fatalf("latency calls = %#v", service.latencyCalls)
				}
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			service := &fakeApplication{servers: []app.ServerView{{ID: "reloaded", Name: "Reloaded", Protocol: domain.ProtocolVLESS}}}
			model := modelForService(t, service)
			updated, command := model.Update(keyRune(test.key))
			model = updated.(Model)
			if command == nil {
				t.Fatal("action returned no command")
			}
			if len(service.refreshCalls) != 0 || len(service.latencyCalls) != 0 || service.listServerCalls != 0 {
				t.Fatal("action ran before command execution")
			}
			message := command()
			test.assertCall(t, service)
			if service.listServerCalls != 1 {
				t.Fatalf("server reload calls = %d", service.listServerCalls)
			}
			updated, _ = model.Update(message)
			model = updated.(Model)
			if model.message != test.wantMessage || len(model.servers) != 1 || model.servers[0].ID != "reloaded" {
				t.Fatalf("result = message %q servers %#v", model.message, model.servers)
			}
		})
	}
}

func TestConnectAndDisconnectRemainCommandsAndUpdateStatus(t *testing.T) {
	service := &fakeApplication{status: rpc.SessionStatus{State: domain.ConnectionStatusConnected, Mode: domain.ConnectionModeProxy, Route: domain.RouteModeRule}}
	model := modelForService(t, service)
	model.servers = []Server{{ID: "endpoint-id", Name: "Endpoint", Protocol: domain.ProtocolVLESS}}
	model.selection = selectionManual
	model.selectedID = "endpoint-id"
	model.mode = domain.ConnectionModeProxy
	model.route = domain.RouteModeRule

	updated, connectCommand := model.Update(keyRune('c'))
	model = updated.(Model)
	if connectCommand == nil || len(service.connectCalls) != 0 {
		t.Fatalf("connect command = %v calls = %#v", connectCommand != nil, service.connectCalls)
	}
	connectMessage := connectCommand()
	if len(service.connectCalls) != 1 || service.connectCalls[0] != (connectCall{target: "endpoint-id", mode: domain.ConnectionModeProxy, route: domain.RouteModeRule}) {
		t.Fatalf("connect calls = %#v", service.connectCalls)
	}
	updated, _ = model.Update(connectMessage)
	model = updated.(Model)
	if model.status.State != domain.ConnectionStatusConnected || model.message != "connected" {
		t.Fatalf("connect result = status %#v message %q", model.status, model.message)
	}

	service.status = rpc.SessionStatus{State: domain.ConnectionStatusDisconnected}
	updated, disconnectCommand := model.Update(keyRune('d'))
	model = updated.(Model)
	if disconnectCommand == nil || service.disconnectCalls != 0 {
		t.Fatalf("disconnect command = %v calls = %d", disconnectCommand != nil, service.disconnectCalls)
	}
	disconnectMessage := disconnectCommand()
	if service.disconnectCalls != 1 {
		t.Fatalf("disconnect calls = %d", service.disconnectCalls)
	}
	updated, _ = model.Update(disconnectMessage)
	model = updated.(Model)
	if model.status.State != domain.ConnectionStatusDisconnected || model.message != "disconnected" {
		t.Fatalf("disconnect result = status %#v message %q", model.status, model.message)
	}
}

func TestConnectUsesAutoBestAndDirectTargets(t *testing.T) {
	tests := []struct {
		name      string
		selection selectionMode
		route     domain.RouteMode
		want      string
	}{
		{name: "auto best", selection: selectionAuto, route: domain.RouteModeGlobal, want: app.AutoTarget},
		{name: "direct", selection: selectionManual, route: domain.RouteModeDirect, want: ""},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			service := &fakeApplication{status: rpc.SessionStatus{State: domain.ConnectionStatusConnected, Mode: domain.ConnectionModeTUN, Route: test.route}}
			model := modelForService(t, service)
			model.servers = []Server{{ID: "endpoint-id", Name: "Endpoint", Protocol: domain.ProtocolVLESS}}
			model.selection = test.selection
			model.selectedID = "endpoint-id"
			model.route = test.route
			_, command := model.Update(keyRune('c'))
			if command == nil {
				t.Fatal("connect returned no command")
			}
			_ = command()
			if len(service.connectCalls) != 1 || service.connectCalls[0].target != test.want {
				t.Fatalf("connect target = %#v, want %q", service.connectCalls, test.want)
			}
		})
	}
}

func TestWithSecretStringClearsCapturedRunesAfterUse(t *testing.T) {
	secret := []rune("https://user:password@provider.example/private?token=value")
	want := string(secret)
	var observed string

	withSecretString(secret, func(value string) {
		observed = value
	})

	if observed != want {
		t.Fatalf("observed secret = %q, want original value", observed)
	}
	for index, character := range secret {
		if character != 0 {
			t.Fatalf("secret rune %d was not cleared", index)
		}
	}
}

func TestSubscriptionInputsAreBounded(t *testing.T) {
	model := modelWithServers(t)
	model.input = inputName
	updated, _ := model.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune(strings.Repeat("n", domain.MaxNameLength+32))})
	model = updated.(Model)
	if len(model.inputName) != domain.MaxNameLength {
		t.Fatalf("name bytes = %d, want %d", len(model.inputName), domain.MaxNameLength)
	}

	model.input = inputURL
	updated, _ = model.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune(strings.Repeat("s", maxSecretInputBytes+32))})
	model = updated.(Model)
	if len([]byte(string(model.secretInput))) != maxSecretInputBytes {
		t.Fatalf("secret bytes = %d, want %d", len([]byte(string(model.secretInput))), maxSecretInputBytes)
	}
}

func TestBracketedPasteFiltersTerminalControlsFromNameURLAndView(t *testing.T) {
	unsafe := []rune{
		'\x1b', '\a', '\r', '\n', '\x00', rune(0x85),
		rune(0x200e), rune(0x200f), rune(0x202a), rune(0x202e), rune(0x2066), rune(0x2069),
		rune(0x2028), rune(0x2029), rune(0x200b), rune(0xfeff), rune(0xd800), rune(-1),
	}
	ordinary := []rune("سلام 世界🙂")
	pasted := append(append([]rune(nil), ordinary...), unsafe...)

	model := modelWithServers(t)
	model.input = inputName
	updated, _ := model.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: pasted, Paste: true})
	model = updated.(Model)
	if model.inputName != string(ordinary) {
		t.Fatalf("name state = %q, want %q", model.inputName, string(ordinary))
	}
	assertNoUnsafeTerminalRunes(t, model.inputName)
	assertNoUnsafeTerminalRunes(t, model.View())

	model.input = inputURL
	updated, _ = model.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: pasted, Paste: true})
	model = updated.(Model)
	if string(model.secretInput) != string(ordinary) {
		t.Fatalf("URL state = %q, want %q", string(model.secretInput), string(ordinary))
	}
	assertNoUnsafeTerminalRunes(t, string(model.secretInput))
	assertNoUnsafeTerminalRunes(t, model.View())

	model.input = inputName
	model.inputName = "unsafe\x1b]52;c;payload\a" + string(rune(0x202e)) + "txt"
	view := model.View()
	assertNoUnsafeTerminalRunes(t, view)
	if strings.Contains(view, "\x1b]52") || strings.ContainsRune(view, rune(0x202e)) {
		t.Fatalf("defense-in-depth render leaked terminal controls: %q", view)
	}
}

func assertNoUnsafeTerminalRunes(t *testing.T, value string) {
	t.Helper()
	for _, character := range value {
		if character == '\n' {
			continue
		}
		if character == '\x1b' || character == '\a' || character == '\r' || character == '\x00' || character == rune(0x85) ||
			character == rune(0x200e) || character == rune(0x200f) || character >= rune(0x202a) && character <= rune(0x202e) ||
			character >= rune(0x2066) && character <= rune(0x2069) || character == rune(0x2028) || character == rune(0x2029) ||
			character == rune(0x200b) || character == rune(0xfeff) || character == rune(0xd800) || character == rune(-1) {
			t.Fatalf("unsafe rune U+%04X survived in %q", character, value)
		}
	}
}

func TestAddSubscriptionMasksAndClearsSecretAfterSubmit(t *testing.T) {
	service := &fakeApplication{}
	adapter, err := NewAdapter(service)
	if err != nil {
		t.Fatalf("NewAdapter: %v", err)
	}
	model, err := NewModel(context.Background(), adapter)
	if err != nil {
		t.Fatalf("NewModel: %v", err)
	}

	model = updateKey(t, model, keyRune('n'))
	for _, character := range "Primary" {
		model = updateKey(t, model, keyRune(character))
	}
	model = updateKey(t, model, tea.KeyMsg{Type: tea.KeyEnter})
	if model.input != inputURL {
		t.Fatalf("input stage = %q, want URL", model.input)
	}
	secret := "https://user:password@provider.example/private?token=value"
	for _, character := range secret {
		model = updateKey(t, model, keyRune(character))
	}

	updated, command := model.Update(tea.KeyMsg{Type: tea.KeyEnter})
	model = updated.(Model)
	if command == nil {
		t.Fatal("URL submit returned no command")
	}
	if model.input != inputNone || model.inputName != "" || len(model.secretInput) != 0 {
		t.Fatalf("submitted secret retained in model: stage=%q name=%q secret=%q", model.input, model.inputName, string(model.secretInput))
	}
	if len(service.addCalls) != 0 {
		t.Fatal("submit performed service call before command execution")
	}

	message := command()
	if len(service.addCalls) != 1 || service.addCalls[0].name != "Primary" || service.addCalls[0].url != secret {
		t.Fatalf("add calls = %#v", service.addCalls)
	}
	updated, _ = model.Update(message)
	model = updated.(Model)
	if model.message != "subscription added" || model.errorMessage != "" {
		t.Fatalf("result messages = %q / %q", model.message, model.errorMessage)
	}
	if containsSensitiveText(model.message+model.errorMessage, secret) {
		t.Fatalf("result retained secret: %#v", model)
	}
}

func TestAddSubscriptionCancelClearsSecretWithoutSideEffects(t *testing.T) {
	service := &fakeApplication{}
	adapter, err := NewAdapter(service)
	if err != nil {
		t.Fatalf("NewAdapter: %v", err)
	}
	model, err := NewModel(context.Background(), adapter)
	if err != nil {
		t.Fatalf("NewModel: %v", err)
	}
	model.input = inputURL
	model.inputName = "Primary"
	model.secretInput = []rune("https://provider.example/private-token")

	updated, command := model.Update(tea.KeyMsg{Type: tea.KeyEsc})
	model = updated.(Model)
	if command != nil || model.input != inputNone || model.inputName != "" || len(model.secretInput) != 0 {
		t.Fatalf("cancel result = command %v model %#v", command != nil, model)
	}
	if len(service.addCalls) != 0 {
		t.Fatalf("cancel called service: %#v", service.addCalls)
	}
}

func containsSensitiveText(value, secret string) bool {
	return strings.Contains(value, secret) || strings.Contains(value, "provider.example") || strings.Contains(value, "private-token")
}

func modelWithServers(t *testing.T, ids ...string) Model {
	t.Helper()
	model := modelForService(t, &fakeApplication{})
	for _, id := range ids {
		model.servers = append(model.servers, Server{ID: id, Name: id, Protocol: domain.ProtocolVLESS})
	}
	return model
}

func modelForService(t *testing.T, service *fakeApplication) Model {
	t.Helper()
	adapter, err := NewAdapter(service)
	if err != nil {
		t.Fatalf("NewAdapter: %v", err)
	}
	model, err := NewModel(context.Background(), adapter)
	if err != nil {
		t.Fatalf("NewModel: %v", err)
	}
	return model
}

func updateKey(t *testing.T, model Model, key tea.KeyMsg) Model {
	t.Helper()
	updated, _ := model.Update(key)
	return updated.(Model)
}

func keyRune(value rune) tea.KeyMsg {
	return tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{value}}
}

type cancelAwareBackend struct {
	started  chan struct{}
	canceled chan struct{}
}

func (*cancelAwareBackend) Snapshot(context.Context) (snapshot, error) {
	return snapshot{}, nil
}

func (*cancelAwareBackend) AddSubscription(context.Context, string, string) ([]Server, error) {
	return nil, nil
}

func (backend *cancelAwareBackend) Refresh(ctx context.Context) ([]Server, error) {
	close(backend.started)
	<-ctx.Done()
	close(backend.canceled)
	return nil, ctx.Err()
}

func (*cancelAwareBackend) CheckLatency(context.Context) ([]Server, error) {
	return nil, nil
}

func (*cancelAwareBackend) Connect(context.Context, string, domain.ConnectionMode, domain.RouteMode) (rpc.SessionStatus, error) {
	return rpc.SessionStatus{}, nil
}

func (*cancelAwareBackend) Disconnect(context.Context) (rpc.SessionStatus, error) {
	return rpc.SessionStatus{}, nil
}

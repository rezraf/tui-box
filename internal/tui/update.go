package tui

import (
	"strings"
	"unicode/utf8"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/rezraf/tui-box/internal/app"
	"github.com/rezraf/tui-box/internal/domain"
	"github.com/rezraf/tui-box/internal/terminaltext"
)

func (model Model) Update(message tea.Msg) (tea.Model, tea.Cmd) {
	switch message := message.(type) {
	case snapshotMsg:
		if model.generation != 0 {
			return model, nil
		}
		model.servers = append([]Server(nil), message.snapshot.Servers...)
		model.status = message.snapshot.Status
		model.clampCursor()
		model.reconcileSelection()
		if message.err != nil {
			model.errorMessage = safeErrorMessage(message.err)
			model.message = ""
		}
	case actionResultMsg:
		if message.generation != model.generation {
			return model, nil
		}
		model.busy = false
		if message.err != nil {
			model.errorMessage = safeErrorMessage(message.err)
			model.message = ""
			return model, nil
		}
		if message.servers != nil {
			model.servers = append([]Server(nil), message.servers...)
			model.clampCursor()
			model.reconcileSelection()
		}
		if message.hasStatus {
			model.status = message.status
		}
		model.message = message.message
		model.errorMessage = ""
	case tea.WindowSizeMsg:
		if message.Width > 0 {
			model.width = message.Width
		}
		if message.Height > 0 {
			model.height = message.Height
		}
	case tea.KeyMsg:
		return model.updateKey(message)
	}
	return model, nil
}

func (model Model) updateKey(key tea.KeyMsg) (tea.Model, tea.Cmd) {
	keyName := key.String()
	if keyName == "ctrl+c" {
		model.cancelInput()
		model.cancel()
		return model, tea.Quit
	}
	if model.input != inputNone {
		return model.updateInput(key)
	}
	if model.busy && isSideEffectKey(keyName) {
		return model, nil
	}
	model.message = ""
	model.errorMessage = ""

	switch keyName {
	case "q":
		model.cancel()
		return model, tea.Quit
	case "down", "j":
		model.moveCursor(1)
	case "up", "k":
		model.moveCursor(-1)
	case "enter":
		if len(model.servers) > 0 {
			model.selection = selectionManual
			model.selectedID = model.servers[model.cursor].ID
		}
	case "a":
		model.selection = selectionAuto
		model.selectedID = ""
	case "m":
		if model.mode == domain.ConnectionModeTUN {
			model.mode = domain.ConnectionModeProxy
		} else {
			model.mode = domain.ConnectionModeTUN
		}
	case "r":
		switch model.route {
		case domain.RouteModeGlobal:
			model.route = domain.RouteModeRule
		case domain.RouteModeRule:
			model.route = domain.RouteModeDirect
		default:
			model.route = domain.RouteModeGlobal
		}
	case "n":
		model.input = inputName
		model.inputName = ""
		model.clearSecretInput()
	case "u":
		generation := model.startAction()
		backend, ctx := model.backend, model.ctx
		return model, func() tea.Msg {
			servers, err := backend.Refresh(ctx)
			return actionResultMsg{generation: generation, servers: servers, message: "subscriptions refreshed", err: err}
		}
	case "l":
		generation := model.startAction()
		backend, ctx := model.backend, model.ctx
		return model, func() tea.Msg {
			servers, err := backend.CheckLatency(ctx)
			return actionResultMsg{generation: generation, servers: servers, message: "latency check completed", err: err}
		}
	case "c":
		target := model.selectedID
		if model.route == domain.RouteModeDirect {
			target = ""
		} else if model.selection == selectionAuto {
			target = app.AutoTarget
		} else if target == "" {
			model.errorMessage = "select a server first"
			return model, nil
		}
		generation := model.startAction()
		backend, ctx := model.backend, model.ctx
		mode, route := model.mode, model.route
		return model, func() tea.Msg {
			status, err := backend.Connect(ctx, target, mode, route)
			return actionResultMsg{generation: generation, status: status, hasStatus: true, message: "connected", err: err}
		}
	case "d":
		generation := model.startAction()
		backend, ctx := model.backend, model.ctx
		return model, func() tea.Msg {
			status, err := backend.Disconnect(ctx)
			return actionResultMsg{generation: generation, status: status, hasStatus: true, message: "disconnected", err: err}
		}
	}
	return model, nil
}

func (model Model) updateInput(key tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch key.String() {
	case "esc":
		model.cancelInput()
		return model, nil
	case "backspace":
		if model.input == inputName {
			model.inputName = removeLastRune(model.inputName)
		} else if len(model.secretInput) > 0 {
			model.secretInput[len(model.secretInput)-1] = 0
			model.secretInput = model.secretInput[:len(model.secretInput)-1]
		}
		return model, nil
	case "enter":
		if model.input == inputName {
			if strings.TrimSpace(model.inputName) == "" {
				model.errorMessage = "subscription name is required"
				return model, nil
			}
			model.input = inputURL
			model.errorMessage = ""
			return model, nil
		}
		if len(model.secretInput) == 0 || strings.TrimSpace(string(model.secretInput)) == "" {
			model.errorMessage = "subscription URL is required"
			return model, nil
		}
		name := model.inputName
		secret := append([]rune(nil), model.secretInput...)
		generation := model.startAction()
		backend, ctx := model.backend, model.ctx
		model.cancelInput()
		return model, func() tea.Msg {
			var servers []Server
			var err error
			withSecretString(secret, func(url string) {
				servers, err = backend.AddSubscription(ctx, name, url)
			})
			return actionResultMsg{generation: generation, servers: servers, message: "subscription added", err: err}
		}
	}

	if key.Type == tea.KeyRunes {
		if model.input == inputName {
			model.inputName = appendRunesWithinBytes(model.inputName, key.Runes, domain.MaxNameLength)
		} else {
			model.secretInput = appendSecretRunes(model.secretInput, key.Runes)
		}
	}
	return model, nil
}

func (model *Model) startAction() uint64 {
	model.generation++
	model.busy = true
	return model.generation
}

func isSideEffectKey(key string) bool {
	switch key {
	case "n", "u", "l", "c", "d":
		return true
	default:
		return false
	}
}

func (model *Model) cancelInput() {
	model.input = inputNone
	model.inputName = ""
	model.clearSecretInput()
}

func (model *Model) clearSecretInput() {
	for index := range model.secretInput {
		model.secretInput[index] = 0
	}
	model.secretInput = nil
}

func withSecretString(secret []rune, use func(string)) {
	defer func() {
		for index := range secret {
			secret[index] = 0
		}
	}()
	use(string(secret))
}

func appendRunesWithinBytes(current string, runes []rune, maximum int) string {
	var builder strings.Builder
	builder.Grow(min(len(current)+len(runes), maximum))
	builder.WriteString(current)
	used := len(current)
	for _, character := range runes {
		if !terminaltext.IsSafeRune(character) {
			continue
		}
		size := utf8.RuneLen(character)
		if used+size > maximum {
			break
		}
		builder.WriteRune(character)
		used += size
	}
	return builder.String()
}

func appendSecretRunes(current, runes []rune) []rune {
	used := len([]byte(string(current)))
	for _, character := range runes {
		if !terminaltext.IsSafeRune(character) {
			continue
		}
		size := utf8.RuneLen(character)
		if used+size > maxSecretInputBytes {
			break
		}
		current = append(current, character)
		used += size
	}
	return current
}

func removeLastRune(value string) string {
	runes := []rune(value)
	if len(runes) == 0 {
		return ""
	}
	return string(runes[:len(runes)-1])
}

func (model *Model) moveCursor(delta int) {
	if len(model.servers) == 0 {
		model.cursor = 0
		return
	}
	model.cursor = (model.cursor + delta + len(model.servers)) % len(model.servers)
}

func (model *Model) clampCursor() {
	if len(model.servers) == 0 {
		model.cursor = 0
		return
	}
	if model.cursor < 0 {
		model.cursor = 0
	}
	if model.cursor >= len(model.servers) {
		model.cursor = len(model.servers) - 1
	}
}

func (model *Model) reconcileSelection() {
	if model.selection != selectionManual {
		return
	}
	for _, server := range model.servers {
		if server.ID == model.selectedID {
			return
		}
	}
	model.selection = selectionAuto
	model.selectedID = ""
}

package tui

import (
	"fmt"
	"strings"
	"time"

	"github.com/charmbracelet/lipgloss"
	"github.com/rezraf/tui-box/internal/domain"
	"github.com/rezraf/tui-box/internal/latency"
	"github.com/rezraf/tui-box/internal/terminaltext"
)

var (
	titleStyle  = lipgloss.NewStyle().Bold(true)
	cursorStyle = lipgloss.NewStyle().Reverse(true)
	errorStyle  = lipgloss.NewStyle().Bold(true)
)

func (model Model) View() string {
	width := max(model.width, 20)
	height := max(model.height, 8)
	listRows := max(height-7, 1)

	lines := make([]string, 0, height)
	lines = append(lines, titleStyle.Render(truncateCells("TuiBox", width)))
	lines = append(lines, truncateCells(model.selectionLine(), width))
	lines = append(lines, "")
	lines = append(lines, truncateCells("Servers", width))
	lines = append(lines, model.serverLines(width, listRows)...)
	lines = append(lines, "")
	lines = append(lines, truncateCells(model.statusLine(), width))
	lines = append(lines, model.footerLine(width))
	return strings.Join(lines, "\n") + "\n"
}

func (model Model) selectionLine() string {
	selection := "Auto Best"
	if model.selection == selectionManual {
		selection = "Manual"
		for _, server := range model.servers {
			if server.ID == model.selectedID {
				selection += ": " + server.Name
				break
			}
		}
	}
	return "Selection: " + selection
}

func (model Model) serverLines(width, rows int) []string {
	lines := make([]string, 0, rows)
	if len(model.servers) == 0 {
		lines = append(lines, truncateCells("  No servers. Press n to add a subscription.", width))
	} else {
		start := model.cursor - rows + 1
		if start < 0 {
			start = 0
		}
		if maximum := len(model.servers) - rows; start > maximum && maximum >= 0 {
			start = maximum
		}
		end := min(start+rows, len(model.servers))
		for index := start; index < end; index++ {
			line := model.serverLine(index, width)
			if index == model.cursor {
				line = cursorStyle.Render(line)
			}
			lines = append(lines, line)
		}
	}
	for len(lines) < rows {
		lines = append(lines, "")
	}
	return lines
}

func (model Model) serverLine(index, width int) string {
	server := model.servers[index]
	cursor := " "
	if index == model.cursor {
		cursor = ">"
	}
	selected := " "
	if model.selection == selectionManual && server.ID == model.selectedID {
		selected = "*"
	}
	protocol := "unknown"
	if server.Protocol != "" {
		protocol = strings.ToUpper(string(server.Protocol))
	}
	line := fmt.Sprintf("%s%s %s  %s  %s", cursor, selected, server.Name, protocol, latencyLabel(server.Latency))
	return truncateCells(line, width)
}

func latencyLabel(result *latency.Result) string {
	if result == nil {
		return "-"
	}
	switch result.Status {
	case latency.StatusSuccess:
		return result.Duration.Round(time.Millisecond).String()
	case latency.StatusUnsupported:
		return "unsupported"
	default:
		return "unavailable"
	}
}

func (model Model) statusLine() string {
	state := model.status.State
	switch state {
	case domain.ConnectionStatusDisconnected, domain.ConnectionStatusConnecting, domain.ConnectionStatusConnected,
		domain.ConnectionStatusDisconnecting, domain.ConnectionStatusFailed:
	default:
		state = domain.ConnectionStatusFailed
	}

	mode, route := model.mode, model.route
	if state != domain.ConnectionStatusDisconnected {
		if model.status.Mode == domain.ConnectionModeTUN || model.status.Mode == domain.ConnectionModeProxy {
			mode = model.status.Mode
		}
		if model.status.Route == domain.RouteModeGlobal || model.status.Route == domain.RouteModeRule || model.status.Route == domain.RouteModeDirect {
			route = model.status.Route
		}
	}
	line := fmt.Sprintf("Status: %s Mode: %s Route: %s", state, mode, route)
	if mode != model.mode || route != model.route {
		line += fmt.Sprintf(" Next: %s/%s", model.mode, model.route)
	}
	return line
}

func (model Model) footerLine(width int) string {
	var value string
	switch model.input {
	case inputName:
		value = "Subscription name: " + model.inputName
	case inputURL:
		value = "Subscription URL: " + strings.Repeat("•", len(model.secretInput))
	default:
		switch {
		case model.errorMessage != "":
			return errorStyle.Render(truncateCells("Error: "+model.errorMessage, width))
		case model.message != "":
			value = model.message
		default:
			value = "↑/k ↓/j move | enter manual | a auto | m mode | r route | n add | u refresh | l latency | c connect | d disconnect | q quit"
		}
	}
	return truncateCells(value, width)
}

func truncateCells(value string, width int) string {
	value = terminaltext.Sanitize(value)
	if width <= 0 {
		return ""
	}
	if lipgloss.Width(value) <= width {
		return value
	}
	if width == 1 {
		return "…"
	}
	var builder strings.Builder
	used := 0
	for _, character := range value {
		characterWidth := lipgloss.Width(string(character))
		if used+characterWidth+1 > width {
			break
		}
		builder.WriteRune(character)
		used += characterWidth
	}
	return builder.String() + "…"
}

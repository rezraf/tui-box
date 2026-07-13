package tui

import (
	"context"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/rezraf/tui-box/internal/domain"
	"github.com/rezraf/tui-box/internal/latency"
	"github.com/rezraf/tui-box/internal/rpc"
)

type Server struct {
	ID       string
	Name     string
	Protocol domain.Protocol
	Latency  *latency.Result
}

type snapshot struct {
	Servers []Server
	Status  rpc.SessionStatus
}

type snapshotMsg struct {
	snapshot snapshot
	err      error
}

type selectionMode string

type inputMode string

const (
	maxSecretInputBytes = 4096

	selectionAuto   selectionMode = "auto"
	selectionManual selectionMode = "manual"

	inputNone inputMode = ""
	inputName inputMode = "name"
	inputURL  inputMode = "url"
)

type actionResultMsg struct {
	generation uint64
	servers    []Server
	status     rpc.SessionStatus
	hasStatus  bool
	message    string
	err        error
}

type Model struct {
	ctx          context.Context
	cancel       context.CancelFunc
	backend      backend
	servers      []Server
	status       rpc.SessionStatus
	cursor       int
	selection    selectionMode
	selectedID   string
	mode         domain.ConnectionMode
	route        domain.RouteMode
	input        inputMode
	inputName    string
	secretInput  []rune
	message      string
	errorMessage string
	width        int
	height       int
	generation   uint64
	busy         bool
}

func NewModel(ctx context.Context, service backend) (Model, error) {
	if ctx == nil || service == nil {
		return Model{}, ErrInvalidConfiguration
	}
	actionContext, cancel := context.WithCancel(ctx)
	return Model{
		ctx:       actionContext,
		cancel:    cancel,
		backend:   service,
		selection: selectionAuto,
		mode:      domain.ConnectionModeTUN,
		route:     domain.RouteModeGlobal,
		status:    rpc.SessionStatus{State: domain.ConnectionStatusDisconnected},
		width:     80,
		height:    24,
	}, nil
}

func (model Model) Init() tea.Cmd {
	backend, ctx := model.backend, model.ctx
	return func() tea.Msg {
		value, err := backend.Snapshot(ctx)
		return snapshotMsg{snapshot: value, err: err}
	}
}

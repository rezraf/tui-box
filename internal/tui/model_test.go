package tui

import (
	"context"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/rezraf/tui-box/internal/app"
	"github.com/rezraf/tui-box/internal/domain"
	"github.com/rezraf/tui-box/internal/latency"
	"github.com/rezraf/tui-box/internal/rpc"
	"github.com/rezraf/tui-box/internal/subscription"
)

func TestModelInitDefersLoadingAndAppliesSafeSnapshot(t *testing.T) {
	service := &fakeApplication{
		servers: []app.ServerView{{
			ID:       "endpoint-id",
			Name:     "Ordinary endpoint",
			Protocol: domain.ProtocolVLESS,
			Latency: &latency.Result{
				EndpointID: "endpoint-id",
				Protocol:   domain.ProtocolVLESS,
				Duration:   12 * time.Millisecond,
				Status:     latency.StatusSuccess,
			},
		}},
		status: rpc.SessionStatus{
			State: domain.ConnectionStatusConnected,
			Mode:  domain.ConnectionModeProxy,
			Route: domain.RouteModeRule,
		},
	}
	adapter, err := NewAdapter(service)
	if err != nil {
		t.Fatalf("NewAdapter: %v", err)
	}
	model, err := NewModel(context.Background(), adapter)
	if err != nil {
		t.Fatalf("NewModel: %v", err)
	}

	command := model.Init()
	if command == nil {
		t.Fatal("Init returned no command")
	}
	if service.listServerCalls != 0 || service.statusCalls != 0 {
		t.Fatal("Init performed side effects before command execution")
	}

	updated, _ := model.Update(command())
	got := updated.(Model)
	if service.listServerCalls != 1 || service.statusCalls != 1 {
		t.Fatalf("load calls = servers %d status %d, want 1/1", service.listServerCalls, service.statusCalls)
	}
	if len(got.servers) != 1 || got.servers[0].ID != "endpoint-id" || got.servers[0].Name != "Ordinary endpoint" {
		t.Fatalf("servers = %#v", got.servers)
	}
	if got.status.State != domain.ConnectionStatusConnected || got.status.Mode != domain.ConnectionModeProxy || got.status.Route != domain.RouteModeRule {
		t.Fatalf("status = %#v", got.status)
	}
}

func TestAdapterRejectsHostileServerFieldsBeforeTheyReachTheModel(t *testing.T) {
	secret := "https://user:password@proxy.example.com:8443/private?token=value"
	service := &fakeApplication{
		servers: []app.ServerView{
			{ID: "safe-id", Name: secret + " SecretRef TLS transport RPC", Protocol: domain.ProtocolVLESS, Latency: &latency.Result{Status: latency.StatusUnavailable, Error: secret}},
			{ID: secret, Name: "Invalid identifier", Protocol: domain.ProtocolTrojan},
			{ID: "invalid-protocol", Name: "Protocol leak", Protocol: domain.Protocol(secret)},
		},
		status: rpc.SessionStatus{State: domain.ConnectionStatus(secret), Mode: domain.ConnectionMode(secret), Route: domain.RouteMode(secret)},
	}
	adapter, err := NewAdapter(service)
	if err != nil {
		t.Fatalf("NewAdapter: %v", err)
	}

	snapshot, err := adapter.Snapshot(context.Background())
	if err != nil {
		t.Fatalf("Snapshot: %v", err)
	}
	if len(snapshot.Servers) != 2 {
		t.Fatalf("servers = %#v, want invalid identifier omitted", snapshot.Servers)
	}
	if snapshot.Servers[0].Name != "Endpoint" || snapshot.Servers[0].Latency == nil || snapshot.Servers[0].Latency.Error != "" {
		t.Fatalf("hostile server was not sanitized: %#v", snapshot.Servers[0])
	}
	if snapshot.Servers[1].Protocol != "" {
		t.Fatalf("hostile protocol retained: %#v", snapshot.Servers[1])
	}
	if snapshot.Status.State != domain.ConnectionStatusFailed || snapshot.Status.Mode != "" || snapshot.Status.Route != "" {
		t.Fatalf("hostile status retained: %#v", snapshot.Status)
	}
}

type addCall struct {
	name string
	url  string
}

type connectCall struct {
	target string
	mode   domain.ConnectionMode
	route  domain.RouteMode
}

type latencyCall struct {
	id  string
	all bool
}

type fakeApplication struct {
	servers []app.ServerView
	status  rpc.SessionStatus
	err     error

	addCalls        []addCall
	refreshCalls    []string
	latencyCalls    []latencyCall
	connectCalls    []connectCall
	disconnectCalls int
	listServerCalls int
	statusCalls     int
}

func (service *fakeApplication) AddSubscription(_ context.Context, name, url string) (app.SubscriptionView, []subscription.Warning, error) {
	service.addCalls = append(service.addCalls, addCall{name: name, url: url})
	return app.SubscriptionView{}, nil, service.err
}

func (service *fakeApplication) UpdateSubscriptions(_ context.Context, id string) ([]app.RefreshResult, error) {
	service.refreshCalls = append(service.refreshCalls, id)
	return nil, service.err
}

func (service *fakeApplication) ListServers(context.Context) ([]app.ServerView, error) {
	service.listServerCalls++
	return append([]app.ServerView(nil), service.servers...), service.err
}

func (service *fakeApplication) CheckLatency(_ context.Context, id string, all bool) ([]latency.Result, error) {
	service.latencyCalls = append(service.latencyCalls, latencyCall{id: id, all: all})
	return nil, service.err
}

func (service *fakeApplication) Connect(_ context.Context, target string, mode domain.ConnectionMode, route domain.RouteMode) (rpc.SessionStatus, error) {
	service.connectCalls = append(service.connectCalls, connectCall{target: target, mode: mode, route: route})
	return service.status, service.err
}

func (service *fakeApplication) Disconnect(context.Context) (rpc.SessionStatus, error) {
	service.disconnectCalls++
	return service.status, service.err
}

func (service *fakeApplication) Status(context.Context) (rpc.SessionStatus, error) {
	service.statusCalls++
	return service.status, service.err
}

var _ tea.Model = Model{}

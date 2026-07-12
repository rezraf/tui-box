package domain

type ConnectionMode string

const (
	ConnectionModeTUN   ConnectionMode = "tun"
	ConnectionModeProxy ConnectionMode = "proxy"
)

type RouteMode string

const (
	RouteModeGlobal RouteMode = "global"
	RouteModeRule   RouteMode = "rule"
	RouteModeDirect RouteMode = "direct"
)

type ConnectionStatus string

const (
	ConnectionStatusDisconnected  ConnectionStatus = "disconnected"
	ConnectionStatusConnecting    ConnectionStatus = "connecting"
	ConnectionStatusConnected     ConnectionStatus = "connected"
	ConnectionStatusDisconnecting ConnectionStatus = "disconnecting"
	ConnectionStatusFailed        ConnectionStatus = "failed"
)

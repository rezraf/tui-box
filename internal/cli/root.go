package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/rezraf/tui-box/internal/app"
	"github.com/rezraf/tui-box/internal/domain"
	"github.com/rezraf/tui-box/internal/latency"
	"github.com/rezraf/tui-box/internal/rpc"
	"github.com/rezraf/tui-box/internal/subscription"
	"github.com/rezraf/tui-box/internal/terminaltext"
	"github.com/spf13/cobra"
)

var (
	ErrInvalidConfiguration = errors.New("CLI configuration is invalid")
	ErrOperationFailed      = errors.New("operation failed")
	ErrDoctorFailed         = errors.New("one or more diagnostic checks failed")
	errUsage                = errors.New("invalid command usage")
)

type Service interface {
	AddSubscription(context.Context, string, string) (app.SubscriptionView, []subscription.Warning, error)
	ListSubscriptions(context.Context) ([]app.SubscriptionView, error)
	UpdateSubscriptions(context.Context, string) ([]app.RefreshResult, error)
	RemoveSubscription(context.Context, string) error
	ListServers(context.Context) ([]app.ServerView, error)
	CheckLatency(context.Context, string, bool) ([]latency.Result, error)
	Connect(context.Context, string, domain.ConnectionMode, domain.RouteMode) (rpc.SessionStatus, error)
	Disconnect(context.Context) (rpc.SessionStatus, error)
	Status(context.Context) (rpc.SessionStatus, error)
	SetTelemetry(context.Context, bool) error
	TelemetryEnabled(context.Context) (bool, error)
	Doctor(context.Context) []app.Diagnostic
	CheckUpdate(context.Context) (app.UpdateInfo, error)
	ApplyUpdate(context.Context, app.UpdateInfo) error
}

type ServiceOpener func(context.Context) (Service, func() error, error)
type TUIRunner func(context.Context, io.Writer, io.Writer) error

type Config struct {
	OpenService ServiceOpener
	RunTUI      TUIRunner
	Version     string
	Build       string
	Stdout      io.Writer
	Stderr      io.Writer
}

type usageError struct {
	message string
}

func (err usageError) Error() string {
	return err.message
}

func New(config Config) (*cobra.Command, error) {
	if config.OpenService == nil || config.RunTUI == nil {
		return nil, ErrInvalidConfiguration
	}
	if config.Stdout == nil {
		config.Stdout = os.Stdout
	}
	if config.Stderr == nil {
		config.Stderr = os.Stderr
	}
	if config.Version == "" {
		config.Version = "dev"
	}
	if config.Build == "" {
		config.Build = "unknown"
	}

	root := &cobra.Command{
		Use:           "tuibox",
		Short:         "Manage TuiBox subscriptions and connections",
		SilenceErrors: true,
		SilenceUsage:  true,
		Args:          exactArgs(0),
		RunE: func(command *cobra.Command, _ []string) error {
			return stableError(config.RunTUI(command.Context(), command.OutOrStdout(), command.ErrOrStderr()))
		},
	}
	root.SetOut(config.Stdout)
	root.SetErr(config.Stderr)
	root.SetFlagErrorFunc(func(_ *cobra.Command, _ error) error {
		return usageError{message: errUsage.Error()}
	})

	root.AddCommand(
		newSubscriptionCommand(config.OpenService),
		newServerCommand(config.OpenService),
		newConnectCommand(config.OpenService),
		newDisconnectCommand(config.OpenService),
		newStatusCommand(config.OpenService),
		newTelemetryCommand(config.OpenService),
		newDoctorCommand(config.OpenService),
		newUpdateCommand(config.OpenService),
		newVersionCommand(config.Version, config.Build),
	)
	return root, nil
}

func newSubscriptionCommand(open ServiceOpener) *cobra.Command {
	command := newCommandGroup("subscription", "Manage subscriptions")
	command.AddCommand(
		&cobra.Command{
			Use:   "add <name> <url>",
			Short: "Add a subscription",
			Args:  exactArgs(2),
			RunE: func(command *cobra.Command, args []string) error {
				return withService(command, open, func(service Service) error {
					view, warnings, err := service.AddSubscription(command.Context(), args[0], args[1])
					if err != nil {
						return err
					}
					return writeJSON(command.OutOrStdout(), struct {
						Subscription app.SubscriptionView   `json:"subscription"`
						Warnings     []subscription.Warning `json:"warnings"`
					}{Subscription: view, Warnings: warnings})
				})
			},
		},
		&cobra.Command{
			Use:   "list",
			Short: "List subscriptions",
			Args:  exactArgs(0),
			RunE: func(command *cobra.Command, _ []string) error {
				return withService(command, open, func(service Service) error {
					views, err := service.ListSubscriptions(command.Context())
					if err != nil {
						return err
					}
					return writeJSON(command.OutOrStdout(), views)
				})
			},
		},
		&cobra.Command{
			Use:   "update [id]",
			Short: "Refresh one or all subscriptions",
			Args:  maximumArgs(1),
			RunE: func(command *cobra.Command, args []string) error {
				id := ""
				if len(args) == 1 {
					id = args[0]
				}
				return withService(command, open, func(service Service) error {
					results, err := service.UpdateSubscriptions(command.Context(), id)
					if err != nil {
						return err
					}
					return writeJSON(command.OutOrStdout(), results)
				})
			},
		},
		&cobra.Command{
			Use:   "remove <id>",
			Short: "Remove a subscription",
			Args:  exactArgs(1),
			RunE: func(command *cobra.Command, args []string) error {
				return withService(command, open, func(service Service) error {
					if err := service.RemoveSubscription(command.Context(), args[0]); err != nil {
						return err
					}
					_, err := fmt.Fprintln(command.OutOrStdout(), "subscription removed")
					return err
				})
			},
		},
	)
	return command
}

func newServerCommand(open ServiceOpener) *cobra.Command {
	command := newCommandGroup("server", "Inspect servers")
	command.AddCommand(&cobra.Command{
		Use:   "list",
		Short: "List servers",
		Args:  exactArgs(0),
		RunE: func(command *cobra.Command, _ []string) error {
			return withService(command, open, func(service Service) error {
				views, err := service.ListServers(command.Context())
				if err != nil {
					return err
				}
				return writeJSON(command.OutOrStdout(), views)
			})
		},
	})

	var all bool
	latencyCommand := &cobra.Command{
		Use:   "latency [id]",
		Short: "Check server latency",
		Args:  maximumArgs(1),
		RunE: func(command *cobra.Command, args []string) error {
			if all == (len(args) == 1) {
				return usageError{message: "provide one server ID or --all"}
			}
			id := ""
			if len(args) == 1 {
				id = args[0]
			}
			return withService(command, open, func(service Service) error {
				results, err := service.CheckLatency(command.Context(), id, all)
				if err != nil {
					return err
				}
				return writeJSON(command.OutOrStdout(), results)
			})
		},
	}
	latencyCommand.Flags().BoolVar(&all, "all", false, "check all servers")
	command.AddCommand(latencyCommand)
	return command
}

func newConnectCommand(open ServiceOpener) *cobra.Command {
	var mode string
	var route string
	command := &cobra.Command{
		Use:   "connect <endpoint-id|auto>",
		Short: "Connect through a server",
		Args:  exactArgs(1),
		RunE: func(command *cobra.Command, args []string) error {
			if !command.Flags().Changed("mode") || !command.Flags().Changed("route") {
				return usageError{message: "--mode and --route are required"}
			}
			if mode != string(domain.ConnectionModeTUN) && mode != string(domain.ConnectionModeProxy) {
				return usageError{message: "--mode must be tun or proxy"}
			}
			if route != string(domain.RouteModeGlobal) && route != string(domain.RouteModeRule) && route != string(domain.RouteModeDirect) {
				return usageError{message: "--route must be global, rule, or direct"}
			}
			return withService(command, open, func(service Service) error {
				status, err := service.Connect(command.Context(), args[0], domain.ConnectionMode(mode), domain.RouteMode(route))
				if err != nil {
					return err
				}
				return writeJSON(command.OutOrStdout(), status)
			})
		},
	}
	command.Flags().StringVar(&mode, "mode", "", "connection mode: tun or proxy")
	command.Flags().StringVar(&route, "route", "", "route mode: global, rule, or direct")
	return command
}

func newDisconnectCommand(open ServiceOpener) *cobra.Command {
	return &cobra.Command{
		Use:   "disconnect",
		Short: "Disconnect the active session",
		Args:  exactArgs(0),
		RunE: func(command *cobra.Command, _ []string) error {
			return withService(command, open, func(service Service) error {
				status, err := service.Disconnect(command.Context())
				if err != nil {
					return err
				}
				return writeJSON(command.OutOrStdout(), status)
			})
		},
	}
}

func newStatusCommand(open ServiceOpener) *cobra.Command {
	return &cobra.Command{
		Use:   "status",
		Short: "Show connection status",
		Args:  exactArgs(0),
		RunE: func(command *cobra.Command, _ []string) error {
			return withService(command, open, func(service Service) error {
				status, err := service.Status(command.Context())
				if err != nil {
					return err
				}
				return writeJSON(command.OutOrStdout(), status)
			})
		},
	}
}

func newTelemetryCommand(open ServiceOpener) *cobra.Command {
	command := newCommandGroup("telemetry", "Manage telemetry consent")
	for _, item := range []struct {
		name    string
		enabled bool
	}{
		{name: "enable", enabled: true},
		{name: "disable", enabled: false},
	} {
		item := item
		command.AddCommand(&cobra.Command{
			Use:   item.name,
			Short: item.name + " telemetry",
			Args:  exactArgs(0),
			RunE: func(command *cobra.Command, _ []string) error {
				return withService(command, open, func(service Service) error {
					if err := service.SetTelemetry(command.Context(), item.enabled); err != nil {
						return err
					}
					_, err := fmt.Fprintf(command.OutOrStdout(), "telemetry %s\n", item.name+"d")
					return err
				})
			},
		})
	}
	command.AddCommand(&cobra.Command{
		Use:   "status",
		Short: "Show telemetry consent",
		Args:  exactArgs(0),
		RunE: func(command *cobra.Command, _ []string) error {
			return withService(command, open, func(service Service) error {
				enabled, err := service.TelemetryEnabled(command.Context())
				if err != nil {
					return err
				}
				state := "disabled"
				if enabled {
					state = "enabled"
				}
				_, err = fmt.Fprintf(command.OutOrStdout(), "telemetry %s\n", state)
				return err
			})
		},
	})
	return command
}

func newDoctorCommand(open ServiceOpener) *cobra.Command {
	return &cobra.Command{
		Use:   "doctor",
		Short: "Check the local installation",
		Args:  exactArgs(0),
		RunE: func(command *cobra.Command, _ []string) error {
			return withService(command, open, func(service Service) error {
				diagnostics := service.Doctor(command.Context())
				if err := writeJSON(command.OutOrStdout(), diagnostics); err != nil {
					return err
				}
				for _, diagnostic := range diagnostics {
					if diagnostic.Severity == app.DiagnosticError {
						return ErrDoctorFailed
					}
				}
				return nil
			})
		},
	}
}

func newUpdateCommand(open ServiceOpener) *cobra.Command {
	var checkOnly bool
	command := &cobra.Command{
		Use:   "update",
		Short: "Check for and apply an update",
		Args:  exactArgs(0),
		RunE: func(command *cobra.Command, _ []string) error {
			return withService(command, open, func(service Service) error {
				info, err := service.CheckUpdate(command.Context())
				if err != nil {
					return err
				}
				applied := false
				if !checkOnly && info.Available {
					if err := service.ApplyUpdate(command.Context(), info); err != nil {
						return err
					}
					applied = true
				}
				return writeJSON(command.OutOrStdout(), struct {
					app.UpdateInfo
					Applied               bool `json:"applied"`
					DaemonRestartRequired bool `json:"daemon_restart_required,omitempty"`
				}{UpdateInfo: info, Applied: applied, DaemonRestartRequired: applied})
			})
		},
	}
	command.Flags().BoolVar(&checkOnly, "check", false, "check without applying")
	return command
}

func newVersionCommand(version, build string) *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Show version information",
		Args:  exactArgs(0),
		RunE: func(command *cobra.Command, _ []string) error {
			_, err := fmt.Fprintf(command.OutOrStdout(), "tuibox %s (%s)\n", version, build)
			return stableError(err)
		},
	}
}

func withService(command *cobra.Command, open ServiceOpener, run func(Service) error) error {
	service, closeService, err := open(command.Context())
	if err != nil {
		if closeService != nil {
			_ = closeService()
		}
		return stableError(err)
	}
	if closeService == nil {
		return ErrOperationFailed
	}
	if service == nil {
		_ = closeService()
		return ErrOperationFailed
	}
	runErr := stableError(run(service))
	closeErr := stableError(closeService())
	if runErr != nil {
		return runErr
	}
	return closeErr
}

func writeJSON(writer io.Writer, value any) error {
	var encoded bytes.Buffer
	encoder := json.NewEncoder(&encoded)
	encoder.SetEscapeHTML(true)
	if err := encoder.Encode(value); err != nil {
		return err
	}
	body := bytes.TrimSuffix(encoded.Bytes(), []byte{'\n'})
	_, err := fmt.Fprintln(writer, terminaltext.Sanitize(string(body)))
	return err
}

func newCommandGroup(use, short string) *cobra.Command {
	return &cobra.Command{
		Use:   use,
		Short: short,
		Args:  exactArgs(0),
		RunE: func(*cobra.Command, []string) error {
			return usageError{message: errUsage.Error()}
		},
	}
}

func exactArgs(expected int) cobra.PositionalArgs {
	return func(_ *cobra.Command, args []string) error {
		if len(args) != expected {
			return usageError{message: errUsage.Error()}
		}
		return nil
	}
}

func maximumArgs(maximum int) cobra.PositionalArgs {
	return func(_ *cobra.Command, args []string) error {
		if len(args) > maximum {
			return usageError{message: errUsage.Error()}
		}
		return nil
	}
}

func stableError(err error) error {
	if err == nil {
		return nil
	}
	var usage usageError
	if errors.As(err, &usage) {
		return usage
	}
	for _, known := range stableErrors {
		if errors.Is(err, known) {
			return known
		}
	}
	return ErrOperationFailed
}

var stableErrors = []error{
	ErrOperationFailed,
	ErrDoctorFailed,
	context.Canceled,
	context.DeadlineExceeded,
	app.ErrInvalidConfiguration,
	app.ErrInvalidInput,
	app.ErrSubscriptionNotFound,
	app.ErrServerNotFound,
	app.ErrStateOperation,
	app.ErrSecretOperation,
	app.ErrRefreshFailed,
	app.ErrRefreshStale,
	app.ErrUpdaterUnavailable,
	rpc.ErrInvalidRequest,
	rpc.ErrUnsupportedVersion,
	rpc.ErrAccessDenied,
	rpc.ErrCoreValidation,
	rpc.ErrProcessFailure,
	rpc.ErrProcessStuck,
	rpc.ErrRollbackFailure,
	rpc.ErrUnavailable,
	rpc.ErrTimeout,
	rpc.ErrInternal,
	rpc.ErrInvalidResponse,
}

func IsUsageError(err error) bool {
	if err == nil {
		return false
	}
	var target usageError
	if errors.As(err, &target) {
		return true
	}
	for _, known := range stableErrors {
		if errors.Is(err, known) {
			return false
		}
	}
	return true
}

func ExitCode(err error) int {
	if err == nil {
		return 0
	}
	if IsUsageError(err) {
		return 2
	}
	return 1
}

func ErrorMessage(err error) string {
	if err == nil {
		return ""
	}
	if IsUsageError(err) {
		return errUsage.Error()
	}
	return stableError(err).Error()
}

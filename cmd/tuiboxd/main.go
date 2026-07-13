//go:build darwin || linux

package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"math"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/rezraf/tui-box/internal/core"
	"github.com/rezraf/tui-box/internal/daemon"
	"github.com/rezraf/tui-box/internal/rpc"
)

const daemonStopTimeout = 5 * time.Second

var (
	errInvalidOptions = errors.New("invalid daemon options")
	errRootRequired   = errors.New("effective root privileges are required")
)

type daemonOptions struct {
	corePath         string
	runtimeDirectory string
	socketPath       string
	socketGID        int
	allowedUIDs      []int
}

type uidValues struct {
	values []int
}

func (values *uidValues) String() string {
	parts := make([]string, len(values.values))
	for index, value := range values.values {
		parts[index] = strconv.Itoa(value)
	}
	return strings.Join(parts, ",")
}

func (values *uidValues) Set(input string) error {
	parts := strings.Split(input, ",")
	if len(parts) == 0 {
		return errInvalidOptions
	}
	for _, part := range parts {
		if part == "" || part != strings.TrimSpace(part) {
			return errInvalidOptions
		}
		parsed, err := strconv.ParseUint(part, 10, 32)
		if err != nil || parsed >= math.MaxUint32 {
			return errInvalidOptions
		}
		values.values = append(values.values, int(parsed))
	}
	return nil
}

func parseOptions(arguments []string) (daemonOptions, error) {
	flags := flag.NewFlagSet("tuiboxd", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	var options daemonOptions
	var socketGID uint64
	var allowed uidValues
	flags.StringVar(&options.corePath, "core", "", "")
	flags.StringVar(&options.runtimeDirectory, "runtime-dir", "", "")
	flags.StringVar(&options.socketPath, "socket", "", "")
	flags.Uint64Var(&socketGID, "socket-gid", math.MaxUint64, "")
	flags.Var(&allowed, "allow-uid", "")
	if err := flags.Parse(arguments); err != nil || flags.NArg() != 0 {
		return daemonOptions{}, errInvalidOptions
	}
	if !validAbsolutePath(options.corePath) || !validAbsolutePath(options.runtimeDirectory) || !validAbsolutePath(options.socketPath) ||
		socketGID >= math.MaxUint32 || len(allowed.values) == 0 {
		return daemonOptions{}, errInvalidOptions
	}
	seen := make(map[int]struct{}, len(allowed.values))
	for _, uid := range allowed.values {
		if _, duplicate := seen[uid]; duplicate {
			return daemonOptions{}, errInvalidOptions
		}
		seen[uid] = struct{}{}
	}
	options.socketGID = int(socketGID)
	options.allowedUIDs = append([]int(nil), allowed.values...)
	return options, nil
}

func validAbsolutePath(path string) bool {
	if path == "" || !filepath.IsAbs(path) || filepath.Clean(path) != path || !utf8.ValidString(path) {
		return false
	}
	for _, character := range path {
		if unicode.IsControl(character) {
			return false
		}
	}
	return true
}

func requireRoot(effectiveUID int) error {
	if effectiveUID != 0 {
		return errRootRequired
	}
	return nil
}

func main() {
	if err := runDaemon(os.Args[1:], os.Geteuid()); err != nil {
		_, _ = fmt.Fprintln(os.Stderr, publicStartupError(err))
		os.Exit(1)
	}
}

func runDaemon(arguments []string, effectiveUID int) error {
	if err := requireRoot(effectiveUID); err != nil {
		return err
	}
	options, err := parseOptions(arguments)
	if err != nil {
		return err
	}

	runner, err := core.NewRunner(options.corePath, options.runtimeDirectory)
	if err != nil {
		return err
	}
	service, err := daemon.NewService(runner, daemonStopTimeout)
	if err != nil {
		_ = runner.Close()
		return err
	}
	server, err := rpc.NewServer(rpc.ServerConfig{
		SocketPath:  options.socketPath,
		SocketGID:   options.socketGID,
		AllowedUIDs: options.allowedUIDs,
		Handler:     service,
	})
	if err != nil {
		_ = service.Close()
		return err
	}

	signalContext, stopSignals := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	serveDone := make(chan error, 1)
	go func() { serveDone <- server.Serve() }()

	serveErr, serverErr := waitForServerShutdown(signalContext.Done(), serveDone, stopSignals, server.Close)
	serviceErr := service.Close()
	return errors.Join(serveErr, serverErr, serviceErr)
}

func waitForServerShutdown(signalDone <-chan struct{}, serveDone <-chan error, stopSignals func(), closeServer func() error) (error, error) {
	var serveErr error
	serveReturned := false
	select {
	case <-signalDone:
	case serveErr = <-serveDone:
		serveReturned = true
	}
	stopSignals()
	closeErr := closeServer()
	if !serveReturned {
		serveErr = <-serveDone
	}
	return serveErr, closeErr
}

func publicStartupError(err error) string {
	switch {
	case errors.Is(err, errRootRequired):
		return "tuiboxd must run as root"
	case errors.Is(err, errInvalidOptions):
		return "tuiboxd configuration is invalid"
	default:
		return "tuiboxd failed"
	}
}

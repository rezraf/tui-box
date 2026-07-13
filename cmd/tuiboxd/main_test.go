//go:build darwin || linux

package main

import (
	"errors"
	"math"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestParseOptionsAcceptsOnlyRequiredFixedFlags(t *testing.T) {
	t.Parallel()

	options, err := parseOptions([]string{
		"--core", "/opt/tuibox/sing-box",
		"--runtime-dir", "/var/lib/tuibox",
		"--socket", "/var/run/tuibox/tuiboxd.sock",
		"--socket-gid", "20",
		"--allow-uid", "501,502",
		"--allow-uid=503",
	})
	if err != nil {
		t.Fatalf("parseOptions() failed: %v", err)
	}
	if options.corePath != "/opt/tuibox/sing-box" || options.runtimeDirectory != "/var/lib/tuibox" ||
		options.socketPath != "/var/run/tuibox/tuiboxd.sock" || options.socketGID != 20 {
		t.Fatalf("parseOptions() = %#v", options)
	}
	if want := []int{501, 502, 503}; !reflect.DeepEqual(options.allowedUIDs, want) {
		t.Fatalf("allowed UIDs = %v, want %v", options.allowedUIDs, want)
	}
}

func TestParseOptionsRejectsInvalidConfiguration(t *testing.T) {
	t.Parallel()

	valid := []string{
		"--core", "/opt/tuibox/sing-box",
		"--runtime-dir", "/var/lib/tuibox",
		"--socket", "/var/run/tuibox/tuiboxd.sock",
		"--socket-gid", "20",
		"--allow-uid", "501",
	}
	tests := []struct {
		name string
		args []string
	}{
		{name: "missing core", args: withoutFlag(valid, "--core")},
		{name: "missing runtime directory", args: withoutFlag(valid, "--runtime-dir")},
		{name: "missing socket", args: withoutFlag(valid, "--socket")},
		{name: "missing socket GID", args: withoutFlag(valid, "--socket-gid")},
		{name: "missing allow UID", args: withoutFlag(valid, "--allow-uid")},
		{name: "relative core", args: replaceFlag(valid, "--core", "sing-box")},
		{name: "unclean runtime directory", args: replaceFlag(valid, "--runtime-dir", "/var/lib/../lib/tuibox")},
		{name: "relative socket", args: replaceFlag(valid, "--socket", "tuiboxd.sock")},
		{name: "negative GID", args: replaceFlag(valid, "--socket-gid", "-1")},
		{name: "overflow GID", args: replaceFlag(valid, "--socket-gid", "4294967296")},
		{name: "negative UID", args: replaceFlag(valid, "--allow-uid", "-1")},
		{name: "overflow UID", args: replaceFlag(valid, "--allow-uid", "4294967296")},
		{name: "empty UID component", args: replaceFlag(valid, "--allow-uid", "501,,502")},
		{name: "duplicate UID", args: append(append([]string(nil), valid...), "--allow-uid", "501")},
		{name: "unknown flag", args: append(append([]string(nil), valid...), "--debug")},
		{name: "positional argument", args: append(append([]string(nil), valid...), "secret")},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if _, err := parseOptions(test.args); !errors.Is(err, errInvalidOptions) {
				t.Fatalf("parseOptions(%v) error = %v, want errInvalidOptions", test.args, err)
			}
		})
	}
}

func TestRequireRootUsesEffectiveUID(t *testing.T) {
	t.Parallel()

	if err := requireRoot(0); err != nil {
		t.Fatalf("requireRoot(0) failed: %v", err)
	}
	if err := requireRoot(501); !errors.Is(err, errRootRequired) {
		t.Fatalf("requireRoot(501) error = %v, want errRootRequired", err)
	}
}

func TestWaitForServerShutdownClosesAndWaitsForServe(t *testing.T) {
	signalDone := make(chan struct{})
	close(signalDone)
	serveDone := make(chan error, 1)
	closeCalled := make(chan struct{})
	started := time.Now()
	serveErr, closeErr := waitForServerShutdown(signalDone, serveDone, func() error {
		close(closeCalled)
		go func() {
			time.Sleep(25 * time.Millisecond)
			serveDone <- nil
		}()
		return nil
	})
	if serveErr != nil || closeErr != nil {
		t.Fatalf("waitForServerShutdown() = %v, %v", serveErr, closeErr)
	}
	select {
	case <-closeCalled:
	default:
		t.Fatal("server Close was not called")
	}
	if time.Since(started) < 25*time.Millisecond {
		t.Fatal("shutdown returned before Serve exited")
	}
}

func TestPublicStartupErrorNeverIncludesUnderlyingDetails(t *testing.T) {
	t.Parallel()

	message := publicStartupError(errors.New("secret.example credential token /private/path"))
	if message == "" {
		t.Fatal("publicStartupError() returned an empty message")
	}
	for _, secret := range []string{"secret.example", "credential", "token", "/private/path"} {
		if strings.Contains(message, secret) {
			t.Fatalf("public startup message leaked %q: %q", secret, message)
		}
	}
}

func TestUIDAndGIDBoundsMatchKernelIdentityWidth(t *testing.T) {
	if uint64(math.MaxUint32) != 4294967295 {
		t.Fatal("unexpected uint32 width")
	}
	options, err := parseOptions([]string{
		"--core", "/core",
		"--runtime-dir", "/runtime",
		"--socket", "/socket",
		"--socket-gid", "4294967295",
		"--allow-uid", "4294967295",
	})
	if err != nil {
		t.Fatalf("parseOptions(max uint32) failed: %v", err)
	}
	if uint64(options.socketGID) != math.MaxUint32 || uint64(options.allowedUIDs[0]) != math.MaxUint32 {
		t.Fatalf("max identities were not preserved: %#v", options)
	}
}

func withoutFlag(input []string, flagName string) []string {
	output := make([]string, 0, len(input)-2)
	for index := 0; index < len(input); index += 2 {
		if input[index] != flagName {
			output = append(output, input[index], input[index+1])
		}
	}
	return output
}

func replaceFlag(input []string, flagName, value string) []string {
	output := append([]string(nil), input...)
	for index := 0; index < len(output); index += 2 {
		if output[index] == flagName {
			output[index+1] = value
			return output
		}
	}
	return output
}

//go:build darwin || linux

package core

import (
	"context"
	"errors"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/rezraf/tui-box/internal/domain"
)

func TestNewRunnerAcceptsOnlyFixedSafeExecutable(t *testing.T) {
	t.Parallel()

	directory := t.TempDir()
	safeExecutable := writeExecutable(t, directory, "safe-core", 0o755)
	if _, err := NewRunner(safeExecutable); err != nil {
		t.Fatalf("NewRunner() rejected safe executable: %v", err)
	}

	tests := []struct {
		name string
		path func(*testing.T) string
	}{
		{name: "relative", path: func(t *testing.T) string {
			t.Helper()
			return "sing-box"
		}},
		{name: "missing", path: func(t *testing.T) string {
			t.Helper()
			return filepath.Join(directory, "missing")
		}},
		{name: "directory", path: func(t *testing.T) string {
			t.Helper()
			return directory
		}},
		{name: "symlink", path: func(t *testing.T) string {
			t.Helper()
			path := filepath.Join(directory, "core-link")
			if err := os.Symlink(safeExecutable, path); err != nil {
				t.Fatal(err)
			}
			return path
		}},
		{name: "not executable", path: func(t *testing.T) string {
			t.Helper()
			return writeExecutable(t, directory, "not-executable", 0o600)
		}},
		{name: "group writable", path: func(t *testing.T) string {
			t.Helper()
			return writeExecutable(t, directory, "group-writable", 0o775)
		}},
		{name: "other writable", path: func(t *testing.T) string {
			t.Helper()
			return writeExecutable(t, directory, "other-writable", 0o757)
		}},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if _, err := NewRunner(test.path(t)); !errors.Is(err, ErrInvalidExecutable) {
				t.Fatalf("NewRunner() error = %v, want ErrInvalidExecutable", err)
			}
		})
	}
}

func TestRunnerWritesOnlyGeneratedConfigToExistingSecurePath(t *testing.T) {
	t.Parallel()

	runner := newTestRunner(t)
	request := validConnectionRequest(domain.ConnectionModeProxy, domain.RouteModeGlobal)
	path := secureConfigPath(t)
	if err := runner.WriteConfig(path, request); err != nil {
		t.Fatalf("WriteConfig() returned an unexpected error: %v", err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	want := generateConfig(t, request)
	if string(got) != string(want) {
		t.Fatalf("written config differs from generated config\ngot: %s\nwant: %s", got, want)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if gotMode := info.Mode().Perm(); gotMode != 0o600 {
		t.Fatalf("config mode = %04o, want 0600", gotMode)
	}
}

func TestRunnerRejectsUnsafeConfigPathsAndInvalidRequestsBeforeWriting(t *testing.T) {
	t.Parallel()

	runner := newTestRunner(t)
	request := validConnectionRequest(domain.ConnectionModeProxy, domain.RouteModeGlobal)
	directory := t.TempDir()
	secure := secureConfigPathIn(t, directory, "secure.json")

	tests := []struct {
		name string
		path func(*testing.T) string
	}{
		{name: "relative", path: func(t *testing.T) string { return "config.json" }},
		{name: "missing", path: func(t *testing.T) string { return filepath.Join(directory, "missing.json") }},
		{name: "directory", path: func(t *testing.T) string { return directory }},
		{name: "symlink", path: func(t *testing.T) string {
			path := filepath.Join(directory, "config-link.json")
			if err := os.Symlink(secure, path); err != nil {
				t.Fatal(err)
			}
			return path
		}},
		{name: "group readable", path: func(t *testing.T) string {
			path := secureConfigPathIn(t, directory, "group-readable.json")
			if err := os.Chmod(path, 0o640); err != nil {
				t.Fatal(err)
			}
			return path
		}},
		{name: "executable", path: func(t *testing.T) string {
			path := secureConfigPathIn(t, directory, "executable.json")
			if err := os.Chmod(path, 0o700); err != nil {
				t.Fatal(err)
			}
			return path
		}},
		{name: "non-private parent", path: func(t *testing.T) string {
			parent := filepath.Join(directory, "shared")
			if err := os.Mkdir(parent, 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(parent, 0o755); err != nil {
				t.Fatal(err)
			}
			return secureConfigPathIn(t, parent, "config.json")
		}},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if err := runner.WriteConfig(test.path(t), request); !errors.Is(err, ErrUnsafeConfigPath) {
				t.Fatalf("WriteConfig() error = %v, want ErrUnsafeConfigPath", err)
			}
		})
	}

	invalidRequest := request
	invalidRequest.UID = -1
	if err := os.WriteFile(secure, []byte("unchanged"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := runner.WriteConfig(secure, invalidRequest); err == nil {
		t.Fatal("WriteConfig() accepted invalid request")
	}
	if got, err := os.ReadFile(secure); err != nil || string(got) != "unchanged" {
		t.Fatalf("invalid request modified config: %q, %v", got, err)
	}
}

func TestRunnerConstructsOnlyFixedDirectCommands(t *testing.T) {
	t.Parallel()

	runner := newTestRunner(t).(*execRunner)
	path := secureConfigPath(t)
	request := validConnectionRequest(domain.ConnectionModeProxy, domain.RouteModeGlobal)
	if err := runner.WriteConfig(path, request); err != nil {
		t.Fatal(err)
	}

	check := runner.command(context.Background(), commandCheck, path, request)
	assertFixedCommand(t, runner.executable, check, []string{runner.executable, "check", "-c", path})
	if check.SysProcAttr == nil || !check.SysProcAttr.Setpgid || check.SysProcAttr.Credential != nil {
		t.Fatalf("check process attributes = %#v, want process group without credential drop", check.SysProcAttr)
	}

	proxy := runner.command(context.Background(), commandRun, path, request)
	assertFixedCommand(t, runner.executable, proxy, []string{runner.executable, "run", "-c", path})
	credential := proxy.SysProcAttr.Credential
	if credential == nil || credential.Uid != uint32(request.UID) || credential.Gid != uint32(request.GID) {
		t.Fatalf("proxy credential = %#v, want UID %d GID %d", credential, request.UID, request.GID)
	}
	if credential.Groups == nil || len(credential.Groups) != 0 || credential.NoSetGroups {
		t.Fatalf("proxy supplementary groups = %#v, want explicit empty group set", credential)
	}

	tunRequest := validConnectionRequest(domain.ConnectionModeTUN, domain.RouteModeGlobal)
	tun := runner.command(context.Background(), commandRun, path, tunRequest)
	if tun.SysProcAttr == nil || !tun.SysProcAttr.Setpgid || tun.SysProcAttr.Credential != nil {
		t.Fatalf("TUN process attributes = %#v, want privileged process group", tun.SysProcAttr)
	}
}

func TestRunnerRejectsChangedExecutableAndConfig(t *testing.T) {
	t.Parallel()

	directory := t.TempDir()
	executable := writeExecutable(t, directory, "sing-box", 0o755)
	runnerValue, err := NewRunner(executable)
	if err != nil {
		t.Fatal(err)
	}
	runner := runnerValue.(*execRunner)
	request := validConnectionRequest(domain.ConnectionModeProxy, domain.RouteModeGlobal)
	path := secureConfigPath(t)
	if err := runner.WriteConfig(path, request); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := runner.Check(context.Background(), path); !errors.Is(err, ErrConfigNotGenerated) {
		t.Fatalf("Check() after config replacement error = %v, want ErrConfigNotGenerated", err)
	}

	if err := os.Remove(executable); err != nil {
		t.Fatal(err)
	}
	writeExecutable(t, directory, "sing-box", 0o755)
	path = secureConfigPath(t)
	if err := runner.WriteConfig(path, request); err != nil {
		t.Fatal(err)
	}
	if err := runner.Check(context.Background(), path); !errors.Is(err, ErrInvalidExecutable) {
		t.Fatalf("Check() after executable replacement error = %v, want ErrInvalidExecutable", err)
	}
}

func TestRunnerRejectsIdentityOverflow(t *testing.T) {
	if strconvIntSize() < 64 {
		t.Skip("int cannot represent a value larger than uint32")
	}
	request := validConnectionRequest(domain.ConnectionModeProxy, domain.RouteModeGlobal)
	request.GID = int(uint64(math.MaxUint32) + 1)
	if output, err := GenerateConfig(request); output != nil || err == nil || !strings.Contains(err.Error(), "GID") {
		t.Fatalf("GenerateConfig() = %q, %v, want GID rejection", output, err)
	}
}

func assertFixedCommand(t *testing.T, executable string, command *exec.Cmd, wantArgs []string) {
	t.Helper()
	if command.Path != executable {
		t.Errorf("command path = %q, want %q", command.Path, executable)
	}
	if strings.Join(command.Args, "\x00") != strings.Join(wantArgs, "\x00") {
		t.Errorf("command args = %q, want %q", command.Args, wantArgs)
	}
	if command.Env == nil || len(command.Env) != 0 {
		t.Errorf("command env = %q, want explicit empty environment", command.Env)
	}
}

func newTestRunner(t *testing.T) Runner {
	t.Helper()
	runner, err := NewRunner(currentExecutable(t))
	if err != nil {
		t.Fatalf("NewRunner() returned an unexpected error: %v", err)
	}
	return runner
}

func currentExecutable(t *testing.T) string {
	t.Helper()
	path, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	return path
}

func writeExecutable(t *testing.T, directory, name string, mode os.FileMode) string {
	t.Helper()
	path := filepath.Join(directory, name)
	if err := os.WriteFile(path, []byte("not executed"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
	return path
}

func secureConfigPath(t *testing.T) string {
	t.Helper()
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	return secureConfigPathIn(t, directory, "config.json")
}

func secureConfigPathIn(t *testing.T, directory, name string) string {
	t.Helper()
	path := filepath.Join(directory, name)
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func strconvIntSize() int {
	return 32 << (^uint(0) >> 63)
}

func TestProcessAPIHandlesGracefulSignalKillWaitAndBoundedOutput(t *testing.T) {
	if runtime.GOOS != "darwin" && runtime.GOOS != "linux" {
		t.Skip("Unix process behavior only")
	}

	helper := buildCoreHelper(t)
	runner, err := NewRunner(helper)
	if err != nil {
		t.Fatal(err)
	}
	request := validConnectionRequest(domain.ConnectionModeTUN, domain.RouteModeGlobal)
	path := secureConfigPath(t)
	if err := runner.WriteConfig(path, request); err != nil {
		t.Fatal(err)
	}
	process, err := runner.Start(context.Background(), path, request)
	if err != nil {
		t.Fatalf("Start() returned an unexpected error: %v", err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for len(process.Output()) == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if err := process.Signal(syscall.SIGTERM); err != nil {
		t.Fatalf("Signal() returned an unexpected error: %v", err)
	}
	if err := process.Wait(); err != nil {
		t.Fatalf("Wait() returned an unexpected error: %v", err)
	}
	if got := len(process.Output()); got != maxCoreOutputBytes {
		t.Fatalf("bounded output length = %d, want %d", got, maxCoreOutputBytes)
	}
	if err := process.Kill(); !errors.Is(err, os.ErrProcessDone) {
		t.Fatalf("Kill() after wait error = %v, want os.ErrProcessDone", err)
	}
}

func TestRunnerCheckAndStartAreContextAwareAndErrorsDoNotLeakSecrets(t *testing.T) {
	helper := buildCoreHelper(t)
	runner, err := NewRunner(helper)
	if err != nil {
		t.Fatal(err)
	}

	blockingRequest := validConnectionRequest(domain.ConnectionModeTUN, domain.RouteModeGlobal)
	blockingRequest.Endpoint.Host = "block-check.example.com"
	path := secureConfigPath(t)
	if err := runner.WriteConfig(path, blockingRequest); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	if err := runner.Check(ctx, path); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Check() error = %v, want context deadline", err)
	}

	const secret = "runner-secret-must-not-leak"
	failureRequest := validConnectionRequest(domain.ConnectionModeProxy, domain.RouteModeGlobal)
	failureRequest.Endpoint.Protocol = domain.ProtocolTrojan
	failureRequest.Endpoint.UUID = ""
	failureRequest.Endpoint.Password = secret
	failureRequest.Endpoint.Host = "fail-check.example.com"
	path = secureConfigPath(t)
	if err := runner.WriteConfig(path, failureRequest); err != nil {
		t.Fatal(err)
	}
	if err := runner.Check(context.Background(), path); !errors.Is(err, ErrCoreCheckFailed) {
		t.Fatalf("Check() error = %v, want ErrCoreCheckFailed", err)
	} else if strings.Contains(err.Error(), secret) {
		t.Fatalf("Check() error leaked secret: %v", err)
	}

	startCtx, startCancel := context.WithCancel(context.Background())
	path = secureConfigPath(t)
	if err := runner.WriteConfig(path, blockingRequest); err != nil {
		t.Fatal(err)
	}
	process, err := runner.Start(startCtx, path, blockingRequest)
	if err != nil {
		t.Fatal(err)
	}
	startCancel()
	waitDone := make(chan error, 1)
	go func() { waitDone <- process.Wait() }()
	select {
	case <-waitDone:
	case <-time.After(5 * time.Second):
		t.Fatal("process did not stop after start context cancellation")
	}
}

func buildCoreHelper(t *testing.T) string {
	t.Helper()
	output := filepath.Join(t.TempDir(), "core-helper")
	command := exec.Command("go", "build", "-o", output, "./testdata/corehelper")
	command.Dir = "."
	if result, err := command.CombinedOutput(); err != nil {
		t.Fatalf("build core helper: %v: %s", err, result)
	}
	return output
}

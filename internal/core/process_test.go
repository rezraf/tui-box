//go:build darwin || linux

package core

import (
	"bytes"
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

func TestNewRunnerAcceptsOnlyTrustedExecutable(t *testing.T) {
	t.Parallel()

	directory := trustedDirectory(t)
	runtimeDirectory := privateDirectory(t)
	safeExecutable := writeExecutable(t, directory, "safe-core", 0o700)
	runner, err := NewRunner(safeExecutable, runtimeDirectory)
	if err != nil {
		t.Fatalf("NewRunner() rejected safe executable: %v", err)
	}
	if err := runner.Close(); err != nil {
		t.Fatalf("Close() failed: %v", err)
	}

	tests := []struct {
		name string
		path func(*testing.T) string
	}{
		{name: "relative", path: func(t *testing.T) string { return "sing-box" }},
		{name: "missing", path: func(t *testing.T) string { return filepath.Join(directory, "missing") }},
		{name: "directory", path: func(t *testing.T) string { return directory }},
		{name: "symlink", path: func(t *testing.T) string {
			path := filepath.Join(directory, "core-link")
			if err := os.Symlink(safeExecutable, path); err != nil {
				t.Fatal(err)
			}
			return path
		}},
		{name: "not executable", path: func(t *testing.T) string {
			return writeExecutable(t, directory, "not-executable", 0o600)
		}},
		{name: "group writable", path: func(t *testing.T) string {
			return writeExecutable(t, directory, "group-writable", 0o770)
		}},
		{name: "other writable", path: func(t *testing.T) string {
			return writeExecutable(t, directory, "other-writable", 0o707)
		}},
		{name: "writable parent", path: func(t *testing.T) string {
			parent := filepath.Join(directory, "writable-parent")
			if err := os.Mkdir(parent, 0o700); err != nil {
				t.Fatal(err)
			}
			path := writeExecutable(t, parent, "core", 0o700)
			if err := os.Chmod(parent, 0o770); err != nil {
				t.Fatal(err)
			}
			return path
		}},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if runner, err := NewRunner(test.path(t), privateDirectory(t)); !errors.Is(err, ErrInvalidExecutable) {
				if runner != nil {
					_ = runner.Close()
				}
				t.Fatalf("NewRunner() error = %v, want ErrInvalidExecutable", err)
			}
		})
	}
}

func TestNewRunnerRejectsExecutableNotOwnedByEffectiveUID(t *testing.T) {
	t.Parallel()

	if os.Geteuid() != 0 {
		if runner, err := NewRunner("/bin/ls", privateDirectory(t)); !errors.Is(err, ErrInvalidExecutable) {
			if runner != nil {
				_ = runner.Close()
			}
			t.Fatalf("NewRunner(/bin/ls) error = %v, want owner rejection", err)
		}
		return
	}

	directory := trustedDirectory(t)
	path := writeExecutable(t, directory, "foreign-core", 0o700)
	if err := os.Chown(path, 65534, 65534); err != nil {
		t.Fatal(err)
	}
	if runner, err := NewRunner(path, privateDirectory(t)); !errors.Is(err, ErrInvalidExecutable) {
		if runner != nil {
			_ = runner.Close()
		}
		t.Fatalf("NewRunner() error = %v, want owner rejection", err)
	}
}

func TestNewRunnerRequiresFixedPrivateRuntimeRoot(t *testing.T) {
	t.Parallel()

	executable := trustedNoopExecutable(t)
	private := privateDirectory(t)

	tests := []struct {
		name string
		path func(*testing.T) string
	}{
		{name: "relative", path: func(t *testing.T) string { return "runtime" }},
		{name: "missing", path: func(t *testing.T) string { return filepath.Join(private, "missing") }},
		{name: "regular file", path: func(t *testing.T) string {
			path := filepath.Join(private, "file")
			if err := os.WriteFile(path, nil, 0o600); err != nil {
				t.Fatal(err)
			}
			return path
		}},
		{name: "symlink", path: func(t *testing.T) string {
			path := filepath.Join(t.TempDir(), "runtime-link")
			if err := os.Symlink(private, path); err != nil {
				t.Fatal(err)
			}
			return path
		}},
		{name: "not private", path: func(t *testing.T) string {
			path := privateDirectory(t)
			if err := os.Chmod(path, 0o750); err != nil {
				t.Fatal(err)
			}
			return path
		}},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if runner, err := NewRunner(executable, test.path(t)); !errors.Is(err, ErrUnsafeRuntimeRoot) {
				if runner != nil {
					_ = runner.Close()
				}
				t.Fatalf("NewRunner() error = %v, want ErrUnsafeRuntimeRoot", err)
			}
		})
	}
}

func TestRunnerRejectsRuntimeRootPermissionChanges(t *testing.T) {
	t.Parallel()

	t.Run("before prepare", func(t *testing.T) {
		t.Parallel()
		runner, runtimeDirectory := newTestRunner(t, trustedNoopExecutable(t))
		if err := os.Chmod(runtimeDirectory, 0o750); err != nil {
			t.Fatal(err)
		}
		if prepared, err := runner.Prepare(validConnectionRequest(domain.ConnectionModeTUN, domain.RouteModeGlobal)); prepared != nil || !errors.Is(err, ErrUnsafeRuntimeRoot) {
			t.Fatalf("Prepare() after runtime chmod = %#v, %v, want ErrUnsafeRuntimeRoot", prepared, err)
		}
	})

	t.Run("after prepare", func(t *testing.T) {
		t.Parallel()
		runner, runtimeDirectory := newTestRunner(t, buildCoreHelper(t))
		prepared, err := runner.Prepare(validConnectionRequest(domain.ConnectionModeTUN, domain.RouteModeGlobal))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(runtimeDirectory, 0o750); err != nil {
			t.Fatal(err)
		}
		if err := runner.Check(context.Background(), prepared); !errors.Is(err, ErrUnsafeRuntimeRoot) {
			t.Fatalf("Check() after runtime chmod error = %v, want ErrUnsafeRuntimeRoot", err)
		}
	})
}

func TestRunnerPrepareCreatesUniquePrivateAtomicConfigs(t *testing.T) {
	t.Parallel()

	runner, runtimeDirectory := newTestRunner(t, trustedNoopExecutable(t))
	request := validConnectionRequest(domain.ConnectionModeTUN, domain.RouteModeGlobal)
	first, err := runner.Prepare(request)
	if err != nil {
		t.Fatalf("Prepare() failed: %v", err)
	}
	second, err := runner.Prepare(request)
	if err != nil {
		t.Fatalf("Prepare() failed: %v", err)
	}

	entries, err := os.ReadDir(runtimeDirectory)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 2 {
		t.Fatalf("runtime entries = %d, want 2 unique configs", len(entries))
	}
	want := generateConfig(t, request)
	for _, entry := range entries {
		if entry.IsDir() || strings.Contains(entry.Name(), ".tmp") {
			t.Fatalf("unexpected runtime entry %q", entry.Name())
		}
		path := filepath.Join(runtimeDirectory, entry.Name())
		info, err := os.Lstat(path)
		if err != nil {
			t.Fatal(err)
		}
		if !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
			t.Fatalf("config %q mode = %v, want regular 0600", entry.Name(), info.Mode())
		}
		if owner, ok := fileOwnerID(info); !ok || owner != os.Geteuid() {
			t.Fatalf("config %q owner = %d, %v, want euid %d", entry.Name(), owner, ok, os.Geteuid())
		}
		got, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, want) {
			t.Fatalf("prepared config differs from generated config: %s", got)
		}
	}

	if err := first.Close(); err != nil {
		t.Fatalf("prepared Close() failed: %v", err)
	}
	if err := first.Close(); err != nil {
		t.Fatalf("second prepared Close() failed: %v", err)
	}
	entries, err = os.ReadDir(runtimeDirectory)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Fatalf("runtime entries after handle close = %d, want 1", len(entries))
	}
	if err := second.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestRunnerUsesOnlyFixedInheritedDescriptorCommands(t *testing.T) {
	t.Parallel()

	runner, _ := newTestRunner(t, buildCoreHelper(t))
	request := validConnectionRequest(domain.ConnectionModeTUN, domain.RouteModeGlobal)
	prepared, err := runner.Prepare(request)
	if err != nil {
		t.Fatal(err)
	}
	if err := runner.Check(context.Background(), prepared); err != nil {
		t.Fatalf("Check() did not use the fixed descriptor command: %v", err)
	}
	process, err := runner.Start(context.Background(), prepared)
	if err != nil {
		t.Fatalf("Start() did not use the fixed descriptor command: %v", err)
	}
	waitForOutput(t, process, "config-readable")
	if err := process.Signal(syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	if err := process.Wait(); err != nil {
		t.Fatal(err)
	}
}

func TestRunnerRequiresSuccessfulCheckOfExactPreparedDigest(t *testing.T) {
	t.Parallel()

	helper := buildCoreHelper(t)
	runner, runtimeDirectory := newTestRunner(t, helper)
	otherRunner, _ := newTestRunner(t, helper)
	request := validConnectionRequest(domain.ConnectionModeTUN, domain.RouteModeGlobal)

	unchecked, err := runner.Prepare(request)
	if err != nil {
		t.Fatal(err)
	}
	if process, err := runner.Start(context.Background(), unchecked); process != nil || !errors.Is(err, ErrConfigNotChecked) {
		t.Fatalf("Start() before Check() = %#v, %v, want ErrConfigNotChecked", process, err)
	}
	if err := otherRunner.Check(context.Background(), unchecked); !errors.Is(err, ErrPreparedConfigNotOwned) {
		t.Fatalf("cross-runner Check() error = %v, want ErrPreparedConfigNotOwned", err)
	}

	path := onlyRuntimeConfig(t, runtimeDirectory)
	if err := os.WriteFile(path, []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := runner.Check(context.Background(), unchecked); !errors.Is(err, ErrPreparedConfigChanged) {
		t.Fatalf("Check() after replacement error = %v, want ErrPreparedConfigChanged", err)
	}
	if err := unchecked.Close(); err != nil {
		t.Fatal(err)
	}

	checked, err := runner.Prepare(request)
	if err != nil {
		t.Fatal(err)
	}
	if err := runner.Check(context.Background(), checked); err != nil {
		t.Fatal(err)
	}
	path = onlyRuntimeConfig(t, runtimeDirectory)
	if err := os.WriteFile(path, []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if process, err := runner.Start(context.Background(), checked); process != nil || !errors.Is(err, ErrPreparedConfigChanged) {
		t.Fatalf("Start() after checked config replacement = %#v, %v, want ErrPreparedConfigChanged", process, err)
	}
}

func TestPreparedConfigAndRunnerCloseAreSafeAndRemoveConfigs(t *testing.T) {
	t.Parallel()

	runner, runtimeDirectory := newTestRunnerWithoutCleanup(t, trustedNoopExecutable(t))
	request := validConnectionRequest(domain.ConnectionModeTUN, domain.RouteModeGlobal)
	first, err := runner.Prepare(request)
	if err != nil {
		t.Fatal(err)
	}
	second, err := runner.Prepare(request)
	if err != nil {
		t.Fatal(err)
	}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	if err := runner.Check(context.Background(), first); !errors.Is(err, ErrPreparedConfigClosed) {
		t.Fatalf("Check() closed handle error = %v, want ErrPreparedConfigClosed", err)
	}
	if err := runner.Close(); err != nil {
		t.Fatal(err)
	}
	if err := runner.Close(); err != nil {
		t.Fatalf("second runner Close() failed: %v", err)
	}
	if err := second.Close(); err != nil {
		t.Fatalf("handle Close() after runner Close() failed: %v", err)
	}
	entries, err := os.ReadDir(runtimeDirectory)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("runner Close() left runtime files: %#v", entries)
	}
	if prepared, err := runner.Prepare(request); prepared != nil || !errors.Is(err, ErrRunnerClosed) {
		t.Fatalf("Prepare() after Close() = %#v, %v, want ErrRunnerClosed", prepared, err)
	}
}

func TestRunnerRejectsChangedExecutable(t *testing.T) {
	t.Parallel()

	directory := trustedDirectory(t)
	executable := writeExecutable(t, directory, "sing-box", 0o700)
	runner, _ := newTestRunner(t, executable)
	request := validConnectionRequest(domain.ConnectionModeTUN, domain.RouteModeGlobal)
	prepared, err := runner.Prepare(request)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(executable); err != nil {
		t.Fatal(err)
	}
	writeExecutable(t, directory, "sing-box", 0o700)
	if err := runner.Check(context.Background(), prepared); !errors.Is(err, ErrInvalidExecutable) {
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

func TestProcessAPIHandlesGracefulSignalKillWaitAndBoundedOutput(t *testing.T) {
	t.Parallel()

	runner, _ := newTestRunner(t, buildCoreHelper(t))
	request := validConnectionRequest(domain.ConnectionModeTUN, domain.RouteModeGlobal)
	prepared, err := runner.Prepare(request)
	if err != nil {
		t.Fatal(err)
	}
	if err := runner.Check(context.Background(), prepared); err != nil {
		t.Fatal(err)
	}
	process, err := runner.Start(context.Background(), prepared)
	if err != nil {
		t.Fatalf("Start() returned an unexpected error: %v", err)
	}
	waitForOutput(t, process, "config-readable")
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
	t.Parallel()

	runner, _ := newTestRunner(t, buildCoreHelper(t))

	blockingRequest := validConnectionRequest(domain.ConnectionModeTUN, domain.RouteModeGlobal)
	blockingRequest.Endpoint.Host = "block-check.example.com"
	blocking, err := runner.Prepare(blockingRequest)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	if err := runner.Check(ctx, blocking); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Check() error = %v, want context deadline", err)
	}

	const secret = "runner-secret-must-not-leak"
	failureRequest := validConnectionRequest(domain.ConnectionModeProxy, domain.RouteModeGlobal)
	failureRequest.Endpoint.Protocol = domain.ProtocolTrojan
	failureRequest.Endpoint.UUID = ""
	failureRequest.Endpoint.Password = secret
	failureRequest.Endpoint.Host = "fail-check.example.com"
	failure, err := runner.Prepare(failureRequest)
	if err != nil {
		t.Fatal(err)
	}
	if err := runner.Check(context.Background(), failure); !errors.Is(err, ErrCoreCheckFailed) {
		t.Fatalf("Check() error = %v, want ErrCoreCheckFailed", err)
	} else if strings.Contains(err.Error(), secret) {
		t.Fatalf("Check() error leaked secret: %v", err)
	}

	startRequest := validConnectionRequest(domain.ConnectionModeTUN, domain.RouteModeGlobal)
	startPrepared, err := runner.Prepare(startRequest)
	if err != nil {
		t.Fatal(err)
	}
	if err := runner.Check(context.Background(), startPrepared); err != nil {
		t.Fatal(err)
	}
	startCtx, startCancel := context.WithCancel(context.Background())
	process, err := runner.Start(startCtx, startPrepared)
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

func TestProxyExecutionDropsIdentityAndReadsInheritedRootOwnedConfig(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root to prove credential drop before inherited config read")
	}

	runner, runtimeDirectory := newTestRunner(t, buildCoreHelper(t))
	request := validConnectionRequest(domain.ConnectionModeProxy, domain.RouteModeGlobal)
	request.UID = 65534
	request.GID = 65534
	prepared, err := runner.Prepare(request)
	if err != nil {
		t.Fatal(err)
	}
	configInfo, err := os.Stat(onlyRuntimeConfig(t, runtimeDirectory))
	if err != nil {
		t.Fatal(err)
	}
	if configInfo.Mode().Perm() != 0o600 {
		t.Fatalf("config mode = %04o, want 0600", configInfo.Mode().Perm())
	}
	if owner, ok := fileOwnerID(configInfo); !ok || owner != 0 {
		t.Fatalf("config owner = %d, %v, want root", owner, ok)
	}
	if err := runner.Check(context.Background(), prepared); err != nil {
		t.Fatal(err)
	}
	process, err := runner.Start(context.Background(), prepared)
	if err != nil {
		t.Fatal(err)
	}
	waitForOutput(t, process, "uid=65534 gid=65534 config-readable")
	if err := process.Signal(syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	if err := process.Wait(); err != nil {
		t.Fatal(err)
	}
}

func newTestRunner(t *testing.T, executable string) (Runner, string) {
	t.Helper()
	runner, runtimeDirectory := newTestRunnerWithoutCleanup(t, executable)
	t.Cleanup(func() {
		if err := runner.Close(); err != nil {
			t.Errorf("runner cleanup: %v", err)
		}
	})
	return runner, runtimeDirectory
}

func newTestRunnerWithoutCleanup(t *testing.T, executable string) (Runner, string) {
	t.Helper()
	runtimeDirectory := privateDirectory(t)
	runner, err := NewRunner(executable, runtimeDirectory)
	if err != nil {
		t.Fatalf("NewRunner() returned an unexpected error: %v", err)
	}
	return runner, runtimeDirectory
}

func trustedNoopExecutable(t *testing.T) string {
	t.Helper()
	return writeExecutable(t, trustedDirectory(t), "core", 0o700)
}

func trustedDirectory(t *testing.T) string {
	t.Helper()
	cache, err := os.UserCacheDir()
	if err != nil {
		t.Fatal(err)
	}
	base := filepath.Join(cache, "tuibox", "core-unit-tests")
	if err := os.MkdirAll(base, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(base, 0o700); err != nil {
		t.Fatal(err)
	}
	directory, err := os.MkdirTemp(base, "trusted-core-*")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(directory, 0o700); err != nil {
		os.RemoveAll(directory)
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(directory); err != nil {
			t.Errorf("remove trusted test directory: %v", err)
		}
	})
	return directory
}

func privateDirectory(t *testing.T) string {
	t.Helper()
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	return directory
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

func onlyRuntimeConfig(t *testing.T, runtimeDirectory string) string {
	t.Helper()
	entries, err := os.ReadDir(runtimeDirectory)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Fatalf("runtime entries = %d, want 1", len(entries))
	}
	return filepath.Join(runtimeDirectory, entries[0].Name())
}

func strconvIntSize() int {
	return 32 << (^uint(0) >> 63)
}

func waitForOutput(t *testing.T, process Process, text string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if bytes.Contains(process.Output(), []byte(text)) {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("process output did not contain %q: %q", text, process.Output())
}

func buildCoreHelper(t *testing.T) string {
	t.Helper()
	output := filepath.Join(trustedDirectory(t), "core-helper")
	command := exec.Command("go", "build", "-o", output, "./testdata/corehelper")
	command.Dir = "."
	if result, err := command.CombinedOutput(); err != nil {
		t.Fatalf("build core helper: %v: %s", err, result)
	}
	return output
}

func TestUnixProcessSupport(t *testing.T) {
	if runtime.GOOS != "darwin" && runtime.GOOS != "linux" {
		t.Fatalf("unexpected OS %s", runtime.GOOS)
	}
}

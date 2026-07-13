//go:build darwin

package update

import (
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/rezraf/tui-box/internal/app"
)

func TestDarwinWritableACLsFailEveryUpdaterTrustBoundary(t *testing.T) {
	uid := uint32(os.Getuid())

	t.Run("trusted ancestor", func(t *testing.T) {
		for _, relative := range []string{"prefix", "prefix/libexec", "prefix/libexec/tuibox"} {
			t.Run(relative, func(t *testing.T) {
				root := t.TempDir()
				directory := filepath.Join(root, filepath.FromSlash(relative))
				if err := os.MkdirAll(filepath.Join(root, "prefix", "libexec", "tuibox"), 0o700); err != nil {
					t.Fatal(err)
				}
				addWritableACL(t, directory, true)
				target := filepath.Join(root, "prefix", "libexec", "tuibox")
				if err := trustedParentChain(target, root, uid); !errors.Is(err, ErrInvalidInstallation) {
					t.Fatalf("trustedParentChain with ACL on %q = %v, want ErrInvalidInstallation", relative, err)
				}
			})
		}
	})

	t.Run("helper before sudo", func(t *testing.T) {
		root := t.TempDir()
		clientPath := filepath.Join(root, "bin", "tuibox")
		helperPath := filepath.Join(root, "libexec", "tuibox", helperBinaryName)
		writeExecutable(t, clientPath, "client")
		writeExecutable(t, helperPath, "helper")
		addWritableACL(t, helperPath, false)

		calls := 0
		updater, err := New(Config{
			CurrentVersion: "v0.1.0",
			GOOS:           "darwin",
			GOARCH:         "arm64",
			ExecutablePath: func() (string, error) { return clientPath, nil },
			RunCommand: func(context.Context, string, []string, io.Reader, io.Writer, io.Writer) error {
				calls++
				return nil
			},
			validateHelper: func(path string) error {
				return validatePrivilegeHelperForOwner(path, uid)
			},
		})
		if err != nil {
			t.Fatal(err)
		}
		info := app.UpdateInfo{CurrentVersion: "v0.1.0", LatestVersion: "v0.2.0", Available: true}
		if err := updater.Apply(context.Background(), info); !errors.Is(err, ErrInvalidInstallation) {
			t.Fatalf("Apply with writable helper ACL = %v, want ErrInvalidInstallation", err)
		}
		if calls != 0 {
			t.Fatalf("privileged command calls = %d, want 0", calls)
		}
	})

	t.Run("privileged layout", func(t *testing.T) {
		root := t.TempDir()
		layout := installationLayout{
			Client: filepath.Join(root, "libexec", "tuibox", "tuibox"),
			Daemon: filepath.Join(root, "libexec", "tuibox", "tuiboxd"),
			Helper: filepath.Join(root, "libexec", "tuibox", helperBinaryName),
		}
		for _, path := range []string{layout.Client, layout.Daemon, layout.Helper} {
			writeExecutable(t, path, filepath.Base(path))
		}
		addWritableACL(t, layout.Daemon, false)
		if err := validatePrivilegedLayoutForOwner(layout, uid); !errors.Is(err, ErrInvalidInstallation) {
			t.Fatalf("validatePrivilegedLayout with writable executable ACL = %v, want ErrInvalidInstallation", err)
		}
	})
}

func TestDarwinReplacementStripsInheritedWritableACLs(t *testing.T) {
	root := t.TempDir()
	directory := filepath.Join(root, "libexec", "tuibox")
	layout := installationLayout{
		Client: filepath.Join(directory, "tuibox"),
		Daemon: filepath.Join(directory, "tuiboxd"),
		Helper: filepath.Join(directory, helperBinaryName),
	}
	for _, path := range []string{layout.Client, layout.Daemon, layout.Helper} {
		writeExecutable(t, path, "old")
	}
	addWritableACL(t, directory, true)

	payload := binariesPayload{Client: []byte("new-client"), Daemon: []byte("new-daemon")}
	if err := replaceInstallation(layout, payload, fileOperations{}); err != nil {
		t.Fatalf("replaceInstallation: %v", err)
	}
	for _, path := range []string{layout.Client, layout.Daemon, layout.Helper} {
		if err := validatePathACL(path); err != nil {
			t.Fatalf("installed executable retained writable ACL at %q: %v", path, err)
		}
	}
}

func addWritableACL(t *testing.T, path string, inheritable bool) {
	t.Helper()
	permissions := "everyone allow write,delete"
	if inheritable {
		permissions = "everyone allow add_file,delete,file_inherit,directory_inherit"
	}
	command := exec.Command("/bin/chmod", "+a", permissions, path)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("add ACL to %q: %v: %s", path, err, output)
	}
	t.Cleanup(func() { _ = exec.Command("/bin/chmod", "-N", path).Run() })
}

func writeExecutable(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o755); err != nil {
		t.Fatal(err)
	}
}

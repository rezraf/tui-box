//go:build linux

package core

import (
	"errors"
	"testing"

	"golang.org/x/sys/unix"
)

func TestInspectExecutableCapabilities(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		size    int
		readErr error
		wantErr bool
	}{
		{name: "absent", size: -1, readErr: unix.ENODATA},
		{name: "unsupported filesystem", size: -1, readErr: unix.ENOTSUP},
		{name: "empty", size: 0},
		{name: "non-empty", size: 20, wantErr: true},
		{name: "invalid negative size", size: -1, wantErr: true},
		{name: "read failure", size: -1, readErr: unix.EACCES, wantErr: true},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			called := false
			err := inspectExecutableCapabilitiesWith("/trusted/sing-box", func(path, name string, destination []byte) (int, error) {
				called = true
				if path != "/trusted/sing-box" {
					t.Fatalf("xattr path = %q, want exact executable path", path)
				}
				if name != "security.capability" {
					t.Fatalf("xattr name = %q, want security.capability", name)
				}
				if destination != nil {
					t.Fatalf("xattr destination = %#v, want nil size query", destination)
				}
				return test.size, test.readErr
			})
			if !called {
				t.Fatal("xattr reader was not called")
			}
			if test.wantErr && !errors.Is(err, ErrInvalidExecutable) {
				t.Fatalf("capability inspection error = %v, want ErrInvalidExecutable", err)
			}
			if !test.wantErr && err != nil {
				t.Fatalf("capability inspection error = %v, want nil", err)
			}
		})
	}
}

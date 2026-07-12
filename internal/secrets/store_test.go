package secrets

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
)

func TestNewStoreChoosesNativeBackendWhenExecutableExists(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		goos       string
		wantLookup string
		resolved   string
		backend    string
	}{
		{name: "macOS Keychain", goos: "darwin", wantLookup: "/usr/bin/security", resolved: "/usr/bin/security", backend: BackendMacOSKeychain},
		{name: "Linux Secret Service", goos: "linux", wantLookup: "secret-tool", resolved: "/usr/bin/secret-tool", backend: BackendLinuxSecretService},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			var lookedUp string
			lookup := func(name string) (string, error) {
				lookedUp = name
				return test.resolved, nil
			}
			store, info, err := newStore(test.goos, t.TempDir(), lookup, &recordingRunner{})
			if err != nil {
				t.Fatalf("newStore() returned an unexpected error: %v", err)
			}
			if store == nil {
				t.Fatal("newStore() returned nil store")
			}
			if lookedUp != test.wantLookup {
				t.Fatalf("looked up executable %q, want %q", lookedUp, test.wantLookup)
			}
			if info.Name != test.backend || info.Warning != "" {
				t.Fatalf("backend info = %#v, want native backend without warning", info)
			}
		})
	}
}

func TestNewStoreFallsBackToFileAndExposesWarning(t *testing.T) {
	t.Parallel()

	directory := filepath.Join(t.TempDir(), "nested", "secrets")
	store, info, err := newStore("linux", directory, func(string) (string, error) {
		return "", errors.New("not found")
	}, &recordingRunner{})
	if err != nil {
		t.Fatalf("newStore() returned an unexpected error: %v", err)
	}
	if info.Name != BackendFile || info.Warning == "" {
		t.Fatalf("backend info = %#v, want file backend with warning", info)
	}
	if err := store.Set(context.Background(), "subscription-1", "https://example.com/private"); err != nil {
		t.Fatalf("fallback Set() returned an unexpected error: %v", err)
	}
	value, err := store.Get(context.Background(), "subscription-1")
	if err != nil {
		t.Fatalf("fallback Get() returned an unexpected error: %v", err)
	}
	if value != "https://example.com/private" {
		t.Fatalf("fallback value = %q, want stored URL", value)
	}
}

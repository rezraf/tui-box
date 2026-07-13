package secrets

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestFileStoreRejectsDuplicateDecodedKeysWithoutRewrite(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		name    string
		content []byte
	}{
		{name: "literal duplicate", content: []byte(`{"subscription-1":"first","subscription-1":"second"}`)},
		{name: "escaped duplicate", content: []byte("{\"subscription-1\":\"first\",\"subscription-\\u0031\":\"second\"}")},
	} {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			directory := filepath.Join(t.TempDir(), "secrets")
			store, err := newFileStore(directory)
			if err != nil {
				t.Fatalf("newFileStore() error = %v", err)
			}
			defer store.Close()

			path := filepath.Join(directory, fallbackFileName)
			if err := os.WriteFile(path, test.content, 0o600); err != nil {
				t.Fatalf("WriteFile() error = %v", err)
			}
			before, err := os.Stat(path)
			if err != nil {
				t.Fatalf("Stat() before Set error = %v", err)
			}
			if err := store.Set(context.Background(), "subscription-2", "new secret"); err == nil {
				t.Fatal("Set() accepted duplicate fallback-secret keys")
			}
			after, err := os.Stat(path)
			if err != nil {
				t.Fatalf("Stat() after Set error = %v", err)
			}
			if !os.SameFile(before, after) {
				t.Fatal("rejected fallback-secret file was replaced")
			}
			persisted, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("ReadFile() after Set error = %v", err)
			}
			if !bytes.Equal(persisted, test.content) {
				t.Fatal("rejected fallback-secret file content changed")
			}
		})
	}
}

func TestFileStoreKeepsCaseDistinctKeys(t *testing.T) {
	t.Parallel()

	directory := filepath.Join(t.TempDir(), "secrets")
	store, err := newFileStore(directory)
	if err != nil {
		t.Fatalf("newFileStore() error = %v", err)
	}
	defer store.Close()
	content := []byte(`{"Subscription-1":"upper","subscription-1":"lower"}`)
	if err := os.WriteFile(filepath.Join(directory, fallbackFileName), content, 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	for key, want := range map[string]string{"Subscription-1": "upper", "subscription-1": "lower"} {
		got, err := store.Get(context.Background(), key)
		if err != nil {
			t.Fatalf("Get(%q) error = %v", key, err)
		}
		if got != want {
			t.Fatalf("Get(%q) = %q, want %q", key, got, want)
		}
	}
}

package secrets

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func TestFileStoreUsesRestrictedPermissionsAndPersistsValues(t *testing.T) {
	t.Parallel()

	directory := filepath.Join(t.TempDir(), "config", "tuibox")
	store, err := newFileStore(directory)
	if err != nil {
		t.Fatalf("newFileStore() returned an unexpected error: %v", err)
	}
	if err := store.Set(context.Background(), "subscription-1", "https://example.com/one"); err != nil {
		t.Fatalf("Set() returned an unexpected error: %v", err)
	}

	assertFileMode(t, directory, 0o700)
	assertFileMode(t, filepath.Join(directory, fallbackLockFileName), 0o600)
	path := filepath.Join(directory, fallbackFileName)
	assertFileMode(t, path, 0o600)

	reopened, err := newFileStore(directory)
	if err != nil {
		t.Fatalf("reopen returned an unexpected error: %v", err)
	}
	value, err := reopened.Get(context.Background(), "subscription-1")
	if err != nil {
		t.Fatalf("Get() returned an unexpected error: %v", err)
	}
	if value != "https://example.com/one" {
		t.Fatalf("Get() = %q, want persisted value", value)
	}
}

func TestFileStoreAtomicallyReplacesAndDeletesValues(t *testing.T) {
	t.Parallel()

	directory := filepath.Join(t.TempDir(), "secrets")
	store, err := newFileStore(directory)
	if err != nil {
		t.Fatalf("newFileStore() returned an unexpected error: %v", err)
	}
	ctx := context.Background()
	if err := store.Set(ctx, "subscription-1", "https://example.com/old"); err != nil {
		t.Fatalf("first Set() returned an unexpected error: %v", err)
	}
	path := filepath.Join(directory, fallbackFileName)
	before, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat() before replacement: %v", err)
	}

	if err := store.Set(ctx, "subscription-1", "https://example.com/new"); err != nil {
		t.Fatalf("replacement Set() returned an unexpected error: %v", err)
	}
	after, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat() after replacement: %v", err)
	}
	if os.SameFile(before, after) {
		t.Fatal("fallback file was modified in place, want atomic replacement")
	}
	assertNoTemporaryFiles(t, directory)

	if err := store.Delete(ctx, "subscription-1"); err != nil {
		t.Fatalf("Delete() returned an unexpected error: %v", err)
	}
	if _, err := store.Get(ctx, "subscription-1"); err == nil {
		t.Fatal("Get() returned nil error after deletion")
	}
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile() after deletion: %v", err)
	}
	var values map[string]string
	if err := json.Unmarshal(content, &values); err != nil {
		t.Fatalf("fallback JSON is malformed: %v", err)
	}
	if len(values) != 0 {
		t.Fatalf("fallback values = %#v, want empty map", values)
	}
}

func TestFileStoreRefusesSymlinkFile(t *testing.T) {
	t.Parallel()

	directory := filepath.Join(t.TempDir(), "secrets")
	if err := os.Mkdir(directory, 0o700); err != nil {
		t.Fatalf("Mkdir(): %v", err)
	}
	target := filepath.Join(t.TempDir(), "target.json")
	if err := os.WriteFile(target, []byte(`{"subscription-1":"secret"}`), 0o600); err != nil {
		t.Fatalf("WriteFile() target: %v", err)
	}
	if err := os.Symlink(target, filepath.Join(directory, fallbackFileName)); err != nil {
		t.Fatalf("Symlink(): %v", err)
	}

	store, err := newFileStore(directory)
	if err == nil {
		t.Fatal("newFileStore() returned nil error for symlink file")
	}
	if store != nil {
		t.Fatal("newFileStore() returned a store for symlink file")
	}
}

func TestIndependentFileStoresDoNotLoseConcurrentUpdates(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "secrets")
	first, err := newFileStore(directory)
	if err != nil {
		t.Fatalf("first newFileStore() returned an unexpected error: %v", err)
	}
	second, err := newFileStore(directory)
	if err != nil {
		t.Fatalf("second newFileStore() returned an unexpected error: %v", err)
	}

	base := make(map[string]string, 500)
	for index := 0; index < 500; index++ {
		base[fmt.Sprintf("existing-%d", index)] = strings.Repeat("x", 128)
	}
	encoded, err := json.Marshal(base)
	if err != nil {
		t.Fatalf("json.Marshal(): %v", err)
	}
	path := filepath.Join(directory, fallbackFileName)

	for attempt := 0; attempt < 25; attempt++ {
		if err := os.WriteFile(path, encoded, 0o600); err != nil {
			t.Fatalf("attempt %d reset WriteFile(): %v", attempt, err)
		}
		start := make(chan struct{})
		errorsChannel := make(chan error, 2)
		var waitGroup sync.WaitGroup
		for _, operation := range []struct {
			store *fileStore
			key   string
		}{
			{store: first, key: "subscription-a"},
			{store: second, key: "subscription-b"},
		} {
			operation := operation
			waitGroup.Add(1)
			go func() {
				defer waitGroup.Done()
				<-start
				if err := operation.store.Set(context.Background(), operation.key, "secret"); err != nil {
					errorsChannel <- err
				}
			}()
		}
		close(start)
		waitGroup.Wait()
		close(errorsChannel)
		for err := range errorsChannel {
			t.Fatalf("attempt %d concurrent Set() failed: %v", attempt, err)
		}

		for _, key := range []string{"subscription-a", "subscription-b"} {
			if _, err := first.Get(context.Background(), key); err != nil {
				t.Fatalf("attempt %d lost concurrent update %q: %v", attempt, key, err)
			}
		}
	}
}

func TestFileStoreRefusesSymlinkedAncestor(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	target := filepath.Join(root, "target")
	if err := os.Mkdir(target, 0o700); err != nil {
		t.Fatalf("Mkdir(): %v", err)
	}
	ancestor := filepath.Join(root, "ancestor")
	if err := os.Symlink(target, ancestor); err != nil {
		t.Fatalf("Symlink(): %v", err)
	}
	if _, err := newFileStore(filepath.Join(ancestor, "nested", "secrets")); err == nil {
		t.Fatal("newFileStore() accepted a symlinked ancestor")
	}
}

func TestFileStoreErrorsDoNotLeakStoredSecrets(t *testing.T) {
	t.Parallel()

	const secret = "https://user:password@example.com/private?token=query-secret"
	directory := filepath.Join(t.TempDir(), "secrets")
	if err := os.Mkdir(directory, 0o700); err != nil {
		t.Fatalf("Mkdir(): %v", err)
	}
	path := filepath.Join(directory, fallbackFileName)
	if err := os.WriteFile(path, []byte(`{"subscription-1":`+secret), 0o600); err != nil {
		t.Fatalf("WriteFile(): %v", err)
	}
	store, err := newFileStore(directory)
	if err != nil {
		t.Fatalf("newFileStore() returned an unexpected error: %v", err)
	}
	_, err = store.Get(context.Background(), "subscription-1")
	if err == nil {
		t.Fatal("Get() returned nil error for malformed file")
	}
	for _, sensitive := range []string{secret, "password", "example.com", "query-secret"} {
		if strings.Contains(err.Error(), sensitive) {
			t.Fatalf("file error leaked %q: %v", sensitive, err)
		}
	}
}

func assertFileMode(t *testing.T, path string, want os.FileMode) {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat(%q): %v", path, err)
	}
	if got := info.Mode().Perm(); got != want {
		t.Fatalf("mode for %q = %04o, want %04o", path, got, want)
	}
}

func assertNoTemporaryFiles(t *testing.T, directory string) {
	t.Helper()
	entries, err := os.ReadDir(directory)
	if err != nil {
		t.Fatalf("ReadDir(): %v", err)
	}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), "."+fallbackFileName+"-") {
			t.Fatalf("temporary file remains after atomic write: %q", entry.Name())
		}
	}
}

package secrets

import (
	"context"
	"encoding/json"
	"errors"
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

func TestFileStoreEnforcesPerSecretSizeBoundary(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "secrets")
	store, err := newFileStore(directory)
	if err != nil {
		t.Fatalf("newFileStore() returned an unexpected error: %v", err)
	}
	atLimit := strings.Repeat("x", maxSecretBytes)
	if err := store.Set(context.Background(), "at-limit", atLimit); err != nil {
		t.Fatalf("Set() rejected %d-byte secret: %v", maxSecretBytes, err)
	}
	got, err := store.Get(context.Background(), "at-limit")
	if err != nil {
		t.Fatalf("Get() at boundary returned an unexpected error: %v", err)
	}
	if got != atLimit {
		t.Fatalf("Get() returned %d bytes, want %d", len(got), len(atLimit))
	}

	if err := store.Set(context.Background(), "over-limit", atLimit+"x"); err == nil {
		t.Fatalf("Set() accepted %d-byte secret", maxSecretBytes+1)
	}
	if _, err := store.Get(context.Background(), "over-limit"); !errors.Is(err, ErrSecretNotFound) {
		t.Fatalf("Get() rejected secret error = %v, want ErrSecretNotFound", err)
	}
}

func TestFileStoreRejectsSecretThatCannotRoundTripThroughJSON(t *testing.T) {
	store, err := newFileStore(filepath.Join(t.TempDir(), "secrets"))
	if err != nil {
		t.Fatalf("newFileStore() returned an unexpected error: %v", err)
	}
	if err := store.Set(context.Background(), "invalid", string([]byte{0xff})); err == nil {
		t.Fatal("Set() accepted invalid UTF-8 secret")
	}
	if _, err := store.Get(context.Background(), "invalid"); !errors.Is(err, ErrSecretNotFound) {
		t.Fatalf("Get() rejected secret error = %v, want ErrSecretNotFound", err)
	}
}

func TestFileStoreEnforcesEncodedFileSizeBoundaryBeforeWrite(t *testing.T) {
	for _, test := range []struct {
		name       string
		targetSize int
		wantError  bool
	}{
		{name: "exact limit is readable", targetSize: maxFallbackFileBytes},
		{name: "one byte above is rejected", targetSize: maxFallbackFileBytes + 1, wantError: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			directory := filepath.Join(t.TempDir(), "secrets")
			store, err := newFileStore(directory)
			if err != nil {
				t.Fatalf("newFileStore() returned an unexpected error: %v", err)
			}
			values, target := fallbackValuesForEncodedSize(t, test.targetSize, "boundary")
			encoded, err := json.Marshal(values)
			if err != nil {
				t.Fatalf("json.Marshal() fixture: %v", err)
			}
			encoded = append(encoded, '\n')
			path := filepath.Join(directory, fallbackFileName)
			if err := os.WriteFile(path, encoded, 0o600); err != nil {
				t.Fatalf("WriteFile() fixture: %v", err)
			}

			before, err := os.Stat(path)
			if err != nil {
				t.Fatalf("Stat() before Set: %v", err)
			}
			err = store.Set(context.Background(), "boundary", target)
			if test.wantError {
				if err == nil {
					t.Fatalf("Set() accepted encoded file above %d bytes", maxFallbackFileBytes)
				}
				after, statErr := os.Stat(path)
				if statErr != nil {
					t.Fatalf("Stat() after rejected Set: %v", statErr)
				}
				if !os.SameFile(before, after) {
					t.Fatal("rejected Set() replaced the fallback file")
				}
				return
			}
			if err != nil {
				t.Fatalf("Set() at encoded boundary returned an unexpected error: %v", err)
			}
			info, err := os.Stat(path)
			if err != nil {
				t.Fatalf("Stat() boundary file: %v", err)
			}
			if info.Size() != int64(maxFallbackFileBytes) {
				t.Fatalf("fallback file size = %d, want %d", info.Size(), maxFallbackFileBytes)
			}
			got, err := store.Get(context.Background(), "boundary")
			if err != nil {
				t.Fatalf("Get() encoded boundary: %v", err)
			}
			if got != target {
				t.Fatalf("Get() boundary secret length = %d, want %d", len(got), len(target))
			}
		})
	}
}

func TestFileStoreOperationsRemainAnchoredAfterDirectoryPathReplacement(t *testing.T) {
	base := t.TempDir()
	directory := filepath.Join(base, "secrets")
	store, err := newFileStore(directory)
	if err != nil {
		t.Fatalf("newFileStore() returned an unexpected error: %v", err)
	}
	moved := filepath.Join(base, "moved")
	if err := os.Rename(directory, moved); err != nil {
		t.Fatalf("Rename() secret directory: %v", err)
	}
	attacker := filepath.Join(base, "attacker")
	if err := os.Mkdir(attacker, 0o700); err != nil {
		t.Fatalf("Mkdir() attacker directory: %v", err)
	}
	if err := os.Symlink(attacker, directory); err != nil {
		t.Fatalf("Symlink() replacement: %v", err)
	}

	if err := store.Set(context.Background(), "subscription-1", "secret"); err != nil {
		t.Fatalf("Set() through held root returned an unexpected error: %v", err)
	}
	assertFileMode(t, filepath.Join(moved, fallbackFileName), 0o600)
	assertFileMode(t, filepath.Join(moved, fallbackLockFileName), 0o600)
	if _, err := os.Stat(filepath.Join(attacker, fallbackFileName)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("replacement directory received fallback write: %v", err)
	}
}

func TestFileStorePreservesCanceledContextIdentity(t *testing.T) {
	store, err := newFileStore(filepath.Join(t.TempDir(), "secrets"))
	if err != nil {
		t.Fatalf("newFileStore() returned an unexpected error: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := store.Set(ctx, "subscription-1", "secret"); !errors.Is(err, context.Canceled) {
		t.Fatalf("Set() error = %v, want context.Canceled", err)
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

func fallbackValuesForEncodedSize(t *testing.T, targetSize int, targetKey string) (map[string]string, string) {
	t.Helper()
	values := make(map[string]string)
	encodedSize := len("{}\n")
	for index := 0; ; index++ {
		targetOverhead := len(targetKey) + 6
		if len(values) == 0 {
			targetOverhead = len(targetKey) + 8
		}
		targetLength := targetSize - encodedSize - targetOverhead
		if targetLength > 0 && targetLength <= maxSecretBytes {
			target := strings.Repeat("t", targetLength)
			withTarget := make(map[string]string, len(values)+1)
			for key, value := range values {
				withTarget[key] = value
			}
			withTarget[targetKey] = target
			encoded, err := json.Marshal(withTarget)
			if err != nil {
				t.Fatalf("json.Marshal() boundary fixture: %v", err)
			}
			if len(encoded)+1 != targetSize {
				t.Fatalf("boundary fixture size = %d, want %d", len(encoded)+1, targetSize)
			}
			return values, target
		}

		key := fmt.Sprintf("filler-%04d", index)
		desiredTargetLength := maxSecretBytes / 2
		valueLength := targetLength - desiredTargetLength - len(key) - 6
		if valueLength > maxSecretBytes {
			valueLength = maxSecretBytes
		}
		if valueLength <= 0 {
			t.Fatalf("cannot construct %d-byte fallback fixture", targetSize)
		}
		values[key] = strings.Repeat("f", valueLength)
		if len(values) == 1 {
			encodedSize = len(key) + valueLength + 8
		} else {
			encodedSize += len(key) + valueLength + 6
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

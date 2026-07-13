package secrets

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sync"

	"github.com/rezraf/tui-box/internal/filelock"
	"github.com/rezraf/tui-box/internal/securepath"
)

const (
	fallbackFileName     = "secrets.json"
	fallbackLockFileName = ".secrets.lock"
	maxFallbackFileBytes = 10 << 20
)

var errFallbackStore = errors.New("local secret store operation failed")

type fileStore struct {
	directory string
	path      string
	lockPath  string
	mu        sync.Mutex
}

func newFileStore(directory string) (*fileStore, error) {
	if err := ensurePrivateDirectory(directory); err != nil {
		return nil, errFallbackStore
	}
	path := filepath.Join(directory, fallbackFileName)
	if err := validatePrivateFileIfPresent(path); err != nil {
		return nil, errFallbackStore
	}
	return &fileStore{directory: directory, path: path, lockPath: filepath.Join(directory, fallbackLockFileName)}, nil
}

func (store *fileStore) Get(ctx context.Context, key string) (string, error) {
	if !validSecretKey(key) {
		return "", errors.New("secret key is invalid")
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if err := contextError(ctx); err != nil {
		return "", err
	}
	lock, err := store.acquireFileLock()
	if err != nil {
		return "", err
	}
	defer lock.Close()
	values, err := store.loadLocked()
	if err != nil {
		return "", err
	}
	value, exists := values[key]
	if !exists {
		return "", ErrSecretNotFound
	}
	return value, nil
}

func (store *fileStore) Set(ctx context.Context, key, secret string) error {
	if !validSecretKey(key) {
		return errors.New("secret key is invalid")
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if err := contextError(ctx); err != nil {
		return err
	}
	lock, err := store.acquireFileLock()
	if err != nil {
		return err
	}
	defer lock.Close()
	values, err := store.loadLocked()
	if err != nil {
		return err
	}
	values[key] = secret
	return store.writeLocked(values)
}

func (store *fileStore) Delete(ctx context.Context, key string) error {
	if !validSecretKey(key) {
		return errors.New("secret key is invalid")
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if err := contextError(ctx); err != nil {
		return err
	}
	lock, err := store.acquireFileLock()
	if err != nil {
		return err
	}
	defer lock.Close()
	values, err := store.loadLocked()
	if err != nil {
		return err
	}
	if _, exists := values[key]; !exists {
		return nil
	}
	delete(values, key)
	return store.writeLocked(values)
}

func (store *fileStore) acquireFileLock() (*filelock.Lock, error) {
	if err := ensurePrivateDirectory(store.directory); err != nil {
		return nil, errFallbackStore
	}
	lock, err := filelock.Acquire(store.lockPath)
	if err != nil {
		return nil, errFallbackStore
	}
	return lock, nil
}

func (store *fileStore) loadLocked() (map[string]string, error) {
	if err := ensurePrivateDirectory(store.directory); err != nil {
		return nil, errFallbackStore
	}
	info, err := os.Lstat(store.path)
	if errors.Is(err, os.ErrNotExist) {
		return make(map[string]string), nil
	}
	if err != nil || !validPrivateFileInfo(info) {
		return nil, errFallbackStore
	}

	file, err := os.Open(store.path)
	if err != nil {
		return nil, errFallbackStore
	}
	defer file.Close()
	openedInfo, err := file.Stat()
	if err != nil || !os.SameFile(info, openedInfo) || !validPrivateFileInfo(openedInfo) {
		return nil, errFallbackStore
	}

	decoder := json.NewDecoder(io.LimitReader(file, maxFallbackFileBytes+1))
	var values map[string]string
	if err := decoder.Decode(&values); err != nil {
		return nil, errFallbackStore
	}
	if err := requireJSONEOF(decoder); err != nil {
		return nil, errFallbackStore
	}
	if values == nil {
		values = make(map[string]string)
	}
	return values, nil
}

func (store *fileStore) writeLocked(values map[string]string) error {
	if err := ensurePrivateDirectory(store.directory); err != nil {
		return errFallbackStore
	}
	if err := validatePrivateFileIfPresent(store.path); err != nil {
		return errFallbackStore
	}
	encoded, err := json.Marshal(values)
	if err != nil {
		return errFallbackStore
	}
	encoded = append(encoded, '\n')

	temporary, err := os.CreateTemp(store.directory, "."+fallbackFileName+"-")
	if err != nil {
		return errFallbackStore
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)

	if err := temporary.Chmod(0o600); err != nil {
		_ = temporary.Close()
		return errFallbackStore
	}
	if _, err := temporary.Write(encoded); err != nil {
		_ = temporary.Close()
		return errFallbackStore
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return errFallbackStore
	}
	if err := temporary.Close(); err != nil {
		return errFallbackStore
	}
	if err := os.Rename(temporaryPath, store.path); err != nil {
		return errFallbackStore
	}
	if err := syncDirectory(store.directory); err != nil {
		return errFallbackStore
	}
	return nil
}

func ensurePrivateDirectory(directory string) error {
	if err := securepath.EnsurePrivateDirectory(directory); err != nil {
		return errFallbackStore
	}
	return nil
}

func validatePrivateFileIfPresent(path string) error {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil || !validPrivateFileInfo(info) {
		return errFallbackStore
	}
	return nil
}

func validPrivateFileInfo(info os.FileInfo) bool {
	return info.Mode().IsRegular() && info.Mode().Perm()&0o077 == 0
}

func requireJSONEOF(decoder *json.Decoder) error {
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return errFallbackStore
	}
	return nil
}

func syncDirectory(directory string) error {
	file, err := os.Open(directory)
	if err != nil {
		return err
	}
	defer file.Close()
	return file.Sync()
}

func contextError(ctx context.Context) error {
	select {
	case <-ctx.Done():
		return errors.New("secret operation canceled")
	default:
		return nil
	}
}

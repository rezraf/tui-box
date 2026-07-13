package secrets

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"sync"
	"unicode/utf8"

	"github.com/rezraf/tui-box/internal/filelock"
	"github.com/rezraf/tui-box/internal/securepath"
	"golang.org/x/sys/unix"
)

const (
	fallbackFileName     = "secrets.json"
	fallbackLockFileName = ".secrets.lock"
	maxSecretBytes       = 64 << 10
	maxFallbackFileBytes = 10 << 20
)

var errFallbackStore = errors.New("local secret store operation failed")

type fileStore struct {
	lifecycle sync.RWMutex
	root      *os.Root
	closed    bool
	closeErr  error
}

func newFileStore(directory string) (*fileStore, error) {
	root, err := securepath.OpenPrivateRoot(directory)
	if err != nil {
		return nil, errFallbackStore
	}
	if err := validatePrivateFileIfPresent(root, fallbackFileName); err != nil {
		_ = root.Close()
		return nil, errFallbackStore
	}
	return &fileStore{root: root}, nil
}

func (store *fileStore) Get(ctx context.Context, key string) (string, error) {
	if err := store.beginOperation(); err != nil {
		return "", err
	}
	defer store.endOperation()

	if !validSecretKey(key) {
		return "", errors.New("secret key is invalid")
	}
	if err := contextError(ctx); err != nil {
		return "", err
	}
	lock, err := store.acquireFileLock(ctx)
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
	if err := store.beginOperation(); err != nil {
		return err
	}
	defer store.endOperation()

	if !validSecretKey(key) {
		return errors.New("secret key is invalid")
	}
	if len(secret) > maxSecretBytes || !utf8.ValidString(secret) {
		return errFallbackStore
	}
	if err := contextError(ctx); err != nil {
		return err
	}
	lock, err := store.acquireFileLock(ctx)
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
	if err := store.beginOperation(); err != nil {
		return err
	}
	defer store.endOperation()

	if !validSecretKey(key) {
		return errors.New("secret key is invalid")
	}
	if err := contextError(ctx); err != nil {
		return err
	}
	lock, err := store.acquireFileLock(ctx)
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

func (store *fileStore) Close() error {
	store.lifecycle.Lock()
	defer store.lifecycle.Unlock()
	if store.closed {
		return store.closeErr
	}
	store.closed = true
	if err := store.root.Close(); err != nil {
		store.closeErr = errFallbackStore
	}
	return store.closeErr
}

func (store *fileStore) beginOperation() error {
	store.lifecycle.RLock()
	if store.closed {
		store.lifecycle.RUnlock()
		return ErrSecretStoreClosed
	}
	return nil
}

func (store *fileStore) endOperation() {
	store.lifecycle.RUnlock()
}

func (store *fileStore) acquireFileLock(ctx context.Context) (*filelock.Lock, error) {
	if err := securepath.ValidatePrivateRoot(store.root); err != nil {
		return nil, errFallbackStore
	}
	lock, err := filelock.Acquire(ctx, store.root, fallbackLockFileName)
	if err == nil {
		return lock, nil
	}
	if contextErr := contextOperationError(ctx, err); contextErr != nil {
		return nil, contextErr
	}
	return nil, errFallbackStore
}

func (store *fileStore) loadLocked() (map[string]string, error) {
	if err := securepath.ValidatePrivateRoot(store.root); err != nil {
		return nil, errFallbackStore
	}
	info, err := store.root.Lstat(fallbackFileName)
	if errors.Is(err, os.ErrNotExist) {
		return make(map[string]string), nil
	}
	if err != nil || !validPrivateFileInfo(info) || info.Size() > maxFallbackFileBytes {
		return nil, errFallbackStore
	}

	file, err := store.root.OpenFile(fallbackFileName, os.O_RDONLY|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, errFallbackStore
	}
	defer file.Close()
	openedInfo, err := file.Stat()
	if err != nil || !os.SameFile(info, openedInfo) || !validPrivateFileInfo(openedInfo) || openedInfo.Size() > maxFallbackFileBytes {
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
	if err := validateFallbackValues(values); err != nil {
		return nil, errFallbackStore
	}
	return values, nil
}

func (store *fileStore) writeLocked(values map[string]string) error {
	if err := securepath.ValidatePrivateRoot(store.root); err != nil {
		return errFallbackStore
	}
	if err := validatePrivateFileIfPresent(store.root, fallbackFileName); err != nil {
		return errFallbackStore
	}
	if err := validateFallbackValues(values); err != nil {
		return errFallbackStore
	}
	encoded, err := json.Marshal(values)
	if err != nil {
		return errFallbackStore
	}
	encoded = append(encoded, '\n')
	if len(encoded) > maxFallbackFileBytes {
		return errFallbackStore
	}

	temporary, temporaryName, err := securepath.CreatePrivateTemp(store.root, "."+fallbackFileName+"-")
	if err != nil {
		return errFallbackStore
	}
	defer store.root.Remove(temporaryName)
	if _, err := temporary.Write(encoded); err != nil {
		_ = temporary.Close()
		return errFallbackStore
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return errFallbackStore
	}
	temporaryInfo, err := temporary.Stat()
	if err != nil || !validPrivateFileInfo(temporaryInfo) || temporaryInfo.Size() != int64(len(encoded)) {
		_ = temporary.Close()
		return errFallbackStore
	}
	if err := temporary.Close(); err != nil {
		return errFallbackStore
	}
	if err := store.root.Rename(temporaryName, fallbackFileName); err != nil {
		return errFallbackStore
	}
	finalInfo, err := store.root.Lstat(fallbackFileName)
	if err != nil || !os.SameFile(temporaryInfo, finalInfo) || !validPrivateFileInfo(finalInfo) || finalInfo.Size() != int64(len(encoded)) {
		return errFallbackStore
	}
	if err := securepath.SyncRoot(store.root); err != nil {
		return errFallbackStore
	}
	return nil
}

func validatePrivateFileIfPresent(root *os.Root, name string) error {
	info, err := root.Lstat(name)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil || !validPrivateFileInfo(info) {
		return errFallbackStore
	}
	return nil
}

func validPrivateFileInfo(info os.FileInfo) bool {
	return info.Mode().IsRegular() && info.Mode().Perm() == 0o600
}

func validateFallbackValues(values map[string]string) error {
	for key, secret := range values {
		if !validSecretKey(key) || len(secret) > maxSecretBytes || !utf8.ValidString(secret) {
			return errFallbackStore
		}
	}
	return nil
}

func requireJSONEOF(decoder *json.Decoder) error {
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return errFallbackStore
	}
	return nil
}

func contextError(ctx context.Context) error {
	return ctx.Err()
}

package state

import (
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"unicode"
	"unicode/utf8"

	"github.com/rezraf/tui-box/internal/domain"
)

const (
	CurrentSchemaVersion = 1
	StateFileName        = "state.json"
	maxStateFileBytes    = 64 << 20
	maxLastErrorBytes    = 4096
	maxRefreshInterval   = 366 * 24 * 60 * 60
)

var (
	errStateStore   = errors.New("state store operation failed")
	errInvalidState = errors.New("state file is invalid")
)

type Snapshot struct {
	SchemaVersion int                   `json:"schema_version"`
	Subscriptions []domain.Subscription `json:"subscriptions"`
	Endpoints     []domain.Endpoint     `json:"endpoints"`
}

type Store struct {
	directory string
	path      string
	mu        sync.Mutex
}

func NewStore(directory string) (*Store, error) {
	if err := ensurePrivateStateDirectory(directory); err != nil {
		return nil, errStateStore
	}
	path := filepath.Join(directory, StateFileName)
	if err := validatePrivateStateFileIfPresent(path); err != nil {
		return nil, errStateStore
	}
	return &Store{directory: directory, path: path}, nil
}

func (store *Store) Load() (Snapshot, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	return store.loadLocked()
}

func (store *Store) Save(snapshot Snapshot) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	if err := validateSnapshot(snapshot); err != nil {
		return errInvalidState
	}
	return store.writeLocked(snapshot)
}

func (store *Store) CommitSubscriptionRefresh(subscriptionID string, endpoints []domain.Endpoint, refreshErr error) (bool, error) {
	if !validStateString(subscriptionID, domain.MaxIDLength, true) {
		return false, errInvalidState
	}
	if refreshErr != nil || len(endpoints) == 0 {
		return false, nil
	}
	if err := validateRefreshEndpoints(subscriptionID, endpoints); err != nil {
		return false, errInvalidState
	}

	store.mu.Lock()
	defer store.mu.Unlock()
	snapshot, err := store.loadLocked()
	if err != nil {
		return false, err
	}
	if !hasSubscription(snapshot.Subscriptions, subscriptionID) {
		return false, errInvalidState
	}

	replaced := make([]domain.Endpoint, 0, len(snapshot.Endpoints)+len(endpoints))
	for _, endpoint := range snapshot.Endpoints {
		if endpoint.SubscriptionID != subscriptionID {
			replaced = append(replaced, endpoint)
		}
	}
	replaced = append(replaced, endpoints...)
	snapshot.Endpoints = replaced
	if err := validateSnapshot(snapshot); err != nil {
		return false, errInvalidState
	}
	if err := store.writeLocked(snapshot); err != nil {
		return false, err
	}
	return true, nil
}

func (store *Store) loadLocked() (Snapshot, error) {
	if err := ensurePrivateStateDirectory(store.directory); err != nil {
		return Snapshot{}, errStateStore
	}
	info, err := os.Lstat(store.path)
	if errors.Is(err, os.ErrNotExist) {
		return Snapshot{SchemaVersion: CurrentSchemaVersion}, nil
	}
	if err != nil || !validPrivateStateFileInfo(info) || info.Size() > maxStateFileBytes {
		return Snapshot{}, errInvalidState
	}

	file, err := os.Open(store.path)
	if err != nil {
		return Snapshot{}, errStateStore
	}
	defer file.Close()
	openedInfo, err := file.Stat()
	if err != nil || !os.SameFile(info, openedInfo) || !validPrivateStateFileInfo(openedInfo) || openedInfo.Size() > maxStateFileBytes {
		return Snapshot{}, errInvalidState
	}

	decoder := json.NewDecoder(io.LimitReader(file, maxStateFileBytes+1))
	decoder.DisallowUnknownFields()
	var snapshot Snapshot
	if err := decoder.Decode(&snapshot); err != nil {
		return Snapshot{}, errInvalidState
	}
	if err := requireStateJSONEOF(decoder); err != nil {
		return Snapshot{}, errInvalidState
	}
	if err := validateSnapshot(snapshot); err != nil {
		return Snapshot{}, errInvalidState
	}
	return snapshot, nil
}

func (store *Store) writeLocked(snapshot Snapshot) error {
	if err := ensurePrivateStateDirectory(store.directory); err != nil {
		return errStateStore
	}
	if err := validatePrivateStateFileIfPresent(store.path); err != nil {
		return errStateStore
	}
	encoded, err := json.MarshalIndent(snapshot, "", "  ")
	if err != nil {
		return errStateStore
	}
	encoded = append(encoded, '\n')

	temporary, err := os.CreateTemp(store.directory, "."+StateFileName+"-")
	if err != nil {
		return errStateStore
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)

	if err := temporary.Chmod(0o600); err != nil {
		_ = temporary.Close()
		return errStateStore
	}
	if _, err := temporary.Write(encoded); err != nil {
		_ = temporary.Close()
		return errStateStore
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return errStateStore
	}
	if err := temporary.Close(); err != nil {
		return errStateStore
	}
	if err := os.Rename(temporaryPath, store.path); err != nil {
		return errStateStore
	}
	if err := syncStateDirectory(store.directory); err != nil {
		return errStateStore
	}
	return nil
}

func validateSnapshot(snapshot Snapshot) error {
	if snapshot.SchemaVersion != CurrentSchemaVersion {
		return errInvalidState
	}
	subscriptionIDs := make(map[string]struct{}, len(snapshot.Subscriptions))
	for _, subscription := range snapshot.Subscriptions {
		if err := validateSubscription(subscription); err != nil {
			return errInvalidState
		}
		if _, duplicate := subscriptionIDs[subscription.ID]; duplicate {
			return errInvalidState
		}
		subscriptionIDs[subscription.ID] = struct{}{}
	}

	endpointIDs := make(map[string]struct{}, len(snapshot.Endpoints))
	for _, endpoint := range snapshot.Endpoints {
		if err := endpoint.Validate(); err != nil {
			return errInvalidState
		}
		if _, exists := subscriptionIDs[endpoint.SubscriptionID]; !exists {
			return errInvalidState
		}
		if _, duplicate := endpointIDs[endpoint.ID]; duplicate {
			return errInvalidState
		}
		endpointIDs[endpoint.ID] = struct{}{}
	}
	return nil
}

func validateSubscription(subscription domain.Subscription) error {
	if !validStateString(subscription.ID, domain.MaxIDLength, true) ||
		!validStateString(subscription.Name, domain.MaxNameLength, true) ||
		!validStateString(subscription.SecretRef, domain.MaxCredentialLength, true) ||
		!validStateString(subscription.LastError, maxLastErrorBytes, false) {
		return errInvalidState
	}
	if subscription.RefreshIntervalSeconds < 0 || subscription.RefreshIntervalSeconds > maxRefreshInterval {
		return errInvalidState
	}
	switch subscription.Format {
	case domain.SubscriptionFormatURIList, domain.SubscriptionFormatBase64, domain.SubscriptionFormatClash, domain.SubscriptionFormatSingBox:
		return nil
	default:
		return errInvalidState
	}
}

func validateRefreshEndpoints(subscriptionID string, endpoints []domain.Endpoint) error {
	seen := make(map[string]struct{}, len(endpoints))
	for _, endpoint := range endpoints {
		if endpoint.SubscriptionID != subscriptionID {
			return errInvalidState
		}
		if err := endpoint.Validate(); err != nil {
			return errInvalidState
		}
		if _, duplicate := seen[endpoint.ID]; duplicate {
			return errInvalidState
		}
		seen[endpoint.ID] = struct{}{}
	}
	return nil
}

func hasSubscription(subscriptions []domain.Subscription, subscriptionID string) bool {
	for _, subscription := range subscriptions {
		if subscription.ID == subscriptionID {
			return true
		}
	}
	return false
}

func validStateString(value string, maxBytes int, required bool) bool {
	if required && strings.TrimSpace(value) == "" {
		return false
	}
	if !utf8.ValidString(value) || len(value) > maxBytes {
		return false
	}
	for _, character := range value {
		if unicode.IsControl(character) {
			return false
		}
	}
	return true
}

func ensurePrivateStateDirectory(directory string) error {
	if directory == "" {
		return errStateStore
	}
	info, err := os.Lstat(directory)
	if errors.Is(err, os.ErrNotExist) {
		if err := os.MkdirAll(directory, 0o700); err != nil {
			return errStateStore
		}
		if err := os.Chmod(directory, 0o700); err != nil {
			return errStateStore
		}
		info, err = os.Lstat(directory)
	}
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() || info.Mode().Perm()&0o077 != 0 {
		return errStateStore
	}
	return nil
}

func validatePrivateStateFileIfPresent(path string) error {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil || !validPrivateStateFileInfo(info) {
		return errStateStore
	}
	return nil
}

func validPrivateStateFileInfo(info os.FileInfo) bool {
	return info.Mode().IsRegular() && info.Mode().Perm()&0o077 == 0
}

func requireStateJSONEOF(decoder *json.Decoder) error {
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return errInvalidState
	}
	return nil
}

func syncStateDirectory(directory string) error {
	file, err := os.Open(directory)
	if err != nil {
		return err
	}
	defer file.Close()
	return file.Sync()
}

package state

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"math"
	"os"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/rezraf/tui-box/internal/domain"
	"github.com/rezraf/tui-box/internal/filelock"
	"github.com/rezraf/tui-box/internal/securepath"
	"github.com/rezraf/tui-box/internal/strictjson"
	"github.com/rezraf/tui-box/internal/terminaltext"
	"golang.org/x/sys/unix"
)

const (
	CurrentSchemaVersion     = 1
	StateFileName            = "state.json"
	StateLockFileName        = ".state.lock"
	MaxStateSubscriptions    = 1024
	MaxStateEndpoints        = 10_000
	maxStateFileBytes        = 64 << 20
	maxLastErrorBytes        = 4096
	maxRefreshInterval       = 366 * 24 * 60 * 60
	endpointIdentityKeyBytes = 32
	defaultOperationTimeout  = 5 * time.Second
)

var (
	ErrStateConflict    = errors.New("state revision conflict")
	ErrStateStoreClosed = errors.New("state store is closed")
	errStateStore       = errors.New("state store operation failed")
	errInvalidState     = errors.New("state file is invalid")
)

type Settings struct {
	TelemetryEnabled    bool   `json:"telemetry_enabled"`
	EndpointIdentityKey string `json:"endpoint_identity_key,omitempty"`
}

type Snapshot struct {
	SchemaVersion int                   `json:"schema_version"`
	Revision      uint64                `json:"revision"`
	Subscriptions []domain.Subscription `json:"subscriptions"`
	Endpoints     []domain.Endpoint     `json:"endpoints"`
	Settings      Settings              `json:"settings"`
}

type Store struct {
	lifecycle sync.RWMutex
	root      *os.Root
	closed    bool
	closeErr  error
}

func NewStore(directory string) (*Store, error) {
	root, err := securepath.OpenPrivateRoot(directory)
	if err != nil {
		return nil, errStateStore
	}
	if err := validatePrivateStateFileIfPresent(root); err != nil {
		_ = root.Close()
		return nil, errStateStore
	}
	return &Store{root: root}, nil
}

func (store *Store) Load() (Snapshot, error) {
	ctx, cancel := defaultOperationContext()
	defer cancel()
	return store.LoadContext(ctx)
}

func (store *Store) LoadContext(ctx context.Context) (Snapshot, error) {
	if err := store.beginOperation(); err != nil {
		return Snapshot{}, err
	}
	defer store.endOperation()

	lock, err := store.acquireFileLock(ctx)
	if err != nil {
		return Snapshot{}, err
	}
	defer lock.Close()
	return store.loadLocked()
}

func (store *Store) Save(snapshot Snapshot) error {
	ctx, cancel := defaultOperationContext()
	defer cancel()
	return store.SaveContext(ctx, snapshot)
}

func (store *Store) SaveContext(ctx context.Context, snapshot Snapshot) error {
	if err := store.beginOperation(); err != nil {
		return err
	}
	defer store.endOperation()

	if err := validateSnapshot(snapshot); err != nil {
		return errInvalidState
	}
	if _, err := encodeSnapshot(snapshot); err != nil {
		return err
	}
	lock, err := store.acquireFileLock(ctx)
	if err != nil {
		return err
	}
	defer lock.Close()
	current, err := store.loadLocked()
	if err != nil {
		return err
	}
	if snapshot.Revision != current.Revision {
		return ErrStateConflict
	}
	if err := incrementRevision(&snapshot); err != nil {
		return err
	}
	return store.writeLocked(snapshot)
}

func (store *Store) Update(update func(*Snapshot) error) error {
	ctx, cancel := defaultOperationContext()
	defer cancel()
	return store.UpdateContext(ctx, update)
}

func (store *Store) UpdateContext(ctx context.Context, update func(*Snapshot) error) error {
	if err := store.beginOperation(); err != nil {
		return err
	}
	defer store.endOperation()
	return store.updateContext(ctx, update)
}

func (store *Store) updateContext(ctx context.Context, update func(*Snapshot) error) error {
	if update == nil {
		return errInvalidState
	}
	lock, err := store.acquireFileLock(ctx)
	if err != nil {
		return err
	}
	defer lock.Close()
	snapshot, err := store.loadLocked()
	if err != nil {
		return err
	}
	revision := snapshot.Revision
	if err := update(&snapshot); err != nil {
		return err
	}
	if snapshot.Revision != revision {
		return errInvalidState
	}
	if err := validateSnapshot(snapshot); err != nil {
		return errInvalidState
	}
	if err := incrementRevision(&snapshot); err != nil {
		return err
	}
	return store.writeLocked(snapshot)
}

func (store *Store) CommitSubscriptionRefresh(subscriptionID string, endpoints []domain.Endpoint, refreshErr error) (bool, error) {
	ctx, cancel := defaultOperationContext()
	defer cancel()
	return store.CommitSubscriptionRefreshContext(ctx, subscriptionID, endpoints, refreshErr)
}

func (store *Store) CommitSubscriptionRefreshContext(ctx context.Context, subscriptionID string, endpoints []domain.Endpoint, refreshErr error) (bool, error) {
	if err := store.beginOperation(); err != nil {
		return false, err
	}
	defer store.endOperation()

	if !validStateString(subscriptionID, domain.MaxIDLength, true) {
		return false, errInvalidState
	}
	if refreshErr != nil || len(endpoints) == 0 {
		return false, nil
	}
	if err := validateRefreshEndpoints(subscriptionID, endpoints); err != nil {
		return false, errInvalidState
	}

	committed := false
	err := store.updateContext(ctx, func(snapshot *Snapshot) error {
		if !hasSubscription(snapshot.Subscriptions, subscriptionID) {
			return errInvalidState
		}
		replaced := make([]domain.Endpoint, 0, len(snapshot.Endpoints)+len(endpoints))
		for _, endpoint := range snapshot.Endpoints {
			if endpoint.SubscriptionID != subscriptionID {
				replaced = append(replaced, endpoint)
			}
		}
		snapshot.Endpoints = append(replaced, endpoints...)
		committed = true
		return nil
	})
	if err != nil {
		return false, err
	}
	return committed, nil
}

func (store *Store) Close() error {
	store.lifecycle.Lock()
	defer store.lifecycle.Unlock()
	if store.closed {
		return store.closeErr
	}
	store.closed = true
	if err := store.root.Close(); err != nil {
		store.closeErr = errStateStore
	}
	return store.closeErr
}

func (store *Store) beginOperation() error {
	store.lifecycle.RLock()
	if store.closed {
		store.lifecycle.RUnlock()
		return ErrStateStoreClosed
	}
	return nil
}

func (store *Store) endOperation() {
	store.lifecycle.RUnlock()
}

func (store *Store) acquireFileLock(ctx context.Context) (*filelock.Lock, error) {
	if err := securepath.ValidatePrivateRoot(store.root); err != nil {
		return nil, errStateStore
	}
	lock, err := filelock.Acquire(ctx, store.root, StateLockFileName)
	if err == nil {
		return lock, nil
	}
	if contextErr := contextOperationError(ctx, err); contextErr != nil {
		return nil, contextErr
	}
	return nil, errStateStore
}

func defaultOperationContext() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), defaultOperationTimeout)
}

func contextOperationError(ctx context.Context, err error) error {
	if ctxErr := ctx.Err(); ctxErr != nil {
		return ctxErr
	}
	if errors.Is(err, context.Canceled) {
		return context.Canceled
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return context.DeadlineExceeded
	}
	return nil
}

func (store *Store) loadLocked() (Snapshot, error) {
	if err := securepath.ValidatePrivateRoot(store.root); err != nil {
		return Snapshot{}, errStateStore
	}
	info, err := store.root.Lstat(StateFileName)
	if errors.Is(err, os.ErrNotExist) {
		return Snapshot{SchemaVersion: CurrentSchemaVersion}, nil
	}
	if err != nil || !validPrivateStateFileInfo(info) || info.Size() > maxStateFileBytes {
		return Snapshot{}, errInvalidState
	}

	file, err := store.root.OpenFile(StateFileName, os.O_RDONLY|unix.O_NOFOLLOW, 0)
	if err != nil {
		return Snapshot{}, errStateStore
	}
	defer file.Close()
	openedInfo, err := file.Stat()
	if err != nil || !os.SameFile(info, openedInfo) || !validPrivateStateFileInfo(openedInfo) || openedInfo.Size() > maxStateFileBytes {
		return Snapshot{}, errInvalidState
	}

	if err := strictjson.ValidateUniqueObjectFields(io.LimitReader(file, maxStateFileBytes+1), strictjson.FoldedKeys); err != nil {
		return Snapshot{}, errInvalidState
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return Snapshot{}, errStateStore
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
	if err := securepath.ValidatePrivateRoot(store.root); err != nil {
		return errStateStore
	}
	if err := validatePrivateStateFileIfPresent(store.root); err != nil {
		return errStateStore
	}
	encoded, err := encodeSnapshot(snapshot)
	if err != nil {
		return err
	}

	temporary, temporaryName, err := securepath.CreatePrivateTemp(store.root, "."+StateFileName+"-")
	if err != nil {
		return errStateStore
	}
	defer store.root.Remove(temporaryName)
	if _, err := temporary.Write(encoded); err != nil {
		_ = temporary.Close()
		return errStateStore
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return errStateStore
	}
	temporaryInfo, err := temporary.Stat()
	if err != nil || !validPrivateStateFileInfo(temporaryInfo) || temporaryInfo.Size() != int64(len(encoded)) {
		_ = temporary.Close()
		return errStateStore
	}
	if err := temporary.Close(); err != nil {
		return errStateStore
	}
	if err := store.root.Rename(temporaryName, StateFileName); err != nil {
		return errStateStore
	}
	finalInfo, err := store.root.Lstat(StateFileName)
	if err != nil || !os.SameFile(temporaryInfo, finalInfo) || !validPrivateStateFileInfo(finalInfo) || finalInfo.Size() != int64(len(encoded)) {
		return errStateStore
	}
	if err := securepath.SyncRoot(store.root); err != nil {
		return errStateStore
	}
	return nil
}

func encodeSnapshot(snapshot Snapshot) ([]byte, error) {
	encoded, err := json.MarshalIndent(snapshot, "", "  ")
	if err != nil {
		return nil, errStateStore
	}
	encoded = append(encoded, '\n')
	if len(encoded) > maxStateFileBytes {
		return nil, errInvalidState
	}
	return encoded, nil
}

func incrementRevision(snapshot *Snapshot) error {
	if snapshot.Revision == math.MaxUint64 {
		return errInvalidState
	}
	snapshot.Revision++
	return nil
}

func validateSnapshot(snapshot Snapshot) error {
	if snapshot.SchemaVersion != CurrentSchemaVersion ||
		len(snapshot.Subscriptions) > MaxStateSubscriptions ||
		len(snapshot.Endpoints) > MaxStateEndpoints ||
		!validEndpointIdentityKey(snapshot.Settings.EndpointIdentityKey) {
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
		!validStateString(subscription.LastError, maxLastErrorBytes, false) ||
		!validStateString(subscription.RefreshToken, domain.MaxIDLength, false) {
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

func validEndpointIdentityKey(value string) bool {
	if value == "" {
		return true
	}
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == endpointIdentityKeyBytes
}

func validStateString(value string, maxBytes int, required bool) bool {
	if required && strings.TrimSpace(value) == "" {
		return false
	}
	if !utf8.ValidString(value) || len(value) > maxBytes {
		return false
	}
	return terminaltext.Valid(value)
}

func validatePrivateStateFileIfPresent(root *os.Root) error {
	info, err := root.Lstat(StateFileName)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil || !validPrivateStateFileInfo(info) {
		return errStateStore
	}
	return nil
}

func validPrivateStateFileInfo(info os.FileInfo) bool {
	return info.Mode().IsRegular() && info.Mode().Perm() == 0o600
}

func requireStateJSONEOF(decoder *json.Decoder) error {
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return errInvalidState
	}
	return nil
}

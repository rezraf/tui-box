package state

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"sync"
	"testing"

	"github.com/rezraf/tui-box/internal/domain"
)

func TestStoreUsesExplicitSchemaAndRestrictedPermissions(t *testing.T) {
	t.Parallel()

	directory := filepath.Join(t.TempDir(), "data", "tuibox")
	store, err := NewStore(directory)
	if err != nil {
		t.Fatalf("NewStore() returned an unexpected error: %v", err)
	}
	empty, err := store.Load()
	if err != nil {
		t.Fatalf("Load() empty store returned an unexpected error: %v", err)
	}
	if empty.SchemaVersion != CurrentSchemaVersion {
		t.Fatalf("empty schema version = %d, want %d", empty.SchemaVersion, CurrentSchemaVersion)
	}

	want := testSnapshot()
	if err := store.Save(want); err != nil {
		t.Fatalf("Save() returned an unexpected error: %v", err)
	}
	want.Revision = 1
	assertMode(t, directory, 0o700)
	assertMode(t, filepath.Join(directory, StateLockFileName), 0o600)
	path := filepath.Join(directory, StateFileName)
	assertMode(t, path, 0o600)

	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile(): %v", err)
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(content, &fields); err != nil {
		t.Fatalf("state JSON is malformed: %v", err)
	}
	if got := string(fields["schema_version"]); got != fmt.Sprint(CurrentSchemaVersion) {
		t.Fatalf("schema_version = %s, want %d", got, CurrentSchemaVersion)
	}

	got, err := store.Load()
	if err != nil {
		t.Fatalf("Load() returned an unexpected error: %v", err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("Load() = %#v, want %#v", got, want)
	}
}

func TestStoreAtomicallyReplacesStateFile(t *testing.T) {
	t.Parallel()

	directory := filepath.Join(t.TempDir(), "state")
	store, err := NewStore(directory)
	if err != nil {
		t.Fatalf("NewStore() returned an unexpected error: %v", err)
	}
	first := testSnapshot()
	if err := store.Save(first); err != nil {
		t.Fatalf("first Save() returned an unexpected error: %v", err)
	}
	path := filepath.Join(directory, StateFileName)
	before, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat() before replacement: %v", err)
	}

	second, err := store.Load()
	if err != nil {
		t.Fatalf("Load() before replacement: %v", err)
	}
	second.Subscriptions[0].Name = "Renamed"
	if err := store.Save(second); err != nil {
		t.Fatalf("second Save() returned an unexpected error: %v", err)
	}
	second.Revision++
	after, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat() after replacement: %v", err)
	}
	if os.SameFile(before, after) {
		t.Fatal("state file was modified in place, want atomic replacement")
	}
	assertNoStateTemporaryFiles(t, directory)

	got, err := store.Load()
	if err != nil {
		t.Fatalf("Load() returned an unexpected error: %v", err)
	}
	if !reflect.DeepEqual(got, second) {
		t.Fatalf("Load() = %#v, want second snapshot", got)
	}
}

func TestStoreStrictlyRejectsMalformedState(t *testing.T) {
	t.Parallel()

	valid, err := json.Marshal(testSnapshot())
	if err != nil {
		t.Fatalf("json.Marshal(): %v", err)
	}
	invalidSubscription := testSnapshot()
	invalidSubscription.Subscriptions[0].Name = ""
	invalidSubscriptionJSON, _ := json.Marshal(invalidSubscription)
	missingSubscriptionFormat := testSnapshot()
	missingSubscriptionFormat.Subscriptions[0].Format = ""
	missingSubscriptionFormatJSON, _ := json.Marshal(missingSubscriptionFormat)
	invalidEndpoint := testSnapshot()
	invalidEndpoint.Endpoints[0].Host = "invalid host"
	invalidEndpointJSON, _ := json.Marshal(invalidEndpoint)
	orphanEndpoint := testSnapshot()
	orphanEndpoint.Endpoints[0].SubscriptionID = "missing-subscription"
	orphanEndpointJSON, _ := json.Marshal(orphanEndpoint)

	tests := []struct {
		name    string
		content []byte
	}{
		{name: "malformed JSON", content: []byte(`{"schema_version":`)},
		{name: "unknown top-level field", content: append(valid[:len(valid)-1], []byte(`,"unexpected":true}`)...)},
		{name: "unknown nested field", content: []byte(`{"schema_version":1,"subscriptions":[{"id":"subscription-a","name":"A","secret_ref":"secret-a","format":"uri-list","refresh_interval_seconds":900,"unexpected":true}],"endpoints":[]}`)},
		{name: "trailing JSON", content: append(append([]byte(nil), valid...), []byte(` {}`)...)},
		{name: "unsupported schema", content: []byte(`{"schema_version":999,"subscriptions":[],"endpoints":[]}`)},
		{name: "invalid subscription", content: invalidSubscriptionJSON},
		{name: "missing subscription format", content: missingSubscriptionFormatJSON},
		{name: "invalid endpoint", content: invalidEndpointJSON},
		{name: "orphan endpoint", content: orphanEndpointJSON},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			directory := filepath.Join(t.TempDir(), "state")
			store, err := NewStore(directory)
			if err != nil {
				t.Fatalf("NewStore() returned an unexpected error: %v", err)
			}
			if err := os.WriteFile(filepath.Join(directory, StateFileName), test.content, 0o600); err != nil {
				t.Fatalf("WriteFile(): %v", err)
			}
			_, err = store.Load()
			if err == nil {
				t.Fatal("Load() returned nil error, want strict rejection")
			}
			if strings.Contains(err.Error(), string(test.content)) {
				t.Fatal("Load() error leaked state content")
			}
		})
	}
}

func TestStoreRefusesSymlinksAndUnsafeExistingPermissions(t *testing.T) {
	t.Parallel()

	t.Run("symlink state file", func(t *testing.T) {
		directory := filepath.Join(t.TempDir(), "state")
		if err := os.Mkdir(directory, 0o700); err != nil {
			t.Fatalf("Mkdir(): %v", err)
		}
		target := filepath.Join(t.TempDir(), "target.json")
		content, _ := json.Marshal(Snapshot{SchemaVersion: CurrentSchemaVersion})
		if err := os.WriteFile(target, content, 0o600); err != nil {
			t.Fatalf("WriteFile(): %v", err)
		}
		if err := os.Symlink(target, filepath.Join(directory, StateFileName)); err != nil {
			t.Fatalf("Symlink(): %v", err)
		}
		if _, err := NewStore(directory); err == nil {
			t.Fatal("NewStore() accepted a symlink state file")
		}
	})

	t.Run("symlink data directory", func(t *testing.T) {
		target := filepath.Join(t.TempDir(), "target")
		if err := os.Mkdir(target, 0o700); err != nil {
			t.Fatalf("Mkdir(): %v", err)
		}
		directory := filepath.Join(t.TempDir(), "state-link")
		if err := os.Symlink(target, directory); err != nil {
			t.Fatalf("Symlink(): %v", err)
		}
		if _, err := NewStore(directory); err == nil {
			t.Fatal("NewStore() accepted a symlink data directory")
		}
	})

	t.Run("symlink nested ancestor", func(t *testing.T) {
		root := t.TempDir()
		target := filepath.Join(root, "target")
		if err := os.Mkdir(target, 0o700); err != nil {
			t.Fatalf("Mkdir(): %v", err)
		}
		ancestor := filepath.Join(root, "ancestor")
		if err := os.Symlink(target, ancestor); err != nil {
			t.Fatalf("Symlink(): %v", err)
		}
		if _, err := NewStore(filepath.Join(ancestor, "nested", "state")); err == nil {
			t.Fatal("NewStore() accepted a symlinked ancestor")
		}
	})

	t.Run("unsafe data directory mode", func(t *testing.T) {
		directory := filepath.Join(t.TempDir(), "state")
		if err := os.Mkdir(directory, 0o755); err != nil {
			t.Fatalf("Mkdir(): %v", err)
		}
		if _, err := NewStore(directory); err == nil {
			t.Fatal("NewStore() accepted group/world-readable data directory")
		}
	})

	t.Run("unsafe state file mode", func(t *testing.T) {
		directory := filepath.Join(t.TempDir(), "state")
		if err := os.Mkdir(directory, 0o700); err != nil {
			t.Fatalf("Mkdir(): %v", err)
		}
		content, _ := json.Marshal(Snapshot{SchemaVersion: CurrentSchemaVersion})
		if err := os.WriteFile(filepath.Join(directory, StateFileName), content, 0o644); err != nil {
			t.Fatalf("WriteFile(): %v", err)
		}
		if _, err := NewStore(directory); err == nil {
			t.Fatal("NewStore() accepted group/world-readable state file")
		}
	})
}

func TestStoreAllowsMacOSTemporaryDirectoryAlias(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("macOS system alias behavior")
	}

	temporaryRoot := t.TempDir()
	resolvedRoot, err := filepath.EvalSymlinks(temporaryRoot)
	if err != nil {
		t.Fatalf("EvalSymlinks(): %v", err)
	}
	if temporaryRoot == resolvedRoot {
		t.Skip("temporary directory does not traverse the /var system alias")
	}
	if _, err := NewStore(filepath.Join(temporaryRoot, "nested", "state")); err != nil {
		t.Fatalf("NewStore() rejected trusted macOS temporary-directory alias: %v", err)
	}
}

func TestCommitSubscriptionRefreshPreservesLastKnownGoodCache(t *testing.T) {
	t.Parallel()

	directory := filepath.Join(t.TempDir(), "state")
	store, err := NewStore(directory)
	if err != nil {
		t.Fatalf("NewStore() returned an unexpected error: %v", err)
	}
	original := testSnapshot()
	if err := store.Save(original); err != nil {
		t.Fatalf("Save() returned an unexpected error: %v", err)
	}
	original.Revision = 1
	path := filepath.Join(directory, StateFileName)
	before, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat(): %v", err)
	}

	committed, err := store.CommitSubscriptionRefresh("subscription-a", nil, nil)
	if err != nil || committed {
		t.Fatalf("empty refresh = (%t, %v), want preserved cache", committed, err)
	}
	candidate := []domain.Endpoint{testEndpoint("new-a", "subscription-a", "new-a.example.com")}
	committed, err = store.CommitSubscriptionRefresh("subscription-a", candidate, errors.New("fetch failed with a private URL"))
	if err != nil || committed {
		t.Fatalf("failed refresh = (%t, %v), want preserved cache", committed, err)
	}

	after, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat() after preserved refresh: %v", err)
	}
	if !os.SameFile(before, after) {
		t.Fatal("preserved refresh rewrote the state file")
	}
	got, err := store.Load()
	if err != nil {
		t.Fatalf("Load() returned an unexpected error: %v", err)
	}
	if !reflect.DeepEqual(got, original) {
		t.Fatalf("cache changed after empty or failed refresh: %#v", got)
	}
}

func TestCommitSubscriptionRefreshReplacesOnlyTargetSubscriptionTransactionally(t *testing.T) {
	t.Parallel()

	directory := filepath.Join(t.TempDir(), "state")
	store, err := NewStore(directory)
	if err != nil {
		t.Fatalf("NewStore() returned an unexpected error: %v", err)
	}
	original := testSnapshot()
	if err := store.Save(original); err != nil {
		t.Fatalf("Save() returned an unexpected error: %v", err)
	}
	original.Revision = 1

	invalid := []domain.Endpoint{testEndpoint("invalid", "subscription-a", "invalid host")}
	committed, err := store.CommitSubscriptionRefresh("subscription-a", invalid, nil)
	if err == nil || committed {
		t.Fatalf("invalid refresh = (%t, %v), want rejection", committed, err)
	}
	preserved, err := store.Load()
	if err != nil {
		t.Fatalf("Load() after invalid refresh: %v", err)
	}
	if !reflect.DeepEqual(preserved, original) {
		t.Fatal("invalid refresh changed cached endpoints")
	}

	replacement := []domain.Endpoint{
		testEndpoint("new-a-1", "subscription-a", "new-a-1.example.com"),
		testEndpoint("new-a-2", "subscription-a", "new-a-2.example.com"),
	}
	committed, err = store.CommitSubscriptionRefresh("subscription-a", replacement, nil)
	if err != nil || !committed {
		t.Fatalf("valid refresh = (%t, %v), want committed replacement", committed, err)
	}
	got, err := store.Load()
	if err != nil {
		t.Fatalf("Load() returned an unexpected error: %v", err)
	}
	if len(got.Endpoints) != 3 {
		t.Fatalf("len(Endpoints) = %d, want two replacements plus preserved subscription B", len(got.Endpoints))
	}
	assertEndpointIDs(t, got.Endpoints, "new-a-1", "new-a-2", "old-b")
	if !reflect.DeepEqual(got.Subscriptions, original.Subscriptions) {
		t.Fatal("endpoint refresh changed subscriptions")
	}
}

func TestStoreRejectsEncodedStateAboveLoadLimitBeforeWrite(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "state")
	store, err := NewStore(directory)
	if err != nil {
		t.Fatalf("NewStore() returned an unexpected error: %v", err)
	}
	original := testSnapshot()
	if err := store.Save(original); err != nil {
		t.Fatalf("initial Save() returned an unexpected error: %v", err)
	}
	original.Revision = 1
	path := filepath.Join(directory, StateFileName)
	before, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat() before oversized Save: %v", err)
	}

	oversized := oversizedValidSnapshot()
	oversized.Revision = original.Revision
	saveErr := store.Save(oversized)
	if saveErr == nil {
		after, statErr := os.Stat(path)
		if statErr != nil {
			t.Fatalf("Stat() after oversized Save: %v", statErr)
		}
		t.Fatalf("Save() accepted encoded state of %d bytes, limit is %d", after.Size(), maxStateFileBytes)
	}
	if !errors.Is(saveErr, errInvalidState) {
		t.Fatalf("oversized Save() error = %v, want errInvalidState", saveErr)
	}

	after, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat() after rejected Save: %v", err)
	}
	if !os.SameFile(before, after) {
		t.Fatal("rejected oversized Save replaced the state file")
	}
	got, err := store.Load()
	if err != nil {
		t.Fatalf("Load() after rejected Save returned an unexpected error: %v", err)
	}
	if !reflect.DeepEqual(got, original) {
		t.Fatal("rejected oversized Save changed the stored snapshot")
	}
}

func TestStoreEnforcesSubscriptionCountBoundary(t *testing.T) {
	store, err := NewStore(filepath.Join(t.TempDir(), "state"))
	if err != nil {
		t.Fatalf("NewStore() returned an unexpected error: %v", err)
	}
	atLimit := Snapshot{SchemaVersion: CurrentSchemaVersion, Subscriptions: testSubscriptions(MaxStateSubscriptions)}
	if err := store.Save(atLimit); err != nil {
		t.Fatalf("Save() rejected %d subscriptions: %v", MaxStateSubscriptions, err)
	}
	loaded, err := store.Load()
	if err != nil {
		t.Fatalf("Load() rejected saved subscription boundary: %v", err)
	}
	if len(loaded.Subscriptions) != MaxStateSubscriptions {
		t.Fatalf("Load() returned %d subscriptions, want %d", len(loaded.Subscriptions), MaxStateSubscriptions)
	}

	overLimit := Snapshot{SchemaVersion: CurrentSchemaVersion, Subscriptions: testSubscriptions(MaxStateSubscriptions + 1)}
	if err := store.Save(overLimit); err == nil {
		t.Fatalf("Save() accepted %d subscriptions", MaxStateSubscriptions+1)
	}
}

func TestStoreEnforcesEndpointCountBoundary(t *testing.T) {
	store, err := NewStore(filepath.Join(t.TempDir(), "state"))
	if err != nil {
		t.Fatalf("NewStore() returned an unexpected error: %v", err)
	}
	subscription := domain.Subscription{ID: "subscription-a", Name: "Subscription A", SecretRef: "secret-a", Format: domain.SubscriptionFormatURIList}
	atLimit := Snapshot{
		SchemaVersion: CurrentSchemaVersion,
		Subscriptions: []domain.Subscription{subscription},
		Endpoints:     testEndpoints(MaxStateEndpoints, subscription.ID),
	}
	if err := store.Save(atLimit); err != nil {
		t.Fatalf("Save() rejected %d endpoints: %v", MaxStateEndpoints, err)
	}
	loaded, err := store.Load()
	if err != nil {
		t.Fatalf("Load() rejected saved endpoint boundary: %v", err)
	}
	if len(loaded.Endpoints) != MaxStateEndpoints {
		t.Fatalf("Load() returned %d endpoints, want %d", len(loaded.Endpoints), MaxStateEndpoints)
	}

	overLimit := Snapshot{
		SchemaVersion: CurrentSchemaVersion,
		Subscriptions: []domain.Subscription{subscription},
		Endpoints:     testEndpoints(MaxStateEndpoints+1, subscription.ID),
	}
	if err := store.Save(overLimit); err == nil {
		t.Fatalf("Save() accepted %d endpoints", MaxStateEndpoints+1)
	}
}

func TestStaleSaveConflictsAndUpdatePreservesBothChanges(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "state")
	first, err := NewStore(directory)
	if err != nil {
		t.Fatalf("first NewStore() returned an unexpected error: %v", err)
	}
	second, err := NewStore(directory)
	if err != nil {
		t.Fatalf("second NewStore() returned an unexpected error: %v", err)
	}
	if err := first.Save(testSnapshot()); err != nil {
		t.Fatalf("initial Save() returned an unexpected error: %v", err)
	}

	firstView, err := first.Load()
	if err != nil {
		t.Fatalf("first Load(): %v", err)
	}
	secondView, err := second.Load()
	if err != nil {
		t.Fatalf("second Load(): %v", err)
	}
	if firstView.Revision == 0 || firstView.Revision != secondView.Revision {
		t.Fatalf("loaded revisions = %d and %d, want one shared nonzero revision", firstView.Revision, secondView.Revision)
	}

	firstView.Subscriptions[0].Name = "Changed by first"
	if err := first.Save(firstView); err != nil {
		t.Fatalf("first Save() returned an unexpected error: %v", err)
	}
	secondView.Subscriptions[1].Name = "Changed by stale second"
	if err := second.Save(secondView); !errors.Is(err, ErrStateConflict) {
		t.Fatalf("stale Save() error = %v, want ErrStateConflict", err)
	}

	if err := second.Update(func(snapshot *Snapshot) error {
		snapshot.Subscriptions[1].Name = "Changed by update"
		return nil
	}); err != nil {
		t.Fatalf("Update() returned an unexpected error: %v", err)
	}
	got, err := first.Load()
	if err != nil {
		t.Fatalf("final Load(): %v", err)
	}
	if got.Subscriptions[0].Name != "Changed by first" || got.Subscriptions[1].Name != "Changed by update" {
		t.Fatalf("final names = %q and %q, want both independent changes", got.Subscriptions[0].Name, got.Subscriptions[1].Name)
	}
}

func TestUpdateRejectsRevisionMutation(t *testing.T) {
	store, err := NewStore(filepath.Join(t.TempDir(), "state"))
	if err != nil {
		t.Fatalf("NewStore() returned an unexpected error: %v", err)
	}
	if err := store.Save(testSnapshot()); err != nil {
		t.Fatalf("initial Save() returned an unexpected error: %v", err)
	}
	if err := store.Update(func(snapshot *Snapshot) error {
		snapshot.Revision++
		return nil
	}); err == nil {
		t.Fatal("Update() accepted callback revision mutation")
	}
	got, err := store.Load()
	if err != nil {
		t.Fatalf("Load() after rejected Update: %v", err)
	}
	if got.Revision != 1 {
		t.Fatalf("revision after rejected Update = %d, want 1", got.Revision)
	}
}

func TestStoreOperationsRemainAnchoredAfterDirectoryPathReplacement(t *testing.T) {
	base := t.TempDir()
	directory := filepath.Join(base, "state")
	store, err := NewStore(directory)
	if err != nil {
		t.Fatalf("NewStore() returned an unexpected error: %v", err)
	}

	moved := filepath.Join(base, "moved")
	if err := os.Rename(directory, moved); err != nil {
		t.Fatalf("Rename() state directory: %v", err)
	}
	attacker := filepath.Join(base, "attacker")
	if err := os.Mkdir(attacker, 0o700); err != nil {
		t.Fatalf("Mkdir() attacker directory: %v", err)
	}
	if err := os.Symlink(attacker, directory); err != nil {
		t.Fatalf("Symlink() replacement: %v", err)
	}

	if err := store.Save(testSnapshot()); err != nil {
		t.Fatalf("Save() through held root returned an unexpected error: %v", err)
	}
	assertMode(t, filepath.Join(moved, StateFileName), 0o600)
	assertMode(t, filepath.Join(moved, StateLockFileName), 0o600)
	if _, err := os.Stat(filepath.Join(attacker, StateFileName)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("replacement directory received state write: %v", err)
	}
}

func TestIndependentStoresDoNotLoseConcurrentRefreshes(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "state")
	first, err := NewStore(directory)
	if err != nil {
		t.Fatalf("first NewStore() returned an unexpected error: %v", err)
	}
	second, err := NewStore(directory)
	if err != nil {
		t.Fatalf("second NewStore() returned an unexpected error: %v", err)
	}

	original := Snapshot{
		SchemaVersion: CurrentSchemaVersion,
		Subscriptions: []domain.Subscription{
			{ID: "subscription-a", Name: "A", SecretRef: "secret-a", Format: domain.SubscriptionFormatURIList},
			{ID: "subscription-b", Name: "B", SecretRef: "secret-b", Format: domain.SubscriptionFormatURIList},
			{ID: "subscription-c", Name: "C", SecretRef: "secret-c", Format: domain.SubscriptionFormatURIList},
		},
		Endpoints: []domain.Endpoint{
			testEndpoint("old-a", "subscription-a", "old-a.example.com"),
			testEndpoint("old-b", "subscription-b", "old-b.example.com"),
		},
	}
	original.Endpoints = append(original.Endpoints, testEndpoints(500, "subscription-c")...)

	for attempt := 0; attempt < 25; attempt++ {
		current, err := first.Load()
		if err != nil {
			t.Fatalf("attempt %d reset Load(): %v", attempt, err)
		}
		original.Revision = current.Revision
		if err := first.Save(original); err != nil {
			t.Fatalf("attempt %d reset Save(): %v", attempt, err)
		}
		start := make(chan struct{})
		errorsChannel := make(chan error, 2)
		var waitGroup sync.WaitGroup
		for _, operation := range []struct {
			store          *Store
			subscriptionID string
			endpoint       domain.Endpoint
		}{
			{store: first, subscriptionID: "subscription-a", endpoint: testEndpoint("new-a", "subscription-a", "new-a.example.com")},
			{store: second, subscriptionID: "subscription-b", endpoint: testEndpoint("new-b", "subscription-b", "new-b.example.com")},
		} {
			operation := operation
			waitGroup.Add(1)
			go func() {
				defer waitGroup.Done()
				<-start
				committed, err := operation.store.CommitSubscriptionRefresh(operation.subscriptionID, []domain.Endpoint{operation.endpoint}, nil)
				if err != nil {
					errorsChannel <- err
					return
				}
				if !committed {
					errorsChannel <- errors.New("refresh was not committed")
				}
			}()
		}
		close(start)
		waitGroup.Wait()
		close(errorsChannel)
		for err := range errorsChannel {
			t.Fatalf("attempt %d concurrent refresh failed: %v", attempt, err)
		}

		got, err := first.Load()
		if err != nil {
			t.Fatalf("attempt %d Load(): %v", attempt, err)
		}
		endpointIDs := make(map[string]struct{}, len(got.Endpoints))
		for _, endpoint := range got.Endpoints {
			endpointIDs[endpoint.ID] = struct{}{}
		}
		for _, id := range []string{"new-a", "new-b"} {
			if _, exists := endpointIDs[id]; !exists {
				t.Fatalf("attempt %d lost concurrent update %q", attempt, id)
			}
		}
	}
}

func TestStoreSupportsConcurrentAccess(t *testing.T) {
	t.Parallel()

	store, err := NewStore(filepath.Join(t.TempDir(), "state"))
	if err != nil {
		t.Fatalf("NewStore() returned an unexpected error: %v", err)
	}
	initial := testSnapshot()
	if err := store.Save(initial); err != nil {
		t.Fatalf("Save() returned an unexpected error: %v", err)
	}

	const workers = 24
	errorsChannel := make(chan error, workers*2)
	var waitGroup sync.WaitGroup
	for index := 0; index < workers; index++ {
		index := index
		waitGroup.Add(2)
		go func() {
			defer waitGroup.Done()
			endpoint := testEndpoint(fmt.Sprintf("endpoint-%d", index), "subscription-a", fmt.Sprintf("host-%d.example.com", index))
			committed, err := store.CommitSubscriptionRefresh("subscription-a", []domain.Endpoint{endpoint}, nil)
			if err != nil {
				errorsChannel <- err
				return
			}
			if !committed {
				errorsChannel <- errors.New("refresh was not committed")
			}
		}()
		go func() {
			defer waitGroup.Done()
			snapshot, err := store.Load()
			if err != nil {
				errorsChannel <- err
				return
			}
			if err := validateSnapshot(snapshot); err != nil {
				errorsChannel <- err
			}
		}()
	}
	waitGroup.Wait()
	close(errorsChannel)
	for err := range errorsChannel {
		t.Errorf("concurrent operation failed: %v", err)
	}

	got, err := store.Load()
	if err != nil {
		t.Fatalf("final Load() returned an unexpected error: %v", err)
	}
	if len(got.Endpoints) != 2 {
		t.Fatalf("len(final Endpoints) = %d, want one A and one preserved B", len(got.Endpoints))
	}
}

func oversizedValidSnapshot() Snapshot {
	const endpointCount = MaxStateEndpoints
	longALPN := strings.Repeat("a", domain.MaxTLSFieldLength)
	longHost := strings.Repeat("a", 63) + "." + strings.Repeat("b", 63) + "." + strings.Repeat("c", 63) + "." + strings.Repeat("d", 61)
	endpoints := make([]domain.Endpoint, endpointCount)
	for index := range endpoints {
		suffix := fmt.Sprint(index)
		endpoints[index] = domain.Endpoint{
			ID:             "endpoint-" + suffix,
			SubscriptionID: "subscription-a",
			Name:           strings.Repeat("n", domain.MaxNameLength),
			Protocol:       domain.ProtocolTrojan,
			Host:           "host-" + suffix + ".example.com",
			Port:           443,
			Password:       strings.Repeat("p", domain.MaxCredentialLength),
			TLS: domain.TLSOptions{
				Enabled:    true,
				ServerName: longHost,
				ALPN:       []string{longALPN, longALPN, longALPN, longALPN, longALPN, longALPN, longALPN, longALPN, longALPN, longALPN, longALPN, longALPN, longALPN, longALPN, longALPN, longALPN},
			},
			Transport: domain.TransportOptions{
				Type: domain.TransportWebSocket,
				Path: strings.Repeat("/", domain.MaxTransportFieldLength),
				Host: strings.Repeat("h", domain.MaxTransportFieldLength),
			},
		}
	}
	return Snapshot{
		SchemaVersion: CurrentSchemaVersion,
		Subscriptions: []domain.Subscription{{
			ID: "subscription-a", Name: "Subscription A", SecretRef: "secret-a", Format: domain.SubscriptionFormatURIList,
		}},
		Endpoints: endpoints,
	}
}

func testSubscriptions(count int) []domain.Subscription {
	subscriptions := make([]domain.Subscription, count)
	for index := range subscriptions {
		suffix := fmt.Sprint(index)
		subscriptions[index] = domain.Subscription{
			ID:        "subscription-" + suffix,
			Name:      "Subscription " + suffix,
			SecretRef: "secret-" + suffix,
			Format:    domain.SubscriptionFormatURIList,
		}
	}
	return subscriptions
}

func testEndpoints(count int, subscriptionID string) []domain.Endpoint {
	endpoints := make([]domain.Endpoint, count)
	for index := range endpoints {
		suffix := fmt.Sprint(index)
		endpoints[index] = testEndpoint("endpoint-"+suffix, subscriptionID, "host-"+suffix+".example.com")
	}
	return endpoints
}

func testSnapshot() Snapshot {
	return Snapshot{
		SchemaVersion: CurrentSchemaVersion,
		Subscriptions: []domain.Subscription{
			{ID: "subscription-a", Name: "Subscription A", SecretRef: "secret-a", Format: domain.SubscriptionFormatURIList, RefreshIntervalSeconds: 900},
			{ID: "subscription-b", Name: "Subscription B", SecretRef: "secret-b", Format: domain.SubscriptionFormatClash, RefreshIntervalSeconds: 1800},
		},
		Endpoints: []domain.Endpoint{
			testEndpoint("old-a", "subscription-a", "old-a.example.com"),
			testEndpoint("old-b", "subscription-b", "old-b.example.com"),
		},
	}
}

func testEndpoint(id, subscriptionID, host string) domain.Endpoint {
	return domain.Endpoint{
		ID:             id,
		SubscriptionID: subscriptionID,
		Name:           id,
		Protocol:       domain.ProtocolShadowsocks,
		Host:           host,
		Port:           8388,
		Password:       "secret",
		Method:         "aes-256-gcm",
	}
}

func assertEndpointIDs(t *testing.T, endpoints []domain.Endpoint, want ...string) {
	t.Helper()
	got := make(map[string]bool, len(endpoints))
	for _, endpoint := range endpoints {
		got[endpoint.ID] = true
	}
	for _, id := range want {
		if !got[id] {
			t.Errorf("endpoint %q is missing from %#v", id, endpoints)
		}
	}
}

func assertMode(t *testing.T, path string, want os.FileMode) {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat(%q): %v", path, err)
	}
	if got := info.Mode().Perm(); got != want {
		t.Fatalf("mode for %q = %04o, want %04o", path, got, want)
	}
}

func assertNoStateTemporaryFiles(t *testing.T, directory string) {
	t.Helper()
	entries, err := os.ReadDir(directory)
	if err != nil {
		t.Fatalf("ReadDir(): %v", err)
	}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), "."+StateFileName+"-") {
			t.Fatalf("temporary file remains after atomic write: %q", entry.Name())
		}
	}
}

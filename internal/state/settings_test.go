package state

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestSnapshotSettingsDefaultTelemetryToDisabledAndPersistConsent(t *testing.T) {
	t.Parallel()

	store, err := NewStore(filepath.Join(t.TempDir(), "state"))
	if err != nil {
		t.Fatalf("NewStore() error = %v", err)
	}
	defer store.Close()

	snapshot, err := store.Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if snapshot.Settings.TelemetryEnabled {
		t.Fatal("telemetry defaulted to enabled")
	}
	if err := store.Update(func(snapshot *Snapshot) error {
		snapshot.Settings.TelemetryEnabled = true
		return nil
	}); err != nil {
		t.Fatalf("Update() error = %v", err)
	}
	persisted, err := store.Load()
	if err != nil {
		t.Fatalf("Load() after update error = %v", err)
	}
	if !persisted.Settings.TelemetryEnabled {
		t.Fatal("telemetry consent was not persisted")
	}
}

func TestStoreRoundTripsLegacyStateWithoutSettings(t *testing.T) {
	t.Parallel()

	fixture, err := os.ReadFile(filepath.Join("testdata", "legacy-v1-without-settings.json"))
	if err != nil {
		t.Fatalf("ReadFile() fixture error = %v", err)
	}
	directory := filepath.Join(t.TempDir(), "state")
	store, err := NewStore(directory)
	if err != nil {
		t.Fatalf("NewStore() error = %v", err)
	}
	defer store.Close()
	statePath := filepath.Join(directory, StateFileName)
	if err := os.WriteFile(statePath, fixture, 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	legacy, err := store.Load()
	if err != nil {
		t.Fatalf("Load() legacy fixture error = %v", err)
	}
	if legacy.Settings.TelemetryEnabled {
		t.Fatal("legacy state enabled telemetry")
	}
	if legacy.Revision != 7 || len(legacy.Subscriptions) != 1 || len(legacy.Endpoints) != 1 {
		t.Fatalf("legacy data = %#v, want revision 7 with one subscription and endpoint", legacy)
	}

	want := legacy
	want.Revision++
	if err := store.Save(legacy); err != nil {
		t.Fatalf("Save() legacy snapshot error = %v", err)
	}
	roundTripped, err := store.Load()
	if err != nil {
		t.Fatalf("Load() round trip error = %v", err)
	}
	if !reflect.DeepEqual(roundTripped, want) {
		t.Fatalf("round trip = %#v, want %#v", roundTripped, want)
	}
	content, err := os.ReadFile(statePath)
	if err != nil {
		t.Fatalf("ReadFile() round trip error = %v", err)
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(content, &fields); err != nil {
		t.Fatalf("Unmarshal() round trip error = %v", err)
	}
	if _, exists := fields["settings"]; !exists {
		t.Fatal("round trip did not persist explicit disabled settings")
	}
}

func TestStoreRejectsUnknownSettingsFields(t *testing.T) {
	t.Parallel()

	directory := filepath.Join(t.TempDir(), "state")
	store, err := NewStore(directory)
	if err != nil {
		t.Fatalf("NewStore() error = %v", err)
	}
	defer store.Close()
	content := []byte(`{"schema_version":1,"revision":0,"subscriptions":[],"endpoints":[],"settings":{"telemetry_enabled":false,"stable_id":"forbidden"}}`)
	if err := os.WriteFile(filepath.Join(directory, StateFileName), content, 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	if _, err := store.Load(); err == nil {
		t.Fatal("Load() accepted an unknown settings field")
	}
}

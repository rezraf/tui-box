package state

import (
	"os"
	"path/filepath"
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

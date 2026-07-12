package domain

import (
	"encoding/json"
	"testing"
	"time"
)

func TestSubscriptionJSONRoundTripUsesExplicitRefreshIntervalSeconds(t *testing.T) {
	t.Parallel()

	lastRefresh := time.Date(2026, time.July, 13, 10, 30, 0, 0, time.UTC)
	original := Subscription{
		ID:                     "subscription-1",
		Name:                   "Primary",
		SecretRef:              "keychain://subscription-1",
		Format:                 SubscriptionFormatURIList,
		RefreshIntervalSeconds: 900,
		LastRefresh:            &lastRefresh,
		LastError:              "temporary failure",
	}

	encoded, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("json.Marshal() returned an unexpected error: %v", err)
	}

	var fields map[string]json.RawMessage
	if err := json.Unmarshal(encoded, &fields); err != nil {
		t.Fatalf("json.Unmarshal() into fields returned an unexpected error: %v", err)
	}
	if got := string(fields["refresh_interval_seconds"]); got != "900" {
		t.Fatalf("refresh_interval_seconds = %s, want 900", got)
	}
	if _, exists := fields["refresh_interval"]; exists {
		t.Fatal("legacy refresh_interval field was serialized")
	}

	var roundTripped Subscription
	if err := json.Unmarshal(encoded, &roundTripped); err != nil {
		t.Fatalf("json.Unmarshal() returned an unexpected error: %v", err)
	}
	if roundTripped.RefreshIntervalSeconds != original.RefreshIntervalSeconds {
		t.Fatalf("RefreshIntervalSeconds = %d, want %d", roundTripped.RefreshIntervalSeconds, original.RefreshIntervalSeconds)
	}
	if roundTripped.LastRefresh == nil {
		t.Fatal("LastRefresh = nil, want a timestamp")
	}
	if !roundTripped.LastRefresh.Equal(lastRefresh) {
		t.Fatalf("LastRefresh = %s, want %s", roundTripped.LastRefresh, lastRefresh)
	}
}

func TestSubscriptionJSONOmitsAbsentLastRefresh(t *testing.T) {
	t.Parallel()

	subscription := Subscription{
		ID:                     "subscription-1",
		Name:                   "Primary",
		SecretRef:              "keychain://subscription-1",
		Format:                 SubscriptionFormatURIList,
		RefreshIntervalSeconds: 900,
	}

	encoded, err := json.Marshal(subscription)
	if err != nil {
		t.Fatalf("json.Marshal() returned an unexpected error: %v", err)
	}

	var fields map[string]json.RawMessage
	if err := json.Unmarshal(encoded, &fields); err != nil {
		t.Fatalf("json.Unmarshal() returned an unexpected error: %v", err)
	}
	if _, exists := fields["last_refresh"]; exists {
		t.Fatal("last_refresh was serialized for an absent LastRefresh")
	}
}

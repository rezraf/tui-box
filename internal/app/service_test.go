package app

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"reflect"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/rezraf/tui-box/internal/domain"
	"github.com/rezraf/tui-box/internal/latency"
	"github.com/rezraf/tui-box/internal/rpc"
	"github.com/rezraf/tui-box/internal/secrets"
	"github.com/rezraf/tui-box/internal/state"
	"github.com/rezraf/tui-box/internal/subscription"
)

const testIdentityKeyHex = "1111111111111111111111111111111111111111111111111111111111111111"

func TestSubscriptionEndpointIDsAreScopedStableAndIndependent(t *testing.T) {
	stateStore := newFakeStateStore()
	secretStore := newFakeSecretStore()
	ids := []string{"subscription-a", "subscription-b"}
	service := newTestService(t, testConfig{
		state:   stateStore,
		secrets: secretStore,
		generateID: func() (string, error) {
			id := ids[0]
			ids = ids[1:]
			return id, nil
		},
		parse: func(subscriptionID string, _ []byte) (subscription.ParseResult, error) {
			return subscription.ParseResult{
				Format:    domain.SubscriptionFormatURIList,
				Endpoints: []domain.Endpoint{validEndpoint("normalized-endpoint", subscriptionID, "Shared endpoint")},
			}, nil
		},
	})

	if _, _, err := service.AddSubscription(context.Background(), "First", "https://first.example/sub"); err != nil {
		t.Fatalf("add first subscription: %v", err)
	}
	if _, _, err := service.AddSubscription(context.Background(), "Second", "https://second.example/sub"); err != nil {
		t.Fatalf("add overlapping subscription: %v", err)
	}

	firstID := expectedScopedEndpointID("subscription-a", "normalized-endpoint")
	secondID := expectedScopedEndpointID("subscription-b", "normalized-endpoint")
	assertEndpointIDs(t, stateStore.snapshotCopy(), firstID, secondID)

	results, err := service.UpdateSubscriptions(context.Background(), "subscription-a")
	if err != nil {
		t.Fatalf("refresh first subscription: %v", err)
	}
	if len(results) != 1 || results[0].ServerCount != 1 {
		t.Fatalf("unexpected refresh result: %#v", results)
	}
	assertEndpointIDs(t, stateStore.snapshotCopy(), firstID, secondID)

	if err := service.RemoveSubscription(context.Background(), "subscription-a"); err != nil {
		t.Fatalf("remove first subscription: %v", err)
	}
	remaining := stateStore.snapshotCopy()
	assertEndpointIDs(t, remaining, secondID)
	if len(remaining.Subscriptions) != 1 || remaining.Subscriptions[0].ID != "subscription-b" {
		t.Fatalf("wrong remaining subscriptions: %#v", remaining.Subscriptions)
	}
	if _, ok := secretStore.value("subscription-subscription-a"); ok {
		t.Fatal("removed subscription secret remains")
	}
	if value, ok := secretStore.value("subscription-subscription-b"); !ok || value != "https://second.example/sub" {
		t.Fatalf("unrelated secret changed: value=%q present=%v", value, ok)
	}
}

func TestPublicEndpointIDsAreKeyedStableAndUnlinkableAcrossInstallations(t *testing.T) {
	document := shadowsocksSubscriptionDocument("hunter2", true)
	keys := [][]byte{bytesOf(0x11, 32), bytesOf(0x22, 32)}
	publicIDs := make([]string, 0, len(keys))

	for _, key := range keys {
		stateStore := newFakeStateStoreWithoutIdentityKey()
		service := newTestService(t, testConfig{
			state:   stateStore,
			fetcher: &fakeFetcher{document: document},
			parse:   subscription.Parse,
			generateIdentityKey: func() ([]byte, error) {
				return append([]byte(nil), key...), nil
			},
		})
		if _, _, err := service.AddSubscription(context.Background(), "Subscription", "https://provider.example/list"); err != nil {
			t.Fatalf("AddSubscription: %v", err)
		}
		snapshot := stateStore.snapshotCopy()
		if len(snapshot.Endpoints) != 1 {
			t.Fatalf("deduplicated endpoints = %d, want 1", len(snapshot.Endpoints))
		}
		initialID := snapshot.Endpoints[0].ID
		if _, err := service.UpdateSubscriptions(context.Background(), "subscription-id"); err != nil {
			t.Fatalf("UpdateSubscriptions: %v", err)
		}
		refreshed := stateStore.snapshotCopy()
		if len(refreshed.Endpoints) != 1 || refreshed.Endpoints[0].ID != initialID {
			t.Fatalf("refresh changed public endpoint ID: before=%q after=%#v", initialID, refreshed.Endpoints)
		}
		publicIDs = append(publicIDs, initialID)
	}
	if publicIDs[0] == publicIDs[1] {
		t.Fatalf("identical imports across installations produced linkable ID %q", publicIDs[0])
	}

	for _, candidate := range []string{"password", "hunter2", "letmein", "secret"} {
		parsed, err := subscription.Parse("subscription-id", shadowsocksSubscriptionDocument(candidate, false))
		if err != nil || len(parsed.Endpoints) != 1 {
			t.Fatalf("parse candidate %q: %v", candidate, err)
		}
		legacyVerifier := expectedLegacyScopedEndpointID("subscription-id", parsed.Endpoints[0].ID)
		if legacyVerifier == publicIDs[0] {
			t.Fatalf("candidate %q was verifiable from public IDs", candidate)
		}
	}
}

func TestFirstRefreshRekeysAllLegacyEndpointIDsBeforeProjection(t *testing.T) {
	legacyA := validEndpoint("legacy-a", "subscription-a", "A")
	legacyB := validEndpoint("legacy-b", "subscription-b", "B")
	stateStore := &fakeStateStore{snapshot: state.Snapshot{
		SchemaVersion: state.CurrentSchemaVersion,
		Subscriptions: []domain.Subscription{
			{ID: "subscription-a", Name: "A", SecretRef: "secret-a", Format: domain.SubscriptionFormatURIList},
			{ID: "subscription-b", Name: "B", SecretRef: "secret-b", Format: domain.SubscriptionFormatURIList},
		},
		Endpoints: []domain.Endpoint{legacyA, legacyB},
	}}
	secretStore := newFakeSecretStore()
	secretStore.values["secret-a"] = "https://provider.example/a"
	secretStore.values["secret-b"] = "https://provider.example/b"
	service := newTestService(t, testConfig{
		state:   stateStore,
		secrets: secretStore,
		parse: func(subscriptionID string, _ []byte) (subscription.ParseResult, error) {
			return subscription.ParseResult{Format: domain.SubscriptionFormatURIList, Endpoints: []domain.Endpoint{validEndpoint("fresh-a", subscriptionID, "A")}}, nil
		},
	})

	if _, err := service.UpdateSubscriptions(context.Background(), "subscription-a"); err != nil {
		t.Fatalf("UpdateSubscriptions: %v", err)
	}
	snapshot := stateStore.snapshotCopy()
	if snapshot.Settings.EndpointIdentityKey != testIdentityKeyHex {
		t.Fatalf("identity key was not persisted")
	}
	remainingB, found := findEndpoint(snapshot.Endpoints, "legacy-b")
	if found || remainingB.ID != "" {
		t.Fatalf("legacy public ID remained after key creation: %#v", snapshot.Endpoints)
	}
	fingerprintB, err := subscription.EndpointFingerprint(legacyB)
	if err != nil {
		t.Fatal(err)
	}
	wantB := expectedScopedEndpointID("subscription-b", fingerprintB)
	if _, found := findEndpoint(snapshot.Endpoints, wantB); !found {
		t.Fatalf("unrefreshed endpoint was not rekeyed: %#v", snapshot.Endpoints)
	}
}

func TestAddSubscriptionWritesOnlySecretReferenceAfterSuccessfulRefresh(t *testing.T) {
	stateStore := newFakeStateStore()
	secretStore := newFakeSecretStore()
	service := newTestService(t, testConfig{state: stateStore, secrets: secretStore})

	view, warnings, err := service.AddSubscription(context.Background(), "Ordinary subscription", "https://provider.example/private-token")
	if err != nil {
		t.Fatalf("AddSubscription: %v", err)
	}
	if len(warnings) != 0 {
		t.Fatalf("unexpected warnings: %#v", warnings)
	}
	if view.ID != "subscription-id" || view.Name != "Ordinary subscription" || view.ServerCount != 1 {
		t.Fatalf("unexpected view: %#v", view)
	}

	snapshot := stateStore.snapshotCopy()
	if len(snapshot.Subscriptions) != 1 || snapshot.Subscriptions[0].SecretRef != "subscription-subscription-id" {
		t.Fatalf("secret reference was not persisted: %#v", snapshot.Subscriptions)
	}
	serializedState := fmt.Sprintf("%#v", snapshot)
	if strings.Contains(serializedState, "https://provider.example/private-token") {
		t.Fatalf("subscription URL leaked into state: %s", serializedState)
	}
	if value, ok := secretStore.value("subscription-subscription-id"); !ok || value != "https://provider.example/private-token" {
		t.Fatalf("secret store value = %q, present=%v", value, ok)
	}
}

func TestAddSubscriptionRefreshFailuresWriteNothing(t *testing.T) {
	tests := []struct {
		name    string
		fetcher *fakeFetcher
		parse   ParseFunc
	}{
		{
			name:    "fetch",
			fetcher: &fakeFetcher{errors: []error{errors.New("private network failure for https://provider.example/token")}},
		},
		{
			name: "parse",
			parse: func(string, []byte) (subscription.ParseResult, error) {
				return subscription.ParseResult{}, errors.New("private parser failure containing endpoint-password")
			},
		},
		{
			name: "empty",
			parse: func(string, []byte) (subscription.ParseResult, error) {
				return subscription.ParseResult{Format: domain.SubscriptionFormatURIList}, nil
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			stateStore := newFakeStateStore()
			secretStore := newFakeSecretStore()
			service := newTestService(t, testConfig{
				state:   stateStore,
				secrets: secretStore,
				fetcher: test.fetcher,
				parse:   test.parse,
			})

			_, _, err := service.AddSubscription(context.Background(), "Subscription", "https://provider.example/token")
			assertStableError(t, err, ErrRefreshFailed)
			if stateStore.updateCalls != 0 {
				t.Fatalf("state writes = %d, want 0", stateStore.updateCalls)
			}
			if len(secretStore.setCalls) != 0 || len(secretStore.deleteCalls) != 0 {
				t.Fatalf("secret writes occurred: set=%#v delete=%#v", secretStore.setCalls, secretStore.deleteCalls)
			}
		})
	}
}

func TestAddSubscriptionRejectsInvalidParserFormatBeforeWrites(t *testing.T) {
	stateStore := newFakeStateStore()
	secretStore := newFakeSecretStore()
	service := newTestService(t, testConfig{
		state:   stateStore,
		secrets: secretStore,
		parse: func(subscriptionID string, _ []byte) (subscription.ParseResult, error) {
			return subscription.ParseResult{
				Format:    domain.SubscriptionFormat("https://provider.example/private-format"),
				Endpoints: []domain.Endpoint{validEndpoint("normalized", subscriptionID, "Endpoint")},
			}, nil
		},
	})

	_, _, err := service.AddSubscription(context.Background(), "Subscription", "https://provider.example/private-token")
	assertStableError(t, err, ErrRefreshFailed)
	if stateStore.updateCalls != 0 || len(secretStore.setCalls) != 0 || len(secretStore.deleteCalls) != 0 {
		t.Fatalf("invalid parser format caused writes: state=%d set=%d delete=%d", stateStore.updateCalls, len(secretStore.setCalls), len(secretStore.deleteCalls))
	}
}

func TestAddSubscriptionRejectsMalformedParserIdentityBeforeWrites(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*domain.Endpoint)
	}{
		{name: "empty normalized ID", mutate: func(endpoint *domain.Endpoint) { endpoint.ID = "" }},
		{name: "wrong subscription ID", mutate: func(endpoint *domain.Endpoint) { endpoint.SubscriptionID = "other-subscription" }},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			stateStore := newFakeStateStore()
			secretStore := newFakeSecretStore()
			service := newTestService(t, testConfig{
				state:   stateStore,
				secrets: secretStore,
				parse: func(subscriptionID string, _ []byte) (subscription.ParseResult, error) {
					endpoint := validEndpoint("normalized", subscriptionID, "Endpoint")
					test.mutate(&endpoint)
					return subscription.ParseResult{Format: domain.SubscriptionFormatURIList, Endpoints: []domain.Endpoint{endpoint}}, nil
				},
			})

			_, _, err := service.AddSubscription(context.Background(), "Subscription", "https://provider.example/private-token")
			assertStableError(t, err, ErrRefreshFailed)
			if stateStore.updateCalls != 0 || len(secretStore.setCalls) != 0 || len(secretStore.deleteCalls) != 0 {
				t.Fatalf("malformed parser identity caused writes: state=%d set=%d delete=%d", stateStore.updateCalls, len(secretStore.setCalls), len(secretStore.deleteCalls))
			}
		})
	}
}

func TestAddSubscriptionRejectsInvalidParserResultBeforeWrites(t *testing.T) {
	stateStore := newFakeStateStore()
	secretStore := newFakeSecretStore()
	service := newTestService(t, testConfig{
		state:   stateStore,
		secrets: secretStore,
		parse: func(subscriptionID string, _ []byte) (subscription.ParseResult, error) {
			endpoint := validEndpoint("normalized", subscriptionID, "Endpoint")
			endpoint.Host = ""
			return subscription.ParseResult{Format: domain.SubscriptionFormatURIList, Endpoints: []domain.Endpoint{endpoint}}, nil
		},
	})

	_, _, err := service.AddSubscription(context.Background(), "Subscription", "https://provider.example/private-token")
	assertStableError(t, err, ErrRefreshFailed)
	if stateStore.updateCalls != 0 || len(secretStore.setCalls) != 0 || len(secretStore.deleteCalls) != 0 {
		t.Fatalf("invalid parser result caused writes: state=%d set=%d delete=%d", stateStore.updateCalls, len(secretStore.setCalls), len(secretStore.deleteCalls))
	}
}

func TestAddSubscriptionStateFailureRollsBackSecretWithBoundedIndependentContext(t *testing.T) {
	stateStore := newFakeStateStore()
	stateStore.updateErrors = []error{errors.New("private state write failure")}
	secretStore := newFakeSecretStore()
	var rollbackContext context.Context
	secretStore.deleteFunc = func(ctx context.Context, key string) error {
		rollbackContext = ctx
		secretStore.mu.Lock()
		delete(secretStore.values, key)
		secretStore.mu.Unlock()
		return nil
	}
	service := newTestService(t, testConfig{state: stateStore, secrets: secretStore})

	_, _, err := service.AddSubscription(context.Background(), "Subscription", "https://provider.example/token")
	assertStableError(t, err, ErrStateOperation)
	if rollbackContext == nil {
		t.Fatal("secret rollback was not attempted")
	}
	assertHasDeadlineWithin(t, rollbackContext, 3*time.Second)
	if _, ok := secretStore.value("subscription-subscription-id"); ok {
		t.Fatal("new secret remains after failed state write")
	}
}

func TestAddSubscriptionRollbackFailureReturnsOnlyStableJoinedErrors(t *testing.T) {
	stateStore := newFakeStateStore()
	stateStore.updateErrors = []error{errors.New("private state failure with https://state.example")}
	secretStore := newFakeSecretStore()
	secretStore.deleteErrors = []error{errors.New("private secret rollback failure endpoint-password")}
	service := newTestService(t, testConfig{state: stateStore, secrets: secretStore})

	_, _, err := service.AddSubscription(context.Background(), "Subscription", "https://provider.example/token")
	assertStableError(t, err, ErrStateOperation, ErrSecretOperation)
	if unwrapped := errors.Unwrap(err); unwrapped != nil {
		if strings.Contains(fmt.Sprintf("%v", unwrapped), "private") {
			t.Fatalf("private error is unwrap-reachable: %v", unwrapped)
		}
	}
	if len(secretStore.deleteCalls) != 1 {
		t.Fatalf("rollback attempts = %d, want 1", len(secretStore.deleteCalls))
	}
	assertHasDeadlineWithin(t, secretStore.deleteCalls[0].context, 3*time.Second)
}

func TestAddSubscriptionKeepsSecretWhenFailedStateWriteIsVisible(t *testing.T) {
	stateStore := newFakeStateStore()
	stateStore.updateErrors = []error{errors.New("private post-commit state failure")}
	stateStore.afterUpdateError = func(snapshot *state.Snapshot) {
		now := time.Date(2026, 7, 13, 11, 0, 0, 0, time.UTC)
		snapshot.Subscriptions = []domain.Subscription{{
			ID:          "subscription-id",
			Name:        "Subscription",
			SecretRef:   "subscription-subscription-id",
			Format:      domain.SubscriptionFormatURIList,
			LastRefresh: &now,
		}}
		snapshot.Endpoints = []domain.Endpoint{
			validEndpoint(expectedScopedEndpointID("subscription-id", "normalized-endpoint"), "subscription-id", "Test endpoint"),
		}
	}
	secretStore := newFakeSecretStore()
	service := newTestService(t, testConfig{state: stateStore, secrets: secretStore})

	_, _, err := service.AddSubscription(context.Background(), "Subscription", "https://provider.example/token")
	assertStableError(t, err, ErrStateOperation)
	if value, ok := secretStore.value("subscription-subscription-id"); !ok || value != "https://provider.example/token" {
		t.Fatalf("secret for visible state commit = %q, present=%v", value, ok)
	}
	if len(secretStore.deleteCalls) != 0 {
		t.Fatalf("visible state commit triggered secret deletion: %#v", secretStore.deleteCalls)
	}
}

func TestAddSubscriptionKeepsSecretWhenRollbackStateCannotBeRead(t *testing.T) {
	stateStore := newFakeStateStore()
	stateStore.updateErrors = []error{errors.New("private state write failure")}
	stateStore.loadErrors = []error{errors.New("private state reload failure")}
	secretStore := newFakeSecretStore()
	service := newTestService(t, testConfig{state: stateStore, secrets: secretStore})

	_, _, err := service.AddSubscription(context.Background(), "Subscription", "https://provider.example/token")
	assertStableError(t, err, ErrStateOperation, ErrSecretOperation)
	if value, ok := secretStore.value("subscription-subscription-id"); !ok || value != "https://provider.example/token" {
		t.Fatalf("secret after uncertain state outcome = %q, present=%v", value, ok)
	}
	if len(secretStore.deleteCalls) != 0 {
		t.Fatalf("uncertain state outcome triggered secret deletion: %#v", secretStore.deleteCalls)
	}
}

func TestUpdateSubscriptionFailurePreservesExactCacheAndStoresStableLastError(t *testing.T) {
	refreshTime := time.Date(2026, 7, 12, 8, 30, 0, 0, time.UTC)
	oldEndpoint := validEndpoint(expectedScopedEndpointID("subscription-id", "old-normalized"), "subscription-id", "Known good")
	oldSubscription := domain.Subscription{
		ID:                     "subscription-id",
		Name:                   "Ordinary subscription",
		SecretRef:              "subscription-secret-ref",
		Format:                 domain.SubscriptionFormatClash,
		RefreshIntervalSeconds: 900,
		LastRefresh:            &refreshTime,
	}
	stateStore := newFakeStateStore()
	stateStore.setSnapshot(state.Snapshot{
		SchemaVersion: state.CurrentSchemaVersion,
		Subscriptions: []domain.Subscription{oldSubscription},
		Endpoints:     []domain.Endpoint{oldEndpoint},
	})
	secretStore := newFakeSecretStore()
	secretStore.setValue("subscription-secret-ref", "https://provider.example/private-token")
	service := newTestService(t, testConfig{
		state:   stateStore,
		secrets: secretStore,
		parse: func(string, []byte) (subscription.ParseResult, error) {
			return subscription.ParseResult{}, errors.New("private parser error proxy.example.com endpoint-password")
		},
	})

	results, err := service.UpdateSubscriptions(context.Background(), "subscription-id")
	if err != nil {
		t.Fatalf("UpdateSubscriptions: %v", err)
	}
	if len(results) != 1 || results[0].SubscriptionID != "subscription-id" || results[0].Error != ErrRefreshFailed.Error() {
		t.Fatalf("unexpected refresh results: %#v", results)
	}
	if strings.Contains(fmt.Sprintf("%#v", results), "private") || strings.Contains(fmt.Sprintf("%#v", results), "proxy.example.com") {
		t.Fatalf("refresh result leaked source error: %#v", results)
	}

	after := stateStore.snapshotCopy()
	if !reflect.DeepEqual(after.Endpoints, []domain.Endpoint{oldEndpoint}) {
		t.Fatalf("last-known-good cache changed:\n got: %#v\nwant: %#v", after.Endpoints, []domain.Endpoint{oldEndpoint})
	}
	wantSubscription := oldSubscription
	wantSubscription.LastError = ErrRefreshFailed.Error()
	if !reflect.DeepEqual(after.Subscriptions, []domain.Subscription{wantSubscription}) {
		t.Fatalf("subscription mutation was not limited to LastError:\n got: %#v\nwant: %#v", after.Subscriptions, []domain.Subscription{wantSubscription})
	}
}

func TestUpdateSubscriptionTreatsInvalidParserResultAsRefreshFailure(t *testing.T) {
	oldEndpoint := validEndpoint(expectedScopedEndpointID("subscription-id", "old"), "subscription-id", "Known good")
	stateStore := newFakeStateStore()
	stateStore.setSnapshot(state.Snapshot{
		SchemaVersion: state.CurrentSchemaVersion,
		Subscriptions: []domain.Subscription{{ID: "subscription-id", Name: "Subscription", SecretRef: "secret-ref", Format: domain.SubscriptionFormatURIList}},
		Endpoints:     []domain.Endpoint{oldEndpoint},
	})
	secretStore := newFakeSecretStore()
	secretStore.setValue("secret-ref", "https://provider.example/private-token")
	service := newTestService(t, testConfig{
		state:   stateStore,
		secrets: secretStore,
		parse: func(subscriptionID string, _ []byte) (subscription.ParseResult, error) {
			endpoint := validEndpoint("new", subscriptionID, "Invalid")
			endpoint.Port = 0
			return subscription.ParseResult{Format: domain.SubscriptionFormatClash, Endpoints: []domain.Endpoint{endpoint}}, nil
		},
	})

	results, err := service.UpdateSubscriptions(context.Background(), "subscription-id")
	if err != nil {
		t.Fatalf("UpdateSubscriptions: %v", err)
	}
	if len(results) != 1 || results[0].Error != ErrRefreshFailed.Error() {
		t.Fatalf("unexpected results: %#v", results)
	}
	after := stateStore.snapshotCopy()
	if !reflect.DeepEqual(after.Endpoints, []domain.Endpoint{oldEndpoint}) || after.Subscriptions[0].LastError != ErrRefreshFailed.Error() {
		t.Fatalf("invalid parser result replaced cache or missed LastError: %#v", after)
	}
}

func TestUpdateSubscriptionDoesNotMutateConcurrentReplacement(t *testing.T) {
	tests := []struct {
		name  string
		parse ParseFunc
	}{
		{
			name: "successful stale refresh",
			parse: func(subscriptionID string, _ []byte) (subscription.ParseResult, error) {
				return subscription.ParseResult{
					Format:    domain.SubscriptionFormatClash,
					Endpoints: []domain.Endpoint{validEndpoint("stale-new", subscriptionID, "Stale provider endpoint")},
				}, nil
			},
		},
		{
			name: "failed stale refresh",
			parse: func(string, []byte) (subscription.ParseResult, error) {
				return subscription.ParseResult{}, errors.New("private stale parser failure")
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			replacementEndpoint := validEndpoint(expectedScopedEndpointID("subscription-id", "replacement"), "subscription-id", "Replacement endpoint")
			stateStore := newFakeStateStore()
			stateStore.setSnapshot(state.Snapshot{
				SchemaVersion: state.CurrentSchemaVersion,
				Subscriptions: []domain.Subscription{{ID: "subscription-id", Name: "Old", SecretRef: "old-secret", Format: domain.SubscriptionFormatURIList}},
				Endpoints:     []domain.Endpoint{validEndpoint(expectedScopedEndpointID("subscription-id", "old"), "subscription-id", "Old endpoint")},
			})
			secretStore := newFakeSecretStore()
			secretStore.setValue("old-secret", "https://old.example/private-token")
			secretStore.setValue("replacement-secret", "https://replacement.example/private-token")
			fetcher := &fakeFetcher{fetchFunc: func(context.Context, string) ([]byte, error) {
				stateStore.setSnapshot(state.Snapshot{
					SchemaVersion: state.CurrentSchemaVersion,
					Subscriptions: []domain.Subscription{{ID: "subscription-id", Name: "Replacement", SecretRef: "replacement-secret", Format: domain.SubscriptionFormatSingBox}},
					Endpoints:     []domain.Endpoint{replacementEndpoint},
				})
				return []byte("replacement race"), nil
			}}
			service := newTestService(t, testConfig{state: stateStore, secrets: secretStore, fetcher: fetcher, parse: test.parse})

			_, err := service.UpdateSubscriptions(context.Background(), "subscription-id")
			assertStableError(t, err, ErrSubscriptionNotFound)
			after := stateStore.snapshotCopy()
			if len(after.Subscriptions) != 1 || after.Subscriptions[0].SecretRef != "replacement-secret" || after.Subscriptions[0].LastError != "" {
				t.Fatalf("replacement subscription was mutated: %#v", after.Subscriptions)
			}
			if !reflect.DeepEqual(after.Endpoints, []domain.Endpoint{replacementEndpoint}) {
				t.Fatalf("replacement endpoints were mutated: %#v", after.Endpoints)
			}
		})
	}
}

func TestUpdateAllContinuesAfterRefreshFailure(t *testing.T) {
	firstEndpoint := validEndpoint(expectedScopedEndpointID("subscription-a", "old-a"), "subscription-a", "First old")
	secondEndpoint := validEndpoint(expectedScopedEndpointID("subscription-b", "old-b"), "subscription-b", "Second old")
	stateStore := newFakeStateStore()
	stateStore.setSnapshot(state.Snapshot{
		SchemaVersion: state.CurrentSchemaVersion,
		Subscriptions: []domain.Subscription{
			{ID: "subscription-a", Name: "First", SecretRef: "secret-a", Format: domain.SubscriptionFormatURIList},
			{ID: "subscription-b", Name: "Second", SecretRef: "secret-b", Format: domain.SubscriptionFormatURIList},
		},
		Endpoints: []domain.Endpoint{firstEndpoint, secondEndpoint},
	})
	secretStore := newFakeSecretStore()
	secretStore.setValue("secret-a", "https://first.example/private")
	secretStore.setValue("secret-b", "https://second.example/private")
	service := newTestService(t, testConfig{
		state:   stateStore,
		secrets: secretStore,
		parse: func(subscriptionID string, _ []byte) (subscription.ParseResult, error) {
			if subscriptionID == "subscription-a" {
				return subscription.ParseResult{}, errors.New("private first parser failure")
			}
			return subscription.ParseResult{
				Format:    domain.SubscriptionFormatClash,
				Endpoints: []domain.Endpoint{validEndpoint("new-b", subscriptionID, "Second refreshed")},
			}, nil
		},
	})

	results, err := service.UpdateSubscriptions(context.Background(), "")
	if err != nil {
		t.Fatalf("UpdateSubscriptions(all): %v", err)
	}
	if len(results) != 2 || results[0].Error != ErrRefreshFailed.Error() || results[1].ServerCount != 1 {
		t.Fatalf("unexpected refresh results: %#v", results)
	}
	assertEndpointIDs(t, stateStore.snapshotCopy(), firstEndpoint.ID, expectedScopedEndpointID("subscription-b", "new-b"))
}

func TestConcurrentRefreshUsesLastStartedResultAcrossStateStoreInstances(t *testing.T) {
	for _, laterFails := range []bool{false, true} {
		name := "later success"
		if laterFails {
			name = "later failure"
		}
		t.Run(name, func(t *testing.T) {
			directory := t.TempDir()
			if err := os.Chmod(directory, 0o700); err != nil {
				t.Fatal(err)
			}
			storeA, err := state.NewStore(directory)
			if err != nil {
				t.Fatal(err)
			}
			defer storeA.Close()
			storeB, err := state.NewStore(directory)
			if err != nil {
				t.Fatal(err)
			}
			defer storeB.Close()

			oldEndpoint := validEndpoint(expectedScopedEndpointID("subscription-id", "old"), "subscription-id", "Old")
			if err := storeA.UpdateContext(context.Background(), func(snapshot *state.Snapshot) error {
				snapshot.Settings.EndpointIdentityKey = testIdentityKeyHex
				snapshot.Subscriptions = []domain.Subscription{{ID: "subscription-id", Name: "Subscription", SecretRef: "secret-ref", Format: domain.SubscriptionFormatURIList}}
				snapshot.Endpoints = []domain.Endpoint{oldEndpoint}
				return nil
			}); err != nil {
				t.Fatal(err)
			}

			secretStoreA := newFakeSecretStore()
			secretStoreA.setValue("secret-ref", "https://provider.example/list")
			secretStoreB := newFakeSecretStore()
			secretStoreB.setValue("secret-ref", "https://provider.example/list")
			startedA := make(chan struct{})
			releaseA := make(chan struct{})
			serviceA := newTestService(t, testConfig{
				state:   storeA,
				secrets: secretStoreA,
				fetcher: &fakeFetcher{fetchFunc: func(context.Context, string) ([]byte, error) {
					close(startedA)
					<-releaseA
					return []byte("old"), nil
				}},
				parse: func(subscriptionID string, _ []byte) (subscription.ParseResult, error) {
					return subscription.ParseResult{Format: domain.SubscriptionFormatURIList, Endpoints: []domain.Endpoint{validEndpoint("old-completion", subscriptionID, "Old completion")}}, nil
				},
				generateRefreshToken: func() (string, error) { return "refresh-a", nil },
				now:                  func() time.Time { return time.Date(2026, 7, 13, 13, 0, 0, 0, time.UTC) },
			})
			fetcherB := &fakeFetcher{document: []byte("new")}
			if laterFails {
				fetcherB.errors = []error{errors.New("later refresh failed")}
			}
			serviceB := newTestService(t, testConfig{
				state:   storeB,
				secrets: secretStoreB,
				fetcher: fetcherB,
				parse: func(subscriptionID string, _ []byte) (subscription.ParseResult, error) {
					return subscription.ParseResult{Format: domain.SubscriptionFormatClash, Endpoints: []domain.Endpoint{validEndpoint("new-completion", subscriptionID, "New completion")}}, nil
				},
				generateRefreshToken: func() (string, error) { return "refresh-b", nil },
				now:                  func() time.Time { return time.Date(2026, 7, 13, 14, 0, 0, 0, time.UTC) },
			})

			doneA := make(chan error, 1)
			go func() {
				_, refreshErr := serviceA.UpdateSubscriptions(context.Background(), "subscription-id")
				doneA <- refreshErr
			}()
			<-startedA
			resultsB, err := serviceB.UpdateSubscriptions(context.Background(), "subscription-id")
			if err != nil {
				t.Fatalf("later refresh returned error: %v", err)
			}
			close(releaseA)
			if err := <-doneA; !errors.Is(err, ErrRefreshStale) {
				t.Fatalf("older completion error = %v, want ErrRefreshStale", err)
			}

			final, err := storeA.LoadContext(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			if laterFails {
				if len(resultsB) != 1 || resultsB[0].Error != ErrRefreshFailed.Error() || final.Subscriptions[0].LastError != ErrRefreshFailed.Error() {
					t.Fatalf("later failure was not retained: results=%#v state=%#v", resultsB, final.Subscriptions)
				}
				if len(final.Endpoints) != 1 || final.Endpoints[0].ID != oldEndpoint.ID {
					t.Fatalf("later failure changed last-known-good endpoints: %#v", final.Endpoints)
				}
			} else {
				wantID := expectedScopedEndpointID("subscription-id", "new-completion")
				if len(final.Endpoints) != 1 || final.Endpoints[0].ID != wantID || final.Subscriptions[0].Format != domain.SubscriptionFormatClash || final.Subscriptions[0].LastRefresh == nil || final.Subscriptions[0].LastRefresh.Hour() != 14 || final.Subscriptions[0].LastError != "" {
					t.Fatalf("later success was overwritten: endpoints=%#v subscription=%#v", final.Endpoints, final.Subscriptions[0])
				}
			}
		})
	}
}

func TestRemoveSubscriptionRestoresSecretWithBoundedContextOnStateFailure(t *testing.T) {
	stateStore, secretStore := populatedSubscriptionStores("subscription-id", "secret-ref")
	stateStore.updateErrors = []error{errors.New("private state write failure")}
	service := newTestService(t, testConfig{state: stateStore, secrets: secretStore})

	err := service.RemoveSubscription(context.Background(), "subscription-id")
	assertStableError(t, err, ErrStateOperation)
	if value, ok := secretStore.value("secret-ref"); !ok || value != "https://provider.example/private-token" {
		t.Fatalf("secret was not restored: value=%q present=%v", value, ok)
	}
	if len(secretStore.setCalls) != 1 {
		t.Fatalf("restore attempts = %d, want 1", len(secretStore.setCalls))
	}
	assertHasDeadlineWithin(t, secretStore.setCalls[0].context, 3*time.Second)
}

func TestRemoveSubscriptionDoesNotRestoreSecretAfterConcurrentRemoval(t *testing.T) {
	stateStore, secretStore := populatedSubscriptionStores("subscription-id", "secret-ref")
	stateStore.beforeUpdate = func(snapshot *state.Snapshot) {
		snapshot.Subscriptions = nil
		snapshot.Endpoints = nil
		stateStore.beforeUpdate = nil
	}
	service := newTestService(t, testConfig{state: stateStore, secrets: secretStore})

	err := service.RemoveSubscription(context.Background(), "subscription-id")
	assertStableError(t, err, ErrSubscriptionNotFound)
	if _, ok := secretStore.value("secret-ref"); ok {
		t.Fatal("secret was restored after concurrent subscription removal")
	}
	if len(secretStore.setCalls) != 0 {
		t.Fatalf("unexpected restore calls: %#v", secretStore.setCalls)
	}
}

func TestRemoveSubscriptionDoesNotRemoveReplacementOrRestoreOldSecret(t *testing.T) {
	stateStore, secretStore := populatedSubscriptionStores("subscription-id", "secret-ref")
	secretStore.setValue("replacement-ref", "https://replacement.example/private")
	stateStore.beforeUpdate = func(snapshot *state.Snapshot) {
		snapshot.Subscriptions[0].SecretRef = "replacement-ref"
		stateStore.beforeUpdate = nil
	}
	service := newTestService(t, testConfig{state: stateStore, secrets: secretStore})

	err := service.RemoveSubscription(context.Background(), "subscription-id")
	assertStableError(t, err, ErrSubscriptionNotFound)
	after := stateStore.snapshotCopy()
	if len(after.Subscriptions) != 1 || after.Subscriptions[0].SecretRef != "replacement-ref" {
		t.Fatalf("replacement subscription was removed: %#v", after.Subscriptions)
	}
	if _, ok := secretStore.value("secret-ref"); ok {
		t.Fatal("old secret was restored after ownership changed")
	}
	if value, ok := secretStore.value("replacement-ref"); !ok || value != "https://replacement.example/private" {
		t.Fatalf("replacement secret changed: value=%q present=%v", value, ok)
	}
}

func TestRemoveSubscriptionRetryCompletesWhenPriorAttemptDeletedSecret(t *testing.T) {
	stateStore, secretStore := populatedSubscriptionStores("subscription-id", "secret-ref")
	stateStore.updateErrors = []error{errors.New("private state write failure")}
	secretStore.setErrors = []error{errors.New("private secret restore failure")}
	service := newTestService(t, testConfig{state: stateStore, secrets: secretStore})

	firstErr := service.RemoveSubscription(context.Background(), "subscription-id")
	assertStableError(t, firstErr, ErrStateOperation, ErrSecretOperation)
	if _, ok := secretStore.value("secret-ref"); ok {
		t.Fatal("failed compensation unexpectedly restored the secret")
	}
	if len(stateStore.snapshotCopy().Subscriptions) != 1 {
		t.Fatal("failed state commit unexpectedly removed the subscription")
	}

	if err := service.RemoveSubscription(context.Background(), "subscription-id"); err != nil {
		t.Fatalf("retry with already-absent secret failed: %v", err)
	}
	after := stateStore.snapshotCopy()
	if len(after.Subscriptions) != 0 || len(after.Endpoints) != 0 {
		t.Fatalf("retry left stranded state: %#v", after)
	}
}

func TestRemoveSubscriptionRestoreFailureReturnsStableJoinedErrors(t *testing.T) {
	stateStore, secretStore := populatedSubscriptionStores("subscription-id", "secret-ref")
	stateStore.updateErrors = []error{errors.New("private state write failure")}
	secretStore.setErrors = []error{errors.New("private secret restore failure")}
	service := newTestService(t, testConfig{state: stateStore, secrets: secretStore})

	err := service.RemoveSubscription(context.Background(), "subscription-id")
	assertStableError(t, err, ErrStateOperation, ErrSecretOperation)
	if len(secretStore.setCalls) != 1 {
		t.Fatalf("restore attempts = %d, want 1", len(secretStore.setCalls))
	}
	assertHasDeadlineWithin(t, secretStore.setCalls[0].context, 3*time.Second)
}

func populatedSubscriptionStores(subscriptionID, secretRef string) (*fakeStateStore, *fakeSecretStore) {
	stateStore := newFakeStateStore()
	stateStore.setSnapshot(state.Snapshot{
		SchemaVersion: state.CurrentSchemaVersion,
		Subscriptions: []domain.Subscription{{
			ID:        subscriptionID,
			Name:      "Subscription",
			SecretRef: secretRef,
			Format:    domain.SubscriptionFormatURIList,
		}},
		Endpoints: []domain.Endpoint{validEndpoint(expectedScopedEndpointID(subscriptionID, "normalized"), subscriptionID, "Endpoint")},
	})
	secretStore := newFakeSecretStore()
	secretStore.setValue(secretRef, "https://provider.example/private-token")
	return stateStore, secretStore
}

func TestConnectValidatesModeAndRouteBeforeSideEffects(t *testing.T) {
	tests := []struct {
		name  string
		mode  domain.ConnectionMode
		route domain.RouteMode
	}{
		{name: "invalid mode for direct", mode: domain.ConnectionMode("private-invalid-mode"), route: domain.RouteModeDirect},
		{name: "invalid mode for global", mode: domain.ConnectionMode("private-invalid-mode"), route: domain.RouteModeGlobal},
		{name: "invalid route", mode: domain.ConnectionModeProxy, route: domain.RouteMode("private-invalid-route")},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			stateStore := newFakeStateStore()
			latencyChecker := &fakeLatencyChecker{}
			daemon := &fakeDaemon{}
			service := newTestService(t, testConfig{state: stateStore, latency: latencyChecker, daemon: daemon})

			_, err := service.Connect(context.Background(), AutoTarget, test.mode, test.route)
			assertStableError(t, err, ErrInvalidInput)
			if stateStore.loadCalls != 0 || len(latencyChecker.calls) != 0 || len(daemon.connectCalls) != 0 {
				t.Fatalf("side effects before validation: state=%d latency=%d daemon=%d", stateStore.loadCalls, len(latencyChecker.calls), len(daemon.connectCalls))
			}
		})
	}
}

func TestConnectDirectSendsNilEndpointWithoutStateOrLatency(t *testing.T) {
	stateStore := newFakeStateStore()
	latencyChecker := &fakeLatencyChecker{}
	daemon := &fakeDaemon{connectStatus: rpc.SessionStatus{State: domain.ConnectionStatusConnected, Mode: domain.ConnectionModeProxy, Route: domain.RouteModeDirect}}
	service := newTestService(t, testConfig{state: stateStore, latency: latencyChecker, daemon: daemon})

	status, err := service.Connect(context.Background(), "ignored-target", domain.ConnectionModeProxy, domain.RouteModeDirect)
	if err != nil {
		t.Fatalf("Connect direct: %v", err)
	}
	if status != daemon.connectStatus {
		t.Fatalf("status = %#v, want %#v", status, daemon.connectStatus)
	}
	if stateStore.loadCalls != 0 || len(latencyChecker.calls) != 0 {
		t.Fatalf("direct route used state or latency: state=%d latency=%d", stateStore.loadCalls, len(latencyChecker.calls))
	}
	if len(daemon.connectCalls) != 1 || daemon.connectCalls[0].Endpoint != nil {
		t.Fatalf("direct payload must contain nil endpoint: %#v", daemon.connectCalls)
	}
}

func TestConnectRejectsInvalidStoredEndpointBeforeLatencyOrDaemon(t *testing.T) {
	invalid := validEndpoint("endpoint-id", "subscription-id", "Endpoint")
	invalid.Host = ""
	stateStore := newFakeStateStore()
	stateStore.setSnapshot(state.Snapshot{
		SchemaVersion: state.CurrentSchemaVersion,
		Subscriptions: []domain.Subscription{{ID: "subscription-id", Name: "Subscription", SecretRef: "secret-ref", Format: domain.SubscriptionFormatURIList}},
		Endpoints:     []domain.Endpoint{invalid},
	})
	latencyChecker := &fakeLatencyChecker{results: []latency.Result{{EndpointID: "endpoint-id", Status: latency.StatusSuccess}}}
	daemon := &fakeDaemon{}
	service := newTestService(t, testConfig{state: stateStore, latency: latencyChecker, daemon: daemon})

	for _, target := range []string{"endpoint-id", AutoTarget} {
		_, err := service.Connect(context.Background(), target, domain.ConnectionModeProxy, domain.RouteModeGlobal)
		assertStableError(t, err, ErrStateOperation)
	}
	if len(latencyChecker.calls) != 0 || len(daemon.connectCalls) != 0 {
		t.Fatalf("invalid endpoint reached dependency: latency=%d daemon=%d", len(latencyChecker.calls), len(daemon.connectCalls))
	}
}

func TestConnectManualAndAutoUseValidatedEndpoints(t *testing.T) {
	first := validEndpoint("endpoint-a", "subscription-id", "First")
	second := validEndpoint("endpoint-b", "subscription-id", "Second")
	stateStore := newFakeStateStore()
	stateStore.setSnapshot(state.Snapshot{
		SchemaVersion: state.CurrentSchemaVersion,
		Subscriptions: []domain.Subscription{{ID: "subscription-id", Name: "Subscription", SecretRef: "secret-ref", Format: domain.SubscriptionFormatURIList}},
		Endpoints:     []domain.Endpoint{first, second},
	})
	latencyChecker := &fakeLatencyChecker{results: []latency.Result{
		{EndpointID: first.ID, Status: latency.StatusSuccess, Duration: 20 * time.Millisecond},
		{EndpointID: second.ID, Status: latency.StatusSuccess, Duration: 10 * time.Millisecond},
	}}
	daemon := &fakeDaemon{}
	service := newTestService(t, testConfig{state: stateStore, latency: latencyChecker, daemon: daemon})

	if _, err := service.Connect(context.Background(), first.ID, domain.ConnectionModeTUN, domain.RouteModeRule); err != nil {
		t.Fatalf("manual Connect: %v", err)
	}
	if _, err := service.Connect(context.Background(), AutoTarget, domain.ConnectionModeProxy, domain.RouteModeGlobal); err != nil {
		t.Fatalf("auto Connect: %v", err)
	}
	if len(daemon.connectCalls) != 2 || daemon.connectCalls[0].Endpoint == nil || !reflect.DeepEqual(*daemon.connectCalls[0].Endpoint, first) || daemon.connectCalls[1].Endpoint == nil || !reflect.DeepEqual(*daemon.connectCalls[1].Endpoint, second) {
		t.Fatalf("unexpected daemon payloads: %#v", daemon.connectCalls)
	}
}

func TestConnectAutoFailureReturnsStableServerError(t *testing.T) {
	endpoint := validEndpoint("endpoint-id", "subscription-id", "Endpoint")
	stateStore := newFakeStateStore()
	stateStore.setSnapshot(state.Snapshot{
		SchemaVersion: state.CurrentSchemaVersion,
		Subscriptions: []domain.Subscription{{ID: "subscription-id", Name: "Subscription", SecretRef: "secret-ref", Format: domain.SubscriptionFormatURIList}},
		Endpoints:     []domain.Endpoint{endpoint},
	})
	latencyChecker := &fakeLatencyChecker{results: []latency.Result{{
		EndpointID: endpoint.ID,
		Protocol:   endpoint.Protocol,
		Status:     latency.StatusUnavailable,
		Error:      "private network failure proxy.example.com:443 endpoint-password",
	}}}
	daemon := &fakeDaemon{}
	service := newTestService(t, testConfig{state: stateStore, latency: latencyChecker, daemon: daemon})

	_, err := service.Connect(context.Background(), AutoTarget, domain.ConnectionModeProxy, domain.RouteModeGlobal)
	assertStableError(t, err, ErrServerNotFound)
	if len(daemon.connectCalls) != 0 {
		t.Fatalf("daemon called without an available endpoint: %#v", daemon.connectCalls)
	}
}

func TestSubscriptionViewsPreserveOrdinaryNamesAndHideSensitiveFields(t *testing.T) {
	stateStore := newFakeStateStore()
	stateStore.setSnapshot(state.Snapshot{
		SchemaVersion: state.CurrentSchemaVersion,
		Subscriptions: []domain.Subscription{
			{ID: "ordinary-id", Name: "Ordinary subscription", SecretRef: "secret-ordinary", Format: domain.SubscriptionFormatURIList, LastError: "private raw failure https://provider.example/token"},
			{ID: "sensitive-id", Name: "https://provider.example/private-token", SecretRef: "secret-sensitive", Format: domain.SubscriptionFormatClash},
		},
	})
	service := newTestService(t, testConfig{state: stateStore})

	views, err := service.ListSubscriptions(context.Background())
	if err != nil {
		t.Fatalf("ListSubscriptions: %v", err)
	}
	if len(views) != 2 {
		t.Fatalf("views = %#v", views)
	}
	byID := map[string]SubscriptionView{views[0].ID: views[0], views[1].ID: views[1]}
	if byID["ordinary-id"].Name != "Ordinary subscription" {
		t.Fatalf("ordinary name changed: %#v", byID["ordinary-id"])
	}
	if byID["ordinary-id"].LastError != ErrRefreshFailed.Error() {
		t.Fatalf("raw LastError exposed: %#v", byID["ordinary-id"])
	}
	if byID["sensitive-id"].Name != "Subscription" {
		t.Fatalf("sensitive subscription name was not replaced: %#v", byID["sensitive-id"])
	}
	serialized := fmt.Sprintf("%#v", views)
	for _, forbidden := range []string{"https://", "provider.example", "private-token", "secret-ordinary", "secret-sensitive", "private raw failure"} {
		if strings.Contains(serialized, forbidden) {
			t.Fatalf("subscription projection leaked %q: %s", forbidden, serialized)
		}
	}
}

func TestServerViewsPreserveOrdinaryNamesAndHideSensitiveFields(t *testing.T) {
	ordinary := validEndpoint(expectedScopedEndpointID("subscription-id", "ordinary"), "subscription-id", "Ordinary endpoint")
	sensitive := domain.Endpoint{
		ID:             expectedScopedEndpointID("subscription-id", "sensitive"),
		SubscriptionID: "subscription-id",
		Name:           "proxy.example.com:8443 11111111-1111-1111-1111-111111111111 private-password tls.example.com /private-path cdn.example.com",
		Protocol:       domain.ProtocolVLESS,
		Host:           "proxy.example.com",
		Port:           8443,
		UUID:           "11111111-1111-1111-1111-111111111111",
		TLS:            domain.TLSOptions{Enabled: true, ServerName: "tls.example.com", ALPN: []string{"h2"}},
		Transport:      domain.TransportOptions{Type: domain.TransportWebSocket, Path: "/private-path", Host: "cdn.example.com"},
		VLESSOptions:   &domain.VLESSOptions{},
	}
	if err := sensitive.Validate(); err != nil {
		t.Fatalf("sensitive fixture invalid: %v", err)
	}
	stateStore := newFakeStateStore()
	stateStore.setSnapshot(state.Snapshot{
		SchemaVersion: state.CurrentSchemaVersion,
		Subscriptions: []domain.Subscription{{ID: "subscription-id", Name: "Subscription", SecretRef: "secret-ref", Format: domain.SubscriptionFormatURIList}},
		Endpoints:     []domain.Endpoint{ordinary, sensitive},
	})
	service := newTestService(t, testConfig{state: stateStore})
	service.latencies[ordinary.ID] = latency.Result{EndpointID: ordinary.ID, Protocol: ordinary.Protocol, Status: latency.StatusUnavailable, Error: "private dial proxy.example.com:443 endpoint-password"}
	service.latencies[sensitive.ID] = latency.Result{EndpointID: sensitive.ID, Protocol: sensitive.Protocol, Status: latency.StatusSuccess, Duration: time.Millisecond}

	views, err := service.ListServers(context.Background())
	if err != nil {
		t.Fatalf("ListServers: %v", err)
	}
	if len(views) != 2 {
		t.Fatalf("views = %#v", views)
	}
	byID := map[string]ServerView{views[0].ID: views[0], views[1].ID: views[1]}
	if byID[ordinary.ID].Name != "Ordinary endpoint" {
		t.Fatalf("ordinary endpoint name changed: %#v", byID[ordinary.ID])
	}
	if byID[sensitive.ID].Name != "Endpoint" {
		t.Fatalf("sensitive endpoint name was not replaced: %#v", byID[sensitive.ID])
	}
	if byID[ordinary.ID].Latency == nil || byID[ordinary.ID].Latency.Error != "latency check failed" {
		t.Fatalf("raw latency error exposed: %#v", byID[ordinary.ID].Latency)
	}
	serialized := fmt.Sprintf("%#v", views)
	for _, forbidden := range []string{"proxy.example.com", "8443", "11111111-1111-1111-1111-111111111111", "private-password", "tls.example.com", "/private-path", "cdn.example.com", "endpoint-password", "private dial"} {
		if strings.Contains(serialized, forbidden) {
			t.Fatalf("server projection leaked %q: %s", forbidden, serialized)
		}
	}
}

func TestServerViewHidesCaseVariantOfEndpointHost(t *testing.T) {
	endpoint := validEndpoint(expectedScopedEndpointID("subscription-id", "case-host"), "subscription-id", "PROXY.EXAMPLE.COM")
	stateStore := newFakeStateStore()
	stateStore.setSnapshot(state.Snapshot{
		SchemaVersion: state.CurrentSchemaVersion,
		Subscriptions: []domain.Subscription{{ID: "subscription-id", Name: "Subscription", SecretRef: "secret-ref", Format: domain.SubscriptionFormatURIList}},
		Endpoints:     []domain.Endpoint{endpoint},
	})
	service := newTestService(t, testConfig{state: stateStore})

	views, err := service.ListServers(context.Background())
	if err != nil {
		t.Fatalf("ListServers: %v", err)
	}
	if len(views) != 1 || views[0].Name != "Endpoint" {
		t.Fatalf("case-variant host leaked through endpoint name: %#v", views)
	}
}

func TestParserWarningsAreProjectedWithoutSourceText(t *testing.T) {
	service := newTestService(t, testConfig{
		parse: func(subscriptionID string, _ []byte) (subscription.ParseResult, error) {
			return subscription.ParseResult{
				Format:    domain.SubscriptionFormatURIList,
				Endpoints: []domain.Endpoint{validEndpoint("normalized", subscriptionID, "Endpoint")},
				Warnings: []subscription.Warning{{
					SubscriptionID: subscriptionID,
					Entry:          7,
					Code:           "private-code-https://provider.example",
					Message:        "private parser warning endpoint-password proxy.example.com",
				}},
			}, nil
		},
	})

	_, warnings, err := service.AddSubscription(context.Background(), "Subscription", "https://provider.example/private-token")
	if err != nil {
		t.Fatalf("AddSubscription: %v", err)
	}
	if len(warnings) != 1 || warnings[0].Code != "entry_skipped" || warnings[0].Message != "entry 7 was skipped because it is malformed or unsupported" {
		t.Fatalf("warning was not safely projected: %#v", warnings)
	}
	serialized := fmt.Sprintf("%#v", warnings)
	for _, forbidden := range []string{"https://", "provider.example", "endpoint-password", "proxy.example.com", "private-code", "private parser"} {
		if strings.Contains(serialized, forbidden) {
			t.Fatalf("warning projection leaked %q: %s", forbidden, serialized)
		}
	}
}

func TestPublicStateFailuresMapToStableApplicationError(t *testing.T) {
	tests := []struct {
		name   string
		invoke func(*Service) error
		update bool
	}{
		{name: "list subscriptions", invoke: func(service *Service) error { _, err := service.ListSubscriptions(context.Background()); return err }},
		{name: "update subscriptions", invoke: func(service *Service) error {
			_, err := service.UpdateSubscriptions(context.Background(), "")
			return err
		}},
		{name: "remove subscription", invoke: func(service *Service) error {
			return service.RemoveSubscription(context.Background(), "subscription-id")
		}},
		{name: "list servers", invoke: func(service *Service) error { _, err := service.ListServers(context.Background()); return err }},
		{name: "check latency", invoke: func(service *Service) error {
			_, err := service.CheckLatency(context.Background(), "endpoint-id", false)
			return err
		}},
		{name: "connect", invoke: func(service *Service) error {
			_, err := service.Connect(context.Background(), "endpoint-id", domain.ConnectionModeProxy, domain.RouteModeGlobal)
			return err
		}},
		{name: "set telemetry", update: true, invoke: func(service *Service) error { return service.SetTelemetry(context.Background(), true) }},
		{name: "telemetry status", invoke: func(service *Service) error { _, err := service.TelemetryEnabled(context.Background()); return err }},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			stateStore := newFakeStateStore()
			privateErr := &privateDependencyError{message: "private state error https://state.example rpc payload"}
			if test.update {
				stateStore.updateErrors = []error{privateErr}
			} else {
				stateStore.loadErrors = []error{privateErr}
			}
			service := newTestService(t, testConfig{state: stateStore})

			err := test.invoke(service)
			assertStableError(t, err, ErrStateOperation)
			assertPrivateErrorNotReachable(t, err)
		})
	}
}

func TestDaemonFailuresPreserveOnlyContextAndSafeRPCSentinels(t *testing.T) {
	tests := []struct {
		name     string
		source   error
		expected error
	}{
		{name: "known rpc", source: fmt.Errorf("private daemon wrapper rpc payload: %w", rpc.ErrAccessDenied), expected: rpc.ErrAccessDenied},
		{name: "unknown", source: &privateDependencyError{message: "private daemon source rpc payload"}, expected: rpc.ErrInternal},
		{name: "canceled", source: fmt.Errorf("private cancellation wrapper: %w", context.Canceled), expected: context.Canceled},
		{name: "deadline", source: fmt.Errorf("private deadline wrapper: %w", context.DeadlineExceeded), expected: context.DeadlineExceeded},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			methods := []struct {
				name   string
				invoke func(*Service) error
			}{
				{name: "connect", invoke: func(service *Service) error {
					_, err := service.Connect(context.Background(), "", domain.ConnectionModeProxy, domain.RouteModeDirect)
					return err
				}},
				{name: "disconnect", invoke: func(service *Service) error { _, err := service.Disconnect(context.Background()); return err }},
				{name: "status", invoke: func(service *Service) error { _, err := service.Status(context.Background()); return err }},
			}
			for _, method := range methods {
				t.Run(method.name, func(t *testing.T) {
					daemon := &fakeDaemon{connectErr: test.source, disconnectErr: test.source, statusErr: test.source}
					service := newTestService(t, testConfig{daemon: daemon})
					err := method.invoke(service)
					if err != test.expected {
						t.Fatalf("error = %v (%T), want exact sentinel %v", err, err, test.expected)
					}
					assertPrivateErrorNotReachable(t, err)
				})
			}
		})
	}
}

func TestUpdaterFailuresMapToStableApplicationError(t *testing.T) {
	privateErr := &privateDependencyError{message: "private updater failure https://release.example/token"}
	updater := &fakeUpdater{checkErr: privateErr, applyErr: privateErr}
	service := newTestService(t, testConfig{updater: updater})

	if _, err := service.CheckUpdate(context.Background()); err != ErrUpdaterUnavailable {
		t.Fatalf("CheckUpdate error = %v, want exact %v", err, ErrUpdaterUnavailable)
	} else {
		assertPrivateErrorNotReachable(t, err)
	}
	if err := service.ApplyUpdate(context.Background(), UpdateInfo{LatestVersion: "v0.2.0", Available: true}); err != ErrUpdaterUnavailable {
		t.Fatalf("ApplyUpdate error = %v, want exact %v", err, ErrUpdaterUnavailable)
	} else {
		assertPrivateErrorNotReachable(t, err)
	}
}

func TestCheckLatencyReturnsOnlySafeProjectedResults(t *testing.T) {
	endpoint := validEndpoint("endpoint-id", "subscription-id", "Endpoint")
	stateStore := newFakeStateStore()
	stateStore.setSnapshot(state.Snapshot{
		SchemaVersion: state.CurrentSchemaVersion,
		Subscriptions: []domain.Subscription{{ID: "subscription-id", Name: "Subscription", SecretRef: "secret-ref", Format: domain.SubscriptionFormatURIList}},
		Endpoints:     []domain.Endpoint{endpoint},
	})
	latencyChecker := &fakeLatencyChecker{results: []latency.Result{{
		EndpointID: endpoint.ID,
		Protocol:   endpoint.Protocol,
		Status:     latency.StatusUnavailable,
		Error:      "private dial failure proxy.example.com:443 endpoint-password",
	}}}
	service := newTestService(t, testConfig{state: stateStore, latency: latencyChecker})

	results, err := service.CheckLatency(context.Background(), endpoint.ID, false)
	if err != nil {
		t.Fatalf("CheckLatency: %v", err)
	}
	if len(results) != 1 || results[0].Error != "latency check failed" {
		t.Fatalf("unsafe latency results: %#v", results)
	}
	if stored := service.latencies[endpoint.ID]; stored.Error != "latency check failed" {
		t.Fatalf("unsafe latency result cached: %#v", stored)
	}
}

func TestCheckLatencyConstrainsMalformedDependencyProjection(t *testing.T) {
	endpoint := validEndpoint("endpoint-id", "subscription-id", "Endpoint")
	stateStore := newFakeStateStore()
	stateStore.setSnapshot(state.Snapshot{
		SchemaVersion: state.CurrentSchemaVersion,
		Subscriptions: []domain.Subscription{{ID: "subscription-id", Name: "Subscription", SecretRef: "secret-ref", Format: domain.SubscriptionFormatURIList}},
		Endpoints:     []domain.Endpoint{endpoint},
	})
	latencyChecker := &fakeLatencyChecker{results: []latency.Result{{
		EndpointID: "https://provider.example/private-token",
		Protocol:   domain.Protocol("endpoint-password"),
		Status:     latency.StatusSuccess,
		Duration:   -time.Second,
		Error:      "private dial failure proxy.example.com:443",
	}}}
	service := newTestService(t, testConfig{state: stateStore, latency: latencyChecker})

	results, err := service.CheckLatency(context.Background(), endpoint.ID, false)
	if err != nil {
		t.Fatalf("CheckLatency: %v", err)
	}
	want := []latency.Result{{
		EndpointID: endpoint.ID,
		Protocol:   endpoint.Protocol,
		Status:     latency.StatusUnavailable,
		Error:      "latency check failed",
	}}
	if !reflect.DeepEqual(results, want) {
		t.Fatalf("malformed latency projection = %#v, want %#v", results, want)
	}
	if len(service.latencies) != 1 || !reflect.DeepEqual(service.latencies[endpoint.ID], want[0]) {
		t.Fatalf("malformed latency cache = %#v, want only %#v", service.latencies, want[0])
	}
}

type privateDependencyError struct {
	message string
}

func (err *privateDependencyError) Error() string {
	return err.message
}

func assertPrivateErrorNotReachable(t *testing.T, err error) {
	t.Helper()
	var privateErr *privateDependencyError
	if errors.As(err, &privateErr) {
		t.Fatalf("private dependency error is unwrap-reachable: %v", privateErr)
	}
}

func TestTelemetryConsentPersistsEnableDisableAndStatusWithoutOtherSideEffects(t *testing.T) {
	stateStore := newFakeStateStore()
	fetcher := &fakeFetcher{}
	latencyChecker := &fakeLatencyChecker{}
	daemon := &fakeDaemon{}
	updater := &fakeUpdater{}
	service := newTestService(t, testConfig{state: stateStore, fetcher: fetcher, latency: latencyChecker, daemon: daemon, updater: updater})

	enabled, err := service.TelemetryEnabled(context.Background())
	if err != nil || enabled {
		t.Fatalf("initial telemetry status = %v, %v; want false, nil", enabled, err)
	}
	if err := service.SetTelemetry(context.Background(), true); err != nil {
		t.Fatalf("enable telemetry: %v", err)
	}
	enabled, err = service.TelemetryEnabled(context.Background())
	if err != nil || !enabled {
		t.Fatalf("enabled telemetry status = %v, %v; want true, nil", enabled, err)
	}
	if err := service.SetTelemetry(context.Background(), false); err != nil {
		t.Fatalf("disable telemetry: %v", err)
	}
	enabled, err = service.TelemetryEnabled(context.Background())
	if err != nil || enabled {
		t.Fatalf("disabled telemetry status = %v, %v; want false, nil", enabled, err)
	}
	if stateStore.snapshotCopy().Settings.TelemetryEnabled {
		t.Fatal("disabled consent was not persisted")
	}
	if len(fetcher.calls) != 0 || len(latencyChecker.calls) != 0 || len(daemon.connectCalls) != 0 || daemon.healthCalls != 0 || updater.checkCalls != 0 || len(updater.applyCalls) != 0 {
		t.Fatalf("telemetry consent triggered unrelated/event side effects: fetch=%d latency=%d connect=%d health=%d update-check=%d update-apply=%d", len(fetcher.calls), len(latencyChecker.calls), len(daemon.connectCalls), daemon.healthCalls, updater.checkCalls, len(updater.applyCalls))
	}
}

func TestDoctorDelegatesChecksAndProjectsOnlyStableDiagnostics(t *testing.T) {
	stateStore := newFakeStateStore()
	daemon := &fakeDaemon{healthErr: &privateDependencyError{message: "private daemon health failure rpc payload"}}
	service := newTestService(t, testConfig{
		state:         stateStore,
		daemon:        daemon,
		secretBackend: secrets.BackendInfo{Name: secrets.BackendFile, Warning: "private backend endpoint-password https://provider.example/token"},
	})

	diagnostics := service.Doctor(context.Background())
	if stateStore.loadCalls != 1 || daemon.healthCalls != 1 {
		t.Fatalf("doctor delegation counts: state=%d daemon=%d", stateStore.loadCalls, daemon.healthCalls)
	}
	byCode := make(map[string]Diagnostic, len(diagnostics))
	for _, diagnostic := range diagnostics {
		byCode[diagnostic.Code] = diagnostic
	}
	if byCode["state_ready"].Severity != DiagnosticInfo || byCode["daemon_unavailable"].Message != rpc.ErrUnavailable.Error() {
		t.Fatalf("unexpected state/daemon diagnostics: %#v", diagnostics)
	}
	warning, ok := byCode["secret_backend_warning"]
	if !ok || warning.Severity != DiagnosticWarning || warning.Message != "credential storage fallback is active" {
		t.Fatalf("unsafe secret backend diagnostic: %#v", warning)
	}
	serialized := fmt.Sprintf("%#v", diagnostics)
	for _, forbidden := range []string{"private", "endpoint-password", "https://", "provider.example", "rpc payload"} {
		if strings.Contains(serialized, forbidden) {
			t.Fatalf("doctor diagnostics leaked %q: %s", forbidden, serialized)
		}
	}
}

func TestDoctorReportsUnsupportedOSAndStateFailureWithoutPrivateText(t *testing.T) {
	stateStore := newFakeStateStore()
	stateStore.loadErrors = []error{&privateDependencyError{message: "private state path /Users/name/state.json"}}
	service := newTestService(t, testConfig{state: stateStore, operatingSystem: "windows"})

	diagnostics := service.Doctor(context.Background())
	byCode := make(map[string]Diagnostic, len(diagnostics))
	for _, diagnostic := range diagnostics {
		byCode[diagnostic.Code] = diagnostic
	}
	if byCode["unsupported_os"].Severity != DiagnosticError || byCode["state_unavailable"].Severity != DiagnosticError || byCode["daemon_ready"].Severity != DiagnosticInfo {
		t.Fatalf("unexpected diagnostics: %#v", diagnostics)
	}
	if strings.Contains(fmt.Sprintf("%#v", diagnostics), "private") || strings.Contains(fmt.Sprintf("%#v", diagnostics), "/Users/") {
		t.Fatalf("doctor leaked state error: %#v", diagnostics)
	}
}

func TestUpdateMethodsRejectUnsafeVersionProjections(t *testing.T) {
	updater := &fakeUpdater{info: UpdateInfo{CurrentVersion: "v0.1.0", LatestVersion: "https://release.example/private-token", Available: true}}
	service := newTestService(t, testConfig{updater: updater})

	info, err := service.CheckUpdate(context.Background())
	if err != ErrUpdaterUnavailable || info != (UpdateInfo{}) {
		t.Fatalf("unsafe CheckUpdate result = %#v, %v", info, err)
	}
	unsafeApply := UpdateInfo{CurrentVersion: "v0.1.0", LatestVersion: "rpc payload https://release.example/private-token", Available: true}
	if err := service.ApplyUpdate(context.Background(), unsafeApply); err != ErrInvalidInput {
		t.Fatalf("unsafe ApplyUpdate error = %v, want %v", err, ErrInvalidInput)
	}
	if len(updater.applyCalls) != 0 {
		t.Fatalf("unsafe update reached updater: %#v", updater.applyCalls)
	}
}

func TestUpdateMethodsDelegateSuccessfulOperations(t *testing.T) {
	info := UpdateInfo{CurrentVersion: "v0.1.0", LatestVersion: "v0.2.0", Available: true}
	updater := &fakeUpdater{info: info}
	service := newTestService(t, testConfig{updater: updater})

	actual, err := service.CheckUpdate(context.Background())
	if err != nil || actual != info {
		t.Fatalf("CheckUpdate = %#v, %v; want %#v, nil", actual, err, info)
	}
	if err := service.ApplyUpdate(context.Background(), info); err != nil {
		t.Fatalf("ApplyUpdate: %v", err)
	}
	if updater.checkCalls != 1 || !reflect.DeepEqual(updater.applyCalls, []UpdateInfo{info}) {
		t.Fatalf("updater delegation: checks=%d applies=%#v", updater.checkCalls, updater.applyCalls)
	}
}

func expectedScopedEndpointID(subscriptionID, normalizedID string) string {
	key, _ := hex.DecodeString(testIdentityKeyHex)
	digest := hmac.New(sha256.New, key)
	_, _ = digest.Write([]byte("tuibox-endpoint-public-v1\x00" + subscriptionID + "\x00" + normalizedID))
	return hex.EncodeToString(digest.Sum(nil))
}

func expectedLegacyScopedEndpointID(subscriptionID, normalizedID string) string {
	digest := sha256.Sum256([]byte("tuibox-endpoint-v1\x00" + subscriptionID + "\x00" + normalizedID))
	return hex.EncodeToString(digest[:])
}

func shadowsocksSubscriptionDocument(password string, duplicate bool) []byte {
	credential := base64.RawURLEncoding.EncodeToString([]byte("aes-256-gcm:" + password))
	entry := "ss://" + credential + "@proxy.example.com:443#Endpoint"
	if duplicate {
		entry += "\n" + entry
	}
	return []byte(entry)
}

func bytesOf(value byte, count int) []byte {
	result := make([]byte, count)
	for index := range result {
		result[index] = value
	}
	return result
}

func assertEndpointIDs(t *testing.T, snapshot state.Snapshot, expected ...string) {
	t.Helper()
	actual := make([]string, 0, len(snapshot.Endpoints))
	for _, endpoint := range snapshot.Endpoints {
		actual = append(actual, endpoint.ID)
	}
	sort.Strings(actual)
	sort.Strings(expected)
	if !reflect.DeepEqual(actual, expected) {
		t.Fatalf("endpoint IDs = %v, want %v", actual, expected)
	}
}

type testConfig struct {
	state                StateStore
	secrets              *fakeSecretStore
	fetcher              *fakeFetcher
	parse                ParseFunc
	latency              *fakeLatencyChecker
	daemon               *fakeDaemon
	updater              *fakeUpdater
	generateID           IDGenerator
	generateIdentityKey  IdentityKeyGenerator
	generateRefreshToken IDGenerator
	now                  Clock
	operatingSystem      string
	secretBackend        secrets.BackendInfo
}

func newTestService(t *testing.T, config testConfig) *Service {
	t.Helper()
	if config.state == nil {
		config.state = newFakeStateStore()
	}
	if config.secrets == nil {
		config.secrets = newFakeSecretStore()
	}
	if config.fetcher == nil {
		config.fetcher = &fakeFetcher{document: []byte("test subscription")}
	}
	if config.parse == nil {
		config.parse = func(subscriptionID string, _ []byte) (subscription.ParseResult, error) {
			return subscription.ParseResult{
				Format:    domain.SubscriptionFormatURIList,
				Endpoints: []domain.Endpoint{validEndpoint("normalized-endpoint", subscriptionID, "Test endpoint")},
			}, nil
		}
	}
	if config.latency == nil {
		config.latency = &fakeLatencyChecker{}
	}
	if config.daemon == nil {
		config.daemon = &fakeDaemon{}
	}
	if config.generateID == nil {
		config.generateID = func() (string, error) { return "subscription-id", nil }
	}
	if config.generateIdentityKey == nil {
		config.generateIdentityKey = func() ([]byte, error) {
			key, err := hex.DecodeString(testIdentityKeyHex)
			return key, err
		}
	}
	if config.generateRefreshToken == nil {
		config.generateRefreshToken = func() (string, error) { return "refresh-token", nil }
	}
	if config.now == nil {
		config.now = func() time.Time { return time.Date(2026, 7, 13, 12, 0, 0, 0, time.FixedZone("test", 3600)) }
	}
	if config.operatingSystem == "" {
		config.operatingSystem = "linux"
	}

	service, err := NewService(Config{
		State:                config.state,
		Secrets:              config.secrets,
		SecretBackend:        config.secretBackend,
		Fetcher:              config.fetcher,
		Parse:                config.parse,
		Latency:              config.latency,
		Daemon:               config.daemon,
		Updater:              config.updater,
		GenerateID:           config.generateID,
		GenerateIdentityKey:  config.generateIdentityKey,
		GenerateRefreshToken: config.generateRefreshToken,
		Now:                  config.now,
		OperatingSystem:      config.operatingSystem,
	})
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	return service
}

func validEndpoint(id, subscriptionID, name string) domain.Endpoint {
	return domain.Endpoint{
		ID:             id,
		SubscriptionID: subscriptionID,
		Name:           name,
		Protocol:       domain.ProtocolShadowsocks,
		Host:           "proxy.example.com",
		Port:           443,
		Password:       "endpoint-password",
		Method:         "aes-256-gcm",
	}
}

type fakeStateStore struct {
	mu sync.Mutex

	snapshot state.Snapshot

	loadErrors       []error
	updateErrors     []error
	beforeUpdate     func(*state.Snapshot)
	afterUpdateError func(*state.Snapshot)

	loadCalls      int
	updateCalls    int
	loadContexts   []context.Context
	updateContexts []context.Context
}

func newFakeStateStore() *fakeStateStore {
	return &fakeStateStore{snapshot: state.Snapshot{
		SchemaVersion: state.CurrentSchemaVersion,
		Settings:      state.Settings{EndpointIdentityKey: testIdentityKeyHex},
	}}
}

func newFakeStateStoreWithoutIdentityKey() *fakeStateStore {
	return &fakeStateStore{snapshot: state.Snapshot{SchemaVersion: state.CurrentSchemaVersion}}
}

func (store *fakeStateStore) LoadContext(ctx context.Context) (state.Snapshot, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	store.loadCalls++
	store.loadContexts = append(store.loadContexts, ctx)
	if err := popError(&store.loadErrors); err != nil {
		return state.Snapshot{}, err
	}
	return cloneSnapshot(store.snapshot), nil
}

func (store *fakeStateStore) UpdateContext(ctx context.Context, update func(*state.Snapshot) error) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	store.updateCalls++
	store.updateContexts = append(store.updateContexts, ctx)
	if store.beforeUpdate != nil {
		store.beforeUpdate(&store.snapshot)
	}
	candidate := cloneSnapshot(store.snapshot)
	if err := update(&candidate); err != nil {
		return err
	}
	if err := validateFakeSnapshot(candidate); err != nil {
		return err
	}
	if err := popError(&store.updateErrors); err != nil {
		if store.afterUpdateError != nil {
			store.afterUpdateError(&store.snapshot)
		}
		return err
	}
	store.snapshot = candidate
	return nil
}

func (store *fakeStateStore) snapshotCopy() state.Snapshot {
	store.mu.Lock()
	defer store.mu.Unlock()
	return cloneSnapshot(store.snapshot)
}

func (store *fakeStateStore) setSnapshot(snapshot state.Snapshot) {
	store.mu.Lock()
	defer store.mu.Unlock()
	if snapshot.Settings.EndpointIdentityKey == "" {
		snapshot.Settings.EndpointIdentityKey = testIdentityKeyHex
	}
	store.snapshot = cloneSnapshot(snapshot)
}

func cloneSnapshot(snapshot state.Snapshot) state.Snapshot {
	clone := snapshot
	clone.Subscriptions = append([]domain.Subscription(nil), snapshot.Subscriptions...)
	for index := range clone.Subscriptions {
		if clone.Subscriptions[index].LastRefresh != nil {
			value := *clone.Subscriptions[index].LastRefresh
			clone.Subscriptions[index].LastRefresh = &value
		}
	}
	clone.Endpoints = append([]domain.Endpoint(nil), snapshot.Endpoints...)
	return clone
}

func validateFakeSnapshot(snapshot state.Snapshot) error {
	ids := make(map[string]struct{}, len(snapshot.Endpoints))
	for _, endpoint := range snapshot.Endpoints {
		if err := endpoint.Validate(); err != nil {
			return errors.New("private invalid endpoint state error")
		}
		if _, exists := ids[endpoint.ID]; exists {
			return errors.New("private duplicate endpoint state error")
		}
		ids[endpoint.ID] = struct{}{}
	}
	return nil
}

type secretCall struct {
	context context.Context
	key     string
	value   string
}

type fakeSecretStore struct {
	mu sync.Mutex

	values map[string]string

	getErrors    []error
	setErrors    []error
	deleteErrors []error
	getFunc      func(context.Context, string) (string, error)
	setFunc      func(context.Context, string, string) error
	deleteFunc   func(context.Context, string) error

	getCalls    []secretCall
	setCalls    []secretCall
	deleteCalls []secretCall
}

func newFakeSecretStore() *fakeSecretStore {
	return &fakeSecretStore{values: make(map[string]string)}
}

func (store *fakeSecretStore) Get(ctx context.Context, key string) (string, error) {
	store.mu.Lock()
	store.getCalls = append(store.getCalls, secretCall{context: ctx, key: key})
	fn := store.getFunc
	if fn == nil {
		if err := popError(&store.getErrors); err != nil {
			store.mu.Unlock()
			return "", err
		}
		value, ok := store.values[key]
		store.mu.Unlock()
		if !ok {
			return "", secrets.ErrSecretNotFound
		}
		return value, nil
	}
	store.mu.Unlock()
	return fn(ctx, key)
}

func (store *fakeSecretStore) Set(ctx context.Context, key, value string) error {
	store.mu.Lock()
	store.setCalls = append(store.setCalls, secretCall{context: ctx, key: key, value: value})
	fn := store.setFunc
	if fn == nil {
		if err := popError(&store.setErrors); err != nil {
			store.mu.Unlock()
			return err
		}
		store.values[key] = value
		store.mu.Unlock()
		return nil
	}
	store.mu.Unlock()
	return fn(ctx, key, value)
}

func (store *fakeSecretStore) Delete(ctx context.Context, key string) error {
	store.mu.Lock()
	store.deleteCalls = append(store.deleteCalls, secretCall{context: ctx, key: key})
	fn := store.deleteFunc
	if fn == nil {
		if err := popError(&store.deleteErrors); err != nil {
			store.mu.Unlock()
			return err
		}
		delete(store.values, key)
		store.mu.Unlock()
		return nil
	}
	store.mu.Unlock()
	return fn(ctx, key)
}

func (store *fakeSecretStore) value(key string) (string, bool) {
	store.mu.Lock()
	defer store.mu.Unlock()
	value, ok := store.values[key]
	return value, ok
}

func (store *fakeSecretStore) setValue(key, value string) {
	store.mu.Lock()
	defer store.mu.Unlock()
	store.values[key] = value
}

func popError(errorsQueue *[]error) error {
	if len(*errorsQueue) == 0 {
		return nil
	}
	err := (*errorsQueue)[0]
	*errorsQueue = (*errorsQueue)[1:]
	return err
}

type fakeFetcher struct {
	document  []byte
	errors    []error
	fetchFunc func(context.Context, string) ([]byte, error)
	calls     []string
}

func (fetcher *fakeFetcher) Fetch(ctx context.Context, url string) ([]byte, error) {
	fetcher.calls = append(fetcher.calls, url)
	if fetcher.fetchFunc != nil {
		return fetcher.fetchFunc(ctx, url)
	}
	if err := popError(&fetcher.errors); err != nil {
		return nil, err
	}
	return append([]byte(nil), fetcher.document...), nil
}

type fakeLatencyChecker struct {
	results []latency.Result
	calls   [][]domain.Endpoint
}

func (checker *fakeLatencyChecker) Check(_ context.Context, endpoints []domain.Endpoint) []latency.Result {
	checker.calls = append(checker.calls, append([]domain.Endpoint(nil), endpoints...))
	return append([]latency.Result(nil), checker.results...)
}

type fakeDaemon struct {
	connectStatus    rpc.SessionStatus
	disconnectStatus rpc.SessionStatus
	status           rpc.SessionStatus
	connectErr       error
	disconnectErr    error
	statusErr        error
	healthErr        error
	connectCalls     []rpc.ConnectPayload
	disconnectCalls  int
	statusCalls      int
	healthCalls      int
}

func (daemon *fakeDaemon) Connect(_ context.Context, payload rpc.ConnectPayload) (rpc.SessionStatus, error) {
	daemon.connectCalls = append(daemon.connectCalls, payload)
	return daemon.connectStatus, daemon.connectErr
}

func (daemon *fakeDaemon) Disconnect(context.Context) (rpc.SessionStatus, error) {
	daemon.disconnectCalls++
	return daemon.disconnectStatus, daemon.disconnectErr
}

func (daemon *fakeDaemon) Status(context.Context) (rpc.SessionStatus, error) {
	daemon.statusCalls++
	return daemon.status, daemon.statusErr
}

func (daemon *fakeDaemon) Health(context.Context) error {
	daemon.healthCalls++
	return daemon.healthErr
}

type fakeUpdater struct {
	info       UpdateInfo
	checkErr   error
	applyErr   error
	checkCalls int
	applyCalls []UpdateInfo
}

func (updater *fakeUpdater) Check(context.Context) (UpdateInfo, error) {
	updater.checkCalls++
	return updater.info, updater.checkErr
}

func (updater *fakeUpdater) Apply(_ context.Context, update UpdateInfo) error {
	updater.applyCalls = append(updater.applyCalls, update)
	return updater.applyErr
}

func assertStableError(t *testing.T, err error, expected ...error) {
	t.Helper()
	if err == nil {
		t.Fatal("expected error")
	}
	for _, target := range expected {
		if !errors.Is(err, target) {
			t.Fatalf("error %q does not match %q", err, target)
		}
	}
	privateFragments := []string{"private", "https://", "proxy.example.com", "endpoint-password", "rpc payload"}
	for _, fragment := range privateFragments {
		if strings.Contains(err.Error(), fragment) {
			t.Fatalf("error leaked %q: %q", fragment, err)
		}
	}
}

func assertHasDeadlineWithin(t *testing.T, ctx context.Context, maximum time.Duration) {
	t.Helper()
	deadline, ok := ctx.Deadline()
	if !ok {
		t.Fatal("compensation context has no deadline")
	}
	remaining := time.Until(deadline)
	if remaining <= 0 || remaining > maximum {
		t.Fatalf("compensation deadline remaining %v, want within %v", remaining, maximum)
	}
}

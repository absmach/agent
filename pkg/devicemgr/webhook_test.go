// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

package devicemgr_test

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/absmach/agent/pkg/devicemgr"
	"github.com/absmach/agent/pkg/iface"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// webhookSink is a test HTTP endpoint that records the events it receives.
type webhookSink struct {
	mu        sync.Mutex
	events    []devicemgr.Event
	signature string
	rawBodies [][]byte
	got       chan struct{}
}

func newWebhookSink() *webhookSink {
	return &webhookSink{got: make(chan struct{}, 16)}
}

func (s *webhookSink) handler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		var ev devicemgr.Event
		if err := json.Unmarshal(raw, &ev); err != nil {
			http.Error(w, "bad body", http.StatusBadRequest)
			return
		}
		s.mu.Lock()
		s.events = append(s.events, ev)
		s.rawBodies = append(s.rawBodies, raw)
		s.signature = r.Header.Get("X-Agent-Webhook-Signature")
		s.mu.Unlock()
		s.got <- struct{}{}
		w.WriteHeader(http.StatusOK)
	}
}

// waitFor blocks until at least n events have been received or the timeout fires.
func (s *webhookSink) waitFor(t *testing.T, n int) {
	t.Helper()
	deadline := time.After(2 * time.Second)
	for {
		s.mu.Lock()
		count := len(s.events)
		s.mu.Unlock()
		if count >= n {
			return
		}
		select {
		case <-s.got:
		case <-deadline:
			t.Fatalf("timed out waiting for %d webhook events, got %d", n, count)
		}
	}
}

func (s *webhookSink) types() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]string, len(s.events))
	for i, e := range s.events {
		out[i] = e.Type
	}
	return out
}

func newWebhookManager(t *testing.T, atomURL string, cfg devicemgr.WebhookConfig) *devicemgr.Manager {
	t.Helper()
	m, err := devicemgr.New(
		filepath.Join(t.TempDir(), "devices.db"),
		devicemgr.ProvisionConfig{
			AtomURL:  atomURL,
			Token:    "test-token",
			TenantID: "test-tenant",
		},
		iface.Config{},
		devicemgr.WithWebhook(cfg),
	)
	require.NoError(t, err)
	t.Cleanup(func() { m.Close() })
	return m
}

func TestManager_WebhookLifecycleEvents(t *testing.T) {
	sink := newWebhookSink()
	hookSrv := httptest.NewServer(sink.handler())
	t.Cleanup(hookSrv.Close)

	mgSrv := magistralaServer(t, nil)
	m := newWebhookManager(t, mgSrv.URL, devicemgr.WebhookConfig{
		URL:    hookSrv.URL,
		Secret: "s3cret",
	})

	d, err := m.Add(context.Background(), "dev", "ext", "key", iface.InterfaceBLE, "AA:BB:CC:DD:EE:FF")
	require.NoError(t, err)
	require.NoError(t, m.MarkSeen(d.ID)) // filtered out of the default event set
	require.NoError(t, m.Remove(d.ID))

	sink.waitFor(t, 2)
	// Give any erroneously-emitted seen event a moment to arrive (it must not).
	time.Sleep(50 * time.Millisecond)

	types := sink.types()
	assert.Contains(t, types, devicemgr.EventDeviceAdded)
	assert.Contains(t, types, devicemgr.EventDeviceRemoved)
	assert.NotContains(t, types, devicemgr.EventDeviceSeen,
		"device.seen must be excluded from the default event set")

	sink.mu.Lock()
	defer sink.mu.Unlock()
	// The added event should carry the full device record.
	var added devicemgr.Event
	for _, e := range sink.events {
		if e.Type == devicemgr.EventDeviceAdded {
			added = e
		}
	}
	require.NotNil(t, added.Device)
	assert.Equal(t, d.ID, added.Device.ID)
	// The signature header must be a valid HMAC of the body, and the raw secret
	// must never appear on the wire.
	assert.True(t, len(sink.signature) > len("sha256="))
	assert.NotContains(t, sink.signature, "s3cret")
}

func TestManager_WebhookHMACSignature(t *testing.T) {
	const secret = "top-secret"
	sink := newWebhookSink()
	hookSrv := httptest.NewServer(sink.handler())
	t.Cleanup(hookSrv.Close)

	mgSrv := magistralaServer(t, nil)
	m := newWebhookManager(t, mgSrv.URL, devicemgr.WebhookConfig{
		URL:    hookSrv.URL,
		Secret: secret,
	})

	_, err := m.Add(context.Background(), "dev", "ext", "key", iface.InterfaceBLE, "addr")
	require.NoError(t, err)
	sink.waitFor(t, 1)

	sink.mu.Lock()
	defer sink.mu.Unlock()
	body := sink.rawBodies[0]
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(body)
	want := "sha256=" + hex.EncodeToString(mac.Sum(nil))
	assert.Equal(t, want, sink.signature, "signature must be HMAC-SHA256 of the exact body")
}

func TestManager_WebhookEventOptIn(t *testing.T) {
	sink := newWebhookSink()
	hookSrv := httptest.NewServer(sink.handler())
	t.Cleanup(hookSrv.Close)

	mgSrv := magistralaServer(t, nil)
	// Explicit allowlist that includes only device.seen.
	m := newWebhookManager(t, mgSrv.URL, devicemgr.WebhookConfig{
		URL:    hookSrv.URL,
		Events: []string{devicemgr.EventDeviceSeen},
	})

	d, err := m.Add(context.Background(), "dev", "ext", "key", iface.InterfaceBLE, "addr")
	require.NoError(t, err) // device.added not in allowlist -> not delivered
	require.NoError(t, m.MarkSeen(d.ID))

	sink.waitFor(t, 1)
	time.Sleep(50 * time.Millisecond)

	types := sink.types()
	assert.Equal(t, []string{devicemgr.EventDeviceSeen}, types,
		"only the explicitly allowlisted event should be delivered")
}

func TestManager_WebhookRetry(t *testing.T) {
	var attempts atomic.Int32
	done := make(chan struct{}, 1)
	hookSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Fail the first attempt with a 503, succeed on the second.
		if attempts.Add(1) == 1 {
			http.Error(w, "unavailable", http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
		select {
		case done <- struct{}{}:
		default:
		}
	}))
	t.Cleanup(hookSrv.Close)

	mgSrv := magistralaServer(t, nil)
	m := newWebhookManager(t, mgSrv.URL, devicemgr.WebhookConfig{
		URL:     hookSrv.URL,
		Retries: 2,
	})

	_, err := m.Add(context.Background(), "dev", "ext", "key", iface.InterfaceBLE, "addr")
	require.NoError(t, err)

	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("webhook was not retried after the initial 503")
	}
	assert.GreaterOrEqual(t, attempts.Load(), int32(2), "delivery should have been retried")
}

func TestManager_NoWebhookByDefault(t *testing.T) {
	// A manager built without WithWebhook must not panic on lifecycle ops.
	mgSrv := magistralaServer(t, nil)
	m := newTestManager(t, mgSrv.URL)

	d, err := m.Add(context.Background(), "dev", "ext", "key", iface.InterfaceBLE, "addr")
	require.NoError(t, err)
	require.NoError(t, m.MarkSeen(d.ID))
	require.NoError(t, m.Remove(d.ID))
}

func TestManager_WebhookDisabledWithEmptyURL(t *testing.T) {
	mgSrv := magistralaServer(t, nil)
	m := newWebhookManager(t, mgSrv.URL, devicemgr.WebhookConfig{URL: ""})

	d, err := m.Add(context.Background(), "dev", "ext", "key", iface.InterfaceBLE, "addr")
	require.NoError(t, err)
	require.NoError(t, m.Remove(d.ID))
}

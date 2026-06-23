// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

package devicemgr

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"sync"
	"sync/atomic"
	"time"
)

// Device lifecycle event types emitted to a configured webhook.
const (
	EventDeviceAdded       = "device.added"
	EventDeviceRemoved     = "device.removed"
	EventDeviceSeen        = "device.seen"
	EventDeviceIfaceOpened = "device.iface_opened"
	EventDeviceIfaceClosed = "device.iface_closed"
)

// defaultWebhookEvents is the set of events delivered when WebhookConfig.Events
// is empty. device.seen is deliberately excluded: the telemetry scheduler marks
// a device seen on every poll (a few milliseconds apart), which would flood the
// queue and crowd out the low-frequency lifecycle events. Enable it explicitly
// via MG_AGENT_DEVICE_WEBHOOK_EVENTS when a receiver actually wants liveness.
var defaultWebhookEvents = []string{
	EventDeviceAdded,
	EventDeviceRemoved,
	EventDeviceIfaceOpened,
	EventDeviceIfaceClosed,
}

// Event is a single device lifecycle notification delivered to a webhook.
// Device is included when the full record is readily available (e.g. on add).
type Event struct {
	Type      string    `json:"event"`
	DeviceID  string    `json:"device_id"`
	Timestamp time.Time `json:"timestamp"`
	Device    *Device   `json:"device,omitempty"`
}

// Notifier delivers device lifecycle events to an external consumer.
// Implementations must be safe for concurrent use and must never block the
// caller of Notify.
type Notifier interface {
	Notify(ev Event)
	Close() error
}

// WebhookConfig configures delivery of lifecycle events to an HTTP endpoint.
type WebhookConfig struct {
	// URL is the endpoint that receives a POST with a JSON Event body for
	// every enabled lifecycle event. An empty URL disables webhook delivery.
	URL string
	// Secret, when set, is used to HMAC-SHA256 sign the request body. The
	// signature is sent as "X-Agent-Webhook-Signature: sha256=<hex>" so the
	// receiver can verify both authenticity and payload integrity without the
	// raw secret ever travelling on the wire. HTTPS is still recommended.
	Secret string
	// Events is the allowlist of event types to deliver. Empty means
	// defaultWebhookEvents (everything except the high-frequency device.seen).
	Events []string
	// Timeout bounds each delivery attempt. Defaults to 5s when zero.
	Timeout time.Duration
	// QueueSize is the number of pending events buffered before new events are
	// dropped to keep device operations non-blocking. Defaults to 64 when zero.
	QueueSize int
	// Retries is the number of additional attempts after the first failed
	// delivery (network error or 5xx). Defaults to 2 when zero; set negative
	// to disable retries.
	Retries int
	// Logger receives debug lines for dropped and failed deliveries. Defaults
	// to slog.Default() when nil.
	Logger *slog.Logger
}

// nopNotifier is the default Notifier used when no webhook is configured.
type nopNotifier struct{}

func (nopNotifier) Notify(Event) {}
func (nopNotifier) Close() error { return nil }

// webhookNotifier delivers events to an HTTP endpoint from a background worker
// so that Notify never blocks the device operation that produced the event.
type webhookNotifier struct {
	cfg     WebhookConfig
	client  *http.Client
	events  chan Event
	allowed map[string]bool
	retries int
	logger  *slog.Logger
	dropped atomic.Uint64
	wg      sync.WaitGroup
	once    sync.Once
	done    chan struct{}
}

// newWebhookNotifier returns a Notifier that POSTs events to cfg.URL. When the
// URL is empty it returns a no-op notifier so callers need not special-case it.
func newWebhookNotifier(cfg WebhookConfig) Notifier {
	if cfg.URL == "" {
		return nopNotifier{}
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 5 * time.Second
	}
	if cfg.QueueSize <= 0 {
		cfg.QueueSize = 64
	}
	retries := cfg.Retries
	if retries == 0 {
		retries = 2
	}
	if retries < 0 {
		retries = 0
	}
	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}
	events := cfg.Events
	if len(events) == 0 {
		events = defaultWebhookEvents
	}
	allowed := make(map[string]bool, len(events))
	for _, e := range events {
		allowed[e] = true
	}
	n := &webhookNotifier{
		cfg:     cfg,
		client:  &http.Client{Timeout: cfg.Timeout},
		events:  make(chan Event, cfg.QueueSize),
		allowed: allowed,
		retries: retries,
		logger:  logger,
		done:    make(chan struct{}),
	}
	n.wg.Add(1)
	go n.run()
	return n
}

// Notify enqueues an event for delivery. Events not in the allowlist are
// ignored. If the queue is full the event is dropped (and counted) rather than
// blocking the caller, since lifecycle notifications are best-effort and must
// not stall device management.
func (n *webhookNotifier) Notify(ev Event) {
	if !n.allowed[ev.Type] {
		return
	}
	if ev.Timestamp.IsZero() {
		ev.Timestamp = time.Now().UTC()
	}
	select {
	case n.events <- ev:
	case <-n.done:
	default:
		total := n.dropped.Add(1)
		n.logger.Debug("device webhook event dropped: queue full",
			slog.String("event", ev.Type),
			slog.String("device_id", ev.DeviceID),
			slog.Uint64("dropped_total", total))
	}
}

// Dropped returns the number of events dropped because the queue was full.
func (n *webhookNotifier) Dropped() uint64 { return n.dropped.Load() }

// Close stops the worker after the in-flight event finishes. Queued but
// undelivered events are discarded.
func (n *webhookNotifier) Close() error {
	n.once.Do(func() {
		close(n.done)
	})
	n.wg.Wait()
	return nil
}

func (n *webhookNotifier) run() {
	defer n.wg.Done()
	for {
		select {
		case <-n.done:
			return
		case ev := <-n.events:
			n.deliver(ev)
		}
	}
}

// deliver POSTs the event, retrying on transient failures (network errors and
// 5xx responses) with a short backoff. It gives up after cfg.Retries extra
// attempts or when the notifier is closing.
func (n *webhookNotifier) deliver(ev Event) {
	body, err := json.Marshal(ev)
	if err != nil {
		return
	}
	var sig string
	if n.cfg.Secret != "" {
		mac := hmac.New(sha256.New, []byte(n.cfg.Secret))
		mac.Write(body)
		sig = "sha256=" + hex.EncodeToString(mac.Sum(nil))
	}

	attempts := n.retries + 1
	for attempt := 0; attempt < attempts; attempt++ {
		if attempt > 0 {
			select {
			case <-n.done:
				return
			case <-time.After(backoff(attempt)):
			}
		}
		delivered, retryable := n.send(body, sig)
		if delivered {
			return
		}
		if !retryable {
			n.logger.Debug("device webhook delivery failed: non-retryable",
				slog.String("event", ev.Type), slog.String("device_id", ev.DeviceID))
			return
		}
	}
	n.logger.Debug("device webhook delivery failed: retries exhausted",
		slog.String("event", ev.Type),
		slog.String("device_id", ev.DeviceID),
		slog.Int("attempts", attempts))
}

// send performs one delivery attempt. It returns whether the event was
// delivered (2xx) and, if not, whether the failure is worth retrying (network
// error or 5xx; 4xx is treated as permanent).
func (n *webhookNotifier) send(body []byte, sig string) (delivered, retryable bool) {
	ctx, cancel := context.WithTimeout(context.Background(), n.cfg.Timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, n.cfg.URL, bytes.NewReader(body))
	if err != nil {
		return false, false
	}
	req.Header.Set("Content-Type", "application/json")
	if sig != "" {
		req.Header.Set("X-Agent-Webhook-Signature", sig)
	}
	resp, err := n.client.Do(req)
	if err != nil {
		return false, true
	}
	// Drain (bounded) and close so the keep-alive connection can be reused.
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
	_ = resp.Body.Close()
	switch {
	case resp.StatusCode >= 200 && resp.StatusCode < 300:
		return true, false
	case resp.StatusCode >= 500:
		return false, true
	default:
		return false, false
	}
}

// backoff returns the delay before retry attempt n (n >= 1): 200ms, 400ms, ...
func backoff(attempt int) time.Duration {
	return time.Duration(attempt) * 200 * time.Millisecond
}

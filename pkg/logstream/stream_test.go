// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

package logstream

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNew(t *testing.T) {
	s := New()
	assert.NotNil(t, s)
	assert.Empty(t, s.subs)
}

func TestPushAndGetBacklog(t *testing.T) {
	s := New()

	s.push("line 1")
	s.push("line 2")
	s.push("line 3")

	_, backlog, _ := s.subscribe()
	assert.Equal(t, []string{"line 1", "line 2", "line 3"}, backlog)
}

func TestRingBuffer(t *testing.T) {
	s := New()

	for i := 0; i < ringSize+50; i++ {
		s.push("line")
	}

	_, backlog, _ := s.subscribe()
	assert.Equal(t, ringSize, len(backlog))
}

func TestSubscribeBroadcast(t *testing.T) {
	s := New()

	id, _, ch := s.subscribe()
	defer s.unsubscribe(id)

	var received string
	var mu sync.Mutex

	go func() {
		select {
		case line := <-ch:
			mu.Lock()
			received = line
			mu.Unlock()
		case <-time.After(time.Second):
		}
	}()

	time.Sleep(50 * time.Millisecond)
	s.push("hello")

	assert.Eventually(t, func() bool {
		mu.Lock()
		defer mu.Unlock()
		return received == "hello"
	}, 2*time.Second, 10*time.Millisecond)
}

func TestUnsubscribe(t *testing.T) {
	s := New()

	id, _, ch := s.subscribe()
	s.unsubscribe(id)

	s.push("after-unsubscribe")

	select {
	case <-ch:
		t.Fatal("should not receive after unsubscribe")
	default:
	}
}

func TestSSEHandler(t *testing.T) {
	s := New()
	s.push("backlog-line")

	handler := SSEHandler(s)

	req := httptest.NewRequest(http.MethodGet, "/logs", nil)
	ctx, cancel := context.WithCancel(req.Context())
	req = req.WithContext(ctx)

	rec := httptest.NewRecorder()

	var wg sync.WaitGroup
	wg.Add(1)

	go func() {
		defer wg.Done()
		handler.ServeHTTP(rec, req)
	}()

	time.Sleep(100 * time.Millisecond)
	s.push("live-line")
	time.Sleep(100 * time.Millisecond)

	cancel()
	wg.Wait()

	body := rec.Body.String()
	assert.Contains(t, body, "data: backlog-line")
	assert.Contains(t, body, "data: live-line")
	assert.Equal(t, "text/event-stream", rec.Header().Get("Content-Type"))
}

func TestHandler(t *testing.T) {
	s := New()
	inner := slog.NewTextHandler(io.Discard, nil)
	h := NewHandler(inner, s)

	assert.True(t, h.Enabled(context.Background(), slog.LevelInfo))

	record := slog.NewRecord(time.Now(), slog.LevelInfo, "test message", 0)
	record.AddAttrs(slog.String("key", "value"))

	err := h.Handle(context.Background(), record)
	require.NoError(t, err)

	_, backlog, _ := s.subscribe()
	require.Len(t, backlog, 1)
	assert.Contains(t, backlog[0], "test message")
	assert.Contains(t, backlog[0], "key=value")
}

func TestHandlerWithAttrs(t *testing.T) {
	s := New()
	inner := slog.NewTextHandler(io.Discard, nil)
	h := NewHandler(inner, s)

	h2 := h.WithAttrs([]slog.Attr{slog.String("persistent", "attr")})
	assert.NotNil(t, h2)
}

func TestHandlerWithGroup(t *testing.T) {
	s := New()
	inner := slog.NewTextHandler(io.Discard, nil)
	h := NewHandler(inner, s)

	h2 := h.WithGroup("mygroup")
	assert.NotNil(t, h2)
}

func TestMultipleSubscribers(t *testing.T) {
	s := New()

	id1, _, ch1 := s.subscribe()
	id2, _, ch2 := s.subscribe()
	defer s.unsubscribe(id1)
	defer s.unsubscribe(id2)

	s.push("broadcast")

	var r1, r2 string
	var mu sync.Mutex

	go func() {
		select {
		case line := <-ch1:
			mu.Lock()
			r1 = line
			mu.Unlock()
		case <-time.After(time.Second):
		}
	}()

	go func() {
		select {
		case line := <-ch2:
			mu.Lock()
			r2 = line
			mu.Unlock()
		case <-time.After(time.Second):
		}
	}()

	assert.Eventually(t, func() bool {
		mu.Lock()
		defer mu.Unlock()
		return r1 == "broadcast" && r2 == "broadcast"
	}, 2*time.Second, 10*time.Millisecond)
}

func TestSSEFormat(t *testing.T) {
	s := New()
	s.push("test line")

	handler := SSEHandler(s)

	req := httptest.NewRequest(http.MethodGet, "/logs", nil)
	ctx, cancel := context.WithCancel(req.Context())
	req = req.WithContext(ctx)

	rec := httptest.NewRecorder()

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		handler.ServeHTTP(rec, req)
	}()

	time.Sleep(100 * time.Millisecond)
	cancel()
	wg.Wait()

	body := rec.Body.String()
	lines := strings.Split(body, "\n")
	found := false
	for _, line := range lines {
		if strings.HasPrefix(line, "data: test line") {
			found = true
			break
		}
	}
	assert.True(t, found, "expected SSE data line format")
}

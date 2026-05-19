// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

package logstream

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"sync"
)

const ringSize = 500

// Stream is a concurrent ring buffer that broadcasts log lines to SSE subscribers.
type Stream struct {
	mu   sync.Mutex
	ring [ringSize]string
	head int
	size int
	subs map[uint64]chan string
	next uint64
}

func New() *Stream {
	return &Stream{subs: make(map[uint64]chan string)}
}

func (s *Stream) push(line string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ring[s.head] = line
	s.head = (s.head + 1) % ringSize
	if s.size < ringSize {
		s.size++
	}
	for _, ch := range s.subs {
		select {
		case ch <- line:
		default:
		}
	}
}

func (s *Stream) subscribe() (id uint64, backlog []string, ch chan string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	backlog = make([]string, s.size)
	start := 0
	if s.size == ringSize {
		start = s.head
	}
	for i := range s.size {
		backlog[i] = s.ring[(start+i)%ringSize]
	}
	ch = make(chan string, 64)
	id = s.next
	s.next++
	s.subs[id] = ch
	return id, backlog, ch
}

func (s *Stream) unsubscribe(id uint64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.subs, id)
}

// Handler wraps a slog.Handler and feeds formatted log lines into the stream.
type Handler struct {
	delegate slog.Handler
	stream   *Stream
}

func NewHandler(delegate slog.Handler, stream *Stream) *Handler {
	return &Handler{delegate: delegate, stream: stream}
}

func (h *Handler) Enabled(ctx context.Context, level slog.Level) bool {
	return h.delegate.Enabled(ctx, level)
}

func (h *Handler) Handle(ctx context.Context, r slog.Record) error {
	var b strings.Builder
	b.WriteString(r.Time.Format("15:04:05"))
	b.WriteString(" ")
	b.WriteString(r.Level.String())
	b.WriteString(" ")
	b.WriteString(r.Message)
	r.Attrs(func(a slog.Attr) bool {
		b.WriteString(" ")
		b.WriteString(a.Key)
		b.WriteString("=")
		b.WriteString(fmt.Sprintf("%v", a.Value))
		return true
	})
	h.stream.push(b.String())
	return h.delegate.Handle(ctx, r)
}

func (h *Handler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return &Handler{delegate: h.delegate.WithAttrs(attrs), stream: h.stream}
}

func (h *Handler) WithGroup(name string) slog.Handler {
	return &Handler{delegate: h.delegate.WithGroup(name), stream: h.stream}
}

// SSEHandler returns an http.Handler that streams log lines to the client as SSE.
func SSEHandler(s *Stream) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		flusher, ok := w.(http.Flusher)
		if !ok {
			http.Error(w, "streaming not supported", http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
		w.Header().Set("Connection", "keep-alive")
		w.Header().Set("X-Accel-Buffering", "no")

		id, backlog, ch := s.subscribe()
		defer s.unsubscribe(id)

		for _, line := range backlog {
			fmt.Fprintf(w, "data: %s\n\n", line)
		}
		flusher.Flush()

		for {
			select {
			case line := <-ch:
				fmt.Fprintf(w, "data: %s\n\n", line)
				flusher.Flush()
			case <-r.Context().Done():
				return
			}
		}
	})
}

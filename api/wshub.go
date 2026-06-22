// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"sync"

	"github.com/gorilla/websocket"
)

var upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool { return true },
}

type WSEvent struct {
	Type  string `json:"type"`
	Data  any    `json:"data,omitempty"`
	Error string `json:"error,omitempty"`
}

var eventCh = make(chan WSEvent, 64)

func PushEvent(event WSEvent) {
	select {
	case eventCh <- event:
	default:
	}
}

type WSClient struct {
	conn *websocket.Conn
	send chan []byte
}

type WSHub struct {
	mu      sync.RWMutex
	clients map[*WSClient]bool
	logger  *slog.Logger
}

func NewWSHub(logger *slog.Logger) *WSHub {
	return &WSHub{
		clients: make(map[*WSClient]bool),
		logger:  logger,
	}
}

func (h *WSHub) Run() {
	for event := range eventCh {
		data, err := json.Marshal(event)
		if err != nil {
			h.logger.Warn("WS marshal", slog.Any("error", err))
			continue
		}
		h.mu.RLock()
		for client := range h.clients {
			select {
			case client.send <- data:
			default:
			}
		}
		h.mu.RUnlock()
	}
}

func (h *WSHub) Send(event WSEvent) {
	PushEvent(event)
}

func (h *WSHub) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		h.logger.Warn("WS upgrade", slog.Any("error", err))
		return
	}
	client := &WSClient{
		conn: conn,
		send: make(chan []byte, 64),
	}
	h.mu.Lock()
	h.clients[client] = true
	h.mu.Unlock()

	go client.writePump()
	go client.readPump(h)
}

func (c *WSClient) writePump() {
	defer c.conn.Close()
	for msg := range c.send {
		if err := c.conn.WriteMessage(websocket.TextMessage, msg); err != nil {
			return
		}
	}
}

func (c *WSClient) readPump(hub *WSHub) {
	defer func() {
		c.conn.Close()
		hub.mu.Lock()
		delete(hub.clients, c)
		hub.mu.Unlock()
	}()
	for {
		_, _, err := c.conn.ReadMessage()
		if err != nil {
			return
		}
	}
}

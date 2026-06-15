// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"os"
	"os/exec"
	"sync"
	"time"

	"github.com/creack/pty"
	"github.com/gorilla/websocket"
)

const (
	wsTermTimeout = 60 * time.Second
)

type wsTerminal struct {
	cmd    *exec.Cmd
	ptmx   *os.File
	mu     sync.Mutex
	closed bool
}

type wsMessage struct {
	Type    string `json:"type"`
	Data    string `json:"data,omitempty"`
	Columns int    `json:"columns,omitempty"`
	Rows    int    `json:"rows,omitempty"`
}

func terminalWSHandler(logger *slog.Logger) http.HandlerFunc {
	upgrader := websocket.Upgrader{
		CheckOrigin:       func(r *http.Request) bool { return true },
		ReadBufferSize:    4096,
		WriteBufferSize:   4096,
		EnableCompression: true,
	}

	return func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			logger.Error("Terminal WebSocket upgrade failed", slog.Any("error", err))
			return
		}

		shell := os.Getenv("SHELL")
		if shell == "" {
			shell = "/bin/sh"
		}

		cmd := exec.Command(shell)
		ptmx, err := pty.Start(cmd)
		if err != nil {
			logger.Error("Failed to start PTY", slog.Any("error", err))
			conn.WriteJSON(wsMessage{Type: "error", Data: "Failed to start shell: " + err.Error()})
			conn.Close()
			return
		}

		term := &wsTerminal{
			cmd:  cmd,
			ptmx: ptmx,
		}

		var wg sync.WaitGroup
		wg.Add(2)

		// Read from PTY -> WebSocket
		go func() {
			defer wg.Done()
			buf := make([]byte, 4096)
			for {
				nr, readErr := ptmx.Read(buf)
				if nr > 0 {
					if writeErr := conn.WriteMessage(websocket.TextMessage, buf[:nr]); writeErr != nil {
						break
					}
				}
				if readErr != nil {
					break
				}
			}
		}()

		// Read from WebSocket -> PTY
		go func() {
			defer wg.Done()
			for {
				_, msg, readErr := conn.ReadMessage()
				if readErr != nil {
					break
				}

				var m wsMessage
				if json.Unmarshal(msg, &m) == nil {
					switch m.Type {
					case "resize":
						if m.Columns > 0 && m.Rows > 0 {
							pty.Setsize(ptmx, &pty.Winsize{Rows: uint16(m.Rows), Cols: uint16(m.Columns)})
						}
						continue
					case "input":
						term.mu.Lock()
						if !term.closed {
							ptmx.Write([]byte(m.Data))
						}
						term.mu.Unlock()
						continue
					}
				}
				// Plain text fallback
				term.mu.Lock()
				if !term.closed {
					ptmx.Write(msg)
				}
				term.mu.Unlock()
			}
		}()

		wg.Wait()

		term.mu.Lock()
		term.closed = true
		term.mu.Unlock()
		ptmx.Close()
		cmd.Wait()
		conn.Close()
	}
}

func init() {
	// Ensure gorilla/websocket is a direct dependency
	_ = websocket.ErrCloseSent
}

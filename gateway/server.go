// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/gorilla/websocket"
)

type Server struct {
	broker *Broker
	tokens map[string][]string
	logger *slog.Logger
}

type authContextKey struct{}

type principal struct {
	ID    string
	Roles []string
}

func NewHandler(broker *Broker, tokens map[string][]string, logger *slog.Logger) http.Handler {
	s := &Server{broker: broker, tokens: tokens, logger: logger}
	r := chi.NewRouter()
	r.Get("/health", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "pass"})
	})
	r.Group(func(api chi.Router) {
		api.Get("/api/agents", s.authorize("viewer", s.listAgents))
		api.Post("/api/agents/{agentID}/rpc", s.authorize("", s.rpc))
		api.Put("/api/agents/{agentID}/state/desired", s.authorize("configuration-admin", s.desired))
	})
	r.Get("/api/agents/{agentID}/events", s.events)
	r.Get("/api/agents/{agentID}/logs", s.logs)
	r.Get("/api/agents/{agentID}/terminal", s.terminal)
	return r
}

func (s *Server) authorize(required string, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		provided := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		roles, ok := s.roles(provided)
		if !ok || (required != "" && !hasRole(roles, required)) {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
			return
		}
		authenticated := principal{ID: tokenID(provided), Roles: roles}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), authContextKey{}, authenticated)))
	}
}

func tokenID(token string) string {
	sum := sha256.Sum256([]byte(token))
	return fmt.Sprintf("%x", sum[:6])
}

func (s *Server) roles(provided string) ([]string, bool) {
	for token, roles := range s.tokens {
		if subtle.ConstantTimeCompare([]byte(provided), []byte(token)) == 1 {
			return roles, true
		}
	}
	return nil, false
}

func hasRole(roles []string, required string) bool {
	for _, role := range roles {
		if role == "*" || role == required {
			return true
		}
	}
	return false
}

func (s *Server) wsAuthorized(r *http.Request, required string) (string, principal, bool) {
	for _, protocol := range websocket.Subprotocols(r) {
		if !strings.HasPrefix(protocol, "bearer.") {
			continue
		}
		raw, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(protocol, "bearer."))
		if err == nil {
			if roles, ok := s.roles(string(raw)); ok && hasRole(roles, required) {
				return protocol, principal{ID: tokenID(string(raw)), Roles: roles}, true
			}
		}
	}
	return "", principal{}, false
}

func (s *Server) listAgents(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"agents": s.broker.Agents()})
}

func (s *Server) rpc(w http.ResponseWriter, r *http.Request) {
	var request struct {
		Method string          `json:"method"`
		Params json.RawMessage `json:"params"`
	}
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&request) != nil || request.Method == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "method and valid params are required"})
		return
	}
	if len(request.Params) == 0 {
		request.Params = json.RawMessage(`{}`)
	}
	authenticated, _ := r.Context().Value(authContextKey{}).(principal)
	required := methodRole(request.Method)
	if required == "" || !hasRole(authenticated.Roles, required) {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "token is not authorized for this RPC method"})
		return
	}
	agentID := chi.URLParam(r, "agentID")
	s.logger.Info("Remote management audit",
		slog.String("actor", authenticated.ID),
		slog.String("agent_id", agentID),
		slog.String("action", request.Method),
	)
	response, err := s.broker.Command(r.Context(), agentID, request.Method, string(request.Params))
	if err != nil {
		s.logger.Warn("Remote management audit failed",
			slog.String("actor", authenticated.ID),
			slog.String("agent_id", agentID),
			slog.String("action", request.Method),
			slog.Any("error", err),
		)
		writeJSON(w, http.StatusGatewayTimeout, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, response)
}

func (s *Server) desired(w http.ResponseWriter, r *http.Request) {
	var desired struct {
		SchemaVersion int               `json:"schemaVersion"`
		Generation    uint64            `json:"generation"`
		Config        map[string]string `json:"config"`
	}
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&desired) != nil || desired.SchemaVersion != 1 || desired.Generation == 0 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "schemaVersion=1, generation and config are required"})
		return
	}
	authenticated, _ := r.Context().Value(authContextKey{}).(principal)
	agentID := chi.URLParam(r, "agentID")
	s.logger.Info("Remote management audit",
		slog.String("actor", authenticated.ID),
		slog.String("agent_id", agentID),
		slog.String("action", "state.desired.publish"),
		slog.Uint64("generation", desired.Generation),
	)
	if err := s.broker.PublishDesired(r.Context(), agentID, desired); err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusAccepted, map[string]any{"status": "published", "generation": desired.Generation})
}

var wsUpgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool {
		origin := r.Header.Get("Origin")
		if origin == "" {
			return true
		}
		parsed, err := url.Parse(origin)
		return err == nil && strings.EqualFold(parsed.Host, r.Host)
	},
}

func (s *Server) upgrade(w http.ResponseWriter, r *http.Request, requiredRole string) (*websocket.Conn, string, principal, bool) {
	protocol, authenticated, ok := s.wsAuthorized(r, requiredRole)
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return nil, "", principal{}, false
	}
	agentID := chi.URLParam(r, "agentID")
	if _, ok := s.broker.Agent(agentID); !ok {
		http.NotFound(w, r)
		return nil, "", principal{}, false
	}
	conn, err := wsUpgrader.Upgrade(w, r, http.Header{"Sec-WebSocket-Protocol": []string{protocol}})
	if err != nil {
		return nil, "", principal{}, false
	}
	return conn, agentID, authenticated, true
}

func (s *Server) events(w http.ResponseWriter, r *http.Request) {
	conn, agentID, _, ok := s.upgrade(w, r, "viewer")
	if !ok {
		return
	}
	defer conn.Close()
	events, cancel := s.broker.Subscribe()
	defer cancel()
	for event := range events {
		if event.AgentID == agentID {
			if err := conn.WriteJSON(event); err != nil {
				return
			}
		}
	}
}

func (s *Server) logs(w http.ResponseWriter, r *http.Request) {
	conn, agentID, authenticated, ok := s.upgrade(w, r, "support")
	if !ok {
		return
	}
	s.logger.Info("Remote management audit",
		slog.String("actor", authenticated.ID),
		slog.String("agent_id", agentID),
		slog.String("action", "log.stream.open"),
	)
	defer conn.Close()
	events, cancel := s.broker.Subscribe()
	defer cancel()
	response, err := s.broker.Command(r.Context(), agentID, "log.stream.open", `{"backlog":true}`)
	if err != nil || response.Error != "" {
		s.writeWSError(conn, response.Error, err)
		return
	}
	sessionID, err := streamSessionID(response.Value)
	if err != nil {
		s.writeWSError(conn, "", err)
		return
	}
	defer s.closeStream(agentID, sessionID)
	s.forwardStream(conn, events, agentID, sessionID, "log")
}

func (s *Server) terminal(w http.ResponseWriter, r *http.Request) {
	conn, agentID, authenticated, ok := s.upgrade(w, r, "terminal-admin")
	if !ok {
		return
	}
	s.logger.Info("Remote management audit",
		slog.String("actor", authenticated.ID),
		slog.String("agent_id", agentID),
		slog.String("action", "terminal.open"),
	)
	defer conn.Close()
	events, cancel := s.broker.Subscribe()
	defer cancel()
	response, err := s.broker.Command(r.Context(), agentID, "terminal.open", `{}`)
	if err != nil || response.Error != "" {
		s.writeWSError(conn, response.Error, err)
		return
	}
	sessionID, err := streamSessionID(response.Value)
	if err != nil {
		s.writeWSError(conn, "", err)
		return
	}
	defer s.closeStream(agentID, sessionID)

	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			_, data, readErr := conn.ReadMessage()
			if readErr != nil {
				return
			}
			var control struct {
				Type    string `json:"type"`
				Data    string `json:"data,omitempty"`
				Columns int    `json:"columns,omitempty"`
				Rows    int    `json:"rows,omitempty"`
			}
			if json.Unmarshal(data, &control) == nil {
				switch control.Type {
				case "resize":
					payload, _ := json.Marshal(map[string]any{
						"action": "resize", "columns": control.Columns, "rows": control.Rows,
					})
					if s.broker.PublishStream(r.Context(), agentID, sessionID, "control", payload, 1) != nil {
						return
					}
					continue
				case "input":
					data = []byte(control.Data)
				}
			}
			if s.broker.PublishStream(r.Context(), agentID, sessionID, "in", data, 0) != nil {
				return
			}
		}
	}()

	outputSuffix := "/gateway/streams/" + sessionID + "/out"
	for {
		select {
		case <-done:
			return
		case event, open := <-events:
			if !open {
				return
			}
			if event.AgentID != agentID || !strings.HasSuffix(event.Topic, outputSuffix) {
				continue
			}
			var frame struct {
				DataBase64 string `json:"dataBase64"`
			}
			if json.Unmarshal(event.Payload, &frame) != nil || frame.DataBase64 == "" {
				continue
			}
			data, decodeErr := base64.StdEncoding.DecodeString(frame.DataBase64)
			if decodeErr == nil && conn.WriteMessage(websocket.TextMessage, data) != nil {
				return
			}
		}
	}
}

func (s *Server) forwardStream(conn *websocket.Conn, events <-chan Event, agentID, sessionID, kind string) {
	outputSuffix := "/gateway/streams/" + sessionID + "/out"
	for event := range events {
		if event.AgentID != agentID || !strings.HasSuffix(event.Topic, outputSuffix) {
			continue
		}
		var frame struct {
			Line string `json:"line"`
		}
		if json.Unmarshal(event.Payload, &frame) != nil {
			continue
		}
		if kind == "log" && conn.WriteMessage(websocket.TextMessage, []byte(frame.Line)) != nil {
			return
		}
	}
}

func (s *Server) closeStream(agentID, sessionID string) {
	payload, _ := json.Marshal(map[string]string{"action": "close"})
	_ = s.broker.PublishStream(s.broker.ctx, agentID, sessionID, "control", payload, 1)
}

func (s *Server) writeWSError(conn *websocket.Conn, rpcMessage string, err error) {
	message := rpcMessage
	if err != nil {
		message = err.Error()
	}
	if message == "" {
		message = "stream request failed"
	}
	_ = conn.WriteJSON(map[string]string{"type": "error", "data": message})
}

func streamSessionID(value json.RawMessage) (string, error) {
	var descriptor struct {
		SessionID string `json:"sessionId"`
	}
	if json.Unmarshal(value, &descriptor) != nil || descriptor.SessionID == "" {
		return "", fmt.Errorf("agent returned an invalid stream descriptor")
	}
	return descriptor.SessionID, nil
}

func methodRole(method string) string {
	switch method {
	case "system.health.get", "system.snapshot.get", "config.get", "runtimeConfig.list",
		"service.list", "device.list", "device.get",
		"nodeRed.status.get", "nodeRed.flows.get", "firmware.update.status.get",
		"job.get", "job.list":
		return "viewer"
	case "agent.pause", "agent.resume", "agent.reload", "job.cancel":
		return "operator"
	case "agent.reset":
		return "system-admin"
	case "config.apply", "runtimeConfig.set":
		return "configuration-admin"
	case "service.register", "service.remove":
		return "service-admin"
	case "device.register", "device.remove":
		return "device-admin"
	case "device.markSeen", "device.interface.open", "device.interface.close", "device.interface.read", "device.interface.write":
		return "device-operator"
	case "backup.create", "backup.restore":
		return "backup-admin"
	case "nodeRed.flows.deploy", "nodeRed.action.execute":
		return "node-red-admin"
	case "firmware.update.start", "firmware.update.abort":
		return "firmware-admin"
	case "log.stream.open", "stream.close":
		return "support"
	case "terminal.open":
		return "terminal-admin"
	default:
		return ""
	}
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

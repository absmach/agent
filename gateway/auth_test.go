// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/absmach/agent/pkg/remote"
	"github.com/stretchr/testify/assert"
)

func TestMethodRolesCoverRemoteSurface(t *testing.T) {
	assert.Equal(t, "viewer", methodRole("system.snapshot.get"))
	assert.Equal(t, "device-operator", methodRole("device.interface.write"))
	assert.Equal(t, "firmware-admin", methodRole("firmware.update.start"))
	assert.Equal(t, "terminal-admin", methodRole("terminal.open"))
	assert.Empty(t, methodRole("unknown.method"))
}

func TestHasRole(t *testing.T) {
	assert.True(t, hasRole([]string{"viewer", "support"}, "support"))
	assert.False(t, hasRole([]string{"viewer"}, "support"))
	assert.True(t, hasRole([]string{"*"}, "terminal-admin"))
}

func TestEveryOpenRPCMethodHasAnAuthorizationRole(t *testing.T) {
	for _, method := range remote.SupportedMethods {
		assert.NotEmptyf(t, methodRole(method), "method %q has no authorization role", method)
	}
}

func TestGatewayHTTPAuthorization(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	handler := NewHandler(
		&Broker{agents: map[string]Agent{}},
		map[string][]string{"viewer-token": {"viewer"}},
		logger,
	)

	request := httptest.NewRequest(http.MethodGet, "/api/agents", nil)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	assert.Equal(t, http.StatusUnauthorized, response.Code)

	request = httptest.NewRequest(
		http.MethodPost,
		"/api/agents/edge/rpc",
		strings.NewReader(`{"method":"terminal.open","params":{}}`),
	)
	request.Header.Set("Authorization", "Bearer viewer-token")
	request.Header.Set("Content-Type", "application/json")
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	assert.Equal(t, http.StatusForbidden, response.Code)
}

func TestWebSocketOriginMustMatchHost(t *testing.T) {
	request := httptest.NewRequest(http.MethodGet, "http://agent.example/events", nil)
	request.Host = "agent.example"
	request.Header.Set("Origin", "https://attacker.example")
	assert.False(t, wsUpgrader.CheckOrigin(request))

	request.Header.Set("Origin", "https://agent.example")
	assert.True(t, wsUpgrader.CheckOrigin(request))
}

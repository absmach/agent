// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

package remote_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"testing"

	"github.com/absmach/agent/pkg/remote"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

const requestID = "a10aaea7-66bd-4b88-a6e7-c3852c62cb24"

func TestDecodeRequestProfile(t *testing.T) {
	valid := []byte(`{"jsonrpc":"2.0","id":"` + requestID + `","method":"system.health.get","params":{}}`)
	request, rpcErr := remote.DecodeRequest(valid)
	require.Nil(t, rpcErr)
	assert.Equal(t, requestID, request.ID)
	assert.Equal(t, "system.health.get", request.Method)

	tests := []struct {
		name    string
		payload string
		code    int
	}{
		{name: "empty", payload: "", code: remote.CodeParseError},
		{name: "batch", payload: `[{"jsonrpc":"2.0"}]`, code: remote.CodeInvalidRequest},
		{name: "notification", payload: `{"jsonrpc":"2.0","method":"x"}`, code: remote.CodeInvalidRequest},
		{name: "null id", payload: `{"jsonrpc":"2.0","id":null,"method":"x"}`, code: remote.CodeInvalidRequest},
		{name: "non UUID id", payload: `{"jsonrpc":"2.0","id":"1","method":"x"}`, code: remote.CodeInvalidRequest},
		{name: "unknown field", payload: `{"jsonrpc":"2.0","id":"` + requestID + `","method":"x","extra":1}`, code: remote.CodeParseError},
		{name: "multiple values", payload: `{"jsonrpc":"2.0","id":"` + requestID + `","method":"x"} {}`, code: remote.CodeParseError},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, got := remote.DecodeRequest([]byte(tc.payload))
			require.NotNil(t, got)
			assert.Equal(t, tc.code, got.Code)
		})
	}
}

func TestAsyncAPITwoChannelContract(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "api", "asyncapi.yaml"))
	require.NoError(t, err)
	var document struct {
		AsyncAPI string `yaml:"asyncapi"`
		Channels map[string]struct {
			Address string `yaml:"address"`
		} `yaml:"channels"`
	}
	require.NoError(t, yaml.Unmarshal(raw, &document))
	assert.Equal(t, "3.1.0", document.AsyncAPI)
	assert.Equal(t, "m/{domainId}/c/{controlChannel}/req", document.Channels["rpcRequests"].Address)
	assert.Equal(t, "m/{domainId}/c/{controlChannel}/res/{requesterId}", document.Channels["rpcResponses"].Address)
	assert.Equal(t, "m/{domainId}/c/{dataChannel}/gateway/telemetry", document.Channels["telemetry"].Address)
	assert.Equal(t, "m/{domainId}/c/{dataChannel}/gateway/state/reported", document.Channels["reportedState"].Address)
	assert.Equal(t, "m/{domainId}/c/{dataChannel}/gateway/presence", document.Channels["presence"].Address)
}

func TestCorrelationData(t *testing.T) {
	value, err := remote.CorrelationData(requestID)
	require.NoError(t, err)
	require.Len(t, value, 16)
	assert.True(t, remote.CorrelationMatches(requestID, value))
	value[0] ^= 0xff
	assert.False(t, remote.CorrelationMatches(requestID, value))
}

func TestOpenRPCMatchesExecutor(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "api", "openrpc.json"))
	require.NoError(t, err)
	var document struct {
		OpenRPC string `json:"openrpc"`
		Methods []struct {
			Name string `json:"name"`
		} `json:"methods"`
	}
	require.NoError(t, json.Unmarshal(raw, &document))
	assert.Equal(t, "1.4.0", document.OpenRPC)

	documented := make([]string, 0, len(document.Methods))
	for _, method := range document.Methods {
		documented = append(documented, method.Name)
	}
	implemented := append([]string(nil), remote.SupportedMethods...)
	sort.Strings(documented)
	sort.Strings(implemented)
	assert.Equal(t, implemented, documented)
}

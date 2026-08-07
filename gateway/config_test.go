// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestLoadConfig(t *testing.T) {
	t.Setenv("MG_AGENT_GATEWAY_MQTT_URL", "ssl://broker:8883")
	t.Setenv("MG_AGENT_GATEWAY_MQTT_USERNAME", "gateway")
	t.Setenv("MG_AGENT_GATEWAY_MQTT_PASSWORD", "secret")
	t.Setenv("MG_AGENT_GATEWAY_TOKEN", "browser-token")
	t.Setenv("MG_AGENT_GATEWAY_REQUEST_TIMEOUT", "3s")
	t.Setenv("MG_AGENT_GATEWAY_AGENTS", `[{"id":"a1","domain_id":"d1","control_channel":"c1","data_channel":"d2"}]`)
	cfg, err := LoadConfig()
	require.NoError(t, err)
	require.Equal(t, 3*time.Second, cfg.RequestTTL)
	require.Equal(t, "a1", cfg.Agents[0].ID)
}

func TestLoadConfigRejectsMissingBearerToken(t *testing.T) {
	t.Setenv("MG_AGENT_GATEWAY_MQTT_URL", "tcp://broker:1883")
	t.Setenv("MG_AGENT_GATEWAY_MQTT_USERNAME", "gateway")
	t.Setenv("MG_AGENT_GATEWAY_MQTT_PASSWORD", "secret")
	t.Setenv("MG_AGENT_GATEWAY_AGENTS", `[{"id":"a1","domain_id":"d1","control_channel":"c1","data_channel":"d2"}]`)
	_, err := LoadConfig()
	require.ErrorContains(t, err, "MG_AGENT_GATEWAY_TOKEN")
}

func TestLoadConfigRejectsSameControlAndDataChannel(t *testing.T) {
	t.Setenv("MG_AGENT_GATEWAY_MQTT_URL", "tcp://broker:1883")
	t.Setenv("MG_AGENT_GATEWAY_MQTT_USERNAME", "gateway")
	t.Setenv("MG_AGENT_GATEWAY_MQTT_PASSWORD", "secret")
	t.Setenv("MG_AGENT_GATEWAY_TOKEN", "browser-token")
	t.Setenv("MG_AGENT_GATEWAY_AGENTS", `[{"id":"a1","domain_id":"d1","control_channel":"same","data_channel":"same"}]`)

	_, err := LoadConfig()
	require.ErrorContains(t, err, "must be different")
}

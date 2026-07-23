// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"
)

// Agent identifies the MQTT resources used by one edge agent.
type Agent struct {
	ID             string `json:"id"`
	Name           string `json:"name"`
	DomainID       string `json:"domain_id"`
	ControlChannel string `json:"control_channel"`
	DataChannel    string `json:"data_channel"`
	CommandSecret  string `json:"command_secret,omitempty"`
}

// Config configures the standalone UI gateway.
type Config struct {
	Address       string
	MQTTURL       string
	MQTTUsername  string
	MQTTPassword  string
	MQTTClientID  string
	MQTTSkipTLS   bool
	MQTTCAPath    string
	MQTTCertPath  string
	MQTTKeyPath   string
	BearerToken   string
	AuthTokens    map[string][]string
	RequestTTL    time.Duration
	SessionExpiry time.Duration
	Agents        []Agent
}

// LoadConfig loads gateway settings from environment variables. Agent metadata
// is deliberately separate from MQTT credentials so the gateway can use a
// restricted service identity rather than an edge-agent password.
func LoadConfig() (Config, error) {
	ttl := 15 * time.Second
	if raw := os.Getenv("MG_AGENT_GATEWAY_REQUEST_TIMEOUT"); raw != "" {
		parsed, err := time.ParseDuration(raw)
		if err != nil {
			return Config{}, fmt.Errorf("request timeout: %w", err)
		}
		ttl = parsed
	}
	cfg := Config{
		Address:       envOr("MG_AGENT_GATEWAY_ADDRESS", ":8080"),
		MQTTURL:       os.Getenv("MG_AGENT_GATEWAY_MQTT_URL"),
		MQTTUsername:  os.Getenv("MG_AGENT_GATEWAY_MQTT_USERNAME"),
		MQTTPassword:  os.Getenv("MG_AGENT_GATEWAY_MQTT_PASSWORD"),
		MQTTClientID:  envOr("MG_AGENT_GATEWAY_MQTT_CLIENT_ID", "magistrala-agent-gateway"),
		MQTTSkipTLS:   os.Getenv("MG_AGENT_GATEWAY_MQTT_SKIP_TLS") == "true",
		MQTTCAPath:    os.Getenv("MG_AGENT_GATEWAY_MQTT_CA_PATH"),
		MQTTCertPath:  os.Getenv("MG_AGENT_GATEWAY_MQTT_CERT_PATH"),
		MQTTKeyPath:   os.Getenv("MG_AGENT_GATEWAY_MQTT_KEY_PATH"),
		BearerToken:   os.Getenv("MG_AGENT_GATEWAY_TOKEN"),
		RequestTTL:    ttl,
		SessionExpiry: 24 * time.Hour,
	}
	if cfg.MQTTURL == "" || cfg.MQTTUsername == "" || cfg.MQTTPassword == "" {
		return Config{}, fmt.Errorf("gateway MQTT URL, username and password are required")
	}
	if cfg.BearerToken == "" {
		if os.Getenv("MG_AGENT_GATEWAY_AUTH_TOKENS") == "" {
			return Config{}, fmt.Errorf("MG_AGENT_GATEWAY_TOKEN or MG_AGENT_GATEWAY_AUTH_TOKENS is required")
		}
	}
	cfg.AuthTokens = make(map[string][]string)
	if raw := os.Getenv("MG_AGENT_GATEWAY_AUTH_TOKENS"); raw != "" {
		if err := json.Unmarshal([]byte(raw), &cfg.AuthTokens); err != nil {
			return Config{}, fmt.Errorf("MG_AGENT_GATEWAY_AUTH_TOKENS: %w", err)
		}
	}
	if cfg.BearerToken != "" {
		cfg.AuthTokens[cfg.BearerToken] = []string{"*"}
	}
	for token, roles := range cfg.AuthTokens {
		if token == "" || len(roles) == 0 {
			return Config{}, fmt.Errorf("gateway authorization tokens require a non-empty token and at least one role")
		}
	}
	if raw := os.Getenv("MG_AGENT_GATEWAY_SESSION_EXPIRY"); raw != "" {
		parsed, err := time.ParseDuration(raw)
		if err != nil || parsed <= 0 {
			return Config{}, fmt.Errorf("MG_AGENT_GATEWAY_SESSION_EXPIRY must be a positive duration")
		}
		cfg.SessionExpiry = parsed
	}
	if strings.ContainsAny(cfg.MQTTClientID, "/+#") {
		return Config{}, fmt.Errorf("gateway MQTT client ID cannot contain MQTT topic separators or wildcards")
	}
	if (cfg.MQTTCertPath == "") != (cfg.MQTTKeyPath == "") {
		return Config{}, fmt.Errorf("gateway MQTT certificate and key paths must be configured together")
	}
	if err := json.Unmarshal([]byte(os.Getenv("MG_AGENT_GATEWAY_AGENTS")), &cfg.Agents); err != nil {
		return Config{}, fmt.Errorf("MG_AGENT_GATEWAY_AGENTS: %w", err)
	}
	if len(cfg.Agents) == 0 {
		return Config{}, fmt.Errorf("at least one gateway agent is required")
	}
	for _, a := range cfg.Agents {
		if a.ID == "" || a.DomainID == "" || a.ControlChannel == "" || a.DataChannel == "" {
			return Config{}, fmt.Errorf("agent id, domain_id, control_channel and data_channel are required")
		}
		if a.ControlChannel == a.DataChannel {
			return Config{}, fmt.Errorf("agent %q control and data channels must be different", a.ID)
		}
	}
	return cfg, nil
}

func envOr(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}

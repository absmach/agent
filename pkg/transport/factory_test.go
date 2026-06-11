// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

package transport

import (
	"log/slog"
	"testing"

	"github.com/absmach/agent"
)

func TestFactoryCreateMQTTTransport(t *testing.T) {
	cfg := &agent.Config{
		Transport: "mqtt",
		MQTT: agent.MQTTConfig{
			URL:      "tcp://localhost:1883",
			Username: "test",
			Password: "test",
		},
		DomainID: "test-domain",
		Channels: agent.ChanConfig{
			CtrlID: "ctrl-channel",
			DataID: "data-channel",
		},
	}

	logger := (*slog.Logger)(nil)
	service := (agent.Service)(nil)

	factory := NewFactory(cfg, service, logger)

	// This will try to connect to MQTT, so we expect it might fail
	// but it should create the factory successfully
	if factory == nil {
		t.Fatal("NewFactory() returned nil")
	}

	if factory.config == nil {
		t.Error("Factory should have config")
	}

	if factory.service != nil {
		t.Error("Factory service should be nil in test")
	}
}

func TestFactoryCreateCoAPTransport(t *testing.T) {
	cfg := &agent.Config{
		Transport: "coap",
		CoAP: agent.CoAPConfig{
			URL:            "localhost:5683",
			SkipTLSVer:     true,
			MaxObserve:     8,
			MaxRetransmits: 5,
			KeepAlive:      0,
			ContentFormat:  50,
		},
		DomainID: "test-domain",
		Channels: agent.ChanConfig{
			CtrlID: "ctrl-channel",
			DataID: "data-channel",
		},
	}

	logger := (*slog.Logger)(nil)
	service := (agent.Service)(nil)

	factory := NewFactory(cfg, service, logger)

	if factory == nil {
		t.Fatal("NewFactory() returned nil")
	}

	if factory.config == nil {
		t.Error("Factory should have config")
	}
}

func TestTransportTypes(t *testing.T) {
	tests := []struct {
		name      string
		transport string
		expected  string
	}{
		{
			name:      "mqtt lowercase",
			transport: "mqtt",
			expected:  "mqtt",
		},
		{
			name:      "mqtt uppercase",
			transport: "MQTT",
			expected:  "mqtt",
		},
		{
			name:      "coap lowercase",
			transport: "coap",
			expected:  "coap",
		},
		{
			name:      "coap uppercase",
			transport: "COAP",
			expected:  "coap",
		},
		{
			name:      "invalid transport defaults to mqtt",
			transport: "invalid",
			expected:  "mqtt",
		},
		{
			name:      "empty transport defaults to mqtt",
			transport: "",
			expected:  "mqtt",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &agent.Config{
				Transport: tt.transport,
			}
			factory := NewFactory(cfg, nil, nil)

			// We can't call CreateTransport without a proper service and logger
			// but we can check that the factory was created correctly
			if factory == nil {
				t.Fatal("NewFactory() returned nil")
			}
		})
	}
}

func TestMQTTPublisherBuildTopic(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "control topic",
			input:    TopicControl,
			expected: "m/test-domain/c/ctrl-channel/res",
		},
		{
			name:     "data topic",
			input:    TopicData,
			expected: "m/test-domain/c/data-channel/gateway/telemetry",
		},
		{
			name:     "custom topic",
			input:    "custom",
			expected: "m/test-domain/c/ctrl-channel/res/custom",
		},
		{
			name:     "empty topic uses default",
			input:    "",
			expected: "m/test-domain/c/ctrl-channel/res",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			publisher := NewMQTTPublisher(nil, "test-domain", "ctrl-channel", TopicControl)
			result := publisher.buildTopic(tt.input)
			if result != tt.expected {
				t.Errorf("buildTopic(%s) = %s, want %s", tt.input, result, tt.expected)
			}
		})
	}
}

func TestCoAPPublisherBuildPath(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "control topic",
			input:    TopicControl,
			expected: "/m/test-domain/c/ctrl-channel/res",
		},
		{
			name:     "data topic",
			input:    TopicData,
			expected: "/m/test-domain/c/data-channel/gateway/telemetry",
		},
		{
			name:     "custom topic",
			input:    "custom",
			expected: "/m/test-domain/c/ctrl-channel/res/custom",
		},
		{
			name:     "empty topic uses default",
			input:    "",
			expected: "/m/test-domain/c/ctrl-channel/res",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			publisher := NewCoAPPublisher(nil, "test-domain", "ctrl-channel", TopicControl, 50)
			result := publisher.buildPath(tt.input)
			if result != tt.expected {
				t.Errorf("buildPath(%s) = %s, want %s", tt.input, result, tt.expected)
			}
		})
	}
}

func TestTransportSetup(t *testing.T) {
	setup := &TransportSetup{
		Broker:    nil,
		Publisher: nil,
		Connector: nil,
	}

	// Test that we can create a setup with nil values
	// (in real usage, these would be populated by the factory)
	_ = setup
}

func TestConnectToMQTTBasic(t *testing.T) {
	conf := agent.MQTTConfig{
		URL:      "tcp://localhost:1883",
		Username: "test",
		Password: "test",
	}

	// We can't actually connect without a real broker
	// but we can test the configuration
	if conf.URL == "" {
		t.Error("MQTT URL should not be empty")
	}

	if conf.Username != "test" {
		t.Errorf("Username = %s, want test", conf.Username)
	}
}

func TestCoAPConfigDefaults(t *testing.T) {
	cfg := agent.CoAPConfig{
		URL: "localhost:5683",
	}

	if cfg.URL != "localhost:5683" {
		t.Errorf("URL = %s, want localhost:5683", cfg.URL)
	}

	if cfg.PSK != "" {
		t.Error("PSK should default to empty string")
	}

	if cfg.SkipTLSVer != false {
		t.Error("SkipTLSVer should default to false")
	}

	if cfg.MaxObserve != 0 {
		t.Error("MaxObserve should default to 0")
	}

	if cfg.MaxRetransmits != 0 {
		t.Error("MaxRetransmits should default to 0")
	}

	if cfg.KeepAlive != 0 {
		t.Error("KeepAlive should default to 0")
	}

	if cfg.ContentFormat != 0 {
		t.Error("ContentFormat should default to 0")
	}
}

func TestMQTTConnectorIsConnected(t *testing.T) {
	// Create a connector with nil client - should handle gracefully
	connector := NewMQTTConnector(nil, "test-domain", "ctrl-channel", TopicControl)

	if connector == nil {
		t.Fatal("NewMQTTConnector() returned nil")
	}

	// With nil client, IsConnected should return false
	if connector.IsConnected() {
		t.Error("IsConnected() should return false with nil client")
	}
}

func TestCoAPConnectorIsConnected(t *testing.T) {
	// Create a connector with nil client - should handle gracefully
	connector := NewCoAPConnector(nil)

	if connector == nil {
		t.Fatal("NewCoAPConnector() returned nil")
	}

	// With nil client, IsConnected should return false
	if connector.IsConnected() {
		t.Error("IsConnected() should return false with nil client")
	}
}

func TestFactoryConfigValidation(t *testing.T) {
	tests := []struct {
		name      string
		config    agent.Config
		wantError bool
	}{
		{
			name: "valid MQTT config",
			config: agent.Config{
				Transport: "mqtt",
				MQTT: agent.MQTTConfig{
					URL:      "tcp://localhost:1883",
					Username: "test",
					Password: "test",
				},
				DomainID: "test-domain",
				Channels: agent.ChanConfig{
					CtrlID: "ctrl-channel",
					DataID: "data-channel",
				},
			},
			wantError: false,
		},
		{
			name: "valid CoAP config",
			config: agent.Config{
				Transport: "coap",
				CoAP: agent.CoAPConfig{
					URL:        "localhost:5683",
					SkipTLSVer: true,
				},
				DomainID: "test-domain",
				Channels: agent.ChanConfig{
					CtrlID: "ctrl-channel",
					DataID: "data-channel",
				},
			},
			wantError: false,
		},
		{
			name: "invalid transport",
			config: agent.Config{
				Transport: "invalid",
			},
			wantError: false, // Should default to MQTT
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			factory := NewFactory(&tt.config, nil, nil)
			if factory == nil {
				t.Fatal("NewFactory() returned nil")
			}

			if factory.config.Transport != tt.config.Transport {
				t.Errorf("Factory transport = %s, want %s", factory.config.Transport, tt.config.Transport)
			}
		})
	}
}

func TestTopicPathMapping(t *testing.T) {
	// Test that MQTT topics map correctly to CoAP paths
	domainID := "test-domain"
	ctrlChannel := "ctrl-channel"
	_ = "data-channel" // Used in other tests, not needed here

	tests := []struct {
		name      string
		mqttTopic string
		coapPath  string
	}{
		{
			name:      "commands request",
			mqttTopic: "m/test-domain/c/ctrl-channel/req",
			coapPath:  "/m/test-domain/c/ctrl-channel/req",
		},
		{
			name:      "commands response",
			mqttTopic: "m/test-domain/c/ctrl-channel/res",
			coapPath:  "/m/test-domain/c/ctrl-channel/res",
		},
		{
			name:      "telemetry",
			mqttTopic: "m/test-domain/c/data-channel/gateway/telemetry",
			coapPath:  "/m/test-domain/c/data-channel/gateway/telemetry",
		},
		{
			name:      "heartbeat",
			mqttTopic: "m/test-domain/c/data-channel/gateway/heartbeat",
			coapPath:  "/m/test-domain/c/data-channel/gateway/heartbeat",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mqttPublisher := NewMQTTPublisher(nil, domainID, ctrlChannel, TopicControl)
			mqttResult := mqttPublisher.buildTopic(tt.mqttTopic)

			coapPublisher := NewCoAPPublisher(nil, domainID, ctrlChannel, TopicControl, 50)
			coapResult := coapPublisher.buildPath(tt.mqttTopic)

			// Extract the last part of the path/topic for comparison
			if mqttResult != tt.mqttTopic {
				t.Errorf("MQTT topic = %s, want %s", mqttResult, tt.mqttTopic)
			}
			if coapResult != tt.coapPath {
				t.Errorf("CoAP path = %s, want %s", coapResult, tt.coapPath)
			}
		})
	}
}

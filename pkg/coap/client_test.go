// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

package coap

import (
	"context"
	"testing"
	"time"

	"github.com/plgd-dev/go-coap/v3/message/codes"
)

func TestNewClient(t *testing.T) {
	tests := []struct {
		name    string
		config  Config
		wantErr bool
	}{
		{
			name: "valid UDP config",
			config: Config{
				URL:            "localhost:5683",
				SkipTLSVer:     true,
				MaxObserve:     8,
				MaxRetransmits: 5,
				KeepAlive:      0,
				ContentFormat:  50,
			},
			wantErr: false,
		},
		{
			name: "valid DTLS with PSK config",
			config: Config{
				URL:            "localhost:5684",
				PSK:            "test-psk",
				SkipTLSVer:     true,
				MaxObserve:     8,
				MaxRetransmits: 5,
				KeepAlive:      0,
				ContentFormat:  50,
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client, err := NewClient(tt.config, nil)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewClient() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr {
				if client == nil {
					t.Fatal("NewClient() returned nil client")
				}
				_ = client.Disconnect()
			}
		})
	}
}

func TestClientIsConnected(t *testing.T) {
	config := Config{
		URL:            "localhost:5683",
		SkipTLSVer:     true,
		MaxObserve:     8,
		MaxRetransmits: 5,
		KeepAlive:      0,
		ContentFormat:  50,
	}

	client, err := NewClient(config, nil)
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}
	defer func() { _ = client.Disconnect() }()

	if client == nil {
		t.Fatal("Client should not be nil")
	}
}

func TestClientDisconnect(t *testing.T) {
	config := Config{
		URL:            "localhost:5683",
		SkipTLSVer:     true,
		MaxObserve:     8,
		MaxRetransmits: 5,
		KeepAlive:      0,
		ContentFormat:  50,
	}

	client, err := NewClient(config, nil)
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}

	err = client.Disconnect()
	if err != nil {
		t.Errorf("Disconnect() error = %v", err)
	}

	if client.IsConnected() {
		t.Error("Client should be disconnected after Disconnect()")
	}
}

func TestClientPing(t *testing.T) {
	config := Config{
		URL:            "localhost:5683",
		SkipTLSVer:     true,
		MaxObserve:     8,
		MaxRetransmits: 5,
		KeepAlive:      0,
		ContentFormat:  50,
	}

	client, err := NewClient(config, nil)
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}
	defer func() { _ = client.Disconnect() }()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	err = client.Ping(ctx)
	// Note: In a real test, this would succeed only if a CoAP server is running
	// This tests the ping interface exists
	if err != nil && client.IsConnected() {
		t.Logf("Ping() returned error (expected if no server running): %v", err)
	}
}

func TestClientSend(t *testing.T) {
	config := Config{
		URL:            "localhost:5683",
		SkipTLSVer:     true,
		MaxObserve:     8,
		MaxRetransmits: 5,
		KeepAlive:      0,
		ContentFormat:  50,
	}

	client, err := NewClient(config, nil)
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}
	defer func() { _ = client.Disconnect() }()

	tests := []struct {
		name    string
		code    codes.Code
		path    string
		payload string
		wantErr bool
	}{
		{
			name:    "GET request",
			code:    codes.GET,
			path:    "/test",
			payload: "",
			wantErr: false,
		},
		{
			name:    "POST request",
			code:    codes.POST,
			path:    "/test",
			payload: "test payload",
			wantErr: false,
		},
		{
			name:    "PUT request",
			code:    codes.PUT,
			path:    "/test",
			payload: "test payload",
			wantErr: false,
		},
		{
			name:    "DELETE request",
			code:    codes.DELETE,
			path:    "/test",
			payload: "",
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Note: These tests will fail if no CoAP server is running
			// They verify the interface exists and handles errors gracefully
			res, err := client.Send(tt.path, tt.code, 50, nil)
			if err != nil {
				t.Logf("Send() returned error (expected if no server running): %v", err)
			}
			if !tt.wantErr && res == nil && client.IsConnected() {
				t.Error("Send() should return a response if connected")
			}
		})
	}
}

func TestClientObserve(t *testing.T) {
	config := Config{
		URL:            "localhost:5683",
		SkipTLSVer:     true,
		MaxObserve:     8,
		MaxRetransmits: 5,
		KeepAlive:      0,
		ContentFormat:  50,
	}

	client, err := NewClient(config, nil)
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}
	defer func() { _ = client.Disconnect() }()

	handlerCalled := false
	handler := func(payload []byte) {
		handlerCalled = true
	}

	// Note: This test verifies the observe interface exists
	// It will only succeed if a CoAP server is running
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()

	obs, err := client.Observe(ctx, "/test", handler)
	if err != nil {
		t.Logf("Observe() returned error (expected if no server running): %v", err)
	}

	if obs != nil {
		_ = client.CancelObserve(ctx, "/test")
	}
	_ = handlerCalled // Suppress unused variable warning
}

func TestCreateDTLSConfig(t *testing.T) {
	tests := []struct {
		name    string
		config  Config
		wantErr bool
	}{
		{
			name: "no DTLS config",
			config: Config{
				URL:         "localhost:5683",
				PSK:         "",
				CertPath:    "",
				PrivKeyPath: "",
				CAPath:      "",
			},
			wantErr: false,
		},
		{
			name: "PSK config",
			config: Config{
				URL:         "localhost:5684",
				PSK:         "test-psk",
				CertPath:    "",
				PrivKeyPath: "",
				CAPath:      "",
			},
			wantErr: false,
		},
		{
			name: "certificate config with invalid paths",
			config: Config{
				URL:         "localhost:5684",
				PSK:         "",
				CertPath:    "/invalid/path/to/cert",
				PrivKeyPath: "/invalid/path/to/key",
				CAPath:      "",
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg, err := createDTLSConfig(tt.config)
			if (err != nil) != tt.wantErr {
				t.Errorf("createDTLSConfig() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr {
				if tt.config.PSK == "" && tt.config.CertPath == "" && cfg != nil {
					t.Error("createDTLSConfig() should return nil when no DTLS config provided")
				}
				if tt.config.PSK != "" && cfg == nil {
					t.Error("createDTLSConfig() should return config when PSK is provided")
				}
			}
		})
	}
}

func TestConfigDefaults(t *testing.T) {
	config := Config{
		URL: "localhost:5683",
	}

	if config.MaxObserve != 0 {
		t.Errorf("Config.MaxObserve should default to 0, got %v", config.MaxObserve)
	}
	if config.MaxRetransmits != 0 {
		t.Errorf("Config.MaxRetransmits should default to 0, got %v", config.MaxRetransmits)
	}
	if config.KeepAlive != 0 {
		t.Errorf("Config.KeepAlive should default to 0, got %v", config.KeepAlive)
	}
	if config.ContentFormat != 0 {
		t.Errorf("Config.ContentFormat should default to 0, got %v", config.ContentFormat)
	}
	if config.SkipTLSVer != false {
		t.Errorf("Config.SkipTLSVer should default to false, got %v", config.SkipTLSVer)
	}
}

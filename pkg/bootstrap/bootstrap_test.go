// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/absmach/agent"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestApplyBootstrapResponse(t *testing.T) {
	defaults := agent.NewConfig(
		agent.ServerConfig{Port: "9999"},
		agent.ChanConfig{},
		agent.NodeRedConfig{URL: "http://nodered:1880"},
		agent.LogConfig{Level: "info"},
		agent.MQTTConfig{URL: "ssl://old.example.com:8883", SkipTLSVer: true},
		agent.HeartbeatConfig{Interval: time.Second},
		agent.TerminalConfig{SessionTimeout: time.Minute},
		agent.OTAConfig{},
	)

	cases := []struct {
		desc       string
		config     agent.Config
		response   bootstrapResponse
		domainID   string
		mqttURL    string
		username   string
		password   string
		ctrlID     string
		dataID     string
		clientCert string
		clientKey  string
		caCert     string
		nodeRedURL string
		err        bool
	}{
		{
			desc:   "apply rendered bootstrap content successfully",
			config: defaults,
			response: bootstrapResponse{
				Content: `{
					"device_id": "device-id",
					"external_id": "external-id",
					"domain_id": "domain-id",
					"mqtt": {
						"url": "ssl://mqtt.example.com:8883",
						"client_id": "client-id",
						"secret": "client-secret"
					},
					"telemetry": {
						"channel_id": "data-channel",
						"topic": "data"
					},
					"commands": {
						"channel_id": "ctrl-channel"
					}
				}`,
				ClientKey:  "client-key-pem",
				ClientCert: "client-cert-pem",
				CaCert:     "ca-cert-pem",
			},
			domainID:   "domain-id",
			mqttURL:    "ssl://mqtt.example.com:8883",
			username:   "client-id",
			password:   "client-secret",
			ctrlID:     "ctrl-channel",
			dataID:     "data-channel",
			clientCert: "client-cert-pem",
			clientKey:  "client-key-pem",
			caCert:     "ca-cert-pem",
			nodeRedURL: defaults.NodeRed.URL,
		},
		{
			desc: "apply runtime field names successfully",
			response: bootstrapResponse{
				Content: `{
					"domain_id": "domain-id",
					"mqtt": {
						"url": "ssl://mqtt.example.com:8883",
						"username": "client-id",
						"password": "client-secret"
					},
					"channels": {
						"ctrl_id": "ctrl-channel",
						"data_id": "data-channel"
					}
				}`,
			},
			domainID: "domain-id",
			mqttURL:  "ssl://mqtt.example.com:8883",
			username: "client-id",
			password: "client-secret",
			ctrlID:   "ctrl-channel",
			dataID:   "data-channel",
		},
		{
			desc: "reject missing channels",
			response: bootstrapResponse{
				Content: `{
					"domain_id": "domain-id",
					"mqtt": {
						"client_id": "client-id",
						"secret": "client-secret"
					}
				}`,
			},
			err: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.desc, func(t *testing.T) {
			got, err := applyBootstrapResponse(tc.config, tc.response)
			if tc.err {
				assert.Error(t, err, fmt.Sprintf("%s: expected error", tc.desc))
				return
			}
			assert.Nil(t, err, fmt.Sprintf("%s: unexpected error %v", tc.desc, err))
			assert.Equal(t, tc.domainID, got.DomainID, fmt.Sprintf("%s: unexpected domain id", tc.desc))
			assert.Equal(t, tc.mqttURL, got.MQTT.URL, fmt.Sprintf("%s: unexpected mqtt url", tc.desc))
			assert.Equal(t, tc.username, got.MQTT.Username, fmt.Sprintf("%s: unexpected mqtt username", tc.desc))
			assert.Equal(t, tc.password, got.MQTT.Password, fmt.Sprintf("%s: unexpected mqtt password", tc.desc))
			assert.Equal(t, tc.ctrlID, got.Channels.CtrlChan(), fmt.Sprintf("%s: unexpected control channel", tc.desc))
			assert.Equal(t, tc.dataID, got.Channels.DataChan(), fmt.Sprintf("%s: unexpected data channel", tc.desc))
			assert.Equal(t, tc.clientCert, got.MQTT.ClientCert, fmt.Sprintf("%s: unexpected client cert", tc.desc))
			assert.Equal(t, tc.clientKey, got.MQTT.ClientKey, fmt.Sprintf("%s: unexpected client key", tc.desc))
			assert.Equal(t, tc.caCert, got.MQTT.CaCert, fmt.Sprintf("%s: unexpected ca cert", tc.desc))
			assert.Equal(t, tc.nodeRedURL, got.NodeRed.URL, fmt.Sprintf("%s: unexpected node-red url", tc.desc))
		})
	}
}

func TestBootstrapConfigURL(t *testing.T) {
	cases := []struct {
		desc    string
		baseURL string
		id      string
		url     string
	}{
		{
			desc:    "preserve colon separated bootstrap id",
			baseURL: "http://bootstrap:9013/clients/bootstrap/",
			id:      "/01:6:0:sb:sa",
			url:     "http://bootstrap:9013/clients/bootstrap/01:6:0:sb:sa",
		},
		{
			desc:    "trim all leading slashes from id",
			baseURL: "http://bootstrap:9013/clients/bootstrap//",
			id:      "//client-id",
			url:     "http://bootstrap:9013/clients/bootstrap/client-id",
		},
	}

	for _, tc := range cases {
		t.Run(tc.desc, func(t *testing.T) {
			got := bootstrapConfigURL(tc.baseURL, tc.id)
			assert.Equal(t, tc.url, got, fmt.Sprintf("%s: expected url %s got %s", tc.desc, tc.url, got))
		})
	}
}

func TestLoadFromCache(t *testing.T) {
	cases := []struct {
		desc    string
		setup   func(t *testing.T, path string)
		err     bool
		content string
	}{
		{
			desc: "load valid cache",
			setup: func(t *testing.T, path string) {
				br := bootstrapResponse{
					Content:    `{"device_id":"dev1"}`,
					ClientKey:  "key",
					ClientCert: "cert",
					CaCert:     "ca",
				}
				data, err := json.Marshal(br)
				require.NoError(t, err)
				require.NoError(t, os.WriteFile(path, data, 0o600))
			},
			content: `{"device_id":"dev1"}`,
		},
		{
			desc: "missing file returns error",
			setup: func(t *testing.T, path string) {
			},
			err: true,
		},
		{
			desc: "corrupt json returns error",
			setup: func(t *testing.T, path string) {
				require.NoError(t, os.WriteFile(path, []byte("not json"), 0o600))
			},
			err: true,
		},
		{
			desc: "empty content returns error",
			setup: func(t *testing.T, path string) {
				br := bootstrapResponse{Content: ""}
				data, err := json.Marshal(br)
				require.NoError(t, err)
				require.NoError(t, os.WriteFile(path, data, 0o600))
			},
			err: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.desc, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "bootstrap.json")
			tc.setup(t, path)
			br, err := loadFromCache(path)
			if tc.err {
				assert.Error(t, err)
				return
			}
			assert.NoError(t, err)
			assert.Equal(t, tc.content, br.Content)
		})
	}
}

func TestStoreToCache(t *testing.T) {
	br := bootstrapResponse{
		Content:    `{"device_id":"dev1"}`,
		ClientKey:  "key",
		ClientCert: "cert",
		CaCert:     "ca",
	}

	t.Run("store and reload", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "subdir", "bootstrap.json")
		require.NoError(t, storeToCache(path, br))
		got, err := loadFromCache(path)
		assert.NoError(t, err)
		assert.Equal(t, br.Content, got.Content)
		assert.Equal(t, br.ClientKey, got.ClientKey)
		assert.Equal(t, br.ClientCert, got.ClientCert)
		assert.Equal(t, br.CaCert, got.CaCert)
	})

	t.Run("overwrites existing cache", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "bootstrap.json")
		require.NoError(t, storeToCache(path, bootstrapResponse{Content: `{"old":true}`}))
		require.NoError(t, storeToCache(path, br))
		got, err := loadFromCache(path)
		assert.NoError(t, err)
		assert.Equal(t, br.Content, got.Content)
	})
}

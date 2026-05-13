// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"fmt"
	"testing"
	"time"

	"github.com/absmach/agent"
	"github.com/stretchr/testify/assert"
)

func TestApplyBootstrapResponse(t *testing.T) {
	defaults := agent.NewConfig(
		agent.ServerConfig{Port: "9999", BrokerURL: "amqp://fluxmq:5682"},
		agent.ChanConfig{},
		agent.NodeRedConfig{URL: "http://nodered:1880"},
		agent.LogConfig{Level: "info"},
		agent.MQTTConfig{URL: "ssl://old.example.com:8883", SkipTLSVer: true},
		agent.HeartbeatConfig{Interval: time.Second},
		agent.TerminalConfig{SessionTimeout: time.Minute},
		"config.toml",
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
		channelID  string
		clientCert string
		clientKey  string
		caCert     string
		brokerURL  string
		nodeRedURL string
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
			brokerURL:  defaults.Server.BrokerURL,
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
			desc: "apply shared channel successfully",
			response: bootstrapResponse{
				Content: `{
					"domain_id": "domain-id",
					"mqtt": {
						"client_id": "client-id",
						"secret": "client-secret"
					},
					"channels": {
						"id": "shared-channel"
					}
				}`,
			},
			domainID:  "domain-id",
			username:  "client-id",
			password:  "client-secret",
			ctrlID:    "shared-channel",
			dataID:    "shared-channel",
			channelID: "shared-channel",
		},
	}

	for _, tc := range cases {
		t.Run(tc.desc, func(t *testing.T) {
			got, err := applyBootstrapResponse(tc.config, tc.response)
			assert.Nil(t, err, fmt.Sprintf("%s: unexpected error %v", tc.desc, err))
			if err == nil {
				assert.Equal(t, tc.domainID, got.DomainID, fmt.Sprintf("%s: unexpected domain id", tc.desc))
				assert.Equal(t, tc.mqttURL, got.MQTT.URL, fmt.Sprintf("%s: unexpected mqtt url", tc.desc))
				assert.Equal(t, tc.username, got.MQTT.Username, fmt.Sprintf("%s: unexpected mqtt username", tc.desc))
				assert.Equal(t, tc.password, got.MQTT.Password, fmt.Sprintf("%s: unexpected mqtt password", tc.desc))
				assert.Equal(t, tc.ctrlID, got.Channels.CtrlChan(), fmt.Sprintf("%s: unexpected control channel", tc.desc))
				assert.Equal(t, tc.dataID, got.Channels.DataChan(), fmt.Sprintf("%s: unexpected data channel", tc.desc))
				assert.Equal(t, tc.channelID, got.Channels.ID, fmt.Sprintf("%s: unexpected shared channel", tc.desc))
				assert.Equal(t, tc.clientCert, got.MQTT.ClientCert, fmt.Sprintf("%s: unexpected client cert", tc.desc))
				assert.Equal(t, tc.clientKey, got.MQTT.ClientKey, fmt.Sprintf("%s: unexpected client key", tc.desc))
				assert.Equal(t, tc.caCert, got.MQTT.CaCert, fmt.Sprintf("%s: unexpected ca cert", tc.desc))
				assert.Equal(t, tc.brokerURL, got.Server.BrokerURL, fmt.Sprintf("%s: unexpected broker url", tc.desc))
				assert.Equal(t, tc.nodeRedURL, got.NodeRed.URL, fmt.Sprintf("%s: unexpected node-red url", tc.desc))
			}
		})
	}
}

func TestBackoffDelay(t *testing.T) {
	cases := []struct {
		attempt int
		baseSec uint64
		want    uint64
	}{
		{attempt: 0, baseSec: 10, want: 10},
		{attempt: 1, baseSec: 10, want: 20},
		{attempt: 2, baseSec: 10, want: 40},
		{attempt: 3, baseSec: 10, want: 80},
		{attempt: 4, baseSec: 10, want: 120}, // 160 capped at 120
		{attempt: 5, baseSec: 10, want: 120}, // 320 capped at 120
		{attempt: 6, baseSec: 10, want: 120}, // exponent capped at 5, still 320 → 120
		{attempt: 0, baseSec: 3, want: 3},
		{attempt: 1, baseSec: 3, want: 6},
		{attempt: 2, baseSec: 3, want: 12},
		{attempt: 3, baseSec: 3, want: 24},
		{attempt: 4, baseSec: 3, want: 48},
		{attempt: 5, baseSec: 3, want: 96},
		{attempt: 6, baseSec: 3, want: 96},  // exponent capped at 5, 3×32=96 (below 120 cap)
		{attempt: 5, baseSec: 4, want: 120}, // 4×32=128 capped at 120
		{attempt: 6, baseSec: 4, want: 120}, // exponent capped at 5, same as above
	}

	for _, tc := range cases {
		got := backoffDelay(tc.attempt, tc.baseSec)
		assert.Equal(t, tc.want, got,
			fmt.Sprintf("backoffDelay(attempt=%d, base=%d): want %d got %d",
				tc.attempt, tc.baseSec, tc.want, got))
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

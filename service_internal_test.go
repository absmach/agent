// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"testing"

	"github.com/absmach/agent/pkg/terminal"
	"github.com/stretchr/testify/assert"
)

func TestChangeDir(t *testing.T) {
	tmp := t.TempDir()
	child := filepath.Join(tmp, "child")
	err := os.Mkdir(child, 0o755)
	assert.Nil(t, err, fmt.Sprintf("unexpected mkdir error %v", err))

	cases := []struct {
		desc    string
		workDir string
		cmd     []string
		dir     string
		output  string
	}{
		{
			desc:    "change to absolute directory",
			workDir: "/",
			cmd:     []string{"cd", child},
			dir:     child,
			output:  "(no output)",
		},
		{
			desc:    "change to relative directory",
			workDir: tmp,
			cmd:     []string{"cd", "child"},
			dir:     child,
			output:  "(no output)",
		},
		{
			desc:    "return shell error for missing directory",
			workDir: tmp,
			cmd:     []string{"cd", "missing"},
			dir:     tmp,
			output:  "sh: cd: " + tmp + "/missing: No such file or directory",
		},
	}
	if info, statErr := os.Stat("/root"); statErr == nil && info.IsDir() {
		cases = append(cases, struct {
			desc    string
			workDir string
			cmd     []string
			dir     string
			output  string
		}{
			desc:    "change to default home directory",
			workDir: tmp,
			cmd:     []string{"cd"},
			dir:     "/root",
			output:  "(no output)",
		})
	}

	for _, tc := range cases {
		t.Run(tc.desc, func(t *testing.T) {
			ag := &agent{workDir: tc.workDir}
			got, err := ag.changeDir(tc.cmd)
			assert.Nil(t, err, fmt.Sprintf("%s: unexpected error %v", tc.desc, err))
			assert.Equal(t, tc.output, got, fmt.Sprintf("%s: unexpected output", tc.desc))
			assert.Equal(t, tc.dir, ag.workDir, fmt.Sprintf("%s: unexpected workdir", tc.desc))
		})
	}
}

func TestNormalizeNodeRedFlow(t *testing.T) {
	ag := &agent{
		config: &Config{
			DomainID: "domain-id",
			Channels: ChanConfig{
				DataID: "data-channel",
			},
			MQTT: MQTTConfig{
				URL:        "ssl://mqtt.example.com:8883",
				Username:   "client-id",
				Password:   "client-secret",
				SkipTLSVer: true,
			},
		},
	}

	cases := []struct {
		desc string
		flow string
		same bool
	}{
		{
			desc: "return invalid json unchanged",
			flow: "{",
			same: true,
		},
		{
			desc: "normalize mqtt settings and topics",
			flow: `[
				{"id":"tab","type":"tab","label":"flow"},
				{"id":"broker-a","type":"mqtt-broker","broker":"old","port":"1883","tls":"old"},
				{"id":"fn","type":"function","func":"msg.topic = \"m/old-domain/c/old-channel/data\";"},
				{"id":"out","type":"mqtt out","broker":"missing","topic":"m/old-domain/c/old-channel/msg"}
			]`,
		},
	}

	for _, tc := range cases {
		t.Run(tc.desc, func(t *testing.T) {
			got := ag.normalizeNodeRedFlow(tc.flow)
			if tc.same {
				assert.Equal(t, tc.flow, got, fmt.Sprintf("%s: expected unchanged flow", tc.desc))
				return
			}

			var nodes []map[string]any
			err := json.Unmarshal([]byte(got), &nodes)
			assert.Nil(t, err, fmt.Sprintf("%s: unexpected json error %v", tc.desc, err))

			byID := map[string]map[string]any{}
			for _, node := range nodes {
				id, _ := node["id"].(string)
				byID[id] = node
			}

			broker := byID["broker-a"]
			assert.Equal(t, "mqtt.example.com", broker["broker"], fmt.Sprintf("%s: unexpected mqtt host", tc.desc))
			assert.Equal(t, "8883", broker["port"], fmt.Sprintf("%s: unexpected mqtt port", tc.desc))
			assert.Equal(t, "client-id-nr", broker["clientid"], fmt.Sprintf("%s: unexpected node-red client id", tc.desc))
			assert.Equal(t, true, broker["usetls"], fmt.Sprintf("%s: unexpected tls flag", tc.desc))
			assert.Equal(t, nodeRedTLSConfigID, broker["tls"], fmt.Sprintf("%s: unexpected tls config id", tc.desc))
			assert.Equal(t, map[string]any{"user": "client-id", "password": "client-secret"}, broker["credentials"], fmt.Sprintf("%s: unexpected credentials", tc.desc))
			assert.Equal(t, `msg.topic = "m/domain-id/c/data-channel/msg";`, byID["fn"]["func"], fmt.Sprintf("%s: unexpected function topic", tc.desc))
			assert.Equal(t, "broker-a", byID["out"]["broker"], fmt.Sprintf("%s: unexpected mqtt out broker", tc.desc))
			assert.Equal(t, "m/domain-id/c/data-channel/msg", byID["out"]["topic"], fmt.Sprintf("%s: unexpected mqtt out topic", tc.desc))
			assert.Contains(t, byID, nodeRedTLSConfigID, fmt.Sprintf("%s: expected tls config node", tc.desc))
		})
	}
}

func TestNodeRedMQTTEndpoint(t *testing.T) {
	cases := []struct {
		desc   string
		rawURL string
		host   string
		port   string
		tls    bool
	}{
		{
			desc: "default empty endpoint",
			port: "1883",
		},
		{
			desc:   "parse ssl endpoint",
			rawURL: "ssl://mqtt.example.com:8883",
			host:   "mqtt.example.com",
			port:   "8883",
			tls:    true,
		},
		{
			desc:   "default mqtts port",
			rawURL: "mqtts://mqtt.example.com",
			host:   "mqtt.example.com",
			port:   "1883",
			tls:    true,
		},
		{
			desc:   "parse host port without scheme",
			rawURL: "mqtt.example.com:1884",
			host:   "mqtt.example.com",
			port:   "1884",
		},
		{
			desc:   "strip path from malformed scheme",
			rawURL: "://mqtt.example.com:1885/path",
			host:   "mqtt.example.com",
			port:   "1885",
		},
	}

	for _, tc := range cases {
		t.Run(tc.desc, func(t *testing.T) {
			host, port, useTLS := nodeRedMQTTEndpoint(tc.rawURL)
			assert.Equal(t, tc.host, host, fmt.Sprintf("%s: unexpected host", tc.desc))
			assert.Equal(t, tc.port, port, fmt.Sprintf("%s: unexpected port", tc.desc))
			assert.Equal(t, tc.tls, useTLS, fmt.Sprintf("%s: unexpected tls flag", tc.desc))
		})
	}
}

func TestPatchNodeRedTopic(t *testing.T) {
	cases := []struct {
		desc     string
		input    string
		domainID string
		channel  string
		want     string
	}{
		{
			desc:     "legacy data topic",
			input:    `msg.topic = "m/old-domain/c/old-channel/data";`,
			domainID: "domain-id",
			channel:  "channel-id",
			want:     `msg.topic = "m/domain-id/c/channel-id/msg";`,
		},
		{
			desc:     "message topic",
			input:    `msg.topic = "m/old-domain/c/old-channel/msg";`,
			domainID: "domain-id",
			channel:  "channel-id",
			want:     `msg.topic = "m/domain-id/c/channel-id/msg";`,
		},
		{
			desc:  "leave topic unchanged without ids",
			input: `msg.topic = "m/old-domain/c/old-channel/msg";`,
			want:  `msg.topic = "m/old-domain/c/old-channel/msg";`,
		},
	}

	for _, tc := range cases {
		t.Run(tc.desc, func(t *testing.T) {
			got := patchNodeRedTopic(tc.input, tc.domainID, tc.channel)
			assert.Equal(t, tc.want, got, fmt.Sprintf("%s: expected content %s got %s", tc.desc, tc.want, got))
		})
	}
}

func TestEnsureNodeRedTLSConfig(t *testing.T) {
	cases := []struct {
		desc string
		in   any
		len  int
	}{
		{
			desc: "append tls config to flow array",
			in:   []any{map[string]any{"id": "broker"}},
			len:  2,
		},
		{
			desc: "keep existing tls config in flow array",
			in:   []any{map[string]any{"id": nodeRedTLSConfigID}},
			len:  1,
		},
		{
			desc: "append tls config to flow object",
			in:   map[string]any{},
			len:  1,
		},
		{
			desc: "keep existing tls config in flow object",
			in:   map[string]any{"configs": []any{map[string]any{"id": nodeRedTLSConfigID}}},
			len:  1,
		},
	}

	for _, tc := range cases {
		t.Run(tc.desc, func(t *testing.T) {
			got := ensureNodeRedTLSConfig(tc.in)
			switch typed := got.(type) {
			case []any:
				assert.Len(t, typed, tc.len, fmt.Sprintf("%s: unexpected array length", tc.desc))
			case map[string]any:
				assert.Len(t, typed["configs"], tc.len, fmt.Sprintf("%s: unexpected config length", tc.desc))
			}
		})
	}

	t.Run("ignore unsupported payload", func(t *testing.T) {
		got := ensureNodeRedTLSConfig("flow")
		assert.Equal(t, "flow", got, "expected unsupported payload to be unchanged")
	})
}

func TestTerminalCloseExistingSession(t *testing.T) {
	ag := &agent{
		logger:    slog.New(slog.NewTextHandler(io.Discard, nil)),
		terminals: map[string]terminal.Session{"uuid": nil},
	}

	cmd := base64.StdEncoding.EncodeToString([]byte(close))
	err := ag.Terminal("uuid", cmd)
	assert.Nil(t, err, fmt.Sprintf("unexpected terminal close error %v", err))
	assert.Empty(t, ag.terminals, "expected terminal to be removed")
}

func TestGetTopic(t *testing.T) {
	ag := &agent{
		config: &Config{
			DomainID: "domain-id",
			Channels: ChanConfig{
				CtrlID: "ctrl-channel",
				DataID: "data-channel",
			},
		},
	}

	cases := []struct {
		desc  string
		topic string
		want  string
	}{
		{
			desc:  "control response",
			topic: control,
			want:  "m/domain-id/c/ctrl-channel/res",
		},
		{
			desc:  "data message",
			topic: data,
			want:  "m/domain-id/c/data-channel/msg",
		},
		{
			desc:  "named response",
			topic: "exec",
			want:  "m/domain-id/c/ctrl-channel/res/exec",
		},
	}

	for _, tc := range cases {
		t.Run(tc.desc, func(t *testing.T) {
			got := ag.getTopic(tc.topic)
			assert.Equal(t, tc.want, got, fmt.Sprintf("%s: expected topic %s got %s", tc.desc, tc.want, got))
		})
	}
}

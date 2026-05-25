// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

package agent_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/absmach/agent"
	agentmocks "github.com/absmach/agent/mocks"
	cfgstore "github.com/absmach/agent/pkg/config"
	"github.com/absmach/agent/pkg/devicemgr"
	"github.com/absmach/agent/pkg/iface"
	nrmocks "github.com/absmach/agent/pkg/nodered/mocks"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

var domainID = "1e7295a6-8de9-4c3c-8e36-387217f131f6"

func mqttTopic(channel, suffix string) string {
	return fmt.Sprintf("m/%s/c/%s/%s", domainID, channel, suffix)
}

func testConfig() agent.Config {
	return agent.NewConfig(
		agent.ServerConfig{Port: "9000"},
		agent.ChanConfig{CtrlID: "ctrl-channel", DataID: "data-channel"},
		agent.NodeRedConfig{URL: "http://nodered:1880/"},
		agent.LogConfig{Level: "debug"},
		agent.MQTTConfig{
			URL:        "ssl://mqtt.example.com:8883",
			Username:   "client-id",
			Password:   "client-secret",
			SkipTLSVer: true,
			Retain:     true,
			QoS:        1,
		},
		agent.HeartbeatConfig{Interval: time.Hour},
		agent.TerminalConfig{SessionTimeout: time.Minute},
		agent.OTAConfig{Enabled: false, BinaryPath: "/usr/local/bin/agent", DownloadDir: "/tmp"},
	)
}

func newServiceWithStore(t *testing.T, cfg agent.Config, store cfgstore.Store) (agent.Service, *agentmocks.MQTTClient, *nrmocks.Client, error) {
	cfg.DomainID = domainID
	mqttClient := agentmocks.NewMQTTClient(t)
	nodeRed := nrmocks.NewClient(t)

	hbToken := agentmocks.NewMQTTToken(t)
	hbToken.On("Wait").Maybe().Return(true)
	hbToken.On("Error").Maybe().Return(error(nil))
	mqttClient.On("Publish", mqttTopic("data-channel", "gateway/heartbeat"),
		mock.Anything, mock.Anything, mock.Anything).Maybe().Return(hbToken)

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	svc, err := agent.New(ctx, mqttClient, &cfg, nodeRed, slog.New(slog.NewTextHandler(io.Discard, nil)), nil, store, nil)
	return svc, mqttClient, nodeRed, err
}

func newService(t *testing.T, cfg agent.Config, devices ...*devicemgr.Manager) (agent.Service, *agentmocks.MQTTClient, *nrmocks.Client, error) {
	t.Helper()
	cfg.DomainID = domainID
	mqttClient := agentmocks.NewMQTTClient(t)
	nodeRed := nrmocks.NewClient(t)

	// selfHeartbeat publishes immediately on startup and then on each ticker
	// interval. Register an optional expectation so any test that doesn't
	// explicitly expect the heartbeat publish won't panic.
	hbToken := agentmocks.NewMQTTToken(t)
	hbToken.On("Wait").Maybe().Return(true)
	hbToken.On("Error").Maybe().Return(error(nil))
	mqttClient.On("Publish", mqttTopic("data-channel", "gateway/heartbeat"),
		mock.Anything, mock.Anything, mock.Anything).Maybe().Return(hbToken)

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	var mgr *devicemgr.Manager
	if len(devices) > 0 {
		mgr = devices[0]
	}

	svc, err := agent.New(ctx, mqttClient, &cfg, nodeRed, slog.New(slog.NewTextHandler(io.Discard, nil)), mgr, nil, nil)
	return svc, mqttClient, nodeRed, err
}

func expectMQTTPublish(t *testing.T, mqttClient *agentmocks.MQTTClient, topic string, err error) *mock.Call {
	token := agentmocks.NewMQTTToken(t)
	token.On("Wait").Return(true).Once()
	token.On("Error").Return(err).Once()
	return mqttClient.On("Publish", topic, byte(1), true, mock.Anything).Return(token).Once()
}

func TestChannelConfig(t *testing.T) {
	cases := []struct {
		desc string
		cfg  agent.ChanConfig
		ctrl string
		data string
	}{
		{
			desc: "use split channels",
			cfg:  agent.ChanConfig{CtrlID: "ctrl-channel", DataID: "data-channel"},
			ctrl: "ctrl-channel",
			data: "data-channel",
		},
	}

	for _, tc := range cases {
		t.Run(tc.desc, func(t *testing.T) {
			assert.Equal(t, tc.ctrl, tc.cfg.CtrlChan())
			assert.Equal(t, tc.data, tc.cfg.DataChan())
		})
	}
}

func TestDurationConfigUnmarshalJSON(t *testing.T) {
	cases := []struct {
		desc      string
		body      string
		heartbeat time.Duration
		terminal  time.Duration
		err       bool
	}{
		{
			desc:      "parse string durations",
			body:      `{"heartbeat":{"interval":"2s"},"terminal":{"session_timeout":"3s"}}`,
			heartbeat: 2 * time.Second,
			terminal:  3 * time.Second,
		},
		{
			desc:      "parse numeric durations",
			body:      `{"heartbeat":{"interval":5000000000},"terminal":{"session_timeout":7000000000}}`,
			heartbeat: 5 * time.Second,
			terminal:  7 * time.Second,
		},
		{
			desc: "reject missing heartbeat duration",
			body: `{"heartbeat":{},"terminal":{"session_timeout":"3s"}}`,
			err:  true,
		},
		{
			desc: "reject invalid heartbeat duration",
			body: `{"heartbeat":{"interval":"soon"},"terminal":{"session_timeout":"3s"}}`,
			err:  true,
		},
		{
			desc: "reject invalid heartbeat type",
			body: `{"heartbeat":{"interval":true},"terminal":{"session_timeout":"3s"}}`,
			err:  true,
		},
		{
			desc: "reject missing terminal duration",
			body: `{"heartbeat":{"interval":"2s"},"terminal":{}}`,
			err:  true,
		},
		{
			desc: "reject invalid terminal duration",
			body: `{"heartbeat":{"interval":"2s"},"terminal":{"session_timeout":true}}`,
			err:  true,
		},
		{
			desc: "reject malformed json",
			body: `{"heartbeat":`,
			err:  true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.desc, func(t *testing.T) {
			var cfg agent.Config
			err := json.Unmarshal([]byte(tc.body), &cfg)
			if tc.err {
				assert.Error(t, err)
				return
			}
			assert.NoError(t, err)
			assert.Equal(t, tc.heartbeat, cfg.Heartbeat.Interval)
			assert.Equal(t, tc.terminal, cfg.Terminal.SessionTimeout)
		})
	}
}

func TestHeartbeat(t *testing.T) {
	h := agent.NewHeartbeat("nodered", "service", time.Hour)
	info := h.Info()
	assert.Equal(t, "nodered", info.Name, "unexpected heartbeat service name")
	assert.Equal(t, "service", info.Type, "unexpected heartbeat service type")
	assert.Equal(t, "online", info.Status, "unexpected initial heartbeat status")

	h.Update()
	assert.Equal(t, "online", h.Info().Status, "unexpected heartbeat status after update")

	expiring := agent.NewHeartbeat("nodered", "service", time.Millisecond)
	assert.Eventually(t, func() bool {
		return expiring.Info().Status == "offline"
	}, 100*time.Millisecond, time.Millisecond, "expected heartbeat to expire")
}

func TestNew(t *testing.T) {
	svc, _, _, err := newService(t, testConfig())
	assert.NoError(t, err)
	assert.NotNil(t, svc)
}

func TestExecute(t *testing.T) {
	tmp := t.TempDir()
	errBoom := fmt.Errorf("boom")

	cases := []struct {
		desc   string
		cmd    string
		output string
		err    bool
		topic  string
		pubErr error
	}{
		{
			desc:   "reject empty command",
			cmd:    "",
			err:    true,
			output: "",
		},
		{
			desc:   "execute shell command successfully",
			cmd:    "printf,hello",
			output: "hello",
			topic:  mqttTopic("ctrl-channel", "res"),
		},
		{
			desc:   "execute command with no output successfully",
			cmd:    "true",
			output: "(no output)",
			topic:  mqttTopic("ctrl-channel", "res"),
		},
		{
			desc:   "execute cd command successfully",
			cmd:    "cd," + tmp,
			output: "(no output)",
		},
		{
			desc: "return execution error",
			cmd:  "false",
			err:  true,
		},
		{
			desc:   "return publish error",
			cmd:    "true",
			err:    true,
			topic:  mqttTopic("ctrl-channel", "res"),
			pubErr: errBoom,
		},
	}

	for _, tc := range cases {
		t.Run(tc.desc, func(t *testing.T) {
			svc, mqttClient, _, err := newService(t, testConfig())
			require.NoError(t, err)
			var payload any
			if tc.topic != "" {
				expectMQTTPublish(t, mqttClient, tc.topic, tc.pubErr).Run(func(args mock.Arguments) {
					payload = args.Get(3)
				})
			}
			got, err := svc.Execute("uuid", tc.cmd)
			if tc.err {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
			assert.Equal(t, tc.output, got)
			if tc.topic != "" && tc.pubErr == nil {
				assert.NotEmpty(t, payload)
			}
		})
	}
}

func TestControl(t *testing.T) {
	errBoom := fmt.Errorf("boom")

	cases := []struct {
		desc   string
		cmd    string
		err    bool
		mockFn func(t *testing.T, mqttClient *agentmocks.MQTTClient, nodeRed *nrmocks.Client)
	}{
		{
			desc: "reject empty command",
			cmd:  "",
			err:  true,
		},
		{
			desc: "reject unknown command",
			cmd:  "reboot",
			err:  true,
		},
		{
			desc: "run node-red command successfully",
			cmd:  "nodered-ping",
			mockFn: func(t *testing.T, mqttClient *agentmocks.MQTTClient, nodeRed *nrmocks.Client) {
				nodeRed.On("Ping").Return("pong", nil).Once()
				expectMQTTPublish(t, mqttClient, mqttTopic("ctrl-channel", "res"), nil)
			},
		},
		{
			desc: "return node-red error",
			cmd:  "nodered-ping",
			err:  true,
			mockFn: func(_ *testing.T, _ *agentmocks.MQTTClient, nodeRed *nrmocks.Client) {
				nodeRed.On("Ping").Return("pong", errBoom).Once()
			},
		},
		{
			desc: "return response publish error",
			cmd:  "nodered-ping",
			err:  true,
			mockFn: func(t *testing.T, mqttClient *agentmocks.MQTTClient, nodeRed *nrmocks.Client) {
				nodeRed.On("Ping").Return("pong", nil).Once()
				expectMQTTPublish(t, mqttClient, mqttTopic("ctrl-channel", "res"), errBoom)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.desc, func(t *testing.T) {
			svc, mqttClient, nodeRed, err := newService(t, testConfig())
			require.NoError(t, err)
			if tc.mockFn != nil {
				tc.mockFn(t, mqttClient, nodeRed)
			}
			err = svc.Control("uuid", tc.cmd)
			if tc.err {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestServiceConfig(t *testing.T) {
	tmp := t.TempDir()
	exportFile := filepath.Join(tmp, "export.toml")
	exportContent := base64.StdEncoding.EncodeToString([]byte(`{"enabled":true}`))
	malformedContent := base64.StdEncoding.EncodeToString([]byte("="))
	errBoom := fmt.Errorf("boom")

	cases := []struct {
		desc        string
		cmd         string
		err         bool
		registerSvc bool
		file        string
		pubErr      error
	}{
		{
			desc:        "view services successfully",
			cmd:         "view",
			registerSvc: true,
		},
		{
			desc:        "return view response publish error",
			cmd:         "view",
			err:         true,
			registerSvc: true,
			pubErr:      errBoom,
		},
		{
			desc: "return error for unknown config command",
			cmd:  "noop",
			err:  true,
		},
		{
			desc: "reject malformed save command",
			cmd:  "save,export,file",
			err:  true,
		},
		{
			desc: "save export config successfully",
			cmd:  "save,export," + exportFile + "," + exportContent,
			file: exportFile,
		},
		{
			desc: "return save config error",
			cmd:  "save,export," + filepath.Join(tmp, "bad.toml") + ",%%%bad",
			err:  true,
		},
		{
			desc: "return unknown service error",
			cmd:  "save,unknown," + filepath.Join(tmp, "unknown.toml") + "," + exportContent,
			err:  true,
		},
		{
			desc: "return malformed export content error",
			cmd:  "save,export," + filepath.Join(tmp, "bad-content.toml") + "," + malformedContent,
			err:  true,
		},
		{
			desc: "return export write error",
			cmd:  "save,export," + tmp + "," + exportContent,
			err:  true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.desc, func(t *testing.T) {
			svc, mqttClient, _, err := newService(t, testConfig())
			require.NoError(t, err)
			if tc.registerSvc {
				require.NoError(t, svc.UpdateLiveness("nodered", "service"))
			}
			if !tc.err || tc.pubErr != nil {
				expectMQTTPublish(t, mqttClient, mqttTopic("ctrl-channel", "res"), tc.pubErr)
			}
			err = svc.ServiceConfig(context.Background(), "uuid", tc.cmd)
			if tc.err {
				assert.Error(t, err)
				return
			}
			assert.NoError(t, err)
			if tc.file != "" {
				assert.FileExists(t, tc.file)
			}
		})
	}
}

func TestConfigGetSet(t *testing.T) {
	cases := []struct {
		desc     string
		cmd      string
		useStore bool
		seed     map[string]string
		wantResp string
		err      bool
	}{
		{
			desc:     "get key without store returns not_configured",
			cmd:      "get,log_level",
			useStore: false,
			wantResp: "not_configured",
		},
		{
			desc:     "get missing key returns not_found",
			cmd:      "get,log_level",
			useStore: true,
			wantResp: "not_found",
		},
		{
			desc:     "set key without store returns not_configured",
			cmd:      "set,log_level,debug",
			useStore: false,
			wantResp: "not_configured",
		},
		{
			desc:     "set key persists and returns ok",
			cmd:      "set,log_level,debug",
			useStore: true,
			wantResp: "ok",
		},
		{
			desc:     "get key after set returns previously set value",
			cmd:      "get,log_level",
			useStore: true,
			seed:     map[string]string{"log_level": "debug"},
			wantResp: "debug",
		},
		{
			desc:     "set heartbeat_interval stores valid duration",
			cmd:      "set,heartbeat_interval,30s",
			useStore: true,
			wantResp: "ok",
		},
		{
			desc:     "reject set with invalid duration",
			cmd:      "set,heartbeat_interval,not-a-duration",
			useStore: true,
			err:      true,
		},
		{
			desc:     "reject set with invalid log level",
			cmd:      "set,log_level,BOGUS",
			useStore: true,
			err:      true,
		},
		{
			desc:     "reject set with heartbeat interval below minimum",
			cmd:      "set,heartbeat_interval,500ms",
			useStore: true,
			err:      true,
		},
		{
			desc:     "reject get without key",
			cmd:      "get",
			useStore: true,
			err:      true,
		},
		{
			desc:     "reject get with empty key",
			cmd:      "get,",
			useStore: true,
			err:      true,
		},
		{
			desc:     "reject get with unknown key",
			cmd:      "get,mqtt_password",
			useStore: true,
			err:      true,
		},
		{
			desc:     "reject set without value",
			cmd:      "set,log_level",
			useStore: true,
			err:      true,
		},
		{
			desc:     "reject set with unknown key",
			cmd:      "set,mqtt_password,secret",
			useStore: true,
			err:      true,
		},
		{
			desc:     "reset key without store returns not_configured",
			cmd:      "reset,log_level",
			useStore: false,
			wantResp: "not_configured",
		},
		{
			desc:     "reset existing key returns ok",
			cmd:      "reset,log_level",
			useStore: true,
			seed:     map[string]string{"log_level": "debug"},
			wantResp: "ok",
		},
		{
			desc:     "reset missing key is no-op and returns ok",
			cmd:      "reset,log_level",
			useStore: true,
			wantResp: "ok",
		},
		{
			desc:     "reject reset without key",
			cmd:      "reset",
			useStore: true,
			err:      true,
		},
		{
			desc:     "reject reset with unknown key",
			cmd:      "reset,mqtt_password",
			useStore: true,
			err:      true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.desc, func(t *testing.T) {
			var s cfgstore.Store
			if tc.useStore {
				var storeErr error
				s, storeErr = cfgstore.NewStore(filepath.Join(t.TempDir(), "config.json"))
				assert.Nil(t, storeErr, fmt.Sprintf("%s: unexpected store error %v", tc.desc, storeErr))
				for k, v := range tc.seed {
					require.NoError(t, s.Set(k, v))
				}
			}
			svc, mqttClient, _, setupErr := newServiceWithStore(t, testConfig(), s)
			assert.Nil(t, setupErr, fmt.Sprintf("%s: unexpected setup error %v", tc.desc, setupErr))

			if !tc.err {
				expectMQTTPublish(t, mqttClient, mqttTopic("ctrl-channel", "res"), nil).Run(func(args mock.Arguments) {
					payload, _ := args.Get(3).(string)
					assert.Contains(t, payload, tc.wantResp, fmt.Sprintf("%s: unexpected response payload", tc.desc))
				})
			}

			err := svc.ServiceConfig(context.Background(), "uuid", tc.cmd)
			if tc.err {
				assert.Error(t, err, fmt.Sprintf("%s: expected error", tc.desc))
			} else {
				assert.Nil(t, err, fmt.Sprintf("%s: unexpected error %v", tc.desc, err))
			}
		})
	}
}

func TestApplyConfigEntry(t *testing.T) {
	cases := []struct {
		desc  string
		key   string
		val   string
		check func(t *testing.T, cfg agent.Config)
	}{
		{
			desc: "set log level",
			key:  "log_level",
			val:  "warn",
			check: func(t *testing.T, cfg agent.Config) {
				assert.Equal(t, "warn", cfg.Log.Level)
			},
		},
		{
			desc: "set heartbeat interval",
			key:  "heartbeat_interval",
			val:  "30s",
			check: func(t *testing.T, cfg agent.Config) {
				assert.Equal(t, 30*time.Second, cfg.Heartbeat.Interval)
			},
		},
		{
			desc: "set terminal session timeout",
			key:  "terminal_session_timeout",
			val:  "2m",
			check: func(t *testing.T, cfg agent.Config) {
				assert.Equal(t, 2*time.Minute, cfg.Terminal.SessionTimeout)
			},
		},
		{
			desc: "invalid duration is ignored",
			key:  "heartbeat_interval",
			val:  "not-a-duration",
			check: func(t *testing.T, cfg agent.Config) {
				assert.Equal(t, time.Hour, cfg.Heartbeat.Interval)
			},
		},
		{
			desc: "zero duration is ignored",
			key:  "heartbeat_interval",
			val:  "0s",
			check: func(t *testing.T, cfg agent.Config) {
				assert.Equal(t, time.Hour, cfg.Heartbeat.Interval)
			},
		},
		{
			desc: "negative duration is ignored",
			key:  "heartbeat_interval",
			val:  "-5s",
			check: func(t *testing.T, cfg agent.Config) {
				assert.Equal(t, time.Hour, cfg.Heartbeat.Interval)
			},
		},
		{
			desc: "unknown key is a no-op",
			key:  "mqtt_password",
			val:  "secret",
			check: func(t *testing.T, cfg agent.Config) {
				assert.Equal(t, "client-secret", cfg.MQTT.Password)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.desc, func(t *testing.T) {
			cfg := testConfig()
			agent.ApplyConfigEntryForTest(&cfg, tc.key, tc.val)
			tc.check(t, cfg)
		})
	}
}

func TestTerminal(t *testing.T) {
	cases := []struct {
		desc      string
		cmd       string
		err       bool
		emptyPath bool
	}{
		{
			desc: "reject malformed base64",
			cmd:  "%%%bad",
			err:  true,
		},
		{
			desc: "return missing terminal session on close",
			cmd:  base64.StdEncoding.EncodeToString([]byte("close")),
			err:  true,
		},
		{
			desc: "ignore unknown terminal command",
			cmd:  base64.StdEncoding.EncodeToString([]byte("noop")),
		},
		{
			desc:      "return terminal open error",
			cmd:       base64.StdEncoding.EncodeToString([]byte("open")),
			err:       true,
			emptyPath: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.desc, func(t *testing.T) {
			if tc.emptyPath {
				t.Setenv("PATH", "")
			}
			svc, _, _, err := newService(t, testConfig())
			require.NoError(t, err)
			err = svc.Terminal("uuid", tc.cmd)
			if tc.err {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestNodeRed(t *testing.T) {
	flow := base64.StdEncoding.EncodeToString([]byte(`[{"id":"broker","type":"mqtt-broker"}]`))
	errBoom := fmt.Errorf("boom")
	normalizedFlow := mock.MatchedBy(func(f string) bool {
		return strings.Contains(f, "mqtt.example.com") &&
			strings.Contains(f, "client-id-nr") &&
			strings.Contains(f, "magistrala-agent-tls")
	})

	cases := []struct {
		desc   string
		cmd    string
		resp   string
		err    bool
		mockFn func(nodeRed *nrmocks.Client)
	}{
		{
			desc: "deploy flows successfully",
			cmd:  "nodered-deploy," + flow,
			resp: "deployed",
			mockFn: func(nodeRed *nrmocks.Client) {
				nodeRed.On("DeployFlows", normalizedFlow).Return("deployed", nil).Once()
			},
		},
		{
			desc: "add flow successfully",
			cmd:  "nodered-add-flow," + flow,
			resp: "added",
			mockFn: func(nodeRed *nrmocks.Client) {
				nodeRed.On("AddFlow", normalizedFlow).Return("added", nil).Once()
			},
		},
		{
			desc: "fetch flows successfully",
			cmd:  "nodered-flows",
			resp: "flows",
			mockFn: func(nodeRed *nrmocks.Client) {
				nodeRed.On("FetchFlows").Return("flows", nil).Once()
			},
		},
		{
			desc: "fetch state successfully",
			cmd:  "nodered-state",
			resp: "started",
			mockFn: func(nodeRed *nrmocks.Client) {
				nodeRed.On("FlowState").Return("started", nil).Once()
			},
		},
		{
			desc: "ping successfully",
			cmd:  "nodered-ping",
			resp: "pong",
			mockFn: func(nodeRed *nrmocks.Client) {
				nodeRed.On("Ping").Return("pong", nil).Once()
			},
		},
		{
			desc: "reject empty command",
			cmd:  "",
			err:  true,
		},
		{
			desc: "reject deploy without flow",
			cmd:  "nodered-deploy",
			err:  true,
		},
		{
			desc: "reject add flow without flow",
			cmd:  "nodered-add-flow",
			err:  true,
		},
		{
			desc: "wrap invalid deploy base64",
			cmd:  "nodered-deploy,%%%bad",
			err:  true,
		},
		{
			desc: "wrap invalid base64",
			cmd:  "nodered-add-flow,%%%bad",
			err:  true,
		},
		{
			desc: "reject unknown command",
			cmd:  "nodered-unknown",
			err:  true,
		},
		{
			desc: "wrap node-red client error",
			cmd:  "nodered-ping",
			err:  true,
			mockFn: func(nodeRed *nrmocks.Client) {
				nodeRed.On("Ping").Return("", errBoom).Once()
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.desc, func(t *testing.T) {
			svc, _, nodeRed, err := newService(t, testConfig())
			require.NoError(t, err)
			if tc.mockFn != nil {
				tc.mockFn(nodeRed)
			}
			got, err := svc.NodeRed(tc.cmd)
			if tc.err {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
			assert.Equal(t, tc.resp, got)
		})
	}
}

func TestAddConfig(t *testing.T) {
	// nolint:dogsled
	svc, _, _, err := newService(t, testConfig())
	require.NoError(t, err)

	cfg := testConfig()
	cfg.DomainID = domainID
	require.NoError(t, svc.AddConfig(cfg))
	assert.Equal(t, cfg.DomainID, svc.Config().DomainID)
}

func TestServices(t *testing.T) {
	// nolint:dogsled
	svc, _, _, err := newService(t, testConfig())
	require.NoError(t, err)

	require.NoError(t, svc.UpdateLiveness("z-service", "service"))
	require.NoError(t, svc.UpdateLiveness("a-service", "service"))

	got := svc.Services()
	assert.Len(t, got, 2)
	assert.Equal(t, "a-service", got[0].Name)
	assert.Equal(t, "z-service", got[1].Name)
}

func TestPublish(t *testing.T) {
	errBoom := fmt.Errorf("boom")

	cases := []struct {
		desc   string
		topic  string
		err    error
		output string
	}{
		{
			desc:   "publish control message successfully",
			topic:  "control",
			output: mqttTopic("ctrl-channel", "res"),
		},
		{
			desc:   "publish data message successfully",
			topic:  "data",
			output: mqttTopic("data-channel", "gateway/telemetry"),
		},
		{
			desc:   "return mqtt publish error",
			topic:  "exec",
			err:    errBoom,
			output: mqttTopic("ctrl-channel", "res/exec"),
		},
	}

	for _, tc := range cases {
		t.Run(tc.desc, func(t *testing.T) {
			svc, mqttClient, _, err := newService(t, testConfig())
			require.NoError(t, err)
			var payload any
			expectMQTTPublish(t, mqttClient, tc.output, tc.err).Run(func(args mock.Arguments) {
				payload = args.Get(3)
			})
			err = svc.Publish(tc.topic, "payload")
			if tc.err != nil {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
			assert.Equal(t, "payload", payload)
		})
	}
}

func TestShutdown(t *testing.T) {
	cases := []struct {
		desc        string
		registerSvc bool
	}{
		{
			desc: "shutdown without registered services",
		},
		{
			desc:        "shutdown with registered services",
			registerSvc: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.desc, func(t *testing.T) {
			svc, mqttClient, _, err := newService(t, testConfig())
			assert.Nil(t, err, fmt.Sprintf("%s: unexpected setup error %v", tc.desc, err))

			if tc.registerSvc {
				err = svc.UpdateLiveness("nodered", "service")
				assert.Nil(t, err, fmt.Sprintf("%s: unexpected liveness error %v", tc.desc, err))
			}

			mqttClient.On("Disconnect", uint(1000)).Once()
			svc.Shutdown()
			mqttClient.AssertExpectations(t)
		})
	}
}

func TestChangeDir(t *testing.T) {
	tmp := t.TempDir()
	child := filepath.Join(tmp, "child")
	require.NoError(t, os.Mkdir(child, 0o755))

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
			got, workDir, err := agent.ChangeDirForTest(tc.workDir, tc.cmd)
			assert.NoError(t, err)
			assert.Equal(t, tc.output, got)
			assert.Equal(t, tc.dir, workDir)
		})
	}
}

func TestNormalizeNodeRedFlow(t *testing.T) {
	cfg := agent.Config{
		DomainID: domainID,
		Channels: agent.ChanConfig{
			DataID: "data-channel",
		},
		MQTT: agent.MQTTConfig{
			URL:        "ssl://mqtt.example.com:8883",
			Username:   "client-id",
			Password:   "client-secret",
			SkipTLSVer: true,
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
				{"id":"out","type":"mqtt out","broker":"missing","topic":"m/old-domain/c/old-channel/data"}
			]`,
		},
	}

	for _, tc := range cases {
		t.Run(tc.desc, func(t *testing.T) {
			got := agent.NormalizeNodeRedFlowForTest(cfg, tc.flow)
			if tc.same {
				assert.Equal(t, tc.flow, got)
				return
			}

			var nodes []map[string]any
			err := json.Unmarshal([]byte(got), &nodes)
			require.NoError(t, err)

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
			assert.Equal(t, agent.NodeRedTLSConfigIDForTest, broker["tls"], fmt.Sprintf("%s: unexpected tls config id", tc.desc))
			assert.Equal(t, map[string]any{"user": "client-id", "password": "client-secret"}, broker["credentials"], fmt.Sprintf("%s: unexpected credentials", tc.desc))
			assert.Equal(t, fmt.Sprintf(`msg.topic = "%s";`, mqttTopic("data-channel", "gateway/telemetry")), byID["fn"]["func"], fmt.Sprintf("%s: unexpected function topic", tc.desc))
			assert.Equal(t, "broker-a", byID["out"]["broker"], fmt.Sprintf("%s: unexpected mqtt out broker", tc.desc))
			assert.Equal(t, mqttTopic("data-channel", "gateway/telemetry"), byID["out"]["topic"], fmt.Sprintf("%s: unexpected mqtt out topic", tc.desc))
			assert.Contains(t, byID, agent.NodeRedTLSConfigIDForTest, fmt.Sprintf("%s: expected tls config node", tc.desc))
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
			host, port, useTLS := agent.NodeRedMQTTEndpointForTest(tc.rawURL)
			assert.Equal(t, tc.host, host)
			assert.Equal(t, tc.port, port)
			assert.Equal(t, tc.tls, useTLS)
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
			domainID: domainID,
			channel:  "channel-id",
			want:     fmt.Sprintf(`msg.topic = "m/%s/c/channel-id/gateway/telemetry";`, domainID),
		},
		{
			desc:  "leave topic unchanged without ids",
			input: `msg.topic = "m/old-domain/c/old-channel/data";`,
			want:  `msg.topic = "m/old-domain/c/old-channel/data";`,
		},
		{
			desc:     "gateway telemetry topic",
			input:    `msg.topic = "m/old-domain/c/old-channel/gateway/telemetry";`,
			domainID: domainID,
			channel:  "channel-id",
			want:     fmt.Sprintf(`msg.topic = "m/%s/c/channel-id/gateway/telemetry";`, domainID),
		},
	}

	for _, tc := range cases {
		t.Run(tc.desc, func(t *testing.T) {
			got := agent.PatchNodeRedTopicForTest(tc.input, tc.domainID, tc.channel)
			assert.Equal(t, tc.want, got)
		})
	}
}

func TestEnsureNodeRedTLSConfig(t *testing.T) {
	cases := []struct {
		desc      string
		in        any
		len       int
		wantEqual bool
	}{
		{
			desc: "append tls config to flow array",
			in:   []any{map[string]any{"id": "broker"}},
			len:  2,
		},
		{
			desc: "keep existing tls config in flow array",
			in:   []any{map[string]any{"id": agent.NodeRedTLSConfigIDForTest}},
			len:  1,
		},
		{
			desc: "append tls config to flow object",
			in:   map[string]any{},
			len:  1,
		},
		{
			desc: "keep existing tls config in flow object",
			in:   map[string]any{"configs": []any{map[string]any{"id": agent.NodeRedTLSConfigIDForTest}}},
			len:  1,
		},
		{
			desc:      "ignore unsupported payload",
			in:        "flow",
			wantEqual: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.desc, func(t *testing.T) {
			got := agent.EnsureNodeRedTLSConfigForTest(tc.in)
			if tc.wantEqual {
				assert.Equal(t, tc.in, got)
				return
			}
			switch typed := got.(type) {
			case []any:
				assert.Len(t, typed, tc.len)
			case map[string]any:
				assert.Len(t, typed["configs"], tc.len)
			}
		})
	}
}

func TestTerminalCloseExistingSession(t *testing.T) {
	sessionCount, err := agent.TerminalCloseExistingSessionForTest("uuid")
	assert.NoError(t, err)
	assert.Zero(t, sessionCount)
}

func TestGetTopic(t *testing.T) {
	cfg := agent.Config{
		DomainID: domainID,
		Channels: agent.ChanConfig{
			CtrlID: "ctrl-channel",
			DataID: "data-channel",
		},
	}

	cases := []struct {
		desc  string
		topic string
		want  string
	}{
		{
			desc:  "control response",
			topic: "control",
			want:  mqttTopic("ctrl-channel", "res"),
		},
		{
			desc:  "data message",
			topic: "data",
			want:  mqttTopic("data-channel", "gateway/telemetry"),
		},
		{
			desc:  "named response",
			topic: "exec",
			want:  mqttTopic("ctrl-channel", "res/exec"),
		},
	}

	for _, tc := range cases {
		t.Run(tc.desc, func(t *testing.T) {
			got := agent.GetTopicForTest(cfg, tc.topic)
			assert.Equal(t, tc.want, got)
		})
	}
}

// provisionHandlerOK returns a handler that always responds with one client and one channel.
func provisionHandlerOK(t *testing.T, deviceID, deviceKey, channelID string) http.HandlerFunc {
	t.Helper()
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		resp := map[string]any{
			"clients":  []map[string]any{{"id": deviceID, "secret": deviceKey, "name": "test-device"}},
			"channels": []map[string]any{{"id": channelID}},
		}
		b, err := json.Marshal(resp)
		assert.NoError(t, err)
		_, err = w.Write(b)
		assert.NoError(t, err)
	}
}

func TestDeviceManager(t *testing.T) {
	const (
		deviceID  = "device-uuid-123"
		deviceKey = "device-key-abc"
		channelID = "channel-uuid-456"
		addCmd    = `add,{"name":"test-device","external_id":"ext-id","external_key":"ext-key","iface_type":"ble","iface_addr":"AA:BB:CC:DD:EE:FF"}`
	)

	provSrv := httptest.NewServer(provisionHandlerOK(t, deviceID, deviceKey, channelID))
	t.Cleanup(provSrv.Close)

	newMgr := func(t *testing.T) *devicemgr.Manager {
		t.Helper()
		mgr, err := devicemgr.New(
			filepath.Join(t.TempDir(), "devices.db"),
			devicemgr.ProvisionConfig{URL: provSrv.URL, Token: "test-token", DomainID: domainID},
			iface.Config{},
		)
		require.NoError(t, err)
		t.Cleanup(func() { mgr.Close() })
		return mgr
	}

	cases := []struct {
		desc      string
		withMgr   bool
		setup     func(t *testing.T, svc agent.Service)
		setupPubs int
		cmdStr    string
		wantErr   bool
	}{
		{
			desc:    "nil manager returns error",
			cmdStr:  "list",
			wantErr: true,
		},
		{
			desc:    "list empty store",
			withMgr: true,
			cmdStr:  "list",
		},
		{
			desc:    "add device via provision API",
			withMgr: true,
			cmdStr:  addCmd,
		},
		{
			desc:    "list after add returns device",
			withMgr: true,
			setup: func(t *testing.T, svc agent.Service) {
				t.Helper()
				require.NoError(t, svc.DeviceManager("setup", addCmd))
			},
			setupPubs: 1,
			cmdStr:    "list",
		},
		{
			desc:    "get existing device",
			withMgr: true,
			setup: func(t *testing.T, svc agent.Service) {
				t.Helper()
				require.NoError(t, svc.DeviceManager("setup", addCmd))
			},
			setupPubs: 1,
			cmdStr:    "get," + deviceID,
		},
		{
			desc:    "mark device seen",
			withMgr: true,
			setup: func(t *testing.T, svc agent.Service) {
				t.Helper()
				require.NoError(t, svc.DeviceManager("setup", addCmd))
			},
			setupPubs: 1,
			cmdStr:    "seen," + deviceID,
		},
		{
			desc:    "remove device",
			withMgr: true,
			setup: func(t *testing.T, svc agent.Service) {
				t.Helper()
				require.NoError(t, svc.DeviceManager("setup", addCmd))
			},
			setupPubs: 1,
			cmdStr:    "remove," + deviceID,
		},
		{
			desc:    "get removed device returns error",
			withMgr: true,
			setup: func(t *testing.T, svc agent.Service) {
				t.Helper()
				require.NoError(t, svc.DeviceManager("setup-add", addCmd))
				require.NoError(t, svc.DeviceManager("setup-remove", "remove,"+deviceID))
			},
			setupPubs: 2,
			cmdStr:    "get," + deviceID,
			wantErr:   true,
		},
		{
			desc:    "open unknown device returns error",
			withMgr: true,
			cmdStr:  "open,no-such-device",
			wantErr: true,
		},
		{
			desc:    "close unknown device returns error",
			withMgr: true,
			cmdStr:  "close,no-such-device",
			wantErr: true,
		},
		{
			desc:    "read interface not open returns error",
			withMgr: true,
			cmdStr:  "read,no-such-device,4",
			wantErr: true,
		},
		{
			desc:    "write interface not open returns error",
			withMgr: true,
			cmdStr:  "write,no-such-device,deadbeef",
			wantErr: true,
		},
		{
			desc:    "empty command",
			withMgr: true,
			cmdStr:  "",
			wantErr: true,
		},
		{
			desc:    "unknown subcommand",
			withMgr: true,
			cmdStr:  "bogus",
			wantErr: true,
		},
		{
			desc:    "add missing args",
			withMgr: true,
			cmdStr:  "add,name,ext-id",
			wantErr: true,
		},
		{
			desc:    "remove missing id",
			withMgr: true,
			cmdStr:  "remove",
			wantErr: true,
		},
		{
			desc:    "get missing id",
			withMgr: true,
			cmdStr:  "get",
			wantErr: true,
		},
		{
			desc:    "seen missing id",
			withMgr: true,
			cmdStr:  "seen",
			wantErr: true,
		},
		{
			desc:    "open missing id",
			withMgr: true,
			cmdStr:  "open",
			wantErr: true,
		},
		{
			desc:    "close missing id",
			withMgr: true,
			cmdStr:  "close",
			wantErr: true,
		},
		{
			desc:    "read missing args",
			withMgr: true,
			cmdStr:  "read,dev-id",
			wantErr: true,
		},
		{
			desc:    "read invalid n",
			withMgr: true,
			cmdStr:  "read,dev-id,notanumber",
			wantErr: true,
		},
		{
			desc:    "write missing hex",
			withMgr: true,
			cmdStr:  "write,dev-id",
			wantErr: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.desc, func(t *testing.T) {
			var mgr *devicemgr.Manager
			if tc.withMgr {
				mgr = newMgr(t)
			}
			svc, mqttClient, _, err := newService(t, testConfig(), mgr)
			require.NoError(t, err)

			registerPublish := func() {
				tok := agentmocks.NewMQTTToken(t)
				tok.On("Wait").Return(true)
				tok.On("Error").Return(error(nil))
				mqttClient.On("Publish", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(tok).Once()
			}
			for range tc.setupPubs {
				registerPublish()
			}
			if tc.setup != nil {
				tc.setup(t, svc)
			}
			if !tc.wantErr {
				registerPublish()
			}

			err = svc.DeviceManager("uuid", tc.cmdStr)
			if tc.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

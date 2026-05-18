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
	"github.com/absmach/agent/pkg/devicemgr"
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

func newService(t *testing.T, cfg agent.Config) (agent.Service, *agentmocks.MQTTClient, *nrmocks.Client, error) {
	cfg.DomainID = domainID
	mqttClient := agentmocks.NewMQTTClient(t)
	nodeRed := nrmocks.NewClient(t)

	// selfHeartbeat publishes immediately on startup and then on each ticker
	// interval. Register an optional expectation so any test that doesn't
	// explicitly expect the heartbeat publish won't panic.
	hbToken := agentmocks.NewMQTTToken(t)
	hbToken.On("Wait").Maybe().Return(true)
	hbToken.On("Error").Maybe().Return(error(nil))
	mqttClient.On("Publish", mqttTopic("ctrl-channel", "services/agent/heartbeat"),
		mock.Anything, mock.Anything, mock.Anything).Maybe().Return(hbToken)

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	svc, err := agent.New(ctx, mqttClient, &cfg, nodeRed, slog.New(slog.NewTextHandler(io.Discard, nil)), nil)
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
			assert.Equal(t, tc.ctrl, tc.cfg.CtrlChan(), fmt.Sprintf("%s: unexpected control channel", tc.desc))
			assert.Equal(t, tc.data, tc.cfg.DataChan(), fmt.Sprintf("%s: unexpected data channel", tc.desc))
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
				assert.Error(t, err, fmt.Sprintf("%s: expected error", tc.desc))
				return
			}
			assert.Nil(t, err, fmt.Sprintf("%s: unexpected error %v", tc.desc, err))
			assert.Equal(t, tc.heartbeat, cfg.Heartbeat.Interval, fmt.Sprintf("%s: unexpected heartbeat interval", tc.desc))
			assert.Equal(t, tc.terminal, cfg.Terminal.SessionTimeout, fmt.Sprintf("%s: unexpected terminal timeout", tc.desc))
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
	assert.Nil(t, err, "unexpected error creating service")
	assert.NotNil(t, svc, "expected service to be non-nil")
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
			assert.Nil(t, err, fmt.Sprintf("%s: unexpected setup error %v", tc.desc, err))
			var payload any
			if tc.topic != "" {
				expectMQTTPublish(t, mqttClient, tc.topic, tc.pubErr).Run(func(args mock.Arguments) {
					payload = args.Get(3)
				})
			}
			got, err := svc.Execute("uuid", tc.cmd)
			if tc.err {
				assert.Error(t, err, fmt.Sprintf("%s: expected error", tc.desc))
			} else {
				assert.Nil(t, err, fmt.Sprintf("%s: unexpected error %v", tc.desc, err))
			}
			assert.Equal(t, tc.output, got, fmt.Sprintf("%s: unexpected output", tc.desc))
			if tc.topic != "" && tc.pubErr == nil {
				assert.NotEmpty(t, payload, fmt.Sprintf("%s: expected publish payload", tc.desc))
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
		fail   bool
		pubErr error
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
		},
		{
			desc: "return node-red error",
			cmd:  "nodered-ping",
			err:  true,
			fail: true,
		},
		{
			desc:   "return response publish error",
			cmd:    "nodered-ping",
			err:    true,
			pubErr: errBoom,
		},
	}

	for _, tc := range cases {
		t.Run(tc.desc, func(t *testing.T) {
			svc, mqttClient, nodeRed, err := newService(t, testConfig())
			assert.Nil(t, err, fmt.Sprintf("%s: unexpected setup error %v", tc.desc, err))
			if strings.HasPrefix(tc.cmd, "nodered-") {
				clientErr := error(nil)
				if tc.fail {
					clientErr = errBoom
				}
				nodeRed.On("Ping").Return("pong", clientErr).Once()
			}
			if strings.HasPrefix(tc.cmd, "nodered-") && !tc.fail && tc.cmd == "nodered-ping" {
				if tc.pubErr != nil || !tc.err {
					expectMQTTPublish(t, mqttClient, mqttTopic("ctrl-channel", "res"), tc.pubErr)
				}
			}
			err = svc.Control("uuid", tc.cmd)
			if tc.err {
				assert.Error(t, err, fmt.Sprintf("%s: expected error", tc.desc))
			} else {
				assert.Nil(t, err, fmt.Sprintf("%s: unexpected error %v", tc.desc, err))
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
			desc: "publish empty response for unknown config command",
			cmd:  "noop",
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
			assert.Nil(t, err, fmt.Sprintf("%s: unexpected setup error %v", tc.desc, err))
			if tc.registerSvc {
				err = svc.UpdateLiveness("nodered", "service")
				assert.Nil(t, err, fmt.Sprintf("%s: unexpected liveness error %v", tc.desc, err))
			}
			if !tc.err || tc.pubErr != nil {
				expectMQTTPublish(t, mqttClient, mqttTopic("ctrl-channel", "res"), tc.pubErr)
			}
			err = svc.ServiceConfig(context.Background(), "uuid", tc.cmd)
			if tc.err {
				assert.Error(t, err, fmt.Sprintf("%s: expected error", tc.desc))
				return
			}
			assert.Nil(t, err, fmt.Sprintf("%s: unexpected error %v", tc.desc, err))
			if tc.file != "" {
				assert.FileExists(t, tc.file, fmt.Sprintf("%s: expected export file", tc.desc))
			}
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
			assert.Nil(t, err, fmt.Sprintf("%s: unexpected setup error %v", tc.desc, err))
			err = svc.Terminal("uuid", tc.cmd)
			if tc.err {
				assert.Error(t, err, fmt.Sprintf("%s: expected error", tc.desc))
			} else {
				assert.Nil(t, err, fmt.Sprintf("%s: unexpected error %v", tc.desc, err))
			}
		})
	}
}

func TestNodeRed(t *testing.T) {
	flow := base64.StdEncoding.EncodeToString([]byte(`[{"id":"broker","type":"mqtt-broker"}]`))
	errBoom := fmt.Errorf("boom")

	cases := []struct {
		desc string
		cmd  string
		resp string
		err  bool
		fail bool
	}{
		{
			desc: "deploy flows successfully",
			cmd:  "nodered-deploy," + flow,
			resp: "deployed",
		},
		{
			desc: "add flow successfully",
			cmd:  "nodered-add-flow," + flow,
			resp: "added",
		},
		{
			desc: "fetch flows successfully",
			cmd:  "nodered-flows",
			resp: "flows",
		},
		{
			desc: "fetch state successfully",
			cmd:  "nodered-state",
			resp: "started",
		},
		{
			desc: "ping successfully",
			cmd:  "nodered-ping",
			resp: "pong",
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
			fail: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.desc, func(t *testing.T) {
			svc, _, nodeRed, err := newService(t, testConfig())
			assert.Nil(t, err, fmt.Sprintf("%s: unexpected setup error %v", tc.desc, err))
			clientErr := error(nil)
			if tc.fail {
				clientErr = errBoom
			}
			normalizedFlow := mock.MatchedBy(func(flow string) bool {
				return strings.Contains(flow, "mqtt.example.com") &&
					strings.Contains(flow, "client-id-nr") &&
					strings.Contains(flow, "magistrala-agent-tls")
			})
			switch tc.desc {
			case "deploy flows successfully":
				nodeRed.On("DeployFlows", normalizedFlow).Return(tc.resp, clientErr).Once()
			case "add flow successfully":
				nodeRed.On("AddFlow", normalizedFlow).Return(tc.resp, clientErr).Once()
			case "fetch flows successfully":
				nodeRed.On("FetchFlows").Return(tc.resp, clientErr).Once()
			case "fetch state successfully":
				nodeRed.On("FlowState").Return(tc.resp, clientErr).Once()
			case "ping successfully", "wrap node-red client error":
				nodeRed.On("Ping").Return(tc.resp, clientErr).Once()
			}
			got, err := svc.NodeRed(tc.cmd)
			if tc.err {
				assert.Error(t, err, fmt.Sprintf("%s: expected error", tc.desc))
			} else {
				assert.Nil(t, err, fmt.Sprintf("%s: unexpected error %v", tc.desc, err))
			}
			assert.Equal(t, tc.resp, got, fmt.Sprintf("%s: unexpected response", tc.desc))
		})
	}
}

func TestAddConfigAndConfig(t *testing.T) {
	// nolint:dogsled
	svc, _, _, err := newService(t, testConfig())
	assert.Nil(t, err, fmt.Sprintf("unexpected setup error %v", err))

	cfg := testConfig()
	cfg.DomainID = domainID
	err = svc.AddConfig(cfg)
	assert.Nil(t, err, fmt.Sprintf("unexpected add config error %v", err))
	assert.Equal(t, cfg.DomainID, svc.Config().DomainID, "unexpected returned config")
}

func TestServices(t *testing.T) {
	// nolint:dogsled
	svc, _, _, err := newService(t, testConfig())
	assert.Nil(t, err, fmt.Sprintf("unexpected setup error %v", err))

	err = svc.UpdateLiveness("z-service", "service")
	assert.Nil(t, err, fmt.Sprintf("unexpected liveness error %v", err))
	err = svc.UpdateLiveness("a-service", "service")
	assert.Nil(t, err, fmt.Sprintf("unexpected liveness error %v", err))

	got := svc.Services()
	assert.Len(t, got, 2, "unexpected services count")
	assert.Equal(t, "a-service", got[0].Name, "expected sorted services")
	assert.Equal(t, "z-service", got[1].Name, "expected sorted services")
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
			output: mqttTopic("data-channel", "msg"),
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
			assert.Nil(t, err, fmt.Sprintf("%s: unexpected setup error %v", tc.desc, err))
			var payload any
			expectMQTTPublish(t, mqttClient, tc.output, tc.err).Run(func(args mock.Arguments) {
				payload = args.Get(3)
			})
			err = svc.Publish(tc.topic, "payload")
			if tc.err != nil {
				assert.Error(t, err, fmt.Sprintf("%s: expected error", tc.desc))
			} else {
				assert.Nil(t, err, fmt.Sprintf("%s: unexpected error %v", tc.desc, err))
			}
			assert.Equal(t, "payload", payload, fmt.Sprintf("%s: unexpected payload", tc.desc))
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
			got, workDir, err := agent.ChangeDirForTest(tc.workDir, tc.cmd)
			assert.Nil(t, err, fmt.Sprintf("%s: unexpected error %v", tc.desc, err))
			assert.Equal(t, tc.output, got, fmt.Sprintf("%s: unexpected output", tc.desc))
			assert.Equal(t, tc.dir, workDir, fmt.Sprintf("%s: unexpected workdir", tc.desc))
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
				{"id":"out","type":"mqtt out","broker":"missing","topic":"m/old-domain/c/old-channel/msg"}
			]`,
		},
	}

	for _, tc := range cases {
		t.Run(tc.desc, func(t *testing.T) {
			got := agent.NormalizeNodeRedFlowForTest(cfg, tc.flow)
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
			assert.Equal(t, agent.NodeRedTLSConfigIDForTest, broker["tls"], fmt.Sprintf("%s: unexpected tls config id", tc.desc))
			assert.Equal(t, map[string]any{"user": "client-id", "password": "client-secret"}, broker["credentials"], fmt.Sprintf("%s: unexpected credentials", tc.desc))
			assert.Equal(t, fmt.Sprintf(`msg.topic = "%s";`, mqttTopic("data-channel", "msg")), byID["fn"]["func"], fmt.Sprintf("%s: unexpected function topic", tc.desc))
			assert.Equal(t, "broker-a", byID["out"]["broker"], fmt.Sprintf("%s: unexpected mqtt out broker", tc.desc))
			assert.Equal(t, mqttTopic("data-channel", "msg"), byID["out"]["topic"], fmt.Sprintf("%s: unexpected mqtt out topic", tc.desc))
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
			domainID: domainID,
			channel:  "channel-id",
			want:     fmt.Sprintf(`msg.topic = "m/%s/c/channel-id/msg";`, domainID),
		},
		{
			desc:     "message topic",
			input:    `msg.topic = "m/old-domain/c/old-channel/msg";`,
			domainID: domainID,
			channel:  "channel-id",
			want:     fmt.Sprintf(`msg.topic = "m/%s/c/channel-id/msg";`, domainID),
		},
		{
			desc:  "leave topic unchanged without ids",
			input: `msg.topic = "m/old-domain/c/old-channel/msg";`,
			want:  `msg.topic = "m/old-domain/c/old-channel/msg";`,
		},
	}

	for _, tc := range cases {
		t.Run(tc.desc, func(t *testing.T) {
			got := agent.PatchNodeRedTopicForTest(tc.input, tc.domainID, tc.channel)
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
	}

	for _, tc := range cases {
		t.Run(tc.desc, func(t *testing.T) {
			got := agent.EnsureNodeRedTLSConfigForTest(tc.in)
			switch typed := got.(type) {
			case []any:
				assert.Len(t, typed, tc.len, fmt.Sprintf("%s: unexpected array length", tc.desc))
			case map[string]any:
				assert.Len(t, typed["configs"], tc.len, fmt.Sprintf("%s: unexpected config length", tc.desc))
			}
		})
	}

	t.Run("ignore unsupported payload", func(t *testing.T) {
		got := agent.EnsureNodeRedTLSConfigForTest("flow")
		assert.Equal(t, "flow", got, "expected unsupported payload to be unchanged")
	})
}

func TestTerminalCloseExistingSession(t *testing.T) {
	sessionCount, err := agent.TerminalCloseExistingSessionForTest("uuid")
	assert.Nil(t, err, fmt.Sprintf("unexpected terminal close error %v", err))
	assert.Zero(t, sessionCount, "expected terminal to be removed")
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
			want:  mqttTopic("data-channel", "msg"),
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
			assert.Equal(t, tc.want, got, fmt.Sprintf("%s: expected topic %s got %s", tc.desc, tc.want, got))
		})
	}
}

// newServiceWithDevices creates a service wired to a real devicemgr.Manager
// backed by a temp BoltDB file. The provision URL is taken from srv.URL when
// srv is non-nil; pass nil to disable provisioning.
func newServiceWithDevices(t *testing.T, srv *httptest.Server) (agent.Service, *agentmocks.MQTTClient) {
	t.Helper()
	cfg := testConfig()
	cfg.DomainID = domainID

	provisionURL := ""
	if srv != nil {
		provisionURL = srv.URL
	}

	mgr, err := devicemgr.New(
		filepath.Join(t.TempDir(), "devices.db"),
		devicemgr.ProvisionConfig{URL: provisionURL, DomainID: domainID},
	)
	require.NoError(t, err)
	t.Cleanup(func() { mgr.Close() })

	mqttClient := agentmocks.NewMQTTClient(t)
	pubsub := agentmocks.NewPubSub(t)
	nodeRed := nrmocks.NewClient(t)

	pubsub.On("Subscribe", context.Background(), mock.Anything).Return(error(nil)).Once()

	svc, err := agent.New(context.Background(), mqttClient, &cfg, nodeRed, pubsub, slog.New(slog.NewTextHandler(io.Discard, nil)), mgr)
	require.NoError(t, err)
	return svc, mqttClient
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

func TestDeviceManager_NilManager(t *testing.T) {
	// nolint:dogsled
	svc, _, _, _, _, err := newService(t, testConfig(), nil)
	require.NoError(t, err)

	err = svc.DeviceManager("uuid-1", "list")
	assert.Error(t, err, "expected error when device manager is not configured")
}

func TestDeviceManager(t *testing.T) {
	const (
		deviceID  = "device-uuid-123"
		deviceKey = "device-key-abc"
		channelID = "channel-uuid-456"
	)

	provSrv := httptest.NewServer(provisionHandlerOK(t, deviceID, deviceKey, channelID))
	t.Cleanup(provSrv.Close)

	svc, mqttClient := newServiceWithDevices(t, provSrv)

	expectPublish := func(t *testing.T) {
		t.Helper()
		token := agentmocks.NewMQTTToken(t)
		token.On("Wait").Return(true)
		token.On("Error").Return(error(nil))
		mqttClient.On("Publish", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(token).Once()
	}

	t.Run("list empty store", func(t *testing.T) {
		expectPublish(t)
		err := svc.DeviceManager("uuid-1", "list")
		assert.NoError(t, err)
	})

	t.Run("add device via provision API", func(t *testing.T) {
		expectPublish(t)
		err := svc.DeviceManager("uuid-2", "add,test-device,ext-id,ext-key,ble,AA:BB:CC:DD:EE:FF")
		assert.NoError(t, err)
	})

	t.Run("list after add returns one device", func(t *testing.T) {
		expectPublish(t)
		err := svc.DeviceManager("uuid-3", "list")
		assert.NoError(t, err)
	})

	t.Run("get existing device", func(t *testing.T) {
		expectPublish(t)
		err := svc.DeviceManager("uuid-4", "get,"+deviceID)
		assert.NoError(t, err)
	})

	t.Run("mark device seen", func(t *testing.T) {
		expectPublish(t)
		err := svc.DeviceManager("uuid-5", "seen,"+deviceID)
		assert.NoError(t, err)
	})

	t.Run("remove device", func(t *testing.T) {
		expectPublish(t)
		err := svc.DeviceManager("uuid-6", "remove,"+deviceID)
		assert.NoError(t, err)
	})

	t.Run("get removed device returns error", func(t *testing.T) {
		err := svc.DeviceManager("uuid-7", "get,"+deviceID)
		assert.Error(t, err)
	})

	cases := []struct {
		desc   string
		cmdStr string
	}{
		{desc: "empty command", cmdStr: ""},
		{desc: "unknown subcommand", cmdStr: "bogus"},
		{desc: "add missing args", cmdStr: "add,name,ext-id"},
		{desc: "remove missing id", cmdStr: "remove"},
		{desc: "get missing id", cmdStr: "get"},
		{desc: "seen missing id", cmdStr: "seen"},
	}

	for _, tc := range cases {
		t.Run(tc.desc, func(t *testing.T) {
			err := svc.DeviceManager("uuid-e", tc.cmdStr)
			assert.Error(t, err, fmt.Sprintf("%s: expected error", tc.desc))
		})
	}
}

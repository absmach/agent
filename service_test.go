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
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/absmach/agent"
	agentmocks "github.com/absmach/agent/mocks"
	nrmocks "github.com/absmach/agent/pkg/nodered/mocks"
	"github.com/absmach/magistrala/pkg/messaging"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func testConfig(file string) agent.Config {
	return agent.NewConfig(
		agent.ServerConfig{Port: "9000", BrokerURL: "amqp://broker:5682"},
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
		file,
	)
}

func newService(t *testing.T, cfg agent.Config, subscribeErr error) (agent.Service, *agentmocks.MQTTClient, *agentmocks.PubSub, *nrmocks.Client, messaging.SubscriberConfig, error) {
	cfg.DomainID = "domain-id"
	mqttClient := agentmocks.NewMQTTClient(t)
	pubsub := agentmocks.NewPubSub(t)
	nodeRed := nrmocks.NewClient(t)

	var subConfig messaging.SubscriberConfig
	pubsub.On("Subscribe", context.Background(), mock.Anything).Run(func(args mock.Arguments) {
		subConfig = args.Get(1).(messaging.SubscriberConfig)
	}).Return(subscribeErr).Once()

	svc, err := agent.New(context.Background(), mqttClient, &cfg, nodeRed, pubsub, slog.New(slog.NewTextHandler(io.Discard, nil)))
	return svc, mqttClient, pubsub, nodeRed, subConfig, err
}

func expectMQTTPublish(t *testing.T, mqttClient *agentmocks.MQTTClient, topic string, err error) *mock.Call {
	token := agentmocks.NewMQTTToken(t)
	token.On("Wait").Return(true).Once()
	token.On("Error").Return(err).Once()
	return mqttClient.On("Publish", topic, byte(1), true, mock.Anything).Return(token).Once()
}

func TestConfig(t *testing.T) {
	tmp := t.TempDir()
	configFile := filepath.Join(tmp, "config.toml")
	cfg := testConfig(configFile)
	cfg.DomainID = "domain-id"

	cases := []struct {
		desc string
		run  func(t *testing.T)
	}{
		{
			desc: "create config successfully",
			run: func(t *testing.T) {
				got := agent.NewConfig(cfg.Server, cfg.Channels, cfg.NodeRed, cfg.Log, cfg.MQTT, cfg.Heartbeat, cfg.Terminal, configFile)
				assert.Equal(t, cfg.Server, got.Server, fmt.Sprintf("%s: unexpected server config", t.Name()))
				assert.Equal(t, cfg.Channels, got.Channels, fmt.Sprintf("%s: unexpected channel config", t.Name()))
				assert.Equal(t, configFile, got.File, fmt.Sprintf("%s: unexpected file path", t.Name()))
			},
		},
		{
			desc: "save and read config successfully",
			run: func(t *testing.T) {
				err := agent.SaveConfig(cfg)
				assert.Nil(t, err, fmt.Sprintf("%s: unexpected save error %v", t.Name(), err))
				got, err := agent.ReadConfig(configFile)
				assert.Nil(t, err, fmt.Sprintf("%s: unexpected read error %v", t.Name(), err))
				assert.Equal(t, cfg.DomainID, got.DomainID, fmt.Sprintf("%s: unexpected domain id", t.Name()))
				assert.Equal(t, cfg.Channels.DataID, got.Channels.DataID, fmt.Sprintf("%s: unexpected data channel", t.Name()))
				assert.Equal(t, configFile, got.File, fmt.Sprintf("%s: unexpected file path", t.Name()))
			},
		},
		{
			desc: "read missing config",
			run: func(t *testing.T) {
				_, err := agent.ReadConfig(filepath.Join(tmp, "missing.toml"))
				assert.Error(t, err, fmt.Sprintf("%s: expected missing file error", t.Name()))
			},
		},
		{
			desc: "read malformed config",
			run: func(t *testing.T) {
				file := filepath.Join(tmp, "bad.toml")
				err := os.WriteFile(file, []byte("="), 0o644)
				assert.Nil(t, err, fmt.Sprintf("%s: unexpected write error %v", t.Name(), err))
				_, err = agent.ReadConfig(file)
				assert.Error(t, err, fmt.Sprintf("%s: expected malformed config error", t.Name()))
			},
		},
		{
			desc: "save config write failure",
			run: func(t *testing.T) {
				bad := cfg
				bad.File = tmp
				err := agent.SaveConfig(bad)
				assert.Error(t, err, fmt.Sprintf("%s: expected write failure", t.Name()))
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.desc, tc.run)
	}
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
			cfg:  agent.ChanConfig{ID: "shared-channel", CtrlID: "ctrl-channel", DataID: "data-channel"},
			ctrl: "ctrl-channel",
			data: "data-channel",
		},
		{
			desc: "fall back to shared channel",
			cfg:  agent.ChanConfig{ID: "shared-channel"},
			ctrl: "shared-channel",
			data: "shared-channel",
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
	errBoom := fmt.Errorf("boom")

	cases := []struct {
		desc         string
		interval     time.Duration
		subscribeErr error
		err          bool
	}{
		{
			desc:     "create service successfully",
			interval: time.Hour,
		},
		{
			desc:         "return subscribe error",
			interval:     time.Hour,
			subscribeErr: errBoom,
			err:          true,
		},
		{
			desc:     "create service with invalid heartbeat interval",
			interval: 0,
		},
	}

	for _, tc := range cases {
		t.Run(tc.desc, func(t *testing.T) {
			cfg := testConfig("")
			cfg.Heartbeat.Interval = tc.interval
			svc, _, _, _, subConfig, err := newService(t, cfg, tc.subscribeErr)
			if tc.err {
				assert.Error(t, err, fmt.Sprintf("%s: expected error", tc.desc))
				return
			}
			assert.Nil(t, err, fmt.Sprintf("%s: unexpected error %v", tc.desc, err))
			assert.NotNil(t, svc, fmt.Sprintf("%s: expected service", tc.desc))
			assert.Equal(t, "agent", subConfig.ID, fmt.Sprintf("%s: unexpected subscriber id", tc.desc))
			assert.Equal(t, "channels.heartbeat.>", subConfig.Topic, fmt.Sprintf("%s: unexpected heartbeat topic", tc.desc))
			assert.NotNil(t, subConfig.Handler, fmt.Sprintf("%s: expected heartbeat handler", tc.desc))
		})
	}
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
			topic:  "m/domain-id/c/ctrl-channel/res",
		},
		{
			desc:   "execute command with no output successfully",
			cmd:    "true",
			output: "(no output)",
			topic:  "m/domain-id/c/ctrl-channel/res",
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
			topic:  "m/domain-id/c/ctrl-channel/res",
			pubErr: errBoom,
		},
	}

	for _, tc := range cases {
		t.Run(tc.desc, func(t *testing.T) {
			svc, mqttClient, _, _, _, err := newService(t, testConfig(""), nil)
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
			svc, mqttClient, _, nodeRed, _, err := newService(t, testConfig(""), nil)
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
					expectMQTTPublish(t, mqttClient, "m/domain-id/c/ctrl-channel/res", tc.pubErr)
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
		desc         string
		cmd          string
		err          bool
		registerSvc  bool
		publishTopic string
		file         string
		pubErr       error
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
			desc:         "save export config successfully",
			cmd:          "save,export," + exportFile + "," + exportContent,
			publishTopic: "commands.export.config",
			file:         exportFile,
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
			svc, mqttClient, pubsub, _, subConfig, err := newService(t, testConfig(""), nil)
			assert.Nil(t, err, fmt.Sprintf("%s: unexpected setup error %v", tc.desc, err))
			if tc.registerSvc {
				err = subConfig.Handler.Handle(&messaging.Message{Channel: "channels.nodered.service"})
				assert.Nil(t, err, fmt.Sprintf("%s: unexpected heartbeat error %v", tc.desc, err))
			}
			if !tc.err || tc.pubErr != nil {
				expectMQTTPublish(t, mqttClient, "m/domain-id/c/ctrl-channel/res", tc.pubErr)
			}
			if tc.publishTopic != "" {
				pubsub.On("Publish", context.Background(), tc.publishTopic, mock.Anything).Return(nil).Once()
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
			svc, _, _, _, _, err := newService(t, testConfig(""), nil)
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
			svc, _, _, nodeRed, _, err := newService(t, testConfig(""), nil)
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
	file := filepath.Join(t.TempDir(), "config.toml")
	svc, _, _, _, _, err := newService(t, testConfig(file), nil)
	assert.Nil(t, err, fmt.Sprintf("unexpected setup error %v", err))

	cfg := testConfig(file)
	cfg.DomainID = "domain-id"
	err = svc.AddConfig(cfg)
	assert.Nil(t, err, fmt.Sprintf("unexpected add config error %v", err))
	assert.FileExists(t, file, "expected config file")
	assert.Equal(t, cfg.DomainID, svc.Config().DomainID, "unexpected returned config")
}

func TestServices(t *testing.T) {
	svc, _, _, _, subConfig, err := newService(t, testConfig(""), nil)
	assert.Nil(t, err, fmt.Sprintf("unexpected setup error %v", err))

	err = subConfig.Handler.Handle(&messaging.Message{Channel: "channels"})
	assert.Error(t, err, "expected malformed heartbeat subject error")
	err = subConfig.Handler.Handle(&messaging.Message{Channel: "channels.z-service.service"})
	assert.Nil(t, err, fmt.Sprintf("unexpected heartbeat error %v", err))
	err = subConfig.Handler.Handle(&messaging.Message{Channel: "channels.a-service.service"})
	assert.Nil(t, err, fmt.Sprintf("unexpected heartbeat error %v", err))
	err = subConfig.Handler.Cancel()
	assert.Nil(t, err, fmt.Sprintf("unexpected handler cancel error %v", err))

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
			output: "m/domain-id/c/ctrl-channel/res",
		},
		{
			desc:   "publish data message successfully",
			topic:  "data",
			output: "m/domain-id/c/data-channel/msg",
		},
		{
			desc:   "return mqtt publish error",
			topic:  "exec",
			err:    errBoom,
			output: "m/domain-id/c/ctrl-channel/res/exec",
		},
	}

	for _, tc := range cases {
		t.Run(tc.desc, func(t *testing.T) {
			svc, mqttClient, _, _, _, err := newService(t, testConfig(""), nil)
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

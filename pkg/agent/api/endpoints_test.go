// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

package api_test

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/absmach/agent/pkg/agent"
	api "github.com/absmach/agent/pkg/agent/api"
	agentmocks "github.com/absmach/agent/pkg/agent/mocks"
	"github.com/absmach/agent/pkg/nodered"
	mglog "github.com/absmach/magistrala/logger"
	mgerrors "github.com/absmach/magistrala/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

const contentType = "application/json"

type testRequest struct {
	client      *http.Client
	method      string
	url         string
	contentType string
	body        io.Reader
}

func (tr testRequest) make() (*http.Response, error) {
	req, err := http.NewRequest(tr.method, tr.url, tr.body)
	if err != nil {
		return nil, err
	}

	if tr.contentType != "" {
		req.Header.Set("Content-Type", tr.contentType)
	}

	req.Header.Set("Referer", "http://localhost")

	return tr.client.Do(req)
}

type genericBody struct {
	Service  string `json:"service"`
	Response string `json:"response"`
}

func toJSON(data any) string {
	jsonData, err := json.Marshal(data)
	if err != nil {
		return ""
	}

	return string(jsonData)
}

func validAgentConfig() agent.Config {
	return agent.Config{
		Server:    agent.ServerConfig{Port: "9999", BrokerURL: "amqp://fluxmq:5682"},
		Channels:  agent.ChanConfig{ID: "channel-id"},
		NodeRed:   agent.NodeRedConfig{URL: "http://nodered:1880"},
		Log:       agent.LogConfig{Level: "info"},
		MQTT:      agent.MQTTConfig{URL: "ssl://broker:8883", Username: "user", Password: "pass"},
		Heartbeat: agent.HeartbeatConfig{Interval: time.Second},
		Terminal:  agent.TerminalConfig{SessionTimeout: time.Minute},
		DomainID:  "domain-id",
		File:      "/tmp/config.toml",
	}
}

func newAgentServer(t *testing.T) (*httptest.Server, *agentmocks.Service) {
	t.Helper()

	svc := agentmocks.NewService(t)
	logger := mglog.NewMock()

	return httptest.NewServer(api.MakeHandler(svc, logger, "instance-id")), svc
}

func TestPublish(t *testing.T) {
	svcErr := mgerrors.New("publish failed")

	cases := []struct {
		desc      string
		req       string
		status    int
		mockSetup func(*agentmocks.Service)
		err       error
	}{
		{
			desc: "publish data",
			req: toJSON(map[string]string{
				"payload": "payload",
				"topic":   "topic",
			}),
			status: http.StatusOK,
			mockSetup: func(svc *agentmocks.Service) {
				svc.On("Publish", "topic", "payload").Return(nil)
			},
		},
		{
			desc:   "publish malformed request",
			req:    toJSON(map[string]string{"payload": "payload"}),
			status: http.StatusInternalServerError,
			err:    agent.ErrMalformedEntity,
		},
		{
			desc:   "publish invalid json",
			req:    "}",
			status: http.StatusInternalServerError,
		},
		{
			desc: "publish service error",
			req: toJSON(map[string]string{
				"payload": "payload",
				"topic":   "topic",
			}),
			status: http.StatusInternalServerError,
			mockSetup: func(svc *agentmocks.Service) {
				svc.On("Publish", "topic", "payload").Return(svcErr)
			},
			err: svcErr,
		},
	}

	for _, tc := range cases {
		t.Run(tc.desc, func(t *testing.T) {
			ts, svc := newAgentServer(t)
			defer ts.Close()

			if tc.mockSetup != nil {
				tc.mockSetup(svc)
			}

			req := testRequest{
				client:      ts.Client(),
				method:      http.MethodPost,
				url:         ts.URL + "/pub",
				contentType: contentType,
				body:        strings.NewReader(tc.req),
			}

			res, err := req.make()
			assert.Nil(t, err, fmt.Sprintf("%s: unexpected error %s", tc.desc, err))
			assert.Equal(t, tc.status, res.StatusCode, fmt.Sprintf("%s: expected status code %d got %d", tc.desc, tc.status, res.StatusCode))

			if tc.status != http.StatusOK {
				return
			}

			var body genericBody
			err = json.NewDecoder(res.Body).Decode(&body)
			assert.Nil(t, err, fmt.Sprintf("%s: unexpected error while decoding response body: %s", tc.desc, err))
			assert.Equal(t, "agent", body.Service)
			assert.Equal(t, "config", body.Response)
		})
	}
}

func TestExec(t *testing.T) {
	svcErr := mgerrors.New("exec failed")

	cases := []struct {
		desc      string
		req       string
		status    int
		mockSetup func(*agentmocks.Service)
		err       error
		response  string
	}{
		{
			desc: "execute command",
			req: toJSON(map[string]string{
				"bn": "device:",
				"n":  "exec",
				"vs": "ls",
			}),
			status: http.StatusOK,
			mockSetup: func(svc *agentmocks.Service) {
				svc.On("Execute", "device", "ls").Return("done", nil)
			},
			response: "done",
		},
		{
			desc:   "execute malformed request",
			req:    toJSON(map[string]string{"bn": "device:", "n": "wrong", "vs": "ls"}),
			status: http.StatusInternalServerError,
			err:    agent.ErrMalformedEntity,
		},
		{
			desc:   "execute invalid json",
			req:    "}",
			status: http.StatusInternalServerError,
		},
		{
			desc: "execute service error",
			req: toJSON(map[string]string{
				"bn": "device:",
				"n":  "exec",
				"vs": "ls",
			}),
			status: http.StatusInternalServerError,
			mockSetup: func(svc *agentmocks.Service) {
				svc.On("Execute", "device", "ls").Return("", svcErr)
			},
			err: svcErr,
		},
	}

	for _, tc := range cases {
		t.Run(tc.desc, func(t *testing.T) {
			ts, svc := newAgentServer(t)
			defer ts.Close()

			if tc.mockSetup != nil {
				tc.mockSetup(svc)
			}

			req := testRequest{
				client:      ts.Client(),
				method:      http.MethodPost,
				url:         ts.URL + "/exec",
				contentType: contentType,
				body:        strings.NewReader(tc.req),
			}

			res, err := req.make()
			assert.Nil(t, err, fmt.Sprintf("%s: unexpected error %s", tc.desc, err))
			assert.Equal(t, tc.status, res.StatusCode, fmt.Sprintf("%s: expected status code %d got %d", tc.desc, tc.status, res.StatusCode))

			if tc.status != http.StatusOK {
				return
			}

			var body struct {
				BaseName string `json:"bn"`
				Name     string `json:"n"`
				Value    string `json:"vs"`
			}
			err = json.NewDecoder(res.Body).Decode(&body)
			assert.Nil(t, err, fmt.Sprintf("%s: unexpected error while decoding response body: %s", tc.desc, err))
			assert.Equal(t, "device:", body.BaseName)
			assert.Equal(t, "exec", body.Name)
			assert.Equal(t, tc.response, body.Value)
		})
	}
}

func TestAddConfig(t *testing.T) {
	current := validAgentConfig()
	svcErr := mgerrors.New("config failed")

	cases := []struct {
		desc      string
		req       string
		status    int
		mockSetup func(*agentmocks.Service)
		err       error
	}{
		{
			desc: "add config",
			req: toJSON(map[string]any{
				"server":   map[string]string{"port": "7777"},
				"channels": map[string]string{"id": "new-channel"},
				"nodered":  map[string]string{"url": "http://new-nodered:1880"},
				"log":      map[string]string{"level": "debug"},
				"mqtt": map[string]string{
					"url":      "ssl://new-broker:8883",
					"username": "new-user",
					"password": "new-pass",
				},
			}),
			status: http.StatusOK,
			mockSetup: func(svc *agentmocks.Service) {
				svc.On("Config").Return(current)
				svc.On("AddConfig", mock.AnythingOfType("agent.Config")).Return(nil)
			},
		},
		{
			desc:   "add config malformed request",
			req:    toJSON(map[string]any{"server": map[string]string{"port": ""}}),
			status: http.StatusInternalServerError,
			err:    agent.ErrMalformedEntity,
		},
		{
			desc:   "add config invalid json",
			req:    "}",
			status: http.StatusInternalServerError,
		},
		{
			desc: "add config service error",
			req: toJSON(map[string]any{
				"server":   map[string]string{"port": "7777"},
				"channels": map[string]string{"id": "new-channel"},
				"nodered":  map[string]string{"url": "http://new-nodered:1880"},
				"log":      map[string]string{"level": "debug"},
				"mqtt": map[string]string{
					"url":      "ssl://new-broker:8883",
					"username": "new-user",
					"password": "new-pass",
				},
			}),
			status: http.StatusInternalServerError,
			mockSetup: func(svc *agentmocks.Service) {
				svc.On("Config").Return(current)
				svc.On("AddConfig", mock.AnythingOfType("agent.Config")).Return(svcErr)
			},
			err: svcErr,
		},
	}

	for _, tc := range cases {
		t.Run(tc.desc, func(t *testing.T) {
			ts, svc := newAgentServer(t)
			defer ts.Close()

			if tc.mockSetup != nil {
				tc.mockSetup(svc)
			}

			req := testRequest{
				client:      ts.Client(),
				method:      http.MethodPost,
				url:         ts.URL + "/config",
				contentType: contentType,
				body:        strings.NewReader(tc.req),
			}

			res, err := req.make()
			assert.Nil(t, err, fmt.Sprintf("%s: unexpected error %s", tc.desc, err))
			assert.Equal(t, tc.status, res.StatusCode, fmt.Sprintf("%s: expected status code %d got %d", tc.desc, tc.status, res.StatusCode))

			if tc.status != http.StatusOK {
				return
			}

			var body genericBody
			err = json.NewDecoder(res.Body).Decode(&body)
			assert.Nil(t, err, fmt.Sprintf("%s: unexpected error while decoding response body: %s", tc.desc, err))
			assert.Equal(t, "agent", body.Service)
			assert.Equal(t, "config", body.Response)
		})
	}
}

func TestViewConfig(t *testing.T) {
	ts, svc := newAgentServer(t)
	defer ts.Close()

	cfg := validAgentConfig()

	svc.On("Config").Return(cfg)

	req := testRequest{
		client: ts.Client(),
		method: http.MethodGet,
		url:    ts.URL + "/config",
	}

	res, err := req.make()
	assert.Nil(t, err)
	assert.Equal(t, http.StatusOK, res.StatusCode)

	var body map[string]any
	err = json.NewDecoder(res.Body).Decode(&body)
	assert.Nil(t, err)
	assert.Equal(t, cfg.Server.Port, body["server"].(map[string]any)["port"])
	assert.Equal(t, cfg.Server.BrokerURL, body["server"].(map[string]any)["broker_url"])
	assert.Equal(t, cfg.Channels.ID, body["channels"].(map[string]any)["id"])
	assert.Equal(t, cfg.NodeRed.URL, body["nodered"].(map[string]any)["url"])
	assert.Equal(t, cfg.MQTT.URL, body["mqtt"].(map[string]any)["url"])
	assert.Equal(t, cfg.MQTT.Username, body["mqtt"].(map[string]any)["username"])
	assert.Equal(t, cfg.MQTT.Password, body["mqtt"].(map[string]any)["password"])
	assert.Equal(t, cfg.DomainID, body["domain_id"])
}

func TestViewServices(t *testing.T) {
	ts, svc := newAgentServer(t)
	defer ts.Close()

	services := []agent.Info{{Name: "nodered", Status: "online", Type: "service"}}

	svc.On("Services").Return(services)

	req := testRequest{
		client: ts.Client(),
		method: http.MethodGet,
		url:    ts.URL + "/services",
	}

	res, err := req.make()
	assert.Nil(t, err)
	assert.Equal(t, http.StatusOK, res.StatusCode)

	var body []agent.Info
	err = json.NewDecoder(res.Body).Decode(&body)
	assert.Nil(t, err)
	assert.Equal(t, services, body)
}

func TestNodeRed(t *testing.T) {
	svcErr := mgerrors.New("nodered failed")

	cases := []struct {
		desc      string
		req       string
		status    int
		mockSetup func(*agentmocks.Service)
		err       error
		response  string
	}{
		{
			desc:   "nodered ping",
			req:    toJSON(map[string]string{"command": "nodered-ping"}),
			status: http.StatusOK,
			mockSetup: func(svc *agentmocks.Service) {
				svc.On("NodeRed", "nodered-ping").Return("pong", nil)
			},
			response: "pong",
		},
		{
			desc:   "nodered deploy",
			req:    toJSON(map[string]string{"command": "nodered-deploy", "flows": "W10="}),
			status: http.StatusOK,
			mockSetup: func(svc *agentmocks.Service) {
				svc.On("NodeRed", "nodered-deploy,W10=").Return("deployed", nil)
			},
			response: "deployed",
		},
		{
			desc:   "nodered malformed request",
			req:    toJSON(map[string]string{"command": ""}),
			status: http.StatusInternalServerError,
			err:    agent.ErrMalformedEntity,
		},
		{
			desc:   "nodered invalid json",
			req:    "}",
			status: http.StatusInternalServerError,
		},
		{
			desc:   "nodered conflict",
			req:    toJSON(map[string]string{"command": "nodered-add-flow", "flows": "W10="}),
			status: http.StatusConflict,
			mockSetup: func(svc *agentmocks.Service) {
				svc.On("NodeRed", "nodered-add-flow,W10=").Return("", mgerrors.Wrap(nodered.ErrFlowConflict, mgerrors.New("duplicate id")))
			},
			err: nodered.ErrFlowConflict,
		},
		{
			desc:   "nodered service error",
			req:    toJSON(map[string]string{"command": "nodered-ping"}),
			status: http.StatusInternalServerError,
			mockSetup: func(svc *agentmocks.Service) {
				svc.On("NodeRed", "nodered-ping").Return("", svcErr)
			},
			err: svcErr,
		},
	}

	for _, tc := range cases {
		t.Run(tc.desc, func(t *testing.T) {
			ts, svc := newAgentServer(t)
			defer ts.Close()

			if tc.mockSetup != nil {
				tc.mockSetup(svc)
			}

			req := testRequest{
				client:      ts.Client(),
				method:      http.MethodPost,
				url:         ts.URL + "/nodered",
				contentType: contentType,
				body:        strings.NewReader(tc.req),
			}

			res, err := req.make()
			assert.Nil(t, err, fmt.Sprintf("%s: unexpected error %s", tc.desc, err))
			assert.Equal(t, tc.status, res.StatusCode, fmt.Sprintf("%s: expected status code %d got %d", tc.desc, tc.status, res.StatusCode))

			if tc.status != http.StatusOK {
				return
			}

			var body genericBody
			err = json.NewDecoder(res.Body).Decode(&body)
			assert.Nil(t, err, fmt.Sprintf("%s: unexpected error while decoding response body: %s", tc.desc, err))
			assert.Equal(t, "agent", body.Service)
			assert.Equal(t, tc.response, body.Response)
		})
	}
}

func TestMiscRoutes(t *testing.T) {
	ts, _ := newAgentServer(t)
	defer ts.Close()

	cases := []struct {
		desc   string
		method string
		url    string
		status int
		check  func(*testing.T, string)
	}{
		{
			desc:   "options route",
			method: http.MethodOptions,
			url:    ts.URL + "/anything",
			status: http.StatusNoContent,
		},
		{
			desc:   "health route",
			method: http.MethodGet,
			url:    ts.URL + "/health",
			status: http.StatusOK,
			check: func(t *testing.T, body string) {
				assert.Contains(t, body, `"status":"pass"`)
			},
		},
		{
			desc:   "metrics route",
			method: http.MethodGet,
			url:    ts.URL + "/metrics",
			status: http.StatusOK,
			check: func(t *testing.T, body string) {
				assert.Contains(t, body, "go_gc_duration_seconds")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.desc, func(t *testing.T) {
			req := testRequest{
				client: ts.Client(),
				method: tc.method,
				url:    tc.url,
			}

			res, err := req.make()
			assert.Nil(t, err, fmt.Sprintf("%s: unexpected error %s", tc.desc, err))
			assert.Equal(t, tc.status, res.StatusCode, fmt.Sprintf("%s: expected status code %d got %d", tc.desc, tc.status, res.StatusCode))

			if tc.check != nil {
				data, err := io.ReadAll(res.Body)
				assert.Nil(t, err)
				tc.check(t, string(data))
			}
		})
	}
}

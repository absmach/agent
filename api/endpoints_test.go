// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

package api_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/absmach/agent"
	api "github.com/absmach/agent/api"
	agentmocks "github.com/absmach/agent/mocks"
	"github.com/absmach/agent/pkg/devicemgr"
	"github.com/absmach/agent/pkg/iface"
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
		Server:    agent.ServerConfig{Port: "9999"},
		Channels:  agent.ChanConfig{CtrlID: "ctrl-channel", DataID: "data-channel"},
		NodeRed:   agent.NodeRedConfig{URL: "http://nodered:1880"},
		Log:       agent.LogConfig{Level: "info"},
		MQTT:      agent.MQTTConfig{URL: "ssl://broker:8883", Username: "user", Password: "pass"},
		Heartbeat: agent.HeartbeatConfig{Interval: time.Second},
		Terminal:  agent.TerminalConfig{SessionTimeout: time.Minute},
		DomainID:  "domain-id",
	}
}

func newAgentServer(t *testing.T) (*httptest.Server, *agentmocks.Service) {
	t.Helper()

	svc := agentmocks.NewService(t)
	logger := mglog.NewMock()
	svc.On("SetPushEvent", mock.Anything).Maybe().Return()

	return httptest.NewServer(api.MakeHandler(svc, logger, nil)), svc
}

func TestPublish(t *testing.T) {
	svcErr := mgerrors.New("publish failed")

	cases := []struct {
		desc      string
		req       string
		status    int
		response  string
		mockSetup func(*agentmocks.Service)
		err       error
	}{
		{
			desc: "publish data",
			req: toJSON(map[string]string{
				"payload": "payload",
				"topic":   "topic",
			}),
			status:   http.StatusOK,
			response: "publish",
			mockSetup: func(svc *agentmocks.Service) {
				svc.On("Publish", "topic", "payload").Return(nil)
			},
		},
		{
			desc:   "publish malformed request",
			req:    toJSON(map[string]string{"payload": "payload"}),
			status: http.StatusBadRequest,
			err:    agent.ErrMalformedEntity,
		},
		{
			desc:   "publish invalid json",
			req:    "}",
			status: http.StatusBadRequest,
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
			assert.Equal(t, tc.response, body.Response)
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
		response  string
		mockSetup func(*agentmocks.Service)
		err       error
	}{
		{
			desc: "add config",
			req: toJSON(map[string]any{
				"server":   map[string]string{"port": "7777"},
				"channels": map[string]string{"ctrl_id": "new-ctrl", "data_id": "new-data"},
				"nodered":  map[string]string{"url": "http://new-nodered:1880"},
				"log":      map[string]string{"level": "debug"},
				"mqtt": map[string]string{
					"url":      "ssl://new-broker:8883",
					"username": "new-user",
					"password": "new-pass",
				},
			}),
			status:   http.StatusOK,
			response: "config",
			mockSetup: func(svc *agentmocks.Service) {
				svc.On("Config").Return(current)
				svc.On("AddConfig", mock.AnythingOfType("agent.Config")).Return(nil)
			},
		},
		{
			desc:   "add config malformed request",
			req:    toJSON(map[string]any{"server": map[string]string{"port": ""}}),
			status: http.StatusBadRequest,
			err:    agent.ErrMalformedEntity,
		},
		{
			desc:   "add config invalid json",
			req:    "}",
			status: http.StatusBadRequest,
		},
		{
			desc: "add config service error",
			req: toJSON(map[string]any{
				"server":   map[string]string{"port": "7777"},
				"channels": map[string]string{"ctrl_id": "new-ctrl", "data_id": "new-data"},
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
			assert.Equal(t, tc.response, body.Response)
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
	assert.Equal(t, cfg.Channels.CtrlID, body["channels"].(map[string]any)["ctrl_id"])
	assert.Equal(t, cfg.Channels.DataID, body["channels"].(map[string]any)["data_id"])
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
			status: http.StatusBadRequest,
			err:    agent.ErrMalformedEntity,
		},
		{
			desc:   "nodered invalid json",
			req:    "}",
			status: http.StatusBadRequest,
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

func TestListDevices(t *testing.T) {
	svcErr := mgerrors.New("list failed")
	dev := devicemgr.Device{
		ID:            "dev-id-1",
		Name:          "sensor-a",
		InterfaceType: iface.InterfaceBLE,
		InterfaceAddr: "AA:BB:CC:DD:EE:FF",
		Active:        true,
	}

	cases := []struct {
		desc      string
		status    int
		mockSetup func(*agentmocks.Service)
	}{
		{
			desc:   "list returns devices",
			status: http.StatusOK,
			mockSetup: func(svc *agentmocks.Service) {
				svc.On("ListDevices").Return([]devicemgr.Device{dev}, nil)
			},
		},
		{
			desc:   "list returns empty slice",
			status: http.StatusOK,
			mockSetup: func(svc *agentmocks.Service) {
				svc.On("ListDevices").Return([]devicemgr.Device{}, nil)
			},
		},
		{
			desc:   "service error",
			status: http.StatusInternalServerError,
			mockSetup: func(svc *agentmocks.Service) {
				svc.On("ListDevices").Return([]devicemgr.Device(nil), svcErr)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.desc, func(t *testing.T) {
			ts, svc := newAgentServer(t)
			defer ts.Close()
			tc.mockSetup(svc)

			req := testRequest{
				client: ts.Client(),
				method: http.MethodGet,
				url:    ts.URL + "/devices",
			}

			res, err := req.make()
			assert.Nil(t, err)
			assert.Equal(t, tc.status, res.StatusCode, tc.desc)
		})
	}
}

func TestGetDevice(t *testing.T) {
	svcErr := mgerrors.New("not found")
	dev := devicemgr.Device{ID: "dev-id-1", Name: "sensor-a"}

	cases := []struct {
		desc      string
		id        string
		status    int
		mockSetup func(*agentmocks.Service)
	}{
		{
			desc:   "get existing device",
			id:     "dev-id-1",
			status: http.StatusOK,
			mockSetup: func(svc *agentmocks.Service) {
				svc.On("GetDevice", "dev-id-1").Return(dev, nil)
			},
		},
		{
			desc:   "get non-existent device",
			id:     "missing",
			status: http.StatusInternalServerError,
			mockSetup: func(svc *agentmocks.Service) {
				svc.On("GetDevice", "missing").Return(devicemgr.Device{}, svcErr)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.desc, func(t *testing.T) {
			ts, svc := newAgentServer(t)
			defer ts.Close()
			tc.mockSetup(svc)

			req := testRequest{
				client: ts.Client(),
				method: http.MethodGet,
				url:    ts.URL + "/devices/" + tc.id,
			}

			res, err := req.make()
			assert.Nil(t, err)
			assert.Equal(t, tc.status, res.StatusCode, tc.desc)
		})
	}
}

func TestAddDevice(t *testing.T) {
	svcErr := mgerrors.New("add failed")
	dev := devicemgr.Device{
		ID:            "dev-id-new",
		Name:          "sensor-b",
		InterfaceType: iface.InterfaceSerial,
		InterfaceAddr: "/dev/ttyUSB0",
	}

	validBody := toJSON(map[string]string{
		"name":           "sensor-b",
		"ext_id":         "ext-id",
		"ext_key":        "ext-key",
		"interface_type": "serial",
		"interface_addr": "/dev/ttyUSB0",
	})

	cases := []struct {
		desc      string
		body      string
		status    int
		mockSetup func(*agentmocks.Service)
	}{
		{
			desc:   "add device successfully",
			body:   validBody,
			status: http.StatusCreated,
			mockSetup: func(svc *agentmocks.Service) {
				svc.On("AddDevice", mock.Anything, "sensor-b", "ext-id", "ext-key", "serial", "/dev/ttyUSB0").
					Return(dev, nil)
			},
		},
		{
			desc:      "missing name returns bad request",
			body:      toJSON(map[string]string{"ext_id": "x", "ext_key": "y", "interface_type": "ble"}),
			status:    http.StatusBadRequest,
			mockSetup: func(_ *agentmocks.Service) {},
		},
		{
			desc:      "invalid JSON returns bad request",
			body:      "}",
			status:    http.StatusBadRequest,
			mockSetup: func(_ *agentmocks.Service) {},
		},
		{
			desc:   "service error",
			body:   validBody,
			status: http.StatusInternalServerError,
			mockSetup: func(svc *agentmocks.Service) {
				svc.On("AddDevice", mock.Anything, "sensor-b", "ext-id", "ext-key", "serial", "/dev/ttyUSB0").
					Return(devicemgr.Device{}, svcErr)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.desc, func(t *testing.T) {
			ts, svc := newAgentServer(t)
			defer ts.Close()
			tc.mockSetup(svc)

			req := testRequest{
				client:      ts.Client(),
				method:      http.MethodPost,
				url:         ts.URL + "/devices",
				contentType: contentType,
				body:        strings.NewReader(tc.body),
			}

			res, err := req.make()
			assert.Nil(t, err)
			assert.Equal(t, tc.status, res.StatusCode, tc.desc)
		})
	}
}

func TestRemoveDevice(t *testing.T) {
	svcErr := mgerrors.New("remove failed")

	cases := []struct {
		desc      string
		id        string
		status    int
		mockSetup func(*agentmocks.Service)
	}{
		{
			desc:   "remove existing device",
			id:     "dev-id-1",
			status: http.StatusNoContent,
			mockSetup: func(svc *agentmocks.Service) {
				svc.On("RemoveDevice", "dev-id-1").Return(nil)
			},
		},
		{
			desc:   "service error",
			id:     "bad-id",
			status: http.StatusInternalServerError,
			mockSetup: func(svc *agentmocks.Service) {
				svc.On("RemoveDevice", "bad-id").Return(svcErr)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.desc, func(t *testing.T) {
			ts, svc := newAgentServer(t)
			defer ts.Close()
			tc.mockSetup(svc)

			req := testRequest{
				client: ts.Client(),
				method: http.MethodDelete,
				url:    ts.URL + "/devices/" + tc.id,
			}

			res, err := req.make()
			assert.Nil(t, err)
			assert.Equal(t, tc.status, res.StatusCode, tc.desc)
		})
	}
}

func TestMarkDeviceSeen(t *testing.T) {
	svcErr := mgerrors.New("mark seen failed")

	cases := []struct {
		desc      string
		id        string
		status    int
		mockSetup func(*agentmocks.Service)
	}{
		{
			desc:   "mark existing device seen",
			id:     "dev-id-1",
			status: http.StatusNoContent,
			mockSetup: func(svc *agentmocks.Service) {
				svc.On("MarkDeviceSeen", "dev-id-1").Return(nil)
			},
		},
		{
			desc:   "service error",
			id:     "bad-id",
			status: http.StatusInternalServerError,
			mockSetup: func(svc *agentmocks.Service) {
				svc.On("MarkDeviceSeen", "bad-id").Return(svcErr)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.desc, func(t *testing.T) {
			ts, svc := newAgentServer(t)
			defer ts.Close()
			tc.mockSetup(svc)

			req := testRequest{
				client: ts.Client(),
				method: http.MethodPost,
				url:    ts.URL + "/devices/" + tc.id + "/seen",
			}

			res, err := req.make()
			assert.Nil(t, err)
			assert.Equal(t, tc.status, res.StatusCode, tc.desc)
		})
	}
}

func TestOTATrigger(t *testing.T) {
	validBody := toJSON(map[string]any{
		"url":    "https://example.com/agent.bin",
		"sha256": "abc123",
		"size":   uint64(1024),
	})

	cases := []struct {
		desc      string
		body      string
		status    int
		mockSetup func(*agentmocks.Service)
	}{
		{
			desc:   "trigger OTA successfully",
			body:   validBody,
			status: http.StatusAccepted,
			mockSetup: func(svc *agentmocks.Service) {
				svc.On("OTA", mock.Anything, "https://example.com/agent.bin", "abc123", uint64(1024)).
					Return(nil).Maybe()
			},
		},
		{
			desc:      "missing URL returns bad request",
			body:      toJSON(map[string]any{"sha256": "abc123"}),
			status:    http.StatusBadRequest,
			mockSetup: func(_ *agentmocks.Service) {},
		},
		{
			desc:      "invalid JSON returns bad request",
			body:      "}",
			status:    http.StatusBadRequest,
			mockSetup: func(_ *agentmocks.Service) {},
		},
	}

	for _, tc := range cases {
		t.Run(tc.desc, func(t *testing.T) {
			ts, svc := newAgentServer(t)
			defer ts.Close()
			tc.mockSetup(svc)

			req := testRequest{
				client:      ts.Client(),
				method:      http.MethodPost,
				url:         ts.URL + "/ota",
				contentType: contentType,
				body:        strings.NewReader(tc.body),
			}

			res, err := req.make()
			assert.Nil(t, err)
			assert.Equal(t, tc.status, res.StatusCode, tc.desc)
		})
	}
}

func TestOTAStatus(t *testing.T) {
	cases := []struct {
		desc      string
		info      agent.OTAStatusInfo
		mockSetup func(*agentmocks.Service)
	}{
		{
			desc: "idle state",
			info: agent.OTAStatusInfo{Busy: false},
			mockSetup: func(svc *agentmocks.Service) {
				svc.On("OTAStatus").Return(agent.OTAStatusInfo{Busy: false})
			},
		},
		{
			desc: "busy state",
			info: agent.OTAStatusInfo{Busy: true},
			mockSetup: func(svc *agentmocks.Service) {
				svc.On("OTAStatus").Return(agent.OTAStatusInfo{Busy: true})
			},
		},
		{
			desc: "idle with last error",
			info: agent.OTAStatusInfo{Busy: false, LastError: "checksum mismatch"},
			mockSetup: func(svc *agentmocks.Service) {
				svc.On("OTAStatus").Return(agent.OTAStatusInfo{Busy: false, LastError: "checksum mismatch"})
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.desc, func(t *testing.T) {
			ts, svc := newAgentServer(t)
			defer ts.Close()
			tc.mockSetup(svc)

			req := testRequest{
				client: ts.Client(),
				method: http.MethodGet,
				url:    ts.URL + "/ota/status",
			}

			res, err := req.make()
			assert.Nil(t, err)
			assert.Equal(t, http.StatusOK, res.StatusCode, tc.desc)

			var body agent.OTAStatusInfo
			err = json.NewDecoder(res.Body).Decode(&body)
			assert.Nil(t, err)
			assert.Equal(t, tc.info.Busy, body.Busy, tc.desc)
			assert.Equal(t, tc.info.LastError, body.LastError, tc.desc)
		})
	}
}

func TestOTAAbort(t *testing.T) {
	svcErr := mgerrors.New("no OTA in progress")

	cases := []struct {
		desc      string
		status    int
		mockSetup func(*agentmocks.Service)
	}{
		{
			desc:   "abort in-progress OTA",
			status: http.StatusOK,
			mockSetup: func(svc *agentmocks.Service) {
				svc.On("OTAAbort").Return(nil)
			},
		},
		{
			desc:   "abort with no OTA running returns error",
			status: http.StatusInternalServerError,
			mockSetup: func(svc *agentmocks.Service) {
				svc.On("OTAAbort").Return(svcErr)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.desc, func(t *testing.T) {
			ts, svc := newAgentServer(t)
			defer ts.Close()
			tc.mockSetup(svc)

			req := testRequest{
				client: ts.Client(),
				method: http.MethodPost,
				url:    ts.URL + "/ota/abort",
			}

			res, err := req.make()
			assert.Nil(t, err)
			assert.Equal(t, tc.status, res.StatusCode, tc.desc)
		})
	}
}

func TestOTAData(t *testing.T) {
	firmware := []byte("fake agent binary content")

	cases := []struct {
		desc      string
		body      []byte
		sha256    string
		status    int
		mockSetup func(*agentmocks.Service)
	}{
		{
			desc:   "upload firmware with sha256",
			body:   firmware,
			sha256: "abc123def456",
			status: http.StatusAccepted,
			mockSetup: func(svc *agentmocks.Service) {
				svc.On("OTAFromData", mock.Anything, firmware, "abc123def456").
					Return(nil).Maybe()
			},
		},
		{
			desc:      "missing sha256 query param returns bad request",
			body:      firmware,
			sha256:    "",
			status:    http.StatusBadRequest,
			mockSetup: func(_ *agentmocks.Service) {},
		},
		{
			desc:      "empty body returns bad request",
			body:      []byte{},
			sha256:    "abc123",
			status:    http.StatusBadRequest,
			mockSetup: func(_ *agentmocks.Service) {},
		},
	}

	for _, tc := range cases {
		t.Run(tc.desc, func(t *testing.T) {
			ts, svc := newAgentServer(t)
			defer ts.Close()
			tc.mockSetup(svc)

			url := ts.URL + "/ota/data"
			if tc.sha256 != "" {
				url += "?sha256=" + tc.sha256
			}

			req := testRequest{
				client:      ts.Client(),
				method:      http.MethodPost,
				url:         url,
				contentType: "application/octet-stream",
				body:        bytes.NewReader(tc.body),
			}

			res, err := req.make()
			assert.Nil(t, err)
			assert.Equal(t, tc.status, res.StatusCode, tc.desc)
		})
	}
}

func TestControl(t *testing.T) {
	svcErr := mgerrors.New("control failed")

	cases := []struct {
		desc      string
		body      string
		status    int
		mockSetup func(*agentmocks.Service)
	}{
		{
			desc:   "stop agent",
			body:   toJSON(map[string]any{"command": "stop"}),
			status: http.StatusAccepted,
			mockSetup: func(svc *agentmocks.Service) {
				svc.On("Control", "http", "stop").Return(nil)
			},
		},
		{
			desc:   "start agent",
			body:   toJSON(map[string]any{"command": "start"}),
			status: http.StatusAccepted,
			mockSetup: func(svc *agentmocks.Service) {
				svc.On("Control", "http", "start").Return(nil)
			},
		},
		{
			desc:   "reload config",
			body:   toJSON(map[string]any{"command": "reload"}),
			status: http.StatusAccepted,
			mockSetup: func(svc *agentmocks.Service) {
				svc.On("Control", "http", "reload").Return(nil)
			},
		},
		{
			desc:      "invalid command returns bad request",
			body:      toJSON(map[string]any{"command": "bogus"}),
			status:    http.StatusBadRequest,
			mockSetup: func(_ *agentmocks.Service) {},
		},
		{
			desc:   "service error returns internal server error",
			body:   toJSON(map[string]any{"command": "stop"}),
			status: http.StatusInternalServerError,
			mockSetup: func(svc *agentmocks.Service) {
				svc.On("Control", "http", "stop").Return(svcErr)
			},
		},
		{
			desc:      "invalid JSON returns bad request",
			body:      "}",
			status:    http.StatusBadRequest,
			mockSetup: func(_ *agentmocks.Service) {},
		},
	}

	for _, tc := range cases {
		t.Run(tc.desc, func(t *testing.T) {
			ts, svc := newAgentServer(t)
			defer ts.Close()
			tc.mockSetup(svc)

			req := testRequest{
				client:      ts.Client(),
				method:      http.MethodPost,
				url:         ts.URL + "/control",
				contentType: contentType,
				body:        strings.NewReader(tc.body),
			}

			res, err := req.make()
			assert.Nil(t, err)
			assert.Equal(t, tc.status, res.StatusCode, tc.desc)
		})
	}
}

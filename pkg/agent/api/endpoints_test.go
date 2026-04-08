// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

package api_test

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/absmach/agent/pkg/agent"
	"github.com/absmach/agent/pkg/agent/api"
	noderedmocks "github.com/absmach/agent/pkg/nodered/mocks"
	"github.com/absmach/magistrala/logger"
	"github.com/absmach/magistrala/pkg/messaging/brokers"
	paho "github.com/eclipse/paho.mqtt.golang"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

type testRequest struct {
	client *http.Client
	method string
	url    string
	body   io.Reader
}

func (tr testRequest) make() (*http.Response, error) {
	req, err := http.NewRequest(tr.method, tr.url, tr.body)
	if err != nil {
		return nil, err
	}

	return tr.client.Do(req)
}

func newService(ctx context.Context, t *testing.T, nc *noderedmocks.Client) (agent.Service, error) {
	opts := paho.NewClientOptions().
		SetUsername(username).
		AddBroker(mqttAddress).
		SetClientID("testing")

	mqttClient := paho.NewClient(opts)
	token := mqttClient.Connect()
	if token.Error() != nil {
		return nil, token.Error()
	}

	if nc == nil {
		nc = noderedmocks.NewClient(t)
	}
	config := agent.Config{}
	config.Heartbeat.Interval = time.Second

	log, err := logger.New(os.Stdout, "debug")
	if err != nil {
		return nil, err
	}

	pubsub, err := brokers.NewPubSub(ctx, brokerAddress, log)
	if err != nil {
		return nil, fmt.Errorf("Failed to connect to Broker: %s %s", err, brokerAddress)
	}
	t.Cleanup(func() { pubsub.Close() })

	agentSvc, err := agent.New(ctx, mqttClient, &config, nc, pubsub, log)
	if err != nil {
		return nil, err
	}

	return agentSvc, nil
}

func newServer(svc agent.Service) *httptest.Server {
	log, _ := logger.New(os.Stdout, "debug")
	mux := api.MakeHandler(svc, log, "")
	return httptest.NewServer(mux)
}

func toJSON(data interface{}) (string, error) {
	jsonData, err := json.Marshal(data)
	if err != nil {
		return "", err
	}
	return string(jsonData), nil
}

func TestPublish(t *testing.T) {
	svc, err := newService(context.TODO(), t, nil)
	if err != nil {
		t.Errorf("failed to create service: %v", err)
		return
	}
	ts := newServer(svc)
	defer ts.Close()
	client := ts.Client()
	data, err := toJSON(struct {
		Payload string
		Topic   string
	}{
		"payload",
		"topic",
	})
	assert.Nil(t, err, "failed to marshal test data")

	cases := []struct {
		desc   string
		req    string
		status int
	}{
		{"publish data", data, http.StatusOK},
		{"publish data with invalid data", "}", http.StatusInternalServerError},
	}

	for _, tc := range cases {
		req := testRequest{
			client: client,
			method: http.MethodPost,
			url:    fmt.Sprintf("%s/pub", ts.URL),
			body:   strings.NewReader(tc.req),
		}
		res, err := req.make()
		assert.Nil(t, err, fmt.Sprintf("%s: unexpected error %s", tc.desc, err))
		assert.Equal(t, tc.status, res.StatusCode, fmt.Sprintf("%s: expected status code %d got %d", tc.desc, tc.status, res.StatusCode))
	}
}

func TestNodeRed(t *testing.T) {
	nc := noderedmocks.NewClient(t)
	nc.On("Ping").Return("", nil)
	nc.On("FetchFlows").Return("", nil)
	nc.On("DeployFlows", mock.Anything).Return("", nil)

	svc, err := newService(context.TODO(), t, nc)
	if err != nil {
		t.Errorf("failed to create service: %v", err)
		return
	}

	ts := newServer(svc)
	defer ts.Close()
	client := ts.Client()

	validPing, err := toJSON(struct {
		Command string `json:"command"`
	}{
		Command: "nodered-ping",
	})
	assert.Nil(t, err, "failed to marshal test data")

	validFlows, err := toJSON(struct {
		Command string `json:"command"`
	}{
		Command: "nodered-flows",
	})
	assert.Nil(t, err, "failed to marshal test data")

	validDeploy, err := toJSON(struct {
		Command string `json:"command"`
		Flows   string `json:"flows"`
	}{
		Command: "nodered-deploy",
		Flows:   "W10=", // base64 of "[]"
	})
	assert.Nil(t, err, "failed to marshal test data")

	emptyCommand, err := toJSON(struct {
		Command string `json:"command"`
	}{
		Command: "",
	})
	assert.Nil(t, err, "failed to marshal test data")

	cases := []struct {
		desc   string
		req    string
		status int
	}{
		{"nodered ping", validPing, http.StatusOK},
		{"nodered fetch flows", validFlows, http.StatusOK},
		{"nodered deploy flow", validDeploy, http.StatusOK},
		{"nodered empty command", emptyCommand, http.StatusInternalServerError},
		{"nodered invalid json", "}", http.StatusInternalServerError},
	}

	for _, tc := range cases {
		req := testRequest{
			client: client,
			method: http.MethodPost,
			url:    fmt.Sprintf("%s/nodered", ts.URL),
			body:   strings.NewReader(tc.req),
		}
		res, err := req.make()
		assert.Nil(t, err, fmt.Sprintf("%s: unexpected error %s", tc.desc, err))
		assert.Equal(t, tc.status, res.StatusCode, fmt.Sprintf("%s: expected status code %d got %d", tc.desc, tc.status, res.StatusCode))
	}
}

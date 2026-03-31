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
	edgexmocks "github.com/absmach/agent/pkg/edgex/mocks"
	noderedmocks "github.com/absmach/agent/pkg/nodered/mocks"
	paho "github.com/eclipse/paho.mqtt.golang"

	"github.com/absmach/magistrala/logger"
	"github.com/absmach/magistrala/pkg/messaging/brokers"
	"github.com/stretchr/testify/assert"
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

func newService(ctx context.Context, t *testing.T) (agent.Service, error) {
	opts := paho.NewClientOptions().
		SetUsername(username).
		AddBroker(mqttAddress).
		SetClientID("testing")

	mqttClient := paho.NewClient(opts)
	token := mqttClient.Connect()
	if token.Error() != nil {
		return nil, token.Error()
	}

	edgexClient := edgexmocks.NewClient(t)
	noderedClient := noderedmocks.NewClient(t)
	config := agent.Config{}
	config.Heartbeat.Interval = time.Second

	logger, err := logger.New(os.Stdout, "debug")
	if err != nil {
		return nil, err
	}

	pubsub, err := brokers.NewPubSub(ctx, brokerAddress, logger)
	if err != nil {
		return nil, fmt.Errorf("Failed to connect to Broker: %s %s", err, brokerAddress)
	}
	defer pubsub.Close()

	agentSvc, err := agent.New(ctx, mqttClient, &config, edgexClient, noderedClient, pubsub, logger)
	if err != nil {
		return nil, err
	}

	return agentSvc, nil
}

func newServer(svc agent.Service) *httptest.Server {
	mux := api.MakeHandler(svc)
	return httptest.NewServer(mux)
}

func toJSON(data interface{}) string {
	jsonData, _ := json.Marshal(data)
	return string(jsonData)
}

func TestPublish(t *testing.T) {
	svc, err := newService(context.TODO(), t)
	if err != nil {
		t.Errorf("failed to create service: %v", err)
		return
	}
	ts := newServer(svc)
	defer ts.Close()
	client := ts.Client()
	data := toJSON(struct {
		Payload string
		Topic   string
	}{
		"payload",
		"topic",
	})

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
	svc, err := newService(context.TODO(), t)
	if err != nil {
		t.Errorf("failed to create service: %v", err)
		return
	}
	ts := newServer(svc)
	defer ts.Close()
	client := ts.Client()

	validPing := toJSON(struct {
		Command string `json:"command"`
	}{
		Command: "nodered-ping",
	})

	validFlows := toJSON(struct {
		Command string `json:"command"`
	}{
		Command: "nodered-flows",
	})

	validDeploy := toJSON(struct {
		Command string `json:"command"`
		Flows   string `json:"flows"`
	}{
		Command: "nodered-deploy",
		Flows:   "W10=", // base64 of "[]"
	})

	emptyCommand := toJSON(struct {
		Command string `json:"command"`
	}{
		Command: "",
	})

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

// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	"encoding/json"
	"net/http"

	"github.com/absmach/agent/pkg/agent"
	"github.com/absmach/supermq"
	kithttp "github.com/go-kit/kit/transport/http"
	"github.com/go-zoo/bone"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// MakeHandler returns a HTTP handler for API endpoints.
func MakeHandler(svc agent.Service) http.Handler {
	r := bone.New()

	r.Post("/pub", kithttp.NewServer(
		pubEndpoint(svc),
		decodePublishRequest,
		encodeResponse,
	))

	r.Post("/exec", kithttp.NewServer(
		execEndpoint(svc),
		decodeExecRequest,
		encodeResponse,
	))

	r.Post("/config", kithttp.NewServer(
		addConfigEndpoint(svc),
		decodeAddConfigRequest,
		encodeResponse,
	))

	r.Get("/config", kithttp.NewServer(
		viewConfigEndpoint(svc),
		decodeRequest,
		encodeResponse,
	))

	r.Get("/services", kithttp.NewServer(
		viewServicesEndpoint(svc),
		decodeRequest,
		encodeResponse,
	))

	r.Post("/nodered", kithttp.NewServer(
		nodeRedEndpoint(svc),
		decodeNodeRedRequest,
		encodeResponse,
	))

	r.Handle("/metrics", promhttp.Handler())
	r.GetFunc("/health", supermq.Health("agent", ""))

	return r
}

func decodeRequest(_ context.Context, r *http.Request) (interface{}, error) {
	return nil, nil
}

func decodePublishRequest(_ context.Context, r *http.Request) (interface{}, error) {
	req := pubReq{}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		return nil, err
	}

	return req, nil
}

func decodeExecRequest(_ context.Context, r *http.Request) (interface{}, error) {
	req := execReq{}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		return nil, err
	}

	return req, nil
}

func decodeAddConfigRequest(_ context.Context, r *http.Request) (interface{}, error) {
	req := addConfigReq{}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		return nil, err
	}

	return req, nil
}

func decodeNodeRedRequest(_ context.Context, r *http.Request) (interface{}, error) {
	req := nodeRedReq{}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		return nil, err
	}

	return req, nil
}

func encodeResponse(_ context.Context, w http.ResponseWriter, response interface{}) error {
	return json.NewEncoder(w).Encode(response)
}

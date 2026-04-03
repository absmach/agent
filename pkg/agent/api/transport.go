// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"

	"github.com/absmach/agent/pkg/agent"
	"github.com/absmach/supermq"
	smqapi "github.com/absmach/supermq/api/http"
	apiutil "github.com/absmach/supermq/api/http/util"
	"github.com/absmach/supermq/pkg/uuid"
	"github.com/go-chi/chi/v5"
	kithttp "github.com/go-kit/kit/transport/http"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// MakeHandler returns a HTTP handler for API endpoints.
func MakeHandler(svc agent.Service, logger *slog.Logger, instanceID string) http.Handler {
	opts := []kithttp.ServerOption{
		kithttp.ServerErrorEncoder(apiutil.LoggingErrorEncoder(logger, smqapi.EncodeError)),
	}

	idp := uuid.New()
	r := chi.NewRouter()
	r.Use(smqapi.RequestIDMiddleware(idp))

	r.Post("/pub", kithttp.NewServer(
		pubEndpoint(svc),
		decodePublishRequest,
		smqapi.EncodeResponse,
		opts...,
	).ServeHTTP)

	r.Post("/exec", kithttp.NewServer(
		execEndpoint(svc),
		decodeExecRequest,
		smqapi.EncodeResponse,
		opts...,
	).ServeHTTP)

	r.Post("/config", kithttp.NewServer(
		addConfigEndpoint(svc),
		decodeAddConfigRequest,
		smqapi.EncodeResponse,
		opts...,
	).ServeHTTP)

	r.Get("/config", kithttp.NewServer(
		viewConfigEndpoint(svc),
		decodeRequest,
		smqapi.EncodeResponse,
		opts...,
	).ServeHTTP)

	r.Get("/services", kithttp.NewServer(
		viewServicesEndpoint(svc),
		decodeRequest,
		smqapi.EncodeResponse,
		opts...,
	).ServeHTTP)

	r.Post("/nodered", kithttp.NewServer(
		nodeRedEndpoint(svc),
		decodeNodeRedRequest,
		smqapi.EncodeResponse,
		opts...,
	).ServeHTTP)

	r.Handle("/metrics", promhttp.Handler())
	r.Get("/health", supermq.Health("agent", instanceID))

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

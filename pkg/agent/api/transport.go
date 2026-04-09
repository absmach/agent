// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"

	"github.com/absmach/agent/pkg/agent"
	"github.com/absmach/magistrala"
	mgapi "github.com/absmach/magistrala/api/http"
	apiutil "github.com/absmach/magistrala/api/http/util"
	"github.com/absmach/magistrala/pkg/uuid"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	kithttp "github.com/go-kit/kit/transport/http"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// MakeHandler returns a HTTP handler for API endpoints.
func MakeHandler(svc agent.Service, logger *slog.Logger, instanceID string) http.Handler {
	opts := []kithttp.ServerOption{
		kithttp.ServerErrorEncoder(apiutil.LoggingErrorEncoder(logger, mgapi.EncodeError)),
	}

	idp := uuid.New()
	r := chi.NewRouter()
	r.Use(mgapi.RequestIDMiddleware(idp))
	r.Use(middleware.SetHeader("Access-Control-Allow-Origin", "*"))
	r.Use(middleware.SetHeader("Access-Control-Allow-Methods", "GET, POST, OPTIONS"))
	r.Use(middleware.SetHeader("Access-Control-Allow-Headers", "Content-Type"))
	r.MethodFunc(http.MethodOptions, "/*", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})

	r.Post("/pub", kithttp.NewServer(
		pubEndpoint(svc),
		decodePublishRequest,
		mgapi.EncodeResponse,
		opts...,
	).ServeHTTP)

	r.Post("/exec", kithttp.NewServer(
		execEndpoint(svc),
		decodeExecRequest,
		mgapi.EncodeResponse,
		opts...,
	).ServeHTTP)

	r.Post("/config", kithttp.NewServer(
		addConfigEndpoint(svc),
		decodeAddConfigRequest,
		mgapi.EncodeResponse,
		opts...,
	).ServeHTTP)

	r.Get("/config", kithttp.NewServer(
		viewConfigEndpoint(svc),
		decodeRequest,
		mgapi.EncodeResponse,
		opts...,
	).ServeHTTP)

	r.Get("/services", kithttp.NewServer(
		viewServicesEndpoint(svc),
		decodeRequest,
		mgapi.EncodeResponse,
		opts...,
	).ServeHTTP)

	r.Post("/nodered", kithttp.NewServer(
		nodeRedEndpoint(svc),
		decodeNodeRedRequest,
		mgapi.EncodeResponse,
		opts...,
	).ServeHTTP)

	r.Handle("/metrics", promhttp.Handler())
	r.Get("/health", magistrala.Health("agent", instanceID))

	return r
}

func decodeRequest(_ context.Context, r *http.Request) (any, error) {
	return nil, nil
}

func decodePublishRequest(_ context.Context, r *http.Request) (any, error) {
	req := pubReq{}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		return nil, err
	}

	return req, nil
}

func decodeExecRequest(_ context.Context, r *http.Request) (any, error) {
	req := execReq{}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		return nil, err
	}

	return req, nil
}

func decodeAddConfigRequest(_ context.Context, r *http.Request) (any, error) {
	req := addConfigReq{}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		return nil, err
	}

	return req, nil
}

func decodeNodeRedRequest(_ context.Context, r *http.Request) (any, error) {
	req := nodeRedReq{}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		return nil, err
	}

	return req, nil
}

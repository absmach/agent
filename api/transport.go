// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"

	"github.com/absmach/agent"
	"github.com/absmach/agent/pkg/logstream"
	agentui "github.com/absmach/agent/ui"
	"github.com/absmach/magistrala"
	mgapi "github.com/absmach/magistrala/api/http"
	apiutil "github.com/absmach/magistrala/api/http/util"
	mgerrors "github.com/absmach/magistrala/pkg/errors"
	"github.com/absmach/magistrala/pkg/uuid"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	kithttp "github.com/go-kit/kit/transport/http"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// MakeHandler returns a HTTP handler for API endpoints.
func MakeHandler(svc agent.Service, logger *slog.Logger, stream *logstream.Stream, instanceID string) http.Handler {
	opts := []kithttp.ServerOption{
		kithttp.ServerErrorEncoder(apiutil.LoggingErrorEncoder(logger, EncodeError)),
	}

	idp := uuid.New()
	r := chi.NewRouter()
	r.Use(mgapi.RequestIDMiddleware(idp))
	r.Use(middleware.SetHeader("Access-Control-Allow-Origin", "*"))
	r.Use(middleware.SetHeader("Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS"))
	r.Use(middleware.SetHeader("Access-Control-Allow-Headers", "Content-Type"))
	r.MethodFunc(http.MethodOptions, "/*", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})

	r.Post("/pub", kithttp.NewServer(
		pubEndpoint(svc),
		decodePublishRequest,
		EncodeResponse,
		opts...,
	).ServeHTTP)

	r.Post("/exec", kithttp.NewServer(
		execEndpoint(svc),
		decodeExecRequest,
		EncodeResponse,
		opts...,
	).ServeHTTP)

	r.Post("/config", kithttp.NewServer(
		addConfigEndpoint(svc),
		decodeAddConfigRequest,
		EncodeResponse,
		opts...,
	).ServeHTTP)

	r.Get("/config", kithttp.NewServer(
		viewConfigEndpoint(svc),
		decodeRequest,
		EncodeResponse,
		opts...,
	).ServeHTTP)

	r.Get("/services", kithttp.NewServer(
		viewServicesEndpoint(svc),
		decodeRequest,
		EncodeResponse,
		opts...,
	).ServeHTTP)

	r.Post("/nodered", kithttp.NewServer(
		nodeRedEndpoint(svc),
		decodeNodeRedRequest,
		EncodeResponse,
		opts...,
	).ServeHTTP)

	r.Get("/devices", kithttp.NewServer(
		listDevicesEndpoint(svc),
		decodeRequest,
		EncodeResponse,
		opts...,
	).ServeHTTP)
	r.Post("/devices", kithttp.NewServer(
		addDeviceEndpoint(svc),
		decodeAddDeviceRequest,
		EncodeResponse,
		opts...,
	).ServeHTTP)
	r.Get("/devices/{id}", kithttp.NewServer(
		getDeviceEndpoint(svc),
		decodeIDFromPath,
		EncodeResponse,
		opts...,
	).ServeHTTP)
	r.Delete("/devices/{id}", kithttp.NewServer(
		removeDeviceEndpoint(svc),
		decodeIDFromPath,
		EncodeResponse,
		opts...,
	).ServeHTTP)
	r.Post("/devices/{id}/seen", kithttp.NewServer(
		markDeviceSeenEndpoint(svc),
		decodeIDFromPath,
		EncodeResponse,
		opts...,
	).ServeHTTP)
	r.Post("/reset", kithttp.NewServer(
		resetEndpoint(svc),
		decodeResetRequest,
		EncodeResponse,
		opts...,
	).ServeHTTP)

	r.Get("/config/runtime", kithttp.NewServer(
		runtimeConfigGetEndpoint(svc),
		decodeRequest,
		EncodeResponse,
		opts...,
	).ServeHTTP)
	r.Post("/config/runtime", kithttp.NewServer(
		runtimeConfigSetEndpoint(svc),
		decodeRuntimeConfigRequest,
		EncodeResponse,
		opts...,
	).ServeHTTP)

	r.Post("/devices/{id}/open", kithttp.NewServer(
		openDeviceEndpoint(svc),
		decodeIDFromPath,
		EncodeResponse,
		opts...,
	).ServeHTTP)
	r.Post("/devices/{id}/close", kithttp.NewServer(
		closeDeviceEndpoint(svc),
		decodeIDFromPath,
		EncodeResponse,
		opts...,
	).ServeHTTP)
	r.Post("/devices/{id}/read", kithttp.NewServer(
		readDeviceEndpoint(svc),
		decodeDeviceReadRequest,
		EncodeResponse,
		opts...,
	).ServeHTTP)
	r.Post("/devices/{id}/write", kithttp.NewServer(
		writeDeviceEndpoint(svc),
		decodeDeviceWriteRequest,
		EncodeResponse,
		opts...,
	).ServeHTTP)

	r.Post("/ota", kithttp.NewServer(
		otaTriggerEndpoint(svc),
		decodeOTATriggerRequest,
		EncodeResponse,
		opts...,
	).ServeHTTP)
	r.Get("/ota/status", kithttp.NewServer(
		otaStatusEndpoint(svc),
		decodeRequest,
		EncodeResponse,
		opts...,
	).ServeHTTP)

	r.Handle("/metrics", promhttp.Handler())
	r.Get("/health", magistrala.Health("agent", instanceID))
	r.Get("/terminal/ws", terminalWSHandler(logger))
	if stream != nil {
		r.Handle("/logs", logstream.SSEHandler(stream))
	}

	r.Get("/", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/ui/", http.StatusFound)
	})
	r.Get("/ui", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/ui/", http.StatusFound)
	})
	r.Handle("/ui/*", http.StripPrefix("/ui", agentui.Handler()))

	return r
}

func decodeRequest(_ context.Context, r *http.Request) (any, error) {
	return nil, nil
}

func decodePublishRequest(_ context.Context, r *http.Request) (any, error) {
	req := pubReq{}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		return nil, mgerrors.Wrap(apiutil.ErrMalformedRequestBody, err)
	}

	return req, nil
}

func decodeExecRequest(_ context.Context, r *http.Request) (any, error) {
	req := execReq{}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		return nil, mgerrors.Wrap(apiutil.ErrMalformedRequestBody, err)
	}

	return req, nil
}

func decodeAddConfigRequest(_ context.Context, r *http.Request) (any, error) {
	req := addConfigReq{}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		return nil, mgerrors.Wrap(apiutil.ErrMalformedRequestBody, err)
	}

	return req, nil
}

func decodeNodeRedRequest(_ context.Context, r *http.Request) (any, error) {
	req := nodeRedReq{}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		return nil, mgerrors.Wrap(apiutil.ErrMalformedRequestBody, err)
	}

	return req, nil
}

func decodeAddDeviceRequest(_ context.Context, r *http.Request) (any, error) {
	req := addDeviceReq{}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		return nil, mgerrors.Wrap(apiutil.ErrMalformedRequestBody, err)
	}
	return req, nil
}

func decodeResetRequest(_ context.Context, r *http.Request) (any, error) {
	req := resetReq{}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		return nil, mgerrors.Wrap(apiutil.ErrMalformedRequestBody, err)
	}
	return req, nil
}

func decodeOTATriggerRequest(_ context.Context, r *http.Request) (any, error) {
	req := otaTriggerReq{}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		return nil, mgerrors.Wrap(apiutil.ErrMalformedRequestBody, err)
	}
	return req, nil
}

func decodeRuntimeConfigRequest(_ context.Context, r *http.Request) (any, error) {
	req := runtimeConfigReq{}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		return nil, mgerrors.Wrap(apiutil.ErrMalformedRequestBody, err)
	}
	return req, nil
}

func decodeDeviceReadRequest(_ context.Context, r *http.Request) (any, error) {
	id := chi.URLParam(r, "id")
	req := decodeIDPayload{ID: id}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		return nil, mgerrors.Wrap(apiutil.ErrMalformedRequestBody, err)
	}
	req.ID = id
	return req, nil
}

func decodeDeviceWriteRequest(_ context.Context, r *http.Request) (any, error) {
	id := chi.URLParam(r, "id")
	req := decodeIDPayload{ID: id}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		return nil, mgerrors.Wrap(apiutil.ErrMalformedRequestBody, err)
	}
	req.ID = id
	return req, nil
}

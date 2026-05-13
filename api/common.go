// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	"encoding/json"
	"net/http"

	"github.com/absmach/magistrala"
	"github.com/absmach/magistrala/pkg/errors"
)

const (
	// ContentType represents JSON content type.
	ContentType = "application/json"
)

// EncodeResponse encodes successful response.
func EncodeResponse(_ context.Context, w http.ResponseWriter, response any) error {
	if ar, ok := response.(magistrala.Response); ok {
		for k, v := range ar.Headers() {
			w.Header().Set(k, v)
		}
		w.Header().Set("Content-Type", ContentType)
		w.WriteHeader(ar.Code())

		if ar.Empty() {
			return nil
		}
	}

	return json.NewEncoder(w).Encode(response)
}

// EncodeError encodes an error response.
func EncodeError(_ context.Context, err error, w http.ResponseWriter) {
	w.Header().Set("Content-Type", ContentType)
	if sdkErr, ok := err.(errors.SDKError); ok {
		w.WriteHeader(sdkErr.StatusCode())
		if err := json.NewEncoder(w).Encode(sdkErr); err != nil {
			w.WriteHeader(http.StatusInternalServerError)
		}
		return
	}

	switch retErr := err.(type) {
	case *errors.RequestError:
		w.WriteHeader(http.StatusBadRequest)
		if err := json.NewEncoder(w).Encode(retErr); err != nil {
			w.WriteHeader(http.StatusInternalServerError)
		}
		return
	case *errors.AuthNError:
		w.WriteHeader(http.StatusUnauthorized)
		if err := json.NewEncoder(w).Encode(retErr); err != nil {
			w.WriteHeader(http.StatusInternalServerError)
		}
		return
	case *errors.AuthZError:
		w.WriteHeader(http.StatusForbidden)
		if err := json.NewEncoder(w).Encode(retErr); err != nil {
			w.WriteHeader(http.StatusInternalServerError)
		}
		return
	case *errors.MediaTypeError:
		w.WriteHeader(http.StatusUnsupportedMediaType)
		if err := json.NewEncoder(w).Encode(retErr); err != nil {
			w.WriteHeader(http.StatusInternalServerError)
		}
		return
	case *errors.ServiceError:
		w.WriteHeader(http.StatusUnprocessableEntity)
		if err := json.NewEncoder(w).Encode(retErr); err != nil {
			w.WriteHeader(http.StatusInternalServerError)
		}
		return
	case *errors.NotFoundError:
		w.WriteHeader(http.StatusNotFound)
		if err := json.NewEncoder(w).Encode(retErr); err != nil {
			w.WriteHeader(http.StatusInternalServerError)
		}
		return
	case *errors.InternalError:
		w.WriteHeader(http.StatusInternalServerError)
		return
	default:
		w.WriteHeader(http.StatusInternalServerError)
	}
}

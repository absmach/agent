// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

package remote

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"github.com/gofrs/uuid/v5"
)

const (
	JSONRPCVersion = "2.0"
	APIVersion     = "1"

	CodeParseError     = -32700
	CodeInvalidRequest = -32600
	CodeMethodNotFound = -32601
	CodeInvalidParams  = -32602
	CodeInternalError  = -32603

	CodeRequestExpired   = -32001
	CodeRequestConflict  = -32002
	CodeRequestRunning   = -32003
	CodeUnauthorized     = -32004
	CodeRevisionConflict = -32005
	CodeJobNotFound      = -32006
	CodeStreamNotFound   = -32007
	CodeResourceLimit    = -32008
)

// Request is the JSON-RPC 2.0 request carried by an MQTT 5 PUBLISH.
// Null IDs and batch requests are deliberately unsupported by this profile.
type Request struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      string          `json:"id"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

// Response is the JSON-RPC 2.0 response carried by an MQTT 5 PUBLISH.
type Response struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      string          `json:"id"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   *RPCError       `json:"error,omitempty"`
}

// RPCError is the structured JSON-RPC error object.
type RPCError struct {
	Code    int             `json:"code"`
	Message string          `json:"message"`
	Data    json.RawMessage `json:"data,omitempty"`
}

func (e *RPCError) Error() string {
	if e == nil {
		return ""
	}
	return e.Message
}

func ErrorResponse(id string, code int, message string, data any) Response {
	rpcErr := &RPCError{Code: code, Message: message}
	if data != nil {
		if encoded, err := json.Marshal(data); err == nil {
			rpcErr.Data = encoded
		}
	}
	return Response{JSONRPC: JSONRPCVersion, ID: id, Error: rpcErr}
}

func ResultResponse(id string, value any) Response {
	encoded, err := json.Marshal(value)
	if err != nil {
		return ErrorResponse(id, CodeInternalError, "failed to encode result", nil)
	}
	return Response{JSONRPC: JSONRPCVersion, ID: id, Result: encoded}
}

// DecodeRequest rejects batches, notifications, null IDs and unknown envelope
// fields. Method-specific parameter validation is performed by the executor.
func DecodeRequest(payload []byte) (Request, *RPCError) {
	trimmed := bytes.TrimSpace(payload)
	if len(trimmed) == 0 {
		return Request{}, &RPCError{Code: CodeParseError, Message: "empty JSON-RPC payload"}
	}
	if trimmed[0] == '[' {
		return Request{}, &RPCError{Code: CodeInvalidRequest, Message: "batch requests are not supported"}
	}
	decoder := json.NewDecoder(bytes.NewReader(trimmed))
	decoder.DisallowUnknownFields()
	var req Request
	if err := decoder.Decode(&req); err != nil {
		return Request{}, &RPCError{Code: CodeParseError, Message: "invalid JSON-RPC payload", Data: mustJSON(map[string]string{"reason": err.Error()})}
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return Request{}, &RPCError{Code: CodeParseError, Message: "multiple JSON values are not allowed"}
	}
	if req.JSONRPC != JSONRPCVersion || req.ID == "" || req.Method == "" {
		return req, &RPCError{Code: CodeInvalidRequest, Message: "jsonrpc, id and method are required"}
	}
	if _, err := uuid.FromString(req.ID); err != nil {
		return req, &RPCError{Code: CodeInvalidRequest, Message: "id must be a UUID"}
	}
	if len(req.Params) == 0 {
		req.Params = json.RawMessage(`{}`)
	}
	if !json.Valid(req.Params) {
		return req, &RPCError{Code: CodeInvalidParams, Message: "params must be valid JSON"}
	}
	return req, nil
}

// CorrelationData returns the required 16-byte MQTT Correlation Data value.
func CorrelationData(id string) ([]byte, error) {
	parsed, err := uuid.FromString(id)
	if err != nil {
		return nil, err
	}
	value := parsed.Bytes()
	return value, nil
}

func CorrelationMatches(id string, correlation []byte) bool {
	expected, err := CorrelationData(id)
	return err == nil && bytes.Equal(expected, correlation)
}

func RequestHash(req Request) string {
	compact := bytes.Buffer{}
	if err := json.Compact(&compact, req.Params); err != nil {
		compact.Write(req.Params)
	}
	sum := sha256.Sum256(append(append([]byte(req.Method), 0), compact.Bytes()...))
	return hex.EncodeToString(sum[:])
}

func DecodeParams[T any](raw json.RawMessage) (T, *RPCError) {
	var value T
	if len(raw) == 0 {
		raw = json.RawMessage(`{}`)
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&value); err != nil {
		return value, &RPCError{
			Code:    CodeInvalidParams,
			Message: "invalid method parameters",
			Data:    mustJSON(map[string]string{"reason": err.Error()}),
		}
	}
	return value, nil
}

func RPCErrorFrom(err error) *RPCError {
	if err == nil {
		return nil
	}
	var rpcErr *RPCError
	if errors.As(err, &rpcErr) {
		return rpcErr
	}
	return &RPCError{Code: CodeInternalError, Message: err.Error()}
}

func mustJSON(value any) json.RawMessage {
	encoded, err := json.Marshal(value)
	if err != nil {
		return json.RawMessage(fmt.Sprintf("%q", err.Error()))
	}
	return encoded
}

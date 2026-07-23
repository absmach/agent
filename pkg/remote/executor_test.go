// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

package remote_test

import (
	"context"
	"encoding/json"
	"path/filepath"
	"testing"

	"github.com/absmach/agent/mocks"
	"github.com/absmach/agent/pkg/remote"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestExecutorReplaysMutatingRequest(t *testing.T) {
	store, err := remote.NewStore(filepath.Join(t.TempDir(), "remote.db"))
	require.NoError(t, err)
	defer store.Close()
	svc := mocks.NewService(t)
	svc.EXPECT().RegisterService("modbus", "driver").Return(nil).Once()
	executor := remote.NewExecutor(svc, store, nil)
	request := remote.Request{
		JSONRPC: remote.JSONRPCVersion, ID: requestID, Method: "service.register",
		Params: json.RawMessage(`{"name":"modbus","type":"driver"}`),
	}

	first := executor.Execute(context.Background(), request)
	second := executor.Execute(context.Background(), request)
	require.Nil(t, first.Error)
	require.Nil(t, second.Error)
	assert.JSONEq(t, string(first.Result), string(second.Result))
}

func TestExecutorRejectsRequestIDConflict(t *testing.T) {
	store, err := remote.NewStore(filepath.Join(t.TempDir(), "remote.db"))
	require.NoError(t, err)
	defer store.Close()
	svc := mocks.NewService(t)
	svc.EXPECT().RegisterService("one", "driver").Return(nil).Once()
	executor := remote.NewExecutor(svc, store, nil)

	first := remote.Request{
		JSONRPC: remote.JSONRPCVersion, ID: requestID, Method: "service.register",
		Params: json.RawMessage(`{"name":"one","type":"driver"}`),
	}
	second := first
	second.Params = json.RawMessage(`{"name":"two","type":"driver"}`)
	require.Nil(t, executor.Execute(context.Background(), first).Error)
	response := executor.Execute(context.Background(), second)
	require.NotNil(t, response.Error)
	assert.Equal(t, remote.CodeRequestConflict, response.Error.Code)
}

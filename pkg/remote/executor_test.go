// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

package remote_test

import (
	"context"
	"encoding/json"
	"path/filepath"
	"testing"
	"time"

	"github.com/absmach/agent"
	"github.com/absmach/agent/mocks"
	"github.com/absmach/agent/pkg/remote"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
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

func TestConfigApplyChecksRevisionWhenJobExecutes(t *testing.T) {
	store, err := remote.NewStore(filepath.Join(t.TempDir(), "remote.db"))
	require.NoError(t, err)
	defer store.Close()
	svc := mocks.NewService(t)
	current := agent.Config{
		TenantID: "domain",
		Channels: agent.ChanConfig{CtrlID: "control", DataID: "data"},
		MQTT: agent.MQTTConfig{
			URL: "tcp://broker:1883", Username: "agent", Password: "secret",
		},
	}
	entered := make(chan struct{})
	release := make(chan struct{})
	svc.EXPECT().Config().Return(current).Once()
	svc.EXPECT().AddConfig(mock.AnythingOfType("agent.Config")).
		Run(func(agent.Config) {
			close(entered)
			<-release
		}).
		Return(nil).
		Once()
	executor := remote.NewExecutor(svc, store, nil)
	params := json.RawMessage(`{
		"config": {
			"tenant_id": "domain",
			"channels": {"ctrl_id": "control", "data_id": "data"},
			"mqtt": {"url": "tcp://broker:1883", "username": "agent", "password": "secret"}
		},
		"expectedRevision": 1
	}`)
	first := executor.Execute(context.Background(), remote.Request{
		JSONRPC: remote.JSONRPCVersion,
		ID:      "720f4494-d822-4f73-bb10-c74d0eaf8865",
		Method:  "config.apply",
		Params:  params,
	})
	require.Nil(t, first.Error)
	select {
	case <-entered:
	case <-time.After(time.Second):
		require.Fail(t, "first config job did not start")
	}

	second := executor.Execute(context.Background(), remote.Request{
		JSONRPC: remote.JSONRPCVersion,
		ID:      "e9e3ca94-98df-42b8-8ea9-27386d577f9f",
		Method:  "config.apply",
		Params:  params,
	})
	require.Nil(t, second.Error)
	close(release)

	require.Eventually(t, func() bool {
		jobs, listErr := store.ListJobs()
		if listErr != nil || len(jobs) != 2 {
			return false
		}
		terminal := 0
		for _, job := range jobs {
			if job.State == remote.JobSucceeded || job.State == remote.JobFailed {
				terminal++
			}
		}
		return terminal == 2
	}, time.Second, 10*time.Millisecond)

	jobs, err := store.ListJobs()
	require.NoError(t, err)
	succeeded, failed := 0, 0
	for _, job := range jobs {
		switch job.State {
		case remote.JobSucceeded:
			succeeded++
		case remote.JobFailed:
			failed++
			assert.Contains(t, job.Error, "revision conflict")
		}
	}
	assert.Equal(t, 1, succeeded)
	assert.Equal(t, 1, failed)
}

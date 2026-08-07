// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

package remote_test

import (
	"encoding/json"
	"path/filepath"
	"testing"
	"time"

	"github.com/absmach/agent/pkg/remote"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestStoreRequestDeduplication(t *testing.T) {
	store, err := remote.NewStore(filepath.Join(t.TempDir(), "remote.db"))
	require.NoError(t, err)
	defer store.Close()

	expires := time.Now().Add(time.Hour)
	result, _, err := store.BeginRequest(requestID, "service.register", "hash-a", expires)
	require.NoError(t, err)
	assert.Equal(t, remote.BeginNew, result)

	result, _, err = store.BeginRequest(requestID, "service.register", "hash-a", expires)
	require.NoError(t, err)
	assert.Equal(t, remote.BeginRunning, result)

	result, _, err = store.BeginRequest(requestID, "service.register", "hash-b", expires)
	require.NoError(t, err)
	assert.Equal(t, remote.BeginConflict, result)

	response := remote.ResultResponse(requestID, map[string]string{"status": "registered"})
	require.NoError(t, store.CompleteRequest(requestID, response))
	result, replay, err := store.BeginRequest(requestID, "service.register", "hash-a", expires)
	require.NoError(t, err)
	assert.Equal(t, remote.BeginReplay, result)
	assert.JSONEq(t, string(response.Result), string(replay.Result))
}

func TestStoreAllowsExpiredRequestIDToBeReused(t *testing.T) {
	store, err := remote.NewStore(filepath.Join(t.TempDir(), "remote.db"))
	require.NoError(t, err)
	defer store.Close()

	result, _, err := store.BeginRequest(
		requestID,
		"service.register",
		"old-hash",
		time.Now().Add(-time.Second),
	)
	require.NoError(t, err)
	assert.Equal(t, remote.BeginNew, result)

	result, _, err = store.BeginRequest(
		requestID,
		"device.register",
		"new-hash",
		time.Now().Add(time.Hour),
	)
	require.NoError(t, err)
	assert.Equal(t, remote.BeginNew, result)
}

func TestStorePersistsJobs(t *testing.T) {
	path := filepath.Join(t.TempDir(), "remote.db")
	store, err := remote.NewStore(path)
	require.NoError(t, err)
	job := remote.Job{
		ID: "job-1", Type: "backup.create", State: remote.JobSucceeded,
		Result: json.RawMessage(`{"devices":1}`),
	}
	require.NoError(t, store.PutJob(job))
	require.NoError(t, store.Close())

	reopened, err := remote.NewStore(path)
	require.NoError(t, err)
	defer reopened.Close()
	got, err := reopened.GetJob("job-1")
	require.NoError(t, err)
	assert.Equal(t, remote.JobSucceeded, got.State)
	assert.JSONEq(t, `{"devices":1}`, string(got.Result))
}

func TestStorePersistsDesiredGeneration(t *testing.T) {
	path := filepath.Join(t.TempDir(), "remote.db")
	store, err := remote.NewStore(path)
	require.NoError(t, err)
	require.NoError(t, store.SetDesiredGeneration(42))
	require.NoError(t, store.Close())

	reopened, err := remote.NewStore(path)
	require.NoError(t, err)
	defer reopened.Close()
	generation, err := reopened.DesiredGeneration()
	require.NoError(t, err)
	assert.Equal(t, uint64(42), generation)
}

func TestJobManagerFailsInterruptedJobsOnRestart(t *testing.T) {
	store, err := remote.NewStore(filepath.Join(t.TempDir(), "remote.db"))
	require.NoError(t, err)
	defer store.Close()
	require.NoError(t, store.PutJob(remote.Job{
		ID: "interrupted", Type: "firmware.update", State: remote.JobRunning,
	}))

	_ = remote.NewJobManager(store, nil)
	job, err := store.GetJob("interrupted")
	require.NoError(t, err)
	assert.Equal(t, remote.JobFailed, job.State)
	assert.Equal(t, "interrupted", job.Phase)
	assert.NotEmpty(t, job.Error)
}

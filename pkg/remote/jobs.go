// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

package remote

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/gofrs/uuid/v5"
)

type JobPublisher func(Job)

// JobManager executes long-running work outside the RPC request lifetime while
// persisting every state transition.
type JobManager struct {
	store   *Store
	publish JobPublisher
	mu      sync.Mutex
	cancel  map[string]context.CancelFunc
	maxJobs int
}

func NewJobManager(store *Store, publish JobPublisher) *JobManager {
	manager := &JobManager{store: store, publish: publish, cancel: make(map[string]context.CancelFunc), maxJobs: 4}
	manager.failInterrupted()
	return manager
}

func (m *JobManager) failInterrupted() {
	jobs, err := m.store.ListJobs()
	if err != nil {
		return
	}
	for _, job := range jobs {
		switch job.State {
		case JobQueued, JobRunning, JobWaiting:
			job.State = JobFailed
			job.Phase = "interrupted"
			job.Error = "agent restarted before the job completed"
			job.UpdatedAt = time.Now().UTC()
			if m.store.PutJob(job) == nil {
				job, _ = m.store.GetJob(job.ID)
				m.emit(job)
			}
		}
	}
}

func (m *JobManager) Start(parent context.Context, jobType string, run func(context.Context, func(string, float64)) (any, error)) (Job, error) {
	m.mu.Lock()
	if len(m.cancel) >= m.maxJobs {
		m.mu.Unlock()
		return Job{}, fmt.Errorf("too many concurrent jobs")
	}
	m.mu.Unlock()
	id, err := uuid.NewV4()
	if err != nil {
		return Job{}, err
	}
	job := Job{ID: id.String(), Type: jobType, State: JobQueued}
	if err := m.store.PutJob(job); err != nil {
		return Job{}, err
	}
	job, _ = m.store.GetJob(job.ID)
	m.emit(job)

	ctx, cancel := context.WithCancel(context.WithoutCancel(parent))
	m.mu.Lock()
	if len(m.cancel) >= m.maxJobs {
		m.mu.Unlock()
		cancel()
		job.State = JobFailed
		job.Phase = "rejected"
		job.Error = "too many concurrent jobs"
		_ = m.store.PutJob(job)
		return Job{}, fmt.Errorf("too many concurrent jobs")
	}
	m.cancel[job.ID] = cancel
	m.mu.Unlock()

	go func() {
		defer func() {
			m.mu.Lock()
			delete(m.cancel, job.ID)
			m.mu.Unlock()
			cancel()
		}()

		current, err := m.store.GetJob(job.ID)
		if err != nil {
			return
		}
		current.State = JobRunning
		current.Phase = "running"
		_ = m.store.PutJob(current)
		current, _ = m.store.GetJob(job.ID)
		m.emit(current)

		update := func(phase string, progress float64) {
			latest, getErr := m.store.GetJob(job.ID)
			if getErr != nil {
				return
			}
			latest.Phase = phase
			latest.Progress = progress
			_ = m.store.PutJob(latest)
			latest, _ = m.store.GetJob(job.ID)
			m.emit(latest)
		}

		result, runErr := run(ctx, update)
		latest, getErr := m.store.GetJob(job.ID)
		if getErr != nil {
			return
		}
		if ctx.Err() != nil {
			latest.State = JobCancelled
			latest.Error = "cancelled"
		} else if runErr != nil {
			latest.State = JobFailed
			latest.Error = runErr.Error()
		} else {
			latest.State = JobSucceeded
			latest.Progress = 100
			latest.Phase = "complete"
			if result != nil {
				latest.Result, _ = json.Marshal(result)
			}
		}
		_ = m.store.PutJob(latest)
		latest, _ = m.store.GetJob(job.ID)
		m.emit(latest)
	}()

	return job, nil
}

func (m *JobManager) Get(id string) (Job, *RPCError) {
	job, err := m.store.GetJob(id)
	if err != nil {
		return Job{}, &RPCError{Code: CodeJobNotFound, Message: fmt.Sprintf("job %q not found", id)}
	}
	return job, nil
}

func (m *JobManager) List() ([]Job, error) {
	return m.store.ListJobs()
}

func (m *JobManager) Cancel(id string) (Job, *RPCError) {
	job, rpcErr := m.Get(id)
	if rpcErr != nil {
		return Job{}, rpcErr
	}
	switch job.State {
	case JobSucceeded, JobFailed, JobCancelled:
		return job, nil
	}
	m.mu.Lock()
	cancel := m.cancel[id]
	m.mu.Unlock()
	if cancel == nil {
		return Job{}, &RPCError{Code: CodeInternalError, Message: "job is not running in this process"}
	}
	cancel()
	job.State = JobCancelled
	job.Error = "cancelled"
	_ = m.store.PutJob(job)
	job, _ = m.store.GetJob(id)
	m.emit(job)
	return job, nil
}

func (m *JobManager) emit(job Job) {
	if m.publish != nil {
		m.publish(job)
	}
}

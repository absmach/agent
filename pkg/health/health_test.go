// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

package health_test

import (
	"context"
	"io"
	"log/slog"
	"sync"
	"testing"
	"time"

	"github.com/absmach/agent/pkg/health"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type mockMQTT struct {
	mu        sync.Mutex
	connected bool
}

func (m *mockMQTT) IsConnected() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.connected
}

type mockChecker struct {
	mu      sync.Mutex
	name    string
	healthy bool
}

func (c *mockChecker) Name() string      { return c.name }
func (c *mockChecker) Healthy() bool     { c.mu.Lock(); defer c.mu.Unlock(); return c.healthy }
func (c *mockChecker) SetHealthy(v bool) { c.mu.Lock(); defer c.mu.Unlock(); c.healthy = v }

func TestSupervisorDisabled(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	sup := health.NewSupervisor(health.Config{Interval: 0}, logger)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err := sup.Run(ctx)
	require.ErrorIs(t, err, context.Canceled)
}

func TestSupervisorHealthy(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	sup := health.NewSupervisor(health.Config{
		Interval: 10 * time.Millisecond,
		Timeout:  50 * time.Millisecond,
	}, logger)

	checker := &mockChecker{name: "test", healthy: true}
	sup.Register(checker)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- sup.Run(ctx)
	}()

	time.Sleep(30 * time.Millisecond)
	assert.True(t, sup.IsHealthy())

	cancel()
	require.ErrorIs(t, <-done, context.Canceled)
}

func TestSupervisorUnhealthyTriggersRestart(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	sup := health.NewSupervisor(health.Config{
		Interval: 10 * time.Millisecond,
		Timeout:  25 * time.Millisecond,
	}, logger)

	checker := &mockChecker{name: "test", healthy: true}
	sup.Register(checker)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- sup.Run(ctx)
	}()

	time.Sleep(20 * time.Millisecond)
	assert.True(t, sup.IsHealthy())

	checker.SetHealthy(false)
	time.Sleep(20 * time.Millisecond)
	assert.False(t, sup.IsHealthy())

	cancel()
	require.ErrorIs(t, <-done, context.Canceled)
}

func TestMQTTChecker(t *testing.T) {
	mock := &mockMQTT{connected: true}
	checker := health.NewMQTTChecker(mock)

	assert.Equal(t, "mqtt", checker.Name())
	assert.True(t, checker.Healthy())

	mock.connected = false
	assert.False(t, checker.Healthy())
}

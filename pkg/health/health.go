// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

package health

import (
	"context"
	"log/slog"
	"net"
	"os"
	"sync/atomic"
	"syscall"
	"time"
)

// MQTTClient is the subset of the Paho MQTT client interface required for
// health checks.
type MQTTClient interface {
	IsConnected() bool
}

// HealthChecker is the interface for subsystem health checks.
type HealthChecker interface {
	Name() string
	Healthy() bool
}

// Config holds the health supervisor configuration.
type Config struct {
	// Interval is how often to run health checks. Zero disables supervision.
	Interval time.Duration
	// Timeout is how long the agent can be unhealthy before triggering a
	// restart. Defaults to 60s if zero.
	Timeout time.Duration
}

// Supervisor periodically checks registered health checkers and triggers a
// process restart if the agent remains unhealthy for longer than the
// configured timeout.
type Supervisor struct {
	checkers []HealthChecker
	interval time.Duration
	timeout  time.Duration
	logger   *slog.Logger
	healthy  atomic.Bool
}

// NewSupervisor creates a new health supervisor. If cfg.Interval is zero the
// supervisor is effectively disabled.
func NewSupervisor(cfg Config, logger *slog.Logger) *Supervisor {
	timeout := cfg.Timeout
	if timeout == 0 {
		timeout = 60 * time.Second
	}
	s := &Supervisor{
		interval: cfg.Interval,
		timeout:  timeout,
		logger:   logger,
	}
	s.healthy.Store(true)
	return s
}

// Register adds a health checker to the supervisor.
func (s *Supervisor) Register(c HealthChecker) {
	s.checkers = append(s.checkers, c)
}

// Run starts the health check loop. It blocks until ctx is cancelled.
// When running under systemd (NOTIFY_SOCKET is set), it also sends periodic
// WATCHDOG=1 notifications.
func (s *Supervisor) Run(ctx context.Context) error {
	if s.interval <= 0 {
		<-ctx.Done()
		return ctx.Err()
	}

	// Start systemd watchdog notifier if applicable.
	socketPath := os.Getenv("NOTIFY_SOCKET")
	if socketPath != "" {
		s.logger.Info("Running under systemd watchdog", slog.String("socket", socketPath))
		go s.sdWatchdogLoop(ctx, socketPath)
	}

	ticker := time.NewTicker(s.interval)
	defer ticker.Stop()

	unhealthySince := time.Time{}

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			anyUnhealthy := false
			for _, c := range s.checkers {
				if !c.Healthy() {
					s.logger.Warn("Health check failed", slog.String("checker", c.Name()))
					anyUnhealthy = true
				}
			}

			if anyUnhealthy {
				if unhealthySince.IsZero() {
					unhealthySince = time.Now()
				}
				if time.Since(unhealthySince) >= s.timeout {
					s.logger.Error("Agent unhealthy for too long, restarting",
						slog.Duration("duration", time.Since(unhealthySince)),
						slog.Duration("timeout", s.timeout))
					s.restart()
				}
			} else {
				if !s.healthy.Load() {
					s.logger.Info("Agent recovered to healthy state")
				}
				unhealthySince = time.Time{}
				s.healthy.Store(true)
			}
		}
	}
}

// restart re-executes the current binary. If the re-exec fails, the process
// exits with a non-zero status.
func (s *Supervisor) restart() {
	s.logger.Info("Restarting agent", slog.String("binary", os.Args[0]))
	_ = syscall.Exec(os.Args[0], os.Args, os.Environ())
	// If we reach here the exec failed. Fall through to let the process exit.
	os.Exit(1)
}

// sdWatchdogLoop sends periodic WATCHDOG=1 notifications to systemd via the
// unix socket at socketPath.
func (s *Supervisor) sdWatchdogLoop(ctx context.Context, socketPath string) {
	ticker := time.NewTicker(s.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := sdNotify(socketPath, "WATCHDOG=1\n"); err != nil {
				s.logger.Warn("Failed to notify systemd watchdog", slog.Any("error", err))
			}
		}
	}
}

// sdNotify sends a message to the systemd notification socket.
func sdNotify(socketPath, state string) error {
	addr := &net.UnixAddr{Name: socketPath, Net: "unixgram"}
	conn, err := net.DialUnix("unixgram", nil, addr)
	if err != nil {
		return err
	}
	defer conn.Close()
	_, err = conn.Write([]byte(state))
	return err
}

// IsHealthy returns whether the supervisor currently considers the agent
// healthy.
func (s *Supervisor) IsHealthy() bool {
	return s.healthy.Load()
}

// MQTTChecker checks if the MQTT client is connected.
type MQTTChecker struct {
	client MQTTClient
}

// NewMQTTChecker creates a health checker for the MQTT connection.
func NewMQTTChecker(client MQTTClient) *MQTTChecker {
	return &MQTTChecker{client: client}
}

func (c *MQTTChecker) Name() string {
	return "mqtt"
}

func (c *MQTTChecker) Healthy() bool {
	return c.client.IsConnected()
}

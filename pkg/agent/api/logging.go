// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	"log/slog"
	"time"

	"github.com/absmach/agent/pkg/agent"
)

var _ agent.Service = (*loggingMiddleware)(nil)

type loggingMiddleware struct {
	logger *slog.Logger
	svc    agent.Service
}

// LoggingMiddleware adds logging facilities to the core service.
func LoggingMiddleware(svc agent.Service, logger *slog.Logger) agent.Service {
	return &loggingMiddleware{logger, svc}
}

func (lm loggingMiddleware) Publish(topic string, payload string) (err error) {
	defer func(begin time.Time) {
		args := []any{
			slog.String("duration", time.Since(begin).String()),
			slog.String("topic", topic),
			slog.String("payload", payload),
		}
		if err != nil {
			args = append(args, slog.Any("error", err))
			lm.logger.Warn("Publish message failed to complete successfully.", args...)
			return
		}
		lm.logger.Info("Publish message completed successfully.", args...)
	}(time.Now())

	return lm.svc.Publish(topic, payload)
}

func (lm loggingMiddleware) Execute(uuid, cmd string) (str string, err error) {
	defer func(begin time.Time) {
		args := []any{
			slog.String("duration", time.Since(begin).String()),
			slog.String("uuid", uuid),
			slog.String("cmd", cmd),
		}
		if err != nil {
			args = append(args, slog.Any("error", err))
			lm.logger.Warn("Execute command failed to complete successfully.", args...)
			return
		}
		lm.logger.Info("Execute command completed successfully.", args...)
	}(time.Now())

	return lm.svc.Execute(uuid, cmd)
}

func (lm loggingMiddleware) Control(uuid, cmd string) (err error) {
	defer func(begin time.Time) {
		args := []any{
			slog.String("duration", time.Since(begin).String()),
			slog.String("uuid", uuid),
			slog.String("cmd", cmd),
		}
		if err != nil {
			args = append(args, slog.Any("error", err))
			lm.logger.Warn("Control command failed to complete successfully.", args...)
			return
		}
		lm.logger.Info("Control command completed successfully.", args...)
	}(time.Now())

	return lm.svc.Control(uuid, cmd)
}

func (lm loggingMiddleware) AddConfig(c agent.Config) (err error) {
	defer func(begin time.Time) {
		duration := slog.String("duration", time.Since(begin).String())
		if err != nil {
			lm.logger.Warn("AddConfig failed to complete successfully.", duration, slog.Any("error", err))
			return
		}
		lm.logger.Info("AddConfig completed successfully.", duration)
	}(time.Now())

	return lm.svc.AddConfig(c)
}

func (lm loggingMiddleware) Config() agent.Config {
	defer func(begin time.Time) {
		lm.logger.Info("Config completed successfully.", slog.String("duration", time.Since(begin).String()))
	}(time.Now())

	return lm.svc.Config()
}

func (lm loggingMiddleware) ServiceConfig(ctx context.Context, uuid, cmdStr string) (err error) {
	defer func(begin time.Time) {
		args := []any{
			slog.String("duration", time.Since(begin).String()),
			slog.String("uuid", uuid),
			slog.String("cmd", cmdStr),
		}
		if err != nil {
			args = append(args, slog.Any("error", err))
			lm.logger.Warn("ServiceConfig failed to complete successfully.", args...)
			return
		}
		lm.logger.Info("ServiceConfig completed successfully.", args...)
	}(time.Now())

	return lm.svc.ServiceConfig(ctx, uuid, cmdStr)
}

func (lm loggingMiddleware) Services() []agent.Info {
	defer func(begin time.Time) {
		duration := slog.String("duration", time.Since(begin).String())
		lm.logger.Info("Services completed successfully.", duration)
	}(time.Now())

	return lm.svc.Services()
}

func (lm loggingMiddleware) Terminal(uuid, cmdStr string) (err error) {
	defer func(begin time.Time) {
		args := []any{
			slog.String("duration", time.Since(begin).String()),
			slog.String("uuid", uuid),
			slog.String("payload", cmdStr),
		}
		if err != nil {
			args = append(args, slog.Any("error", err))
			lm.logger.Warn("Terminal failed to complete successfully.", args...)
			return
		}
		lm.logger.Info("Terminal completed successfully.", args...)
	}(time.Now())

	return lm.svc.Terminal(uuid, cmdStr)
}

// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/absmach/agent/pkg/agent"
	"github.com/go-chi/chi/v5/middleware"
)

var _ agent.Service = (*loggingMiddleware)(nil)

type loggingMiddleware struct {
	logger *slog.Logger
	svc    agent.Service
}

// NewLogging adds logging facilities to the core service.
func NewLogging(svc agent.Service, logger *slog.Logger) agent.Service {
	return &loggingMiddleware{logger, svc}
}

func (lm *loggingMiddleware) Publish(topic string, payload string) (err error) {
	defer func(begin time.Time) {
		args := []any{
			slog.String("duration", time.Since(begin).String()),
			slog.String("topic", topic),
		}
		if err != nil {
			args = append(args, slog.String("error", err.Error()))
			lm.logger.Warn("Publish message failed to complete successfully.", args...)
			return
		}
		lm.logger.Info("Publish message completed successfully.", args...)
	}(time.Now())

	return lm.svc.Publish(topic, payload)
}

func (lm *loggingMiddleware) Execute(uuid, cmd string) (str string, err error) {
	defer func(begin time.Time) {
		args := []any{
			slog.String("duration", time.Since(begin).String()),
			slog.String("uuid", uuid),
			slog.String("cmd", cmd),
		}
		if err != nil {
			args = append(args, slog.String("error", err.Error()))
			lm.logger.Warn("Execute command failed to complete successfully.", args...)
			return
		}
		lm.logger.Info("Execute command completed successfully.", args...)
	}(time.Now())

	return lm.svc.Execute(uuid, cmd)
}

func (lm *loggingMiddleware) Control(uuid, cmd string) (err error) {
	defer func(begin time.Time) {
		args := []any{
			slog.String("duration", time.Since(begin).String()),
			slog.String("uuid", uuid),
			slog.String("cmd", cmd),
		}
		if err != nil {
			args = append(args, slog.String("error", err.Error()))
			lm.logger.Warn("Control command failed to complete successfully.", args...)
			return
		}
		lm.logger.Info("Control command completed successfully.", args...)
	}(time.Now())

	return lm.svc.Control(uuid, cmd)
}

func (lm *loggingMiddleware) AddConfig(c agent.Config) (err error) {
	defer func(begin time.Time) {
		args := []any{
			slog.String("duration", time.Since(begin).String()),
		}
		if err != nil {
			args = append(args, slog.String("error", err.Error()))
			lm.logger.Warn("Add config failed to complete successfully.", args...)
			return
		}
		lm.logger.Info("Add config completed successfully.", args...)
	}(time.Now())

	return lm.svc.AddConfig(c)
}

func (lm *loggingMiddleware) Config() agent.Config {
	defer func(begin time.Time) {
		lm.logger.Info("Retrieve config completed successfully.", slog.String("duration", time.Since(begin).String()))
	}(time.Now())

	return lm.svc.Config()
}

func (lm *loggingMiddleware) ServiceConfig(ctx context.Context, uuid, cmdStr string) (err error) {
	defer func(begin time.Time) {
		args := []any{
			slog.String("duration", time.Since(begin).String()),
			slog.String("request_id", middleware.GetReqID(ctx)),
			slog.String("uuid", uuid),
			slog.String("cmd", cmdStr),
		}
		if err != nil {
			args = append(args, slog.String("error", err.Error()))
			lm.logger.Warn("Save config failed to complete successfully.", args...)
			return
		}
		lm.logger.Info("Save config completed successfully.", args...)
	}(time.Now())

	return lm.svc.ServiceConfig(ctx, uuid, cmdStr)
}

func (lm *loggingMiddleware) Services() []agent.Info {
	defer func(begin time.Time) {
		lm.logger.Info("Retrieve services completed successfully.", slog.String("duration", time.Since(begin).String()))
	}(time.Now())

	return lm.svc.Services()
}

func (lm *loggingMiddleware) Terminal(uuid, cmdStr string) (err error) {
	defer func(begin time.Time) {
		args := []any{
			slog.String("duration", time.Since(begin).String()),
			slog.String("uuid", uuid),
		}
		if err != nil {
			args = append(args, slog.String("error", err.Error()))
			lm.logger.Warn(fmt.Sprintf("Terminal command %q failed to complete successfully.", cmdStr), args...)
			return
		}
		lm.logger.Info(fmt.Sprintf("Terminal command %q completed successfully.", cmdStr), args...)
	}(time.Now())

	return lm.svc.Terminal(uuid, cmdStr)
}

func (lm *loggingMiddleware) NodeRed(uuid, cmdStr string) (resp string, err error) {
	defer func(begin time.Time) {
		args := []any{
			slog.String("duration", time.Since(begin).String()),
			slog.String("uuid", uuid),
		}
		if err != nil {
			args = append(args, slog.String("error", err.Error()))
			lm.logger.Warn(fmt.Sprintf("NodeRed command %q failed to complete successfully.", cmdStr), args...)
			return
		}
		lm.logger.Info(fmt.Sprintf("NodeRed command %q completed successfully.", cmdStr), args...)
	}(time.Now())

	return lm.svc.NodeRed(uuid, cmdStr)
}

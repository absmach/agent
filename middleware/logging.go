// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

package middleware

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/absmach/agent"
	"github.com/absmach/agent/pkg/devicemgr"
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

func (lm *loggingMiddleware) CommandSecret() string {
	defer func(begin time.Time) {
		lm.logger.Info("Retrieve command secret completed successfully.", slog.String("duration", time.Since(begin).String()))
	}(time.Now())

	return lm.svc.CommandSecret()
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

func (lm *loggingMiddleware) Ping() (err error) {
	defer func(begin time.Time) {
		args := []any{
			slog.String("duration", time.Since(begin).String()),
		}
		if err != nil {
			args = append(args, slog.String("error", err.Error()))
			lm.logger.Warn("Ping failed to complete successfully.", args...)
			return
		}
		lm.logger.Info("Ping completed successfully.", args...)
	}(time.Now())

	return lm.svc.Ping()
}

func (lm *loggingMiddleware) UpdateLiveness(svcname, svctype string) (err error) {
	defer func(begin time.Time) {
		args := []any{
			slog.String("duration", time.Since(begin).String()),
			slog.String("svcname", svcname),
			slog.String("svctype", svctype),
		}
		if err != nil {
			args = append(args, slog.String("error", err.Error()))
			lm.logger.Warn("Update liveness failed to complete successfully.", args...)
			return
		}
		lm.logger.Info("Update liveness completed successfully.", args...)
	}(time.Now())

	return lm.svc.UpdateLiveness(svcname, svctype)
}

func (lm *loggingMiddleware) OTA(ctx context.Context, url, sha256hex string, size uint64) (err error) {
	defer func(begin time.Time) {
		args := []any{
			slog.String("duration", time.Since(begin).String()),
			slog.String("url", url),
			slog.String("sha256hex", sha256hex),
		}
		if err != nil {
			args = append(args, slog.String("error", err.Error()))
			lm.logger.Warn("OTA update failed to complete successfully.", args...)
			return
		}
		lm.logger.Info("OTA update completed successfully.", args...)
	}(time.Now())

	return lm.svc.OTA(ctx, url, sha256hex, size)
}

func (lm *loggingMiddleware) NodeRed(cmdStr string) (resp string, err error) {
	defer func(begin time.Time) {
		args := []any{
			slog.String("duration", time.Since(begin).String()),
		}
		if err != nil {
			args = append(args, slog.String("error", err.Error()))
			lm.logger.Warn(fmt.Sprintf("NodeRed command %q failed to complete successfully.", cmdStr), args...)
			return
		}
		lm.logger.Info(fmt.Sprintf("NodeRed command %q completed successfully.", cmdStr), args...)
	}(time.Now())

	return lm.svc.NodeRed(cmdStr)
}

func (lm *loggingMiddleware) Shutdown() {
	lm.logger.Info("Shutdown initiated")
	lm.svc.Shutdown()
	lm.logger.Info("Shutdown completed")
}

func (lm *loggingMiddleware) DeviceManager(ctx context.Context, uuid, cmdStr string) (err error) {
	defer func(begin time.Time) {
		args := []any{
			slog.String("duration", time.Since(begin).String()),
			slog.String("uuid", uuid),
			slog.String("cmd", cmdStr),
		}
		if err != nil {
			args = append(args, slog.String("error", err.Error()))
			lm.logger.Warn("DeviceManager command failed to complete successfully.", args...)
			return
		}
		lm.logger.Info("DeviceManager command completed successfully.", args...)
	}(time.Now())

	return lm.svc.DeviceManager(ctx, uuid, cmdStr)
}

func (lm *loggingMiddleware) OTAStatus() agent.OTAStatusInfo {
	return lm.svc.OTAStatus()
}

func (lm *loggingMiddleware) OTAAbort() (err error) {
	defer func(begin time.Time) {
		args := []any{
			slog.String("duration", time.Since(begin).String()),
		}
		if err != nil {
			args = append(args, slog.String("error", err.Error()))
			lm.logger.Warn("OTA abort failed to complete successfully.", args...)
			return
		}
		lm.logger.Info("OTA abort completed successfully.", args...)
	}(time.Now())

	return lm.svc.OTAAbort()
}

func (lm *loggingMiddleware) ListDevices() (devs []devicemgr.Device, err error) {
	defer func(begin time.Time) {
		args := []any{slog.String("duration", time.Since(begin).String())}
		if err != nil {
			args = append(args, slog.String("error", err.Error()))
			lm.logger.Warn("ListDevices failed.", args...)
			return
		}
		lm.logger.Info("ListDevices completed.", args...)
	}(time.Now())
	return lm.svc.ListDevices()
}

func (lm *loggingMiddleware) GetDevice(id string) (d devicemgr.Device, err error) {
	defer func(begin time.Time) {
		args := []any{slog.String("duration", time.Since(begin).String()), slog.String("id", id)}
		if err != nil {
			args = append(args, slog.String("error", err.Error()))
			lm.logger.Warn("GetDevice failed.", args...)
			return
		}
		lm.logger.Info("GetDevice completed.", args...)
	}(time.Now())
	return lm.svc.GetDevice(id)
}

func (lm *loggingMiddleware) AddDevice(ctx context.Context, name, extID, extKey, ifaceType, ifaceAddr string) (d devicemgr.Device, err error) {
	defer func(begin time.Time) {
		args := []any{slog.String("duration", time.Since(begin).String()), slog.String("name", name)}
		if err != nil {
			args = append(args, slog.String("error", err.Error()))
			lm.logger.Warn("AddDevice failed.", args...)
			return
		}
		lm.logger.Info("AddDevice completed.", args...)
	}(time.Now())
	return lm.svc.AddDevice(ctx, name, extID, extKey, ifaceType, ifaceAddr)
}

func (lm *loggingMiddleware) RemoveDevice(id string) (err error) {
	defer func(begin time.Time) {
		args := []any{slog.String("duration", time.Since(begin).String()), slog.String("id", id)}
		if err != nil {
			args = append(args, slog.String("error", err.Error()))
			lm.logger.Warn("RemoveDevice failed.", args...)
			return
		}
		lm.logger.Info("RemoveDevice completed.", args...)
	}(time.Now())
	return lm.svc.RemoveDevice(id)
}

func (lm *loggingMiddleware) MarkDeviceSeen(id string) (err error) {
	defer func(begin time.Time) {
		args := []any{slog.String("duration", time.Since(begin).String()), slog.String("id", id)}
		if err != nil {
			args = append(args, slog.String("error", err.Error()))
			lm.logger.Warn("MarkDeviceSeen failed.", args...)
			return
		}
		lm.logger.Info("MarkDeviceSeen completed.", args...)
	}(time.Now())
	return lm.svc.MarkDeviceSeen(id)
}

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

func (lm *loggingMiddleware) Reset(ctx context.Context, mode string) (err error) {
	defer func(begin time.Time) {
		args := []any{
			slog.String("duration", time.Since(begin).String()),
			slog.String("mode", mode),
		}
		if err != nil {
			args = append(args, slog.String("error", err.Error()))
			lm.logger.Warn("Reset failed to complete successfully.", args...)
			return
		}
		lm.logger.Info("Reset completed successfully.", args...)
	}(time.Now())

	return lm.svc.Reset(ctx, mode)
}

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

func (lm *loggingMiddleware) Route(ctx context.Context, uuid, cmd string) (err error) {
	defer func(begin time.Time) {
		args := []any{
			slog.String("duration", time.Since(begin).String()),
			slog.String("uuid", uuid),
			slog.String("cmd", cmd),
		}
		if err != nil {
			args = append(args, slog.String("error", err.Error()))
			lm.logger.Warn("Route command failed to complete successfully.", args...)
			return
		}
		lm.logger.Info("Route command completed successfully.", args...)
	}(time.Now())

	return lm.svc.Route(ctx, uuid, cmd)
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

func (lm *loggingMiddleware) RegisterService(svcname, svctype string) (err error) {
	defer func(begin time.Time) {
		args := []any{
			slog.String("duration", time.Since(begin).String()),
			slog.String("svcname", svcname),
			slog.String("svctype", svctype),
		}
		if err != nil {
			args = append(args, slog.String("error", err.Error()))
			lm.logger.Warn("Register service failed to complete successfully.", args...)
			return
		}
		lm.logger.Info("Register service completed successfully.", args...)
	}(time.Now())

	return lm.svc.RegisterService(svcname, svctype)
}

func (lm *loggingMiddleware) RemoveService(svcname string) (err error) {
	defer func(begin time.Time) {
		args := []any{
			slog.String("duration", time.Since(begin).String()),
			slog.String("svcname", svcname),
		}
		if err != nil {
			args = append(args, slog.String("error", err.Error()))
			lm.logger.Warn("Remove service failed to complete successfully.", args...)
			return
		}
		lm.logger.Info("Remove service completed successfully.", args...)
	}(time.Now())

	return lm.svc.RemoveService(svcname)
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

func (lm *loggingMiddleware) OTAFromData(ctx context.Context, data []byte, sha256hex string) (err error) {
	defer func(begin time.Time) {
		args := []any{
			slog.String("duration", time.Since(begin).String()),
			slog.Int("bytes", len(data)),
			slog.String("sha256hex", sha256hex),
		}
		if err != nil {
			args = append(args, slog.String("error", err.Error()))
			lm.logger.Warn("OTA from data failed to complete successfully.", args...)
			return
		}
		lm.logger.Info("OTA from data completed successfully.", args...)
	}(time.Now())

	return lm.svc.OTAFromData(ctx, data, sha256hex)
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

func (lm *loggingMiddleware) Telemetry() agent.TelemetryData {
	return lm.svc.Telemetry()
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

func (lm *loggingMiddleware) OpenDevice(ctx context.Context, id string) (err error) {
	defer func(begin time.Time) {
		args := []any{slog.String("duration", time.Since(begin).String()), slog.String("id", id)}
		if err != nil {
			args = append(args, slog.String("error", err.Error()))
			lm.logger.Warn("OpenDevice failed.", args...)
			return
		}
		lm.logger.Info("OpenDevice completed.", args...)
	}(time.Now())
	return lm.svc.OpenDevice(ctx, id)
}

func (lm *loggingMiddleware) CloseDevice(id string) (err error) {
	defer func(begin time.Time) {
		args := []any{slog.String("duration", time.Since(begin).String()), slog.String("id", id)}
		if err != nil {
			args = append(args, slog.String("error", err.Error()))
			lm.logger.Warn("CloseDevice failed.", args...)
			return
		}
		lm.logger.Info("CloseDevice completed.", args...)
	}(time.Now())
	return lm.svc.CloseDevice(id)
}

func (lm *loggingMiddleware) ReadDevice(id string, n int) (data []byte, err error) {
	defer func(begin time.Time) {
		args := []any{slog.String("duration", time.Since(begin).String()), slog.String("id", id), slog.Int("n", n)}
		if err != nil {
			args = append(args, slog.String("error", err.Error()))
			lm.logger.Warn("ReadDevice failed.", args...)
			return
		}
		lm.logger.Info("ReadDevice completed.", args...)
	}(time.Now())
	return lm.svc.ReadDevice(id, n)
}

func (lm *loggingMiddleware) WriteDevice(id, hexData string) (n int, err error) {
	defer func(begin time.Time) {
		args := []any{slog.String("duration", time.Since(begin).String()), slog.String("id", id)}
		if err != nil {
			args = append(args, slog.String("error", err.Error()))
			lm.logger.Warn("WriteDevice failed.", args...)
			return
		}
		lm.logger.Info("WriteDevice completed.", args...)
	}(time.Now())
	return lm.svc.WriteDevice(id, hexData)
}

func (lm *loggingMiddleware) GetRuntimeConfig(key string) (val string, err error) {
	defer func(begin time.Time) {
		args := []any{slog.String("duration", time.Since(begin).String()), slog.String("key", key)}
		if err != nil {
			args = append(args, slog.String("error", err.Error()))
			lm.logger.Warn("GetRuntimeConfig failed.", args...)
			return
		}
		lm.logger.Info("GetRuntimeConfig completed.", args...)
	}(time.Now())
	return lm.svc.GetRuntimeConfig(key)
}

func (lm *loggingMiddleware) SetRuntimeConfig(ctx context.Context, key, value string) (err error) {
	defer func(begin time.Time) {
		args := []any{slog.String("duration", time.Since(begin).String()), slog.String("key", key), slog.String("value", value)}
		if err != nil {
			args = append(args, slog.String("error", err.Error()))
			lm.logger.Warn("SetRuntimeConfig failed.", args...)
			return
		}
		lm.logger.Info("SetRuntimeConfig completed.", args...)
	}(time.Now())
	return lm.svc.SetRuntimeConfig(ctx, key, value)
}

func (lm *loggingMiddleware) SetPushEvent(fn func(string)) {
	lm.svc.SetPushEvent(fn)
}

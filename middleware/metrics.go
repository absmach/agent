// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

//go:build !test
// +build !test

package middleware

import (
	"context"
	"time"

	"github.com/absmach/agent"
	"github.com/absmach/agent/pkg/devicemgr"
	"github.com/go-kit/kit/metrics"
)

func (ms *metricsMiddleware) Reset(ctx context.Context, mode string) error {
	defer func(begin time.Time) {
		ms.counter.With("method", "reset").Add(1)
		ms.latency.With("method", "reset").Observe(time.Since(begin).Seconds())
	}(time.Now())

	return ms.svc.Reset(ctx, mode)
}

var _ agent.Service = (*metricsMiddleware)(nil)

type metricsMiddleware struct {
	counter metrics.Counter
	latency metrics.Histogram
	svc     agent.Service
}

// NewMetrics returns a new metrics middleware wrapper.
func NewMetrics(svc agent.Service, counter metrics.Counter, latency metrics.Histogram) agent.Service {
	return &metricsMiddleware{
		svc:     svc,
		counter: counter,
		latency: latency,
	}
}

func (ms *metricsMiddleware) Control(uuid, cmdStr string) error {
	defer func(begin time.Time) {
		ms.counter.With("method", "control").Add(1)
		ms.latency.With("method", "control").Observe(time.Since(begin).Seconds())
	}(time.Now())

	return ms.svc.Control(uuid, cmdStr)
}

func (ms *metricsMiddleware) Route(ctx context.Context, uuid, cmdStr string) error {
	defer func(begin time.Time) {
		ms.counter.With("method", "route").Add(1)
		ms.latency.With("method", "route").Observe(time.Since(begin).Seconds())
	}(time.Now())

	return ms.svc.Route(ctx, uuid, cmdStr)
}

func (ms *metricsMiddleware) AddConfig(ec agent.Config) error {
	defer func(begin time.Time) {
		ms.counter.With("method", "add_config").Add(1)
		ms.latency.With("method", "add_config").Observe(time.Since(begin).Seconds())
	}(time.Now())

	return ms.svc.AddConfig(ec)
}

func (ms *metricsMiddleware) ServiceConfig(ctx context.Context, uuid, cmdStr string) error {
	defer func(begin time.Time) {
		ms.counter.With("method", "service_config").Add(1)
		ms.latency.With("method", "service_config").Observe(time.Since(begin).Seconds())
	}(time.Now())

	return ms.svc.ServiceConfig(ctx, uuid, cmdStr)
}

func (ms *metricsMiddleware) Config() agent.Config {
	defer func(begin time.Time) {
		ms.counter.With("method", "config").Add(1)
		ms.latency.With("method", "config").Observe(time.Since(begin).Seconds())
	}(time.Now())

	return ms.svc.Config()
}

func (ms *metricsMiddleware) CommandSecret() string {
	defer func(begin time.Time) {
		ms.counter.With("method", "command_secret").Add(1)
		ms.latency.With("method", "command_secret").Observe(time.Since(begin).Seconds())
	}(time.Now())

	return ms.svc.CommandSecret()
}

func (ms *metricsMiddleware) Services() []agent.Info {
	defer func(begin time.Time) {
		ms.counter.With("method", "services").Add(1)
		ms.latency.With("method", "services").Observe(time.Since(begin).Seconds())
	}(time.Now())

	return ms.svc.Services()
}

func (ms *metricsMiddleware) Publish(topic, payload string) error {
	defer func(begin time.Time) {
		ms.counter.With("method", "publish").Add(1)
		ms.latency.With("method", "publish").Observe(time.Since(begin).Seconds())
	}(time.Now())

	return ms.svc.Publish(topic, payload)
}

func (ms *metricsMiddleware) Terminal(uuid, cmdStr string) error {
	defer func(begin time.Time) {
		ms.counter.With("method", "terminal").Add(1)
		ms.latency.With("method", "terminal").Observe(time.Since(begin).Seconds())
	}(time.Now())

	return ms.svc.Terminal(uuid, cmdStr)
}

func (ms *metricsMiddleware) Ping() error {
	defer func(begin time.Time) {
		ms.counter.With("method", "ping").Add(1)
		ms.latency.With("method", "ping").Observe(time.Since(begin).Seconds())
	}(time.Now())

	return ms.svc.Ping()
}

func (ms *metricsMiddleware) UpdateLiveness(svcname, svctype string) error {
	defer func(begin time.Time) {
		ms.counter.With("method", "update_liveness").Add(1)
		ms.latency.With("method", "update_liveness").Observe(time.Since(begin).Seconds())
	}(time.Now())

	return ms.svc.UpdateLiveness(svcname, svctype)
}

func (ms *metricsMiddleware) RegisterService(svcname, svctype string) error {
	defer func(begin time.Time) {
		ms.counter.With("method", "register_service").Add(1)
		ms.latency.With("method", "register_service").Observe(time.Since(begin).Seconds())
	}(time.Now())

	return ms.svc.RegisterService(svcname, svctype)
}

func (ms *metricsMiddleware) RemoveService(svcname string) error {
	defer func(begin time.Time) {
		ms.counter.With("method", "remove_service").Add(1)
		ms.latency.With("method", "remove_service").Observe(time.Since(begin).Seconds())
	}(time.Now())

	return ms.svc.RemoveService(svcname)
}

func (ms *metricsMiddleware) OTA(ctx context.Context, url, sha256hex string, size uint64) error {
	defer func(begin time.Time) {
		ms.counter.With("method", "ota").Add(1)
		ms.latency.With("method", "ota").Observe(time.Since(begin).Seconds())
	}(time.Now())

	return ms.svc.OTA(ctx, url, sha256hex, size)
}

func (ms *metricsMiddleware) OTAFromData(ctx context.Context, data []byte, sha256hex string) error {
	defer func(begin time.Time) {
		ms.counter.With("method", "ota_from_data").Add(1)
		ms.latency.With("method", "ota_from_data").Observe(time.Since(begin).Seconds())
	}(time.Now())

	return ms.svc.OTAFromData(ctx, data, sha256hex)
}

func (ms *metricsMiddleware) NodeRed(cmdStr string) (string, error) {
	defer func(begin time.Time) {
		ms.counter.With("method", "nodered").Add(1)
		ms.latency.With("method", "nodered").Observe(time.Since(begin).Seconds())
	}(time.Now())

	return ms.svc.NodeRed(cmdStr)
}

func (ms *metricsMiddleware) Shutdown() {
	ms.svc.Shutdown()
}

func (ms *metricsMiddleware) DeviceManager(ctx context.Context, uuid, cmdStr string) error {
	defer func(begin time.Time) {
		ms.counter.With("method", "device_manager").Add(1)
		ms.latency.With("method", "device_manager").Observe(time.Since(begin).Seconds())
	}(time.Now())

	return ms.svc.DeviceManager(ctx, uuid, cmdStr)
}

func (ms *metricsMiddleware) OTAStatus() agent.OTAStatusInfo {
	return ms.svc.OTAStatus()
}

func (ms *metricsMiddleware) Telemetry() agent.TelemetryData {
	return ms.svc.Telemetry()
}

func (ms *metricsMiddleware) OTAAbort() error {
	defer func(begin time.Time) {
		ms.counter.With("method", "ota_abort").Add(1)
		ms.latency.With("method", "ota_abort").Observe(time.Since(begin).Seconds())
	}(time.Now())

	return ms.svc.OTAAbort()
}

func (ms *metricsMiddleware) ListDevices() ([]devicemgr.Device, error) {
	defer func(begin time.Time) {
		ms.counter.With("method", "list_devices").Add(1)
		ms.latency.With("method", "list_devices").Observe(time.Since(begin).Seconds())
	}(time.Now())
	return ms.svc.ListDevices()
}

func (ms *metricsMiddleware) GetDevice(id string) (devicemgr.Device, error) {
	defer func(begin time.Time) {
		ms.counter.With("method", "get_device").Add(1)
		ms.latency.With("method", "get_device").Observe(time.Since(begin).Seconds())
	}(time.Now())
	return ms.svc.GetDevice(id)
}

func (ms *metricsMiddleware) AddDevice(ctx context.Context, name, extID, extKey, ifaceType, ifaceAddr string) (devicemgr.Device, error) {
	defer func(begin time.Time) {
		ms.counter.With("method", "add_device").Add(1)
		ms.latency.With("method", "add_device").Observe(time.Since(begin).Seconds())
	}(time.Now())
	return ms.svc.AddDevice(ctx, name, extID, extKey, ifaceType, ifaceAddr)
}

func (ms *metricsMiddleware) RemoveDevice(id string) error {
	defer func(begin time.Time) {
		ms.counter.With("method", "remove_device").Add(1)
		ms.latency.With("method", "remove_device").Observe(time.Since(begin).Seconds())
	}(time.Now())
	return ms.svc.RemoveDevice(id)
}

func (ms *metricsMiddleware) MarkDeviceSeen(id string) error {
	defer func(begin time.Time) {
		ms.counter.With("method", "mark_device_seen").Add(1)
		ms.latency.With("method", "mark_device_seen").Observe(time.Since(begin).Seconds())
	}(time.Now())
	return ms.svc.MarkDeviceSeen(id)
}

func (ms *metricsMiddleware) OpenDevice(ctx context.Context, id string) error {
	defer func(begin time.Time) {
		ms.counter.With("method", "open_device").Add(1)
		ms.latency.With("method", "open_device").Observe(time.Since(begin).Seconds())
	}(time.Now())
	return ms.svc.OpenDevice(ctx, id)
}

func (ms *metricsMiddleware) CloseDevice(id string) error {
	defer func(begin time.Time) {
		ms.counter.With("method", "close_device").Add(1)
		ms.latency.With("method", "close_device").Observe(time.Since(begin).Seconds())
	}(time.Now())
	return ms.svc.CloseDevice(id)
}

func (ms *metricsMiddleware) ReadDevice(id string, n int) ([]byte, error) {
	defer func(begin time.Time) {
		ms.counter.With("method", "read_device").Add(1)
		ms.latency.With("method", "read_device").Observe(time.Since(begin).Seconds())
	}(time.Now())
	return ms.svc.ReadDevice(id, n)
}

func (ms *metricsMiddleware) WriteDevice(id, hexData string) (int, error) {
	defer func(begin time.Time) {
		ms.counter.With("method", "write_device").Add(1)
		ms.latency.With("method", "write_device").Observe(time.Since(begin).Seconds())
	}(time.Now())
	return ms.svc.WriteDevice(id, hexData)
}

func (ms *metricsMiddleware) GetRuntimeConfig(key string) (string, error) {
	defer func(begin time.Time) {
		ms.counter.With("method", "get_runtime_config").Add(1)
		ms.latency.With("method", "get_runtime_config").Observe(time.Since(begin).Seconds())
	}(time.Now())
	return ms.svc.GetRuntimeConfig(key)
}

func (ms *metricsMiddleware) SetRuntimeConfig(ctx context.Context, key, value string) error {
	defer func(begin time.Time) {
		ms.counter.With("method", "set_runtime_config").Add(1)
		ms.latency.With("method", "set_runtime_config").Observe(time.Since(begin).Seconds())
	}(time.Now())
	return ms.svc.SetRuntimeConfig(ctx, key, value)
}

func (ms *metricsMiddleware) SetPushEvent(fn func(string)) {
	ms.svc.SetPushEvent(fn)
}

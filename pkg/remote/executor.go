// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

package remote

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/absmach/agent"
	"github.com/absmach/agent/pkg/devicemgr"
)

type StreamManager interface {
	OpenLog(context.Context, json.RawMessage) (any, *RPCError)
	OpenTerminal(context.Context, json.RawMessage) (any, *RPCError)
	CloseStream(json.RawMessage) (any, *RPCError)
}

// Executor maps the OpenRPC method surface to the same Service implementation
// used by the local HTTP API.
type Executor struct {
	svc      agent.Service
	store    *Store
	jobs     *JobManager
	streams  StreamManager
	revision atomic.Uint64
	mu       sync.Mutex
}

var SupportedMethods = []string{
	"system.health.get",
	"system.snapshot.get",
	"agent.pause",
	"agent.resume",
	"agent.reload",
	"agent.reset",
	"config.get",
	"config.apply",
	"runtimeConfig.list",
	"runtimeConfig.set",
	"service.list",
	"service.register",
	"service.remove",
	"device.list",
	"device.get",
	"device.register",
	"device.remove",
	"device.markSeen",
	"device.interface.open",
	"device.interface.close",
	"device.interface.read",
	"device.interface.write",
	"backup.create",
	"backup.restore",
	"nodeRed.status.get",
	"nodeRed.flows.get",
	"nodeRed.flows.deploy",
	"nodeRed.action.execute",
	"firmware.update.start",
	"firmware.update.abort",
	"firmware.update.status.get",
	"job.get",
	"job.list",
	"job.cancel",
	"log.stream.open",
	"terminal.open",
	"stream.close",
}

func NewExecutor(svc agent.Service, store *Store, publishJob JobPublisher) *Executor {
	e := &Executor{svc: svc, store: store}
	e.jobs = NewJobManager(store, publishJob)
	e.revision.Store(1)
	return e
}

func (e *Executor) SetStreams(streams StreamManager) {
	e.streams = streams
}

func (e *Executor) IsMutating(method string) bool {
	switch method {
	case "system.health.get", "system.snapshot.get", "config.get", "runtimeConfig.list",
		"service.list", "device.list", "device.get", "device.interface.read",
		"nodeRed.status.get", "nodeRed.flows.get", "firmware.update.status.get",
		"job.get", "job.list":
		return false
	default:
		return true
	}
}

func (e *Executor) Execute(ctx context.Context, req Request) Response {
	if !e.IsMutating(req.Method) {
		result, rpcErr := e.call(ctx, req)
		if rpcErr != nil {
			return Response{JSONRPC: JSONRPCVersion, ID: req.ID, Error: rpcErr}
		}
		return ResultResponse(req.ID, result)
	}

	hash := RequestHash(req)
	begin, replay, err := e.store.BeginRequest(req.ID, req.Method, hash, requestRetention())
	if err != nil {
		return ErrorResponse(req.ID, CodeInternalError, "failed to persist request", nil)
	}
	switch begin {
	case BeginReplay:
		return replay
	case BeginRunning:
		return ErrorResponse(req.ID, CodeRequestRunning, "request is already running", map[string]bool{"retryable": true})
	case BeginConflict:
		return ErrorResponse(req.ID, CodeRequestConflict, "request ID was reused with different content", nil)
	}

	result, rpcErr := e.call(ctx, req)
	var response Response
	if rpcErr != nil {
		response = Response{JSONRPC: JSONRPCVersion, ID: req.ID, Error: rpcErr}
	} else {
		response = ResultResponse(req.ID, result)
	}
	if err := e.store.CompleteRequest(req.ID, response); err != nil {
		return ErrorResponse(req.ID, CodeInternalError, "failed to persist response", nil)
	}
	return response
}

func (e *Executor) call(ctx context.Context, req Request) (any, *RPCError) {
	switch req.Method {
	case "system.health.get":
		return e.health(), nil
	case "system.snapshot.get":
		return e.snapshot()
	case "agent.pause":
		return e.control(req.ID, "stop")
	case "agent.resume":
		return e.control(req.ID, "start")
	case "agent.reload":
		return e.control(req.ID, "reload")
	case "agent.reset":
		return e.startReset(ctx, req.Params)
	case "config.get":
		return redactedConfig(e.svc.Config()), nil
	case "config.apply":
		return e.startConfigApply(ctx, req.Params)
	case "runtimeConfig.list":
		return e.runtimeConfig()
	case "runtimeConfig.set":
		return e.runtimeConfigSet(ctx, req.Params)
	case "service.list":
		return e.svc.Services(), nil
	case "service.register":
		return e.serviceRegister(req.Params)
	case "service.remove":
		return e.serviceRemove(req.Params)
	case "device.list":
		devices, err := e.svc.ListDevices()
		return devices, RPCErrorFrom(err)
	case "device.get":
		return e.deviceGet(req.Params)
	case "device.register":
		return e.deviceRegister(ctx, req.Params)
	case "device.remove":
		return e.deviceAction(ctx, req.Params, "remove")
	case "device.markSeen":
		return e.deviceAction(ctx, req.Params, "seen")
	case "device.interface.open":
		return e.deviceAction(ctx, req.Params, "open")
	case "device.interface.close":
		return e.deviceAction(ctx, req.Params, "close")
	case "device.interface.read":
		return e.deviceRead(req.Params)
	case "device.interface.write":
		return e.deviceWrite(req.Params)
	case "backup.create":
		return e.startBackup(ctx)
	case "backup.restore":
		return e.startRestore(ctx, req.Params)
	case "nodeRed.status.get":
		value, err := e.svc.NodeRed("nodered-state")
		return value, RPCErrorFrom(err)
	case "nodeRed.flows.get":
		value, err := e.svc.NodeRed("nodered-flows")
		if err != nil {
			return nil, RPCErrorFrom(err)
		}
		var decoded any
		if json.Unmarshal([]byte(value), &decoded) == nil {
			return decoded, nil
		}
		return value, nil
	case "nodeRed.flows.deploy":
		return e.startNodeRedDeploy(ctx, req.Params)
	case "nodeRed.action.execute":
		return e.nodeRedAction(req.Params)
	case "firmware.update.start":
		return e.startFirmware(ctx, req.Params)
	case "firmware.update.abort":
		if err := e.svc.OTAAbort(); err != nil {
			return nil, RPCErrorFrom(err)
		}
		return map[string]string{"status": "aborted"}, nil
	case "firmware.update.status.get":
		return e.svc.OTAStatus(), nil
	case "job.get":
		params, rpcErr := DecodeParams[struct {
			JobID string `json:"jobId"`
		}](req.Params)
		if rpcErr != nil || params.JobID == "" {
			return nil, required(rpcErr, "jobId")
		}
		return e.jobs.Get(params.JobID)
	case "job.list":
		jobs, err := e.jobs.List()
		return jobs, RPCErrorFrom(err)
	case "job.cancel":
		params, rpcErr := DecodeParams[struct {
			JobID string `json:"jobId"`
		}](req.Params)
		if rpcErr != nil || params.JobID == "" {
			return nil, required(rpcErr, "jobId")
		}
		return e.jobs.Cancel(params.JobID)
	case "log.stream.open":
		if e.streams == nil {
			return nil, &RPCError{Code: CodeInternalError, Message: "stream manager is unavailable"}
		}
		return e.streams.OpenLog(ctx, req.Params)
	case "terminal.open":
		if e.streams == nil {
			return nil, &RPCError{Code: CodeInternalError, Message: "stream manager is unavailable"}
		}
		return e.streams.OpenTerminal(ctx, req.Params)
	case "stream.close":
		if e.streams == nil {
			return nil, &RPCError{Code: CodeInternalError, Message: "stream manager is unavailable"}
		}
		return e.streams.CloseStream(req.Params)
	default:
		return nil, &RPCError{Code: CodeMethodNotFound, Message: fmt.Sprintf("method %q is not defined", req.Method)}
	}
}

func (e *Executor) health() map[string]any {
	instanceID, _ := os.Hostname()
	status := "fail"
	if e.svc.Health() {
		status = "pass"
	}
	return map[string]any{
		"healthy": e.svc.Health(), "status": status, "version": agent.Version,
		"commit": agent.Commit, "build_time": agent.BuildTime,
		"description": "agent service", "instance_id": instanceID,
	}
}

func (e *Executor) snapshot() (any, *RPCError) {
	devices, err := e.svc.ListDevices()
	if err != nil {
		return nil, RPCErrorFrom(err)
	}
	return map[string]any{
		"health": e.health(), "config": redactedConfig(e.svc.Config()),
		"services": e.svc.Services(), "devices": devices,
		"telemetry": e.svc.Telemetry(), "ota": e.svc.OTAStatus(),
		"revision": e.revision.Load(),
	}, nil
}

func (e *Executor) control(id, action string) (any, *RPCError) {
	if err := e.svc.Control(id, action); err != nil {
		return nil, RPCErrorFrom(err)
	}
	return map[string]string{"status": "accepted"}, nil
}

func (e *Executor) runtimeConfig() (any, *RPCError) {
	keys := []string{"log_level", "heartbeat_interval", "telemetry_interval", "terminal_session_timeout", "bs_valid"}
	values := make(map[string]string, len(keys))
	for _, key := range keys {
		if value, err := e.svc.GetRuntimeConfig(key); err == nil {
			values[key] = value
		}
	}
	return map[string]any{"revision": e.revision.Load(), "config": values}, nil
}

func (e *Executor) runtimeConfigSet(ctx context.Context, raw json.RawMessage) (any, *RPCError) {
	params, rpcErr := DecodeParams[struct {
		Key              string  `json:"key"`
		Value            string  `json:"value"`
		ExpectedRevision *uint64 `json:"expectedRevision,omitempty"`
	}](raw)
	if rpcErr != nil || params.Key == "" {
		return nil, required(rpcErr, "key")
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if rpcErr := e.checkRevision(params.ExpectedRevision); rpcErr != nil {
		return nil, rpcErr
	}
	if err := e.svc.SetRuntimeConfig(ctx, params.Key, params.Value); err != nil {
		return nil, RPCErrorFrom(err)
	}
	revision := e.revision.Add(1)
	return map[string]any{"revision": revision, "key": params.Key, "value": params.Value}, nil
}

func (e *Executor) serviceRegister(raw json.RawMessage) (any, *RPCError) {
	params, rpcErr := DecodeParams[struct {
		Name string `json:"name"`
		Type string `json:"type"`
	}](raw)
	if rpcErr != nil || params.Name == "" {
		return nil, required(rpcErr, "name")
	}
	if err := e.svc.RegisterService(params.Name, params.Type); err != nil {
		return nil, RPCErrorFrom(err)
	}
	return map[string]string{"status": "registered"}, nil
}

func (e *Executor) serviceRemove(raw json.RawMessage) (any, *RPCError) {
	params, rpcErr := DecodeParams[struct {
		Name string `json:"name"`
	}](raw)
	if rpcErr != nil || params.Name == "" {
		return nil, required(rpcErr, "name")
	}
	if err := e.svc.RemoveService(params.Name); err != nil {
		return nil, RPCErrorFrom(err)
	}
	return map[string]string{"status": "removed"}, nil
}

func (e *Executor) deviceGet(raw json.RawMessage) (any, *RPCError) {
	params, rpcErr := decodeDeviceID(raw)
	if rpcErr != nil {
		return nil, rpcErr
	}
	device, err := e.svc.GetDevice(params)
	return device, RPCErrorFrom(err)
}

func (e *Executor) deviceRegister(ctx context.Context, raw json.RawMessage) (any, *RPCError) {
	params, rpcErr := DecodeParams[struct {
		Name             string `json:"name"`
		ExternalID       string `json:"externalId"`
		ExternalKey      string `json:"externalKey"`
		InterfaceType    string `json:"interfaceType"`
		InterfaceAddress string `json:"interfaceAddress"`
	}](raw)
	if rpcErr != nil || params.Name == "" || params.ExternalID == "" || params.ExternalKey == "" {
		return nil, required(rpcErr, "name, externalId and externalKey")
	}
	device, err := e.svc.AddDevice(ctx, params.Name, params.ExternalID, params.ExternalKey, params.InterfaceType, params.InterfaceAddress)
	return device, RPCErrorFrom(err)
}

func (e *Executor) deviceAction(ctx context.Context, raw json.RawMessage, action string) (any, *RPCError) {
	id, rpcErr := decodeDeviceID(raw)
	if rpcErr != nil {
		return nil, rpcErr
	}
	var err error
	switch action {
	case "remove":
		err = e.svc.RemoveDevice(id)
	case "seen":
		err = e.svc.MarkDeviceSeen(id)
	case "open":
		err = e.svc.OpenDevice(ctx, id)
	case "close":
		err = e.svc.CloseDevice(id)
	}
	if err != nil {
		return nil, RPCErrorFrom(err)
	}
	return map[string]string{"status": "ok"}, nil
}

func (e *Executor) deviceRead(raw json.RawMessage) (any, *RPCError) {
	params, rpcErr := DecodeParams[struct {
		DeviceID string `json:"deviceId"`
		Bytes    int    `json:"bytes"`
	}](raw)
	if rpcErr != nil || params.DeviceID == "" || params.Bytes <= 0 {
		return nil, required(rpcErr, "deviceId and positive bytes")
	}
	data, err := e.svc.ReadDevice(params.DeviceID, params.Bytes)
	if err != nil {
		return nil, RPCErrorFrom(err)
	}
	return map[string]any{"dataBase64": base64.StdEncoding.EncodeToString(data), "bytesRead": len(data)}, nil
}

func (e *Executor) deviceWrite(raw json.RawMessage) (any, *RPCError) {
	params, rpcErr := DecodeParams[struct {
		DeviceID   string `json:"deviceId"`
		DataBase64 string `json:"dataBase64"`
	}](raw)
	if rpcErr != nil || params.DeviceID == "" || params.DataBase64 == "" {
		return nil, required(rpcErr, "deviceId and dataBase64")
	}
	data, err := base64.StdEncoding.DecodeString(params.DataBase64)
	if err != nil {
		return nil, &RPCError{Code: CodeInvalidParams, Message: "dataBase64 is invalid"}
	}
	written, err := e.svc.WriteDevice(params.DeviceID, hex.EncodeToString(data))
	if err != nil {
		return nil, RPCErrorFrom(err)
	}
	return map[string]int{"bytesWritten": written}, nil
}

func (e *Executor) nodeRedAction(raw json.RawMessage) (any, *RPCError) {
	params, rpcErr := DecodeParams[struct {
		Action string          `json:"action"`
		Flows  json.RawMessage `json:"flows,omitempty"`
	}](raw)
	if rpcErr != nil || params.Action == "" {
		return nil, required(rpcErr, "action")
	}
	allowed := map[string]string{"ping": "nodered-ping", "state": "nodered-state", "flows": "nodered-flows"}
	command, ok := allowed[params.Action]
	if params.Action == "addFlow" && len(params.Flows) > 0 {
		command = "nodered-add-flow," + base64.StdEncoding.EncodeToString(params.Flows)
		ok = true
	}
	if !ok {
		return nil, &RPCError{Code: CodeInvalidParams, Message: "unsupported Node-RED action"}
	}
	value, err := e.svc.NodeRed(command)
	return value, RPCErrorFrom(err)
}

func (e *Executor) startFirmware(ctx context.Context, raw json.RawMessage) (any, *RPCError) {
	params, rpcErr := DecodeParams[struct {
		URL    string `json:"url"`
		SHA256 string `json:"sha256"`
		Size   uint64 `json:"size"`
	}](raw)
	decodedHash, hashErr := hex.DecodeString(params.SHA256)
	if rpcErr != nil || !strings.HasPrefix(params.URL, "https://") ||
		hashErr != nil || len(decodedHash) != 32 {
		return nil, required(rpcErr, "https url and 64-character sha256")
	}
	job, err := e.jobs.Start(ctx, "firmware.update", func(jobCtx context.Context, update func(string, float64)) (any, error) {
		update("download", 0)
		done := make(chan error, 1)
		go func() {
			done <- e.svc.OTA(jobCtx, params.URL, params.SHA256, params.Size)
		}()
		ticker := time.NewTicker(500 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case err := <-done:
				status := e.svc.OTAStatus()
				update(status.State, status.Progress)
				return status, err
			case <-ticker.C:
				status := e.svc.OTAStatus()
				update(status.State, status.Progress)
			case <-jobCtx.Done():
				_ = e.svc.OTAAbort()
				err := <-done
				if err == nil {
					err = jobCtx.Err()
				}
				return e.svc.OTAStatus(), err
			}
		}
	})
	return job, RPCErrorFrom(err)
}

func (e *Executor) startBackup(ctx context.Context) (any, *RPCError) {
	job, err := e.jobs.Start(ctx, "backup.create", func(context.Context, func(string, float64)) (any, error) {
		return e.svc.BackupDevices()
	})
	return job, RPCErrorFrom(err)
}

func (e *Executor) startRestore(ctx context.Context, raw json.RawMessage) (any, *RPCError) {
	params, rpcErr := DecodeParams[struct {
		Backup  devicemgr.Backup `json:"backup"`
		Replace bool             `json:"replace"`
	}](raw)
	if rpcErr != nil {
		return nil, rpcErr
	}
	job, err := e.jobs.Start(ctx, "backup.restore", func(context.Context, func(string, float64)) (any, error) {
		count, err := e.svc.RestoreDevices(params.Backup, params.Replace)
		return map[string]int{"imported": count}, err
	})
	return job, RPCErrorFrom(err)
}

func (e *Executor) startNodeRedDeploy(ctx context.Context, raw json.RawMessage) (any, *RPCError) {
	params, rpcErr := DecodeParams[struct {
		Flows json.RawMessage `json:"flows"`
	}](raw)
	if rpcErr != nil || len(params.Flows) == 0 {
		return nil, required(rpcErr, "flows")
	}
	job, err := e.jobs.Start(ctx, "nodeRed.flows.deploy", func(context.Context, func(string, float64)) (any, error) {
		encoded := base64.StdEncoding.EncodeToString(params.Flows)
		return e.svc.NodeRed("nodered-deploy," + encoded)
	})
	return job, RPCErrorFrom(err)
}

func (e *Executor) startReset(ctx context.Context, raw json.RawMessage) (any, *RPCError) {
	params, rpcErr := DecodeParams[struct {
		Mode string `json:"mode"`
	}](raw)
	if rpcErr != nil || params.Mode == "" {
		return nil, required(rpcErr, "mode")
	}
	job, err := e.jobs.Start(ctx, "agent.reset", func(jobCtx context.Context, update func(string, float64)) (any, error) {
		update("resetting", 50)
		if err := e.svc.Reset(jobCtx, params.Mode); err != nil {
			return nil, err
		}
		if params.Mode == agent.ResetGraceful || params.Mode == agent.ResetImmediate || params.Mode == agent.ResetNow {
			go func() {
				time.Sleep(time.Second)
				_ = syscall.Exec(os.Args[0], os.Args, os.Environ())
			}()
		}
		return map[string]string{"mode": params.Mode}, nil
	})
	return job, RPCErrorFrom(err)
}

func (e *Executor) startConfigApply(ctx context.Context, raw json.RawMessage) (any, *RPCError) {
	params, rpcErr := DecodeParams[struct {
		Config           agent.Config `json:"config"`
		ExpectedRevision *uint64      `json:"expectedRevision,omitempty"`
	}](raw)
	if rpcErr != nil {
		return nil, rpcErr
	}
	job, err := e.jobs.Start(ctx, "config.apply", func(context.Context, func(string, float64)) (any, error) {
		e.mu.Lock()
		defer e.mu.Unlock()
		if conflict := e.checkRevision(params.ExpectedRevision); conflict != nil {
			return nil, conflict
		}
		current := e.svc.Config()
		if params.Config.MQTT.Password == "" {
			params.Config.MQTT.Password = current.MQTT.Password
		}
		if params.Config.MQTT.GatewayKey == "" {
			params.Config.MQTT.GatewayKey = current.MQTT.GatewayKey
		}
		if params.Config.MQTT.PrivKeyPath == "" {
			params.Config.MQTT.PrivKeyPath = current.MQTT.PrivKeyPath
		}
		if len(params.Config.MQTT.CA) == 0 {
			params.Config.MQTT.CA = current.MQTT.CA
		}
		if len(params.Config.MQTT.Cert.Certificate) == 0 {
			params.Config.MQTT.Cert = current.MQTT.Cert
		}
		if params.Config.Provision.Token == "" {
			params.Config.Provision.Token = current.Provision.Token
		}
		params.Config.CommandSecret = current.CommandSecret
		if params.Config.TenantID == "" || params.Config.MQTT.URL == "" ||
			params.Config.MQTT.Username == "" || params.Config.MQTT.Password == "" {
			return nil, fmt.Errorf("tenant_id and MQTT url, username and password are required")
		}
		if err := params.Config.Channels.Validate(); err != nil {
			return nil, err
		}
		if params.Config.Channels.CtrlID == params.Config.Channels.DataID {
			return nil, fmt.Errorf("control and data channels must be different")
		}
		if err := e.svc.AddConfig(params.Config); err != nil {
			return nil, err
		}
		revision := e.revision.Add(1)
		return map[string]uint64{"revision": revision}, nil
	})
	return job, RPCErrorFrom(err)
}

func (e *Executor) checkRevision(expected *uint64) *RPCError {
	if expected == nil {
		return nil
	}
	actual := e.revision.Load()
	if *expected != actual {
		return &RPCError{
			Code: CodeRevisionConflict, Message: "configuration revision conflict",
			Data: mustJSON(map[string]uint64{"expected": *expected, "actual": actual}),
		}
	}
	return nil
}

func decodeDeviceID(raw json.RawMessage) (string, *RPCError) {
	params, rpcErr := DecodeParams[struct {
		DeviceID string `json:"deviceId"`
	}](raw)
	if rpcErr != nil || params.DeviceID == "" {
		return "", required(rpcErr, "deviceId")
	}
	return params.DeviceID, nil
}

func required(rpcErr *RPCError, fields string) *RPCError {
	if rpcErr != nil {
		return rpcErr
	}
	return &RPCError{Code: CodeInvalidParams, Message: fields + " required"}
}

func redactedConfig(cfg agent.Config) agent.Config {
	cfg.MQTT.Password = ""
	cfg.MQTT.GatewayKey = ""
	cfg.MQTT.PrivKeyPath = ""
	cfg.Provision.Token = ""
	cfg.CommandSecret = ""
	return cfg
}

func requestRetention() time.Time {
	return time.Now().UTC().Add(24 * time.Hour)
}

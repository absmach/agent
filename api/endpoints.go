// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"strings"
	"syscall"

	"github.com/absmach/agent"
	"github.com/absmach/agent/pkg/nodered"
	mgerrors "github.com/absmach/magistrala/pkg/errors"
	"github.com/go-chi/chi/v5"
	"github.com/go-kit/kit/endpoint"
)

const svcName = "agent"

func pubEndpoint(svc agent.Service) endpoint.Endpoint {
	return func(_ context.Context, request any) (any, error) {
		req := request.(pubReq)

		if err := req.validate(); err != nil {
			return nil, err
		}

		topic := req.Topic
		payload := req.Payload

		if err := svc.Publish(topic, payload); err != nil {
			return nil, err
		}

		return publishRes{
			Service:  svcName,
			Response: "publish",
		}, nil
	}
}

func execEndpoint(svc agent.Service) endpoint.Endpoint {
	return func(_ context.Context, request any) (any, error) {
		req := request.(execReq)

		if err := req.validate(); err != nil {
			return nil, err
		}

		uuid := strings.TrimSuffix(req.BaseName, ":")
		out, err := svc.Execute(uuid, req.Value)
		if err != nil {
			return nil, err
		}

		resp := execRes{
			BaseName: req.BaseName,
			Name:     "exec",
			Value:    out,
		}
		return resp, nil
	}
}

func addConfigEndpoint(svc agent.Service) endpoint.Endpoint {
	return func(_ context.Context, request any) (any, error) {
		req := request.(addConfigReq)

		if err := req.validate(); err != nil {
			return nil, err
		}

		current := svc.Config()

		current.Server.Port = req.Server.Port
		current.Channels.CtrlID = req.Channels.CtrlID
		current.Channels.DataID = req.Channels.DataID
		current.NodeRed.URL = req.NodeRed.Url
		current.Log.Level = req.Log.Level
		current.MQTT.URL = req.Mqtt.Url
		current.MQTT.Username = req.Mqtt.Username
		current.MQTT.Password = req.Mqtt.Password

		if err := svc.AddConfig(current); err != nil {
			return nil, err
		}

		return addConfigRes{
			Service:  svcName,
			Response: "config",
		}, nil
	}
}

func viewConfigEndpoint(svc agent.Service) endpoint.Endpoint {
	return func(_ context.Context, request any) (any, error) {
		return viewConfigRes{Config: svc.Config()}, nil
	}
}

func viewServicesEndpoint(svc agent.Service) endpoint.Endpoint {
	return func(_ context.Context, request any) (any, error) {
		return viewServicesRes(svc.Services()), nil
	}
}

func nodeRedEndpoint(svc agent.Service) endpoint.Endpoint {
	return func(_ context.Context, request any) (any, error) {
		req := request.(nodeRedReq)

		if err := req.validate(); err != nil {
			return nil, err
		}

		cmdStr := req.Command
		if req.Flows != "" {
			cmdStr = req.Command + "," + req.Flows
		}

		resp, err := svc.NodeRed(cmdStr)
		if err != nil {
			if mgerrors.Contains(err, nodered.ErrFlowConflict) {
				return nil, mgerrors.NewSDKErrorWithStatus(err, http.StatusConflict)
			}
			return nil, err
		}

		return nodeRedRes{
			Service:  svcName,
			Response: resp,
		}, nil
	}
}

func listDevicesEndpoint(svc agent.Service) endpoint.Endpoint {
	return func(_ context.Context, _ any) (any, error) {
		devs, err := svc.ListDevices()
		if err != nil {
			return nil, err
		}
		return listDevicesRes{Devices: devs}, nil
	}
}

func getDeviceEndpoint(svc agent.Service) endpoint.Endpoint {
	return func(_ context.Context, request any) (any, error) {
		id := request.(string)
		d, err := svc.GetDevice(id)
		if err != nil {
			return nil, err
		}
		return getDeviceRes{Device: d}, nil
	}
}

func addDeviceEndpoint(svc agent.Service) endpoint.Endpoint {
	return func(ctx context.Context, request any) (any, error) {
		req := request.(addDeviceReq)
		if err := req.validate(); err != nil {
			return nil, err
		}
		d, err := svc.AddDevice(ctx, req.Name, req.ExtID, req.ExtKey, req.IfaceType, req.IfaceAddr)
		if err != nil {
			return nil, err
		}
		return addDeviceRes{Device: d}, nil
	}
}

func removeDeviceEndpoint(svc agent.Service) endpoint.Endpoint {
	return func(_ context.Context, request any) (any, error) {
		id := request.(string)
		if err := svc.RemoveDevice(id); err != nil {
			return nil, err
		}
		return removeDeviceRes{}, nil
	}
}

func markDeviceSeenEndpoint(svc agent.Service) endpoint.Endpoint {
	return func(_ context.Context, request any) (any, error) {
		id := request.(string)
		if err := svc.MarkDeviceSeen(id); err != nil {
			return nil, err
		}
		return markDeviceSeenRes{}, nil
	}
}

func decodeIDFromPath(_ context.Context, r *http.Request) (any, error) {
	return chi.URLParam(r, "id"), nil
}

func otaTriggerEndpoint(svc agent.Service) endpoint.Endpoint {
	return func(ctx context.Context, request any) (any, error) {
		req := request.(otaTriggerReq)
		if err := req.validate(); err != nil {
			return nil, err
		}
		// Detach from the request context so the OTA download continues after
		// the HTTP response is sent, while still inheriting request metadata
		// (e.g. trace IDs) via context values.
		otaCtx := context.WithoutCancel(ctx)
		go func() {
			_ = svc.OTA(otaCtx, req.URL, req.SHA256Hex, req.Size)
		}()
		return otaTriggerRes{Status: "triggered"}, nil
	}
}

func resetEndpoint(svc agent.Service) endpoint.Endpoint {
	return func(ctx context.Context, request any) (any, error) {
		req := request.(resetReq)
		if err := req.validate(); err != nil {
			return nil, err
		}
		mode := req.Mode
		if mode == "" {
			mode = agent.ResetGraceful
		}
		resetCtx := context.WithoutCancel(ctx)
		go func() {
			if err := svc.Reset(resetCtx, mode); err != nil {
				return
			}
			switch mode {
			case agent.ResetGraceful, agent.ResetImmediate, agent.ResetNow:
				if err := syscall.Exec(os.Args[0], os.Args, os.Environ()); err != nil {
					panic(err)
				}
			}
		}()
		return resetRes{
			Service:  svcName,
			Response: "reset",
			Mode:     mode,
		}, nil
	}
}

func otaStatusEndpoint(svc agent.Service) endpoint.Endpoint {
	return func(_ context.Context, _ any) (any, error) {
		return otaStatusRes{OTAStatusInfo: svc.OTAStatus()}, nil
	}
}

func openDeviceEndpoint(svc agent.Service) endpoint.Endpoint {
	return func(ctx context.Context, request any) (any, error) {
		id := request.(string)
		if err := svc.OpenDevice(ctx, id); err != nil {
			return nil, err
		}
		return simpleRes{Service: svcName, Response: "opened"}, nil
	}
}

func closeDeviceEndpoint(svc agent.Service) endpoint.Endpoint {
	return func(_ context.Context, request any) (any, error) {
		id := request.(string)
		if err := svc.CloseDevice(id); err != nil {
			return nil, err
		}
		return simpleRes{Service: svcName, Response: "closed"}, nil
	}
}

func readDeviceEndpoint(svc agent.Service) endpoint.Endpoint {
	return func(_ context.Context, request any) (any, error) {
		req := request.(decodeIDPayload)
		data, err := svc.ReadDevice(req.ID, req.Bytes)
		if err != nil {
			return nil, err
		}
		return deviceReadRes{Data: fmt.Sprintf("%x", data)}, nil
	}
}

func writeDeviceEndpoint(svc agent.Service) endpoint.Endpoint {
	return func(_ context.Context, request any) (any, error) {
		req := request.(decodeIDPayload)
		n, err := svc.WriteDevice(req.ID, req.Data)
		if err != nil {
			return nil, err
		}
		return deviceWriteRes{Bytes: n}, nil
	}
}

func runtimeConfigGetEndpoint(svc agent.Service) endpoint.Endpoint {
	return func(_ context.Context, request any) (any, error) {
		keys := []string{
			agent.KeyLogLevel,
			agent.KeyHeartbeatInterval,
			agent.KeyTelemetryInterval,
			agent.KeyTerminalSessionTimeout,
			agent.KeyCommandSecret,
			agent.KeyBsValid,
		}
		result := make(map[string]string)
		for _, k := range keys {
			val, err := svc.GetRuntimeConfig(k)
			if err != nil {
				result[k] = "error"
			} else {
				result[k] = val
			}
		}
		return runtimeConfigRes{Config: result}, nil
	}
}

func runtimeConfigSetEndpoint(svc agent.Service) endpoint.Endpoint {
	return func(ctx context.Context, request any) (any, error) {
		req := request.(runtimeConfigReq)
		if err := req.validate(); err != nil {
			return nil, err
		}
		if err := svc.SetRuntimeConfig(ctx, req.Key, req.Value); err != nil {
			return nil, err
		}
		return simpleRes{Service: svcName, Response: "ok"}, nil
	}
}

func telemetryDataEndpoint(svc agent.Service) endpoint.Endpoint {
	return func(_ context.Context, _ any) (any, error) {
		return svc.Telemetry(), nil
	}
}

func addServiceEndpoint(svc agent.Service) endpoint.Endpoint {
	return func(_ context.Context, request any) (any, error) {
		req := request.(addServiceReq)
		if err := req.validate(); err != nil {
			return nil, err
		}
		if err := svc.RegisterService(req.Name, req.Type); err != nil {
			return nil, err
		}
		return simpleRes{Service: svcName, Response: "registered"}, nil
	}
}

func removeServiceEndpoint(svc agent.Service) endpoint.Endpoint {
	return func(_ context.Context, request any) (any, error) {
		id := request.(string)
		if id == "" {
			return nil, agent.ErrMalformedEntity
		}
		if err := svc.RemoveService(id); err != nil {
			return nil, err
		}
		return removeDeviceRes{}, nil
	}
}

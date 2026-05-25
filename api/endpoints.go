// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	"net/http"
	"strings"

	"github.com/absmach/agent"
	"github.com/absmach/agent/pkg/nodered"
	mgerrors "github.com/absmach/magistrala/pkg/errors"
	"github.com/go-chi/chi/v5"
	"github.com/go-kit/kit/endpoint"
)

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
			Service:  "agent",
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
			Service:  "agent",
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
			Service:  "agent",
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
		go func() {
			_ = svc.OTA(ctx, req.URL, req.SHA256Hex, req.Size)
		}()
		return otaTriggerRes{Status: "triggered"}, nil
	}
}

func otaStatusEndpoint(svc agent.Service) endpoint.Endpoint {
	return func(_ context.Context, _ any) (any, error) {
		return otaStatusRes{OTAStatusInfo: svc.OTAStatus()}, nil
	}
}

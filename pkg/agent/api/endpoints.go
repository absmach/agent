// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	"strings"

	"github.com/absmach/agent/pkg/agent"
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

		return genericRes{
			Service:  "agent",
			Response: "config",
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
		current.Channels.ID = req.Channels.ID
		current.NodeRed.URL = req.NodeRed.Url
		current.Log.Level = req.Log.Level
		current.MQTT.URL = req.Mqtt.Url
		current.MQTT.Username = req.Mqtt.Username
		current.MQTT.Password = req.Mqtt.Password

		if err := svc.AddConfig(current); err != nil {
			return nil, err
		}

		return genericRes{
			Service:  "agent",
			Response: "config",
		}, nil
	}
}

func viewConfigEndpoint(svc agent.Service) endpoint.Endpoint {
	return func(_ context.Context, request any) (any, error) {
		c := svc.Config()
		return c, nil
	}
}

func viewServicesEndpoint(svc agent.Service) endpoint.Endpoint {
	return func(_ context.Context, request any) (any, error) {
		return svc.Services(), nil
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
			return nil, err
		}

		return genericRes{
			Service:  "agent",
			Response: resp,
		}, nil
	}
}

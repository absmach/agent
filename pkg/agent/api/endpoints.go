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
	return func(_ context.Context, request interface{}) (interface{}, error) {
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
	return func(_ context.Context, request interface{}) (interface{}, error) {
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
	return func(_ context.Context, request interface{}) (interface{}, error) {
		req := request.(addConfigReq)

		if err := req.validate(); err != nil {
			return nil, err
		}

		sc := agent.ServerConfig{Port: req.Agent.Server.Port}
		cc := agent.ChanConfig{
			ID: req.Agent.Channels.ID,
		}
		nc := agent.NodeRedConfig{URL: req.Agent.NodeRed.Url}
		lc := agent.LogConfig{Level: req.Agent.Log.Level}
		mc := agent.MQTTConfig{
			URL:      req.Agent.Mqtt.Url,
			Username: req.Agent.Mqtt.Username,
			Password: req.Agent.Mqtt.Password,
		}
		c := agent.Config{
			Server:   sc,
			Channels: cc,
			NodeRed:  nc,
			Log:      lc,
			MQTT:     mc,
		}

		if err := svc.AddConfig(c); err != nil {
			return nil, err
		}

		return genericRes{
			Service:  "agent",
			Response: "config",
		}, nil
	}
}

func viewConfigEndpoint(svc agent.Service) endpoint.Endpoint {
	return func(_ context.Context, request interface{}) (interface{}, error) {
		c := svc.Config()
		return c, nil
	}
}

func viewServicesEndpoint(svc agent.Service) endpoint.Endpoint {
	return func(_ context.Context, request interface{}) (interface{}, error) {
		return svc.Services(), nil
	}
}

func nodeRedEndpoint(svc agent.Service) endpoint.Endpoint {
	return func(_ context.Context, request interface{}) (interface{}, error) {
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

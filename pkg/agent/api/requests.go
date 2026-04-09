// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"github.com/absmach/agent/pkg/agent"
)

type pubReq struct {
	Topic   string `json:"topic"`
	Payload string `json:"payload"`
}

func (req pubReq) validate() error {
	if req.Topic == "" || req.Payload == "" {
		return agent.ErrMalformedEntity
	}

	return nil
}

type execReq struct {
	BaseName string `json:"bn"`
	Name     string `json:"n"`
	Value    string `json:"vs"`
}

func (req execReq) validate() error {
	if req.BaseName == "" || req.Name != "exec" || req.Value == "" {
		return agent.ErrMalformedEntity
	}

	return nil
}

type addConfigReq struct {
	agentConfig
}

func (req addConfigReq) validate() error {
	if req.Server.Port == "" ||
		req.Mqtt.Username == "" ||
		req.Mqtt.Password == "" ||
		req.Channels.ID == "" ||
		req.Log.Level == "" ||
		req.Mqtt.Url == "" {
		return agent.ErrMalformedEntity
	}

	return nil
}

type nodeRedReq struct {
	Command string `json:"command"`
	Flows   string `json:"flows"`
}

func (req nodeRedReq) validate() error {
	if req.Command == "" {
		return agent.ErrMalformedEntity
	}

	return nil
}

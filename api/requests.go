// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"github.com/absmach/agent"
)

type serverConfig struct {
	Port string `json:"port"`
}

type chanConfig struct {
	CtrlID string `json:"ctrl_id"`
	DataID string `json:"data_id"`
}

type noderedConfig struct {
	Url string `json:"url"`
}

type logConfig struct {
	Level string `json:"level"`
}

type mqttConfig struct {
	Url      string `json:"url"`
	Username string `json:"username"`
	Password string `json:"password"`
	QoS      byte   `json:"qos"`
}

// Config struct of Magistrala Agent.
type agentConfig struct {
	Server   serverConfig  `json:"server"`
	Channels chanConfig    `json:"channels"`
	NodeRed  noderedConfig `json:"nodered"`
	Log      logConfig     `json:"log"`
	Mqtt     mqttConfig    `json:"mqtt"`
}

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
		(req.Channels.CtrlID == "" || req.Channels.DataID == "") ||
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

type addDeviceReq struct {
	Name      string `json:"name"`
	ExtID     string `json:"ext_id"`
	ExtKey    string `json:"ext_key"`
	IfaceType string `json:"interface_type"`
	IfaceAddr string `json:"interface_addr"`
}

func (req addDeviceReq) validate() error {
	if req.Name == "" || req.ExtID == "" || req.ExtKey == "" || req.IfaceType == "" || req.IfaceAddr == "" {
		return agent.ErrMalformedEntity
	}
	return nil
}

type otaTriggerReq struct {
	URL       string `json:"url"`
	SHA256Hex string `json:"sha256,omitempty"`
	Size      uint64 `json:"size,omitempty"`
}

func (req otaTriggerReq) validate() error {
	if req.URL == "" {
		return agent.ErrMalformedEntity
	}
	return nil
}

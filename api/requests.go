// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"github.com/absmach/agent"
	"github.com/absmach/agent/pkg/devicemgr"
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

type coapConfig struct {
	Url            string `json:"url"`
	PSK            string `json:"psk"`
	SkipTLSVer     bool   `json:"skip_tls_ver"`
	MaxObserve     uint   `json:"max_observe"`
	MaxRetransmits uint   `json:"max_retransmits"`
	KeepAlive      uint64 `json:"keep_alive"`
	ContentFormat  int    `json:"content_format"`
	Cert           string `json:"cert"`
	Key            string `json:"key"`
	CA             string `json:"ca"`
}

// Config struct of Magistrala Agent.
type agentConfig struct {
	Server    serverConfig  `json:"server"`
	Channels  chanConfig    `json:"channels"`
	NodeRed   noderedConfig `json:"nodered"`
	Log       logConfig     `json:"log"`
	Mqtt      mqttConfig    `json:"mqtt"`
	CoAP      coapConfig    `json:"coap"`
	Transport string        `json:"transport"`
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

type addConfigReq struct {
	agentConfig
}

func (req addConfigReq) validate() error {
	if req.Server.Port == "" ||
		(req.Channels.CtrlID == "" || req.Channels.DataID == "") ||
		req.Log.Level == "" {
		return agent.ErrMalformedEntity
	}

	switch req.Transport {
	case "coap":
		if req.CoAP.Url == "" {
			return agent.ErrMalformedEntity
		}
	default:
		if req.Mqtt.Username == "" ||
			req.Mqtt.Password == "" ||
			req.Mqtt.Url == "" {
			return agent.ErrMalformedEntity
		}
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

type restoreDevicesReq struct {
	Backup  devicemgr.Backup
	Replace bool
}

func (req restoreDevicesReq) validate() error {
	for _, d := range req.Backup.Devices {
		if d.ID == "" {
			return agent.ErrMalformedEntity
		}
	}
	return nil
}

type resetReq struct {
	Mode string `json:"mode"`
}

func (req resetReq) validate() error {
	switch req.Mode {
	case agent.ResetGraceful, agent.ResetImmediate, agent.ResetNow, agent.ResetWatchdog, "":
		return nil
	default:
		return agent.ErrMalformedEntity
	}
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

// otaDataReq carries a raw firmware binary for MQTT-style OTA installation
// (the HTTP equivalent of publishing to the ota data topic). The SHA-256 hash
// is mandatory because there is no sidecar fallback for data-delivered firmware.
type otaDataReq struct {
	Data      []byte
	SHA256Hex string
}

func (req otaDataReq) validate() error {
	if req.SHA256Hex == "" {
		return agent.ErrMalformedEntity
	}
	if len(req.Data) == 0 {
		return agent.ErrMalformedEntity
	}
	return nil
}

// controlReq drives the agent lifecycle control subcommands (stop, start,
// reload) over HTTP. The response is published to the MQTT control channel
// exactly as if the command had arrived over MQTT.
type controlReq struct {
	Command string `json:"command"`
}

func (req controlReq) validate() error {
	switch req.Command {
	case agent.CtrlStop, agent.CtrlStart, agent.CtrlReload:
		return nil
	default:
		return agent.ErrMalformedEntity
	}
}

type runtimeConfigReq struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

func (req runtimeConfigReq) validate() error {
	if req.Key == "" {
		return agent.ErrMalformedEntity
	}
	return nil
}

type decodeIDPayload struct {
	ID    string
	Bytes int    `json:"bytes"`
	Data  string `json:"data"`
}

type addServiceReq struct {
	Name string `json:"name"`
	Type string `json:"type"`
}

func (req addServiceReq) validate() error {
	if req.Name == "" {
		return agent.ErrMalformedEntity
	}
	return nil
}

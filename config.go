// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"crypto/tls"
	"encoding/json"
	"time"

	"github.com/absmach/magistrala/pkg/errors"
)

type ServerConfig struct {
	Port string `json:"port"`
}

type ChanConfig struct {
	CtrlID string `json:"ctrl_id"`
	DataID string `json:"data_id"`
}

func (c ChanConfig) CtrlChan() string {
	return c.CtrlID
}

func (c ChanConfig) DataChan() string {
	return c.DataID
}

func (c ChanConfig) Validate() error {
	if c.CtrlID == "" {
		return errors.New("channels.ctrl_id is required")
	}
	if c.DataID == "" {
		return errors.New("channels.data_id is required")
	}
	return nil
}

type NodeRedConfig struct {
	URL string `json:"url"`
}

type LogConfig struct {
	Level string `json:"level"`
}

type MQTTConfig struct {
	URL         string          `json:"url"`
	Username    string          `json:"username"`
	Password    string          `json:"password"`
	MTLS        bool            `json:"mtls"`
	SkipTLSVer  bool            `json:"skip_tls_ver"`
	Retain      bool            `json:"retain"`
	QoS         byte            `json:"qos"`
	CmdQoS      byte            `json:"cmd_qos"`
	CAPath      string          `json:"ca_path"`
	CertPath    string          `json:"cert_path"`
	PrivKeyPath string          `json:"priv_key_path"`
	CA          []byte          `json:"-"`
	Cert        tls.Certificate `json:"-"`
	GatewayCert string          `json:"gateway_cert"`
	GatewayKey  string          `json:"gateway_key"`
	CaCert      string          `json:"ca_cert"`
}

type HeartbeatConfig struct {
	Interval time.Duration
}

type TelemetryConfig struct {
	Interval           time.Duration `json:"interval"`
	IncludeTemperature bool          `json:"include_temperature"`
	IncludeNetwork     bool          `json:"include_network"`
	IncludeLoad        bool          `json:"include_load"`
}

type TerminalConfig struct {
	SessionTimeout time.Duration `json:"session_timeout"`
}

type OTAConfig struct {
	Enabled     bool   `json:"enabled"`
	BinaryPath  string `json:"binary_path"`
	DownloadDir string `json:"download_dir"`
}

type CoAPConfig struct {
	URL            string `json:"url"`
	PSK            string `json:"psk"`
	CertPath       string `json:"cert_path"`
	PrivKeyPath    string `json:"priv_key_path"`
	CAPath         string `json:"ca_path"`
	SkipTLSVer     bool   `json:"skip_tls_ver"`
	MaxObserve     uint   `json:"max_observe"`
	MaxRetransmits uint   `json:"max_retransmits"`
	KeepAlive      uint64 `json:"keep_alive"`
	ContentFormat  int    `json:"content_format"`
	Cert           string `json:"cert"`
	Key            string `json:"key"`
	CA             string `json:"ca"`
}

type ProvisionConfig struct {
	AtomURL        string `json:"atom_url"`
	RulesEngineURL string `json:"rules_engine_url"`
	Token          string `json:"token"`
	DBPath         string `json:"db_path"`
	TenantID       string `json:"tenant_id"`
}

type Config struct {
	Server        ServerConfig    `json:"server"`
	Terminal      TerminalConfig  `json:"terminal"`
	Heartbeat     HeartbeatConfig `json:"heartbeat"`
	Telemetry     TelemetryConfig `json:"telemetry"`
	Channels      ChanConfig      `json:"channels"`
	NodeRed       NodeRedConfig   `json:"nodered"`
	Log           LogConfig       `json:"log"`
	MQTT          MQTTConfig      `json:"mqtt"`
	CoAP          CoAPConfig      `json:"coap"`
	Transport     string          `json:"transport"`
	OTA           OTAConfig       `json:"ota"`
	Provision     ProvisionConfig `json:"provision"`
	TenantID      string          `json:"tenant_id"`
	CommandSecret string          `json:"-"`
}

func NewConfig(sc ServerConfig, cc ChanConfig, nc NodeRedConfig, lc LogConfig, mc MQTTConfig, coc CoAPConfig, transport string, hc HeartbeatConfig, tc TerminalConfig, oc OTAConfig, tlc TelemetryConfig) Config {
	return Config{
		Server:    sc,
		Channels:  cc,
		NodeRed:   nc,
		Log:       lc,
		MQTT:      mc,
		CoAP:      coc,
		Transport: transport,
		Heartbeat: hc,
		Terminal:  tc,
		OTA:       oc,
		Telemetry: tlc,
	}
}

// UnmarshalJSON parses the duration from JSON.
func (d *HeartbeatConfig) UnmarshalJSON(b []byte) error {
	var v map[string]any
	if err := json.Unmarshal(b, &v); err != nil {
		return err
	}
	interval, ok := v["interval"]
	if !ok {
		return errors.New("missing value")
	}
	switch value := interval.(type) {
	case float64:
		d.Interval = time.Duration(value)
		return nil
	case string:
		var err error
		d.Interval, err = time.ParseDuration(value)
		if err != nil {
			return err
		}
		return nil
	default:
		return errors.New("invalid duration")
	}
}

// UnmarshalJSON parses the duration from JSON.
func (d *TerminalConfig) UnmarshalJSON(b []byte) error {
	var v map[string]any
	if err := json.Unmarshal(b, &v); err != nil {
		return err
	}
	session_timeout, ok := v["session_timeout"]
	if !ok {
		return errors.New("missing value")
	}
	switch value := session_timeout.(type) {
	case float64:
		d.SessionTimeout = time.Duration(value)
		return nil
	case string:
		var err error
		d.SessionTimeout, err = time.ParseDuration(value)
		if err != nil {
			return err
		}
		return nil
	default:
		return errors.New("invalid duration")
	}
}

// UnmarshalJSON parses the duration from JSON.
func (d *TelemetryConfig) UnmarshalJSON(b []byte) error {
	var v map[string]any
	if err := json.Unmarshal(b, &v); err != nil {
		return err
	}
	interval, ok := v["interval"]
	if !ok {
		return errors.New("missing value")
	}
	switch value := interval.(type) {
	case float64:
		d.Interval = time.Duration(value)
		return nil
	case string:
		var err error
		d.Interval, err = time.ParseDuration(value)
		if err != nil {
			return err
		}
		return nil
	default:
		return errors.New("invalid duration")
	}
}

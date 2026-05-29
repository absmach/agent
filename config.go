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
	CAPath      string          `json:"ca_path"`
	CertPath    string          `json:"cert_path"`
	PrivKeyPath string          `json:"priv_key_path"`
	CA          []byte          `json:"-"`
	Cert        tls.Certificate `json:"-"`
	ClientCert  string          `json:"client_cert"`
	ClientKey   string          `json:"client_key"`
	CaCert      string          `json:"ca_cert"`
}

type HeartbeatConfig struct {
	Interval time.Duration
}

type TerminalConfig struct {
	SessionTimeout time.Duration `json:"session_timeout"`
}

type OTAConfig struct {
	Enabled     bool   `json:"enabled"`
	BinaryPath  string `json:"binary_path"`
	DownloadDir string `json:"download_dir"`
}

type ProvisionConfig struct {
	ClientsURL     string `json:"clients_url"`
	ChannelsURL    string `json:"channels_url"`
	RulesEngineURL string `json:"rules_engine_url"`
	Token          string `json:"token"`
	DBPath         string `json:"db_path"`
	DomainID       string `json:"domain_id"`
}

type Config struct {
	Server    ServerConfig    `json:"server"`
	Terminal  TerminalConfig  `json:"terminal"`
	Heartbeat HeartbeatConfig `json:"heartbeat"`
	Channels  ChanConfig      `json:"channels"`
	NodeRed   NodeRedConfig   `json:"nodered"`
	Log       LogConfig       `json:"log"`
	MQTT      MQTTConfig      `json:"mqtt"`
	OTA       OTAConfig       `json:"ota"`
	Provision ProvisionConfig `json:"provision"`
	DomainID  string          `json:"domain_id"`
}

func NewConfig(sc ServerConfig, cc ChanConfig, nc NodeRedConfig, lc LogConfig, mc MQTTConfig, hc HeartbeatConfig, tc TerminalConfig, oc OTAConfig) Config {
	return Config{
		Server:    sc,
		Channels:  cc,
		NodeRed:   nc,
		Log:       lc,
		MQTT:      mc,
		Heartbeat: hc,
		Terminal:  tc,
		OTA:       oc,
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

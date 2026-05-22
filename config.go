// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"crypto/tls"
	"encoding/json"
	"strconv"
	"strings"
	"time"

	"github.com/absmach/magistrala/pkg/errors"
)

var errConfigKeyNotFound = errors.New("config key not found")

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
	Interval time.Duration `json:"interval"`
}

type TerminalConfig struct {
	SessionTimeout time.Duration `json:"session_timeout"`
}

type OTAConfig struct {
	Enabled     bool   `json:"enabled"`
	BinaryPath  string `json:"binary_path"`
	DownloadDir string `json:"download_dir"`
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

func ApplyOverrides(cfg *Config, overrides map[string]string) error {
	for key, value := range overrides {
		if err := applyConfigOverride(cfg, key, value); err != nil {
			return err
		}
	}

	return nil
}

func applyConfigOverride(cfg *Config, key, value string) error {
	b, err := json.Marshal(cfg)
	if err != nil {
		return err
	}

	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		return err
	}

	if err := setInMap(m, key, value); err != nil {
		return err
	}

	b, err = json.Marshal(m)
	if err != nil {
		return err
	}

	return json.Unmarshal(b, cfg)
}

func configGetFromMap(m map[string]any, key string) (string, error) {
	parts := strings.Split(key, ".")
	current := any(m)
	for _, part := range parts {
		cm, ok := current.(map[string]any)
		if !ok {
			return "", errConfigKeyNotFound
		}

		val, ok := cm[part]
		if !ok {
			return "", errConfigKeyNotFound
		}
		current = val
	}

	switch v := current.(type) {
	case string:
		return v, nil
	case float64:
		return strconv.FormatFloat(v, 'f', -1, 64), nil
	case bool:
		return strconv.FormatBool(v), nil
	default:
		b, _ := json.Marshal(v)

		return string(b), nil
	}
}

func setInMap(m map[string]any, key, value string) error {
	parts := strings.Split(key, ".")
	current := m
	for i := 0; i < len(parts)-1; i++ {
		next, ok := current[parts[i]]
		if !ok {
			return errConfigKeyNotFound
		}

		cm, ok := next.(map[string]any)
		if !ok {
			return errConfigKeyNotFound
		}
		current = cm
	}

	leaf := parts[len(parts)-1]
	existing, ok := current[leaf]
	if !ok {
		return errConfigKeyNotFound
	}

	switch existing.(type) {
	case bool:
		b, err := strconv.ParseBool(value)
		if err != nil {
			current[leaf] = value

			return nil
		}
		current[leaf] = b
	case float64:
		f, err := strconv.ParseFloat(value, 64)
		if err != nil {
			current[leaf] = value

			return nil
		}
		current[leaf] = f
	default:
		current[leaf] = value
	}

	return nil
}

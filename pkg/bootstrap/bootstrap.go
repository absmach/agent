// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/absmach/agent/pkg/agent"
	"github.com/absmach/magistrala/bootstrap"
	"github.com/absmach/magistrala/pkg/errors"
	toml "github.com/pelletier/go-toml"
)

const exportConfigFile = "/configs/export/config.toml"

type exportMQTT struct {
	Username          string `json:"username" toml:"username"`
	Password          string `json:"password" toml:"password"`
	ClientCert        string `json:"client_cert" toml:"client_cert"`
	ClientCertKey     string `json:"client_cert_key" toml:"client_cert_key"`
	ClientCertPath    string `json:"client_cert_path" toml:"client_cert_path"`
	ClientPrivKeyPath string `json:"client_priv_key_path" toml:"client_priv_key_path"`
}

type exportRoute struct {
	MqttTopic string `json:"mqtt_topic" toml:"mqtt_topic"`
	SubTopic  string `json:"subtopic" toml:"subtopic"`
	Type      string `json:"type" toml:"type"`
	Workers   int    `json:"workers" toml:"workers"`
}

type exportConfig struct {
	MQTT   exportMQTT    `json:"mqtt" toml:"mqtt"`
	Routes []exportRoute `json:"routes" toml:"routes"`
	File   string        `json:"file" toml:"-"`
}

// Config represents the parameters for bootstrapping.
type Config struct {
	URL           string
	ID            string
	Key           string
	Retries       string
	RetryDelaySec string
	Encrypt       string
	SkipTLS       bool
}

type ServicesConfig struct {
	Agent  agent.Config `json:"agent"`
	Export exportConfig `json:"export"`
}

type ConfigContent struct {
	Content string `json:"content"`
}

type deviceConfig struct {
	ClientID         string              `json:"client_id"`
	ClientSecret     string              `json:"client_secret"`
	Channels         []bootstrap.Channel `json:"channels"`
	MainfluxID       string              `json:"mainflux_id"`
	MainfluxKey      string              `json:"mainflux_key"`
	MainfluxChannels []bootstrap.Channel `json:"mainflux_channels"`
	ClientKey        string              `json:"client_key"`
	ClientCert       string              `json:"client_cert"`
	CaCert           string              `json:"ca_cert"`
	SvcsConf         ServicesConfig      `json:"-"`
}

// Bootstrap - Retrieve device config.
func Bootstrap(cfg Config, logger *slog.Logger, file string) error {
	retries, err := strconv.ParseUint(cfg.Retries, 10, 64)
	if err != nil {
		return errors.New(fmt.Sprintf("Invalid BOOTSTRAP_RETRIES value: %s", err))
	}

	if retries == 0 {
		logger.Info("No bootstrapping, environment variables will be used")
		return nil
	}

	retryDelaySec, err := strconv.ParseUint(cfg.RetryDelaySec, 10, 64)
	if err != nil {
		return errors.New(fmt.Sprintf("Invalid BOOTSTRAP_RETRY_DELAY_SECONDS value: %s", err))
	}

	logger.Info("Requesting config", slog.String("config_id", cfg.ID), slog.String("config_url", cfg.URL))

	dc := deviceConfig{}

	for i := 0; i < int(retries); i++ {
		dc, err = getConfig(cfg.ID, cfg.Key, cfg.URL, cfg.SkipTLS, logger)
		if err == nil {
			break
		}
		logger.Error("Fetching bootstrap failed", slog.Any("error", err))

		logger.Debug("Retrying...", slog.Uint64("retries_remaining", retries), slog.Uint64("delay", retryDelaySec))
		time.Sleep(time.Duration(retryDelaySec) * time.Second)
		if i == int(retries)-1 {
			logger.Warn("Retries exhausted")
			logger.Info("Continuing with local config")
			return nil
		}
	}

	dc.normalize()

	if len(dc.Channels) < 1 {
		return agent.ErrMalformedEntity
	}

	sc := dc.SvcsConf.Agent.Server
	cc := agent.ChanConfig{
		ID: dc.Channels[0].ID,
	}
	lc := dc.SvcsConf.Agent.Log
	nc := dc.SvcsConf.Agent.NodeRed

	mc := dc.SvcsConf.Agent.MQTT
	mc.Password = dc.ClientSecret
	mc.Username = dc.ClientID
	mc.ClientCert = dc.ClientCert
	mc.ClientKey = dc.ClientKey
	mc.CaCert = dc.CaCert

	hc := dc.SvcsConf.Agent.Heartbeat
	tc := dc.SvcsConf.Agent.Terminal
	c := agent.NewConfig(sc, cc, nc, lc, mc, hc, tc, file)

	dc.SvcsConf.Export = fillExportConfig(dc.SvcsConf.Export, c)

	saveExportConfig(dc.SvcsConf.Export, logger)

	return agent.SaveConfig(c)
}

func (dc *deviceConfig) normalize() {
	if dc.ClientID == "" {
		dc.ClientID = dc.MainfluxID
	}
	if dc.ClientSecret == "" {
		dc.ClientSecret = dc.MainfluxKey
	}
	if len(dc.Channels) == 0 {
		dc.Channels = dc.MainfluxChannels
	}
}

// if export config isnt filled use agent configs.
func fillExportConfig(econf exportConfig, c agent.Config) exportConfig {
	if econf.MQTT.Username == "" {
		econf.MQTT.Username = c.MQTT.Username
	}
	if econf.MQTT.Password == "" {
		econf.MQTT.Password = c.MQTT.Password
	}
	if econf.MQTT.ClientCert == "" {
		econf.MQTT.ClientCert = c.MQTT.ClientCert
	}
	if econf.MQTT.ClientCertKey == "" {
		econf.MQTT.ClientCertKey = c.MQTT.ClientKey
	}
	if econf.MQTT.ClientCertPath == "" {
		econf.MQTT.ClientCertPath = c.MQTT.CertPath
	}
	if econf.MQTT.ClientPrivKeyPath == "" {
		econf.MQTT.ClientPrivKeyPath = c.MQTT.PrivKeyPath
	}
	for i, route := range econf.Routes {
		if route.MqttTopic == "" {
			econf.Routes[i].MqttTopic = "channels/" + c.Channels.ID + "/messages"
		}
	}
	return econf
}

func saveExportConfig(econf exportConfig, logger *slog.Logger) {
	file := econf.File
	if file == "" {
		file = exportConfigFile
	}
	if _, err := os.Stat(file); err == nil {
		logger.Info("Export config file exists", slog.Any("file", file))
		return
	}
	logger.Info("Saving export config file", slog.Any("file", file))
	b, err := toml.Marshal(econf)
	if err != nil {
		logger.Warn("Failed to marshal export config", slog.Any("error", err))
		return
	}
	if err := os.WriteFile(file, b, 0o644); err != nil {
		logger.Warn("Failed to save export config file", slog.Any("error", err))
	}
}

func getConfig(bsID, bsKey, bsSvrURL string, skipTLS bool, logger *slog.Logger) (deviceConfig, error) {
	// Get the SystemCertPool, continue with an empty pool on error.
	rootCAs, err := x509.SystemCertPool()
	if err != nil {
		logger.Error(err.Error())
	}
	if rootCAs == nil {
		rootCAs = x509.NewCertPool()
	}
	// Trust the augmented cert pool in our client.
	config := &tls.Config{
		InsecureSkipVerify: skipTLS,
		RootCAs:            rootCAs,
	}
	tr := &http.Transport{TLSClientConfig: config}
	client := &http.Client{Transport: tr}
	url := fmt.Sprintf("%s/%s", bsSvrURL, bsID)

	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return deviceConfig{}, err
	}

	authScheme := "Client"
	if strings.Contains(bsSvrURL, "/things/bootstrap") {
		authScheme = "Thing"
	}
	req.Header.Add("Authorization", fmt.Sprintf("%s %s", authScheme, bsKey))
	resp, err := client.Do(req)
	if err != nil {
		return deviceConfig{}, err
	}
	if resp.StatusCode >= http.StatusBadRequest {
		return deviceConfig{}, errors.New(http.StatusText(resp.StatusCode))
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return deviceConfig{}, err
	}
	defer resp.Body.Close()
	dc := deviceConfig{}
	h := ConfigContent{}
	if err := json.Unmarshal([]byte(body), &h); err != nil {
		return deviceConfig{}, err
	}
	fmt.Println(h.Content)
	sc := ServicesConfig{}
	if err := json.Unmarshal([]byte(h.Content), &sc); err != nil {
		return deviceConfig{}, err
	}
	if err := json.Unmarshal([]byte(body), &dc); err != nil {
		return deviceConfig{}, err
	}
	dc.SvcsConf = sc
	return dc, nil
}

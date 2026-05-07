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

// ServicesConfig holds the full agent and export configuration embedded in
// the bootstrap content field.
type ServicesConfig struct {
	Agent  agent.Config `json:"agent"`
	Export exportConfig `json:"export"`
}

// bootstrapResponse holds the fields returned by the bootstrap endpoint.
// All device credentials and channel information arrive via the rendered
// Content field; ClientCert, ClientKey, and CaCert remain direct response fields.
type bootstrapResponse struct {
	Content    string `json:"content"`
	ClientKey  string `json:"client_key"`
	ClientCert string `json:"client_cert"`
	CaCert     string `json:"ca_cert"`
}

// Bootstrap retrieves device configuration from the bootstrap service and
// writes it to the local config file.
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

	var br bootstrapResponse

	for i := 0; i < int(retries); i++ {
		br, err = getConfig(cfg.ID, cfg.Key, cfg.URL, cfg.SkipTLS, logger)
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

	var sc ServicesConfig
	if err := json.Unmarshal([]byte(br.Content), &sc); err != nil {
		return fmt.Errorf("failed to parse bootstrap content: %w", err)
	}

	if sc.Agent.Channels.ID == "" {
		return agent.ErrMalformedEntity
	}

	// MQTT credentials and channel arrive via rendered content; certificates
	// are still returned as direct fields on the bootstrap response.
	mc := sc.Agent.MQTT
	mc.ClientCert = br.ClientCert
	mc.ClientKey = br.ClientKey
	mc.CaCert = br.CaCert

	c := agent.NewConfig(sc.Agent.Server, sc.Agent.Channels, sc.Agent.NodeRed, sc.Agent.Log, mc, sc.Agent.Heartbeat, sc.Agent.Terminal, file)
	c.DomainID = sc.Agent.DomainID

	sc.Export = fillExportConfig(sc.Export, c)
	saveExportConfig(sc.Export, logger)

	return agent.SaveConfig(c)
}

// fillExportConfig backfills any zero-value export fields from the agent config.
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

func getConfig(bsID, bsKey, bsSvrURL string, skipTLS bool, logger *slog.Logger) (bootstrapResponse, error) {
	rootCAs, err := x509.SystemCertPool()
	if err != nil {
		logger.Error(err.Error())
	}
	if rootCAs == nil {
		rootCAs = x509.NewCertPool()
	}

	tlsCfg := &tls.Config{
		InsecureSkipVerify: skipTLS,
		RootCAs:            rootCAs,
	}
	tr := &http.Transport{TLSClientConfig: tlsCfg}
	client := &http.Client{Transport: tr}
	url := fmt.Sprintf("%s/%s", bsSvrURL, bsID)

	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return bootstrapResponse{}, err
	}

	authScheme := "Client"
	if strings.Contains(bsSvrURL, "/things/bootstrap") {
		authScheme = "Thing"
	}
	req.Header.Add("Authorization", fmt.Sprintf("%s %s", authScheme, bsKey))

	resp, err := client.Do(req)
	if err != nil {
		return bootstrapResponse{}, err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= http.StatusBadRequest {
		return bootstrapResponse{}, errors.New(http.StatusText(resp.StatusCode))
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return bootstrapResponse{}, err
	}

	var br bootstrapResponse
	if err := json.Unmarshal(body, &br); err != nil {
		return bootstrapResponse{}, err
	}

	return br, nil
}

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
	"strconv"
	"strings"
	"time"

	"github.com/absmach/agent"
	"github.com/absmach/magistrala/pkg/errors"
)

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

// renderedContent holds the device configuration rendered by the bootstrap
// service from the profile template and binding snapshots.
type renderedContent struct {
	DeviceID   string `json:"device_id"`
	ExternalID string `json:"external_id"`
	DomainID   string `json:"domain_id"`
	MQTT       struct {
		URL      string `json:"url"`
		ClientID string `json:"client_id"`
		Secret   string `json:"secret"`
		Username string `json:"username"`
		Password string `json:"password"`
	} `json:"mqtt"`
	Telemetry struct {
		ChannelID string `json:"channel_id"`
		Topic     string `json:"topic"`
	} `json:"telemetry"`
	Commands struct {
		ChannelID string `json:"channel_id"`
	} `json:"commands"`
	Channels struct {
		CtrlID string `json:"ctrl_id"`
		DataID string `json:"data_id"`
	} `json:"channels"`
	Provision struct {
		ClientsURL     string `json:"clients_url"`
		ChannelsURL    string `json:"channels_url"`
		RulesEngineURL string `json:"rules_engine_url"`
		Token          string `json:"token"`
	} `json:"provision"`
}

// bootstrapResponse holds the fields returned by the bootstrap endpoint.
type bootstrapResponse struct {
	Content    string `json:"content"`
	ClientKey  string `json:"client_key"`
	ClientCert string `json:"client_cert"`
	CaCert     string `json:"ca_cert"`
}

// FetchAgentConfig retrieves device configuration from the bootstrap service and
// overlays the returned credentials and channel IDs onto agentCfg.
func FetchAgentConfig(cfg Config, agentCfg agent.Config, logger *slog.Logger) (agent.Config, error) {
	retries, err := strconv.ParseUint(cfg.Retries, 10, 64)
	if err != nil {
		return agentCfg, errors.New(fmt.Sprintf("Invalid BOOTSTRAP_RETRIES value: %s", err))
	}
	if retries == 0 {
		retries = 1
	}

	retryDelaySec, err := strconv.ParseUint(cfg.RetryDelaySec, 10, 64)
	if err != nil {
		return agentCfg, errors.New(fmt.Sprintf("Invalid BOOTSTRAP_RETRY_DELAY_SECONDS value: %s", err))
	}

	logger.Info("Requesting config", slog.String("config_id", cfg.ID), slog.String("config_url", cfg.URL))

	var br bootstrapResponse
	var fetchErr error

	for i := 0; i < int(retries); i++ {
		br, fetchErr = getConfig(cfg.ID, cfg.Key, cfg.URL, cfg.SkipTLS, logger)
		if fetchErr == nil {
			break
		}
		logger.Error("Fetching bootstrap failed", slog.Any("error", fetchErr))

		if i < int(retries)-1 {
			logger.Debug("Retrying...", slog.Int("attempt", i+1), slog.Uint64("retries", retries), slog.Uint64("delay_sec", retryDelaySec))
			time.Sleep(time.Duration(retryDelaySec) * time.Second)
		}
	}
	if fetchErr != nil {
		return agentCfg, fmt.Errorf("bootstrap retries exhausted: %w", fetchErr)
	}

	return applyBootstrapResponse(agentCfg, br)
}

func applyBootstrapResponse(agentCfg agent.Config, br bootstrapResponse) (agent.Config, error) {
	var rc renderedContent
	if err := json.Unmarshal([]byte(br.Content), &rc); err != nil {
		return agentCfg, fmt.Errorf("failed to parse bootstrap content: %w", err)
	}

	telemetryChannel := rc.Telemetry.ChannelID
	if telemetryChannel == "" {
		telemetryChannel = rc.Channels.DataID
	}
	if telemetryChannel == "" {
		return agentCfg, agent.ErrMalformedEntity
	}

	commandChannel := rc.Commands.ChannelID
	if commandChannel == "" {
		commandChannel = rc.Channels.CtrlID
	}
	if commandChannel == "" {
		return agentCfg, agent.ErrMalformedEntity
	}

	// Overlay device identity from bootstrap onto the env-based config.
	// Infrastructure settings (broker URL, TLS, timeouts) are preserved from env.
	if rc.DomainID != "" {
		agentCfg.DomainID = rc.DomainID
	}
	username := rc.MQTT.ClientID
	if username == "" {
		username = rc.MQTT.Username
	}
	if username != "" {
		agentCfg.MQTT.Username = username
	}
	password := rc.MQTT.Secret
	if password == "" {
		password = rc.MQTT.Password
	}
	if password != "" {
		agentCfg.MQTT.Password = password
	}
	if rc.MQTT.URL != "" {
		agentCfg.MQTT.URL = rc.MQTT.URL
	}
	agentCfg.Channels.CtrlID = commandChannel
	agentCfg.Channels.DataID = telemetryChannel
	agentCfg.MQTT.ClientCert = br.ClientCert
	agentCfg.MQTT.ClientKey = br.ClientKey
	agentCfg.MQTT.CaCert = br.CaCert
	if rc.Provision.ClientsURL != "" {
		agentCfg.Provision.ClientsURL = rc.Provision.ClientsURL
	}
	if rc.Provision.ChannelsURL != "" {
		agentCfg.Provision.ChannelsURL = rc.Provision.ChannelsURL
	}
	if rc.Provision.RulesEngineURL != "" {
		agentCfg.Provision.RulesEngineURL = rc.Provision.RulesEngineURL
	}
	if rc.Provision.Token != "" {
		agentCfg.Provision.Token = rc.Provision.Token
	}

	return agentCfg, nil
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
	url := bootstrapConfigURL(bsSvrURL, bsID)

	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return bootstrapResponse{}, err
	}

	req.Header.Add("Authorization", "Client "+bsKey)

	resp, err := client.Do(req)
	if err != nil {
		return bootstrapResponse{}, err
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			logger.Error(err.Error())
		}
	}()

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

func bootstrapConfigURL(bsSvrURL, bsID string) string {
	return fmt.Sprintf("%s/%s", strings.TrimRight(bsSvrURL, "/"), strings.TrimLeft(bsID, "/"))
}

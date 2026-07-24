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
	"path/filepath"
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
	CachePath     string
}

// renderedContent holds the device configuration rendered by the bootstrap
// service from the profile template and binding snapshots.
type renderedContent struct {
	DeviceID   string `json:"device_id"`
	ExternalID string `json:"external_id"`
	TenantID   string `json:"tenant_id"`
	MQTT       struct {
		URL       string `json:"url"`
		GatewayID string `json:"gateway_id"`
		Secret    string `json:"secret"`
		Username  string `json:"username"`
		Password  string `json:"password"`
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
		AtomURL        string `json:"atom_url"`
		RulesEngineURL string `json:"rules_engine_url"`
		Token          string `json:"token"`
	} `json:"provision"`
}

// bootstrapResponse holds the fields returned by the bootstrap endpoint.
type bootstrapResponse struct {
	Content     string `json:"content"`
	GatewayKey  string `json:"gateway_key"`
	GatewayCert string `json:"gateway_cert"`
	CaCert      string `json:"ca_cert"`
}

// FetchAgentConfig retrieves device configuration from the bootstrap service and
// overlays the returned credentials and channel IDs onto agentCfg.
// When cfg.CachePath is set and forceFetch is false, it first attempts to load
// a previously cached response from disk. On cache miss it fetches from the
// bootstrap service and writes the response to cfg.CachePath.
func FetchAgentConfig(cfg Config, agentCfg agent.Config, logger *slog.Logger, forceFetch bool) (agent.Config, error) {
	if !forceFetch && cfg.CachePath != "" {
		br, err := loadFromCache(cfg.CachePath)
		if err == nil {
			logger.Info("Loaded bootstrap config from cache", slog.String("path", cfg.CachePath))
			return applyBootstrapResponse(agentCfg, br)
		}
		logger.Info("Bootstrap cache miss, fetching from service", slog.String("path", cfg.CachePath), slog.Any("error", err))
	}

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

	if cfg.CachePath != "" {
		if cacheErr := storeToCache(cfg.CachePath, br); cacheErr != nil {
			logger.Warn("Failed to cache bootstrap response", slog.Any("error", cacheErr))
		} else {
			logger.Info("Cached bootstrap response", slog.String("path", cfg.CachePath))
		}
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
	if rc.TenantID != "" {
		agentCfg.TenantID = rc.TenantID
	}
	username := rc.MQTT.GatewayID
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
	agentCfg.MQTT.GatewayCert = br.GatewayCert
	agentCfg.MQTT.GatewayKey = br.GatewayKey
	agentCfg.MQTT.CaCert = br.CaCert
	if rc.Provision.AtomURL != "" {
		agentCfg.Provision.AtomURL = rc.Provision.AtomURL
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

func loadFromCache(path string) (bootstrapResponse, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return bootstrapResponse{}, err
	}
	var br bootstrapResponse
	if err := json.Unmarshal(data, &br); err != nil {
		return bootstrapResponse{}, err
	}
	if br.Content == "" {
		return bootstrapResponse{}, errors.New("cached bootstrap response has empty content")
	}
	if br.GatewayKey == "" || br.GatewayCert == "" {
		return bootstrapResponse{}, errors.New("cached bootstrap response has empty credentials")
	}
	return br, nil
}

func storeToCache(path string, br bootstrapResponse) error {
	data, err := json.MarshalIndent(br, "", "  ")
	if err != nil {
		return err
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}

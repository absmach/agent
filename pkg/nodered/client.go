// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

package nodered

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
)

// Client interface for Node-RED operations.
type Client interface {
	// DeployFlows replaces all flows in Node-RED.
	DeployFlows(flows string) (string, error)

	// AddFlow adds a single flow tab to Node-RED.
	AddFlow(flow string) (string, error)

	// FetchFlows retrieves current flows from Node-RED.
	FetchFlows() (string, error)

	// FlowState returns the current runtime state of Node-RED flows.
	FlowState() (string, error)

	// Ping checks Node-RED availability.
	Ping() (string, error)
}

type noderedClient struct {
	url    string
	logger *slog.Logger
}

// NewClient creates a new Node-RED client.
func NewClient(noderedURL string, logger *slog.Logger) Client {
	return &noderedClient{
		url:    noderedURL,
		logger: logger,
	}
}

// DeployFlows deploys flows to the Node-RED instance.
func (nc *noderedClient) DeployFlows(flows string) (string, error) {
	url := nc.url + "flows"

	// Validate that flows is valid JSON before sending.
	if !json.Valid([]byte(flows)) {
		return "", fmt.Errorf("invalid JSON flows payload")
	}

	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader([]byte(flows)))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Node-RED-Deployment-Type", "full")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		return "", fmt.Errorf("node-red deploy failed with status %d: %s", resp.StatusCode, string(body))
	}

	return string(body), nil
}

// AddFlow adds a single new flow tab to Node-RED.
func (nc *noderedClient) AddFlow(flow string) (string, error) {
	url := nc.url + "flow"

	if !json.Valid([]byte(flow)) {
		return "", fmt.Errorf("invalid JSON flow payload")
	}

	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader([]byte(flow)))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		return "", fmt.Errorf("node-red add flow failed with status %d: %s", resp.StatusCode, string(body))
	}

	return string(body), nil
}

// FlowState returns the runtime state of Node-RED flows.
func (nc *noderedClient) FlowState() (string, error) {
	url := nc.url + "flows/state"

	resp, err := http.Get(url)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	return string(body), nil
}

// FetchFlows retrieves the current flows from Node-RED.
func (nc *noderedClient) FetchFlows() (string, error) {
	url := nc.url + "flows"

	resp, err := http.Get(url)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	return string(body), nil
}

// Ping checks if Node-RED is available.
func (nc *noderedClient) Ping() (string, error) {
	url := nc.url + "settings"

	resp, err := http.Get(url)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	return string(body), nil
}

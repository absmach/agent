// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

package nodered

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"

	mgerrors "github.com/absmach/magistrala/pkg/errors"
)

var ErrFlowConflict = mgerrors.New("node-red flow conflict")

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
// It accepts either the POST /flow object format or a flat array (POST /flows format),
// automatically converting the array into the {id, label, nodes, configs} object
// that the POST /flow endpoint requires. Imported node ids are rekeyed so example
// flows with fixed ids can be added alongside existing flows.
func (nc *noderedClient) AddFlow(flow string) (string, error) {
	if !json.Valid([]byte(flow)) {
		return "", fmt.Errorf("invalid JSON flow payload")
	}

	payload, err := normalizeAddFlowPayload(flow)
	if err != nil {
		return "", fmt.Errorf("failed to normalize flow payload: %w", err)
	}

	req, err := http.NewRequest(http.MethodPost, nc.url+"flow", bytes.NewReader(payload))
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

	if resp.StatusCode == http.StatusBadRequest && strings.Contains(string(body), "duplicate id") {
		return "", mgerrors.Wrap(ErrFlowConflict, fmt.Errorf("node-red rejected the flow due to duplicate ids even after rekeying: %s", string(body)))
	}

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		return "", fmt.Errorf("node-red add flow failed with status %d: %s", resp.StatusCode, string(body))
	}

	return string(body), nil
}

func normalizeAddFlowPayload(flow string) ([]byte, error) {
	var payload any
	if err := json.Unmarshal([]byte(flow), &payload); err != nil {
		return nil, err
	}

	rekeyNodeRedIDs(payload)

	trimmed := strings.TrimSpace(flow)
	if !strings.HasPrefix(trimmed, "[") {
		return json.Marshal(payload)
	}

	nodes, ok := payload.([]any)
	if !ok {
		return nil, fmt.Errorf("expected flow array payload")
	}

	var tab map[string]any
	parsedNodes := make([]map[string]any, 0, len(nodes))
	for _, raw := range nodes {
		n, ok := raw.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("invalid flow node payload")
		}
		parsedNodes = append(parsedNodes, n)
		if n["type"] == "tab" {
			tab = n
		}
	}
	if tab == nil {
		return nil, fmt.Errorf("no tab node found in flow array")
	}

	tabID, _ := tab["id"].(string)
	label, _ := tab["label"].(string)

	// Split remaining nodes into flow nodes (z == tabID) and config nodes (no z or z == "").
	flowNodes := []map[string]any{}
	configNodes := []map[string]any{}
	for _, n := range parsedNodes {
		if n["type"] == "tab" {
			continue
		}
		z, _ := n["z"].(string)
		if z == tabID {
			flowNodes = append(flowNodes, n)
		} else {
			configNodes = append(configNodes, n)
		}
	}

	normalizedPayload := map[string]any{
		"id":      tabID,
		"label":   label,
		"nodes":   flowNodes,
		"configs": configNodes,
	}

	return json.Marshal(normalizedPayload)
}

func rekeyNodeRedIDs(payload any) {
	ids := map[string]string{}
	collectNodeRedIDs(payload, ids)
	if len(ids) == 0 {
		return
	}
	rewriteNodeRedIDs(payload, ids)
}

func collectNodeRedIDs(value any, ids map[string]string) {
	switch v := value.(type) {
	case map[string]any:
		if id, ok := v["id"].(string); ok && id != "" {
			if _, exists := ids[id]; !exists {
				ids[id] = newNodeRedID()
			}
		}
		for _, child := range v {
			collectNodeRedIDs(child, ids)
		}
	case []any:
		for _, child := range v {
			collectNodeRedIDs(child, ids)
		}
	}
}

func rewriteNodeRedIDs(value any, ids map[string]string) {
	switch v := value.(type) {
	case map[string]any:
		for key, child := range v {
			switch typed := child.(type) {
			case string:
				if replacement, ok := ids[typed]; ok {
					v[key] = replacement
				}
			default:
				rewriteNodeRedIDs(typed, ids)
			}
		}
	case []any:
		for i, child := range v {
			switch typed := child.(type) {
			case string:
				if replacement, ok := ids[typed]; ok {
					v[i] = replacement
				}
			default:
				rewriteNodeRedIDs(typed, ids)
			}
		}
	}
}

func newNodeRedID() string {
	buf := make([]byte, 8)
	if _, err := rand.Read(buf); err != nil {
		panic(fmt.Sprintf("failed to generate node-red id: %v", err))
	}
	return "nr-" + hex.EncodeToString(buf)
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

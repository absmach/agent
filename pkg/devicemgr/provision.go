// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

package devicemgr

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

const maxResponseBytes = 1 << 20 // 1 MiB

// ProvisionConfig holds the Magistrala Provision service endpoint and credentials.
type ProvisionConfig struct {
	URL      string `json:"url"`
	Token    string `json:"token"`
	DomainID string `json:"domain_id"`
}

type provisionClient struct {
	cfg    ProvisionConfig
	client *http.Client
}

func newProvisionClient(cfg ProvisionConfig) *provisionClient {
	return &provisionClient{
		cfg:    cfg,
		client: &http.Client{Timeout: 20 * time.Second},
	}
}

type provisionRequest struct {
	Name        string `json:"name"`
	ExternalID  string `json:"external_id"`
	ExternalKey string `json:"external_key"`
}

type provisionResponse struct {
	Clients []struct {
		ID     string `json:"id"`
		Secret string `json:"secret"`
		Name   string `json:"name"`
	} `json:"clients"`
	Channels []struct {
		ID string `json:"id"`
	} `json:"channels"`
}

// Provision calls the Magistrala Provision API and returns the created Device
// (with ID, Key, ChannelID populated). The caller fills in interface fields.
func (p *provisionClient) Provision(ctx context.Context, name, externalID, externalKey string) (Device, error) {
	if p.cfg.URL == "" {
		return Device{}, fmt.Errorf("provision URL not configured")
	}
	if p.cfg.Token == "" {
		return Device{}, fmt.Errorf("provision token not configured")
	}

	baseURL := strings.TrimSuffix(p.cfg.URL, "/")
	domainID := p.cfg.DomainID
	var endpoint string
	if domainID != "" {
		endpoint = fmt.Sprintf("%s/%s/mapping", baseURL, domainID)
	} else {
		endpoint = fmt.Sprintf("%s/mapping", baseURL)
	}

	body, err := json.Marshal(provisionRequest{
		Name:        name,
		ExternalID:  externalID,
		ExternalKey: externalKey,
	})
	if err != nil {
		return Device{}, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return Device{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+p.cfg.Token)

	resp, err := p.client.Do(req)
	if err != nil {
		return Device{}, fmt.Errorf("provision request: %w", err)
	}
	defer resp.Body.Close()
	limited := io.LimitReader(resp.Body, maxResponseBytes)

	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(io.LimitReader(limited, 512))
		return Device{}, fmt.Errorf("provision API returned %d: %s", resp.StatusCode, b)
	}

	var pr provisionResponse
	if err := json.NewDecoder(limited).Decode(&pr); err != nil {
		return Device{}, fmt.Errorf("decode provision response: %w", err)
	}
	if len(pr.Clients) != 1 {
		return Device{}, fmt.Errorf("provision response: expected 1 client, got %d", len(pr.Clients))
	}

	d := Device{
		ID:   pr.Clients[0].ID,
		Key:  pr.Clients[0].Secret,
		Name: pr.Clients[0].Name,
	}
	if d.Name == "" {
		d.Name = name
	}
	if len(pr.Channels) > 0 {
		d.ChannelID = pr.Channels[0].ID
	}
	return d, nil
}

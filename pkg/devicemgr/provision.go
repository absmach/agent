// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

package devicemgr

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/absmach/agent/pkg/atomsdk"
)

type ProvisionConfig struct {
	AtomURL        string
	RulesEngineURL string
	Token          string
	TenantID       string
}

type provisionClient struct {
	cfg        ProvisionConfig
	sdk        atomsdk.SDK
	httpClient *http.Client
}

func newProvisionClient(cfg ProvisionConfig) *provisionClient {
	return &provisionClient{
		cfg: cfg,
		sdk: atomsdk.New(atomsdk.Config{
			AtomURL: cfg.AtomURL,
			Token:   cfg.Token,
		}),
		httpClient: &http.Client{},
	}
}

func (p *provisionClient) Provision(ctx context.Context, name, externalID, externalKey string) (Device, error) {
	if p.cfg.AtomURL == "" {
		return Device{}, fmt.Errorf("provision atom URL not configured")
	}
	if p.cfg.Token == "" {
		return Device{}, fmt.Errorf("provision token (PAT) not configured")
	}

	// Step 1: Create the device entity.
	entity, err := p.sdk.CreateEntity(ctx, name, p.cfg.TenantID)
	if err != nil {
		return Device{}, fmt.Errorf("create device %q: %s", name, err)
	}

	// Step 2: Create API key for the device (used as MQTT password).
	key, err := p.sdk.CreateAPIKey(ctx, entity.ID, fmt.Sprintf("%s-key", name))
	if err != nil {
		cleanupCtx := context.WithoutCancel(ctx)
		_ = p.sdk.DeleteEntity(cleanupCtx, entity.ID)
		return Device{}, fmt.Errorf("create api key for %q: %s", name, err)
	}

	// Step 3: Create the telemetry resource (channel).
	resource, err := p.sdk.CreateResource(ctx, fmt.Sprintf("%s-telemetry", name), p.cfg.TenantID, entity.ID)
	if err != nil {
		cleanupCtx := context.WithoutCancel(ctx)
		var rollbackErrs []string
		if delErr := p.sdk.DeleteEntity(cleanupCtx, entity.ID); delErr != nil {
			rollbackErrs = append(rollbackErrs, fmt.Sprintf("delete entity %s: %s", entity.ID, delErr))
		}
		return Device{}, fmt.Errorf("create resource for %q: %s; rollback: %s", name, err, strings.Join(rollbackErrs, "; "))
	}

	// Step 4: Connect device → resource (grant publish/subscribe).
	if err := p.sdk.Connect(ctx, entity.ID, resource.ID, p.cfg.TenantID); err != nil {
		cleanupCtx := context.WithoutCancel(ctx)
		var rollbackErrs []string
		if delErr := p.sdk.DeleteEntity(cleanupCtx, entity.ID); delErr != nil {
			rollbackErrs = append(rollbackErrs, fmt.Sprintf("delete entity %s: %s", entity.ID, delErr))
		}
		if delErr := p.sdk.DeleteResource(cleanupCtx, resource.ID); delErr != nil {
			rollbackErrs = append(rollbackErrs, fmt.Sprintf("delete resource %s: %s", resource.ID, delErr))
		}
		return Device{}, fmt.Errorf("connect device %s to resource %s: %s; rollback: %s", entity.ID, resource.ID, err, strings.Join(rollbackErrs, "; "))
	}

	// Step 5: Create a save_senml Rule Engine rule so telemetry is persisted.
	// This is a direct REST call to the rules engine (not part of Atom GraphQL).
	if p.cfg.RulesEngineURL != "" {
		if err := p.addRule(ctx, name, resource.ID); err != nil {
			cleanupCtx := context.WithoutCancel(ctx)
			var rollbackErrs []string
			if delErr := p.sdk.DeleteEntity(cleanupCtx, entity.ID); delErr != nil {
				rollbackErrs = append(rollbackErrs, fmt.Sprintf("delete entity %s: %s", entity.ID, delErr))
			}
			if delErr := p.sdk.DeleteResource(cleanupCtx, resource.ID); delErr != nil {
				rollbackErrs = append(rollbackErrs, fmt.Sprintf("delete resource %s: %s", resource.ID, delErr))
			}
			return Device{}, fmt.Errorf("create rule for %q: %s; rollback: %s", name, err, strings.Join(rollbackErrs, "; "))
		}
	}

	return Device{
		ID:        entity.ID,
		Key:       key,
		Name:      name,
		ChannelID: resource.ID,
	}, nil
}

func (p *provisionClient) addRule(ctx context.Context, name, inputChannel string) error {
	rule := map[string]any{
		"name":          fmt.Sprintf("device-%s-storage", name),
		"input_channel": inputChannel,
		"input_topic":   "msg",
		"logic":         map[string]any{"type": 0, "value": "return message.payload"},
		"outputs":       []map[string]string{{"type": "save_senml"}},
		"status":        "enabled",
	}
	data, err := json.Marshal(rule)
	if err != nil {
		return fmt.Errorf("marshal rule: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.cfg.RulesEngineURL, bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("create rule request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if p.cfg.Token != "" {
		req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", p.cfg.Token))
	}
	resp, err := p.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("create rule: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		return fmt.Errorf("create rule: unexpected status %d", resp.StatusCode)
	}
	return nil
}

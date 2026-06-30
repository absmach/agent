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

// provisionArtifacts tracks the Atom records created during provisioning so a
// failed step can be rolled back in reverse dependency order.
type provisionArtifacts struct {
	entityID     string
	credentialID string
	resourceID   string
	grant        atomsdk.Grant
}

func (p *provisionClient) Provision(ctx context.Context, name, externalID, externalKey string) (Device, error) {
	if p.cfg.AtomURL == "" {
		return Device{}, fmt.Errorf("provision atom URL not configured")
	}
	if p.cfg.Token == "" {
		return Device{}, fmt.Errorf("provision token (PAT) not configured")
	}

	var art provisionArtifacts

	// Step 1: Create the device entity.
	entity, err := p.sdk.CreateEntity(ctx, name, p.cfg.TenantID)
	if err != nil {
		return Device{}, fmt.Errorf("create device %q: %s", name, err)
	}
	art.entityID = entity.ID

	// Step 2: Create API key for the device (used as MQTT password).
	apiKey, err := p.sdk.CreateAPIKey(ctx, entity.ID, fmt.Sprintf("%s-key", name))
	if err != nil {
		return Device{}, p.fail(ctx, fmt.Sprintf("create api key for %q", name), err, art)
	}
	art.credentialID = apiKey.CredentialID

	// Step 3: Create the telemetry resource (channel).
	resource, err := p.sdk.CreateResource(ctx, fmt.Sprintf("%s-telemetry", name), p.cfg.TenantID, entity.ID)
	if err != nil {
		return Device{}, p.fail(ctx, fmt.Sprintf("create resource for %q", name), err, art)
	}
	art.resourceID = resource.ID

	// Step 4: Connect device → resource (grant publish/subscribe).
	grant, err := p.sdk.Connect(ctx, entity.ID, resource.ID, p.cfg.TenantID)
	if err != nil {
		return Device{}, p.fail(ctx, fmt.Sprintf("connect device %s to resource %s", entity.ID, resource.ID), err, art)
	}
	art.grant = grant

	// Step 5: Create a save_senml Rule Engine rule so telemetry is persisted.
	// This is a direct REST call to the rules engine (not part of Atom GraphQL).
	if p.cfg.RulesEngineURL != "" {
		if err := p.addRule(ctx, name, resource.ID); err != nil {
			return Device{}, p.fail(ctx, fmt.Sprintf("create rule for %q", name), err, art)
		}
	}

	return Device{
		ID:        entity.ID,
		Key:       apiKey.Key,
		Name:      name,
		ChannelID: resource.ID,
	}, nil
}

// fail rolls back everything provisioned so far and returns an error that
// describes the failed step together with any rollback failures.
func (p *provisionClient) fail(ctx context.Context, step string, cause error, art provisionArtifacts) error {
	if rollbackErrs := p.rollback(ctx, art); len(rollbackErrs) > 0 {
		return fmt.Errorf("%s: %s; rollback: %s", step, cause, strings.Join(rollbackErrs, "; "))
	}
	return fmt.Errorf("%s: %s", step, cause)
}

// rollback removes the Atom records in art in reverse dependency order. Atom
// soft-deletes entities and resources, which does not cascade to credentials
// or authorization records, so the API key, permission block, and direct
// policy must each be removed explicitly. Cleanup is best-effort; any failures
// are returned so they can be surfaced in the provisioning error.
func (p *provisionClient) rollback(ctx context.Context, art provisionArtifacts) []string {
	ctx = context.WithoutCancel(ctx)
	var errs []string
	if art.grant.DirectPolicyID != "" {
		if err := p.sdk.DeleteDirectPolicy(ctx, art.grant.DirectPolicyID); err != nil {
			errs = append(errs, fmt.Sprintf("delete direct policy %s: %s", art.grant.DirectPolicyID, err))
		}
	}
	if art.grant.PermissionBlockID != "" {
		if err := p.sdk.DeletePermissionBlock(ctx, art.grant.PermissionBlockID); err != nil {
			errs = append(errs, fmt.Sprintf("delete permission block %s: %s", art.grant.PermissionBlockID, err))
		}
	}
	if art.credentialID != "" {
		if err := p.sdk.RevokeCredential(ctx, art.entityID, art.credentialID); err != nil {
			errs = append(errs, fmt.Sprintf("revoke credential %s: %s", art.credentialID, err))
		}
	}
	if art.resourceID != "" {
		if err := p.sdk.DeleteResource(ctx, art.resourceID); err != nil {
			errs = append(errs, fmt.Sprintf("delete resource %s: %s", art.resourceID, err))
		}
	}
	if art.entityID != "" {
		if err := p.sdk.DeleteEntity(ctx, art.entityID); err != nil {
			errs = append(errs, fmt.Sprintf("delete entity %s: %s", art.entityID, err))
		}
	}
	return errs
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

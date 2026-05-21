// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

package devicemgr

import (
	"context"
	"fmt"

	mgSDK "github.com/absmach/magistrala/pkg/sdk"
)

// ProvisionConfig holds the Magistrala service URLs and credentials
// needed to provision a downstream device via the SDK.
type ProvisionConfig struct {
	ClientsURL     string `json:"clients_url"`
	ChannelsURL    string `json:"channels_url"`
	RulesEngineURL string `json:"rules_engine_url"`
	Token          string `json:"token"`
	DomainID       string `json:"domain_id"`
}

type provisionClient struct {
	cfg ProvisionConfig
	sdk mgSDK.SDK
}

func newProvisionClient(cfg ProvisionConfig) *provisionClient {
	return &provisionClient{
		cfg: cfg,
		sdk: mgSDK.NewSDK(mgSDK.Config{
			ClientsURL:     cfg.ClientsURL,
			ChannelsURL:    cfg.ChannelsURL,
			RulesEngineURL: cfg.RulesEngineURL,
		}),
	}
}

// Provision creates a Magistrala Client and Channel, connects them,
// creates a save_senml Rule Engine rule, and returns the populated Device.
// The four steps mirror what provision.sh does in Steps 2–5.
func (p *provisionClient) Provision(ctx context.Context, name, externalID, externalKey string) (Device, error) {
	if p.cfg.ClientsURL == "" {
		return Device{}, fmt.Errorf("provision clients URL not configured")
	}
	if p.cfg.Token == "" {
		return Device{}, fmt.Errorf("provision token (PAT) not configured")
	}

	// Step 1: Create the device Client.
	client, sdkErr := p.sdk.CreateClient(ctx, mgSDK.Client{
		Name: name,
		Credentials: mgSDK.ClientCredentials{
			Identity: externalID,
			Secret:   externalKey,
		},
	}, p.cfg.DomainID, p.cfg.Token)
	if sdkErr != nil {
		return Device{}, fmt.Errorf("create client %q: %s", name, sdkErr)
	}

	// Step 2: Create the telemetry Channel.
	channel, sdkErr := p.sdk.CreateChannel(ctx, mgSDK.Channel{
		Name: fmt.Sprintf("%s-telemetry", name),
	}, p.cfg.DomainID, p.cfg.Token)
	if sdkErr != nil {
		_ = p.sdk.DeleteClient(ctx, client.ID, p.cfg.DomainID, p.cfg.Token)
		return Device{}, fmt.Errorf("create channel for %q: %s", name, sdkErr)
	}

	// Step 3: Connect client → channel (publish + subscribe).
	sdkErr = p.sdk.Connect(ctx, mgSDK.Connection{
		ClientIDs:  []string{client.ID},
		ChannelIDs: []string{channel.ID},
		Types:      []string{"publish", "subscribe"},
	}, p.cfg.DomainID, p.cfg.Token)
	if sdkErr != nil {
		_ = p.sdk.DeleteClient(ctx, client.ID, p.cfg.DomainID, p.cfg.Token)
		_ = p.sdk.DeleteChannel(ctx, channel.ID, p.cfg.DomainID, p.cfg.Token)
		return Device{}, fmt.Errorf("connect client %s to channel %s: %s", client.ID, channel.ID, sdkErr)
	}

	// Step 4: Create a save_senml Rule Engine rule so telemetry is persisted.
	// Skipped if RulesEngineURL is not configured.
	if p.cfg.RulesEngineURL != "" {
		_, sdkErr = p.sdk.AddRule(ctx, mgSDK.Rule{
			Name:         fmt.Sprintf("device-%s-storage", name),
			DomainID:     p.cfg.DomainID,
			InputChannel: channel.ID,
			InputTopic:   "msg",
			Logic:        map[string]any{"type": 0, "value": "return message.payload"},
			Outputs:      []map[string]string{{"type": "save_senml"}},
			Status:       "enabled",
		}, p.cfg.DomainID, p.cfg.Token)
		if sdkErr != nil {
			_ = p.sdk.DeleteClient(ctx, client.ID, p.cfg.DomainID, p.cfg.Token)
			_ = p.sdk.DeleteChannel(ctx, channel.ID, p.cfg.DomainID, p.cfg.Token)
			return Device{}, fmt.Errorf("create rule for %q: %s", name, sdkErr)
		}
	}

	secret := client.Credentials.Secret
	if secret == "" {
		secret = externalKey
	}
	return Device{
		ID:        client.ID,
		Key:       secret,
		Name:      name,
		ChannelID: channel.ID,
	}, nil
}

// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"encoding/base64"
	"io"
	"log/slog"

	"github.com/absmach/agent/pkg/terminal"
)

const NodeRedTLSConfigIDForTest = nodeRedTLSConfigID

func ApplyConfigEntryForTest(cfg *Config, key, val string) {
	ApplyConfigEntry(cfg, key, val)
}

func NormalizeNodeRedFlowForTest(cfg Config, flow string) string {
	ag := &agent{config: &cfg}
	return ag.normalizeNodeRedFlow(flow)
}

func NodeRedMQTTEndpointForTest(rawURL string) (string, string, bool) {
	return nodeRedMQTTEndpoint(rawURL)
}

func PatchNodeRedTopicForTest(value, domainID, channelID string) string {
	return patchNodeRedTopic(value, domainID, channelID)
}

func EnsureNodeRedTLSConfigForTest(payload any) any {
	return ensureNodeRedTLSConfig(payload)
}

func TerminalCloseExistingSessionForTest(uuid string) (int, error) {
	ag := &agent{
		logger:    slog.New(slog.NewTextHandler(io.Discard, nil)),
		terminals: map[string]terminal.Session{uuid: nil},
		config:    &Config{},
	}

	cmd := base64.StdEncoding.EncodeToString([]byte(close))
	err := ag.Terminal(uuid, cmd)
	return len(ag.terminals), err
}

func GetTopicForTest(cfg Config, topic string) string {
	ag := &agent{config: &cfg}
	return ag.getTopic(topic)
}

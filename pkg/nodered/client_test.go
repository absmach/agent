// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

package nodered

import (
	"encoding/json"
	"testing"
)

func TestNormalizeAddFlowPayloadRekeysIDs(t *testing.T) {
	input := `[
		{"id":"flow-speed-sensor","type":"tab","label":"Speed Sensor Flow"},
		{"id":"mqtt-broker-config","type":"mqtt-broker","name":"Magistrala Cloud MQTT","tls":"magistrala-agent-tls","z":""},
		{"id":"inject-speed","type":"inject","z":"flow-speed-sensor","wires":[["build-speed-senml"]]},
		{"id":"build-speed-senml","type":"function","z":"flow-speed-sensor","broker":"mqtt-broker-config","wires":[["mqtt-pub-speed"]]},
		{"id":"mqtt-pub-speed","type":"mqtt out","z":"flow-speed-sensor","broker":"mqtt-broker-config"},
		{"id":"magistrala-agent-tls","type":"tls-config","z":""}
	]`

	payload, err := normalizeAddFlowPayload(input)
	if err != nil {
		t.Fatalf("normalizeAddFlowPayload returned error: %v", err)
	}

	var got map[string]any
	if err := json.Unmarshal(payload, &got); err != nil {
		t.Fatalf("failed to unmarshal normalized payload: %v", err)
	}

	tabID, _ := got["id"].(string)
	if tabID == "" || tabID == "flow-speed-sensor" {
		t.Fatalf("expected rekeyed tab id, got %q", tabID)
	}

	nodes, _ := got["nodes"].([]any)
	configs, _ := got["configs"].([]any)
	if len(nodes) == 0 || len(configs) == 0 {
		t.Fatalf("expected nodes and configs in normalized payload")
	}

	foundTLS := false
	foundBroker := false
	for _, raw := range configs {
		cfg := raw.(map[string]any)
		if cfg["id"] == "magistrala-agent-tls" || cfg["id"] == "mqtt-broker-config" {
			t.Fatalf("expected config ids to be rekeyed, got %v", cfg["id"])
		}
		if cfg["type"] == "tls-config" {
			foundTLS = true
		}
		if cfg["type"] == "mqtt-broker" {
			foundBroker = true
		}
	}
	if !foundTLS || !foundBroker {
		t.Fatalf("expected both tls and broker config nodes in configs")
	}

	inject := nodes[0].(map[string]any)
	if inject["z"] != tabID {
		t.Fatalf("expected node z to point to rekeyed tab id, got %v want %v", inject["z"], tabID)
	}
}

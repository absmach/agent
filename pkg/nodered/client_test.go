// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

package nodered

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNormalizeAddFlowPayload(t *testing.T) {
	cases := []struct {
		desc     string
		input    string
		err      string
		validate func(t *testing.T, payload []byte)
	}{
		{
			desc: "normalize flow array and rekey ids successfully",
			input: `[
				{"id":"flow-speed-sensor","type":"tab","label":"Speed Sensor Flow"},
				{"id":"mqtt-broker-config","type":"mqtt-broker","name":"Magistrala Cloud MQTT","tls":"magistrala-agent-tls","z":""},
				{"id":"inject-speed","type":"inject","z":"flow-speed-sensor","wires":[["build-speed-senml"]]},
				{"id":"build-speed-senml","type":"function","z":"flow-speed-sensor","broker":"mqtt-broker-config","wires":[["mqtt-pub-speed"]]},
				{"id":"mqtt-pub-speed","type":"mqtt out","z":"flow-speed-sensor","broker":"mqtt-broker-config"},
				{"id":"magistrala-agent-tls","type":"tls-config","z":""}
			]`,
			validate: assertNormalizedFlowArray,
		},
		{
			desc: "normalize flow object and rekey references successfully",
			input: `{
				"id":"flow-speed-sensor",
				"label":"Speed Sensor Flow",
				"nodes":[
					{"id":"inject-speed","type":"inject","z":"flow-speed-sensor","wires":[["build-speed-senml"]]},
					{"id":"build-speed-senml","type":"function","z":"flow-speed-sensor","broker":"mqtt-broker-config","wires":[["mqtt-pub-speed"]]},
					{"id":"mqtt-pub-speed","type":"mqtt out","z":"flow-speed-sensor","broker":"mqtt-broker-config"}
				],
				"configs":[
					{"id":"mqtt-broker-config","type":"mqtt-broker","name":"Magistrala Cloud MQTT","tls":"magistrala-agent-tls","z":""},
					{"id":"magistrala-agent-tls","type":"tls-config","z":""}
				]
			}`,
			validate: assertNormalizedFlowObject,
		},
		{
			desc: "preserve freetext fields while rekeying ids",
			input: `[
				{"id":"tab-1","type":"tab","label":"my-label"},
				{"id":"some-node-id","type":"inject","z":"tab-1","name":"some-node-id","label":"some-node-id","info":"some-node-id","wires":[[]]}
			]`,
			validate: assertFreetextFieldsPreserved,
		},
		{
			desc:  "normalize invalid json",
			input: `}`,
			err:   "invalid character",
		},
		{
			desc: "normalize flow array without tab",
			input: `[
				{"id":"inject-speed","type":"inject","z":"flow-speed-sensor","wires":[[]]}
			]`,
			err: "no tab node found in flow array",
		},
		{
			desc: "normalize flow array with invalid node payload",
			input: `[
				{"id":"flow-speed-sensor","type":"tab","label":"Speed Sensor Flow"},
				"invalid-node"
			]`,
			err: "invalid flow node payload",
		},
	}

	for _, tc := range cases {
		t.Run(tc.desc, func(t *testing.T) {
			payload, err := normalizeAddFlowPayload(tc.input)
			if tc.err != "" {
				if !assert.Error(t, err, fmt.Sprintf("%s: expected error", tc.desc)) {
					return
				}
				assert.True(t, strings.Contains(err.Error(), tc.err), fmt.Sprintf("%s: expected error %q got %q", tc.desc, tc.err, err))
				return
			}

			assert.NoError(t, err, fmt.Sprintf("%s: unexpected error %s", tc.desc, err))
			assert.NotEmpty(t, payload, fmt.Sprintf("%s: expected payload", tc.desc))
			if tc.validate != nil {
				tc.validate(t, payload)
			}
		})
	}
}

func assertNormalizedFlowArray(t *testing.T, payload []byte) {
	t.Helper()

	got := decodePayload(t, payload)
	tabID, _ := got["id"].(string)
	assert.NotEmpty(t, tabID)
	assert.NotEqual(t, "flow-speed-sensor", tabID)
	assert.Equal(t, "Speed Sensor Flow", got["label"])

	nodes := payloadSlice(t, got, "nodes")
	configs := payloadSlice(t, got, "configs")
	assert.Len(t, nodes, 3)
	assert.Len(t, configs, 2)

	foundTLS := false
	foundBroker := false
	for _, raw := range configs {
		cfg := raw.(map[string]any)
		assert.NotContains(t, []string{"magistrala-agent-tls", "mqtt-broker-config"}, cfg["id"])
		if cfg["type"] == "tls-config" {
			foundTLS = true
		}
		if cfg["type"] == "mqtt-broker" {
			foundBroker = true
		}
	}
	assert.True(t, foundTLS)
	assert.True(t, foundBroker)

	inject := nodes[0].(map[string]any)
	assert.Equal(t, tabID, inject["z"])
	assert.NotEqual(t, "inject-speed", inject["id"])
}

func assertNormalizedFlowObject(t *testing.T, payload []byte) {
	t.Helper()

	got := decodePayload(t, payload)
	tabID, _ := got["id"].(string)
	assert.NotEmpty(t, tabID)
	assert.NotEqual(t, "flow-speed-sensor", tabID)
	assert.Equal(t, "Speed Sensor Flow", got["label"])

	nodes := payloadSlice(t, got, "nodes")
	configs := payloadSlice(t, got, "configs")
	assert.Len(t, nodes, 3)
	assert.Len(t, configs, 2)

	functionNode := nodes[1].(map[string]any)
	assert.Equal(t, tabID, functionNode["z"])
	assert.NotEqual(t, "build-speed-senml", functionNode["id"])
	assert.NotEqual(t, "mqtt-broker-config", functionNode["broker"])

	wires := functionNode["wires"].([]any)
	firstWire := wires[0].([]any)
	assert.NotEqual(t, "mqtt-pub-speed", firstWire[0])
}

func assertFreetextFieldsPreserved(t *testing.T, payload []byte) {
	t.Helper()

	got := decodePayload(t, payload)
	assert.Equal(t, "my-label", got["label"])

	nodes := payloadSlice(t, got, "nodes")
	assert.NotEmpty(t, nodes)

	node := nodes[0].(map[string]any)
	assert.Equal(t, "some-node-id", node["name"])
	assert.Equal(t, "some-node-id", node["label"])
	assert.Equal(t, "some-node-id", node["info"])
	assert.NotEqual(t, "some-node-id", node["id"])
}

func decodePayload(t *testing.T, payload []byte) map[string]any {
	t.Helper()

	var got map[string]any
	err := json.Unmarshal(payload, &got)
	assert.NoError(t, err, fmt.Sprintf("failed to unmarshal normalized payload: %s", err))

	return got
}

func payloadSlice(t *testing.T, payload map[string]any, key string) []any {
	t.Helper()

	values, ok := payload[key].([]any)
	assert.True(t, ok, fmt.Sprintf("expected %s to be a slice", key))

	return values
}

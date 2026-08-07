// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/eclipse/paho.golang/paho"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSubscribeReplaysRetainedAgentState(t *testing.T) {
	agent := Agent{
		ID: "edge", DomainID: "domain", ControlChannel: "control", DataChannel: "data",
	}
	broker := &Broker{
		ctx: context.Background(), agents: map[string]Agent{"edge": agent},
		subs: make(map[chan Event]struct{}), latest: make(map[string]map[string]Event),
		logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	broker.handle(&paho.Publish{
		Topic:   dataTopic(agent, "gateway/state/reported"),
		Payload: []byte(`{"schemaVersion":1}`), Retain: true,
	})

	events, cancel := broker.Subscribe()
	defer cancel()
	select {
	case event := <-events:
		assert.Equal(t, "edge", event.AgentID)
		assert.True(t, event.Retain)
		assert.JSONEq(t, `{"schemaVersion":1}`, string(event.Payload))
	case <-time.After(time.Second):
		require.Fail(t, "retained state was not replayed")
	}
}

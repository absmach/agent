// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

package conn

import (
	"testing"

	"github.com/absmach/agent/pkg/senml"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestExtractHeartbeat(t *testing.T) {
	serviceType := "node-red"
	payload, err := senml.EncodeRecords([]senml.Record{
		{Name: "service_type", StringValue: &serviceType},
	})
	require.NoError(t, err)

	name, gotType, ok := extractHeartbeat(
		"m/domain/c/control/services/flows/heartbeat",
		payload,
	)
	assert.True(t, ok)
	assert.Equal(t, "flows", name)
	assert.Equal(t, serviceType, gotType)

	_, _, ok = extractHeartbeat("m/domain/c/control/req", payload)
	assert.False(t, ok)
}

// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

package remote

import (
	"testing"

	"github.com/eclipse/paho.golang/paho"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestValidateRequestProperties(t *testing.T) {
	server := &MQTTServer{cfg: MQTTConfig{
		DomainID:       "domain",
		ControlChannel: "control",
	}}
	format := byte(1)
	expiry := uint32(30)
	valid := &paho.Publish{Properties: &paho.PublishProperties{
		ResponseTopic:   "m/domain/c/control/res/gateway",
		CorrelationData: make([]byte, 16),
		ContentType:     "application/json",
		PayloadFormat:   &format,
		MessageExpiry:   &expiry,
		User:            paho.UserProperties{{Key: "api-version", Value: APIVersion}},
	}}

	_, _, rpcErr := server.validateRequestProperties(valid)
	require.Nil(t, rpcErr)

	withoutExpiry := *valid
	properties := *valid.Properties
	properties.MessageExpiry = nil
	withoutExpiry.Properties = &properties
	_, _, rpcErr = server.validateRequestProperties(&withoutExpiry)
	require.NotNil(t, rpcErr)
	assert.Equal(t, CodeInvalidRequest, rpcErr.Code)

	outsideChannel := *valid
	properties = *valid.Properties
	properties.ResponseTopic = "m/domain/c/other/res/gateway"
	outsideChannel.Properties = &properties
	_, _, rpcErr = server.validateRequestProperties(&outsideChannel)
	require.NotNil(t, rpcErr)
	assert.Equal(t, CodeInvalidRequest, rpcErr.Code)
}

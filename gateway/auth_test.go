// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"testing"

	"github.com/absmach/agent/pkg/remote"
	"github.com/stretchr/testify/assert"
)

func TestMethodRolesCoverRemoteSurface(t *testing.T) {
	assert.Equal(t, "viewer", methodRole("system.snapshot.get"))
	assert.Equal(t, "device-operator", methodRole("device.interface.write"))
	assert.Equal(t, "firmware-admin", methodRole("firmware.update.start"))
	assert.Equal(t, "terminal-admin", methodRole("terminal.open"))
	assert.Empty(t, methodRole("unknown.method"))
}

func TestHasRole(t *testing.T) {
	assert.True(t, hasRole([]string{"viewer", "support"}, "support"))
	assert.False(t, hasRole([]string{"viewer"}, "support"))
	assert.True(t, hasRole([]string{"*"}, "terminal-admin"))
}

func TestEveryOpenRPCMethodHasAnAuthorizationRole(t *testing.T) {
	for _, method := range remote.SupportedMethods {
		assert.NotEmptyf(t, methodRole(method), "method %q has no authorization role", method)
	}
}

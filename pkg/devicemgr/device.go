// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

package devicemgr

import (
	"time"

	"github.com/absmach/agent/pkg/iface"
)

// Device is a downstream device managed by the gateway.
type Device struct {
	ID            string              `json:"id"`
	Key           string              `json:"key"`
	ChannelID     string              `json:"channel_id"`
	InterfaceType iface.InterfaceType `json:"interface_type"`
	InterfaceAddr string              `json:"interface_addr"`
	Name          string              `json:"name"`
	Active        bool                `json:"active"`
	LastSeen      time.Time           `json:"last_seen"`
}

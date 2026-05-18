// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

package devicemgr

import "time"

// InterfaceType describes the physical bus a downstream device is attached to.
type InterfaceType string

const (
	InterfaceBLE     InterfaceType = "ble"
	InterfaceSerial  InterfaceType = "serial"
	InterfaceI2C     InterfaceType = "i2c"
	InterfaceUSB     InterfaceType = "usb"
	InterfaceZigbee  InterfaceType = "zigbee"
	InterfaceUnknown InterfaceType = "unknown"
)

// Device is a downstream device managed by the gateway.
type Device struct {
	ID            string        `json:"id"`
	Key           string        `json:"key"`
	ChannelID     string        `json:"channel_id"`
	InterfaceType InterfaceType `json:"interface_type"`
	InterfaceAddr string        `json:"interface_addr"`
	Name          string        `json:"name"`
	Active        bool          `json:"active"`
	LastSeen      time.Time     `json:"last_seen"`
}

// ParseInterfaceType converts a string to InterfaceType.
func ParseInterfaceType(s string) InterfaceType {
	switch InterfaceType(s) {
	case InterfaceBLE, InterfaceSerial, InterfaceI2C, InterfaceUSB, InterfaceZigbee:
		return InterfaceType(s)
	default:
		return InterfaceUnknown
	}
}

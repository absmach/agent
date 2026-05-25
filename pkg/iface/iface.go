// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

package iface

import (
	"fmt"

	"github.com/absmach/agent/pkg/iface/i2c"
	"github.com/absmach/agent/pkg/iface/modbus"
	"github.com/absmach/agent/pkg/iface/serial"
)

// InterfaceType describes the physical bus a downstream device is attached to.
type InterfaceType string

const (
	InterfaceBLE       InterfaceType = "ble"
	InterfaceSerial    InterfaceType = "serial"
	InterfaceI2C       InterfaceType = "i2c"
	InterfaceUSB       InterfaceType = "usb"
	InterfaceZigbee    InterfaceType = "zigbee"
	InterfaceModbusRTU InterfaceType = "modbus-rtu"
	InterfaceModbusTCP InterfaceType = "modbus-tcp"
	InterfaceUnknown   InterfaceType = "unknown"
)

// ParseInterfaceType converts a string to InterfaceType.
func ParseInterfaceType(s string) InterfaceType {
	switch InterfaceType(s) {
	case InterfaceBLE, InterfaceSerial, InterfaceI2C, InterfaceUSB,
		InterfaceZigbee, InterfaceModbusRTU, InterfaceModbusTCP:
		return InterfaceType(s)
	default:
		return InterfaceUnknown
	}
}

// Interface represents a physical communication bus to a downstream device.
type Interface interface {
	// Open initialises the connection to the device.
	Open() error
	// Close releases all resources held by the interface.
	Close() error
	// Read reads up to len(buf) bytes from the device into buf.
	Read(buf []byte) (int, error)
	// Write sends data to the device.
	Write(data []byte) (int, error)
}

// Config holds configuration for all supported interface types.
type Config struct {
	Serial serial.Config
	Modbus modbus.Config
	I2C    i2c.Config
}

// New returns an Interface for the given type and address.
// addr meaning per type:
//
//	serial / usb            — device path, e.g. /dev/ttyS0, /dev/ttyACM0
//	modbus-rtu              — serial device path, e.g. /dev/ttyS0
//	modbus-tcp              — host:port, e.g. 192.168.1.10:502
//	i2c                     — bus path, e.g. /dev/i2c-1
func New(ifaceType InterfaceType, addr string, cfg Config) (Interface, error) {
	switch ifaceType {
	case InterfaceSerial, InterfaceUSB:
		c := cfg.Serial
		c.Path = addr
		return serial.New(c), nil
	case InterfaceModbusRTU:
		c := cfg.Modbus
		c.Mode = modbus.ModeRTU
		c.Address = addr
		return modbus.New(c), nil
	case InterfaceModbusTCP:
		c := cfg.Modbus
		c.Mode = modbus.ModeTCP
		c.Address = addr
		return modbus.New(c), nil
	case InterfaceI2C:
		c := cfg.I2C
		c.Bus = addr
		return i2c.New(c), nil
	case InterfaceBLE:
		return nil, fmt.Errorf("ble: not implemented")
	case InterfaceZigbee:
		return nil, fmt.Errorf("zigbee: not implemented")
	default:
		return nil, fmt.Errorf("unsupported interface type: %s", ifaceType)
	}
}

// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

package iface_test

import (
	"testing"

	"github.com/absmach/agent/pkg/iface"
	"github.com/stretchr/testify/assert"
)

func TestParseInterfaceType(t *testing.T) {
	cases := []struct {
		input string
		want  iface.InterfaceType
	}{
		{"ble", iface.InterfaceBLE},
		{"serial", iface.InterfaceSerial},
		{"i2c", iface.InterfaceI2C},
		{"usb", iface.InterfaceUSB},
		{"zigbee", iface.InterfaceZigbee},
		{"modbus-rtu", iface.InterfaceModbusRTU},
		{"modbus-tcp", iface.InterfaceModbusTCP},
		{"unknown-type", iface.InterfaceUnknown},
		{"", iface.InterfaceUnknown},
	}

	for _, tc := range cases {
		t.Run(tc.input, func(t *testing.T) {
			got := iface.ParseInterfaceType(tc.input)
			assert.Equal(t, tc.want, got)
		})
	}
}

func TestNew_BLENotImplemented(t *testing.T) {
	_, err := iface.New(iface.InterfaceBLE, "addr", iface.Config{})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not implemented")
}

func TestNew_ZigbeeNotImplemented(t *testing.T) {
	_, err := iface.New(iface.InterfaceZigbee, "addr", iface.Config{})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not implemented")
}

func TestNew_UnknownType(t *testing.T) {
	_, err := iface.New(iface.InterfaceUnknown, "addr", iface.Config{})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported interface type")
}

func TestNew_Serial(t *testing.T) {
	ifc, err := iface.New(iface.InterfaceSerial, "/dev/ttyS0", iface.Config{})
	assert.NoError(t, err)
	assert.NotNil(t, ifc)
}

func TestNew_USB(t *testing.T) {
	ifc, err := iface.New(iface.InterfaceUSB, "/dev/ttyACM0", iface.Config{})
	assert.NoError(t, err)
	assert.NotNil(t, ifc)
}

func TestNew_ModbusRTU(t *testing.T) {
	ifc, err := iface.New(iface.InterfaceModbusRTU, "/dev/ttyS0", iface.Config{})
	assert.NoError(t, err)
	assert.NotNil(t, ifc)
}

func TestNew_ModbusTCP(t *testing.T) {
	ifc, err := iface.New(iface.InterfaceModbusTCP, "192.168.1.10:502", iface.Config{})
	assert.NoError(t, err)
	assert.NotNil(t, ifc)
}

func TestNew_I2C(t *testing.T) {
	ifc, err := iface.New(iface.InterfaceI2C, "/dev/i2c-1", iface.Config{})
	assert.NoError(t, err)
	assert.NotNil(t, ifc)
}

// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

package modbus

import (
	"fmt"
	"time"

	"github.com/goburrow/modbus"
)

// Mode selects the Modbus transport.
type Mode string

const (
	ModeRTU Mode = "rtu"
	ModeTCP Mode = "tcp"
)

// Config holds Modbus client parameters.
type Config struct {
	Mode    Mode
	Address string // serial path for RTU (e.g. /dev/ttyS0), host:port for TCP
	SlaveID byte

	// RTU-only parameters
	BaudRate int
	DataBits int
	StopBits int
	Parity   string // "N" = none, "E" = even, "O" = odd

	// Default register range used by Read and Write
	RegisterStart uint16
	RegisterCount uint16

	Timeout time.Duration
}

// DefaultConfig returns a Config with sensible defaults.
func DefaultConfig() Config {
	return Config{
		SlaveID:       1,
		BaudRate:      9600,
		DataBits:      8,
		StopBits:      1,
		Parity:        "N",
		RegisterStart: 0,
		RegisterCount: 1,
		Timeout:       5 * time.Second,
	}
}

// closer is the subset of both RTUClientHandler and TCPClientHandler that we need.
type closer interface {
	Close() error
}

// Modbus wraps a goburrow Modbus client for RTU or TCP transport.
// Read returns holding register values as big-endian bytes (2 bytes per register).
// Write interprets supplied bytes as big-endian uint16 register values.
type Modbus struct {
	cfg     Config
	handler closer
	client  modbus.Client
}

// New returns an uninitialised Modbus. Call Open before reading or writing.
func New(cfg Config) *Modbus {
	return &Modbus{cfg: cfg}
}

// Open connects to the Modbus device.
func (m *Modbus) Open() error {
	if m.cfg.Address == "" {
		return fmt.Errorf("modbus: address is required")
	}

	switch m.cfg.Mode {
	case ModeRTU:
		h := modbus.NewRTUClientHandler(m.cfg.Address)
		h.BaudRate = m.cfg.BaudRate
		h.DataBits = m.cfg.DataBits
		h.StopBits = m.cfg.StopBits
		h.Parity = m.cfg.Parity
		h.SlaveId = m.cfg.SlaveID
		h.Timeout = m.cfg.Timeout
		if err := h.Connect(); err != nil {
			return fmt.Errorf("modbus rtu: connect %s: %w", m.cfg.Address, err)
		}
		m.handler = h
		m.client = modbus.NewClient(h)
	case ModeTCP:
		h := modbus.NewTCPClientHandler(m.cfg.Address)
		h.SlaveId = m.cfg.SlaveID
		h.Timeout = m.cfg.Timeout
		if err := h.Connect(); err != nil {
			return fmt.Errorf("modbus tcp: connect %s: %w", m.cfg.Address, err)
		}
		m.handler = h
		m.client = modbus.NewClient(h)
	default:
		return fmt.Errorf("modbus: unknown mode %q", m.cfg.Mode)
	}

	return nil
}

// Close disconnects from the Modbus device.
func (m *Modbus) Close() error {
	if m.handler == nil {
		return nil
	}
	if err := m.handler.Close(); err != nil {
		return fmt.Errorf("modbus: close: %w", err)
	}
	m.handler = nil
	m.client = nil
	return nil
}

// Read reads cfg.RegisterCount holding registers starting at cfg.RegisterStart
// and copies them into buf (big-endian, 2 bytes per register).
func (m *Modbus) Read(buf []byte) (int, error) {
	if m.client == nil {
		return 0, fmt.Errorf("modbus: not connected")
	}
	results, err := m.client.ReadHoldingRegisters(m.cfg.RegisterStart, m.cfg.RegisterCount)
	if err != nil {
		return 0, fmt.Errorf("modbus: read registers: %w", err)
	}
	n := copy(buf, results)
	return n, nil
}

// Write interprets data as big-endian uint16 register values and writes them
// starting at cfg.RegisterStart.
func (m *Modbus) Write(data []byte) (int, error) {
	if m.client == nil {
		return 0, fmt.Errorf("modbus: not connected")
	}
	if len(data)%2 != 0 {
		return 0, fmt.Errorf("modbus: data length must be even (got %d bytes)", len(data))
	}
	count := uint16(len(data) / 2)
	if _, err := m.client.WriteMultipleRegisters(m.cfg.RegisterStart, count, data); err != nil {
		return 0, fmt.Errorf("modbus: write registers: %w", err)
	}
	return len(data), nil
}

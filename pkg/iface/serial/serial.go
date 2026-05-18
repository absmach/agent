// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

package serial

import (
	"fmt"

	goserial "go.bug.st/serial"
)

// Config holds serial port parameters.
type Config struct {
	Path     string
	BaudRate int
	DataBits int
	StopBits goserial.StopBits
	Parity   goserial.Parity
}

// DefaultConfig returns sensible defaults (9600 8N1).
func DefaultConfig(path string) Config {
	return Config{
		Path:     path,
		BaudRate: 9600,
		DataBits: 8,
		StopBits: goserial.OneStopBit,
		Parity:   goserial.NoParity,
	}
}

// Serial wraps a go.bug.st/serial.Port.
// It covers /dev/ttyS*, /dev/ttyUSB*, and /dev/ttyACM* (USB CDC-ACM).
type Serial struct {
	cfg  Config
	port goserial.Port
}

// New returns an uninitialised Serial. Call Open before reading or writing.
func New(cfg Config) *Serial {
	return &Serial{cfg: cfg}
}

// Open opens the serial port with the configured parameters.
func (s *Serial) Open() error {
	if s.cfg.Path == "" {
		return fmt.Errorf("serial: path is required")
	}
	mode := &goserial.Mode{
		BaudRate: s.cfg.BaudRate,
		DataBits: s.cfg.DataBits,
		StopBits: s.cfg.StopBits,
		Parity:   s.cfg.Parity,
	}
	port, err := goserial.Open(s.cfg.Path, mode)
	if err != nil {
		return fmt.Errorf("serial: open %s: %w", s.cfg.Path, err)
	}
	s.port = port
	return nil
}

// Close closes the serial port.
func (s *Serial) Close() error {
	if s.port == nil {
		return nil
	}
	if err := s.port.Close(); err != nil {
		return fmt.Errorf("serial: close: %w", err)
	}
	s.port = nil
	return nil
}

// Read reads up to len(buf) bytes from the serial port.
func (s *Serial) Read(buf []byte) (int, error) {
	if s.port == nil {
		return 0, fmt.Errorf("serial: port not open")
	}
	return s.port.Read(buf)
}

// Write writes data to the serial port.
func (s *Serial) Write(data []byte) (int, error) {
	if s.port == nil {
		return 0, fmt.Errorf("serial: port not open")
	}
	return s.port.Write(data)
}

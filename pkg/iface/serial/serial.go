// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

package serial

import (
	"fmt"
	"time"

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

const openTimeout = 10 * time.Second
const readTimeout = 100 * time.Millisecond

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

	type result struct {
		port goserial.Port
		err  error
	}
	ch := make(chan result, 1)
	go func() {
		p, err := goserial.Open(s.cfg.Path, mode)
		ch <- result{p, err}
	}()

	select {
	case r := <-ch:
		if r.err != nil {
			return fmt.Errorf("serial: open %s: %w", s.cfg.Path, r.err)
		}
		s.port = r.port
		if err := s.port.SetReadTimeout(readTimeout); err != nil {
			return fmt.Errorf("serial: set read timeout: %w", err)
		}
		return nil
	case <-time.After(openTimeout):
		return fmt.Errorf("serial: open %s: timeout after %v", s.cfg.Path, openTimeout)
	}
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

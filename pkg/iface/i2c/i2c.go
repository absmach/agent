// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package i2c

import (
	"fmt"
	"os"
	"unsafe"

	"golang.org/x/sys/unix"
)

const i2cSlave = 0x0703 // I2C_SLAVE ioctl request code

// Config holds I2C bus and device address parameters.
type Config struct {
	Bus  string // e.g. /dev/i2c-1
	Addr uint8  // 7-bit device address
}

// I2C communicates with a device on a Linux I2C bus via /dev/i2c-N.
type I2C struct {
	cfg Config
	f   *os.File
}

// New returns an uninitialised I2C. Call Open before reading or writing.
func New(cfg Config) *I2C {
	return &I2C{cfg: cfg}
}

// Open opens the I2C bus file and selects the target device address.
func (d *I2C) Open() error {
	if d.cfg.Bus == "" {
		return fmt.Errorf("i2c: bus path is required")
	}
	f, err := os.OpenFile(d.cfg.Bus, os.O_RDWR, 0)
	if err != nil {
		return fmt.Errorf("i2c: open %s: %w", d.cfg.Bus, err)
	}
	// Set the slave address for subsequent read/write calls.
	if err := unix.IoctlSetInt(int(f.Fd()), i2cSlave, int(d.cfg.Addr)); err != nil {
		f.Close()
		return fmt.Errorf("i2c: set slave 0x%02x on %s: %w", d.cfg.Addr, d.cfg.Bus, err)
	}
	d.f = f
	return nil
}

// Close closes the I2C bus file descriptor.
func (d *I2C) Close() error {
	if d.f == nil {
		return nil
	}
	if err := d.f.Close(); err != nil {
		return fmt.Errorf("i2c: close: %w", err)
	}
	d.f = nil
	return nil
}

// Read reads up to len(buf) bytes from the device.
func (d *I2C) Read(buf []byte) (int, error) {
	if d.f == nil {
		return 0, fmt.Errorf("i2c: not open")
	}
	n, err := d.f.Read(buf)
	if err != nil {
		return n, fmt.Errorf("i2c: read: %w", err)
	}
	return n, nil
}

// Write sends data to the device.
func (d *I2C) Write(data []byte) (int, error) {
	if d.f == nil {
		return 0, fmt.Errorf("i2c: not open")
	}
	n, err := d.f.Write(data)
	if err != nil {
		return n, fmt.Errorf("i2c: write: %w", err)
	}
	return n, nil
}

// ensure unsafe is used (required by the ioctl call path via unix package).
var _ = unsafe.Sizeof(0)

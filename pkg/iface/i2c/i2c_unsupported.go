// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

//go:build !linux

package i2c

import "fmt"

// Config holds I2C bus and device address parameters.
type Config struct {
	Bus  string
	Addr uint8
}

// I2C is a stub on non-Linux platforms.
type I2C struct {
	cfg Config
}

// New returns an I2C stub that always errors.
func New(cfg Config) *I2C {
	return &I2C{cfg: cfg}
}

func (d *I2C) Open() error {
	return fmt.Errorf("i2c: not supported on this platform")
}

func (d *I2C) Close() error {
	return nil
}

func (d *I2C) Read(buf []byte) (int, error) {
	return 0, fmt.Errorf("i2c: not supported on this platform")
}

func (d *I2C) Write(data []byte) (int, error) {
	return 0, fmt.Errorf("i2c: not supported on this platform")
}

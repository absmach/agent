// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

package terminal

import (
	"bytes"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"sync"
	"time"

	"github.com/absmach/agent/pkg/senml"
	"github.com/absmach/magistrala/pkg/errors"
	"github.com/creack/pty"
)

const (
	terminal = "term"
	second   = time.Duration(1 * time.Second)
)

type term struct {
	uuid         string
	ptmx         *os.File
	done         chan bool
	topic        string
	timeout      time.Duration
	resetTimeout time.Duration
	timer        *time.Ticker
	publish      func(channel, payload string) error
	publishBytes func([]byte) error
	logger       *slog.Logger
	mu           sync.Mutex
}

type Session interface {
	Send(p []byte) error
	Resize(columns, rows uint16) error
	Close() error
	IsDone() chan bool
	io.Writer
}

func (t *term) Resize(columns, rows uint16) error {
	return pty.Setsize(t.ptmx, &pty.Winsize{Rows: rows, Cols: columns})
}

func (t *term) Close() error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.timer != nil {
		t.timer.Stop()
	}
	if t.ptmx == nil {
		return nil
	}
	err := t.ptmx.Close()
	t.ptmx = nil
	return err
}

func NewSession(uuid string, timeout time.Duration, publish func(channel, payload string) error, logger *slog.Logger) (Session, error) {
	t := &term{
		logger:       logger,
		uuid:         uuid,
		publish:      publish,
		timeout:      timeout,
		resetTimeout: timeout,
		topic:        "term/" + uuid,
		done:         make(chan bool),
	}

	shell := os.Getenv("SHELL")
	if shell == "" {
		shell = "/bin/sh"
	}
	c := exec.Command(shell)
	ptmx, err := pty.Start(c)
	if err != nil {
		return t, errors.New(err.Error())
	}
	t.ptmx = ptmx

	// Copy output to mqtt
	go func() {
		buf := make([]byte, 4096)
		for {
			nr, readErr := t.ptmx.Read(buf)
			if nr > 0 {
				if _, writeErr := t.Write(buf[:nr]); writeErr != nil {
					t.logger.Error("Error sending terminal data", slog.Any("error", writeErr))
				}
			}
			if readErr != nil {
				if readErr != io.EOF {
					t.logger.Error("PTY read error", slog.Any("error", readErr))
				}
				return
			}
		}
	}()

	t.timer = time.NewTicker(1 * time.Second)

	go func() {
		for range t.timer.C {
			t.decrementCounter()
		}
		t.logger.Debug("exiting timer routine")
	}()

	return t, nil
}

// NewStreamSession creates a PTY session whose output is delivered as raw
// bytes. Remote transports use this to frame terminal output themselves rather
// than wrapping every frame in the legacy SenML terminal envelope.
func NewStreamSession(uuid string, timeout time.Duration, publish func([]byte) error, logger *slog.Logger) (Session, error) {
	t := &term{
		logger:       logger,
		uuid:         uuid,
		publishBytes: publish,
		timeout:      timeout,
		resetTimeout: timeout,
		done:         make(chan bool),
	}

	shell := os.Getenv("SHELL")
	if shell == "" {
		shell = "/bin/sh"
	}
	c := exec.Command(shell)
	ptmx, err := pty.Start(c)
	if err != nil {
		return t, errors.New(err.Error())
	}
	t.ptmx = ptmx

	go t.copyOutput()
	t.startTimer()
	return t, nil
}

func (t *term) copyOutput() {
	buf := make([]byte, 4096)
	for {
		nr, readErr := t.ptmx.Read(buf)
		if nr > 0 {
			if _, writeErr := t.Write(buf[:nr]); writeErr != nil {
				t.logger.Error("Error sending terminal data", slog.Any("error", writeErr))
			}
		}
		if readErr != nil {
			if readErr != io.EOF {
				t.logger.Error("PTY read error", slog.Any("error", readErr))
			}
			return
		}
	}
}

func (t *term) startTimer() {
	t.timer = time.NewTicker(1 * time.Second)
	go func() {
		for range t.timer.C {
			t.decrementCounter()
		}
		t.logger.Debug("exiting timer routine")
	}()
}

func (t *term) resetCounter(timeout time.Duration) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if timeout > 0 {
		t.timeout = timeout
		return
	}
}

func (t *term) decrementCounter() {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.timeout -= second
	if t.timeout == 0 {
		t.done <- true
		t.timer.Stop()
	}
}

func (t *term) IsDone() chan bool {
	return t.done
}

func (t *term) Write(p []byte) (int, error) {
	t.resetCounter(t.resetTimeout)
	n := len(p)
	t.logger.Info("Terminal output", slog.Int("bytes", n), slog.String("uuid", t.uuid))
	if t.publishBytes != nil {
		if err := t.publishBytes(append([]byte(nil), p...)); err != nil {
			t.logger.Error("Terminal stream publish failed", slog.Any("error", err), slog.String("uuid", t.uuid))
			return n, err
		}
		return n, nil
	}
	payload, err := senml.EncodeString(t.uuid, terminal, string(p))
	if err != nil {
		return n, err
	}

	if err := t.publish(t.topic, string(payload)); err != nil {
		t.logger.Error("Terminal publish failed", slog.Any("error", err), slog.String("uuid", t.uuid))
		return n, err
	}
	return n, nil
}

func (t *term) Send(p []byte) error {
	t.resetCounter(t.resetTimeout)
	in := bytes.NewReader(p)
	nr, err := io.Copy(t.ptmx, in)
	t.logger.Info("Terminal input", slog.Int("bytes", int(nr)), slog.String("uuid", t.uuid))
	if err != nil {
		return errors.New(err.Error())
	}
	return nil
}

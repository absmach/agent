// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

package ota

import (
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"net/http"
	neturl "net/url"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/absmach/senml"
)

// State represents the OTA update state machine.
type State int

const (
	StateIdle State = iota
	StateTriggered
	StateDownloading
	StateVerifying
	StateReady
	StateRestarting
)

func (s State) String() string {
	switch s {
	case StateIdle:
		return "IDLE"
	case StateTriggered:
		return "TRIGGERED"
	case StateDownloading:
		return "DOWNLOADING"
	case StateVerifying:
		return "VERIFYING"
	case StateReady:
		return "READY"
	case StateRestarting:
		return "RESTARTING"
	default:
		return "UNKNOWN"
	}
}

// ProgressFn is called on state transitions and during download.
// progress is 0–100 and is only meaningful in StateDownloading.
type ProgressFn func(state State, progress float64)

// Config holds the OTA updater parameters.
type Config struct {
	BinaryPath  string // absolute path to the running binary, e.g. /usr/local/bin/agent
	DownloadDir string // directory for the temporary download file, e.g. /tmp
}

// Trigger holds the parsed fields from an OTA SenML trigger payload.
type Trigger struct {
	URL       string
	SHA256Hex string // hex-encoded expected SHA-256, empty if not provided
	Size      uint64 // expected byte count, 0 means no size check
}

// TriggerFromRecords parses OTA trigger fields from the SenML records that
// follow the dispatch record. The full wire format (all records in the pack) is:
//
//	{"bn":"<uuid>:", "n":"ota",  "vs":""}              — dispatch record (index 0, not passed here)
//	{"n":"url",  "vs":"https://..."}                   — required
//	{"n":"hash", "vs":"<sha256-hex>"}                  — optional
//	{"n":"size", "v":<byte-count>}                     — optional
//
// Pass sm.Records[1:] to skip the dispatch record.
func TriggerFromRecords(records []senml.Record) (Trigger, error) {
	var t Trigger
	for _, r := range records {
		switch r.Name {
		case "url":
			if r.StringValue == nil || strings.TrimSpace(*r.StringValue) == "" {
				return Trigger{}, fmt.Errorf("ota trigger: url record has no value")
			}
			t.URL = strings.TrimSpace(*r.StringValue)
		case "hash":
			if r.StringValue != nil {
				t.SHA256Hex = *r.StringValue
			}
		case "size":
			if r.Value != nil {
				t.Size = uint64(*r.Value)
			}
		}
	}
	if t.URL == "" {
		return Trigger{}, fmt.Errorf("ota trigger: url is required")
	}
	return t, nil
}

// Run executes the full OTA cycle: download → verify → replace → restart.
// sha256hex is the expected SHA-256 hex digest; if empty the sidecar at url+".sha256" is tried.
// size is the expected byte count; if non-zero the downloaded file is checked against it.
// Verification is mandatory: if neither sha256hex nor a reachable sidecar is available the
// update is aborted and the running binary is left untouched.
// On success it never returns (the process is replaced in-place).
func Run(ctx context.Context, cfg Config, url, sha256hex string, size uint64, progressFn ProgressFn) error {
	if progressFn == nil {
		progressFn = func(State, float64) {}
	}
	progressFn(StateTriggered, 0)

	progressFn(StateDownloading, 0)
	tmpPath, err := download(ctx, url, cfg.DownloadDir, size, func(pct float64) {
		progressFn(StateDownloading, pct)
	})
	if err != nil {
		return fmt.Errorf("ota download: %w", err)
	}

	progressFn(StateVerifying, 100)
	verified, err := verify(ctx, url, tmpPath, sha256hex)
	if err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("ota verify: %w", err)
	}
	if !verified {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("ota verify: no hash provided and sidecar not found at %s.sha256; refusing unverified install", url)
	}

	progressFn(StateReady, 100)
	if err := replace(tmpPath, cfg.BinaryPath); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("ota replace: %w", err)
	}

	progressFn(StateRestarting, 100)
	return syscall.Exec(cfg.BinaryPath, os.Args, os.Environ())
}

// download fetches url into a temporary file under dir and returns its path.
// If size is non-zero the stream is aborted as soon as written bytes exceed it.
// pctFn is called each time download progress crosses a 5% threshold.
func download(ctx context.Context, url, dir string, size uint64, pctFn func(float64)) (string, error) {
	u, err := neturl.Parse(url)
	if err != nil {
		return "", fmt.Errorf("invalid URL: %w", err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return "", fmt.Errorf("unsupported URL scheme %q, must be http or https", u.Scheme)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", err
	}

	client := &http.Client{Timeout: 10 * time.Minute}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("server returned HTTP %d", resp.StatusCode)
	}

	f, err := os.CreateTemp(dir, "agent-ota-*")
	if err != nil {
		return "", err
	}
	tmpName := f.Name()

	total := resp.ContentLength
	var written int64
	lastPct := 0.0
	buf := make([]byte, 32*1024)
	pctFn(0)

	for {
		if ctx.Err() != nil {
			_ = f.Close()
			_ = os.Remove(tmpName)
			return "", ctx.Err()
		}
		n, rerr := resp.Body.Read(buf)
		if n > 0 {
			if _, werr := f.Write(buf[:n]); werr != nil {
				_ = f.Close()
				_ = os.Remove(tmpName)
				return "", werr
			}
			written += int64(n)
			if size > 0 && uint64(written) > size {
				_ = f.Close()
				_ = os.Remove(tmpName)
				return "", fmt.Errorf("download exceeded expected size %d bytes", size)
			}
			if total > 0 {
				pct := float64(written) / float64(total) * 100
				if pct-lastPct >= 5 {
					lastPct = pct
					pctFn(pct)
				}
			}
		}
		if rerr == io.EOF {
			break
		}
		if rerr != nil {
			_ = f.Close()
			_ = os.Remove(tmpName)
			return "", rerr
		}
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(tmpName)
		return "", err
	}
	pctFn(100)
	return tmpName, nil
}

// verify checks the SHA-256 of tmpPath.
// If sha256hex is non-empty it is used directly.
// Otherwise a sidecar file at url+".sha256" is fetched.
// Returns (true, nil) if verified, (false, nil) if no hash was available (verification skipped),
// or (false, err) on a hash mismatch or I/O error.
func verify(ctx context.Context, url, tmpPath, sha256hex string) (bool, error) {
	expected := sha256hex
	if expected == "" {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url+".sha256", nil)
		if err != nil {
			return false, nil
		}
		client := &http.Client{Timeout: 30 * time.Second}
		resp, err := client.Do(req)
		if err != nil {
			return false, fmt.Errorf("fetch sidecar: %w", err)
		}
		defer func() { _ = resp.Body.Close() }()
		if resp.StatusCode == http.StatusNotFound {
			return false, nil
		}
		if resp.StatusCode != http.StatusOK {
			return false, fmt.Errorf("fetch sidecar: unexpected HTTP %d", resp.StatusCode)
		}
		raw, err := io.ReadAll(io.LimitReader(resp.Body, 128))
		if err != nil {
			return false, nil
		}
		fields := strings.Fields(string(raw))
		if len(fields) == 0 {
			return false, nil
		}
		expected = fields[0]
	}

	f, err := os.Open(tmpPath)
	if err != nil {
		return false, err
	}
	defer func() { _ = f.Close() }()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return false, err
	}
	got := fmt.Sprintf("%x", h.Sum(nil))
	if got != expected {
		return false, fmt.Errorf("sha256 mismatch: got %s, want %s", got, expected)
	}
	return true, nil
}

// replace atomically installs src as dst.
// It first tries os.Rename (fast, atomic when src and dst share a filesystem).
// On a cross-device rename failure it falls back to a copy-then-rename into dst's directory.
func replace(src, dst string) error {
	if err := os.Chmod(src, 0o755); err != nil {
		return err
	}
	if err := os.Rename(src, dst); err == nil {
		return nil
	}
	dir := filepath.Dir(dst)
	tmp, err := os.CreateTemp(dir, ".agent-ota-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()

	in, err := os.Open(src)
	if err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
		return err
	}
	if _, err := io.Copy(tmp, in); err != nil {
		_ = in.Close()
		_ = tmp.Close()
		_ = os.Remove(tmpName)
		return err
	}
	_ = in.Close()
	if err := tmp.Chmod(0o755); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
		return err
	}
	_ = tmp.Close()
	if err := os.Rename(tmpName, dst); err != nil {
		_ = os.Remove(tmpName)
		return err
	}
	_ = os.Remove(src)
	return nil
}

// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

package ota

import (
	"context"
	"crypto/sha256"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// --- State ---

func TestState_String(t *testing.T) {
	cases := []struct {
		state    State
		expected string
	}{
		{StateIdle, "IDLE"},
		{StateTriggered, "TRIGGERED"},
		{StateDownloading, "DOWNLOADING"},
		{StateVerifying, "VERIFYING"},
		{StateReady, "READY"},
		{StateRestarting, "RESTARTING"},
		{State(99), "UNKNOWN"},
	}
	for _, tc := range cases {
		assert.Equal(t, tc.expected, tc.state.String(), tc.state)
	}
}

// --- ParseTrigger ---

func TestParseTrigger(t *testing.T) {
	cases := []struct {
		desc      string
		input     string
		url       string
		sha256hex string
		size      uint64
		wantErr   bool
	}{
		{
			desc:  "url only",
			input: "https://example.com/agent.bin",
			url:   "https://example.com/agent.bin",
		},
		{
			desc:      "url with sha256",
			input:     "https://example.com/agent.bin,sha256:abcdef1234567890",
			url:       "https://example.com/agent.bin",
			sha256hex: "abcdef1234567890",
		},
		{
			desc:      "url with sha256 and size",
			input:     "https://example.com/agent.bin,sha256:abcdef1234567890,153600",
			url:       "https://example.com/agent.bin",
			sha256hex: "abcdef1234567890",
			size:      153600,
		},
		{
			desc:  "url with size only",
			input: "https://example.com/agent.bin,153600",
			url:   "https://example.com/agent.bin",
			size:  153600,
		},
		{
			desc:      "size before sha256",
			input:     "https://example.com/agent.bin,153600,sha256:abcdef1234567890",
			url:       "https://example.com/agent.bin",
			sha256hex: "abcdef1234567890",
			size:      153600,
		},
		{
			desc:      "whitespace around fields",
			input:     "https://example.com/agent.bin, sha256:abcdef1234567890, 153600",
			url:       "https://example.com/agent.bin",
			sha256hex: "abcdef1234567890",
			size:      153600,
		},
		{
			desc:    "empty string",
			input:   "",
			wantErr: true,
		},
		{
			desc:    "only comma",
			input:   ",",
			wantErr: true,
		},
		{
			desc:  "unknown extra field ignored",
			input: "https://example.com/agent.bin,someunknownfield",
			url:   "https://example.com/agent.bin",
		},
	}
	for _, tc := range cases {
		t.Run(tc.desc, func(t *testing.T) {
			tr, err := ParseTrigger(tc.input)
			if tc.wantErr {
				assert.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.url, tr.URL)
			assert.Equal(t, tc.sha256hex, tr.SHA256Hex)
			assert.Equal(t, tc.size, tr.Size)
		})
	}
}

// --- download ---

func TestDownload_Success(t *testing.T) {
	content := []byte("fake agent binary content")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", fmt.Sprintf("%d", len(content)))
		w.WriteHeader(http.StatusOK)
		w.Write(content)
	}))
	defer srv.Close()

	dir := t.TempDir()
	var progressCalls []float64
	path, err := download(context.Background(), srv.URL, dir, func(pct float64) {
		progressCalls = append(progressCalls, pct)
	})
	require.NoError(t, err)
	defer os.Remove(path)

	got, err := os.ReadFile(path)
	require.NoError(t, err)
	assert.Equal(t, content, got)
	assert.Contains(t, progressCalls, float64(0), "0%% should be reported immediately")
	assert.Contains(t, progressCalls, float64(100), "100%% should always be reported")
}

func TestDownload_ServerError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	_, err := download(context.Background(), srv.URL, t.TempDir(), func(float64) {})
	assert.ErrorContains(t, err, "500")
}

func TestDownload_NotFound(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	_, err := download(context.Background(), srv.URL, t.TempDir(), func(float64) {})
	assert.Error(t, err)
}

func TestDownload_ContextCancelled(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// block until client disconnects
		<-r.Context().Done()
	}))
	defer srv.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := download(ctx, srv.URL, t.TempDir(), func(float64) {})
	assert.Error(t, err)
}

func TestDownload_ProgressReportedEvery5Percent(t *testing.T) {
	const size = 1000
	content := make([]byte, size)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", fmt.Sprintf("%d", size))
		w.WriteHeader(http.StatusOK)
		w.Write(content)
	}))
	defer srv.Close()

	var calls []float64
	path, err := download(context.Background(), srv.URL, t.TempDir(), func(pct float64) {
		calls = append(calls, pct)
	})
	require.NoError(t, err)
	os.Remove(path)

	// consecutive reported values should differ by at least 5%, except the final 100%
	for i := 1; i < len(calls)-1; i++ {
		assert.GreaterOrEqual(t, calls[i]-calls[i-1], 5.0,
			"progress jumps should be >=5%% (got %.1f -> %.1f)", calls[i-1], calls[i])
	}
}

// --- verify ---

func sha256hex(data []byte) string {
	h := sha256.Sum256(data)
	return fmt.Sprintf("%x", h[:])
}

func writeTempFile(t *testing.T, content []byte) string {
	t.Helper()
	f, err := os.CreateTemp(t.TempDir(), "ota-verify-*")
	require.NoError(t, err)
	_, err = f.Write(content)
	require.NoError(t, err)
	require.NoError(t, f.Close())
	return f.Name()
}

func TestVerify_InlineHash_Match(t *testing.T) {
	content := []byte("agent binary")
	path := writeTempFile(t, content)
	err := verify(context.Background(), "http://unused", path, sha256hex(content))
	assert.NoError(t, err)
}

func TestVerify_InlineHash_Mismatch(t *testing.T) {
	path := writeTempFile(t, []byte("agent binary"))
	err := verify(context.Background(), "http://unused", path, "deadbeef")
	assert.ErrorContains(t, err, "sha256 mismatch")
}

func TestVerify_Sidecar_Match(t *testing.T) {
	content := []byte("agent binary")
	path := writeTempFile(t, content)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "%s  agent.bin\n", sha256hex(content))
	}))
	defer srv.Close()

	err := verify(context.Background(), srv.URL+"/agent.bin", path, "")
	assert.NoError(t, err)
}

func TestVerify_Sidecar_Mismatch(t *testing.T) {
	path := writeTempFile(t, []byte("agent binary"))

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "deadbeef  agent.bin\n")
	}))
	defer srv.Close()

	err := verify(context.Background(), srv.URL+"/agent.bin", path, "")
	assert.ErrorContains(t, err, "sha256 mismatch")
}

func TestVerify_Sidecar_NotFound_Skipped(t *testing.T) {
	path := writeTempFile(t, []byte("agent binary"))

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	err := verify(context.Background(), srv.URL+"/agent.bin", path, "")
	assert.NoError(t, err, "missing sidecar should be silently skipped")
}

func TestVerify_NoHashNoSidecar_Skipped(t *testing.T) {
	path := writeTempFile(t, []byte("agent binary"))
	// immediately-closed server simulates connection refused — network error should be skipped
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	srv.Close()
	err := verify(context.Background(), srv.URL+"/agent.bin", path, "")
	assert.NoError(t, err, "unreachable sidecar host should be silently skipped")
}

func TestVerify_InlineTakesPrecedenceOverSidecar(t *testing.T) {
	content := []byte("agent binary")
	path := writeTempFile(t, content)

	// sidecar serves wrong hash — inline hash is correct, should pass
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "deadbeef  agent.bin\n")
	}))
	defer srv.Close()

	err := verify(context.Background(), srv.URL+"/agent.bin", path, sha256hex(content))
	assert.NoError(t, err, "inline hash should take precedence over sidecar")
}

// --- replace ---

func TestReplace_SameFilesystem(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "new-agent")
	dst := filepath.Join(dir, "agent")

	require.NoError(t, os.WriteFile(src, []byte("new binary"), 0o644))
	require.NoError(t, os.WriteFile(dst, []byte("old binary"), 0o755))

	require.NoError(t, replace(src, dst))

	got, err := os.ReadFile(dst)
	require.NoError(t, err)
	assert.Equal(t, []byte("new binary"), got)

	info, err := os.Stat(dst)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o755), info.Mode().Perm(), "binary should be executable")

	_, err = os.Stat(src)
	assert.True(t, os.IsNotExist(err), "src temp file should be consumed")
}

func TestReplace_MissingSource(t *testing.T) {
	dir := t.TempDir()
	err := replace(filepath.Join(dir, "nonexistent"), filepath.Join(dir, "dst"))
	assert.Error(t, err)
}

// --- Run error paths ---

func TestRun_DownloadFails_BadURL(t *testing.T) {
	// immediately-closed server gives connection refused without a timeout
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	srv.Close()

	cfg := Config{Enabled: true, BinaryPath: "/tmp/agent", DownloadDir: t.TempDir()}
	var states []State
	err := Run(context.Background(), cfg, srv.URL, "", func(s State, _ float64) {
		states = append(states, s)
	})
	require.Error(t, err)
	assert.ErrorContains(t, err, "ota download")
	assert.Equal(t, []State{StateTriggered, StateDownloading}, states,
		"should report TRIGGERED then DOWNLOADING before failing")
}

func TestRun_DownloadFails_ServerError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer srv.Close()

	cfg := Config{Enabled: true, BinaryPath: "/tmp/agent", DownloadDir: t.TempDir()}
	err := Run(context.Background(), cfg, srv.URL, "", func(State, float64) {})
	assert.ErrorContains(t, err, "ota download")
}

func TestRun_VerifyFails_HashMismatch(t *testing.T) {
	content := []byte("fake binary content")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", fmt.Sprintf("%d", len(content)))
		w.WriteHeader(http.StatusOK)
		w.Write(content)
	}))
	defer srv.Close()

	dir := t.TempDir()
	cfg := Config{Enabled: true, BinaryPath: filepath.Join(dir, "agent"), DownloadDir: dir}

	var states []State
	err := Run(context.Background(), cfg, srv.URL, "deadbeef", func(s State, _ float64) {
		states = append(states, s)
	})
	require.Error(t, err)
	assert.ErrorContains(t, err, "ota verify")
	assert.Contains(t, states, StateVerifying)

	// temp file should be cleaned up after verify failure
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		assert.False(t, e.Name() != filepath.Base(cfg.BinaryPath) &&
			len(e.Name()) > 9 && e.Name()[:9] == "agent-ota",
			"temp file %q should have been removed", e.Name())
	}
}

func TestRun_StateProgression_OnDownloadFailure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	cfg := Config{Enabled: true, BinaryPath: "/tmp/agent", DownloadDir: t.TempDir()}
	var states []State
	Run(context.Background(), cfg, srv.URL, "", func(s State, _ float64) {
		states = append(states, s)
	})

	assert.Equal(t, StateTriggered, states[0], "first state must be TRIGGERED")
	assert.Equal(t, StateDownloading, states[1], "second state must be DOWNLOADING")
	assert.Len(t, states, 2, "should not progress past DOWNLOADING on server error")
}

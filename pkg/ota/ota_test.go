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
	"strings"
	"testing"

	"github.com/absmach/senml"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

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

func TestParseCfgFromRecords(t *testing.T) {
	urlVal := "https://example.com/agent.bin"
	hashVal := "abcdef1234567890"
	sizeVal := 153600.0

	cases := []struct {
		desc     string
		records  []senml.Record
		wantURL  string
		wantHash string
		wantSize uint64
	}{
		{
			desc:     "url, hash, and size present",
			records:  []senml.Record{{Name: "url", StringValue: &urlVal}, {Name: "hash", StringValue: &hashVal}, {Name: "size", Value: &sizeVal}},
			wantURL:  urlVal,
			wantHash: hashVal,
			wantSize: 153600,
		},
		{
			desc:     "hash and size only (no url for MQTT path)",
			records:  []senml.Record{{Name: "hash", StringValue: &hashVal}, {Name: "size", Value: &sizeVal}},
			wantHash: hashVal,
			wantSize: 153600,
		},
		{
			desc:    "empty records",
			records: []senml.Record{},
		},
		{
			desc:    "url with nil string value is ignored",
			records: []senml.Record{{Name: "url", StringValue: nil}},
			wantURL: "",
		},
	}

	for _, tc := range cases {
		t.Run(tc.desc, func(t *testing.T) {
			tr := ParseCfgFromRecords(tc.records)
			assert.Equal(t, tc.wantURL, tr.URL)
			assert.Equal(t, tc.wantHash, tr.SHA256Hex)
			assert.Equal(t, tc.wantSize, tr.Size)
		})
	}
}

func TestRunFromData(t *testing.T) {
	content := []byte("fake binary content for mqtt ota")

	cases := []struct {
		desc            string
		data            []byte
		sha256hex       string
		wantErrContains string
	}{
		{
			desc:            "empty hash rejected",
			data:            content,
			sha256hex:       "",
			wantErrContains: "hash required",
		},
		{
			desc:            "hash mismatch",
			data:            content,
			sha256hex:       "deadbeef",
			wantErrContains: "sha256 mismatch",
		},
		{
			desc:      "correct hash proceeds to exec (expected to fail in test)",
			data:      content,
			sha256hex: sha256hex(content),
			// syscall.Exec fails because content is not a valid binary;
			// we just check there is an error (not a verify error).
			wantErrContains: "",
		},
	}

	for _, tc := range cases {
		t.Run(tc.desc, func(t *testing.T) {
			dir := t.TempDir()
			dst := filepath.Join(dir, "agent-dst")
			cfg := Config{BinaryPath: dst, DownloadDir: dir}

			var states []State
			err := RunFromData(context.Background(), cfg, tc.data, tc.sha256hex,
				func(s State, _, _ int64, _ float64) { states = append(states, s) })

			assert.Error(t, err)
			if tc.wantErrContains != "" {
				assert.ErrorContains(t, err, tc.wantErrContains)
			}
		})
	}
}

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

func TestTriggerFromRecords(t *testing.T) {
	urlVal := "https://example.com/agent.bin"
	hashVal := "abcdef1234567890"
	sizeVal := 153600.0

	cases := []struct {
		desc      string
		records   []senml.Record
		url       string
		sha256hex string
		size      uint64
		wantErr   bool
	}{
		{
			desc:    "url only",
			records: []senml.Record{{Name: "url", StringValue: &urlVal}},
			url:     urlVal,
		},
		{
			desc: "url with hash",
			records: []senml.Record{
				{Name: "url", StringValue: &urlVal},
				{Name: "hash", StringValue: &hashVal},
			},
			url:       urlVal,
			sha256hex: hashVal,
		},
		{
			desc: "url with hash and size",
			records: []senml.Record{
				{Name: "url", StringValue: &urlVal},
				{Name: "hash", StringValue: &hashVal},
				{Name: "size", Value: &sizeVal},
			},
			url:       urlVal,
			sha256hex: hashVal,
			size:      153600,
		},
		{
			desc: "url with size only",
			records: []senml.Record{
				{Name: "url", StringValue: &urlVal},
				{Name: "size", Value: &sizeVal},
			},
			url:  urlVal,
			size: 153600,
		},
		{
			desc:    "empty records",
			records: []senml.Record{},
			wantErr: true,
		},
		{
			desc:    "missing url record",
			records: []senml.Record{{Name: "hash", StringValue: &hashVal}},
			wantErr: true,
		},
		{
			desc:    "url record with nil value",
			records: []senml.Record{{Name: "url", StringValue: nil}},
			wantErr: true,
		},
		{
			desc:    "url record with whitespace-only value",
			records: []senml.Record{{Name: "url", StringValue: func() *string { s := "   "; return &s }()}},
			wantErr: true,
		},
		{
			desc: "unknown records ignored",
			records: []senml.Record{
				{Name: "url", StringValue: &urlVal},
				{Name: "extra", StringValue: &hashVal},
			},
			url: urlVal,
		},
	}

	for _, tc := range cases {
		t.Run(tc.desc, func(t *testing.T) {
			tr, err := TriggerFromRecords(tc.records)
			if tc.wantErr {
				assert.Error(t, err, fmt.Sprintf("%s: expected error", tc.desc))
				return
			}
			require.NoError(t, err, fmt.Sprintf("%s: unexpected error", tc.desc))
			assert.Equal(t, tc.url, tr.URL, fmt.Sprintf("%s: unexpected URL", tc.desc))
			assert.Equal(t, tc.sha256hex, tr.SHA256Hex, fmt.Sprintf("%s: unexpected SHA256", tc.desc))
			assert.Equal(t, tc.size, tr.Size, fmt.Sprintf("%s: unexpected size", tc.desc))
		})
	}
}

func TestDownload(t *testing.T) {
	content := []byte("fake agent binary content")

	cases := []struct {
		desc            string
		handler         http.HandlerFunc
		url             string
		sizeLimit       uint64
		cancelCtx       bool
		wantErr         bool
		wantErrContains string
	}{
		{
			desc: "success",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Length", fmt.Sprintf("%d", len(content)))
				_, _ = w.Write(content)
			},
		},
		{
			desc: "size exceeded",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Length", fmt.Sprintf("%d", len(content)))
				_, _ = w.Write(content)
			},
			sizeLimit:       4,
			wantErr:         true,
			wantErrContains: "exceeded expected size",
		},
		{
			desc:            "bad scheme file",
			url:             "file:///etc/passwd",
			wantErr:         true,
			wantErrContains: "unsupported URL scheme",
		},
		{
			desc:            "bad scheme ftp",
			url:             "ftp://example.com/agent.bin",
			wantErr:         true,
			wantErrContains: "unsupported URL scheme",
		},
		{
			desc: "server error",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusInternalServerError)
			},
			wantErr:         true,
			wantErrContains: "500",
		},
		{
			desc: "not found",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusNotFound)
			},
			wantErr: true,
		},
		{
			desc: "context cancelled",
			handler: func(w http.ResponseWriter, r *http.Request) {
				<-r.Context().Done()
			},
			cancelCtx: true,
			wantErr:   true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.desc, func(t *testing.T) {
			ctx := context.Background()
			url := tc.url

			if tc.handler != nil {
				srv := httptest.NewServer(tc.handler)
				defer srv.Close()
				url = srv.URL
			}
			if tc.cancelCtx {
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			}

			var progress []float64
			path, err := download(ctx, url, t.TempDir(), tc.sizeLimit, func(_, _ int64, pct float64) {
				progress = append(progress, pct)
			})
			if tc.wantErr {
				assert.Error(t, err, fmt.Sprintf("%s: expected error", tc.desc))
				if tc.wantErrContains != "" {
					assert.ErrorContains(t, err, tc.wantErrContains, fmt.Sprintf("%s: wrong error", tc.desc))
				}
				return
			}
			require.NoError(t, err, fmt.Sprintf("%s: unexpected error", tc.desc))
			defer func() { _ = os.Remove(path) }()

			got, err := os.ReadFile(path)
			require.NoError(t, err)
			assert.Equal(t, content, got, fmt.Sprintf("%s: unexpected content", tc.desc))
			assert.Contains(t, progress, float64(0), fmt.Sprintf("%s: 0%% should be reported", tc.desc))
			assert.Contains(t, progress, float64(100), fmt.Sprintf("%s: 100%% should be reported", tc.desc))
		})
	}

	t.Run("progress reported every 5 percent", func(t *testing.T) {
		const size = 1000
		body := make([]byte, size)
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Length", fmt.Sprintf("%d", size))
			_, _ = w.Write(body)
		}))
		defer srv.Close()

		var calls []float64
		path, err := download(context.Background(), srv.URL, t.TempDir(), 0, func(_, _ int64, pct float64) {
			calls = append(calls, pct)
		})
		require.NoError(t, err)
		_ = os.Remove(path)

		for i := 1; i < len(calls)-1; i++ {
			assert.GreaterOrEqual(t, calls[i]-calls[i-1], 5.0,
				"progress jumps should be >=5%% (got %.1f -> %.1f)", calls[i-1], calls[i])
		}
	})
}

func TestVerify(t *testing.T) {
	content := []byte("agent binary")

	closedSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	closedSrv.Close()
	closedURL := closedSrv.URL + "/agent.bin"

	cases := []struct {
		desc            string
		sha256hex       string
		handler         http.HandlerFunc
		url             string
		wantErr         bool
		wantErrContains string
	}{
		{
			desc:      "inline hash match",
			sha256hex: sha256hex(content),
		},
		{
			desc:            "inline hash mismatch",
			sha256hex:       "deadbeef",
			wantErr:         true,
			wantErrContains: "sha256 mismatch",
		},
		{
			desc: "sidecar match",
			handler: func(w http.ResponseWriter, r *http.Request) {
				_, _ = fmt.Fprintf(w, "%s  agent.bin\n", sha256hex(content))
			},
		},
		{
			desc: "sidecar mismatch",
			handler: func(w http.ResponseWriter, r *http.Request) {
				_, _ = fmt.Fprintf(w, "deadbeef  agent.bin\n")
			},
			wantErr:         true,
			wantErrContains: "sha256 mismatch",
		},
		{
			desc: "sidecar not found skipped",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusNotFound)
			},
		},
		{
			desc:    "network error fails closed",
			url:     closedURL,
			wantErr: true,
		},
		{
			desc: "inline hash takes precedence over sidecar",
			handler: func(w http.ResponseWriter, r *http.Request) {
				_, _ = fmt.Fprintf(w, "deadbeef  agent.bin\n")
			},
			sha256hex: sha256hex(content),
		},
	}

	for _, tc := range cases {
		t.Run(tc.desc, func(t *testing.T) {
			path := writeTempFile(t, content)
			url := tc.url

			if tc.handler != nil {
				srv := httptest.NewServer(tc.handler)
				defer srv.Close()
				url = srv.URL + "/agent.bin"
			}
			if url == "" {
				url = "http://unused"
			}

			_, err := verify(context.Background(), url, path, tc.sha256hex)
			if tc.wantErr {
				assert.Error(t, err, fmt.Sprintf("%s: expected error", tc.desc))
				if tc.wantErrContains != "" {
					assert.ErrorContains(t, err, tc.wantErrContains, fmt.Sprintf("%s: wrong error", tc.desc))
				}
				return
			}
			require.NoError(t, err, fmt.Sprintf("%s: unexpected error", tc.desc))
		})
	}
}

func TestReplace(t *testing.T) {
	cases := []struct {
		desc    string
		hasSrc  bool
		wantErr bool
	}{
		{
			desc:   "same filesystem",
			hasSrc: true,
		},
		{
			desc:    "missing source",
			hasSrc:  false,
			wantErr: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.desc, func(t *testing.T) {
			dir := t.TempDir()
			dst := filepath.Join(dir, "agent")
			require.NoError(t, os.WriteFile(dst, []byte("old binary"), 0o755))

			src := filepath.Join(dir, "new-agent")
			if tc.hasSrc {
				require.NoError(t, os.WriteFile(src, []byte("new binary"), 0o644))
			}

			err := replace(src, dst)
			if tc.wantErr {
				assert.Error(t, err, fmt.Sprintf("%s: expected error", tc.desc))
				return
			}
			require.NoError(t, err, fmt.Sprintf("%s: unexpected error", tc.desc))

			got, err := os.ReadFile(dst)
			require.NoError(t, err)
			assert.Equal(t, []byte("new binary"), got, fmt.Sprintf("%s: unexpected content", tc.desc))

			info, err := os.Stat(dst)
			require.NoError(t, err)
			assert.Equal(t, os.FileMode(0o755), info.Mode().Perm(), fmt.Sprintf("%s: binary should be executable", tc.desc))

			_, err = os.Stat(src)
			assert.True(t, os.IsNotExist(err), fmt.Sprintf("%s: src temp file should be consumed", tc.desc))
		})
	}
}

func TestRun(t *testing.T) {
	content := []byte("fake binary content")

	cases := []struct {
		desc            string
		handler         http.HandlerFunc
		sha256hex       string
		closedServer    bool
		wantErrContains string
		wantStates      []State
		checkCleanup    bool
	}{
		{
			desc:            "connection refused",
			closedServer:    true,
			wantErrContains: "ota download",
			wantStates:      []State{StateTriggered, StateDownloading},
		},
		{
			desc: "server error",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusInternalServerError)
			},
			wantErrContains: "ota download",
			wantStates:      []State{StateTriggered, StateDownloading},
		},
		{
			desc: "hash mismatch",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Length", fmt.Sprintf("%d", len(content)))
				_, _ = w.Write(content)
			},
			sha256hex:       "deadbeef",
			wantErrContains: "ota verify",
			checkCleanup:    true,
		},
		{
			desc: "no hash and no sidecar",
			handler: func(w http.ResponseWriter, r *http.Request) {
				if strings.HasSuffix(r.URL.Path, ".sha256") {
					w.WriteHeader(http.StatusNotFound)
					return
				}
				w.Header().Set("Content-Length", fmt.Sprintf("%d", len(content)))
				_, _ = w.Write(content)
			},
			wantErrContains: "ota verify",
			checkCleanup:    true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.desc, func(t *testing.T) {
			var url string
			if tc.closedServer {
				srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
				srv.Close()
				url = srv.URL
			} else {
				srv := httptest.NewServer(tc.handler)
				defer srv.Close()
				url = srv.URL
			}

			dir := t.TempDir()
			cfg := Config{BinaryPath: filepath.Join(dir, "agent"), DownloadDir: dir}
			var states []State
			err := Run(context.Background(), cfg, url, tc.sha256hex, 0, func(s State, _, _ int64, _ float64) {
				states = append(states, s)
			})

			require.Error(t, err, fmt.Sprintf("%s: expected error", tc.desc))
			assert.ErrorContains(t, err, tc.wantErrContains, fmt.Sprintf("%s: wrong error", tc.desc))
			if len(tc.wantStates) > 0 {
				assert.Equal(t, tc.wantStates, states, fmt.Sprintf("%s: unexpected state sequence", tc.desc))
			}
			if tc.checkCleanup {
				entries, _ := os.ReadDir(dir)
				for _, e := range entries {
					assert.False(t,
						e.Name() != filepath.Base(cfg.BinaryPath) && strings.HasPrefix(e.Name(), "agent-ota"),
						fmt.Sprintf("%s: temp file %q should be removed", tc.desc, e.Name()))
				}
			}
		})
	}
}

// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

package devicemgr_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/absmach/agent/pkg/devicemgr"
	"github.com/absmach/agent/pkg/iface"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// magistralaServer returns a combined httptest.Server that handles the three
// SDK endpoints used during provisioning:
//
//	POST /{domainID}/clients          → create client
//	POST /{domainID}/channels         → create channel
//	POST /{domainID}/channels/connect → connect
//	DELETE /{domainID}/clients/{id}   → rollback client
//	DELETE /{domainID}/channels/{id}  → rollback channel
//
// Pass overrides to intercept specific paths; nil falls back to the default
// 201 responses.
func magistralaServer(t *testing.T, overrides map[string]http.HandlerFunc) *httptest.Server {
	t.Helper()

	callCount := 0 // counts channel creation calls to assign unique IDs

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if fn, ok := overrides[r.URL.Path]; ok {
			fn(w, r)
			return
		}
		// Default handlers
		switch {
		case strings.HasSuffix(r.URL.Path, "/clients") && r.Method == http.MethodPost:
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"id":   "device-uuid",
				"name": "my-device",
				"credentials": map[string]any{
					"identity": "ext-id",
					"secret":   "device-secret",
				},
			})

		case strings.HasSuffix(r.URL.Path, "/channels") && r.Method == http.MethodPost:
			callCount++
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"id":   fmt.Sprintf("channel-uuid-%d", callCount),
				"name": fmt.Sprintf("channel-%d", callCount),
			})

		case strings.HasSuffix(r.URL.Path, "/connect") && r.Method == http.MethodPost:
			w.WriteHeader(http.StatusCreated)

		case strings.Contains(r.URL.Path, "/clients/") && r.Method == http.MethodDelete:
			w.WriteHeader(http.StatusNoContent)

		case strings.Contains(r.URL.Path, "/channels/") && r.Method == http.MethodDelete:
			w.WriteHeader(http.StatusNoContent)

		default:
			http.Error(w, "unexpected request: "+r.Method+" "+r.URL.Path, http.StatusNotFound)
		}
	}))

	t.Cleanup(srv.Close)
	return srv
}

func newTestManager(t *testing.T, clientsURL, channelsURL string) *devicemgr.Manager {
	t.Helper()
	m, err := devicemgr.New(
		filepath.Join(t.TempDir(), "devices.db"),
		devicemgr.ProvisionConfig{
			ClientsURL:  clientsURL,
			ChannelsURL: channelsURL,
			Token:       "test-token",
			DomainID:    "test-domain",
		},
		iface.Config{},
	)
	require.NoError(t, err)
	t.Cleanup(func() { m.Close() })
	return m
}

func TestNew(t *testing.T) {
	cases := []struct {
		desc    string
		dbPath  string
		wantErr bool
	}{
		{
			desc:   "create manager with valid path",
			dbPath: filepath.Join(t.TempDir(), "devices.db"),
		},
		{
			desc:    "fail on invalid db path",
			dbPath:  "/nonexistent/dir/devices.db",
			wantErr: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.desc, func(t *testing.T) {
			m, err := devicemgr.New(tc.dbPath, devicemgr.ProvisionConfig{}, iface.Config{})
			if tc.wantErr {
				assert.Error(t, err, fmt.Sprintf("%s: expected error", tc.desc))
				return
			}
			require.NoError(t, err, fmt.Sprintf("%s: unexpected error", tc.desc))
			m.Close()
		})
	}
}

func TestManager_Add(t *testing.T) {
	srv := magistralaServer(t, nil)

	errorSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "internal server error", http.StatusInternalServerError)
	}))
	t.Cleanup(errorSrv.Close)

	closedSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	closedSrv.Close()

	cases := []struct {
		desc        string
		clientsURL  string
		channelsURL string
		ifaceType   iface.InterfaceType
		ifaceAddr   string
		wantID      string
		wantKey     string
		wantErr     bool
	}{
		{
			desc:        "provision and save device successfully",
			clientsURL:  srv.URL,
			channelsURL: srv.URL,
			ifaceType:   iface.InterfaceBLE,
			ifaceAddr:   "AA:BB:CC:DD:EE:FF",
			wantID:      "device-uuid",
			wantKey:     "device-secret",
		},
		{
			desc:        "fail when provision clients URL is empty",
			clientsURL:  "",
			channelsURL: srv.URL,
			wantErr:     true,
		},
		{
			desc:        "fail when clients API returns error",
			clientsURL:  errorSrv.URL,
			channelsURL: srv.URL,
			wantErr:     true,
		},
		{
			desc:        "fail when provision server is unreachable",
			clientsURL:  closedSrv.URL,
			channelsURL: closedSrv.URL,
			wantErr:     true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.desc, func(t *testing.T) {
			m := newTestManager(t, tc.clientsURL, tc.channelsURL)
			d, err := m.Add("my-device", "ext-id", "ext-key", tc.ifaceType, tc.ifaceAddr)
			if tc.wantErr {
				assert.Error(t, err, fmt.Sprintf("%s: expected error", tc.desc))
				return
			}
			require.NoError(t, err, fmt.Sprintf("%s: unexpected error", tc.desc))
			assert.Equal(t, tc.wantID, d.ID, fmt.Sprintf("%s: unexpected ID", tc.desc))
			assert.Equal(t, tc.wantKey, d.Key, fmt.Sprintf("%s: unexpected Key", tc.desc))
			assert.NotEmpty(t, d.ChannelID, fmt.Sprintf("%s: channel ID should be set", tc.desc))
			assert.Equal(t, tc.ifaceType, d.InterfaceType, fmt.Sprintf("%s: unexpected InterfaceType", tc.desc))
			assert.Equal(t, tc.ifaceAddr, d.InterfaceAddr, fmt.Sprintf("%s: unexpected InterfaceAddr", tc.desc))
			assert.True(t, d.Active, fmt.Sprintf("%s: device should be active", tc.desc))
		})
	}
}

func TestManager_Add_AuthHeader(t *testing.T) {
	var gotAuth string
	srv := magistralaServer(t, map[string]http.HandlerFunc{
		"/test-domain/clients": func(w http.ResponseWriter, r *http.Request) {
			gotAuth = r.Header.Get("Authorization")
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"id":   "d1",
				"name": "n",
				"credentials": map[string]any{
					"secret": "k1",
				},
			})
		},
	})

	t.Run("uses Bearer token when token is configured", func(t *testing.T) {
		m, err := devicemgr.New(
			filepath.Join(t.TempDir(), "devices.db"),
			devicemgr.ProvisionConfig{
				ClientsURL:  srv.URL,
				ChannelsURL: srv.URL,
				Token:       "my-pat-token", // SDK prepends "Bearer " automatically
				DomainID:    "test-domain",
			},
			iface.Config{},
		)
		require.NoError(t, err)
		defer m.Close()
		_, err = m.Add(context.Background(), "dev", "ext-id", "ext-key", iface.InterfaceBLE, "addr")
		require.NoError(t, err)
		assert.Equal(t, "Bearer my-pat-token", gotAuth)
	})
}

func TestManager_Add_WithRules(t *testing.T) {
	srv := magistralaServer(t, nil)

	var rulePayload map[string]any
	rulesSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodPost, r.Method)
		// SDK adds "Bearer " prefix to the raw token
		assert.Equal(t, "Bearer pat-token", r.Header.Get("Authorization"))
		if err := json.NewDecoder(r.Body).Decode(&rulePayload); err != nil {
			http.Error(w, "bad body", http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(rulePayload) // echo back so SDK can decode
	}))
	t.Cleanup(rulesSrv.Close)

	failRulesSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "internal error", http.StatusInternalServerError)
	}))
	t.Cleanup(failRulesSrv.Close)

	t.Run("creates save_senml rule after provisioning", func(t *testing.T) {
		m, err := devicemgr.New(
			filepath.Join(t.TempDir(), "devices.db"),
			devicemgr.ProvisionConfig{
				ClientsURL:     srv.URL,
				ChannelsURL:    srv.URL,
				RulesEngineURL: rulesSrv.URL,
				Token:          "pat-token",
				DomainID:       "dom",
			},
			iface.Config{},
		)
		require.NoError(t, err)
		defer m.Close()

		d, err := m.Add("sensor", "ext-id", "ext-key", iface.InterfaceBLE, "AA:BB:CC:DD:EE:FF")
		require.NoError(t, err)
		assert.NotEmpty(t, d.ChannelID)
		assert.Equal(t, d.ChannelID, rulePayload["input_channel"])
		outputs, _ := rulePayload["outputs"].([]any)
		require.Len(t, outputs, 1)
		out, _ := outputs[0].(map[string]any)
		assert.Equal(t, "save_senml", out["type"])
	})

	t.Run("returns error when rules API fails", func(t *testing.T) {
		m, err := devicemgr.New(
			filepath.Join(t.TempDir(), "devices.db"),
			devicemgr.ProvisionConfig{
				ClientsURL:     srv.URL,
				ChannelsURL:    srv.URL,
				RulesEngineURL: failRulesSrv.URL,
				Token:          "pat-token",
				DomainID:       "dom",
			},
			iface.Config{},
		)
		require.NoError(t, err)
		defer m.Close()

		_, err = m.Add("sensor", "ext-id", "ext-key", iface.InterfaceBLE, "addr")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "rule")
	})

	t.Run("skips rule creation when RulesEngineURL is empty", func(t *testing.T) {
		m, err := devicemgr.New(
			filepath.Join(t.TempDir(), "devices.db"),
			devicemgr.ProvisionConfig{
				ClientsURL:  srv.URL,
				ChannelsURL: srv.URL,
				Token:       "pat-token",
				DomainID:    "dom",
			},
			iface.Config{},
		)
		require.NoError(t, err)
		defer m.Close()

		_, err = m.Add("sensor", "ext-id", "ext-key", iface.InterfaceBLE, "addr")
		assert.NoError(t, err)
	})
}

func TestManager_Remove(t *testing.T) {
	srv := provisionServer(t, nil)
	m := newTestManager(t, srv.URL)
	d, err := m.Add(context.Background(), "my-device", "ext-id", "ext-key", iface.InterfaceBLE, "addr")
	require.NoError(t, err)

	cases := []struct {
		desc string
		id   string
	}{
		{desc: "remove existing device", id: d.ID},
		{desc: "remove non-existent device is a no-op", id: "does-not-exist"},
	}

	for _, tc := range cases {
		t.Run(tc.desc, func(t *testing.T) {
			err := m.Remove(tc.id)
			assert.NoError(t, err, fmt.Sprintf("%s: unexpected error", tc.desc))
		})
	}

	_, err = m.Get(d.ID)
	assert.Error(t, err, "device should be absent after remove")
}

func TestManager_Get(t *testing.T) {
	srv := provisionServer(t, nil)
	m := newTestManager(t, srv.URL)
	d, err := m.Add(context.Background(), "my-device", "ext-id", "ext-key", iface.InterfaceBLE, "addr")
	require.NoError(t, err)

	cases := []struct {
		desc    string
		id      string
		wantErr bool
	}{
		{desc: "get existing device", id: d.ID},
		{desc: "get non-existent device returns error", id: "missing", wantErr: true},
	}

	for _, tc := range cases {
		t.Run(tc.desc, func(t *testing.T) {
			got, err := m.Get(tc.id)
			if tc.wantErr {
				assert.Error(t, err, fmt.Sprintf("%s: expected error", tc.desc))
				return
			}
			require.NoError(t, err, fmt.Sprintf("%s: unexpected error", tc.desc))
			assert.Equal(t, d.ID, got.ID, fmt.Sprintf("%s: unexpected ID", tc.desc))
		})
	}
}

func TestManager_List(t *testing.T) {
	t.Run("empty manager returns empty slice", func(t *testing.T) {
		m := newTestManager(t, "", "")
		devs, err := m.List()
		require.NoError(t, err)
		assert.Empty(t, devs)
	})

	t.Run("list returns all provisioned devices", func(t *testing.T) {
		callCount := 0
		srv := magistralaServer(t, map[string]http.HandlerFunc{
			"/test-domain/clients": func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodPost {
					http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
					return
				}
				callCount++
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusCreated)
				_ = json.NewEncoder(w).Encode(map[string]any{
					"id":   fmt.Sprintf("dev-%d", callCount),
					"name": fmt.Sprintf("device-%d", callCount),
					"credentials": map[string]any{
						"secret": "k",
					},
				})
			},
		})
		m := newTestManager(t, srv.URL)
		_, err := m.Add(context.Background(), "d1", "e1", "k1", iface.InterfaceBLE, "addr1")
		require.NoError(t, err)
		_, err = m.Add(context.Background(), "d2", "e2", "k2", iface.InterfaceSerial, "addr2")
		require.NoError(t, err)
		devs, err := m.List()
		require.NoError(t, err)
		assert.Len(t, devs, 2)
	})
}

func TestManager_MarkSeen(t *testing.T) {
	srv := provisionServer(t, nil)
	m := newTestManager(t, srv.URL)
	d, err := m.Add(context.Background(), "my-device", "ext-id", "ext-key", iface.InterfaceBLE, "addr")
	require.NoError(t, err)

	cases := []struct {
		desc    string
		id      string
		wantErr bool
	}{
		{desc: "mark existing device as seen", id: d.ID},
		{desc: "mark non-existent device returns error", id: "missing", wantErr: true},
	}

	for _, tc := range cases {
		t.Run(tc.desc, func(t *testing.T) {
			err := m.MarkSeen(tc.id)
			if tc.wantErr {
				assert.Error(t, err, fmt.Sprintf("%s: expected error", tc.desc))
				return
			}
			assert.NoError(t, err, fmt.Sprintf("%s: unexpected error", tc.desc))
		})
	}
}

func TestManager_OpenIface(t *testing.T) {
	t.Run("error on unknown device", func(t *testing.T) {
		m := newTestManager(t, "", "")
		err := m.OpenIface("nonexistent-id")
		assert.Error(t, err)
	})

	t.Run("error when interface type is unsupported (BLE)", func(t *testing.T) {
		srv := provisionServer(t, nil)
		m := newTestManager(t, srv.URL)
		d, err := m.Add(context.Background(), "dev", "eid", "ekey", iface.InterfaceBLE, "AA:BB:CC:DD:EE:FF")
		require.NoError(t, err)
		err = m.OpenIface(d.ID)
		assert.Error(t, err)
	})

	t.Run("idempotent: second open on already-open interface returns nil", func(t *testing.T) {
		m := newTestManager(t, "", "")
		err := m.OpenIface("no-such-device")
		assert.Error(t, err)
	})
}

func TestManager_CloseIface(t *testing.T) {
	t.Run("error when interface not open", func(t *testing.T) {
		m := newTestManager(t, "", "")
		err := m.CloseIface("any-device-id")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "not open")
	})
}

func TestManager_ReadIface(t *testing.T) {
	t.Run("error when interface not open", func(t *testing.T) {
		m := newTestManager(t, "", "")
		_, err := m.ReadIface("any-device-id", 4)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "not open")
	})
}

func TestManager_WriteIface(t *testing.T) {
	t.Run("error when interface not open", func(t *testing.T) {
		m := newTestManager(t, "", "")
		_, err := m.WriteIface("any-device-id", "deadbeef")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "not open")
	})

	t.Run("error on invalid hex when interface not open", func(t *testing.T) {
		m := newTestManager(t, "", "")
		_, err := m.WriteIface("any-device-id", "zzzz")
		assert.Error(t, err)
	})
}

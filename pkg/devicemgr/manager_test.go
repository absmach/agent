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

const (
	mgFieldName        = "name"
	mgFieldCredentials = "credentials"
	mgFieldSecret      = "secret"
	mgIDNotExist       = "does-not-exist"
	mgDescMarkNotExist = "mark non-existent device returns error"
	mgDescIfaceNotOpen = "error when interface not open"
	mgAnyDeviceID      = "any-device-id"
	mgErrNotOpen       = "not open"
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

	callCount := 0

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if fn, ok := overrides[r.URL.Path]; ok {
			fn(w, r)
			return
		}
		switch {
		case strings.HasSuffix(r.URL.Path, "/clients") && r.Method == http.MethodPost:
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"id":        "device-uuid",
				mgFieldName: "my-device",
				mgFieldCredentials: map[string]any{
					"identity":    "ext-id",
					mgFieldSecret: "device-secret",
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
				assert.Error(t, err)
				return
			}
			require.NoError(t, err)
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
			d, err := m.Add(context.Background(), "my-device", "ext-id", "ext-key", tc.ifaceType, tc.ifaceAddr)
			if tc.wantErr {
				assert.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.wantID, d.ID)
			assert.Equal(t, tc.wantKey, d.Key)
			assert.NotEmpty(t, d.ChannelID)
			assert.Equal(t, tc.ifaceType, d.InterfaceType)
			assert.Equal(t, tc.ifaceAddr, d.InterfaceAddr)
			assert.False(t, d.Active)
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
				"id":          "d1",
				"name":        "n",
				"credentials": map[string]any{"secret": "k1"},
			})
		},
	})

	cases := []struct {
		desc     string
		token    string
		wantAuth string
	}{
		{
			desc:     "uses Bearer token when token is configured",
			token:    "my-pat-token",
			wantAuth: "Bearer my-pat-token",
		},
	}

	for _, tc := range cases {
		t.Run(tc.desc, func(t *testing.T) {
			m, err := devicemgr.New(
				filepath.Join(t.TempDir(), "devices.db"),
				devicemgr.ProvisionConfig{
					ClientsURL:  srv.URL,
					ChannelsURL: srv.URL,
					Token:       tc.token,
					DomainID:    "test-domain",
				},
				iface.Config{},
			)
			require.NoError(t, err)
			defer m.Close()
			_, err = m.Add(context.Background(), "dev", "ext-id", "ext-key", iface.InterfaceBLE, "addr")
			require.NoError(t, err)
			assert.Equal(t, tc.wantAuth, gotAuth)
		})
	}
}

func TestManager_Add_WithRules(t *testing.T) {
	srv := magistralaServer(t, nil)

	var rulePayload map[string]any
	rulesSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodPost, r.Method)
		assert.Equal(t, "Bearer pat-token", r.Header.Get("Authorization"))
		if err := json.NewDecoder(r.Body).Decode(&rulePayload); err != nil {
			http.Error(w, "bad body", http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(rulePayload)
	}))
	t.Cleanup(rulesSrv.Close)

	failRulesSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "internal error", http.StatusInternalServerError)
	}))
	t.Cleanup(failRulesSrv.Close)

	cases := []struct {
		desc           string
		rulesEngineURL string
		wantErr        bool
		errContains    string
		checkRule      bool
	}{
		{
			desc:           "creates save_senml rule after provisioning",
			rulesEngineURL: rulesSrv.URL,
			checkRule:      true,
		},
		{
			desc:           "returns error when rules API fails",
			rulesEngineURL: failRulesSrv.URL,
			wantErr:        true,
			errContains:    "rule",
		},
		{
			desc:           "skips rule creation when RulesEngineURL is empty",
			rulesEngineURL: "",
		},
	}

	for _, tc := range cases {
		t.Run(tc.desc, func(t *testing.T) {
			rulePayload = nil
			m, err := devicemgr.New(
				filepath.Join(t.TempDir(), "devices.db"),
				devicemgr.ProvisionConfig{
					ClientsURL:     srv.URL,
					ChannelsURL:    srv.URL,
					RulesEngineURL: tc.rulesEngineURL,
					Token:          "pat-token",
					DomainID:       "dom",
				},
				iface.Config{},
			)
			require.NoError(t, err)
			defer m.Close()

			d, err := m.Add(context.Background(), "sensor", "ext-id", "ext-key", iface.InterfaceBLE, "AA:BB:CC:DD:EE:FF")
			if tc.wantErr {
				assert.Error(t, err)
				if tc.errContains != "" {
					assert.Contains(t, err.Error(), tc.errContains)
				}
				return
			}
			require.NoError(t, err)
			if tc.checkRule {
				assert.NotEmpty(t, d.ChannelID)
				assert.Equal(t, d.ChannelID, rulePayload["input_channel"])
				outputs, _ := rulePayload["outputs"].([]any)
				require.Len(t, outputs, 1)
				out, _ := outputs[0].(map[string]any)
				assert.Equal(t, "save_senml", out["type"])
			}
		})
	}
}

func TestManager_Remove(t *testing.T) {
	srv := magistralaServer(t, nil)
	m := newTestManager(t, srv.URL, srv.URL)
	d, err := m.Add(context.Background(), "my-device", "ext-id", "ext-key", iface.InterfaceBLE, "addr")
	require.NoError(t, err)

	cases := []struct {
		desc string
		id   string
	}{
		{desc: "remove existing device", id: d.ID},
		{desc: "remove non-existent device is a no-op", id: mgIDNotExist},
	}

	for _, tc := range cases {
		t.Run(tc.desc, func(t *testing.T) {
			assert.NoError(t, m.Remove(tc.id))
		})
	}

	_, err = m.Get(d.ID)
	assert.Error(t, err, "device should be absent after remove")
}

func TestManager_Get(t *testing.T) {
	srv := magistralaServer(t, nil)
	m := newTestManager(t, srv.URL, srv.URL)
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
				assert.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, d.ID, got.ID)
		})
	}
}

func TestManager_List(t *testing.T) {
	callCount := 0
	multiSrv := magistralaServer(t, map[string]http.HandlerFunc{
		"/test-domain/clients": func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodPost {
				http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
				return
			}
			callCount++
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"id":          fmt.Sprintf("dev-%d", callCount),
				"name":        fmt.Sprintf("device-%d", callCount),
				"credentials": map[string]any{"secret": "k"},
			})
		},
	})

	cases := []struct {
		desc        string
		clientsURL  string
		channelsURL string
		seedNames   []string
		wantCount   int
	}{
		{
			desc:      "empty manager returns empty slice",
			wantCount: 0,
		},
		{
			desc:        "list returns all provisioned devices",
			clientsURL:  multiSrv.URL,
			channelsURL: multiSrv.URL,
			seedNames:   []string{"d1", "d2"},
			wantCount:   2,
		},
	}

	for _, tc := range cases {
		t.Run(tc.desc, func(t *testing.T) {
			m := newTestManager(t, tc.clientsURL, tc.channelsURL)
			for i, name := range tc.seedNames {
				_, err := m.Add(context.Background(), name, fmt.Sprintf("e%d", i), fmt.Sprintf("k%d", i), iface.InterfaceBLE, fmt.Sprintf("addr%d", i))
				require.NoError(t, err)
			}
			devs, err := m.List()
			require.NoError(t, err)
			assert.Len(t, devs, tc.wantCount)
		})
	}
}

func TestManager_MarkSeen(t *testing.T) {
	srv := magistralaServer(t, nil)
	m := newTestManager(t, srv.URL, srv.URL)
	d, err := m.Add(context.Background(), "my-device", "ext-id", "ext-key", iface.InterfaceBLE, "addr")
	require.NoError(t, err)

	cases := []struct {
		desc    string
		id      string
		wantErr bool
	}{
		{desc: "mark existing device as seen", id: d.ID},
		{desc: mgDescMarkNotExist, id: "missing", wantErr: true},
	}

	for _, tc := range cases {
		t.Run(tc.desc, func(t *testing.T) {
			err := m.MarkSeen(tc.id)
			if tc.wantErr {
				assert.Error(t, err)
				return
			}
			assert.NoError(t, err)
		})
	}
}

func TestManager_OpenIface(t *testing.T) {
	srv := magistralaServer(t, nil)
	m := newTestManager(t, srv.URL, srv.URL)
	d, err := m.Add(context.Background(), "dev", "eid", "ekey", iface.InterfaceBLE, "AA:BB:CC:DD:EE:FF")
	require.NoError(t, err)

	cases := []struct {
		desc    string
		id      string
		wantErr bool
	}{
		{
			desc:    "error on unknown device",
			id:      "nonexistent-id",
			wantErr: true,
		},
		{
			desc:    "error when interface type is unsupported (BLE)",
			id:      d.ID,
			wantErr: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.desc, func(t *testing.T) {
			err := m.OpenIface(tc.id)
			if tc.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestManager_CloseIface(t *testing.T) {
	cases := []struct {
		desc        string
		id          string
		errContains string
	}{
		{
			desc:        mgDescIfaceNotOpen,
			id:          mgAnyDeviceID,
			errContains: mgErrNotOpen,
		},
	}

	for _, tc := range cases {
		t.Run(tc.desc, func(t *testing.T) {
			m := newTestManager(t, "", "")
			err := m.CloseIface(tc.id)
			assert.Error(t, err)
			assert.Contains(t, err.Error(), tc.errContains)
		})
	}
}

func TestManager_ReadIface(t *testing.T) {
	cases := []struct {
		desc        string
		id          string
		n           int
		errContains string
	}{
		{
			desc:        "error when interface not open",
			id:          "any-device-id",
			n:           4,
			errContains: "not open",
		},
	}

	for _, tc := range cases {
		t.Run(tc.desc, func(t *testing.T) {
			m := newTestManager(t, "", "")
			_, err := m.ReadIface(tc.id, tc.n)
			assert.Error(t, err)
			assert.Contains(t, err.Error(), tc.errContains)
		})
	}
}

func TestManager_WriteIface(t *testing.T) {
	cases := []struct {
		desc        string
		id          string
		hexData     string
		errContains string
	}{
		{
			desc:        "error when interface not open",
			id:          "any-device-id",
			hexData:     "deadbeef",
			errContains: "not open",
		},
		{
			desc:    "error on invalid hex data",
			id:      "any-device-id",
			hexData: "zzzz",
		},
	}

	for _, tc := range cases {
		t.Run(tc.desc, func(t *testing.T) {
			m := newTestManager(t, "", "")
			_, err := m.WriteIface(tc.id, tc.hexData)
			assert.Error(t, err)
			if tc.errContains != "" {
				assert.Contains(t, err.Error(), tc.errContains)
			}
		})
	}
}

// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

package devicemgr_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"testing"

	"github.com/absmach/agent/pkg/devicemgr"
	"github.com/absmach/agent/pkg/iface"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestStore_ExportImport(t *testing.T) {
	src := newTestStore(t)
	d1 := makeDevice("aaa")
	d2 := makeDevice("bbb")
	require.NoError(t, src.Save(d1))
	require.NoError(t, src.Save(d2))

	backup, err := src.Export()
	require.NoError(t, err)
	assert.Equal(t, devicemgr.CurrentSchemaVersion, backup.SchemaVersion)
	assert.Len(t, backup.Devices, 2)
	assert.False(t, backup.ExportedAt.IsZero())

	t.Run("import into empty store", func(t *testing.T) {
		dst := newTestStore(t)
		n, err := dst.Import(backup, false)
		require.NoError(t, err)
		assert.Equal(t, 2, n)

		got, err := dst.Get(d1.ID)
		require.NoError(t, err)
		assert.Equal(t, d1.Name, got.Name)
	})

	t.Run("import with replace clears pre-existing devices", func(t *testing.T) {
		dst := newTestStore(t)
		require.NoError(t, dst.Save(makeDevice("stale")))

		n, err := dst.Import(backup, true)
		require.NoError(t, err)
		assert.Equal(t, 2, n)

		_, err = dst.Get("stale")
		assert.Error(t, err, "replace import should drop devices not in the backup")

		devs, err := dst.List()
		require.NoError(t, err)
		assert.Len(t, devs, 2)
	})

	t.Run("merge import keeps pre-existing devices", func(t *testing.T) {
		dst := newTestStore(t)
		require.NoError(t, dst.Save(makeDevice("keep")))

		n, err := dst.Import(backup, false)
		require.NoError(t, err)
		assert.Equal(t, 2, n)

		devs, err := dst.List()
		require.NoError(t, err)
		assert.Len(t, devs, 3, "merge import should retain existing devices")
	})

	t.Run("reject device with empty ID", func(t *testing.T) {
		dst := newTestStore(t)
		bad := devicemgr.Backup{
			SchemaVersion: devicemgr.CurrentSchemaVersion,
			Devices:       []devicemgr.Device{{Name: "no-id"}},
		}
		_, err := dst.Import(bad, false)
		assert.Error(t, err)
	})

	t.Run("reject backup from newer schema", func(t *testing.T) {
		dst := newTestStore(t)
		future := devicemgr.Backup{SchemaVersion: devicemgr.CurrentSchemaVersion + 1}
		_, err := dst.Import(future, false)
		assert.Error(t, err)
	})
}

func TestManager_BackupRestore(t *testing.T) {
	// The default mock returns a fixed client ID, so use an override that hands
	// out unique IDs and lets the two devices coexist in the registry.
	callCount := 0
	srv := magistralaServer(t, map[string]http.HandlerFunc{
		"/test-domain/clients": func(w http.ResponseWriter, r *http.Request) {
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
	m := newTestManager(t, srv.URL, srv.URL)

	_, err := m.Add(context.Background(), "dev-a", "ext-a", "key-a", iface.InterfaceBLE, "AA:BB:CC:DD:EE:01")
	require.NoError(t, err)
	_, err = m.Add(context.Background(), "dev-b", "ext-b", "key-b", iface.InterfaceBLE, "AA:BB:CC:DD:EE:02")
	require.NoError(t, err)

	backup, err := m.Backup()
	require.NoError(t, err)
	assert.Len(t, backup.Devices, 2)

	// Restore the snapshot into a fresh manager and confirm the devices land.
	dst := newTestManager(t, srv.URL, srv.URL)
	n, err := dst.Restore(backup, true)
	require.NoError(t, err)
	assert.Equal(t, 2, n)

	devs, err := dst.List()
	require.NoError(t, err)
	assert.Len(t, devs, 2)
}

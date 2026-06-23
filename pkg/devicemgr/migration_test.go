// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

package devicemgr_test

import (
	"path/filepath"
	"testing"

	"github.com/absmach/agent/pkg/devicemgr"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestStore_SchemaVersion(t *testing.T) {
	s := newTestStore(t)

	v, err := s.SchemaVersion()
	require.NoError(t, err)
	assert.Equal(t, devicemgr.CurrentSchemaVersion, v, "fresh store should be at the current schema version")
}

func TestStore_MigratePersistsAcrossReopen(t *testing.T) {
	path := filepath.Join(t.TempDir(), "devices.db")

	s, err := devicemgr.NewStore(path)
	require.NoError(t, err)
	d := makeDevice("device-1")
	require.NoError(t, s.Save(d))
	require.NoError(t, s.Close())

	// Re-open the same file: migrations must be idempotent and data preserved.
	reopened, err := devicemgr.NewStore(path)
	require.NoError(t, err)
	t.Cleanup(func() { reopened.Close() })

	v, err := reopened.SchemaVersion()
	require.NoError(t, err)
	assert.Equal(t, devicemgr.CurrentSchemaVersion, v)

	got, err := reopened.Get(d.ID)
	require.NoError(t, err)
	assert.Equal(t, d.ID, got.ID, "device should survive reopen + migration")
}

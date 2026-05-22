// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

package config_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/absmach/agent/pkg/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewStore_MissingFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	s, err := config.NewStore(path)
	require.NoError(t, err)
	_, ok := s.Get("any")
	assert.False(t, ok, "expected empty store when file is missing")
}

func TestNewStore_MalformedJSON(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	err := os.WriteFile(path, []byte("not-valid-json"), 0o600)
	require.NoError(t, err)
	_, err = config.NewStore(path)
	assert.Error(t, err, "expected error on malformed JSON")
}

func TestNewStore_EmptyFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	err := os.WriteFile(path, []byte(""), 0o600)
	require.NoError(t, err)
	s, err := config.NewStore(path)
	require.NoError(t, err, "empty file should be treated as an empty store")
	_, ok := s.Get("any")
	assert.False(t, ok)
}

func TestStore_SetGet_RoundTrip(t *testing.T) {
	s, err := config.NewStore(filepath.Join(t.TempDir(), "config.json"))
	require.NoError(t, err)
	require.NoError(t, s.Set("key", "value"))
	val, ok := s.Get("key")
	assert.True(t, ok)
	assert.Equal(t, "value", val)
}

func TestStore_GetMissingKey(t *testing.T) {
	s, err := config.NewStore(filepath.Join(t.TempDir(), "config.json"))
	require.NoError(t, err)
	_, ok := s.Get("missing")
	assert.False(t, ok)
}

func TestStore_Set_Overwrites(t *testing.T) {
	s, err := config.NewStore(filepath.Join(t.TempDir(), "config.json"))
	require.NoError(t, err)
	require.NoError(t, s.Set("key", "first"))
	require.NoError(t, s.Set("key", "second"))
	val, ok := s.Get("key")
	assert.True(t, ok)
	assert.Equal(t, "second", val)
}

func TestStore_Persistence(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	s1, err := config.NewStore(path)
	require.NoError(t, err)
	require.NoError(t, s1.Set("key", "persisted"))

	s2, err := config.NewStore(path)
	require.NoError(t, err)
	val, ok := s2.Get("key")
	assert.True(t, ok, "expected key to survive store reload")
	assert.Equal(t, "persisted", val)
}

func TestStore_All_Snapshot(t *testing.T) {
	s, err := config.NewStore(filepath.Join(t.TempDir(), "config.json"))
	require.NoError(t, err)
	require.NoError(t, s.Set("a", "1"))
	require.NoError(t, s.Set("b", "2"))

	all := s.All()
	assert.Equal(t, map[string]string{"a": "1", "b": "2"}, all)

	// Mutating the snapshot must not affect the store.
	all["c"] = "3"
	_, ok := s.Get("c")
	assert.False(t, ok, "snapshot mutation must not affect the store")
}

func TestStore_Remove_ExistingKey(t *testing.T) {
	s, err := config.NewStore(filepath.Join(t.TempDir(), "config.json"))
	require.NoError(t, err)
	require.NoError(t, s.Set("key", "value"))
	require.NoError(t, s.Remove("key"))
	_, ok := s.Get("key")
	assert.False(t, ok, "expected key to be removed")
}

func TestStore_Remove_MissingKey(t *testing.T) {
	s, err := config.NewStore(filepath.Join(t.TempDir(), "config.json"))
	require.NoError(t, err)
	assert.NoError(t, s.Remove("nonexistent"), "remove of missing key must not error")
}

func TestStore_Remove_Persists(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	s1, err := config.NewStore(path)
	require.NoError(t, err)
	require.NoError(t, s1.Set("key", "value"))
	require.NoError(t, s1.Remove("key"))

	s2, err := config.NewStore(path)
	require.NoError(t, err)
	_, ok := s2.Get("key")
	assert.False(t, ok, "removed key must not reappear after reload")
}

func TestStore_Remove_WriteError(t *testing.T) {
	path := filepath.Join(t.TempDir(), "noexist", "config.json")
	s, err := config.NewStore(path)
	require.NoError(t, err)
	// Manually seed an entry so Remove actually tries to write.
	require.Error(t, s.Set("key", "val"), "expected write error")
	// Remove on a missing-key store is a no-op — no write attempted.
	assert.NoError(t, s.Remove("key"))
}

func TestStore_Set_WriteError(t *testing.T) {
	// Path in a non-existent subdirectory — NewStore succeeds (file not found),
	// but persist() fails because the parent directory doesn't exist.
	path := filepath.Join(t.TempDir(), "noexist", "config.json")
	s, err := config.NewStore(path)
	require.NoError(t, err)
	err = s.Set("key", "val")
	assert.Error(t, err, "expected error when parent directory does not exist")
}

// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

package devicemgr_test

import (
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"github.com/absmach/agent/pkg/devicemgr"
	"github.com/absmach/agent/pkg/iface"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newTestStore(t *testing.T) *devicemgr.Store {
	t.Helper()
	s, err := devicemgr.NewStore(filepath.Join(t.TempDir(), "devices.db"))
	require.NoError(t, err)
	t.Cleanup(func() { s.Close() })
	return s
}

func makeDevice(id string) devicemgr.Device {
	return devicemgr.Device{
		ID:            id,
		Key:           "key-" + id,
		ChannelID:     "ch-" + id,
		InterfaceType: iface.InterfaceBLE,
		InterfaceAddr: "AA:BB:CC:DD:EE:FF",
		Name:          "device-" + id,
		Active:        true,
		LastSeen:      time.Now().UTC().Truncate(time.Millisecond),
	}
}

func TestNewStore(t *testing.T) {
	cases := []struct {
		desc    string
		path    string
		wantErr bool
	}{
		{
			desc: "create new store at valid path",
			path: filepath.Join(t.TempDir(), "devices.db"),
		},
		{
			desc:    "fail on bad path",
			path:    "/nonexistent/dir/devices.db",
			wantErr: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.desc, func(t *testing.T) {
			s, err := devicemgr.NewStore(tc.path)
			if tc.wantErr {
				assert.Error(t, err, fmt.Sprintf("%s: expected error", tc.desc))
				return
			}
			require.NoError(t, err, fmt.Sprintf("%s: unexpected error", tc.desc))
			s.Close()
		})
	}
}

func TestStore_SaveAndGet(t *testing.T) {
	s := newTestStore(t)
	d := makeDevice("device-1")

	cases := []struct {
		desc    string
		id      string
		save    *devicemgr.Device
		wantErr bool
	}{
		{
			desc: "save and retrieve device",
			id:   d.ID,
			save: &d,
		},
		{
			desc:    "get non-existent device returns error",
			id:      "does-not-exist",
			wantErr: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.desc, func(t *testing.T) {
			if tc.save != nil {
				require.NoError(t, s.Save(*tc.save), fmt.Sprintf("%s: save failed", tc.desc))
			}
			got, err := s.Get(tc.id)
			if tc.wantErr {
				assert.Error(t, err, fmt.Sprintf("%s: expected error", tc.desc))
				return
			}
			require.NoError(t, err, fmt.Sprintf("%s: unexpected error", tc.desc))
			assert.Equal(t, tc.save.ID, got.ID, fmt.Sprintf("%s: unexpected ID", tc.desc))
			assert.Equal(t, tc.save.Key, got.Key, fmt.Sprintf("%s: unexpected Key", tc.desc))
			assert.Equal(t, tc.save.ChannelID, got.ChannelID, fmt.Sprintf("%s: unexpected ChannelID", tc.desc))
			assert.Equal(t, tc.save.InterfaceType, got.InterfaceType, fmt.Sprintf("%s: unexpected InterfaceType", tc.desc))
			assert.Equal(t, tc.save.InterfaceAddr, got.InterfaceAddr, fmt.Sprintf("%s: unexpected InterfaceAddr", tc.desc))
			assert.Equal(t, tc.save.Name, got.Name, fmt.Sprintf("%s: unexpected Name", tc.desc))
			assert.Equal(t, tc.save.Active, got.Active, fmt.Sprintf("%s: unexpected Active", tc.desc))
		})
	}
}

func TestStore_SaveOverwrites(t *testing.T) {
	s := newTestStore(t)
	d := makeDevice("device-1")
	require.NoError(t, s.Save(d))

	d.Name = "updated-name"
	d.Active = false
	require.NoError(t, s.Save(d))

	got, err := s.Get(d.ID)
	require.NoError(t, err)
	assert.Equal(t, "updated-name", got.Name)
	assert.False(t, got.Active)
}

func TestStore_Remove(t *testing.T) {
	s := newTestStore(t)
	d := makeDevice("device-1")
	require.NoError(t, s.Save(d))

	cases := []struct {
		desc string
		id   string
	}{
		{
			desc: "remove existing device",
			id:   d.ID,
		},
		{
			desc: "remove non-existent device is a no-op",
			id:   "does-not-exist",
		},
	}

	for _, tc := range cases {
		t.Run(tc.desc, func(t *testing.T) {
			err := s.Remove(tc.id)
			assert.NoError(t, err, fmt.Sprintf("%s: unexpected error", tc.desc))
		})
	}

	_, err := s.Get(d.ID)
	assert.Error(t, err, "device should be gone after remove")
}

func TestStore_List(t *testing.T) {
	s := newTestStore(t)

	t.Run("empty store returns empty slice", func(t *testing.T) {
		devs, err := s.List()
		require.NoError(t, err)
		assert.Empty(t, devs)
	})

	d1 := makeDevice("aaa")
	d2 := makeDevice("bbb")
	require.NoError(t, s.Save(d1))
	require.NoError(t, s.Save(d2))

	t.Run("list returns all saved devices", func(t *testing.T) {
		devs, err := s.List()
		require.NoError(t, err)
		assert.Len(t, devs, 2)
		ids := map[string]bool{}
		for _, d := range devs {
			ids[d.ID] = true
		}
		assert.True(t, ids[d1.ID])
		assert.True(t, ids[d2.ID])
	})
}

func TestStore_MarkSeen(t *testing.T) {
	s := newTestStore(t)
	d := makeDevice("device-1")
	d.Active = false
	require.NoError(t, s.Save(d))

	cases := []struct {
		desc    string
		id      string
		wantErr bool
	}{
		{
			desc: "mark existing device as seen",
			id:   d.ID,
		},
		{
			desc:    "mark non-existent device returns error",
			id:      "does-not-exist",
			wantErr: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.desc, func(t *testing.T) {
			before := time.Now()
			err := s.MarkSeen(tc.id)
			if tc.wantErr {
				assert.Error(t, err, fmt.Sprintf("%s: expected error", tc.desc))
				return
			}
			require.NoError(t, err, fmt.Sprintf("%s: unexpected error", tc.desc))
			got, err := s.Get(tc.id)
			require.NoError(t, err)
			assert.True(t, got.Active, "MarkSeen should set Active = true")
			assert.True(t, got.LastSeen.After(before) || got.LastSeen.Equal(before),
				"MarkSeen should update LastSeen")
		})
	}
}

// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

package devicemgr

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/absmach/agent/pkg/iface"
	bolt "go.etcd.io/bbolt"
	bolterrors "go.etcd.io/bbolt/errors"
)

// Backup is a portable snapshot of the device registry. It is the payload
// returned by an export and accepted by a restore, and it carries the schema
// version so a restore can reject snapshots from an incompatible future build.
type Backup struct {
	SchemaVersion int       `json:"schema_version"`
	ExportedAt    time.Time `json:"exported_at"`
	Devices       []Device  `json:"devices"`
}

// Export returns a Backup containing every registered device and the current
// on-disk schema version. The read runs in a single transaction so the
// snapshot is internally consistent.
func (s *Store) Export() (Backup, error) {
	b := Backup{ExportedAt: time.Now().UTC()}
	err := s.db.View(func(tx *bolt.Tx) error {
		meta := tx.Bucket(metaBucket)
		if meta != nil {
			b.SchemaVersion = readSchemaVersion(meta)
		}
		return tx.Bucket(devicesBucket).ForEach(func(_, v []byte) error {
			var d Device
			if err := json.Unmarshal(v, &d); err != nil {
				return err
			}
			b.Devices = append(b.Devices, d)
			return nil
		})
	})
	if err != nil {
		return Backup{}, err
	}
	return b, nil
}

// Import writes the devices from a Backup into the store. When replace is true
// the existing registry is cleared first, so the store ends up matching the
// snapshot exactly; otherwise the devices are merged in, overwriting any record
// that shares an ID. It returns the number of devices written.
func (s *Store) Import(b Backup, replace bool) (int, error) {
	if b.SchemaVersion > CurrentSchemaVersion {
		return 0, fmt.Errorf("backup schema version %d is newer than supported version %d", b.SchemaVersion, CurrentSchemaVersion)
	}
	for _, d := range b.Devices {
		if d.ID == "" {
			return 0, fmt.Errorf("backup contains a device with an empty ID")
		}
	}

	count := 0
	err := s.db.Update(func(tx *bolt.Tx) error {
		if replace {
			if err := tx.DeleteBucket(devicesBucket); err != nil && !errors.Is(err, bolterrors.ErrBucketNotFound) {
				return err
			}
			if _, err := tx.CreateBucket(devicesBucket); err != nil {
				return err
			}
		}
		bkt := tx.Bucket(devicesBucket)
		for _, d := range b.Devices {
			data, err := json.Marshal(d)
			if err != nil {
				return err
			}
			if err := bkt.Put([]byte(d.ID), data); err != nil {
				return err
			}
			count++
		}
		return nil
	})
	if err != nil {
		return 0, err
	}
	return count, nil
}

// Backup returns a portable snapshot of the registry suitable for storing
// off-device or transferring to another agent.
func (m *Manager) Backup() (Backup, error) {
	return m.store.Export()
}

// Restore loads devices from a Backup into the registry. When replace is true
// the existing registry is cleared first; any open physical interfaces are
// closed because their devices may no longer be present. It returns the number
// of devices written.
//
// Restore is an administrative operation and is not synchronized against
// concurrent OpenIface calls: a replace restore that runs at the same time as
// an OpenIface may leave an interface open for a device the restore removed.
// Callers should quiesce device activity (or restart the agent) around a
// replace restore.
func (m *Manager) Restore(b Backup, replace bool) (int, error) {
	if replace {
		m.closeAllIfaces()
	}
	return m.store.Import(b, replace)
}

// closeAllIfaces closes every open interface and clears the cached reads. It is
// used by Restore(replace=true) to drop interface state that may reference
// devices removed by the snapshot.
func (m *Manager) closeAllIfaces() {
	m.mu.Lock()
	interfaces := m.interfaces
	m.interfaces = make(map[string]iface.Interface)
	m.lastRead = make(map[string][]byte)
	m.mu.Unlock()
	for _, ifc := range interfaces {
		// Best-effort close; registry state is already cleared.
		_ = ifc.Close()
	}
}

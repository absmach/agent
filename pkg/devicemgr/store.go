// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

package devicemgr

import (
	"encoding/json"
	"fmt"
	"strconv"
	"time"

	"github.com/absmach/agent/pkg/iface"
	bolt "go.etcd.io/bbolt"
)

var (
	devicesBucket = []byte("devices")
	metaBucket    = []byte("meta")
)

// schemaVersionKey stores the on-disk registry schema version in the meta
// bucket. It lets the store migrate older database files forward on open.
var schemaVersionKey = []byte("schema_version")

// CurrentSchemaVersion is the schema version written by this build of the
// store. Bump it and add a migration to migrations when the on-disk layout
// changes.
const CurrentSchemaVersion = 1

// migrations maps a source schema version to the function that upgrades the
// database from that version to the next one. Migrations run in order inside a
// single write transaction when the store is opened.
var migrations = map[int]func(tx *bolt.Tx) error{
	// 0 -> 1: baseline. Ensure the devices bucket exists. Older agent builds
	// created the devices bucket but never tracked a schema version, so they
	// are treated as version 0 and upgraded in place without data loss.
	0: func(tx *bolt.Tx) error {
		_, err := tx.CreateBucketIfNotExists(devicesBucket)
		return err
	},
}

// Store persists devices in a BoltDB file.
type Store struct {
	db *bolt.DB
}

// NewStore opens (or creates) the BoltDB file at path and runs any pending
// schema migrations so the registry is usable across agent upgrades.
func NewStore(path string) (*Store, error) {
	db, err := bolt.Open(path, 0o600, nil)
	if err != nil {
		return nil, fmt.Errorf("open device store: %w", err)
	}
	if err := db.Update(func(tx *bolt.Tx) error {
		if _, err := tx.CreateBucketIfNotExists(devicesBucket); err != nil {
			return err
		}
		if _, err := tx.CreateBucketIfNotExists(metaBucket); err != nil {
			return err
		}
		return nil
	}); err != nil {
		db.Close()
		return nil, fmt.Errorf("create device buckets: %w", err)
	}
	s := &Store{db: db}
	if err := s.migrate(); err != nil {
		db.Close()
		return nil, fmt.Errorf("migrate device store: %w", err)
	}
	return s, nil
}

// migrate brings the on-disk schema up to CurrentSchemaVersion by running each
// pending migration in sequence. It is a no-op once the database is current.
func (s *Store) migrate() error {
	return s.db.Update(func(tx *bolt.Tx) error {
		meta := tx.Bucket(metaBucket)
		from := readSchemaVersion(meta)
		if from > CurrentSchemaVersion {
			return fmt.Errorf("device store schema version %d is newer than supported version %d", from, CurrentSchemaVersion)
		}
		for v := from; v < CurrentSchemaVersion; v++ {
			migrate, ok := migrations[v]
			if !ok {
				return fmt.Errorf("missing migration from schema version %d", v)
			}
			if err := migrate(tx); err != nil {
				return fmt.Errorf("apply migration %d->%d: %w", v, v+1, err)
			}
		}
		return writeSchemaVersion(meta, CurrentSchemaVersion)
	})
}

// readSchemaVersion returns the schema version recorded in the meta bucket,
// or 0 when no version has been written yet (fresh or pre-versioning database).
func readSchemaVersion(meta *bolt.Bucket) int {
	v := meta.Get(schemaVersionKey)
	if v == nil {
		return 0
	}
	n, err := strconv.Atoi(string(v))
	if err != nil {
		return 0
	}
	return n
}

func writeSchemaVersion(meta *bolt.Bucket, version int) error {
	return meta.Put(schemaVersionKey, []byte(strconv.Itoa(version)))
}

// SchemaVersion returns the schema version currently stored on disk.
func (s *Store) SchemaVersion() (int, error) {
	var version int
	err := s.db.View(func(tx *bolt.Tx) error {
		meta := tx.Bucket(metaBucket)
		if meta == nil {
			return fmt.Errorf("bucket %q not found", metaBucket)
		}
		version = readSchemaVersion(meta)
		return nil
	})
	return version, err
}

// Close closes the underlying database.
func (s *Store) Close() error {
	return s.db.Close()
}

// Save persists a device, overwriting any existing record with the same ID.
func (s *Store) Save(d Device) error {
	b, err := json.Marshal(d)
	if err != nil {
		return err
	}
	return s.db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket(devicesBucket).Put([]byte(d.ID), b)
	})
}

// Remove deletes a device by its ID. No error if the device is absent.
func (s *Store) Remove(id string) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket(devicesBucket).Delete([]byte(id))
	})
}

// Get retrieves a single device by ID.
func (s *Store) Get(id string) (Device, error) {
	var d Device
	err := s.db.View(func(tx *bolt.Tx) error {
		v := tx.Bucket(devicesBucket).Get([]byte(id))
		if v == nil {
			return fmt.Errorf("device %s not found", id)
		}
		return json.Unmarshal(v, &d)
	})
	return d, err
}

// Count returns the number of stored devices without loading the records.
func (s *Store) Count() (int, error) {
	var n int
	err := s.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(devicesBucket)
		if b == nil {
			return fmt.Errorf("bucket %q not found", devicesBucket)
		}
		n = b.Stats().KeyN
		return nil
	})
	return n, err
}

// List returns all stored devices.
func (s *Store) List() ([]Device, error) {
	var devices []Device
	err := s.db.View(func(tx *bolt.Tx) error {
		return tx.Bucket(devicesBucket).ForEach(func(_, v []byte) error {
			var d Device
			if err := json.Unmarshal(v, &d); err != nil {
				return err
			}
			devices = append(devices, d)
			return nil
		})
	})
	return devices, err
}

// errAddrFound is a sentinel returned from ForEach to stop iteration early.
var errAddrFound = fmt.Errorf("found")

// FindByAddr returns the first active device matching the given interface type
// and address. Returns an error if no match is found.
func (s *Store) FindByAddr(ifaceType iface.InterfaceType, addr string) (Device, error) {
	var found Device
	err := s.db.View(func(tx *bolt.Tx) error {
		return tx.Bucket(devicesBucket).ForEach(func(_, v []byte) error {
			var d Device
			if err := json.Unmarshal(v, &d); err != nil {
				return err
			}
			if d.Active && d.InterfaceType == ifaceType && d.InterfaceAddr == addr {
				found = d
				return errAddrFound
			}
			return nil
		})
	})
	if err == errAddrFound {
		return found, nil
	}
	if err != nil {
		return Device{}, err
	}
	return Device{}, fmt.Errorf("no device with interface type %v addr %s", ifaceType, addr)
}

// MarkInactive sets Active = false for the given device ID.
func (s *Store) MarkInactive(id string) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		bkt := tx.Bucket(devicesBucket)
		v := bkt.Get([]byte(id))
		if v == nil {
			return fmt.Errorf("device %s not found", id)
		}
		var d Device
		if err := json.Unmarshal(v, &d); err != nil {
			return err
		}
		d.Active = false
		b, err := json.Marshal(d)
		if err != nil {
			return err
		}
		return bkt.Put([]byte(id), b)
	})
}

// MarkSeen sets LastSeen = now for the given device ID without changing Active.
// Use this when the device sends data while the interface is already open,
// or for manual pings from the UI.
func (s *Store) MarkSeen(id string) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		bkt := tx.Bucket(devicesBucket)
		v := bkt.Get([]byte(id))
		if v == nil {
			return fmt.Errorf("device %s not found", id)
		}
		var d Device
		if err := json.Unmarshal(v, &d); err != nil {
			return err
		}
		d.LastSeen = time.Now().UTC()
		b, err := json.Marshal(d)
		if err != nil {
			return err
		}
		return bkt.Put([]byte(id), b)
	})
}

// MarkActive sets Active = true and LastSeen = now for the given device ID.
// Called only when the physical interface is successfully opened.
func (s *Store) MarkActive(id string) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		bkt := tx.Bucket(devicesBucket)
		v := bkt.Get([]byte(id))
		if v == nil {
			return fmt.Errorf("device %s not found", id)
		}
		var d Device
		if err := json.Unmarshal(v, &d); err != nil {
			return err
		}
		d.Active = true
		d.LastSeen = time.Now().UTC()
		b, err := json.Marshal(d)
		if err != nil {
			return err
		}
		return bkt.Put([]byte(id), b)
	})
}

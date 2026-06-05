// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

package devicemgr

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/absmach/agent/pkg/iface"
	bolt "go.etcd.io/bbolt"
)

var devicesBucket = []byte("devices")

// Store persists devices in a BoltDB file.
type Store struct {
	db *bolt.DB
}

// NewStore opens (or creates) the BoltDB file at path.
func NewStore(path string) (*Store, error) {
	db, err := bolt.Open(path, 0o600, nil)
	if err != nil {
		return nil, fmt.Errorf("open device store: %w", err)
	}
	if err := db.Update(func(tx *bolt.Tx) error {
		_, err := tx.CreateBucketIfNotExists(devicesBucket)
		return err
	}); err != nil {
		db.Close()
		return nil, fmt.Errorf("create devices bucket: %w", err)
	}
	return &Store{db: db}, nil
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

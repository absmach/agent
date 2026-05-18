// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

package devicemgr

import (
	"fmt"
	"time"
)

// Manager handles the downstream device registry and Magistrala provisioning.
type Manager struct {
	store     *Store
	provision *provisionClient
}

// New creates a Manager backed by a BoltDB store at dbPath.
// If cfg.URL is empty, provisioning is disabled and Add will fail.
func New(dbPath string, cfg ProvisionConfig) (*Manager, error) {
	store, err := NewStore(dbPath)
	if err != nil {
		return nil, err
	}
	return &Manager{
		store:     store,
		provision: newProvisionClient(cfg),
	}, nil
}

// Close releases the store.
func (m *Manager) Close() error {
	return m.store.Close()
}

// Add provisions a new downstream device via the Magistrala Provision API,
// saves it to the local registry, and returns it.
func (m *Manager) Add(name, externalID, externalKey string, ifaceType InterfaceType, ifaceAddr string) (Device, error) {
	if m.provision.cfg.URL == "" {
		return Device{}, fmt.Errorf("provision URL not configured")
	}
	d, err := m.provision.Provision(name, externalID, externalKey)
	if err != nil {
		return Device{}, fmt.Errorf("provision %s: %w", name, err)
	}
	d.InterfaceType = ifaceType
	d.InterfaceAddr = ifaceAddr
	d.Active = true
	d.LastSeen = time.Now().UTC()
	if err := m.store.Save(d); err != nil {
		return d, fmt.Errorf("save device %s: %w", d.ID, err)
	}
	return d, nil
}

// Remove deletes a device from the registry.
func (m *Manager) Remove(id string) error {
	return m.store.Remove(id)
}

// Get retrieves a single device.
func (m *Manager) Get(id string) (Device, error) {
	return m.store.Get(id)
}

// List returns all registered devices.
func (m *Manager) List() ([]Device, error) {
	return m.store.List()
}

// MarkSeen updates LastSeen and Active for a device (called when a device sends data).
func (m *Manager) MarkSeen(id string) error {
	return m.store.MarkSeen(id)
}

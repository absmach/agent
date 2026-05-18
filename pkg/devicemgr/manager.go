// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

package devicemgr

import (
	"encoding/hex"
	"fmt"
	"time"

	"github.com/absmach/agent/pkg/iface"
)

// Manager handles the downstream device registry and Magistrala provisioning.
type Manager struct {
	store      *Store
	provision  *provisionClient
	interfaces map[string]iface.Interface
	ifaceCfg   iface.Config
}

// New creates a Manager backed by a BoltDB store at dbPath.
// If cfg.URL is empty, provisioning is disabled and Add will fail.
func New(dbPath string, cfg ProvisionConfig, ifaceCfg iface.Config) (*Manager, error) {
	store, err := NewStore(dbPath)
	if err != nil {
		return nil, err
	}
	return &Manager{
		store:      store,
		provision:  newProvisionClient(cfg),
		interfaces: make(map[string]iface.Interface),
		ifaceCfg:   ifaceCfg,
	}, nil
}

// Close releases all open interfaces and the store.
func (m *Manager) Close() error {
	for id, ifc := range m.interfaces {
		_ = ifc.Close()
		delete(m.interfaces, id)
	}
	return m.store.Close()
}

// Add provisions a new downstream device via the Magistrala Provision API,
// saves it to the local registry, and returns it.
func (m *Manager) Add(name, externalID, externalKey string, ifaceType iface.InterfaceType, ifaceAddr string) (Device, error) {
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

// Remove deletes a device from the registry and closes any open interface.
func (m *Manager) Remove(id string) error {
	if ifc, ok := m.interfaces[id]; ok {
		_ = ifc.Close()
		delete(m.interfaces, id)
	}
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

// OpenIface opens the physical interface for a registered device.
func (m *Manager) OpenIface(id string) error {
	if _, ok := m.interfaces[id]; ok {
		return nil // already open
	}
	d, err := m.store.Get(id)
	if err != nil {
		return fmt.Errorf("device %s: %w", id, err)
	}
	ifc, err := iface.New(d.InterfaceType, d.InterfaceAddr, m.ifaceCfg)
	if err != nil {
		return fmt.Errorf("create interface for device %s: %w", id, err)
	}
	if err := ifc.Open(); err != nil {
		return fmt.Errorf("open interface for device %s: %w", id, err)
	}
	m.interfaces[id] = ifc
	return nil
}

// CloseIface closes the physical interface for a registered device.
func (m *Manager) CloseIface(id string) error {
	ifc, ok := m.interfaces[id]
	if !ok {
		return fmt.Errorf("device %s: interface not open", id)
	}
	err := ifc.Close()
	delete(m.interfaces, id)
	if err != nil {
		return fmt.Errorf("close interface for device %s: %w", id, err)
	}
	return nil
}

// ReadIface reads n bytes from the open interface of the given device.
func (m *Manager) ReadIface(id string, n int) ([]byte, error) {
	ifc, ok := m.interfaces[id]
	if !ok {
		return nil, fmt.Errorf("device %s: interface not open", id)
	}
	buf := make([]byte, n)
	read, err := ifc.Read(buf)
	if err != nil {
		return nil, fmt.Errorf("read from device %s: %w", id, err)
	}
	return buf[:read], nil
}

// WriteIface sends hex-encoded data to the open interface of the given device.
func (m *Manager) WriteIface(id, hexData string) (int, error) {
	ifc, ok := m.interfaces[id]
	if !ok {
		return 0, fmt.Errorf("device %s: interface not open", id)
	}
	data, err := hex.DecodeString(hexData)
	if err != nil {
		return 0, fmt.Errorf("decode hex for device %s: %w", id, err)
	}
	n, err := ifc.Write(data)
	if err != nil {
		return n, fmt.Errorf("write to device %s: %w", id, err)
	}
	return n, nil
}

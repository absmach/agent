// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

package devicemgr

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"

	"github.com/absmach/agent/pkg/iface"
)

// Manager handles the downstream device registry and Magistrala provisioning.
type Manager struct {
	store      *Store
	provision  *provisionClient
	mu         sync.RWMutex
	interfaces map[string]iface.Interface
	ifaceCfg   iface.Config
}

// New creates a Manager backed by a BoltDB store at dbPath.
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
// All interface close errors are collected and joined before returning.
func (m *Manager) Close() error {
	m.mu.Lock()
	interfaces := m.interfaces
	m.interfaces = make(map[string]iface.Interface)
	m.mu.Unlock()

	var errs []error
	for id, ifc := range interfaces {
		if err := ifc.Close(); err != nil {
			errs = append(errs, fmt.Errorf("close interface %s: %w", id, err))
		}
	}
	return errors.Join(append(errs, m.store.Close())...)
}

// Add provisions a new downstream device via the Magistrala SDK,
// saves it to the local registry, and returns it.
func (m *Manager) Add(ctx context.Context, name, externalID, externalKey string, ifaceType iface.InterfaceType, ifaceAddr string) (Device, error) {
	d, err := m.provision.Provision(ctx, name, externalID, externalKey)
	if err != nil {
		return Device{}, fmt.Errorf("provision %s: %w", name, err)
	}
	d.InterfaceType = ifaceType
	d.InterfaceAddr = ifaceAddr
	d.Active = false
	if err := m.store.Save(d); err != nil {
		return d, fmt.Errorf("save device %s: %w", d.ID, err)
	}
	return d, nil
}

// Remove deletes a device from the registry and closes any open interface.
func (m *Manager) Remove(id string) error {
	m.mu.Lock()
	ifc, ok := m.interfaces[id]
	if ok {
		delete(m.interfaces, id)
	}
	m.mu.Unlock()
	if ok {
		if err := ifc.Close(); err != nil {
			return fmt.Errorf("close interface %s: %w", id, err)
		}
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

// FindByAddr returns the first active device matching the given interface type
// and address. Used to route inbound data (e.g. a BLE notification) to the
// correct device without knowing its ID in advance.
func (m *Manager) FindByAddr(ifaceType iface.InterfaceType, addr string) (Device, error) {
	return m.store.FindByAddr(ifaceType, addr)
}

// OpenIface opens the physical interface for a registered device.
func (m *Manager) OpenIface(id string) error {
	m.mu.RLock()
	_, alreadyOpen := m.interfaces[id]
	m.mu.RUnlock()
	if alreadyOpen {
		return nil
	}
	d, err := m.store.Get(id)
	if err != nil {
		return fmt.Errorf("device %s: %w", id, err)
	}
	ifc, err := iface.New(d.InterfaceType, d.InterfaceAddr, m.ifaceCfg)
	if err != nil {
		_ = m.store.MarkInactive(id)
		return fmt.Errorf("create interface for device %s: %w", id, err)
	}
	if err := ifc.Open(); err != nil {
		_ = m.store.MarkInactive(id)
		return fmt.Errorf("open interface for device %s: %w", id, err)
	}
	m.mu.Lock()
	if _, alreadyOpen := m.interfaces[id]; alreadyOpen {
		// Another goroutine opened it while we were initialising; discard ours.
		m.mu.Unlock()
		_ = ifc.Close()
		return nil
	}
	m.interfaces[id] = ifc
	m.mu.Unlock()
	_ = m.store.MarkActive(id)
	return nil
}

// CloseIface closes the physical interface for a registered device.
func (m *Manager) CloseIface(id string) error {
	m.mu.Lock()
	ifc, ok := m.interfaces[id]
	if ok {
		delete(m.interfaces, id)
	}
	m.mu.Unlock()
	if !ok {
		return fmt.Errorf("device %s: interface not open", id)
	}
	if err := ifc.Close(); err != nil {
		return fmt.Errorf("close interface for device %s: %w", id, err)
	}
	_ = m.store.MarkInactive(id)
	return nil
}

// ReadIface reads n bytes from the open interface of the given device.
func (m *Manager) ReadIface(id string, n int) ([]byte, error) {
	m.mu.RLock()
	ifc, ok := m.interfaces[id]
	if !ok {
		m.mu.RUnlock()
		return nil, fmt.Errorf("device %s: interface not open", id)
	}
	buf := make([]byte, n)
	read, err := ifc.Read(buf)
	m.mu.RUnlock()
	if err != nil {
		return nil, fmt.Errorf("read from device %s: %w", id, err)
	}
	return buf[:read], nil
}

// WriteIface sends hex-encoded data to the open interface of the given device.
func (m *Manager) WriteIface(id, hexData string) (int, error) {
	data, err := hex.DecodeString(hexData)
	if err != nil {
		return 0, fmt.Errorf("decode hex for device %s: %w", id, err)
	}
	m.mu.RLock()
	ifc, ok := m.interfaces[id]
	if !ok {
		m.mu.RUnlock()
		return 0, fmt.Errorf("device %s: interface not open", id)
	}
	n, err := ifc.Write(data)
	m.mu.RUnlock()
	if err != nil {
		return n, fmt.Errorf("write to device %s: %w", id, err)
	}
	return n, nil
}

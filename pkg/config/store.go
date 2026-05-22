// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"encoding/json"
	"maps"
	"os"
	"sync"
)

// Store is a thread-safe, file-backed key-value store that persists entries
// to a JSON file immediately on every Set call.
type Store struct {
	mu      sync.RWMutex
	entries map[string]string
	path    string
}

// NewStore opens (or creates) the JSON file at path and loads any existing
// entries into memory. Returns an error only if the file exists but cannot
// be parsed; a missing file is treated as an empty store.
func NewStore(path string) (*Store, error) {
	s := &Store{
		entries: make(map[string]string),
		path:    path,
	}
	if err := s.load(); err != nil && !os.IsNotExist(err) {
		return nil, err
	}
	return s, nil
}

// Get returns the value for key and whether it was found.
func (s *Store) Get(key string) (string, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	v, ok := s.entries[key]
	return v, ok
}

// Set writes key→value to the in-memory cache and immediately persists.
// If the disk write fails the in-memory change is rolled back.
func (s *Store) Set(key, value string) error {
	s.mu.Lock()
	prev, existed := s.entries[key]
	s.entries[key] = value
	snapshot := s.copyEntries()
	s.mu.Unlock()

	if err := s.writeSnapshot(snapshot); err != nil {
		s.mu.Lock()
		if existed {
			s.entries[key] = prev
		} else {
			delete(s.entries, key)
		}
		s.mu.Unlock()
		return err
	}
	return nil
}

// All returns a snapshot of all entries.
func (s *Store) All() map[string]string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.copyEntries()
}

func (s *Store) load() error {
	b, err := os.ReadFile(s.path)
	if err != nil {
		return err
	}
	if len(b) == 0 {
		return nil
	}
	return json.Unmarshal(b, &s.entries)
}

// copyEntries returns a copy of s.entries. Must be called with the lock held.
func (s *Store) copyEntries() map[string]string {
	out := make(map[string]string, len(s.entries))
	maps.Copy(out, s.entries)
	return out
}

func (s *Store) writeSnapshot(m map[string]string) error {
	b, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, s.path)
}

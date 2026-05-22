// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

package configstore

import (
	"encoding/json"
	"maps"
	"os"
	"sync"

	"github.com/absmach/magistrala/pkg/errors"
)

var (
	errReadFile  = errors.New("failed to read config file")
	errWriteFile = errors.New("failed to write config file")
	errParseJSON = errors.New("failed to parse config file")
	errNotFound  = errors.New("key not found")
)

type Store interface {
	Get(key string) (string, error)
	Set(key, value string) error
	Remove(key string) error
	Load() error
	Save() error
	All() map[string]string
}

type store struct {
	mu       sync.Mutex
	filePath string
	data     map[string]string
}

func New(filePath string) Store {
	return &store{
		filePath: filePath,
		data:     make(map[string]string),
	}
}

func (s *store) Load() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	raw, err := os.ReadFile(s.filePath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}

		return errors.Wrap(errReadFile, err)
	}

	if len(raw) == 0 {
		return nil
	}

	var data map[string]string
	if err := json.Unmarshal(raw, &data); err != nil {
		return errors.Wrap(errParseJSON, err)
	}

	s.data = data

	return nil
}

func (s *store) Save() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.saveLocked()
}

func (s *store) saveLocked() error {
	raw, err := json.MarshalIndent(s.data, "", "  ")
	if err != nil {
		return errors.Wrap(errWriteFile, err)
	}

	return os.WriteFile(s.filePath, raw, 0o644)
}

func (s *store) Get(key string) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	val, ok := s.data[key]
	if !ok {
		return "", errors.Wrap(errNotFound, errors.New(key))
	}

	return val, nil
}

func (s *store) Set(key, value string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.data[key] = value

	return s.saveLocked()
}

func (s *store) Remove(key string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	delete(s.data, key)

	return s.saveLocked()
}

func (s *store) All() map[string]string {
	s.mu.Lock()
	defer s.mu.Unlock()

	cp := make(map[string]string, len(s.data))
	maps.Copy(cp, s.data)

	return cp
}

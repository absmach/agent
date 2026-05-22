// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

package configstore_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/absmach/agent/pkg/configstore"
	"github.com/stretchr/testify/assert"
)

func TestNew(t *testing.T) {
	tmp := t.TempDir()
	path := filepath.Join(tmp, "config.json")

	s := configstore.New(path)
	assert.NotNil(t, s)
}

func TestLoadMissingFile(t *testing.T) {
	tmp := t.TempDir()
	path := filepath.Join(tmp, "missing.json")

	s := configstore.New(path)
	err := s.Load()
	assert.Nil(t, err)
}

func TestLoadEmptyFile(t *testing.T) {
	tmp := t.TempDir()
	path := filepath.Join(tmp, "config.json")
	assert.Nil(t, os.WriteFile(path, []byte{}, 0o644))

	s := configstore.New(path)
	err := s.Load()
	assert.Nil(t, err)
}

func TestLoadInvalidJSON(t *testing.T) {
	tmp := t.TempDir()
	path := filepath.Join(tmp, "config.json")
	assert.Nil(t, os.WriteFile(path, []byte("{invalid"), 0o644))

	s := configstore.New(path)
	err := s.Load()
	assert.Error(t, err)
}

func TestSetGetRemove(t *testing.T) {
	tmp := t.TempDir()
	path := filepath.Join(tmp, "config.json")

	s := configstore.New(path)
	assert.Nil(t, s.Load())

	assert.Nil(t, s.Set("mqtt.url", "tcp://localhost:1883"))

	val, err := s.Get("mqtt.url")
	assert.Nil(t, err)
	assert.Equal(t, "tcp://localhost:1883", val)

	assert.Nil(t, s.Remove("mqtt.url"))

	_, err = s.Get("mqtt.url")
	assert.Error(t, err)
}

func TestGetNotFound(t *testing.T) {
	tmp := t.TempDir()
	path := filepath.Join(tmp, "config.json")

	s := configstore.New(path)
	assert.Nil(t, s.Load())

	_, err := s.Get("nonexistent")
	assert.Error(t, err)
}

func TestAll(t *testing.T) {
	tmp := t.TempDir()
	path := filepath.Join(tmp, "config.json")

	s := configstore.New(path)
	assert.Nil(t, s.Load())

	assert.Nil(t, s.Set("a", "1"))
	assert.Nil(t, s.Set("b", "2"))

	all := s.All()
	assert.Equal(t, "1", all["a"])
	assert.Equal(t, "2", all["b"])
	assert.Len(t, all, 2)
}

func TestPersistAcrossInstances(t *testing.T) {
	tmp := t.TempDir()
	path := filepath.Join(tmp, "config.json")

	s1 := configstore.New(path)
	assert.Nil(t, s1.Load())
	assert.Nil(t, s1.Set("log.level", "debug"))

	s2 := configstore.New(path)
	assert.Nil(t, s2.Load())

	val, err := s2.Get("log.level")
	assert.Nil(t, err)
	assert.Equal(t, "debug", val)
}

func TestSaveCreatesFile(t *testing.T) {
	tmp := t.TempDir()
	path := filepath.Join(tmp, "subdir", "config.json")

	s := configstore.New(path)
	assert.Nil(t, s.Load())
	err := s.Save()
	assert.Error(t, err)
}

func TestOverwriteValue(t *testing.T) {
	tmp := t.TempDir()
	path := filepath.Join(tmp, "config.json")

	s := configstore.New(path)
	assert.Nil(t, s.Load())

	assert.Nil(t, s.Set("key", "old"))
	val, _ := s.Get("key")
	assert.Equal(t, "old", val)

	assert.Nil(t, s.Set("key", "new"))
	val, _ = s.Get("key")
	assert.Equal(t, "new", val)
}

func TestFileContent(t *testing.T) {
	tmp := t.TempDir()
	path := filepath.Join(tmp, "config.json")

	s := configstore.New(path)
	assert.Nil(t, s.Load())
	assert.Nil(t, s.Set("mqtt.url", "tcp://broker:1883"))
	assert.Nil(t, s.Set("log.level", "info"))

	raw, err := os.ReadFile(path)
	assert.Nil(t, err)
	assert.Contains(t, string(raw), "mqtt.url")
	assert.Contains(t, string(raw), "tcp://broker:1883")
	assert.Contains(t, string(raw), "log.level")
	assert.Contains(t, string(raw), "info")
}

// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

package remote

import (
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"time"

	bolt "go.etcd.io/bbolt"
)

var (
	requestBucket = []byte("requests")
	jobBucket     = []byte("jobs")
	stateBucket   = []byte("state")
	generationKey = []byte("desired-generation")
)

type RequestState string

const (
	RequestRunning   RequestState = "running"
	RequestCompleted RequestState = "completed"
)

type RequestRecord struct {
	ID        string       `json:"id"`
	Method    string       `json:"method"`
	Hash      string       `json:"hash"`
	State     RequestState `json:"state"`
	Response  Response     `json:"response,omitempty"`
	ExpiresAt time.Time    `json:"expires_at"`
	UpdatedAt time.Time    `json:"updated_at"`
}

type BeginResult int

const (
	BeginNew BeginResult = iota
	BeginReplay
	BeginRunning
	BeginConflict
)

type JobState string

const (
	JobQueued    JobState = "queued"
	JobRunning   JobState = "running"
	JobWaiting   JobState = "waiting"
	JobSucceeded JobState = "succeeded"
	JobFailed    JobState = "failed"
	JobCancelled JobState = "cancelled"
)

type Job struct {
	ID        string          `json:"id"`
	Type      string          `json:"type"`
	State     JobState        `json:"state"`
	Progress  float64         `json:"progress"`
	Phase     string          `json:"phase,omitempty"`
	Result    json.RawMessage `json:"result,omitempty"`
	Error     string          `json:"error,omitempty"`
	CreatedAt time.Time       `json:"created_at"`
	UpdatedAt time.Time       `json:"updated_at"`
}

// Store is a fresh protocol-state database. There are intentionally no schema
// migrations: incompatible development databases should be deleted.
type Store struct {
	db *bolt.DB
}

func NewStore(path string) (*Store, error) {
	db, err := bolt.Open(path, 0o600, &bolt.Options{Timeout: 2 * time.Second})
	if err != nil {
		return nil, err
	}
	if err := db.Update(func(tx *bolt.Tx) error {
		if _, err := tx.CreateBucketIfNotExists(requestBucket); err != nil {
			return err
		}
		if _, err := tx.CreateBucketIfNotExists(jobBucket); err != nil {
			return err
		}
		_, err := tx.CreateBucketIfNotExists(stateBucket)
		return err
	}); err != nil {
		_ = db.Close()
		return nil, err
	}
	return &Store{db: db}, nil
}

func (s *Store) DesiredGeneration() (uint64, error) {
	var generation uint64
	err := s.db.View(func(tx *bolt.Tx) error {
		raw := tx.Bucket(stateBucket).Get(generationKey)
		if raw == nil {
			return nil
		}
		return json.Unmarshal(raw, &generation)
	})
	return generation, err
}

func (s *Store) SetDesiredGeneration(generation uint64) error {
	raw, err := json.Marshal(generation)
	if err != nil {
		return err
	}
	return s.db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket(stateBucket).Put(generationKey, raw)
	})
}

func (s *Store) Close() error {
	if s == nil || s.db == nil {
		return nil
	}
	return s.db.Close()
}

func (s *Store) BeginRequest(id, method, hash string, expiresAt time.Time) (BeginResult, Response, error) {
	var result BeginResult
	var response Response
	err := s.db.Update(func(tx *bolt.Tx) error {
		bucket := tx.Bucket(requestBucket)
		raw := bucket.Get([]byte(id))
		if raw != nil {
			var existing RequestRecord
			if err := json.Unmarshal(raw, &existing); err != nil {
				return err
			}
			if !existing.ExpiresAt.IsZero() && time.Now().UTC().After(existing.ExpiresAt) {
				if err := bucket.Delete([]byte(id)); err != nil {
					return err
				}
				raw = nil
			}
		}
		if raw != nil {
			var existing RequestRecord
			if err := json.Unmarshal(raw, &existing); err != nil {
				return err
			}
			if existing.Method != method || existing.Hash != hash {
				result = BeginConflict
				return nil
			}
			if existing.State == RequestCompleted {
				result = BeginReplay
				response = existing.Response
				return nil
			}
			result = BeginRunning
			return nil
		}
		now := time.Now().UTC()
		record := RequestRecord{
			ID: id, Method: method, Hash: hash, State: RequestRunning,
			ExpiresAt: expiresAt, UpdatedAt: now,
		}
		encoded, err := json.Marshal(record)
		if err != nil {
			return err
		}
		result = BeginNew
		return bucket.Put([]byte(id), encoded)
	})
	return result, response, err
}

func (s *Store) CompleteRequest(id string, response Response) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		bucket := tx.Bucket(requestBucket)
		raw := bucket.Get([]byte(id))
		if raw == nil {
			return fmt.Errorf("request %s not found", id)
		}
		var record RequestRecord
		if err := json.Unmarshal(raw, &record); err != nil {
			return err
		}
		record.State = RequestCompleted
		record.Response = response
		record.UpdatedAt = time.Now().UTC()
		encoded, err := json.Marshal(record)
		if err != nil {
			return err
		}
		return bucket.Put([]byte(id), encoded)
	})
}

func (s *Store) PruneRequests(now time.Time) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		cursor := tx.Bucket(requestBucket).Cursor()
		for key, raw := cursor.First(); key != nil; key, raw = cursor.Next() {
			var record RequestRecord
			if json.Unmarshal(raw, &record) == nil && !record.ExpiresAt.IsZero() && now.After(record.ExpiresAt) {
				if err := cursor.Delete(); err != nil {
					return err
				}
			}
		}
		return nil
	})
}

func (s *Store) PutJob(job Job) error {
	job.UpdatedAt = time.Now().UTC()
	if job.CreatedAt.IsZero() {
		job.CreatedAt = job.UpdatedAt
	}
	encoded, err := json.Marshal(job)
	if err != nil {
		return err
	}
	return s.db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket(jobBucket).Put([]byte(job.ID), encoded)
	})
}

func (s *Store) GetJob(id string) (Job, error) {
	var job Job
	err := s.db.View(func(tx *bolt.Tx) error {
		raw := tx.Bucket(jobBucket).Get([]byte(id))
		if raw == nil {
			return errors.New("job not found")
		}
		return json.Unmarshal(raw, &job)
	})
	return job, err
}

func (s *Store) ListJobs() ([]Job, error) {
	var jobs []Job
	err := s.db.View(func(tx *bolt.Tx) error {
		return tx.Bucket(jobBucket).ForEach(func(_, raw []byte) error {
			var job Job
			if err := json.Unmarshal(raw, &job); err != nil {
				return err
			}
			jobs = append(jobs, job)
			return nil
		})
	})
	sort.Slice(jobs, func(i, j int) bool { return jobs[i].CreatedAt.After(jobs[j].CreatedAt) })
	return jobs, err
}

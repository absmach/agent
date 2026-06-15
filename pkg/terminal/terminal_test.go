// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

package terminal

import (
	"encoding/json"
	"log/slog"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type mockPublisher struct {
	mu       sync.Mutex
	messages []struct {
		topic   string
		payload string
	}
}

func (m *mockPublisher) publish(channel, payload string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.messages = append(m.messages, struct {
		topic   string
		payload string
	}{channel, payload})
	return nil
}

func (m *mockPublisher) messagesLen() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.messages)
}

func (m *mockPublisher) lastMessage() (string, string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.messages) == 0 {
		return "", ""
	}
	last := m.messages[len(m.messages)-1]
	return last.topic, last.payload
}

func TestNewSession(t *testing.T) {
	pub := &mockPublisher{}
	logger := slog.Default()

	sess, err := NewSession("test-uuid-1", 60*time.Second, pub.publish, logger)
	require.NoError(t, err)
	require.NotNil(t, sess)

	done := sess.IsDone()
	assert.NotNil(t, done)

	time.Sleep(100 * time.Millisecond)

	err = sess.Send([]byte("echo hello\n"))
	require.NoError(t, err)
	time.Sleep(200 * time.Millisecond)

	assert.Greater(t, pub.messagesLen(), 0, "expected PTY output to be published")

	topic, _ := pub.lastMessage()
	assert.Contains(t, topic, "term/test-uuid-1")

	select {
	case <-done:
		t.Fatal("session should not be done yet")
	default:
	}
}

func TestSessionIdleTimeout(t *testing.T) {
	pub := &mockPublisher{}
	logger := slog.Default()

	sess, err := NewSession("test-uuid-timeout", 2*time.Second, pub.publish, logger)
	require.NoError(t, err)

	done := sess.IsDone()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("session should have timed out")
	}
}

func TestSessionWritePublishes(t *testing.T) {
	pub := &mockPublisher{}
	logger := slog.Default()

	sess, err := NewSession("test-uuid-write", 10*time.Second, pub.publish, logger)
	require.NoError(t, err)

	time.Sleep(100 * time.Millisecond)

	err = sess.Send([]byte("echo test-output-123\n"))
	require.NoError(t, err)

	assert.Eventually(t, func() bool {
		return pub.messagesLen() > 0
	}, 2*time.Second, 50*time.Millisecond, "expected output after write")

	for i := 0; i < pub.messagesLen(); i++ {
		pub.mu.Lock()
		_, payload := pub.messages[i].topic, pub.messages[i].payload
		pub.mu.Unlock()

		var pack struct {
			Records []struct {
				Name        string  `json:"n"`
				StringValue *string `json:"vs"`
			} `json:"e"`
		}
		if err := json.Unmarshal([]byte(payload), &pack); err == nil && len(pack.Records) > 0 && pack.Records[0].StringValue != nil {
			if *pack.Records[0].StringValue != "" {
				return
			}
		}
	}
}

func TestSessionTopicFormat(t *testing.T) {
	pub := &mockPublisher{}
	logger := slog.Default()
	uuid := "unique-session-id"

	sess, err := NewSession(uuid, 10*time.Second, pub.publish, logger)
	require.NoError(t, err)

	time.Sleep(100 * time.Millisecond)

	_ = sess.Send([]byte("echo hi\n"))

	assert.Eventually(t, func() bool {
		return pub.messagesLen() > 0
	}, 2*time.Second, 50*time.Millisecond)

	topic, _ := pub.lastMessage()
	assert.Equal(t, "term/"+uuid, topic)
}

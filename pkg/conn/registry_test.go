// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

package conn

import (
	"context"
	"io"
	"log/slog"
	"testing"

	"github.com/absmach/agent"
	agentmocks "github.com/absmach/agent/mocks"
	"github.com/absmach/agent/pkg/senml"
	mqtt "github.com/eclipse/paho.mqtt.golang"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// fakeMessage is a minimal mqtt.Message used to drive handleMsg in tests.
type fakeMessage struct {
	topic   string
	payload []byte
}

func (m fakeMessage) Duplicate() bool   { return false }
func (m fakeMessage) Qos() byte         { return 0 }
func (m fakeMessage) Retained() bool    { return false }
func (m fakeMessage) Topic() string     { return m.topic }
func (m fakeMessage) MessageID() uint16 { return 0 }
func (m fakeMessage) Payload() []byte   { return m.payload }
func (m fakeMessage) Ack()              {}

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// newTestBroker builds a broker backed by mock service and client. The returned
// concrete type lets tests exercise the unexported registry and dispatch paths.
func newTestBroker(t *testing.T, svc *agentmocks.Service) *broker {
	t.Helper()
	client := agentmocks.NewMQTTClient(t)
	b := NewBroker(svc, client, "ctrl-channel", "tenant-1", discardLogger()).(*broker)
	b.ctx = context.Background()
	return b
}

func cmdPack(t *testing.T, uuid, name, value string, extra ...senml.Record) []byte {
	t.Helper()
	records := []senml.Record{{BaseName: uuid + ":", Name: name, StringValue: &value}}
	records = append(records, extra...)
	b, err := senml.EncodeRecords(records)
	require.NoError(t, err)
	return b
}

func TestBrokerRegistryMetadata(t *testing.T) {
	svc := agentmocks.NewService(t)
	b := newTestBroker(t, svc)

	cmds := b.Commands()
	byName := make(map[string]Command, len(cmds))
	for _, c := range cmds {
		byName[c.Name] = c
	}

	// Every command issued by the issue plus the registry helpers must exist.
	for _, name := range []string{control, config, service, term, nred, ping, reset, otaCmd, devices, route, help} {
		c, ok := byName[name]
		assert.Truef(t, ok, "command %q should be registered", name)
		assert.NotEmptyf(t, c.Description, "command %q should have a description", name)
		assert.NotEmptyf(t, c.Usage, "command %q should have usage docs", name)
		assert.Truef(t, c.RequiresAuth, "built-in command %q should require auth", name)
	}

	// Commands() must be sorted by name.
	for i := 1; i < len(cmds); i++ {
		assert.LessOrEqual(t, cmds[i-1].Name, cmds[i].Name)
	}
}

func TestBrokerRegister(t *testing.T) {
	svc := agentmocks.NewService(t)
	b := newTestBroker(t, svc)

	before := len(b.Commands())

	noop := func(context.Context, senml.Pack) error { return nil }

	// A nil handler and an empty name are both rejected.
	b.Register(Command{Name: "ignored-nil"})
	b.Register(Command{Handler: noop})
	assert.Len(t, b.Commands(), before, "invalid registrations must be ignored")

	// A valid registration is added with its metadata preserved.
	b.Register(Command{Name: "custom", Description: "d", Usage: "u", Handler: noop, RequiresAuth: false})
	cmds := b.Commands()
	assert.Len(t, cmds, before+1)

	var custom Command
	for _, c := range cmds {
		if c.Name == "custom" {
			custom = c
		}
	}
	assert.Equal(t, "d", custom.Description)
	assert.False(t, custom.RequiresAuth)

	// RegisterHandler defaults RequiresAuth to true.
	b.RegisterHandler("legacy", noop)
	cmds = b.Commands()
	var legacy Command
	for _, c := range cmds {
		if c.Name == "legacy" {
			legacy = c
		}
	}
	assert.True(t, legacy.RequiresAuth)
}

func TestHandleMsgPerCommandAuth(t *testing.T) {
	const secret = "s3cr3t"

	cases := []struct {
		desc         string
		requiresAuth bool
		withToken    bool
		wantInvoked  bool
	}{
		{desc: "no-auth command dispatches without token", requiresAuth: false, withToken: false, wantInvoked: true},
		{desc: "auth command rejected without token", requiresAuth: true, withToken: false, wantInvoked: false},
		{desc: "auth command dispatches with valid token", requiresAuth: true, withToken: true, wantInvoked: true},
	}

	for _, tc := range cases {
		t.Run(tc.desc, func(t *testing.T) {
			svc := agentmocks.NewService(t)
			// CommandSecret is consulted only for RequiresAuth commands.
			svc.EXPECT().CommandSecret().Return(secret).Maybe()
			b := newTestBroker(t, svc)

			invoked := false
			b.Register(Command{
				Name:         "probe",
				Description:  "test probe",
				Usage:        "probe",
				RequiresAuth: tc.requiresAuth,
				Handler: func(context.Context, senml.Pack) error {
					invoked = true
					return nil
				},
			})

			var extra []senml.Record
			if tc.withToken {
				extra = append(extra, senml.Record{Name: "token", StringValue: new(secret)})
			}
			b.handleMsg(fakeMessage{payload: cmdPack(t, "u1", "probe", "", extra...)})

			assert.Equal(t, tc.wantInvoked, invoked)
		})
	}
}

func TestHandleMsgUnknownCommand(t *testing.T) {
	svc := agentmocks.NewService(t)
	b := newTestBroker(t, svc)
	// No handler, no secret lookup: an unknown command is dropped without panic
	// and without consulting the service.
	b.handleMsg(fakeMessage{payload: cmdPack(t, "u1", "does-not-exist", "")})
}

func TestHelpCommandPublishesRegistry(t *testing.T) {
	svc := agentmocks.NewService(t)
	svc.EXPECT().CommandSecret().Return("").Maybe()

	var published string
	svc.EXPECT().Publish(control, mock.Anything).Run(func(_ string, payload string) {
		published = payload
	}).Return(nil).Once()

	b := newTestBroker(t, svc)
	b.handleMsg(fakeMessage{payload: cmdPack(t, "u1", help, "")})

	require.NotEmpty(t, published, "help must publish a response")
	// The response is a SenML pack whose string value is the JSON command list.
	records, err := senml.Decode([]byte(published))
	require.NoError(t, err)
	require.NotEmpty(t, records)
	require.NotNil(t, records[0].StringValue)
	for _, name := range []string{route, control, help} {
		assert.Contains(t, *records[0].StringValue, name)
	}
}

func TestOTAStatusCommandPublishesStatus(t *testing.T) {
	svc := agentmocks.NewService(t)
	svc.EXPECT().CommandSecret().Return("").Maybe()
	svc.EXPECT().OTAStatus().Return(agent.OTAStatusInfo{Busy: true}).Once()

	var published string
	svc.EXPECT().Publish(control, mock.Anything).Run(func(_ string, payload string) {
		published = payload
	}).Return(nil).Once()

	b := newTestBroker(t, svc)
	b.handleMsg(fakeMessage{payload: cmdPack(t, "u1", otaCmd, otaStatus)})

	require.NotEmpty(t, published)
	records, err := senml.Decode([]byte(published))
	require.NoError(t, err)
	require.NotEmpty(t, records)
	require.NotNil(t, records[0].StringValue)
	assert.Contains(t, *records[0].StringValue, "busy")
}

var _ mqtt.Message = fakeMessage{}

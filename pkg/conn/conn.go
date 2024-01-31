// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

package conn

import (
	"context"
	"fmt"
	"log/slog"
	"regexp"
	"strings"

	"github.com/absmach/agent/pkg/agent"
	"github.com/absmach/magistrala/pkg/messaging"
	"github.com/absmach/senml"
	"robpike.io/filter"

	mqtt "github.com/eclipse/paho.mqtt.golang"
)

const (
	reqTopic  = "req"
	servTopic = "services"
	commands  = "commands"

	control = "control"
	exec    = "exec"
	config  = "config"
	service = "service"
	term    = "term"
)

var channelPartRegExp = regexp.MustCompile(`^channels/([\w\-]+)/messages/services(/[^?]*)?(\?.*)?$`)

var _ MqttBroker = (*broker)(nil)

// MqttBroker represents the MQTT broker.
type MqttBroker interface {
	// Subscribes to given topic and receives events.
	Subscribe(ctx context.Context) error
}

type broker struct {
	svc           agent.Service
	client        mqtt.Client
	logger        *slog.Logger
	messageBroker messaging.PubSub
	channel       string
	ctx           context.Context
}

// NewBroker returns new MQTT broker instance.
func NewBroker(svc agent.Service, client mqtt.Client, chann string, messBroker messaging.PubSub, log *slog.Logger) MqttBroker {
	return &broker{
		svc:           svc,
		client:        client,
		logger:        log,
		messageBroker: messBroker,
		channel:       chann,
	}
}

// Subscribe subscribes to the MQTT message broker.
func (b *broker) Subscribe(ctx context.Context) error {
	topic := fmt.Sprintf("channels/%s/messages/%s", b.channel, reqTopic)
	b.ctx = ctx
	s := b.client.Subscribe(topic, 0, b.handleMsg)
	if err := s.Error(); s.Wait() && err != nil {
		return err
	}
	topic = fmt.Sprintf("channels/%s/messages/%s/#", b.channel, servTopic)
	if b.messageBroker != nil {
		n := b.client.Subscribe(topic, 0, b.handleNatsMsg)
		if err := n.Error(); n.Wait() && err != nil {
			return err
		}
	}

	return nil
}

// handleNatsMsg triggered when new message is received on MQTT broker.
func (b *broker) handleNatsMsg(mc mqtt.Client, msg mqtt.Message) {
	ctx := context.Background()
	message := messaging.Message{
		Payload: msg.Payload(),
	}
	if topic := extractNatsTopic(msg.Topic()); topic != "" {
		if err := b.messageBroker.Publish(ctx, topic, &message); err != nil {
			b.logger.Warn("Error publishing message", slog.Any("error", err))
		}
	}
}

func extractNatsTopic(topic string) string {
	isEmpty := func(s string) bool {
		return (len(s) == 0)
	}
	channelParts := channelPartRegExp.FindStringSubmatch(topic)
	if len(channelParts) < 3 {
		return ""
	}
	filtered := filter.Drop(strings.Split(channelParts[2], "/"), isEmpty).([]string)
	natsTopic := strings.Join(filtered, ".")

	return fmt.Sprintf("%s.%s", commands, natsTopic)
}

// handleMsg triggered when new message is received on MQTT broker.
func (b *broker) handleMsg(mc mqtt.Client, msg mqtt.Message) {
	sm, err := senml.Decode(msg.Payload(), senml.JSON)
	if err != nil {
		b.logger.Warn("SenML decode failed", slog.Any("error", err))
		return
	}

	if len(sm.Records) == 0 {
		b.logger.Error("SenML payload empty", slog.Any("payload", msg.Payload()))
		return
	}
	cmdType := sm.Records[0].Name
	cmdStr := *sm.Records[0].StringValue
	uuid := strings.TrimSuffix(sm.Records[0].BaseName, ":")

	switch cmdType {
	case control:
		b.logger.Info("Control command", slog.String("uuid", uuid), slog.String("command", cmdStr))
		if err := b.svc.Control(uuid, cmdStr); err != nil {
			b.logger.Warn("Control operation failed", slog.Any("error", err))
		}
	case exec:
		b.logger.Info("Execute command", slog.String("uuid", uuid), slog.String("command", cmdStr))
		if _, err := b.svc.Execute(uuid, cmdStr); err != nil {
			b.logger.Warn("Execute operation failed", slog.Any("error", err))
		}
	case config:
		b.logger.Info("Config command", slog.String("uuid", uuid), slog.String("command", cmdStr))
		if err := b.svc.ServiceConfig(b.ctx, uuid, cmdStr); err != nil {
			b.logger.Warn("Config operation failed", slog.Any("error", err))
		}
	case service:
		b.logger.Info("Services view command", slog.String("uuid", uuid), slog.String("command", cmdStr))
		if err := b.svc.ServiceConfig(b.ctx, uuid, cmdStr); err != nil {
			b.logger.Warn("Services view operation failed", slog.Any("error", err))
		}
	case term:
		b.logger.Info("Term view command", slog.String("uuid", uuid), slog.String("command", cmdStr))
		if err := b.svc.Terminal(uuid, cmdStr); err != nil {
			b.logger.Warn("Term view operation failed", slog.Any("error", err))
		}
	}
}

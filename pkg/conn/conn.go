// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

package conn

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"regexp"
	"strings"
	"syscall"

	"github.com/absmach/agent"
	"github.com/absmach/senml"
	mqtt "github.com/eclipse/paho.mqtt.golang"
	"robpike.io/filter"
)

const (
	reqTopic  = "req"
	servTopic = "services"

	control = "control"
	exec    = "exec"
	config  = "config"
	service = "service"
	term    = "term"
	nred    = "nodered"
	ping    = "ping"
	reset   = "reset"
)

var channelPartRegExp = regexp.MustCompile(`^m/([\w\-]+)/c/([\w\-]+)/services(/[^?]*)?(\?.*)?$`)

var _ MqttBroker = (*broker)(nil)

// MqttBroker represents the MQTT broker.
type MqttBroker interface {
	// Subscribes to given topic and receives events.
	Subscribe(ctx context.Context) error
	// Resubscribe re-runs topic subscriptions after a reconnect.
	Resubscribe()
}

type broker struct {
	svc      agent.Service
	client   mqtt.Client
	logger   *slog.Logger
	channel  string
	domainID string
	ctx      context.Context
}

// NewBroker returns new MQTT broker instance.
func NewBroker(svc agent.Service, client mqtt.Client, chann, domainID string, log *slog.Logger) MqttBroker {
	return &broker{
		svc:      svc,
		client:   client,
		logger:   log,
		channel:  chann,
		domainID: domainID,
	}
}

// Subscribe subscribes to the MQTT message broker.
func (b *broker) Subscribe(ctx context.Context) error {
	b.ctx = ctx
	return b.subscribe()
}

func (b *broker) subscribe() error {
	topic := fmt.Sprintf("m/%s/c/%s/%s", b.domainID, b.channel, reqTopic)
	s := b.client.Subscribe(topic, 0, func(_ mqtt.Client, msg mqtt.Message) { b.handleMsg(msg) })
	if err := s.Error(); s.Wait() && err != nil {
		return err
	}
	topic = fmt.Sprintf("m/%s/c/%s/%s/#", b.domainID, b.channel, servTopic)
	n := b.client.Subscribe(topic, 0, func(_ mqtt.Client, msg mqtt.Message) { b.handleBrokerMsg(msg) })
	if err := n.Error(); n.Wait() && err != nil {
		return err
	}
	return nil
}

// Resubscribe re-runs the topic subscriptions after a reconnect.
func (b *broker) Resubscribe() {
	if err := b.subscribe(); err != nil {
		b.logger.Warn("Failed to re-subscribe after reconnect", slog.Any("error", err))
	}
}

// handleBrokerMsg triggered when new message is received on MQTT broker.
func (b *broker) handleBrokerMsg(msg mqtt.Message) {
	if svcname, svctype, ok := extractHeartbeat(msg.Topic(), msg.Payload()); ok {
		if err := b.svc.UpdateLiveness(svcname, svctype); err != nil {
			b.logger.Warn("Error updating service liveness", slog.Any("error", err))
		}
		return
	}

	if topic := extractBrokerTopic(msg.Topic()); topic != "" {
		message := messaging.Message{Payload: msg.Payload()}
		if err := b.messageBroker.Publish(b.ctx, topic, &message); err != nil {
			b.logger.Warn("Error publishing message", slog.Any("error", err))
		}
	}
}

// extractHeartbeat checks whether the MQTT topic is a service heartbeat and,
// if so, returns the service name and type parsed from the topic and SenML payload.
func extractHeartbeat(mqttTopic string, payload []byte) (svcname, svctype string, ok bool) {
	isEmpty := func(s string) bool { return len(s) == 0 }
	channelParts := channelPartRegExp.FindStringSubmatch(mqttTopic)
	if len(channelParts) < 4 || channelParts[3] == "" {
		return "", "", false
	}
	parts := filter.Drop(strings.Split(channelParts[3], "/"), isEmpty).([]string)
	if len(parts) < 2 || parts[len(parts)-1] != "heartbeat" {
		return "", "", false
	}
	return parts[0], parseSvcType(payload), true
}

// parseSvcType extracts the service_type field from a SenML heartbeat payload,
// defaulting to "service" if the payload cannot be parsed.
func parseSvcType(payload []byte) string {
	sm, err := senml.Decode(payload, senml.JSON)
	if err != nil {
		return "service"
	}
	for _, r := range sm.Records {
		if r.Name == "service_type" && r.StringValue != nil {
			return *r.StringValue
		}
	}
	return "service"
}

// handleMsg triggered when new message is received on MQTT broker.
func (b *broker) handleMsg(msg mqtt.Message) {
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
	case nred:
		b.logger.Info("NodeRed command", slog.String("uuid", uuid), slog.String("command", cmdStr))
		if _, err := b.svc.NodeRed(cmdStr); err != nil {
			b.logger.Warn("NodeRed operation failed", slog.Any("error", err))
		}
	case ping:
		b.logger.Info("Ping command")
		if err := b.svc.Ping(); err != nil {
			b.logger.Warn("Ping failed", slog.Any("error", err))
		}
	case reset:
		b.logger.Info("Reset command received, restarting process", slog.String("uuid", uuid))
		if err := syscall.Exec(os.Args[0], os.Args, os.Environ()); err != nil {
			b.logger.Error("Reset failed", slog.Any("error", err))
		}
	}
}

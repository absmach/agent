// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

// Package conn retains only local-service heartbeat discovery on the original
// MQTT connection. Remote management is implemented exclusively by pkg/remote
// using MQTT 5 and JSON-RPC 2.0.
package conn

import (
	"context"
	"fmt"
	"log/slog"
	"regexp"
	"strings"

	"github.com/absmach/agent"
	"github.com/absmach/agent/pkg/senml"
	mqtt "github.com/eclipse/paho.mqtt.golang"
	"robpike.io/filter"
)

const serviceTopic = "services"

var channelPartRegExp = regexp.MustCompile(`^m/([\w\-]+)/c/([\w\-]+)/services(/[^?]*)?(\?.*)?$`)

type MqttBroker interface {
	Subscribe(context.Context) error
	Resubscribe()
}

type broker struct {
	svc      agent.Service
	client   mqtt.Client
	logger   *slog.Logger
	channel  string
	tenantID string
	ctx      context.Context
}

func NewBroker(svc agent.Service, client mqtt.Client, channel, tenantID string, logger *slog.Logger) MqttBroker {
	return &broker{
		svc: svc, client: client, logger: logger, channel: channel, tenantID: tenantID,
	}
}

func (b *broker) Subscribe(ctx context.Context) error {
	b.ctx = ctx
	return b.subscribe()
}

func (b *broker) subscribe() error {
	topic := fmt.Sprintf("m/%s/c/%s/%s/#", b.tenantID, b.channel, serviceTopic)
	token := b.client.Subscribe(topic, 0, func(_ mqtt.Client, message mqtt.Message) {
		if name, serviceType, ok := extractHeartbeat(message.Topic(), message.Payload()); ok {
			if err := b.svc.UpdateLiveness(name, serviceType); err != nil {
				b.logger.Warn("Error updating service liveness", slog.Any("error", err))
			}
		}
	})
	token.Wait()
	return token.Error()
}

func (b *broker) Resubscribe() {
	if err := b.subscribe(); err != nil {
		b.logger.Warn("Failed to re-subscribe after reconnect", slog.Any("error", err))
	}
}

func extractHeartbeat(topic string, payload []byte) (name, serviceType string, ok bool) {
	isEmpty := func(value string) bool { return value == "" }
	channelParts := channelPartRegExp.FindStringSubmatch(topic)
	if len(channelParts) < 4 || channelParts[3] == "" {
		return "", "", false
	}
	parts := filter.Drop(strings.Split(channelParts[3], "/"), isEmpty).([]string)
	if len(parts) < 2 || parts[len(parts)-1] != "heartbeat" {
		return "", "", false
	}
	return parts[len(parts)-2], parseServiceType(payload), true
}

func parseServiceType(payload []byte) string {
	records, err := senml.Decode(payload)
	if err != nil {
		return "service"
	}
	for _, record := range records {
		if record.Name == "service_type" && record.StringValue != nil {
			return *record.StringValue
		}
	}
	return "service"
}

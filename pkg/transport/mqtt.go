// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

package transport

import (
	"context"
	"fmt"

	"github.com/absmach/agent/pkg/conn"
	paho "github.com/eclipse/paho.mqtt.golang"
)

type MQTTPublisher struct {
	client   paho.Client
	domainID string
	channels string
	topic    string
}

func NewMQTTPublisher(client paho.Client, domainID, channels, topic string) *MQTTPublisher {
	return &MQTTPublisher{
		client:   client,
		domainID: domainID,
		channels: channels,
		topic:    topic,
	}
}

func (m *MQTTPublisher) Publish(topic, payload string) error {
	topic = m.buildTopic(topic)
	token := m.client.Publish(topic, 0, false, payload)
	token.Wait()
	return token.Error()
}

func (m *MQTTPublisher) buildTopic(topic string) string {
	if topic == "" {
		topic = m.topic
	}
	switch topic {
	case TopicControl:
		return fmt.Sprintf("m/%s/c/%s/res", m.domainID, m.channels)
	case TopicData:
		return fmt.Sprintf("m/%s/c/%s/gateway/telemetry", m.domainID, m.channels)
	default:
		return fmt.Sprintf("m/%s/c/%s/res/%s", m.domainID, m.channels, topic)
	}
}

type MQTTConnector struct {
	client   paho.Client
	domainID string
	channels string
	topic    string
}

func NewMQTTConnector(client paho.Client, domainID, channels, topic string) *MQTTConnector {
	return &MQTTConnector{
		client:   client,
		domainID: domainID,
		channels: channels,
		topic:    topic,
	}
}

func (m *MQTTConnector) IsConnected() bool {
	return m.client.IsConnected()
}

func (m *MQTTConnector) Publish(topic, payload string) error {
	topic = m.buildTopic(topic)
	token := m.client.Publish(topic, 0, false, payload)
	token.Wait()
	return token.Error()
}

func (m *MQTTConnector) buildTopic(topic string) string {
	if topic == "" {
		topic = m.topic
	}
	switch topic {
	case TopicControl:
		return fmt.Sprintf("m/%s/c/%s/res", m.domainID, m.channels)
	case TopicData:
		return fmt.Sprintf("m/%s/c/%s/gateway/telemetry", m.domainID, m.channels)
	default:
		return fmt.Sprintf("m/%s/c/%s/res/%s", m.domainID, m.channels, topic)
	}
}

type MQTTBroker struct {
	broker    conn.MqttBroker
	connector *MQTTConnector
}

func NewMQTTBroker(broker conn.MqttBroker, client paho.Client, domainID, channels, topic string) *MQTTBroker {
	return &MQTTBroker{
		broker:    broker,
		connector: NewMQTTConnector(client, domainID, channels, topic),
	}
}

func (m *MQTTBroker) Subscribe(ctx context.Context) error {
	return m.broker.Subscribe(ctx)
}

func (m *MQTTBroker) Resubscribe() {
	m.broker.Resubscribe()
}

func (m *MQTTBroker) IsConnected() bool {
	return m.connector.IsConnected()
}

func (m *MQTTBroker) Publish(topic, payload string) error {
	return m.connector.Publish(topic, payload)
}

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
	tenantID string
	ctrlChan string
	dataChan string
	topic    string
}

func NewMQTTPublisher(client paho.Client, tenantID, ctrlChan, dataChan, topic string) *MQTTPublisher {
	return &MQTTPublisher{
		client:   client,
		tenantID: tenantID,
		ctrlChan: ctrlChan,
		dataChan: dataChan,
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
		return fmt.Sprintf("m/%s/c/%s/res", m.tenantID, m.ctrlChan)
	case TopicData:
		return fmt.Sprintf("m/%s/c/%s/gateway/telemetry", m.tenantID, m.dataChan)
	default:
		return fmt.Sprintf("m/%s/c/%s/res/%s", m.tenantID, m.ctrlChan, topic)
	}
}

type MQTTConnector struct {
	client   paho.Client
	tenantID string
	ctrlChan string
	dataChan string
	topic    string
}

func NewMQTTConnector(client paho.Client, tenantID, ctrlChan, dataChan, topic string) *MQTTConnector {
	return &MQTTConnector{
		client:   client,
		tenantID: tenantID,
		ctrlChan: ctrlChan,
		dataChan: dataChan,
		topic:    topic,
	}
}

func (m *MQTTConnector) IsConnected() bool {
	if m.client == nil {
		return false
	}
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
		return fmt.Sprintf("m/%s/c/%s/res", m.tenantID, m.ctrlChan)
	case TopicData:
		return fmt.Sprintf("m/%s/c/%s/gateway/telemetry", m.tenantID, m.dataChan)
	default:
		return fmt.Sprintf("m/%s/c/%s/res/%s", m.tenantID, m.ctrlChan, topic)
	}
}

type MQTTBroker struct {
	broker    conn.MqttBroker
	connector *MQTTConnector
}

func NewMQTTBroker(broker conn.MqttBroker, client paho.Client, tenantID, ctrlChan, dataChan, topic string) *MQTTBroker {
	return &MQTTBroker{
		broker:    broker,
		connector: NewMQTTConnector(client, tenantID, ctrlChan, dataChan, topic),
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

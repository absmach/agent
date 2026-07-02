// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

package transport

import (
	"context"
	"fmt"
	"strings"

	"github.com/absmach/agent/pkg/coap"
	"github.com/plgd-dev/go-coap/v3/message"
	"github.com/plgd-dev/go-coap/v3/message/codes"
)

type CoAPPublisher struct {
	client   *coap.Client
	tenantID string
	ctrlChan string
	dataChan string
	topic    string
	cf       int
}

func NewCoAPPublisher(client *coap.Client, tenantID, ctrlChan, dataChan, topic string, cf int) *CoAPPublisher {
	return &CoAPPublisher{
		client:   client,
		tenantID: tenantID,
		ctrlChan: ctrlChan,
		dataChan: dataChan,
		topic:    topic,
		cf:       cf,
	}
}

func (c *CoAPPublisher) Publish(topic, payload string) error {
	path := c.buildPath(topic)
	cf := c.cf
	if cf == 0 {
		cf = 50
	}

	_, err := c.client.Send(context.Background(), path, codes.POST, message.MediaType(cf), strings.NewReader(payload))
	return err
}

func (c *CoAPPublisher) buildPath(topic string) string {
	if topic == "" {
		topic = c.topic
	}
	switch topic {
	case TopicControl:
		return fmt.Sprintf("/m/%s/c/%s/res", c.tenantID, c.ctrlChan)
	case TopicData:
		return fmt.Sprintf("/m/%s/c/%s/gateway/telemetry", c.tenantID, c.dataChan)
	default:
		return fmt.Sprintf("/m/%s/c/%s/res/%s", c.tenantID, c.ctrlChan, topic)
	}
}

type CoAPConnector struct {
	client *coap.Client
}

func NewCoAPConnector(client *coap.Client) *CoAPConnector {
	return &CoAPConnector{client: client}
}

func (c *CoAPConnector) IsConnected() bool {
	if c.client == nil {
		return false
	}
	return c.client.IsConnected()
}

type CoAPBroker struct {
	broker    *coap.Broker
	publisher *CoAPPublisher
}

func NewCoAPBroker(broker *coap.Broker, client *coap.Client, tenantID, ctrlChan, dataChan, topic string, cf int) *CoAPBroker {
	return &CoAPBroker{
		broker:    broker,
		publisher: NewCoAPPublisher(client, tenantID, ctrlChan, dataChan, topic, cf),
	}
}

func (c *CoAPBroker) Subscribe(ctx context.Context) error {
	return c.broker.Subscribe(ctx)
}

func (c *CoAPBroker) Resubscribe() {
	c.broker.Resubscribe()
}

func (c *CoAPBroker) IsConnected() bool {
	return c.publisher.client.IsConnected()
}

func (c *CoAPBroker) Publish(topic, payload string) error {
	return c.publisher.Publish(topic, payload)
}

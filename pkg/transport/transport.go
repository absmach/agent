// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

package transport

import (
	"context"
)

const (
	TopicControl = "control"
	TopicData    = "data"
)

type Publisher interface {
	Publish(topic, payload string) error
}

type Connector interface {
	IsConnected() bool
}

type Subscriber interface {
	Subscribe(ctx context.Context) error
	Resubscribe()
}

type Broker interface {
	Publisher
	Connector
	Subscriber
}

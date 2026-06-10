// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

package conn

import (
	"context"
	"crypto/subtle"
	"fmt"
	"log/slog"
	"os"
	"regexp"
	"strings"
	"sync"
	"syscall"

	"github.com/absmach/agent"
	"github.com/absmach/agent/pkg/encoder"
	"github.com/absmach/agent/pkg/ota"
	"github.com/absmach/agent/pkg/senml"
	mqtt "github.com/eclipse/paho.mqtt.golang"
	"robpike.io/filter"
)

const (
	reqTopic    = "req"
	servTopic   = "services"
	otaCfgTopic = "ota/cfg"

	control = "control"
	exec    = "exec"
	config  = "config"
	service = "service"
	term    = "term"
	nred    = "nodered"
	ping    = "ping"
	reset   = "reset"
	otaCmd  = "ota"
	devices = "devices"
)

var channelPartRegExp = regexp.MustCompile(`^m/([\w\-]+)/c/([\w\-]+)/services(/[^?]*)?(\?.*)?$`)

// CommandHandler processes a single inbound MQTT command.
// pack contains the full decoded SenML pack; pack.Records[0] is always the
// command record. Multi-record commands (e.g. OTA) use pack.Records[1:].
type CommandHandler func(ctx context.Context, pack senml.Pack) error

var _ MqttBroker = (*broker)(nil)

// MqttBroker represents the MQTT broker.
type MqttBroker interface {
	// Subscribe subscribes to given topic and receives events.
	Subscribe(ctx context.Context) error
	// Resubscribe re-runs topic subscriptions after a reconnect.
	Resubscribe()
	// RegisterHandler registers a CommandHandler for the given command name.
	// Calling RegisterHandler with an existing name replaces the previous handler.
	RegisterHandler(name string, h CommandHandler)
}

type broker struct {
	svc      agent.Service
	client   mqtt.Client
	logger   *slog.Logger
	channel  string
	domainID string
	ctx      context.Context
	handlers map[string]CommandHandler
	mu       sync.RWMutex
}

// NewBroker returns a new MQTT broker instance with all built-in command
// handlers pre-registered.
func NewBroker(svc agent.Service, client mqtt.Client, chann, domainID string, log *slog.Logger) MqttBroker {
	b := &broker{
		svc:      svc,
		client:   client,
		logger:   log,
		channel:  chann,
		domainID: domainID,
		handlers: make(map[string]CommandHandler),
	}
	b.registerBuiltins()
	return b
}

// RegisterHandler registers a CommandHandler for name, replacing any existing one.
// A nil handler is rejected to avoid panics when a matching command arrives later.
func (b *broker) RegisterHandler(name string, h CommandHandler) {
	if h == nil {
		b.logger.Warn("RegisterHandler called with nil handler", slog.String("name", name))
		return
	}
	b.mu.Lock()
	b.handlers[name] = h
	b.mu.Unlock()
}

// registerBuiltins wires the built-in command set into the handler registry.
func (b *broker) registerBuiltins() {
	svc := b.svc
	log := b.logger

	b.RegisterHandler(control, func(ctx context.Context, pack senml.Pack) error {
		uuid, cmdStr := extractCmd(pack)
		log.Info("Control command", slog.String("uuid", uuid), slog.String("command", cmdStr))
		return svc.Control(uuid, cmdStr)
	})

	b.RegisterHandler(exec, func(ctx context.Context, pack senml.Pack) error {
		uuid, cmdStr := extractCmd(pack)
		log.Info("Execute command", slog.String("uuid", uuid), slog.String("command", cmdStr))
		_, err := svc.Execute(uuid, cmdStr)
		return err
	})

	b.RegisterHandler(config, func(ctx context.Context, pack senml.Pack) error {
		uuid, cmdStr := extractCmd(pack)
		log.Info("Config command", slog.String("uuid", uuid), slog.String("command", cmdStr))
		return svc.ServiceConfig(ctx, uuid, cmdStr)
	})

	b.RegisterHandler(service, func(ctx context.Context, pack senml.Pack) error {
		uuid, cmdStr := extractCmd(pack)
		log.Info("Services view command", slog.String("uuid", uuid), slog.String("command", cmdStr))
		return svc.ServiceConfig(ctx, uuid, cmdStr)
	})

	b.RegisterHandler(term, func(ctx context.Context, pack senml.Pack) error {
		uuid, cmdStr := extractCmd(pack)
		log.Info("Term command", slog.String("uuid", uuid), slog.String("command", cmdStr))
		return svc.Terminal(uuid, cmdStr)
	})

	b.RegisterHandler(nred, func(ctx context.Context, pack senml.Pack) error {
		uuid, cmdStr := extractCmd(pack)
		log.Info("NodeRed command", slog.String("uuid", uuid), slog.String("command", cmdStr))
		_, err := svc.NodeRed(cmdStr)
		return err
	})

	b.RegisterHandler(ping, func(ctx context.Context, pack senml.Pack) error {
		log.Info("Ping command")
		return svc.Ping()
	})

	b.RegisterHandler(reset, func(ctx context.Context, pack senml.Pack) error {
		uuid, _ := extractCmd(pack)
		log.Info("Reset command received, performing graceful shutdown", slog.String("uuid", uuid))
		svc.Shutdown()
		if err := syscall.Exec(os.Args[0], os.Args, os.Environ()); err != nil {
			log.Error("Reset failed", slog.Any("error", err))
			return err
		}
		return nil
	})

	b.RegisterHandler(otaCmd, func(ctx context.Context, pack senml.Pack) error {
		uuid, cmdStr := extractCmd(pack)
		if cmdStr == "abort" {
			log.Info("OTA abort command", slog.String("uuid", uuid))
			if err := svc.OTAAbort(); err != nil {
				log.Warn("OTA abort failed", slog.Any("error", err))
				return err
			}
			return nil
		}
		trigger, err := ota.TriggerFromRecords(pack.Records[1:])
		if err != nil {
			return err
		}
		log.Info("OTA command", slog.String("uuid", uuid), slog.String("url", trigger.URL))
		go func() {
			if err := svc.OTA(context.WithoutCancel(ctx), trigger.URL, trigger.SHA256Hex, trigger.Size); err != nil {
				log.Warn("OTA operation failed", slog.Any("error", err))
			}
		}()
		return nil
	})

	b.handlers[devices] = func(ctx context.Context, pack senml.Pack) error {
		uuid, cmdStr := extractCmd(pack)
		log.Info("Devices command", slog.String("uuid", uuid), slog.String("command", cmdStr))
		if err := svc.DeviceManager(ctx, uuid, cmdStr); err != nil {
			if payload, encErr := encoder.EncodeSenML(uuid, devices, err.Error()); encErr == nil {
				if pubErr := svc.Publish("control", string(payload)); pubErr != nil {
					log.Warn("Failed to publish DeviceManager error response", slog.Any("error", pubErr))
				}
			}
			return err
		}
		return nil
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
	topic = fmt.Sprintf("m/%s/c/%s/%s", b.domainID, b.channel, otaCfgTopic)
	o := b.client.Subscribe(topic, 0, func(_ mqtt.Client, msg mqtt.Message) { b.handleOTACfgMsg(b.ctx, msg) })
	if err := o.Error(); o.Wait() && err != nil {
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
	}
}

// handleOTACfgMsg handles OTA trigger messages arriving on the ota/cfg topic.
// The payload is a SenML pack with url, hash, and size records.
// If a command secret is configured, the pack must include a valid token record.
func (b *broker) handleOTACfgMsg(ctx context.Context, msg mqtt.Message) {
	records, err := senml.Decode(msg.Payload())
	if err != nil {
		b.logger.Warn("OTA cfg SenML decode failed", slog.Any("error", err))
		return
	}
	if len(records) == 0 {
		b.logger.Error("OTA cfg SenML payload empty")
		return
	}

	commandSecret := b.svc.CommandSecret()
	if commandSecret != "" {
		if !authorizeCommand(records, commandSecret) {
			b.logger.Warn("OTA cfg rejected: invalid or missing token")
			return
		}
	}

	trigger, err := ota.TriggerFromRecords(records)
	if err != nil {
		b.logger.Warn("OTA cfg trigger parse failed", slog.Any("error", err))
		return
	}

	b.logger.Info("OTA cfg command", slog.String("url", trigger.URL))
	go func(ctx context.Context) {
		if err := b.svc.OTA(ctx, trigger.URL, trigger.SHA256Hex, trigger.Size); err != nil {
			b.logger.Warn("OTA cfg operation failed", slog.Any("error", err))
		}
	}(context.WithoutCancel(ctx))
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
	return parts[len(parts)-2], parseSvcType(payload), true
}

// parseSvcType extracts the service_type field from a SenML heartbeat payload,
// defaulting to "service" if the payload cannot be parsed.
func parseSvcType(payload []byte) string {
	records, err := senml.Decode(payload)
	if err != nil {
		return "service"
	}
	for _, r := range records {
		if r.Name == "service_type" && r.StringValue != nil {
			return *r.StringValue
		}
	}
	return "service"
}

// handleMsg dispatches an inbound MQTT command to the registered handler.
func (b *broker) handleMsg(msg mqtt.Message) {
	records, err := senml.Decode(msg.Payload())
	if err != nil {
		b.logger.Warn("SenML decode failed", slog.Any("error", err))
		return
	}
	if len(records) == 0 {
		b.logger.Error("SenML payload empty", slog.Any("payload", msg.Payload()))
		return
	}

	commandSecret := b.svc.CommandSecret()
	if commandSecret != "" {
		if !authorizeCommand(records, commandSecret) {
			b.logger.Warn("Command rejected: invalid or missing token")
			return
		}
	}

	cmdType := records[0].Name

	b.mu.RLock()
	h, ok := b.handlers[cmdType]
	b.mu.RUnlock()

	if !ok {
		b.logger.Warn("no handler registered for command", slog.String("command", cmdType))
		return
	}
	sm := senml.Pack{Records: records}
	if err := h(b.ctx, sm); err != nil {
		b.logger.Warn("command handler failed", slog.String("command", cmdType), slog.Any("error", err))
	}
}

// authorizeCommand checks whether the SenML pack contains a valid token record.
// Returns false if the token is missing or does not match the stored secret.
// Uses constant-time comparison to prevent timing attacks.
func authorizeCommand(records []senml.Record, secret string) bool {
	for _, r := range records {
		if r.Name == "token" && r.StringValue != nil {
			return subtle.ConstantTimeCompare([]byte(*r.StringValue), []byte(secret)) == 1
		}
	}
	return false
}

// extractCmd returns the uuid and string value from the first SenML record.
func extractCmd(pack senml.Pack) (uuid, cmdStr string) {
	if len(pack.Records) == 0 {
		return "", ""
	}
	uuid = strings.TrimSuffix(pack.Records[0].BaseName, ":")
	if sv := pack.Records[0].StringValue; sv != nil {
		cmdStr = *sv
	}
	return uuid, cmdStr
}

// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

package coap

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
	"time"

	"github.com/absmach/agent"
	"github.com/absmach/agent/pkg/encoder"
	"github.com/absmach/agent/pkg/ota"
	"github.com/absmach/agent/pkg/senml"
	"github.com/plgd-dev/go-coap/v3/message"
	"github.com/plgd-dev/go-coap/v3/message/codes"
	"robpike.io/filter"
)

const (
	reqTopic       = "req"
	servTopic      = "services"
	otaCfgTopic    = "ota/cfg"
	otaStatusTopic = "ota/status"

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

type CommandHandler func(ctx context.Context, pack senml.Pack) error

type Broker struct {
	svc      agent.Service
	client   *Client
	logger   *slog.Logger
	channel  string
	domainID string
	ctx      context.Context
	handlers map[string]CommandHandler
	mu       sync.RWMutex
}

func NewBroker(svc agent.Service, client *Client, channel, domainID string, logger *slog.Logger) *Broker {
	b := &Broker{
		svc:      svc,
		client:   client,
		logger:   logger,
		channel:  channel,
		domainID: domainID,
		handlers: make(map[string]CommandHandler),
	}
	b.registerBuiltins()
	return b
}

func (b *Broker) RegisterHandler(name string, h CommandHandler) {
	if h == nil {
		b.logger.Warn("RegisterHandler called with nil handler", slog.String("name", name))
		return
	}
	b.mu.Lock()
	b.handlers[name] = h
	b.mu.Unlock()
}

func (b *Broker) registerBuiltins() {
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

	b.RegisterHandler(devices, func(ctx context.Context, pack senml.Pack) error {
		uuid, cmdStr := extractCmd(pack)
		log.Info("Devices command", slog.String("uuid", uuid), slog.String("command", cmdStr))
		if err := svc.DeviceManager(ctx, uuid, cmdStr); err != nil {
			if payload, encErr := encoder.EncodeSenML(uuid, devices, err.Error()); encErr == nil {
				if pubErr := b.publish(ctx, "control", string(payload)); pubErr != nil {
					log.Warn("Failed to publish DeviceManager error response", slog.Any("error", pubErr))
				}
			}
			return err
		}
		return nil
	})
}

func (b *Broker) Subscribe(ctx context.Context) error {
	b.ctx = ctx

	reqPath := b.buildPath(reqTopic)
	servPath := b.buildPath(servTopic + "/#")
	otaCfgPath := b.buildPath(otaCfgTopic)

	if _, err := b.client.Observe(ctx, reqPath, b.handleMessage); err != nil {
		return fmt.Errorf("failed to observe %s: %w", reqPath, err)
	}

	if _, err := b.client.Observe(ctx, servPath, b.handleBrokerMessage); err != nil {
		return fmt.Errorf("failed to observe %s: %w", servPath, err)
	}

	if _, err := b.client.Observe(ctx, otaCfgPath, b.handleOTACfgMessage); err != nil {
		return fmt.Errorf("failed to observe %s: %w", otaCfgPath, err)
	}

	b.logger.Info("CoAP broker subscribed to topics",
		slog.String("req", reqPath),
		slog.String("services", servPath),
		slog.String("ota_cfg", otaCfgPath))

	return nil
}

func (b *Broker) Resubscribe() {
	b.logger.Info("Resubscribing CoAP broker")
	if err := b.Subscribe(b.ctx); err != nil {
		b.logger.Warn("Failed to re-subscribe", slog.Any("error", err))
	}
}

func (b *Broker) handleBrokerMessage(payload []byte) {
	path, _ := extractPathFromPayload(payload)
	if svcname, svctype, ok := extractHeartbeat(path, payload); ok {
		if err := b.svc.UpdateLiveness(svcname, svctype); err != nil {
			b.logger.Warn("Error updating service liveness", slog.Any("error", err))
		}
	}
}

func (b *Broker) handleOTACfgMessage(payload []byte) {
	records, err := senml.Decode(payload)
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
	}(context.WithoutCancel(b.ctx))
}

func (b *Broker) handleMessage(payload []byte) {
	records, err := senml.Decode(payload)
	if err != nil {
		b.logger.Warn("SenML decode failed", slog.Any("error", err))
		return
	}
	if len(records) == 0 {
		b.logger.Error("SenML payload empty")
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

func (b *Broker) publish(ctx context.Context, topic, payload string) error {
	path := b.buildPath(topic)
	reader := strings.NewReader(payload)
	cf := message.MediaType(b.client.config.ContentFormat)

	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	if _, err := b.client.Send(ctx, path, codes.POST, cf, reader); err != nil {
		return fmt.Errorf("failed to publish to %s: %w", path, err)
	}

	return nil
}

func (b *Broker) buildPath(topic string) string {
	return fmt.Sprintf("/m/%s/c/%s/%s", b.domainID, b.channel, topic)
}

func authorizeCommand(records []senml.Record, secret string) bool {
	for _, r := range records {
		if r.Name == "token" && r.StringValue != nil {
			return subtle.ConstantTimeCompare([]byte(*r.StringValue), []byte(secret)) == 1
		}
	}
	return false
}

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

func extractPathFromPayload(payload []byte) (string, bool) {
	records, err := senml.Decode(payload)
	if err != nil {
		return "", false
	}
	if len(records) == 0 {
		return "", false
	}

	if records[0].StringValue != nil {
		return *records[0].StringValue, true
	}

	return "", false
}

func extractHeartbeat(path string, payload []byte) (svcname, svctype string, ok bool) {
	isEmpty := func(s string) bool { return len(s) == 0 }
	channelParts := channelPartRegExp.FindStringSubmatch(path)
	if len(channelParts) < 4 || channelParts[3] == "" {
		return "", "", false
	}
	parts := filter.Drop(strings.Split(channelParts[3], "/"), isEmpty).([]string)
	if len(parts) < 2 || parts[len(parts)-1] != "heartbeat" {
		return "", "", false
	}
	return parts[len(parts)-2], parseSvcType(payload), true
}

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

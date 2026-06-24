// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

package conn

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"regexp"
	"sort"
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

// otaDataPrep holds the expected hash and size for firmware arriving on the ota data topic.
type otaDataPrep struct {
	hash string
	size uint64
}

const (
	reqTopic     = "req"
	servTopic    = "services"
	otaCfgTopic  = "ota/cfg"
	otaDataTopic = "ota"

	control = "control"
	config  = "config"
	service = "service"
	term    = "term"
	nred    = "nodered"
	ping    = "ping"
	reset   = "reset"
	otaCmd  = "ota"
	devices = "devices"
	route   = "route"
	help    = "help"

	otaStatus = "status"
	otaAbort  = "abort"
)

var channelPartRegExp = regexp.MustCompile(`^m/([\w\-]+)/c/([\w\-]+)/services(/[^?]*)?(\?.*)?$`)

// CommandHandler processes a single inbound MQTT command.
// pack contains the full decoded SenML pack; pack.Records[0] is always the
// command record. Multi-record commands (e.g. OTA) use pack.Records[1:].
type CommandHandler func(ctx context.Context, pack senml.Pack) error

// Command describes a registered command together with its handler and
// human-readable metadata. The metadata is surfaced by the built-in help
// command so operators can discover the available command surface at runtime.
type Command struct {
	// Name is the SenML record name that selects this command.
	Name string
	// Description is a one-line summary of what the command does.
	Description string
	// Usage documents the argument format, e.g. "exec,<command>[,arg...]".
	Usage string
	// Handler processes the decoded command pack.
	Handler CommandHandler
	// RequiresAuth, when true, rejects the command if a command secret is
	// configured and the pack lacks a valid token. Authorization is therefore
	// enforced per command rather than as a single global gate.
	RequiresAuth bool
}

var _ MqttBroker = (*broker)(nil)

// MqttBroker represents the MQTT broker.
type MqttBroker interface {
	// Subscribe subscribes to given topic and receives events.
	Subscribe(ctx context.Context) error
	// Resubscribe re-runs topic subscriptions after a reconnect.
	Resubscribe()
	// RegisterHandler registers a CommandHandler for the given command name.
	// Calling RegisterHandler with an existing name replaces the previous handler.
	// The command is registered with RequiresAuth set to true.
	RegisterHandler(name string, h CommandHandler)
	// Register adds a Command (with metadata) to the registry, replacing any
	// existing command registered under the same name.
	Register(cmd Command)
	// Commands returns all registered commands sorted by name.
	Commands() []Command
}

type broker struct {
	svc       agent.Service
	client    mqtt.Client
	logger    *slog.Logger
	channel   string
	tenantID  string
	ctx       context.Context
	commands  map[string]Command
	mu        sync.RWMutex
	otaPrep   *otaDataPrep
	otaPrepMu sync.Mutex
}

// NewBroker returns a new MQTT broker instance with all built-in command
// handlers pre-registered.
func NewBroker(svc agent.Service, client mqtt.Client, chann, tenantID string, log *slog.Logger) MqttBroker {
	b := &broker{
		svc:      svc,
		client:   client,
		logger:   log,
		channel:  chann,
		tenantID: tenantID,
		commands: make(map[string]Command),
	}
	b.registerBuiltins()
	return b
}

// RegisterHandler registers a CommandHandler for name, replacing any existing one.
// A nil handler is rejected to avoid panics when a matching command arrives later.
// The command is registered with RequiresAuth set to true.
func (b *broker) RegisterHandler(name string, h CommandHandler) {
	if h == nil {
		b.logger.Warn("RegisterHandler called with nil handler", slog.String("name", name))
		return
	}
	b.Register(Command{Name: name, Handler: h, RequiresAuth: true})
}

// Register adds cmd to the registry, replacing any existing command with the
// same name. A command with a nil handler or empty name is rejected.
func (b *broker) Register(cmd Command) {
	if cmd.Handler == nil {
		b.logger.Warn("Register called with nil handler", slog.String("name", cmd.Name))
		return
	}
	if cmd.Name == "" {
		b.logger.Warn("Register called with empty command name")
		return
	}
	b.mu.Lock()
	b.commands[cmd.Name] = cmd
	b.mu.Unlock()
}

// Commands returns all registered commands sorted by name.
func (b *broker) Commands() []Command {
	b.mu.RLock()
	out := make([]Command, 0, len(b.commands))
	for _, c := range b.commands {
		out = append(out, c)
	}
	b.mu.RUnlock()
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// registerBuiltins wires the built-in command set into the command registry.
// Every built-in declares RequiresAuth: true, preserving the requirement that
// commands carry a valid token whenever a command secret is configured.
func (b *broker) registerBuiltins() {
	svc := b.svc
	log := b.logger

	b.Register(Command{
		Name:         control,
		Description:  "Agent lifecycle control and Node-RED passthrough",
		Usage:        "control,<stop|start|reload|status|nodered-*>",
		RequiresAuth: true,
		Handler: func(_ context.Context, pack senml.Pack) error {
			uuid, cmdStr := extractCmd(pack)
			log.Info("Control command", slog.String("uuid", uuid), slog.String("command", cmdStr))
			return svc.Control(uuid, cmdStr)
		},
	})

	b.Register(Command{
		Name:         config,
		Description:  "View or modify runtime configuration",
		Usage:        "config,<view|get|set|save|reset>[,args...]",
		RequiresAuth: true,
		Handler: func(ctx context.Context, pack senml.Pack) error {
			uuid, cmdStr := extractCmd(pack)
			log.Info("Config command", slog.String("uuid", uuid), slog.String("command", cmdStr))
			return svc.ServiceConfig(ctx, uuid, cmdStr)
		},
	})

	b.Register(Command{
		Name:         service,
		Description:  "View registered local services",
		Usage:        "service,view",
		RequiresAuth: true,
		Handler: func(ctx context.Context, pack senml.Pack) error {
			uuid, cmdStr := extractCmd(pack)
			log.Info("Services view command", slog.String("uuid", uuid), slog.String("command", cmdStr))
			return svc.ServiceConfig(ctx, uuid, cmdStr)
		},
	})

	b.Register(Command{
		Name:         term,
		Description:  "Interactive terminal session control",
		Usage:        "term,<base64(open|close|c,<data>)>",
		RequiresAuth: true,
		Handler: func(_ context.Context, pack senml.Pack) error {
			uuid, cmdStr := extractCmd(pack)
			log.Info("Term command", slog.String("uuid", uuid), slog.String("command", cmdStr))
			return svc.Terminal(uuid, cmdStr)
		},
	})

	b.Register(Command{
		Name:         nred,
		Description:  "Node-RED flow management",
		Usage:        "nodered,<nodered-deploy|nodered-add-flow|nodered-flows|nodered-state|nodered-ping>[,<base64-flow>]",
		RequiresAuth: true,
		Handler: func(_ context.Context, pack senml.Pack) error {
			uuid, cmdStr := extractCmd(pack)
			log.Info("NodeRed command", slog.String("uuid", uuid), slog.String("command", cmdStr))
			resp, err := svc.NodeRed(cmdStr)
			if err != nil {
				if payload, encErr := encoder.EncodeSenML(uuid, nred, err.Error()); encErr == nil {
					if pubErr := svc.Publish(control, string(payload)); pubErr != nil {
						log.Warn("Failed to publish NodeRed error response", slog.Any("error", pubErr))
					}
				}
				return err
			}
			if payload, encErr := encoder.EncodeSenML(uuid, nred, resp); encErr == nil {
				if pubErr := svc.Publish(control, string(payload)); pubErr != nil {
					log.Warn("Failed to publish NodeRed response", slog.Any("error", pubErr))
				}
			}
			return nil
		},
	})

	b.Register(Command{
		Name:         ping,
		Description:  "Publish an immediate health heartbeat",
		Usage:        "ping",
		RequiresAuth: true,
		Handler: func(_ context.Context, _ senml.Pack) error {
			log.Info("Ping command")
			return svc.Ping()
		},
	})

	b.Register(Command{
		Name:         reset,
		Description:  "Reboot/reset the agent process",
		Usage:        "reset,<graceful|immediate|watchdog|now>",
		RequiresAuth: true,
		Handler: func(ctx context.Context, pack senml.Pack) error {
			uuid, cmdStr := extractCmd(pack)
			mode := agent.ResetGraceful
			if cmdStr != "" {
				mode = cmdStr
			}
			log.Info("Reset command received", slog.String("uuid", uuid), slog.String("mode", mode))
			if err := svc.Reset(ctx, mode); err != nil {
				log.Error("Reset failed", slog.Any("error", err))
				return err
			}
			switch mode {
			case agent.ResetGraceful, agent.ResetImmediate, agent.ResetNow:
				log.Info("Re-executing agent binary", slog.String("mode", mode))
				if err := syscall.Exec(os.Args[0], os.Args, os.Environ()); err != nil {
					log.Error("Re-exec failed", slog.Any("error", err))
					return err
				}
			case agent.ResetWatchdog:
				log.Info("Watchdog reset delegated to health supervisor")
			}
			return nil
		},
	})

	b.Register(Command{
		Name:         otaCmd,
		Description:  "Trigger, query, or abort an OTA update",
		Usage:        "ota,<status|abort> | ota with url/hash/size records",
		RequiresAuth: true,
		Handler: func(ctx context.Context, pack senml.Pack) error {
			uuid, cmdStr := extractCmd(pack)
			switch cmdStr {
			case otaAbort:
				log.Info("OTA abort command", slog.String("uuid", uuid))
				if err := svc.OTAAbort(); err != nil {
					log.Warn("OTA abort failed", slog.Any("error", err))
					return err
				}
				return nil
			case otaStatus:
				log.Info("OTA status command", slog.String("uuid", uuid))
				return b.publishOTAStatus(uuid)
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
		},
	})

	b.Register(Command{
		Name:         devices,
		Description:  "Manage downstream devices",
		Usage:        "devices,<list|add|remove|get|seen|open|close|read|write>[,args...]",
		RequiresAuth: true,
		Handler: func(ctx context.Context, pack senml.Pack) error {
			uuid, cmdStr := extractCmd(pack)
			log.Info("Devices command", slog.String("uuid", uuid), slog.String("command", cmdStr))
			if err := svc.DeviceManager(ctx, uuid, cmdStr); err != nil {
				if payload, encErr := encoder.EncodeSenML(uuid, devices, err.Error()); encErr == nil {
					if pubErr := svc.Publish(control, string(payload)); pubErr != nil {
						log.Warn("Failed to publish DeviceManager error response", slog.Any("error", pubErr))
					}
				}
				return err
			}
			return nil
		},
	})

	b.Register(Command{
		Name:         route,
		Description:  "Forward a payload to a downstream device interface",
		Usage:        "route,<device_id>,<hex_payload>[,<read_bytes>]",
		RequiresAuth: true,
		Handler: func(ctx context.Context, pack senml.Pack) error {
			uuid, cmdStr := extractCmd(pack)
			log.Info("Route command", slog.String("uuid", uuid), slog.String("command", cmdStr))
			if err := svc.Route(ctx, uuid, cmdStr); err != nil {
				if payload, encErr := encoder.EncodeSenML(uuid, route, err.Error()); encErr == nil {
					if pubErr := svc.Publish(control, string(payload)); pubErr != nil {
						log.Warn("Failed to publish Route error response", slog.Any("error", pubErr))
					}
				}
				return err
			}
			return nil
		},
	})

	b.Register(Command{
		Name:         help,
		Description:  "List available commands and their usage",
		Usage:        "help",
		RequiresAuth: true,
		Handler: func(_ context.Context, pack senml.Pack) error {
			uuid, _ := extractCmd(pack)
			log.Info("Help command", slog.String("uuid", uuid))
			return b.publishHelp(uuid)
		},
	})
}

// publishHelp marshals the registered command metadata to JSON and publishes it
// as the response to a help command.
func (b *broker) publishHelp(uuid string) error {
	type cmdInfo struct {
		Name        string `json:"name"`
		Description string `json:"description"`
		Usage       string `json:"usage"`
	}
	cmds := b.Commands()
	infos := make([]cmdInfo, 0, len(cmds))
	for _, c := range cmds {
		infos = append(infos, cmdInfo{Name: c.Name, Description: c.Description, Usage: c.Usage})
	}
	j, err := json.Marshal(infos)
	if err != nil {
		return fmt.Errorf("help: marshal commands: %w", err)
	}
	payload, err := encoder.EncodeSenML(uuid, help, string(j))
	if err != nil {
		return fmt.Errorf("help: encode response: %w", err)
	}
	return b.svc.Publish(control, string(payload))
}

// publishOTAStatus marshals the current OTA status to JSON and publishes it as
// the response to an ota,status command.
func (b *broker) publishOTAStatus(uuid string) error {
	j, err := json.Marshal(b.svc.OTAStatus())
	if err != nil {
		return fmt.Errorf("ota status: marshal: %w", err)
	}
	payload, err := encoder.EncodeSenML(uuid, otaCmd, string(j))
	if err != nil {
		return fmt.Errorf("ota status: encode response: %w", err)
	}
	return b.svc.Publish(control, string(payload))
}

// Subscribe subscribes to the MQTT message broker.
func (b *broker) Subscribe(ctx context.Context) error {
	b.ctx = ctx
	return b.subscribe()
}

func (b *broker) subscribe() error {
	topic := fmt.Sprintf("m/%s/c/%s/%s", b.tenantID, b.channel, reqTopic)
	s := b.client.Subscribe(topic, 0, func(_ mqtt.Client, msg mqtt.Message) { b.handleMsg(msg) })
	if err := s.Error(); s.Wait() && err != nil {
		return err
	}
	topic = fmt.Sprintf("m/%s/c/%s/%s/#", b.tenantID, b.channel, servTopic)
	n := b.client.Subscribe(topic, 0, func(_ mqtt.Client, msg mqtt.Message) { b.handleBrokerMsg(msg) })
	if err := n.Error(); n.Wait() && err != nil {
		return err
	}
	topic = fmt.Sprintf("m/%s/c/%s/%s", b.tenantID, b.channel, otaCfgTopic)
	o := b.client.Subscribe(topic, 0, func(_ mqtt.Client, msg mqtt.Message) { b.handleOTACfgMsg(b.ctx, msg) })
	if err := o.Error(); o.Wait() && err != nil {
		return err
	}
	topic = fmt.Sprintf("m/%s/c/%s/%s", b.tenantID, b.channel, otaDataTopic)
	d := b.client.Subscribe(topic, 0, func(_ mqtt.Client, msg mqtt.Message) { b.handleOTADataMsg(b.ctx, msg) })
	if err := d.Error(); d.Wait() && err != nil {
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
// When url is present, firmware is fetched via HTTP. When url is absent, the
// hash and size are stored so the next message on the ota data topic can be
// installed directly.
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

	cfg := ota.ParseCfgFromRecords(records)

	if cfg.URL != "" {
		// A URL trigger supersedes any pending data-path priming so a later
		// stray ota data message can't install against a stale hash.
		b.otaPrepMu.Lock()
		b.otaPrep = nil
		b.otaPrepMu.Unlock()
		b.logger.Info("OTA cfg HTTP download", slog.String("url", cfg.URL))
		go func(ctx context.Context) {
			if err := b.svc.OTA(ctx, cfg.URL, cfg.SHA256Hex, cfg.Size); err != nil {
				b.logger.Warn("OTA cfg HTTP operation failed", slog.Any("error", err))
			}
		}(context.WithoutCancel(ctx))
		return
	}

	if cfg.SHA256Hex == "" {
		b.logger.Warn("OTA cfg has no url and no hash; ignoring")
		return
	}

	b.otaPrepMu.Lock()
	b.otaPrep = &otaDataPrep{hash: cfg.SHA256Hex, size: cfg.Size}
	b.otaPrepMu.Unlock()
	b.logger.Info("OTA cfg primed for MQTT data delivery", slog.String("hash", cfg.SHA256Hex), slog.Uint64("size", cfg.Size))
}

// handleOTADataMsg receives firmware binary on the ota data topic and installs it.
// A prior ota/cfg message without a url must have primed the expected hash and size.
//
// The data topic carries no token of its own; trust rests entirely on the prior
// authenticated ota/cfg priming and on OTAFromData verifying the payload against
// the primed SHA-256 hash before install. Payloads that don't match are rejected.
func (b *broker) handleOTADataMsg(ctx context.Context, msg mqtt.Message) {
	b.otaPrepMu.Lock()
	prep := b.otaPrep
	b.otaPrep = nil
	b.otaPrepMu.Unlock()

	if prep == nil {
		b.logger.Warn("OTA data received with no prior cfg priming; ignoring")
		return
	}

	data := msg.Payload()
	if prep.size > 0 && uint64(len(data)) != prep.size {
		b.logger.Warn("OTA data size mismatch",
			slog.Int("got", len(data)),
			slog.Uint64("expected", prep.size))
		return
	}

	b.logger.Info("OTA data received via MQTT", slog.Int("bytes", len(data)))
	go func(ctx context.Context) {
		if err := b.svc.OTAFromData(ctx, data, prep.hash); err != nil {
			b.logger.Warn("OTA data operation failed", slog.Any("error", err))
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

	cmdType := records[0].Name

	b.mu.RLock()
	cmd, ok := b.commands[cmdType]
	b.mu.RUnlock()

	if !ok {
		b.logger.Warn("no handler registered for command", slog.String("command", cmdType))
		return
	}

	// Authorization is enforced per command: a command with RequiresAuth set is
	// rejected unless it carries a valid token whenever a command secret is set.
	if cmd.RequiresAuth {
		if commandSecret := b.svc.CommandSecret(); commandSecret != "" {
			if !authorizeCommand(records, commandSecret) {
				b.logger.Warn("Command rejected: invalid or missing token", slog.String("command", cmdType))
				return
			}
		}
	}

	sm := senml.Pack{Records: records}
	if err := cmd.Handler(b.ctx, sm); err != nil {
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

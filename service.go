// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/url"
	"os"
	"regexp"
	"runtime/metrics"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	cfgstore "github.com/absmach/agent/pkg/config"
	"github.com/absmach/agent/pkg/devicemgr"
	"github.com/absmach/agent/pkg/iface"
	"github.com/absmach/agent/pkg/nodered"
	"github.com/absmach/agent/pkg/ota"
	"github.com/absmach/agent/pkg/senml"
	"github.com/absmach/agent/pkg/terminal"
	"github.com/absmach/magistrala/pkg/errors"
	paho "github.com/eclipse/paho.mqtt.golang"
	toml "github.com/pelletier/go-toml"
)

const (
	// Reset modes for the Reset method.
	ResetGraceful  = "graceful"
	ResetImmediate = "immediate"
	ResetWatchdog  = "watchdog"
	ResetNow       = "now"

	Commands = "commands"
	config   = "config"

	view = "view"
	save = "save"

	char    = "char"
	open    = "open"
	close   = "close"
	control = "control"
	data    = "data"

	// control subcommands for agent lifecycle management.
	ctrlStop   = "stop"
	ctrlStart  = "start"
	ctrlReload = "reload"
	ctrlStatus = "status"

	export = "export"

	KeyLogLevel               = "log_level"
	KeyHeartbeatInterval      = "heartbeat_interval"
	KeyTelemetryInterval      = "telemetry_interval"
	KeyTerminalSessionTimeout = "terminal_session_timeout"
	KeyCommandSecret          = "command_secret"
	KeyBsValid                = "bs_valid"
	keyLogLevel               = KeyLogLevel
	keyHeartbeatInterval      = KeyHeartbeatInterval
	keyTelemetryInterval      = KeyTelemetryInterval
	keyTerminalSessionTimeout = KeyTerminalSessionTimeout
	keyCommandSecret          = KeyCommandSecret
	keyBsValid                = KeyBsValid
	keyDomainID               = "domain_id"
	keyChannelsCtrlID         = "channels_ctrl_id"
	keyChannelsDataID         = "channels_data_id"
	keyMqttURL                = "mqtt_url"
	keyMqttUsername           = "mqtt_username"
	keyMqttPassword           = "mqtt_password"
	keyMQTTPassword           = "mqtt_password"
	keyProvisionToken         = "provision_token"

	notConfigured = "not_configured"
	notFound      = "not_found"

	senmlNameUptime = "uptime"
	notAllowed      = "not_allowed"

	// senmlBaseGateway is the SenML base name used for gateway-scoped records.
	senmlBaseGateway = "gw:"

	provisionTimeout = 30 * time.Second
)

var (
	startTime = time.Now()

	// Version is the agent binary version, injected at build time via
	// -ldflags "-X github.com/absmach/agent.Version=x.y.z".
	Version   = "0.0.0"
	Commit    = "unknown"
	BuildTime = "unknown"

	heapSamples = []metrics.Sample{{Name: "/memory/classes/heap/free:bytes"}}
)

var (
	// errInvalidCommand indicates malformed command.
	errInvalidCommand = errors.New("invalid command")

	// ErrMalformedEntity indicates malformed entity specification.
	ErrMalformedEntity = errors.ErrMalformedEntity

	// ErrInvalidQueryParams indicates malformed URL.
	ErrInvalidQueryParams = errors.New("invalid query params")

	// errUnknownCommand indicates that command is not found.
	errUnknownCommand = errors.New("Unknown command")

	// errNoSuchService indicates service not supported.
	errNoSuchService = errors.New("no such service")

	// errFailedEncode indicates error in encoding.
	errFailedEncode = errors.New("failed to encode")

	// errFailedToPublish.
	errFailedToPublish = errors.New("failed to publish")

	// errFailedToCreateTerminalSession.
	errFailedToCreateTerminalSession = errors.New("failed to create terminal session")

	// errNoSuchTerminalSession terminal session doesnt exist error on closing.
	errNoSuchTerminalSession = errors.New("no such terminal session")

	// errNodeRedFailed.
	errNodeRedFailed = errors.New("failed to execute node-red operation")

	// errDeviceManagerFailed.
	errDeviceManagerFailed = errors.New("device manager operation failed")

	// errDeviceManagerDisabled indicates device manager is not configured.
	errDeviceManagerDisabled = errors.New("device manager not configured")

	// errRouteFailed indicates a failure routing a command to a downstream device.
	errRouteFailed = errors.New("failed to route command to device")
)

// DeviceService groups the downstream-device management methods of Service.
// Handlers or components that only manage devices can depend on this narrower interface.
type DeviceService interface {
	// DeviceManager handles downstream device registration and provisioning commands.
	DeviceManager(ctx context.Context, uuid, cmdStr string) error

	// ListDevices returns all registered downstream devices.
	ListDevices() ([]devicemgr.Device, error)

	// GetDevice returns a single downstream device by ID.
	GetDevice(id string) (devicemgr.Device, error)

	// AddDevice provisions and registers a new downstream device.
	AddDevice(ctx context.Context, name, extID, extKey, ifaceType, ifaceAddr string) (devicemgr.Device, error)

	// RemoveDevice removes a downstream device by ID.
	RemoveDevice(id string) error

	// MarkDeviceSeen records a live heartbeat for a downstream device.
	MarkDeviceSeen(id string) error
}

// Service specifies API for publishing messages and subscribing to topics.
type Service interface {
	// Control command.
	Control(uuid, cmdStr string) error

	// Route forwards a raw payload to a downstream device's physical interface
	// and publishes the device's response. cmdStr is comma-delimited:
	// <device_id>,<hex_payload>[,<read_bytes>].
	Route(ctx context.Context, uuid, cmdStr string) error

	// Update configuration file.
	AddConfig(Config) error

	// Config returns Config struct created from config file.
	Config() Config

	// CommandSecret returns the current command secret for inbound MQTT command validation.
	CommandSecret() string

	// Saves config file.
	ServiceConfig(ctx context.Context, uuid, cmdStr string) error

	// Services returns service list.
	Services() []Info

	// Terminal used for terminal control of gateway.
	Terminal(uuid, cmdStr string) error

	// Publish message.
	Publish(topic, payload string) error

	// Ping publishes an immediate heartbeat SenML record to the data channel
	// under the gateway/heartbeat topic, matching the periodic self-heartbeat format.
	Ping() error

	// NodeRed manages Node-RED flow operations.
	NodeRed(cmdStr string) (string, error)

	// UpdateLiveness registers or refreshes the liveness of a local service from
	// an authenticated MQTT heartbeat message.
	UpdateLiveness(svcname, svctype string) error

	// RegisterService manually registers a local service so that it appears on
	// the services list immediately, regardless of MQTT heartbeats.
	RegisterService(svcname, svctype string) error

	// RemoveService removes a previously registered service from the services list.
	RemoveService(svcname string) error

	// OTA triggers an over-the-air binary update by downloading from url.
	OTA(ctx context.Context, url, sha256hex string, size uint64) error

	// OTAFromData installs firmware from a binary payload received via MQTT.
	// sha256hex must be the hex-encoded SHA-256 of data.
	OTAFromData(ctx context.Context, data []byte, sha256hex string) error

	// Reset performs a reset in the given mode. Supported modes are:
	//   - "graceful"  – clean shutdown, save state, close connections, then exec
	//   - "immediate" – emergency reset with minimal cleanup, then exec
	//   - "watchdog"  – notify the health supervisor to trigger a watchdog reset
	//   - "now"       – alias for "immediate"
	// The caller is responsible for calling syscall.Exec after a successful
	// graceful or immediate reset (watchdog is handled by the supervisor).
	Reset(ctx context.Context, mode string) error

	// Shutdown performs a graceful shutdown: stops all service heartbeat
	// tickers and disconnects the MQTT client.
	Shutdown()

	// OTAStatus returns whether an OTA operation is currently in progress and the last error message, if any.
	OTAStatus() OTAStatusInfo

	// Telemetry returns the current gateway telemetry readings (live snapshot).
	Telemetry() TelemetryData

	// OTAAbort cancels an in-progress OTA update. It returns an error if no OTA is running.
	OTAAbort() error

	// OpenDevice opens the physical interface for a registered downstream device.
	OpenDevice(ctx context.Context, id string) error

	// CloseDevice closes the physical interface for a registered downstream device.
	CloseDevice(id string) error

	// ReadDevice reads up to n bytes from the open interface of the given device.
	ReadDevice(id string, n int) ([]byte, error)

	// WriteDevice sends hex-encoded data to the open interface of the given device.
	WriteDevice(id, hexData string) (int, error)

	// GetRuntimeConfig returns the value of a single runtime-configurable key.
	GetRuntimeConfig(key string) (string, error)

	// SetRuntimeConfig sets a runtime-configurable key to the given value.
	SetRuntimeConfig(ctx context.Context, key, value string) error

	DeviceService
}

// OTAStatusInfo reports the current state of the OTA subsystem.
type OTAStatusInfo struct {
	Busy      bool   `json:"busy"`
	LastError string `json:"last_error,omitempty"`
}

// TelemetryData holds the current gateway telemetry readings.
type TelemetryData struct {
	Uptime         float64  `json:"uptime"`
	MemTotal       uint64   `json:"mem_total,omitempty"`
	MemAvailable   uint64   `json:"mem_available,omitempty"`
	MemUsed        uint64   `json:"mem_used,omitempty"`
	CPUTemperature *float64 `json:"cpu_temperature,omitempty"`
	RSSI           *float64 `json:"rssi,omitempty"`
	LoadAvg1m      *float64 `json:"load_avg_1m,omitempty"`
	LoadAvg5m      *float64 `json:"load_avg_5m,omitempty"`
	LoadAvg15m     *float64 `json:"load_avg_15m,omitempty"`
	DiskUsagePct   *float64 `json:"disk_usage_percent,omitempty"`
	DevicesActive  *int     `json:"devices_active,omitempty"`
}

var _ Service = (*agent)(nil)

type agent struct {
	ctx                 context.Context
	mqttClient          paho.Client
	config              *Config
	noderedClient       nodered.Client
	logger              *slog.Logger
	svcs                map[string]Heartbeat
	svcsMu              sync.RWMutex
	terminals           map[string]terminal.Session
	termMu              sync.Mutex
	devices             *devicemgr.Manager
	sched               *Scheduler
	pushEvent           func(typeName string)
	otaBusy             atomic.Bool
	store               cfgstore.Store
	heartbeatIntervalCh chan time.Duration
	telemetryIntervalCh chan time.Duration
	telemetryStarted    atomic.Bool
	logLevel            *slog.LevelVar
	cfgMu               sync.RWMutex
	startupConfig       Config
	otaMu               sync.Mutex
	otaLastErr          string
	otaCancel           context.CancelFunc
	otaAborted          atomic.Bool
	bootstrapCachePath  string
	runCtx              context.Context
	paused              atomic.Bool
}

// New returns agent service implementation.
func New(ctx context.Context, mc paho.Client, cfg *Config, nc nodered.Client, logger *slog.Logger, devices *devicemgr.Manager, store cfgstore.Store, levelVar *slog.LevelVar, bootstrapCachePath string) (Service, error) {
	ag := &agent{
		ctx:                 ctx,
		mqttClient:          mc,
		noderedClient:       nc,
		config:              cfg,
		logger:              logger,
		svcs:                make(map[string]Heartbeat),
		terminals:           make(map[string]terminal.Session),
		devices:             devices,
		store:               store,
		heartbeatIntervalCh: make(chan time.Duration, 1),
		telemetryIntervalCh: make(chan time.Duration, 1),
		logLevel:            levelVar,
		startupConfig:       *cfg,
		bootstrapCachePath:  bootstrapCachePath,
		runCtx:              ctx,
	}

	if devices != nil {
		sched := newScheduler(devices, cfg.MQTT, cfg.DomainID, logger)
		if err := sched.Start(ctx); err != nil {
			logger.Warn("Failed to start device scheduler", slog.Any("error", err))
		}
		ag.sched = sched
	}

	topic := fmt.Sprintf("m/%s/c/%s/gateway/heartbeat",
		cfg.DomainID, cfg.Channels.DataChan())
	go ag.selfHeartbeat(ctx, topic, cfg.Heartbeat.Interval, cfg.MQTT.QoS)

	if cfg.Telemetry.Interval > 0 {
		telemetryTopic := fmt.Sprintf("m/%s/c/%s/gateway/telemetry",
			cfg.DomainID, cfg.Channels.DataChan())
		ag.telemetryStarted.Store(true)
		go ag.selfTelemetry(ctx, telemetryTopic, cfg.Telemetry.Interval, cfg.MQTT.QoS)
	}

	return ag, nil
}

func (a *agent) SetPushEvent(fn func(string)) {
	a.pushEvent = fn
}

func (a *agent) Control(uuid, cmdStr string) error {
	cmdArgs := strings.Split(strings.ReplaceAll(cmdStr, " ", ""), ",")
	if len(cmdArgs) < 1 || cmdArgs[0] == "" {
		return errInvalidCommand
	}

	var resp string
	var err error

	cmd := cmdArgs[0]
	switch {
	case cmd == ctrlStop:
		resp = a.controlStop()
	case cmd == ctrlStart:
		resp = a.controlStart()
	case cmd == ctrlReload:
		resp = a.controlReload()
	case cmd == ctrlStatus:
		resp, err = a.controlStatus()
	case strings.HasPrefix(cmd, "nodered-"):
		resp, err = a.NodeRed(cmdStr)
	default:
		err = errUnknownCommand
	}

	if err != nil {
		return err
	}

	return a.processResponse(uuid, cmd, resp)
}

// controlStop pauses the agent's background publishing loops (heartbeat and
// telemetry) and stops the per-device scheduler. The process stays alive so a
// subsequent control,start can resume it.
func (a *agent) controlStop() string {
	a.paused.Store(true)
	if a.sched != nil {
		a.sched.Stop()
	}
	a.logger.Info("Agent paused via control command")
	return "stopped"
}

// controlStart resumes the background publishing loops and restarts the
// per-device scheduler using the agent's run context. The scheduler context
// descends from the process context passed to New so device goroutines still
// terminate on shutdown; if that context is already cancelled (process is
// shutting down) the scheduler is not restarted.
func (a *agent) controlStart() string {
	a.paused.Store(false)
	switch {
	case a.sched == nil:
		// No device scheduler configured; nothing to restart.
	case a.runCtx == nil || a.runCtx.Err() != nil:
		a.logger.Warn("Run context unavailable; device scheduler not restarted",
			slog.Any("error", contextErr(a.runCtx)))
	default:
		if err := a.sched.Start(a.runCtx); err != nil {
			a.logger.Warn("Failed to restart device scheduler", slog.Any("error", err))
		}
	}
	a.logger.Info("Agent resumed via control command")
	return "started"
}

// contextErr returns ctx.Err() guarding against a nil context.
func contextErr(ctx context.Context) error {
	if ctx == nil {
		return context.Canceled
	}
	return ctx.Err()
}

// controlReload re-applies persisted runtime config overrides from the store so
// that out-of-band changes to the store take effect without a restart. Each
// value is validated before being applied; invalid entries (e.g. from manual
// file edits) are skipped and logged. The response lists the keys that were
// applied for auditability.
func (a *agent) controlReload() string {
	if a.store == nil {
		return notConfigured
	}
	var applied []string
	for key, val := range a.store.All() {
		if !settableKeys[key] {
			continue
		}
		if err := validateSettableValue(key, val); err != nil {
			a.logger.Warn("Skipping invalid persisted config value on reload",
				slog.String("key", key), slog.Any("error", err))
			continue
		}
		a.cfgMu.Lock()
		ApplyConfigEntry(a.config, key, val)
		a.cfgMu.Unlock()
		a.applyLiveUpdate(key, val)
		applied = append(applied, key)
	}
	sort.Strings(applied)
	a.logger.Info("Agent config reloaded via control command", slog.Any("applied", applied))
	if len(applied) == 0 {
		return "reloaded"
	}
	return "reloaded:" + strings.Join(applied, ",")
}

// controlStatus reports the agent's current runtime state as a JSON document.
func (a *agent) controlStatus() (string, error) {
	status := struct {
		Running       bool    `json:"running"`
		Paused        bool    `json:"paused"`
		UptimeSeconds float64 `json:"uptime_seconds"`
		Version       string  `json:"version"`
	}{
		Running:       true,
		Paused:        a.paused.Load(),
		UptimeSeconds: time.Since(startTime).Seconds(),
		Version:       Version,
	}
	b, err := json.Marshal(status)
	if err != nil {
		return "", errors.New(err.Error())
	}
	return string(b), nil
}

// Route forwards a raw payload to a downstream device's physical interface and
// publishes the device's response. cmdStr is comma-delimited:
//
//	<device_id>,<hex_payload>[,<read_bytes>]
//
// The interface is opened if not already open, the hex payload is written, and
// when read_bytes is supplied (0 < n <= 65536) that many bytes are read back
// and returned as a hex string. With no read_bytes, the number of bytes written
// is returned.
func (a *agent) Route(_ context.Context, uuid, cmdStr string) error {
	if a.devices == nil {
		return errors.Wrap(errRouteFailed, errDeviceManagerDisabled)
	}

	args := strings.Split(strings.ReplaceAll(cmdStr, " ", ""), ",")
	if len(args) < 2 || args[0] == "" || args[1] == "" {
		return errors.Wrap(errRouteFailed, errInvalidCommand)
	}
	deviceID, hexPayload := args[0], args[1]

	readBytes := 0
	if len(args) >= 3 && args[2] != "" {
		n, perr := strconv.Atoi(args[2])
		if perr != nil || n <= 0 || n > 65536 {
			return errors.Wrap(errRouteFailed, errInvalidCommand)
		}
		readBytes = n
	}

	// Resolve the device first so a missing device returns a clear error rather
	// than surfacing as an opaque interface-open failure.
	if _, err := a.devices.Get(deviceID); err != nil {
		return errors.Wrap(errRouteFailed, err)
	}

	if err := a.devices.OpenIface(deviceID); err != nil {
		return errors.Wrap(errRouteFailed, err)
	}

	written, err := a.devices.WriteIface(deviceID, hexPayload)
	if err != nil {
		return errors.Wrap(errRouteFailed, err)
	}

	resp := strconv.Itoa(written)
	if readBytes > 0 {
		read, rerr := a.devices.ReadIface(deviceID, readBytes)
		if rerr != nil {
			return errors.Wrap(errRouteFailed, rerr)
		}
		resp = fmt.Sprintf("%x", read)
	}

	return a.processResponse(uuid, "route", resp)
}

// Message for this command
// [{"bn":"1:", "n":"services", "vs":"view"}]
// [{"bn":"1:", "n":"config", "vs":"save, export, filename, filecontent"}]
// config_file_content is base64 encoded marshaled structure representing service conf
// Example of creation:
//
//	b, _ := toml.Marshal(cfg)
//	config_file_content := base64.StdEncoding.EncodeToString(b).
func (a *agent) ServiceConfig(ctx context.Context, uuid, cmdStr string) error {
	rawParts := strings.Split(cmdStr, ",")
	cmdArgs := make([]string, len(rawParts))
	for i, p := range rawParts {
		cmdArgs[i] = strings.TrimSpace(p)
	}
	if len(cmdArgs) < 1 {
		return errInvalidCommand
	}
	resp := ""
	cmd := cmdArgs[0]
	switch cmd {
	case view:
		services, err := json.Marshal(a.Services())
		if err != nil {
			return errors.New(err.Error())
		}
		resp = string(services)
	case save:
		if len(cmdArgs) < 4 {
			return errInvalidCommand
		}
		service := cmdArgs[1]
		fileName := cmdArgs[2]
		fileCont := cmdArgs[3]
		if err := a.saveConfig(ctx, service, fileName, fileCont); err != nil {
			return err
		}
	case "get":
		if len(cmdArgs) < 2 || cmdArgs[1] == "" {
			return errInvalidCommand
		}
		key := cmdArgs[1]
		if key == keyCommandSecret {
			if a.store == nil {
				resp = notConfigured
			} else if _, ok := a.store.Get(key); ok {
				resp = "REDACTED"
			} else {
				resp = notFound
			}
		} else if credentialKeys[key] {
			resp = notAllowed
		} else if !settableKeys[key] {
			resp = notFound
		} else if a.store == nil {
			resp = notConfigured
		} else if val, ok := a.store.Get(key); ok {
			resp = val
		} else if fallback := a.configFallback(key); fallback != "" {
			resp = fallback
		} else {
			resp = notFound
		}
	case "set":
		if len(cmdArgs) < 3 || cmdArgs[1] == "" || cmdArgs[2] == "" {
			return errInvalidCommand
		}
		key, val := cmdArgs[1], cmdArgs[2]
		if !settableKeys[key] {
			resp = notFound
		} else {
			if err := validateSettableValue(key, val); err != nil {
				return err
			}
			if a.store == nil {
				resp = notConfigured
			} else {
				if err := a.store.Set(key, val); err != nil {
					return err
				}
				a.cfgMu.Lock()
				ApplyConfigEntry(a.config, key, val)
				a.cfgMu.Unlock()
				a.applyLiveUpdate(key, val)
				resp = "ok"
			}
		}
	case "reset":
		if len(cmdArgs) < 2 || cmdArgs[1] == "" {
			return errInvalidCommand
		}
		key := cmdArgs[1]
		if !settableKeys[key] {
			resp = notFound
		} else if a.store == nil {
			resp = notConfigured
		} else {
			if err := a.store.Remove(key); err != nil {
				return err
			}
			a.revertToStartup(key)
			resp = "ok"
		}
	default:
		return errInvalidCommand
	}
	return a.processResponse(uuid, cmd, resp)
}

func (a *agent) Terminal(uuid, cmdStr string) error {
	b, err := base64.StdEncoding.DecodeString(cmdStr)
	if err != nil {
		return errors.New(err.Error())
	}
	cmdArgs := strings.Split(string(b), ",")
	if len(cmdArgs) < 1 {
		return errInvalidCommand
	}

	cmd := cmdArgs[0]
	ch := ""
	if len(cmdArgs) > 1 {
		ch = cmdArgs[1]
	}
	cfg := a.Config()
	switch cmd {
	case char:
		if err := a.terminalWrite(uuid, ch); err != nil {
			return err
		}
	case open:
		if err := a.terminalOpen(uuid, cfg.Terminal.SessionTimeout); err != nil {
			return err
		}
	case close:
		if err := a.terminalClose(uuid); err != nil {
			return err
		}
	}
	return nil
}

func (a *agent) terminalOpen(uuid string, timeout time.Duration) error {
	a.termMu.Lock()
	defer a.termMu.Unlock()
	if _, ok := a.terminals[uuid]; !ok {
		term, err := terminal.NewSession(uuid, timeout, a.Publish, a.logger)
		if err != nil {
			return errors.Wrap(errors.Wrap(errFailedToCreateTerminalSession, fmt.Errorf(" for %s", uuid)), err)
		}
		a.terminals[uuid] = term
		go func() {
			for range term.IsDone() {
				a.termMu.Lock()
				delete(a.terminals, uuid)
				a.termMu.Unlock()
				return
			}
		}()
	}
	return nil
}

func (a *agent) terminalClose(uuid string) error {
	a.termMu.Lock()
	defer a.termMu.Unlock()
	if _, ok := a.terminals[uuid]; ok {
		delete(a.terminals, uuid)
		return nil
	}
	return errors.Wrap(errNoSuchTerminalSession, fmt.Errorf("session :%s", uuid))
}

func (a *agent) terminalWrite(uuid, cmd string) error {
	if err := a.terminalOpen(uuid, a.Config().Terminal.SessionTimeout); err != nil {
		return err
	}
	a.termMu.Lock()
	term := a.terminals[uuid]
	a.termMu.Unlock()
	return term.Send([]byte(cmd))
}

func (a *agent) NodeRed(cmdStr string) (string, error) {
	cmdArgs := strings.Split(strings.ReplaceAll(cmdStr, " ", ""), ",")

	cmd := cmdArgs[0]
	if cmd == "" {
		return "", errInvalidCommand
	}

	var resp string
	var err error

	switch cmd {
	case "nodered-deploy":
		if len(cmdArgs) < 2 || cmdArgs[1] == "" {
			return "", errInvalidCommand
		}
		flowData, decErr := base64.StdEncoding.DecodeString(cmdArgs[1])
		if decErr != nil {
			return "", errors.Wrap(errNodeRedFailed, decErr)
		}
		resp, err = a.noderedClient.DeployFlows(a.normalizeNodeRedFlow(string(flowData)))
	case "nodered-add-flow":
		if len(cmdArgs) < 2 || cmdArgs[1] == "" {
			return "", errInvalidCommand
		}
		flowData, decErr := base64.StdEncoding.DecodeString(cmdArgs[1])
		if decErr != nil {
			return "", errors.Wrap(errNodeRedFailed, decErr)
		}
		resp, err = a.noderedClient.AddFlow(a.normalizeNodeRedFlow(string(flowData)))
	case "nodered-flows":
		resp, err = a.noderedClient.FetchFlows()
	case "nodered-state":
		resp, err = a.noderedClient.FlowState()
	case "nodered-ping":
		resp, err = a.noderedClient.Ping()
	default:
		err = errUnknownCommand
	}

	if err != nil {
		return "", errors.Wrap(errNodeRedFailed, err)
	}

	return resp, nil
}

// normalizeNodeRedFlow updates deployed flow JSON so Node-RED follows the same
// MQTT target and credentials as the agent runtime config.
func (a *agent) normalizeNodeRedFlow(flowJSON string) string {
	var payload any
	if err := json.Unmarshal([]byte(flowJSON), &payload); err != nil {
		return flowJSON
	}

	cfg := a.Config()
	host, port, useTLS := nodeRedMQTTEndpoint(cfg.MQTT.URL)
	dataChannel := cfg.Channels.DataChan()
	brokerIDs := map[string]struct{}{}

	patchNodeRedValue(payload, func(node map[string]any) {
		nodeType, _ := node["type"].(string)
		switch nodeType {
		case "mqtt-broker":
			id, _ := node["id"].(string)
			if id != "" {
				brokerIDs[id] = struct{}{}
			}
			if host != "" {
				node["broker"] = host
			}
			node["port"] = port
			node["clientid"] = cfg.MQTT.Username + "-nr"
			node["usetls"] = useTLS
			if useTLS && cfg.MQTT.SkipTLSVer {
				node["tls"] = nodeRedTLSConfigID
			} else {
				delete(node, "tls")
			}
			node["credentials"] = map[string]any{
				"user":     cfg.MQTT.Username,
				"password": cfg.MQTT.Password,
			}
		case "function":
			if fn, ok := node["func"].(string); ok {
				node["func"] = patchNodeRedTopic(fn, cfg.DomainID, dataChannel)
			}
		}

		if topic, ok := node["topic"].(string); ok {
			node["topic"] = patchNodeRedTopic(topic, cfg.DomainID, dataChannel)
		}
	})

	if len(brokerIDs) == 1 {
		var brokerID string
		for id := range brokerIDs {
			brokerID = id
		}
		patchNodeRedValue(payload, func(node map[string]any) {
			nodeType, _ := node["type"].(string)
			if nodeType != "mqtt out" {
				return
			}
			ref, _ := node["broker"].(string)
			if _, ok := brokerIDs[ref]; !ok {
				node["broker"] = brokerID
			}
		})
	}

	if useTLS && cfg.MQTT.SkipTLSVer {
		payload = ensureNodeRedTLSConfig(payload)
	}

	b, err := json.Marshal(payload)
	if err != nil {
		return flowJSON
	}
	return string(b)
}

const nodeRedTLSConfigID = "magistrala-agent-tls"

var nodeRedTopicPattern = regexp.MustCompile(`m/[^/"'\s]*/c/[^/"'\s]*/(?:data|gateway/telemetry)`)

func nodeRedMQTTEndpoint(rawURL string) (host, port string, useTLS bool) {
	if rawURL == "" {
		return "", "1883", false
	}

	parsed, err := url.Parse(rawURL)
	if err != nil || parsed.Host == "" {
		host = rawURL
		if strings.Contains(host, "://") {
			host = strings.SplitN(host, "://", 2)[1]
		}
		if idx := strings.Index(host, "/"); idx >= 0 {
			host = host[:idx]
		}
		if strings.Contains(host, ":") {
			parts := strings.Split(host, ":")
			return parts[0], parts[len(parts)-1], false
		}
		return host, "1883", false
	}

	host = parsed.Hostname()
	port = parsed.Port()
	if port == "" {
		port = "1883"
	}
	switch parsed.Scheme {
	case "ssl", "tls", "mqtts":
		useTLS = true
	}

	return host, port, useTLS
}

func patchNodeRedTopic(value, domainID, channelID string) string {
	if domainID == "" || channelID == "" {
		return value
	}
	return nodeRedTopicPattern.ReplaceAllString(value, fmt.Sprintf("m/%s/c/%s/gateway/telemetry", domainID, channelID))
}

func patchNodeRedValue(value any, patch func(map[string]any)) {
	switch typed := value.(type) {
	case []any:
		for _, item := range typed {
			patchNodeRedValue(item, patch)
		}
	case map[string]any:
		patch(typed)
		for _, item := range typed {
			patchNodeRedValue(item, patch)
		}
	}
}

func ensureNodeRedTLSConfig(payload any) any {
	tlsNode := map[string]any{
		"id":               nodeRedTLSConfigID,
		"type":             "tls-config",
		"name":             "Magistrala MQTT TLS",
		"cert":             "",
		"key":              "",
		"ca":               "",
		"certname":         "",
		"keyname":          "",
		"caname":           "",
		"servername":       "",
		"verifyservercert": false,
		"alpnprotocol":     "",
	}

	switch typed := payload.(type) {
	case []any:
		for _, item := range typed {
			node, ok := item.(map[string]any)
			if ok && node["id"] == nodeRedTLSConfigID {
				return payload
			}
		}
		return append(typed, tlsNode)
	case map[string]any:
		configs, _ := typed["configs"].([]any)
		for _, item := range configs {
			node, ok := item.(map[string]any)
			if ok && node["id"] == nodeRedTLSConfigID {
				return payload
			}
		}
		typed["configs"] = append(configs, tlsNode)
		return typed
	default:
		return payload
	}
}

func (a *agent) processResponse(uuid, cmd, resp string) error {
	payload, err := senml.EncodeString(uuid, cmd, resp)
	if err != nil {
		return errors.Wrap(errFailedEncode, err)
	}
	if err := a.publishCmd(control, string(payload)); err != nil {
		return errors.Wrap(errFailedToPublish, err)
	}
	return nil
}

func (a *agent) saveConfig(_ context.Context, service, fileName, fileCont string) error {
	switch service {
	case export:
		content, err := base64.StdEncoding.DecodeString(fileCont)
		if err != nil {
			return errors.New(err.Error())
		}
		if err := saveExportConfig(fileName, content); err != nil {
			return err
		}

	default:
		return errNoSuchService
	}

	return nil
}

func saveExportConfig(fileName string, content []byte) error {
	var data map[string]any
	if err := toml.Unmarshal(content, &data); err != nil {
		if err2 := json.Unmarshal(content, &data); err2 != nil {
			return errors.New("failed to unmarshal export config content")
		}
	}
	b, err := toml.Marshal(data)
	if err != nil {
		return errors.New("failed to marshal export config content")
	}
	if err := os.WriteFile(fileName, b, 0o644); err != nil {
		return errors.New(err.Error())
	}
	return nil
}

func (a *agent) AddConfig(c Config) error {
	a.cfgMu.Lock()
	defer a.cfgMu.Unlock()
	*a.config = c
	return nil
}

func (a *agent) Config() Config {
	a.cfgMu.RLock()
	defer a.cfgMu.RUnlock()
	return *a.config
}

func (a *agent) CommandSecret() string {
	a.cfgMu.RLock()
	defer a.cfgMu.RUnlock()
	return a.config.CommandSecret
}

func (a *agent) Services() []Info {
	a.svcsMu.RLock()
	defer a.svcsMu.RUnlock()
	svcInfos := []Info{}
	keys := []string{}
	for k := range a.svcs {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, key := range keys {
		service := a.svcs[key].Info()
		svcInfos = append(svcInfos, service)
	}
	return svcInfos
}

func (a *agent) Publish(t, payload string) error {
	return a.publish(t, payload, a.Config().MQTT.QoS)
}

func (a *agent) publishCmd(t, payload string) error {
	return a.publish(t, payload, a.Config().MQTT.CmdQoS)
}

func (a *agent) publish(t, payload string, qos byte) error {
	topic := a.getTopic(t)
	mqtt := a.Config().MQTT
	token := a.mqttClient.Publish(topic, qos, mqtt.Retain, payload)
	token.Wait()
	if err := token.Error(); err != nil {
		return errors.New(err.Error())
	}
	return nil
}

func (a *agent) selfHeartbeat(ctx context.Context, topic string, interval time.Duration, qos byte) {
	publish := func() {
		if a.paused.Load() {
			return
		}
		payload, err := a.selfHeartbeatPayload()
		if err != nil {
			a.logger.Error("failed to encode self-heartbeat", slog.Any("error", err))
			return
		}
		token := a.mqttClient.Publish(topic, qos, false, payload)
		token.Wait()
		if err := token.Error(); err != nil {
			a.logger.Warn("self-heartbeat publish failed", slog.Any("error", err))
		}
	}
	publish()
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			publish()
		case d := <-a.heartbeatIntervalCh:
			ticker.Reset(d)
		case <-ctx.Done():
			return
		}
	}
}

func (a *agent) selfHeartbeatPayload() ([]byte, error) {
	metrics.Read(heapSamples)

	heapFree := uint64(0)
	if len(heapSamples) > 0 {
		heapFree = heapSamples[0].Value.Uint64()
	}

	deviceCount := 0
	if a.devices != nil {
		n, err := a.devices.Count()
		if err != nil {
			a.logger.Warn("failed to count devices for self-heartbeat", slog.Any("error", err))
		} else {
			deviceCount = n
		}
	}

	svcType := "agent"
	heartbeat := true
	fwVersion := Version
	uptime := time.Since(startTime).Seconds()
	heapFreeValue := float64(heapFree)
	deviceCountValue := float64(deviceCount)
	connected := a.mqttClient.IsConnected()

	pack := []senml.Record{
		{BaseName: "agent:", Name: "service_type", StringValue: &svcType},
		{Name: "heartbeat", BoolValue: &heartbeat},
		{Name: "fw_version", StringValue: &fwVersion},
		{Name: senmlNameUptime, Unit: "s", Value: &uptime},
		{Name: "heap_free", Unit: "By", Value: &heapFreeValue},
		{Name: "devices", Unit: "count", Value: &deviceCountValue},
		{Name: "connected", BoolValue: &connected},
	}
	return senml.EncodeRecords(pack)
}

func (a *agent) selfTelemetry(ctx context.Context, topic string, interval time.Duration, qos byte) {
	publish := func() {
		if a.paused.Load() {
			return
		}
		records := a.gatewayTelemetryPayload()
		if len(records) == 0 {
			return
		}
		b, err := senml.EncodeRecords(records)
		if err != nil {
			a.logger.Warn("failed to encode self-telemetry", slog.Any("error", err))
			return
		}
		token := a.mqttClient.Publish(topic, qos, false, b)
		token.Wait()
		if err := token.Error(); err != nil {
			a.logger.Warn("self-telemetry publish failed", slog.Any("error", err))
		}
	}

	var ticker *time.Ticker
	var tickerCh <-chan time.Time

	stopTicker := func() {
		if ticker != nil {
			ticker.Stop()
			ticker = nil
			tickerCh = nil
		}
	}

	startTicker := func(d time.Duration) {
		stopTicker()
		ticker = time.NewTicker(d)
		tickerCh = ticker.C
	}

	if interval > 0 {
		startTicker(interval)
		publish()
	}
	defer stopTicker()

	for {
		select {
		case <-tickerCh:
			publish()
		case d := <-a.telemetryIntervalCh:
			if d > 0 {
				if ticker == nil {
					startTicker(d)
					publish()
				} else {
					ticker.Reset(d)
				}
			} else {
				stopTicker()
			}
		case <-ctx.Done():
			return
		}
	}
}

// Telemetry returns a live snapshot of the current gateway telemetry readings.
func (a *agent) Telemetry() TelemetryData {
	cfg := a.Config()
	data := TelemetryData{
		Uptime: time.Since(startTime).Seconds(),
	}

	if total, _, available, ok := readMemoryStats(); ok {
		data.MemTotal = total
		data.MemAvailable = available
		data.MemUsed = total - available
	}

	if cfg.Telemetry.IncludeTemperature {
		if temp, ok := readCPUTemperature(); ok {
			data.CPUTemperature = &temp
		}
	}

	if cfg.Telemetry.IncludeNetwork {
		if rssi, ok := readInterfaceRSSI(); ok {
			data.RSSI = &rssi
		}
	}

	if cfg.Telemetry.IncludeLoad {
		if l1, l5, l15, ok := readLoadAverage(); ok {
			data.LoadAvg1m = &l1
			data.LoadAvg5m = &l5
			data.LoadAvg15m = &l15
		}
	}

	if pct, ok := readDiskUsagePercent(); ok {
		data.DiskUsagePct = &pct
	}

	if a.devices != nil {
		if n, err := a.devices.Count(); err == nil {
			count := n
			data.DevicesActive = &count
		}
	}

	return data
}

func (a *agent) gatewayTelemetryPayload() []senml.Record {
	cfg := a.Config()
	now := float64(time.Now().UnixNano()) / float64(time.Second)
	uptime := time.Since(startTime).Seconds()

	records := []senml.Record{
		{BaseName: senmlBaseGateway, BaseTime: now, Name: "uptime", Unit: "s", Value: &uptime},
	}

	if total, _, available, ok := readMemoryStats(); ok {
		used := float64(total - available)
		free := float64(available)
		records = append(records,
			senml.Record{Name: "heap_free", Unit: "By", Value: &free},
			senml.Record{Name: "heap_used", Unit: "By", Value: &used},
		)
	}

	if cfg.Telemetry.IncludeTemperature {
		if temp, ok := readCPUTemperature(); ok {
			records = append(records, senml.Record{Name: "temperature", Unit: "Cel", Value: &temp})
		}
	}

	if cfg.Telemetry.IncludeNetwork {
		if rssi, ok := readInterfaceRSSI(); ok {
			records = append(records, senml.Record{Name: "rssi", Unit: "dB", Value: &rssi})
		}
	}

	if cfg.Telemetry.IncludeLoad {
		if l1, l5, l15, ok := readLoadAverage(); ok {
			records = append(records,
				senml.Record{Name: "load_avg_1m", Value: &l1},
				senml.Record{Name: "load_avg_5m", Value: &l5},
				senml.Record{Name: "load_avg_15m", Value: &l15},
			)
		}
	}

	if diskPct, ok := readDiskUsagePercent(); ok {
		records = append(records, senml.Record{Name: "disk_usage_percent", Unit: "%", Value: &diskPct})
	}

	if a.devices != nil {
		if n, err := a.devices.Count(); err == nil {
			devicesActive := float64(n)
			records = append(records, senml.Record{Name: "devices_active", Value: &devicesActive})
		}
	}

	return records
}

func (a *agent) UpdateLiveness(svcname, svctype string) error {
	a.svcsMu.Lock()
	defer a.svcsMu.Unlock()
	if _, ok := a.svcs[svcname]; !ok {
		svc := NewHeartbeat(svcname, svctype, a.Config().Heartbeat.Interval)
		a.svcs[svcname] = svc
	}
	a.svcs[svcname].Update()
	return nil
}

func (a *agent) RegisterService(svcname, svctype string) error {
	if svcname == "" {
		return errors.New("service name is required")
	}
	a.svcsMu.Lock()
	defer a.svcsMu.Unlock()
	if _, ok := a.svcs[svcname]; !ok {
		svc := NewHeartbeat(svcname, svctype, a.Config().Heartbeat.Interval)
		a.svcs[svcname] = svc
	}
	a.svcs[svcname].Update()
	return nil
}

func (a *agent) RemoveService(svcname string) error {
	if svcname == "" {
		return errors.New("service name is required")
	}
	a.svcsMu.Lock()
	defer a.svcsMu.Unlock()
	if svc, ok := a.svcs[svcname]; ok {
		svc.Stop()
		delete(a.svcs, svcname)
	}
	return nil
}

func (a *agent) Ping() error {
	cfg := a.Config()
	if cfg.DomainID == "" || cfg.Channels.DataChan() == "" {
		return errors.New("ping: domain ID or data channel not configured")
	}
	topic := fmt.Sprintf("m/%s/c/%s/gateway/heartbeat", cfg.DomainID, cfg.Channels.DataChan())
	payload, err := a.selfHeartbeatPayload()
	if err != nil {
		return err
	}
	token := a.mqttClient.Publish(topic, cfg.MQTT.QoS, false, payload)
	token.Wait()
	return token.Error()
}

func (a *agent) OTA(ctx context.Context, url, sha256hex string, size uint64) error {
	cfg := a.Config()
	if !cfg.OTA.Enabled {
		return errors.New("OTA is disabled")
	}

	otaCtx, otaCancel := context.WithCancel(ctx)

	a.otaMu.Lock()
	if a.otaBusy.Load() {
		a.otaMu.Unlock()
		otaCancel()
		return errors.New("OTA already in progress")
	}
	a.otaBusy.Store(true)
	a.otaLastErr = ""
	a.otaCancel = otaCancel
	a.otaAborted.Store(false)
	a.otaMu.Unlock()

	defer func() {
		a.otaMu.Lock()
		a.otaCancel = nil
		a.otaMu.Unlock()
		a.otaBusy.Store(false)
	}()

	otaCfg := ota.Config{
		BinaryPath:  cfg.OTA.BinaryPath,
		DownloadDir: cfg.OTA.DownloadDir,
	}

	domainID := cfg.DomainID
	ctrlChan := cfg.Channels.CtrlChan()
	qos := cfg.MQTT.QoS
	statusTopic := fmt.Sprintf("m/%s/c/%s/ota/status", domainID, ctrlChan)

	progressFn := func(state ota.State, bytesWritten, totalBytes int64, progress float64) {
		a.publishOTAStatus(statusTopic, qos, state, bytesWritten, totalBytes, progress, "")
	}

	runErr := ota.Run(otaCtx, otaCfg, url, sha256hex, size, progressFn)
	if runErr != nil {
		a.otaMu.Lock()
		if context.Cause(otaCtx) != nil || otaCtx.Err() != nil {
			a.otaLastErr = "aborted"
		}
		if a.otaAborted.Load() {
			a.publishOTAStatus(statusTopic, qos, ota.StateAborted, 0, 0, 0, "OTA aborted by user")
			a.otaLastErr = "OTA aborted by user"
		} else {
			a.publishOTAStatus(statusTopic, qos, ota.StateAborted, 0, 0, 0, runErr.Error())
			a.otaLastErr = runErr.Error()
		}
		a.otaMu.Unlock()
	}
	return runErr
}

func (a *agent) OTAFromData(ctx context.Context, data []byte, sha256hex string) error {
	cfg := a.Config()
	if !cfg.OTA.Enabled {
		return errors.New("OTA is disabled")
	}

	otaCtx, otaCancel := context.WithCancel(ctx)

	a.otaMu.Lock()
	if a.otaBusy.Load() {
		a.otaMu.Unlock()
		otaCancel()
		return errors.New("OTA already in progress")
	}
	a.otaBusy.Store(true)
	a.otaLastErr = ""
	a.otaCancel = otaCancel
	a.otaAborted.Store(false)
	a.otaMu.Unlock()

	defer func() {
		a.otaMu.Lock()
		a.otaCancel = nil
		a.otaMu.Unlock()
		a.otaBusy.Store(false)
	}()

	otaCfg := ota.Config{
		BinaryPath:  cfg.OTA.BinaryPath,
		DownloadDir: cfg.OTA.DownloadDir,
	}

	domainID := cfg.DomainID
	ctrlChan := cfg.Channels.CtrlChan()
	qos := cfg.MQTT.QoS
	statusTopic := fmt.Sprintf("m/%s/c/%s/ota/status", domainID, ctrlChan)

	progressFn := func(state ota.State, bytesWritten, totalBytes int64, progress float64) {
		a.publishOTAStatus(statusTopic, qos, state, bytesWritten, totalBytes, progress, "")
	}

	runErr := ota.RunFromData(otaCtx, otaCfg, data, sha256hex, progressFn)
	if runErr != nil {
		a.otaMu.Lock()
		if a.otaAborted.Load() {
			a.publishOTAStatus(statusTopic, qos, ota.StateAborted, 0, 0, 0, "OTA aborted by user")
			a.otaLastErr = "OTA aborted by user"
		} else {
			a.publishOTAStatus(statusTopic, qos, ota.StateAborted, 0, 0, 0, runErr.Error())
			a.otaLastErr = runErr.Error()
		}
		a.otaMu.Unlock()
	}
	return runErr
}

// publishOTAStatus publishes a retained OTA status SenML record to statusTopic.
// errMsg is appended as an "error" field only when non-empty.
func (a *agent) publishOTAStatus(statusTopic string, qos byte, state ota.State, bytesWritten, totalBytes int64, progress float64, errMsg string) {
	now := float64(time.Now().UnixNano()) / float64(time.Second)
	stateStr := strings.ToLower(state.String())
	bytesVal := float64(bytesWritten)
	totalVal := float64(totalBytes)
	pack := []senml.Record{
		{BaseName: senmlBaseGateway, BaseTime: now, Name: "state", StringValue: &stateStr},
		{Name: "bytes", Unit: "By", Value: &bytesVal},
		{Name: "total", Unit: "By", Value: &totalVal},
		{Name: "progress", Unit: "%", Value: &progress},
	}
	if errMsg != "" {
		pack = append(pack, senml.Record{Name: "error", StringValue: &errMsg})
	}
	b, err := senml.EncodeRecords(pack)
	if err != nil {
		a.logger.Warn("Failed to encode OTA status", slog.Any("error", err))
		return
	}

	a.logger.Info("OTA progress",
		slog.String("state", stateStr),
		slog.Float64("progress", progress),
	)

	token := a.mqttClient.Publish(statusTopic, qos, true, b)
	token.Wait()
}

func (a *agent) OTAAbort() error {
	a.otaMu.Lock()
	cancel := a.otaCancel
	if cancel != nil {
		a.otaLastErr = "aborted"
	}
	a.otaMu.Unlock()
	if cancel == nil {
		return errors.New("no OTA in progress")
	}
	a.otaAborted.Store(true)
	cancel()
	return nil
}

func (a *agent) OTAStatus() OTAStatusInfo {
	a.otaMu.Lock()
	lastErr := a.otaLastErr
	a.otaMu.Unlock()
	return OTAStatusInfo{
		Busy:      a.otaBusy.Load(),
		LastError: lastErr,
	}
}

func (a *agent) ListDevices() ([]devicemgr.Device, error) {
	if a.devices == nil {
		return []devicemgr.Device{}, nil
	}
	return a.devices.List()
}

func (a *agent) GetDevice(id string) (devicemgr.Device, error) {
	if a.devices == nil {
		return devicemgr.Device{}, errDeviceManagerDisabled
	}
	return a.devices.Get(id)
}

func (a *agent) AddDevice(ctx context.Context, name, extID, extKey, ifaceType, ifaceAddr string) (devicemgr.Device, error) {
	if a.devices == nil {
		return devicemgr.Device{}, errDeviceManagerDisabled
	}
	d, err := a.devices.Add(ctx, name, extID, extKey, iface.ParseInterfaceType(ifaceType), ifaceAddr)
	if err != nil {
		return d, err
	}
	if a.sched != nil {
		a.sched.StartDevice(context.WithoutCancel(ctx), d)
	}
	return d, nil
}

func (a *agent) RemoveDevice(id string) error {
	if a.devices == nil {
		return errDeviceManagerDisabled
	}
	if a.sched != nil {
		a.sched.StopDevice(id)
	}
	return a.devices.Remove(id)
}

func (a *agent) MarkDeviceSeen(id string) error {
	if a.devices == nil {
		return errDeviceManagerDisabled
	}
	return a.devices.MarkSeen(id)
}

func (a *agent) Reset(ctx context.Context, mode string) error {
	a.logger.Info("Reset initiated", slog.String("mode", mode))

	switch mode {
	case ResetGraceful:
		return a.gracefulReset()
	case ResetImmediate, ResetNow:
		return a.immediateReset()
	case ResetWatchdog:
		return a.watchdogReset()
	default:
		return fmt.Errorf("unknown reset mode: %s", mode)
	}
}

func (a *agent) gracefulReset() error {
	a.saveResetReason(ResetGraceful)

	a.sendGoodbyeHeartbeat()

	a.svcsMu.RLock()
	for name, svc := range a.svcs {
		svc.Stop()
		a.logger.Debug("stopped service heartbeat", slog.String("service", name))
	}
	a.svcsMu.RUnlock()

	if a.sched != nil {
		a.sched.Stop()
	}

	a.closeTerminals()

	a.logger.Debug("disconnecting MQTT client")
	a.mqttClient.Disconnect(5000)
	a.logger.Info("graceful reset complete")
	return nil
}

func (a *agent) immediateReset() error {
	a.saveResetReason(ResetImmediate)

	a.logger.Debug("immediate reset, disconnecting MQTT client")
	a.mqttClient.Disconnect(100)
	a.logger.Info("immediate reset complete")
	return nil
}

func (a *agent) watchdogReset() error {
	a.saveResetReason(ResetWatchdog)
	a.logger.Info("watchdog reset requested")
	return nil
}

func (a *agent) Shutdown() {
	_ = a.Reset(context.Background(), ResetGraceful)
}

func (a *agent) saveResetReason(mode string) {
	if a.store == nil {
		return
	}
	if err := a.store.Set("reset_reason", mode); err != nil {
		a.logger.Warn("Failed to save reset reason", slog.Any("error", err))
	}
}

func (a *agent) sendGoodbyeHeartbeat() {
	cfg := a.Config()
	if cfg.DomainID == "" || cfg.Channels.DataChan() == "" {
		return
	}
	topic := fmt.Sprintf("m/%s/c/%s/gateway/heartbeat", cfg.DomainID, cfg.Channels.DataChan())

	svcType := "agent"
	heartbeat := false
	pack := []senml.Record{
		{BaseName: "agent:", Name: "service_type", StringValue: &svcType},
		{Name: "heartbeat", BoolValue: &heartbeat},
	}
	payload, err := senml.EncodeRecords(pack)
	if err != nil {
		a.logger.Error("Failed to encode goodbye heartbeat", slog.Any("error", err))
		return
	}
	token := a.mqttClient.Publish(topic, cfg.MQTT.QoS, false, payload)
	token.Wait()
}

func (a *agent) closeTerminals() {
	a.termMu.Lock()
	defer a.termMu.Unlock()
	for uuid := range a.terminals {
		delete(a.terminals, uuid)
	}
}

// settableKeys is the allowlist of keys that can be remotely get/set via MQTT.
// Unknown keys are rejected to prevent arbitrary storage growth.
var settableKeys = map[string]bool{
	keyLogLevel:               true,
	keyHeartbeatInterval:      true,
	keyTelemetryInterval:      true,
	keyTerminalSessionTimeout: true,
	keyCommandSecret:          true,
	keyBsValid:                true,
	keyMQTTPassword:           true,
	keyProvisionToken:         true,
}

// credentialKeys holds keys that can be written but never read back remotely.
// A get on any credential key returns not_allowed instead of the stored value.
var credentialKeys = map[string]bool{
	keyMQTTPassword:   true,
	keyProvisionToken: true,
}

// validateSettableValue returns errInvalidCommand if val is not a valid value for key.
func validateSettableValue(key, val string) error {
	switch key {
	case keyLogLevel:
		var l slog.Level
		if err := l.UnmarshalText([]byte(val)); err != nil {
			return errInvalidCommand
		}
	case keyHeartbeatInterval:
		d, err := time.ParseDuration(val)
		if err != nil || d < time.Second {
			return errInvalidCommand
		}
	case keyTelemetryInterval:
		d, err := time.ParseDuration(val)
		if err != nil || (d != 0 && (d < time.Second || d > time.Hour)) {
			return errInvalidCommand
		}
	case keyTerminalSessionTimeout:
		d, err := time.ParseDuration(val)
		if err != nil || d <= 0 {
			return errInvalidCommand
		}
	case keyBsValid:
		if val != "0" && val != "1" {
			return errInvalidCommand
		}
	case keyCommandSecret, keyMQTTPassword, keyProvisionToken:
		if val == "" {
			return errInvalidCommand
		}
	default:
		return errInvalidCommand
	}
	return nil
}

// revertToStartup restores key's value from startupConfig and applies the
// live update so running subsystems reflect the reverted value immediately.
func (a *agent) revertToStartup(key string) {
	a.cfgMu.Lock()
	var liveVal string
	switch key {
	case keyLogLevel:
		a.config.Log.Level = a.startupConfig.Log.Level
		liveVal = a.config.Log.Level
	case keyHeartbeatInterval:
		a.config.Heartbeat.Interval = a.startupConfig.Heartbeat.Interval
		liveVal = a.config.Heartbeat.Interval.String()
	case keyTelemetryInterval:
		a.config.Telemetry.Interval = a.startupConfig.Telemetry.Interval
		liveVal = a.config.Telemetry.Interval.String()
	case keyTerminalSessionTimeout:
		a.config.Terminal.SessionTimeout = a.startupConfig.Terminal.SessionTimeout
		liveVal = a.config.Terminal.SessionTimeout.String()
	case keyCommandSecret:
		a.config.CommandSecret = a.startupConfig.CommandSecret
		liveVal = a.config.CommandSecret
	case keyMQTTPassword:
		a.config.MQTT.Password = a.startupConfig.MQTT.Password
	case keyProvisionToken:
		a.config.Provision.Token = a.startupConfig.Provision.Token
	}
	a.cfgMu.Unlock()
	if liveVal != "" {
		a.applyLiveUpdate(key, liveVal)
	}
}

// ApplyConfigEntry updates cfg in place for the known settable keys.
// Used at startup to replay persisted overrides before the agent starts.
//
// Keys for bootstrap-derived fields (domain_id, channels_*, mqtt_*) are
// applied at startup only. They are not included in settableKeys and
// cannot be modified via runtime MQTT set commands.
func ApplyConfigEntry(cfg *Config, key, val string) {
	switch key {
	case keyLogLevel:
		cfg.Log.Level = val
	case keyHeartbeatInterval:
		if d, err := time.ParseDuration(val); err == nil && d > 0 {
			cfg.Heartbeat.Interval = d
		}
	case keyTelemetryInterval:
		if d, err := time.ParseDuration(val); err == nil && d > 0 {
			cfg.Telemetry.Interval = d
		}
	case keyTerminalSessionTimeout:
		if d, err := time.ParseDuration(val); err == nil && d > 0 {
			cfg.Terminal.SessionTimeout = d
		}
	case keyCommandSecret:
		cfg.CommandSecret = val
	case keyDomainID:
		cfg.DomainID = val
	case keyChannelsCtrlID:
		cfg.Channels.CtrlID = val
	case keyChannelsDataID:
		cfg.Channels.DataID = val
	case keyMqttURL:
		cfg.MQTT.URL = val
	case keyMqttUsername:
		cfg.MQTT.Username = val
	case keyMqttPassword:
		cfg.MQTT.Password = val
	case keyProvisionToken:
		cfg.Provision.Token = val
	}
}

// applyLiveUpdate propagates a config change to running subsystems so the
// effect is immediate without requiring a restart.
func (a *agent) applyLiveUpdate(key, val string) {
	switch key {
	case keyBsValid:
		if val == "0" && a.bootstrapCachePath != "" {
			if err := os.Remove(a.bootstrapCachePath); err != nil {
				if !os.IsNotExist(err) {
					a.logger.Warn("Failed to delete bootstrap cache", slog.Any("error", err))
				}
			} else {
				a.logger.Info("Bootstrap cache invalidated")
			}
		}
	case keyLogLevel:
		if a.logLevel != nil {
			var l slog.Level
			if err := l.UnmarshalText([]byte(val)); err == nil {
				a.logLevel.Set(l)
			}
		}
	case keyHeartbeatInterval:
		if d, err := time.ParseDuration(val); err == nil && d > 0 {
			select {
			case a.heartbeatIntervalCh <- d:
			default:
			}
		}
	case keyTelemetryInterval:
		if d, err := time.ParseDuration(val); err == nil {
			if d > 0 && !a.telemetryStarted.Load() {
				a.telemetryStarted.Store(true)
				cfg := a.Config()
				telemetryTopic := fmt.Sprintf("m/%s/c/%s/gateway/telemetry",
					cfg.DomainID, cfg.Channels.DataChan())
				go a.selfTelemetry(a.ctx, telemetryTopic, 0, cfg.MQTT.QoS)
			}
			select {
			case a.telemetryIntervalCh <- d:
			default:
			}
		}
	case keyCommandSecret:
		// Secret is read from Config() on each inbound message;
		// no live subsystem needs updating.
	}
}

func (a *agent) configFallback(key string) string {
	cfg := a.Config()
	switch key {
	case keyLogLevel:
		return cfg.Log.Level
	case keyHeartbeatInterval:
		return cfg.Heartbeat.Interval.String()
	case keyTelemetryInterval:
		return cfg.Telemetry.Interval.String()
	case keyTerminalSessionTimeout:
		return cfg.Terminal.SessionTimeout.String()
	}
	return ""
}

func (a *agent) getTopic(topic string) (t string) {
	cfg := a.Config()
	domainID := cfg.DomainID
	switch topic {
	case control:
		t = fmt.Sprintf("m/%s/c/%s/res", domainID, cfg.Channels.CtrlChan())
	case data:
		t = fmt.Sprintf("m/%s/c/%s/gateway/telemetry", domainID, cfg.Channels.DataChan())
	default:
		t = fmt.Sprintf("m/%s/c/%s/res/%s", domainID, cfg.Channels.CtrlChan(), topic)
	}
	return t
}

// DeviceManager handles downstream device management commands.
// cmdStr is comma-delimited: <subcommand>[,args...]
//
//	list                                         → JSON array of all devices
//	add,<name>,<ext_id>,<ext_key>,<iface>,<addr> → provision + register
//	remove,<device_id>                           → deregister
//	get,<device_id>                              → JSON for one device
//	seen,<device_id>                             → mark device active/last-seen
//	open,<device_id>                             → open physical interface
//	close,<device_id>                            → close physical interface
//	read,<device_id>,<n_bytes>                   → read n bytes, reply as hex
//	write,<device_id>,<hex_data>                 → write hex bytes to interface
func (a *agent) DeviceManager(ctx context.Context, uuid, cmdStr string) error {
	if a.devices == nil {
		return errDeviceManagerDisabled
	}

	args := strings.Split(strings.TrimSpace(cmdStr), ",")
	if len(args) == 0 || args[0] == "" {
		return errors.Wrap(errDeviceManagerFailed, errInvalidCommand)
	}

	sub := args[0]
	var (
		resp string
		err  error
	)

	switch sub {
	case "list":
		devs, lerr := a.devices.List()
		if lerr != nil {
			return errors.Wrap(errDeviceManagerFailed, lerr)
		}
		b, jerr := json.Marshal(devs)
		if jerr != nil {
			return errors.Wrap(errDeviceManagerFailed, jerr)
		}
		resp = string(b)

	case "add":
		comma := strings.IndexByte(strings.TrimSpace(cmdStr), ',')
		if comma < 0 {
			return errors.Wrap(errDeviceManagerFailed, errInvalidCommand)
		}
		var addReq struct {
			Name        string `json:"name"`
			ExternalID  string `json:"external_id"`
			ExternalKey string `json:"external_key"`
			IfaceType   string `json:"iface_type"`
			IfaceAddr   string `json:"iface_addr"`
		}
		if jerr := json.Unmarshal([]byte(strings.TrimSpace(cmdStr)[comma+1:]), &addReq); jerr != nil {
			return errors.Wrap(errDeviceManagerFailed, errInvalidCommand)
		}
		if addReq.Name == "" || addReq.ExternalID == "" || addReq.ExternalKey == "" {
			return errors.Wrap(errDeviceManagerFailed, errInvalidCommand)
		}
		ifaceType := iface.ParseInterfaceType(addReq.IfaceType)
		addCtx, cancel := context.WithTimeout(ctx, provisionTimeout)
		d, aerr := a.devices.Add(addCtx, addReq.Name, addReq.ExternalID, addReq.ExternalKey, ifaceType, addReq.IfaceAddr)
		cancel()
		if aerr != nil {
			return errors.Wrap(errDeviceManagerFailed, aerr)
		}
		b, jerr := json.Marshal(d)
		if jerr != nil {
			return errors.Wrap(errDeviceManagerFailed, jerr)
		}
		resp = string(b)

	case "remove":
		if len(args) < 2 {
			return errors.Wrap(errDeviceManagerFailed, errInvalidCommand)
		}
		if err = a.devices.Remove(args[1]); err != nil {
			return errors.Wrap(errDeviceManagerFailed, err)
		}
		resp = "ok"

	case "get":
		if len(args) < 2 {
			return errors.Wrap(errDeviceManagerFailed, errInvalidCommand)
		}
		d, gerr := a.devices.Get(args[1])
		if gerr != nil {
			return errors.Wrap(errDeviceManagerFailed, gerr)
		}
		b, jerr := json.Marshal(d)
		if jerr != nil {
			return errors.Wrap(errDeviceManagerFailed, jerr)
		}
		resp = string(b)

	case "seen":
		if len(args) < 2 {
			return errors.Wrap(errDeviceManagerFailed, errInvalidCommand)
		}
		if err = a.devices.MarkSeen(args[1]); err != nil {
			return errors.Wrap(errDeviceManagerFailed, err)
		}
		resp = "ok"

	case "open":
		if len(args) < 2 {
			return errors.Wrap(errDeviceManagerFailed, errInvalidCommand)
		}
		if err = a.devices.OpenIface(args[1]); err != nil {
			return errors.Wrap(errDeviceManagerFailed, err)
		}
		resp = "ok"

	case "close":
		if len(args) < 2 {
			return errors.Wrap(errDeviceManagerFailed, errInvalidCommand)
		}
		if err = a.devices.CloseIface(args[1]); err != nil {
			return errors.Wrap(errDeviceManagerFailed, err)
		}
		resp = "ok"

	case "read":
		if len(args) < 3 {
			return errors.Wrap(errDeviceManagerFailed, errInvalidCommand)
		}
		n, serr := strconv.Atoi(args[2])
		if serr != nil || n <= 0 || n > 65536 {
			return errors.Wrap(errDeviceManagerFailed, errInvalidCommand)
		}
		data, rerr := a.devices.ReadIface(args[1], n)
		if rerr != nil {
			return errors.Wrap(errDeviceManagerFailed, rerr)
		}
		resp = fmt.Sprintf("%x", data)

	case "write":
		if len(args) < 3 {
			return errors.Wrap(errDeviceManagerFailed, errInvalidCommand)
		}
		written, werr := a.devices.WriteIface(args[1], args[2])
		if werr != nil {
			return errors.Wrap(errDeviceManagerFailed, werr)
		}
		resp = fmt.Sprintf("%d", written)

	default:
		return errors.Wrap(errDeviceManagerFailed, errUnknownCommand)
	}

	return a.processResponse(uuid, sub, resp)
}

func (a *agent) OpenDevice(ctx context.Context, id string) error {
	if a.devices == nil {
		return errDeviceManagerDisabled
	}
	return a.devices.OpenIface(id)
}

func (a *agent) CloseDevice(id string) error {
	if a.devices == nil {
		return errDeviceManagerDisabled
	}
	return a.devices.CloseIface(id)
}

func (a *agent) ReadDevice(id string, n int) ([]byte, error) {
	if a.devices == nil {
		return nil, errDeviceManagerDisabled
	}
	data, err := a.devices.ReadIface(id, n)
	if err != nil {
		return nil, err
	}
	if len(data) > 0 {
		return data, nil
	}
	if last := a.devices.LastReadData(id); len(last) > 0 {
		return last, nil
	}
	return data, nil
}

func (a *agent) WriteDevice(id, hexData string) (int, error) {
	if a.devices == nil {
		return 0, errDeviceManagerDisabled
	}
	return a.devices.WriteIface(id, hexData)
}

func (a *agent) GetRuntimeConfig(key string) (string, error) {
	if !settableKeys[key] {
		return "", errInvalidCommand
	}
	if a.store == nil {
		return "", errors.New(notConfigured)
	}
	if val, ok := a.store.Get(key); ok {
		if credentialKeys[key] {
			return notAllowed, nil
		}
		if key == keyCommandSecret {
			if _, ok := a.store.Get(key); ok {
				return "REDACTED", nil
			}
		}
		return val, nil
	}
	if fallback := a.configFallback(key); fallback != "" {
		return fallback, nil
	}
	return "", errors.New(notFound)
}

func (a *agent) SetRuntimeConfig(ctx context.Context, key, value string) error {
	if !settableKeys[key] {
		return errInvalidCommand
	}
	if err := validateSettableValue(key, value); err != nil {
		return err
	}
	if a.store == nil {
		return errors.New(notConfigured)
	}
	if err := a.store.Set(key, value); err != nil {
		return err
	}
	a.cfgMu.Lock()
	ApplyConfigEntry(a.config, key, value)
	a.cfgMu.Unlock()
	a.applyLiveUpdate(key, value)
	return nil
}

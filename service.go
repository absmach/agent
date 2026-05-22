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
	"os/exec"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	cfgstore "github.com/absmach/agent/pkg/config"
	"github.com/absmach/agent/pkg/devicemgr"
	"github.com/absmach/agent/pkg/encoder"
	"github.com/absmach/agent/pkg/iface"
	"github.com/absmach/agent/pkg/nodered"
	"github.com/absmach/agent/pkg/ota"
	"github.com/absmach/agent/pkg/terminal"
	"github.com/absmach/magistrala/pkg/errors"
	senml "github.com/absmach/senml"
	paho "github.com/eclipse/paho.mqtt.golang"
	toml "github.com/pelletier/go-toml"
)

const (
	Commands = "commands"
	config   = "config"

	view = "view"
	save = "save"

	char    = "c"
	open    = "open"
	close   = "close"
	control = "control"
	data    = "data"

	export = "export"
)

var startTime = time.Now()

// execAllowlist is the set of command names permitted via the exec MQTT command.
var execAllowlist = map[string]bool{
	"cat": true, "cd": true, "curl": true, "date": true, "df": true,
	"echo": true, "env": true, "false": true, "free": true, "hostname": true,
	"id": true, "ifconfig": true, "ip": true, "journalctl": true, "ls": true,
	"netstat": true, "ping": true, "printf": true, "ps": true, "pwd": true,
	"ss": true, "systemctl": true, "true": true, "uname": true, "uptime": true,
	"who": true,
}

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

	// errFailedExecute.
	errFailedExecute = errors.New("failed to execute command")

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
)

// Service specifies API for publishing messages and subscribing to topics.
type Service interface {
	// Execute command.
	Execute(uuid, cmd string) (string, error)

	// Control command.
	Control(uuid, cmdStr string) error

	// Update configuration file.
	AddConfig(Config) error

	// Config returns Config struct created from config file.
	Config() Config

	// Saves config file.
	ServiceConfig(ctx context.Context, uuid, cmdStr string) error

	// Services returns service list.
	Services() []Info

	// Terminal used for terminal control of gateway.
	Terminal(uuid, cmdStr string) error

	// Publish message.
	Publish(topic, payload string) error

	// Ping publishes an immediate heartbeat SenML record to the control channel.
	Ping() error

	// NodeRed manages Node-RED flow operations.
	NodeRed(cmdStr string) (string, error)

	// UpdateLiveness registers or refreshes the liveness of a local service from
	// an authenticated MQTT heartbeat message.
	UpdateLiveness(svcname, svctype string) error

	// OTA triggers an over-the-air binary update by downloading from url.
	OTA(ctx context.Context, url, sha256hex string, size uint64) error
	// Shutdown performs a graceful shutdown: stops all service heartbeat
	// tickers and disconnects the MQTT client.
	Shutdown()

	// DeviceManager handles downstream device registration and provisioning commands.
	DeviceManager(uuid, cmdStr string) error
}

var _ Service = (*agent)(nil)

type agent struct {
	mqttClient          paho.Client
	config              *Config
	noderedClient       nodered.Client
	logger              *slog.Logger
	svcs                map[string]Heartbeat
	terminals           map[string]terminal.Session
	devices             *devicemgr.Manager
	workDir             string
	otaBusy             atomic.Bool
	store               cfgstore.Store
	heartbeatIntervalCh chan time.Duration
	logLevel            *slog.LevelVar
	cfgMu               sync.RWMutex
	startupConfig       Config
}

// New returns agent service implementation.
func New(ctx context.Context, mc paho.Client, cfg *Config, nc nodered.Client, logger *slog.Logger, devices *devicemgr.Manager, store cfgstore.Store, levelVar *slog.LevelVar) (Service, error) {
	ag := &agent{
		mqttClient:          mc,
		noderedClient:       nc,
		config:              cfg,
		logger:              logger,
		svcs:                make(map[string]Heartbeat),
		terminals:           make(map[string]terminal.Session),
		devices:             devices,
		workDir:             "/",
		store:               store,
		heartbeatIntervalCh: make(chan time.Duration, 1),
		logLevel:            levelVar,
		startupConfig:       *cfg,
	}

	topic := fmt.Sprintf("m/%s/c/%s/gateway/heartbeat",
		cfg.DomainID, cfg.Channels.DataChan())
	go ag.selfHeartbeat(ctx, topic, cfg.Heartbeat.Interval, cfg.MQTT.QoS)

	return ag, nil
}

func (a *agent) changeDir(cmdArr []string) (string, error) {
	var target string
	if len(cmdArr) < 2 || cmdArr[1] == "~" {
		target = "/root"
	} else if strings.HasPrefix(cmdArr[1], "/") {
		target = cmdArr[1]
	} else {
		target = a.workDir + "/" + cmdArr[1]
	}
	if info, statErr := os.Stat(target); statErr != nil || !info.IsDir() {
		return "sh: cd: " + target + ": No such file or directory", nil
	}
	a.workDir = target
	return "(no output)", nil
}

func (a *agent) Execute(uuid, cmd string) (string, error) {
	cmdArr := strings.Split(strings.ReplaceAll(cmd, " ", ""), ",")
	if len(cmdArr) < 1 || cmdArr[0] == "" {
		return "", errInvalidCommand
	}

	if cmdArr[0] == "cd" {
		return a.changeDir(cmdArr)
	}

	if !execAllowlist[cmdArr[0]] {
		return "", errInvalidCommand
	}

	execCmd := exec.Command(cmdArr[0], cmdArr[1:]...)
	execCmd.Dir = a.workDir
	out, err := execCmd.CombinedOutput()
	if err != nil && len(out) == 0 {
		return "", errors.Wrap(errFailedExecute, err)
	}

	payload, err := encoder.EncodeSenML(uuid, strings.Join(cmdArr, " "), string(out))
	if err != nil {
		return "", errors.Wrap(errFailedEncode, err)
	}

	if err := a.Publish(control, string(payload)); err != nil {
		return "", errors.Wrap(errFailedToPublish, err)
	}

	output := string(out)
	if output == "" {
		output = "(no output)"
	}

	return output, nil
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

// Message for this command
// [{"bn":"1:", "n":"services", "vs":"view"}]
// [{"bn":"1:", "n":"config", "vs":"save, export, filename, filecontent"}]
// config_file_content is base64 encoded marshaled structure representing service conf
// Example of creation:
//
//	b, _ := toml.Marshal(cfg)
//	config_file_content := base64.StdEncoding.EncodeToString(b).
func (a *agent) ServiceConfig(ctx context.Context, uuid, cmdStr string) error {
	cmdArgs := strings.Split(strings.ReplaceAll(cmdStr, " ", ""), ",")
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
		if !settableKeys[cmdArgs[1]] {
			return errInvalidCommand
		}
		if a.store == nil {
			resp = "not_configured"
		} else if val, ok := a.store.Get(cmdArgs[1]); ok {
			resp = val
		} else {
			resp = "not_found"
		}
	case "set":
		// Use SplitN(3) so values containing commas (e.g. URLs) are preserved.
		setArgs := strings.SplitN(strings.ReplaceAll(cmdStr, " ", ""), ",", 3)
		if len(setArgs) < 3 || setArgs[1] == "" || setArgs[2] == "" {
			return errInvalidCommand
		}
		key, val := setArgs[1], setArgs[2]
		if !settableKeys[key] {
			return errInvalidCommand
		}
		if err := validateSettableValue(key, val); err != nil {
			return err
		}
		if a.store == nil {
			resp = "not_configured"
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
	case "reset":
		if len(cmdArgs) < 2 || cmdArgs[1] == "" {
			return errInvalidCommand
		}
		key := cmdArgs[1]
		if !settableKeys[key] {
			return errInvalidCommand
		}
		if a.store == nil {
			resp = "not_configured"
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
	if _, ok := a.terminals[uuid]; !ok {
		term, err := terminal.NewSession(uuid, timeout, a.Publish, a.logger)
		if err != nil {
			return errors.Wrap(errors.Wrap(errFailedToCreateTerminalSession, fmt.Errorf(" for %s", uuid)), err)
		}
		a.terminals[uuid] = term
		go func() {
			for range term.IsDone() {
				_ = a.terminalClose(uuid)
				delete(a.terminals, uuid)
				return
			}
		}()
	}
	return nil
}

func (a *agent) terminalClose(uuid string) error {
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
	term := a.terminals[uuid]
	p := []byte(cmd)
	return term.Send(p)
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
	payload, err := encoder.EncodeSenML(uuid, cmd, resp)
	if err != nil {
		return errors.Wrap(errFailedEncode, err)
	}
	if err := a.Publish(control, string(payload)); err != nil {
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

func (a *agent) Services() []Info {
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
	topic := a.getTopic(t)
	mqtt := a.Config().MQTT
	token := a.mqttClient.Publish(topic, mqtt.QoS, mqtt.Retain, payload)
	token.Wait()
	err := token.Error()
	if err != nil {
		return errors.New(err.Error())
	}
	return nil
}

func (a *agent) selfHeartbeat(ctx context.Context, topic string, interval time.Duration, qos byte) {
	svcType := "agent"
	pack := senml.Pack{Records: []senml.Record{
		{BaseName: "agent:", Name: "service_type", StringValue: &svcType},
	}}
	payload, err := senml.Encode(pack, senml.JSON)
	if err != nil {
		a.logger.Error("failed to encode self-heartbeat", slog.Any("error", err))
		return
	}

	publish := func() {
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

func (a *agent) UpdateLiveness(svcname, svctype string) error {
	if _, ok := a.svcs[svcname]; !ok {
		svc := NewHeartbeat(svcname, svctype, a.Config().Heartbeat.Interval)
		a.svcs[svcname] = svc
	}
	a.svcs[svcname].Update()
	return nil
}

func (a *agent) Ping() error {
	now := float64(time.Now().UnixNano())
	vb := true
	uptime := time.Since(startTime).Seconds()
	pack := senml.Pack{Records: []senml.Record{
		{BaseName: "gw:", BaseTime: now, Name: "heartbeat", BoolValue: &vb},
		{Name: "uptime", Unit: "s", Value: &uptime},
	}}
	b, err := senml.Encode(pack, senml.JSON)
	if err != nil {
		return err
	}
	return a.Publish(control, string(b))
}

func (a *agent) OTA(ctx context.Context, url, sha256hex string, size uint64) error {
	if !a.config.OTA.Enabled {
		return errors.New("OTA is disabled")
	}
	if !a.otaBusy.CompareAndSwap(false, true) {
		return errors.New("OTA already in progress")
	}
	defer a.otaBusy.Store(false)

	otaCfg := ota.Config{
		BinaryPath:  a.config.OTA.BinaryPath,
		DownloadDir: a.config.OTA.DownloadDir,
	}

	domainID := a.config.DomainID
	ctrlChan := a.config.Channels.CtrlChan()
	qos := a.config.MQTT.QoS
	statusTopic := fmt.Sprintf("m/%s/c/%s/ota/status", domainID, ctrlChan)

	progressFn := func(state ota.State, progress float64) {
		now := float64(time.Now().UnixNano())
		stateStr := strings.ToLower(state.String())
		statusPack := senml.Pack{Records: []senml.Record{
			{BaseName: "gw:", BaseTime: now, Name: "ota_state", StringValue: &stateStr},
			{Name: "ota_progress", Unit: "%", Value: &progress},
		}}
		b, err := senml.Encode(statusPack, senml.JSON)
		if err != nil {
			a.logger.Warn("Failed to encode OTA status", slog.Any("error", err))
			return
		}
		token := a.mqttClient.Publish(statusTopic, qos, false, b)
		token.Wait()
	}

	return ota.Run(ctx, otaCfg, url, sha256hex, size, progressFn)
}

func (a *agent) Shutdown() {
	a.logger.Debug("shutting down service heartbeats")
	for name, svc := range a.svcs {
		svc.Stop()
		a.logger.Debug("stopped service heartbeat", slog.String("service", name))
	}

	a.logger.Debug("disconnecting MQTT client")
	a.mqttClient.Disconnect(1000)
	a.logger.Info("graceful shutdown complete")
}

// settableKeys is the allowlist of config keys readable/writable via MQTT
// get/set. Only these keys are accepted; unknown keys are rejected to prevent
// arbitrary storage growth.
var settableKeys = map[string]bool{
	"log_level":                true,
	"heartbeat_interval":       true,
	"terminal_session_timeout": true,
}

// validateSettableValue returns errInvalidCommand if val is not a valid value for key.
func validateSettableValue(key, val string) error {
	switch key {
	case "log_level":
		var l slog.Level
		if err := l.UnmarshalText([]byte(val)); err != nil {
			return errInvalidCommand
		}
	case "heartbeat_interval":
		d, err := time.ParseDuration(val)
		if err != nil || d < time.Second {
			return errInvalidCommand
		}
	case "terminal_session_timeout":
		d, err := time.ParseDuration(val)
		if err != nil || d <= 0 {
			return errInvalidCommand
		}
	}
	return nil
}

// revertToStartup restores key's value from startupConfig and applies the
// live update so running subsystems reflect the reverted value immediately.
func (a *agent) revertToStartup(key string) {
	a.cfgMu.Lock()
	var liveVal string
	switch key {
	case "log_level":
		a.config.Log.Level = a.startupConfig.Log.Level
		liveVal = a.config.Log.Level
	case "heartbeat_interval":
		a.config.Heartbeat.Interval = a.startupConfig.Heartbeat.Interval
		liveVal = a.config.Heartbeat.Interval.String()
	case "terminal_session_timeout":
		a.config.Terminal.SessionTimeout = a.startupConfig.Terminal.SessionTimeout
		liveVal = a.config.Terminal.SessionTimeout.String()
	}
	a.cfgMu.Unlock()
	if liveVal != "" {
		a.applyLiveUpdate(key, liveVal)
	}
}

// ApplyConfigEntry updates cfg in place for the known settable keys.
// Used at startup to replay persisted overrides before the agent starts.
func ApplyConfigEntry(cfg *Config, key, val string) {
	switch key {
	case "log_level":
		cfg.Log.Level = val
	case "heartbeat_interval":
		if d, err := time.ParseDuration(val); err == nil && d > 0 {
			cfg.Heartbeat.Interval = d
		}
	case "terminal_session_timeout":
		if d, err := time.ParseDuration(val); err == nil && d > 0 {
			cfg.Terminal.SessionTimeout = d
		}
	}
}

// applyLiveUpdate propagates a config change to running subsystems so the
// effect is immediate without requiring a restart.
func (a *agent) applyLiveUpdate(key, val string) {
	switch key {
	case "log_level":
		if a.logLevel != nil {
			var l slog.Level
			if err := l.UnmarshalText([]byte(val)); err == nil {
				a.logLevel.Set(l)
			}
		}
	case "heartbeat_interval":
		if d, err := time.ParseDuration(val); err == nil && d > 0 {
			select {
			case a.heartbeatIntervalCh <- d:
			default:
			}
		}
	}
}

func (a *agent) getTopic(topic string) (t string) {
	cfg := a.Config()
	domainID := cfg.DomainID
	switch topic {
	case control:
		t = fmt.Sprintf("m/%s/c/%s/res", domainID, cfg.Channels.CtrlChan())
	case data:
		t = fmt.Sprintf("m/%s/c/%s/gateway/telemetry", domainID, a.config.Channels.DataChan())
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
func (a *agent) DeviceManager(uuid, cmdStr string) error {
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
		d, aerr := a.devices.Add(context.Background(), addReq.Name, addReq.ExternalID, addReq.ExternalKey, ifaceType, addReq.IfaceAddr)
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

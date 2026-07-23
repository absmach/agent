// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

package remote

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/absmach/agent"
	"github.com/absmach/agent/pkg/logstream"
	"github.com/absmach/agent/pkg/terminal"
	"github.com/eclipse/paho.golang/autopaho"
	"github.com/eclipse/paho.golang/paho"
	"github.com/gofrs/uuid/v5"
)

const (
	defaultSessionExpiry = 24 * time.Hour
	defaultStreamLife    = 10 * time.Minute
	defaultStreamIdle    = 60 * time.Second
	defaultStreamBytes   = int64(8 << 20)
	defaultStreamRate    = 100
	defaultRequestBytes  = 1 << 20
	defaultRequestSlots  = 16
)

type MQTTConfig struct {
	URL             string
	Username        string
	Password        string
	ClientID        string
	MTLS            bool
	SkipTLSVerify   bool
	CA              []byte
	Certificate     tls.Certificate
	DomainID        string
	ControlChannel  string
	DataChannel     string
	StorePath       string
	SessionExpiry   time.Duration
	StreamLifetime  time.Duration
	StreamIdle      time.Duration
	MaxStreamBytes  int64
	MaxStreamRate   int
	MaxRequestBytes int
	MaxRequests     int
}

type streamSession struct {
	id       string
	kind     string
	cancel   context.CancelFunc
	terminal terminal.Session
	sequence atomic.Uint64
	bytes    atomic.Int64
	lastSeen atomic.Int64
	rateMu   sync.Mutex
	rateAt   time.Time
	rateUsed int
}

// MQTTServer is the Agent-side MQTT 5 remote-management endpoint.
type MQTTServer struct {
	ctx       context.Context
	cfg       MQTTConfig
	svc       agent.Service
	logs      *logstream.Stream
	logger    *slog.Logger
	store     *Store
	executor  *Executor
	router    *paho.StandardRouter
	client    *autopaho.ConnectionManager
	streamMu  sync.Mutex
	streams   map[string]*streamSession
	pendingMu sync.Mutex
	pending   map[string]chan Response
	requests  chan struct{}
	agentID   string
	bootID    string
	closeOnce sync.Once
}

func NewMQTTServer(ctx context.Context, cfg MQTTConfig, svc agent.Service, logs *logstream.Stream, logger *slog.Logger) (*MQTTServer, error) {
	if cfg.DomainID == "" || cfg.ControlChannel == "" || cfg.DataChannel == "" {
		return nil, fmt.Errorf("remote MQTT domain, control channel and data channel are required")
	}
	if cfg.ControlChannel == cfg.DataChannel {
		return nil, fmt.Errorf("remote MQTT control and data channels must be different")
	}
	if cfg.Username == "" || strings.ContainsAny(cfg.Username, "/+#") {
		return nil, fmt.Errorf("remote MQTT username must be non-empty and MQTT-topic safe")
	}
	if cfg.StorePath == "" {
		cfg.StorePath = "/var/lib/agent/remote.db"
	}
	if cfg.SessionExpiry <= 0 {
		cfg.SessionExpiry = defaultSessionExpiry
	}
	if cfg.StreamLifetime <= 0 {
		cfg.StreamLifetime = defaultStreamLife
	}
	if cfg.StreamIdle <= 0 {
		cfg.StreamIdle = defaultStreamIdle
	}
	if cfg.MaxStreamBytes <= 0 {
		cfg.MaxStreamBytes = defaultStreamBytes
	}
	if cfg.MaxStreamRate <= 0 {
		cfg.MaxStreamRate = defaultStreamRate
	}
	if cfg.MaxRequestBytes <= 0 {
		cfg.MaxRequestBytes = defaultRequestBytes
	}
	if cfg.MaxRequests <= 0 {
		cfg.MaxRequests = defaultRequestSlots
	}
	if err := os.MkdirAll(filepath.Dir(cfg.StorePath), 0o700); err != nil {
		return nil, err
	}
	store, err := NewStore(cfg.StorePath)
	if err != nil {
		return nil, fmt.Errorf("open remote protocol store: %w", err)
	}
	s := &MQTTServer{
		ctx: ctx, cfg: cfg, svc: svc, logs: logs, logger: logger,
		store: store, streams: make(map[string]*streamSession),
		pending: make(map[string]chan Response), agentID: cfg.Username,
		requests: make(chan struct{}, cfg.MaxRequests),
	}
	bootID, _ := uuid.NewV4()
	s.bootID = bootID.String()
	s.executor = NewExecutor(svc, store, s.publishJob)
	s.executor.SetStreams(s)
	s.router = paho.NewStandardRouter()
	s.registerRoutes()

	serverURL, err := mqtt5URL(cfg.URL)
	if err != nil {
		_ = store.Close()
		return nil, err
	}
	tlsConfig, err := mqttTLSConfig(cfg, serverURL)
	if err != nil {
		_ = store.Close()
		return nil, err
	}
	clientID := cfg.ClientID
	if clientID == "" {
		clientID = cfg.Username + "-agent-rpc"
	}
	sessionSeconds := uint32(cfg.SessionExpiry / time.Second)
	format := byte(1)
	willExpiry := uint32(7 * 24 * time.Hour / time.Second)
	willPayload, _ := json.Marshal(s.presence("offline"))
	clientConfig := autopaho.ClientConfig{
		ServerUrls:                    []*url.URL{serverURL},
		TlsCfg:                        tlsConfig,
		KeepAlive:                     30,
		CleanStartOnInitialConnection: true,
		SessionExpiryInterval:         sessionSeconds,
		ConnectUsername:               cfg.Username,
		ConnectPassword:               []byte(cfg.Password),
		WillMessage: &paho.WillMessage{
			Topic: s.dataTopic("gateway/presence"), Payload: willPayload, QoS: 1, Retain: true,
		},
		WillProperties: &paho.WillProperties{
			ContentType: "application/json", PayloadFormat: &format, MessageExpiry: &willExpiry,
			User: paho.UserProperties{{Key: "api-version", Value: APIVersion}},
		},
		OnConnectionUp: func(cm *autopaho.ConnectionManager, _ *paho.Connack) {
			s.subscribe(cm)
			if s.client != nil {
				go func() {
					if err := s.publishPresence("online"); err != nil {
						s.logger.Warn("Failed to publish presence after reconnect", slog.Any("error", err))
					}
					if err := s.publishReportedState("connected"); err != nil {
						s.logger.Warn("Failed to publish reported state after reconnect", slog.Any("error", err))
					}
				}()
			}
		},
		OnConnectError: func(err error) {
			s.logger.Warn("Remote MQTT 5 connection failed", slog.Any("error", err))
		},
		ClientConfig: paho.ClientConfig{
			ClientID: clientID,
			OnPublishReceived: []func(paho.PublishReceived) (bool, error){
				func(received paho.PublishReceived) (bool, error) {
					s.router.Route(received.Packet.Packet())
					return true, nil
				},
			},
			OnClientError: func(err error) {
				s.logger.Warn("Remote MQTT 5 client error", slog.Any("error", err))
			},
			OnServerDisconnect: func(disconnect *paho.Disconnect) {
				s.logger.Warn("Remote MQTT 5 server disconnected", slog.Uint64("reason_code", uint64(disconnect.ReasonCode)))
			},
		},
	}
	cm, err := autopaho.NewConnection(ctx, clientConfig)
	if err != nil {
		_ = store.Close()
		return nil, err
	}
	s.client = cm
	awaitCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	if err := cm.AwaitConnection(awaitCtx); err != nil {
		_ = store.Close()
		return nil, fmt.Errorf("connect remote MQTT 5 client: %w", err)
	}
	if err := s.publishPresence("online"); err != nil {
		s.logger.Warn("Failed to publish initial presence", slog.Any("error", err))
	}
	if err := s.publishReportedState("connected"); err != nil {
		s.logger.Warn("Failed to publish initial reported state", slog.Any("error", err))
	}

	svc.SetPushEvent(func(eventType string) {
		go s.publishChange(eventType)
	})
	go s.pruneLoop()
	return s, nil
}

func (s *MQTTServer) registerRoutes() {
	s.router.RegisterHandler(s.controlTopic("req"), func(message *paho.Publish) {
		s.dispatchRequest(message)
	})
	s.router.RegisterHandler(s.controlTopic("gateway/state/desired"), func(message *paho.Publish) {
		go s.handleDesired(message)
	})
	s.router.RegisterHandler(s.controlTopic("gateway/streams/+/control"), func(message *paho.Publish) {
		go s.handleStreamControl(message)
	})
	s.router.RegisterHandler(s.controlTopic("gateway/streams/+/in"), func(message *paho.Publish) {
		go s.handleStreamInput(message)
	})
	s.router.RegisterHandler(s.controlTopic("service/+/res/"+s.agentID+"/"+s.bootID), func(message *paho.Publish) {
		go s.handleServiceResponse(message)
	})
}

func (s *MQTTServer) dispatchRequest(message *paho.Publish) {
	responseTopic, correlation, _ := s.validateRequestProperties(message)
	request, _ := DecodeRequest(message.Payload)
	if len(message.Payload) > s.cfg.MaxRequestBytes {
		s.publishResponse(responseTopic, correlation, ErrorResponse(
			request.ID, CodeResourceLimit, "request payload exceeds the configured limit", nil,
		))
		return
	}
	select {
	case s.requests <- struct{}{}:
		go func() {
			defer func() { <-s.requests }()
			s.handleRequest(message)
		}()
	default:
		s.publishResponse(responseTopic, correlation, ErrorResponse(
			request.ID, CodeResourceLimit, "too many concurrent requests", map[string]bool{"retryable": true},
		))
	}
}

func (s *MQTTServer) subscribe(cm *autopaho.ConnectionManager) {
	topics := []paho.SubscribeOptions{
		{Topic: s.controlTopic("req"), QoS: 1},
		{Topic: s.controlTopic("gateway/state/desired"), QoS: 1},
		{Topic: s.controlTopic("gateway/streams/+/control"), QoS: 1},
		{Topic: s.controlTopic("gateway/streams/+/in"), QoS: 0},
		{Topic: s.controlTopic("service/+/res/" + s.agentID + "/" + s.bootID), QoS: 1},
	}
	ctx, cancel := context.WithTimeout(s.ctx, 10*time.Second)
	defer cancel()
	if _, err := cm.Subscribe(ctx, &paho.Subscribe{Subscriptions: topics}); err != nil {
		s.logger.Error("Remote MQTT 5 subscription failed", slog.Any("error", err))
	}
}

// CallService performs Agent-to-server JSON-RPC over the same control channel.
// The logical service name is part of the topic so server-side workers can be
// independently authorized and scaled.
func (s *MQTTServer) CallService(ctx context.Context, serviceName, method string, params any) (json.RawMessage, *RPCError) {
	if serviceName == "" || strings.ContainsAny(serviceName, "/+#") {
		return nil, &RPCError{Code: CodeInvalidParams, Message: "invalid service name"}
	}
	id, err := uuid.NewV4()
	if err != nil {
		return nil, RPCErrorFrom(err)
	}
	rawParams, err := json.Marshal(params)
	if err != nil {
		return nil, &RPCError{Code: CodeInvalidParams, Message: "invalid service parameters"}
	}
	request := Request{
		JSONRPC: JSONRPCVersion, ID: id.String(), Method: method, Params: rawParams,
	}
	payload, _ := json.Marshal(request)
	correlation, _ := CorrelationData(request.ID)
	responseTopic := s.controlTopic("service/" + serviceName + "/res/" + s.agentID + "/" + s.bootID)
	deadline, hasDeadline := ctx.Deadline()
	if !hasDeadline {
		deadline = time.Now().Add(30 * time.Second)
	}
	remaining := time.Until(deadline)
	if remaining <= 0 {
		return nil, &RPCError{Code: CodeRequestExpired, Message: "service request deadline expired"}
	}
	expiry := uint32(max(1, int64(remaining/time.Second)))
	format := byte(1)
	responseCh := make(chan Response, 1)
	s.pendingMu.Lock()
	s.pending[request.ID] = responseCh
	s.pendingMu.Unlock()
	defer func() {
		s.pendingMu.Lock()
		delete(s.pending, request.ID)
		s.pendingMu.Unlock()
	}()
	if err := s.publish(s.controlTopic("service/"+serviceName+"/req"), payload, 1, false, &paho.PublishProperties{
		ResponseTopic: responseTopic, CorrelationData: correlation,
		ContentType: "application/json", PayloadFormat: &format, MessageExpiry: &expiry,
		User: paho.UserProperties{
			{Key: "api-version", Value: APIVersion},
			{Key: "request-deadline", Value: deadline.UTC().Format(time.RFC3339Nano)},
		},
	}); err != nil {
		return nil, RPCErrorFrom(err)
	}
	select {
	case response := <-responseCh:
		if response.Error != nil {
			return nil, response.Error
		}
		return response.Result, nil
	case <-ctx.Done():
		return nil, &RPCError{Code: CodeRequestExpired, Message: ctx.Err().Error()}
	}
}

func (s *MQTTServer) handleServiceResponse(message *paho.Publish) {
	if message.Properties == nil ||
		len(message.Properties.CorrelationData) != 16 ||
		message.Properties.ContentType != "application/json" ||
		message.Properties.PayloadFormat == nil || *message.Properties.PayloadFormat != 1 ||
		message.Properties.User.Get("api-version") != APIVersion {
		return
	}
	var response Response
	if json.Unmarshal(message.Payload, &response) != nil ||
		!CorrelationMatches(response.ID, message.Properties.CorrelationData) {
		return
	}
	s.pendingMu.Lock()
	pending := s.pending[response.ID]
	s.pendingMu.Unlock()
	if pending == nil {
		return
	}
	select {
	case pending <- response:
	default:
	}
}

func (s *MQTTServer) handleRequest(message *paho.Publish) {
	responseTopic, correlation, validationErr := s.validateRequestProperties(message)
	req, decodeErr := DecodeRequest(message.Payload)
	if validationErr != nil {
		s.publishResponse(responseTopic, correlation, ErrorResponse(req.ID, validationErr.Code, validationErr.Message, validationErr.Data))
		return
	}
	if decodeErr != nil {
		s.publishResponse(responseTopic, correlation, Response{JSONRPC: JSONRPCVersion, ID: req.ID, Error: decodeErr})
		return
	}
	if !CorrelationMatches(req.ID, correlation) {
		s.publishResponse(responseTopic, correlation, ErrorResponse(req.ID, CodeInvalidRequest, "JSON-RPC id does not match MQTT Correlation Data", nil))
		return
	}
	if deadline := message.Properties.User.Get("request-deadline"); deadline != "" {
		parsed, err := time.Parse(time.RFC3339Nano, deadline)
		if err != nil || time.Now().After(parsed) {
			s.publishResponse(responseTopic, correlation, ErrorResponse(req.ID, CodeRequestExpired, "request deadline expired", nil))
			return
		}
	} else {
		s.publishResponse(responseTopic, correlation, ErrorResponse(req.ID, CodeInvalidRequest, "request-deadline MQTT property is required", nil))
		return
	}

	response := s.executor.Execute(s.ctx, req)
	s.publishResponse(responseTopic, correlation, response)
}

func (s *MQTTServer) validateRequestProperties(message *paho.Publish) (string, []byte, *RPCError) {
	if message.Properties == nil {
		return "", nil, &RPCError{Code: CodeInvalidRequest, Message: "MQTT 5 request properties are required"}
	}
	responseTopic := message.Properties.ResponseTopic
	correlation := append([]byte(nil), message.Properties.CorrelationData...)
	expectedPrefix := s.controlTopic("res/")
	if responseTopic == "" || !strings.HasPrefix(responseTopic, expectedPrefix) ||
		strings.ContainsAny(responseTopic, "+#") {
		return "", correlation, &RPCError{Code: CodeInvalidRequest, Message: "invalid MQTT Response Topic"}
	}
	if len(correlation) != 16 {
		return responseTopic, correlation, &RPCError{Code: CodeInvalidRequest, Message: "MQTT Correlation Data must be a 16-byte UUID"}
	}
	if message.Properties.ContentType != "application/json" {
		return responseTopic, correlation, &RPCError{Code: CodeInvalidRequest, Message: "Content Type must be application/json"}
	}
	if message.Properties.PayloadFormat == nil || *message.Properties.PayloadFormat != 1 {
		return responseTopic, correlation, &RPCError{Code: CodeInvalidRequest, Message: "Payload Format Indicator must be UTF-8"}
	}
	if message.Properties.MessageExpiry == nil || *message.Properties.MessageExpiry == 0 {
		return responseTopic, correlation, &RPCError{Code: CodeInvalidRequest, Message: "Message Expiry Interval is required"}
	}
	if message.Properties.User.Get("api-version") != APIVersion {
		return responseTopic, correlation, &RPCError{Code: CodeInvalidRequest, Message: "unsupported api-version"}
	}
	return responseTopic, correlation, nil
}

func (s *MQTTServer) publishResponse(topic string, correlation []byte, response Response) {
	if topic == "" {
		s.logger.Warn("Cannot publish JSON-RPC response without a valid response topic")
		return
	}
	payload, err := json.Marshal(response)
	if err != nil {
		s.logger.Error("Failed to encode JSON-RPC response", slog.Any("error", err))
		return
	}
	expiry := uint32(30)
	format := byte(1)
	properties := &paho.PublishProperties{
		CorrelationData: correlation, ContentType: "application/json",
		PayloadFormat: &format, MessageExpiry: &expiry,
		User: paho.UserProperties{{Key: "api-version", Value: APIVersion}},
	}
	if err := s.publish(topic, payload, 1, false, properties); err != nil {
		s.logger.Error("Failed to publish JSON-RPC response", slog.Any("error", err))
	}
}

func (s *MQTTServer) handleDesired(message *paho.Publish) {
	if message.Properties == nil ||
		message.Properties.ContentType != "application/json" ||
		message.Properties.PayloadFormat == nil || *message.Properties.PayloadFormat != 1 ||
		message.Properties.User.Get("api-version") != APIVersion {
		s.publishEvent("configuration.rejected", map[string]any{"error": "invalid MQTT properties"})
		return
	}
	var desired struct {
		SchemaVersion int               `json:"schemaVersion"`
		Generation    uint64            `json:"generation"`
		Config        map[string]string `json:"config"`
	}
	if err := json.Unmarshal(message.Payload, &desired); err != nil || desired.SchemaVersion != 1 || desired.Generation == 0 {
		s.publishEvent("configuration.rejected", map[string]any{"error": "invalid desired state"})
		return
	}
	current, err := s.store.DesiredGeneration()
	if err != nil {
		s.publishEvent("configuration.rejected", map[string]any{"error": "failed to read desired generation"})
		return
	}
	if desired.Generation < current {
		s.publishEvent("configuration.rejected", map[string]any{
			"generation": desired.Generation, "appliedGeneration": current, "error": "stale desired state",
		})
		return
	}
	if desired.Generation == current {
		_ = s.publishReportedState("desired-replayed")
		return
	}
	for key, value := range desired.Config {
		if err := s.svc.SetRuntimeConfig(s.ctx, key, value); err != nil {
			s.publishEvent("configuration.rejected", map[string]any{
				"generation": desired.Generation, "key": key, "error": err.Error(),
			})
			return
		}
	}
	if err := s.store.SetDesiredGeneration(desired.Generation); err != nil {
		s.publishEvent("configuration.rejected", map[string]any{
			"generation": desired.Generation, "error": "failed to persist desired generation",
		})
		return
	}
	s.publishEvent("configuration.applied", map[string]any{"generation": desired.Generation})
	_ = s.publishReportedState("desired-applied")
}

func (s *MQTTServer) publishChange(eventType string) {
	s.publishEvent(eventType+".changed", nil)
	if err := s.publishReportedState(eventType + "-changed"); err != nil {
		s.logger.Warn("Failed to publish reported state", slog.Any("error", err))
	}
}

func (s *MQTTServer) publishEvent(eventType string, data any) {
	payload := map[string]any{
		"schemaVersion": 1, "type": eventType,
		"timestamp": time.Now().UTC(), "data": data,
	}
	encoded, _ := json.Marshal(payload)
	expiry := uint32(3600)
	format := byte(1)
	_ = s.publish(s.dataTopic("gateway/events"), encoded, 1, false, &paho.PublishProperties{
		ContentType: "application/json", PayloadFormat: &format, MessageExpiry: &expiry,
		User: paho.UserProperties{{Key: "api-version", Value: APIVersion}},
	})
}

func (s *MQTTServer) publishJob(job Job) {
	encoded, _ := json.Marshal(map[string]any{
		"schemaVersion": 1, "timestamp": time.Now().UTC(), "job": job,
	})
	expiry := uint32(86400)
	format := byte(1)
	_ = s.publish(s.dataTopic("gateway/jobs/events"), encoded, 1, false, &paho.PublishProperties{
		ContentType: "application/json", PayloadFormat: &format, MessageExpiry: &expiry,
		User: paho.UserProperties{{Key: "api-version", Value: APIVersion}},
	})
}

func (s *MQTTServer) publishReportedState(reason string) error {
	devices, _ := s.svc.ListDevices()
	appliedGeneration, _ := s.store.DesiredGeneration()
	state := map[string]any{
		"schemaVersion": 1, "reportedAt": time.Now().UTC(), "reason": reason,
		"agentId": s.agentID, "bootId": s.bootID, "capabilities": SupportedMethods,
		"appliedGeneration": appliedGeneration,
		"health":            s.executor.health(), "config": redactedConfig(s.svc.Config()),
		"services": s.svc.Services(), "devices": devices, "ota": s.svc.OTAStatus(),
	}
	encoded, err := json.Marshal(state)
	if err != nil {
		return err
	}
	format := byte(1)
	return s.publish(s.dataTopic("gateway/state/reported"), encoded, 1, true, &paho.PublishProperties{
		ContentType: "application/json", PayloadFormat: &format,
		User: paho.UserProperties{{Key: "api-version", Value: APIVersion}},
	})
}

func (s *MQTTServer) presence(status string) map[string]any {
	return map[string]any{
		"schemaVersion": 1,
		"agentId":       s.agentID,
		"bootId":        s.bootID,
		"status":        status,
		"timestamp":     time.Now().UTC(),
		"capabilities":  SupportedMethods,
	}
}

func (s *MQTTServer) publishPresence(status string) error {
	payload, err := json.Marshal(s.presence(status))
	if err != nil {
		return err
	}
	format := byte(1)
	expiry := uint32(7 * 24 * time.Hour / time.Second)
	return s.publish(s.dataTopic("gateway/presence"), payload, 1, true, &paho.PublishProperties{
		ContentType: "application/json", PayloadFormat: &format, MessageExpiry: &expiry,
		User: paho.UserProperties{{Key: "api-version", Value: APIVersion}},
	})
}

func (s *MQTTServer) OpenLog(_ context.Context, raw json.RawMessage) (any, *RPCError) {
	var params struct {
		Backlog bool `json:"backlog"`
	}
	if len(raw) > 0 {
		if _, rpcErr := DecodeParams[struct {
			Backlog bool `json:"backlog"`
		}](raw); rpcErr != nil {
			return nil, rpcErr
		} else {
			_ = json.Unmarshal(raw, &params)
		}
	}
	if s.logs == nil {
		return nil, &RPCError{Code: CodeInternalError, Message: "log stream is unavailable"}
	}
	session, ctx := s.newStream("log")
	backlog, lines, unsubscribe := s.logs.Subscribe()
	if !params.Backlog {
		backlog = nil
	}
	go func() {
		defer unsubscribe()
		defer s.removeStream(session.id)
		for _, line := range backlog {
			if err := s.publishLogFrame(session, line); err != nil {
				return
			}
		}
		for {
			select {
			case line := <-lines:
				if err := s.publishLogFrame(session, line); err != nil {
					return
				}
			case <-ctx.Done():
				return
			}
		}
	}()
	return s.streamDescriptor(session), nil
}

func (s *MQTTServer) OpenTerminal(_ context.Context, raw json.RawMessage) (any, *RPCError) {
	params, rpcErr := DecodeParams[struct {
		Columns int `json:"columns,omitempty"`
		Rows    int `json:"rows,omitempty"`
	}](raw)
	if rpcErr != nil {
		return nil, rpcErr
	}
	session, ctx := s.newStream("terminal")
	term, err := terminal.NewStreamSession(session.id, s.cfg.StreamIdle, func(data []byte) error {
		return s.publishTerminalFrame(session, data)
	}, s.logger)
	if err != nil {
		s.removeStream(session.id)
		return nil, RPCErrorFrom(err)
	}
	session.terminal = term
	if params.Columns > 0 && params.Rows > 0 {
		_ = term.Resize(uint16(params.Columns), uint16(params.Rows))
	}
	go func() {
		select {
		case <-ctx.Done():
		case <-term.IsDone():
		}
		s.removeStream(session.id)
	}()
	return s.streamDescriptor(session), nil
}

func (s *MQTTServer) CloseStream(raw json.RawMessage) (any, *RPCError) {
	params, rpcErr := DecodeParams[struct {
		SessionID string `json:"sessionId"`
	}](raw)
	if rpcErr != nil || params.SessionID == "" {
		return nil, required(rpcErr, "sessionId")
	}
	if !s.removeStream(params.SessionID) {
		return nil, &RPCError{Code: CodeStreamNotFound, Message: "stream not found"}
	}
	return map[string]string{"status": "closed"}, nil
}

func (s *MQTTServer) newStream(kind string) (*streamSession, context.Context) {
	id, _ := uuid.NewV4()
	ctx, cancel := context.WithTimeout(s.ctx, s.cfg.StreamLifetime)
	session := &streamSession{id: id.String(), kind: kind, cancel: cancel}
	session.touch()
	s.streamMu.Lock()
	s.streams[session.id] = session
	s.streamMu.Unlock()
	go s.expireIdleStream(ctx, session)
	return session, ctx
}

func (s *MQTTServer) expireIdleStream(ctx context.Context, session *streamSession) {
	interval := min(time.Second, s.cfg.StreamIdle/2)
	if interval <= 0 {
		interval = time.Second
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			lastSeen := time.Unix(0, session.lastSeen.Load())
			if time.Since(lastSeen) >= s.cfg.StreamIdle {
				s.removeStream(session.id)
				return
			}
		case <-ctx.Done():
			return
		}
	}
}

func (session *streamSession) touch() {
	session.lastSeen.Store(time.Now().UnixNano())
}

func (session *streamSession) allow(maxPerSecond int) bool {
	now := time.Now()
	session.rateMu.Lock()
	defer session.rateMu.Unlock()
	if session.rateAt.IsZero() || now.Sub(session.rateAt) >= time.Second {
		session.rateAt = now
		session.rateUsed = 0
	}
	session.rateUsed++
	if session.rateUsed > maxPerSecond {
		return false
	}
	session.touch()
	return true
}

func (s *MQTTServer) removeStream(id string) bool {
	s.streamMu.Lock()
	session, ok := s.streams[id]
	if ok {
		delete(s.streams, id)
	}
	s.streamMu.Unlock()
	if !ok {
		return false
	}
	session.cancel()
	if session.terminal != nil {
		_ = session.terminal.Close()
	}
	return true
}

func (s *MQTTServer) streamDescriptor(session *streamSession) map[string]any {
	return map[string]any{
		"sessionId": session.id, "kind": session.kind,
		"expiresAt":    time.Now().Add(s.cfg.StreamLifetime).UTC(),
		"idleTimeout":  s.cfg.StreamIdle.String(),
		"controlTopic": s.controlTopic("gateway/streams/" + session.id + "/control"),
		"inputTopic":   s.controlTopic("gateway/streams/" + session.id + "/in"),
		"outputTopic":  s.dataTopic("gateway/streams/" + session.id + "/out"),
		"maxBytes":     s.cfg.MaxStreamBytes,
		"maxRate":      s.cfg.MaxStreamRate,
	}
}

func (s *MQTTServer) publishLogFrame(session *streamSession, line string) error {
	return s.publishStreamFrame(session, map[string]any{
		"stream": "log", "line": line,
	})
}

func (s *MQTTServer) publishTerminalFrame(session *streamSession, data []byte) error {
	return s.publishStreamFrame(session, map[string]any{
		"stream": "pty", "dataBase64": base64.StdEncoding.EncodeToString(data),
	})
}

func (s *MQTTServer) publishStreamFrame(session *streamSession, fields map[string]any) error {
	if !session.allow(s.cfg.MaxStreamRate) {
		s.removeStream(session.id)
		return fmt.Errorf("stream frame rate limit exceeded")
	}
	added := int64(0)
	switch value := fields["line"].(type) {
	case string:
		added = int64(len(value))
	}
	if raw, ok := fields["dataBase64"].(string); ok {
		if decoded, err := base64.StdEncoding.DecodeString(raw); err == nil {
			added += int64(len(decoded))
		}
	}
	if session.bytes.Add(added) > s.cfg.MaxStreamBytes {
		s.removeStream(session.id)
		return fmt.Errorf("stream byte limit exceeded")
	}
	fields["sessionId"] = session.id
	fields["sequence"] = session.sequence.Add(1)
	fields["timestamp"] = time.Now().UTC()
	encoded, _ := json.Marshal(fields)
	format := byte(1)
	expiry := uint32(30)
	return s.publish(s.dataTopic("gateway/streams/"+session.id+"/out"), encoded, 0, false, &paho.PublishProperties{
		ContentType: "application/json", PayloadFormat: &format, MessageExpiry: &expiry,
		User: paho.UserProperties{{Key: "api-version", Value: APIVersion}},
	})
}

func (s *MQTTServer) handleStreamInput(message *paho.Publish) {
	session := s.sessionFromTopic(message.Topic)
	if session == nil || session.kind != "terminal" || session.terminal == nil {
		return
	}
	if !session.allow(s.cfg.MaxStreamRate) {
		s.removeStream(session.id)
		return
	}
	if session.bytes.Add(int64(len(message.Payload))) > s.cfg.MaxStreamBytes {
		s.removeStream(session.id)
		return
	}
	if err := session.terminal.Send(message.Payload); err != nil {
		s.removeStream(session.id)
	}
}

func (s *MQTTServer) handleStreamControl(message *paho.Publish) {
	session := s.sessionFromTopic(message.Topic)
	if session == nil {
		return
	}
	if !session.allow(s.cfg.MaxStreamRate) {
		s.removeStream(session.id)
		return
	}
	var command struct {
		Action  string `json:"action"`
		Columns int    `json:"columns,omitempty"`
		Rows    int    `json:"rows,omitempty"`
	}
	if json.Unmarshal(message.Payload, &command) != nil {
		return
	}
	switch command.Action {
	case "close":
		s.removeStream(session.id)
	case "resize":
		if session.terminal != nil && command.Columns > 0 && command.Rows > 0 {
			_ = session.terminal.Resize(uint16(command.Columns), uint16(command.Rows))
		}
	}
}

func (s *MQTTServer) sessionFromTopic(topic string) *streamSession {
	parts := strings.Split(topic, "/")
	if len(parts) < 2 {
		return nil
	}
	id := parts[len(parts)-2]
	s.streamMu.Lock()
	defer s.streamMu.Unlock()
	return s.streams[id]
}

func (s *MQTTServer) publish(topic string, payload []byte, qos byte, retain bool, properties *paho.PublishProperties) error {
	ctx, cancel := context.WithTimeout(s.ctx, 10*time.Second)
	defer cancel()
	_, err := s.client.Publish(ctx, &paho.Publish{
		Topic: topic, Payload: payload, QoS: qos, Retain: retain, Properties: properties,
	})
	return err
}

func (s *MQTTServer) controlTopic(suffix string) string {
	return fmt.Sprintf("m/%s/c/%s/%s", s.cfg.DomainID, s.cfg.ControlChannel, suffix)
}

func (s *MQTTServer) dataTopic(suffix string) string {
	return fmt.Sprintf("m/%s/c/%s/%s", s.cfg.DomainID, s.cfg.DataChannel, suffix)
}

func (s *MQTTServer) pruneLoop() {
	ticker := time.NewTicker(time.Hour)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			if err := s.store.PruneRequests(time.Now().UTC()); err != nil {
				s.logger.Warn("Failed to prune remote requests", slog.Any("error", err))
			}
		case <-s.ctx.Done():
			return
		}
	}
}

func (s *MQTTServer) Close() error {
	var result error
	s.closeOnce.Do(func() {
		s.streamMu.Lock()
		ids := make([]string, 0, len(s.streams))
		for id := range s.streams {
			ids = append(ids, id)
		}
		s.streamMu.Unlock()
		for _, id := range ids {
			s.removeStream(id)
		}
		if s.client != nil {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			payload, _ := json.Marshal(s.presence("offline"))
			format := byte(1)
			expiry := uint32(7 * 24 * time.Hour / time.Second)
			_, _ = s.client.Publish(ctx, &paho.Publish{
				Topic: s.dataTopic("gateway/presence"), Payload: payload, QoS: 1, Retain: true,
				Properties: &paho.PublishProperties{
					ContentType: "application/json", PayloadFormat: &format, MessageExpiry: &expiry,
					User: paho.UserProperties{{Key: "api-version", Value: APIVersion}},
				},
			})
			result = s.client.Disconnect(ctx)
			cancel()
		}
		if closeErr := s.store.Close(); result == nil {
			result = closeErr
		}
	})
	return result
}

func mqtt5URL(raw string) (*url.URL, error) {
	if !strings.Contains(raw, "://") {
		raw = "mqtt://" + raw
	}
	parsed, err := url.Parse(raw)
	if err != nil {
		return nil, err
	}
	switch parsed.Scheme {
	case "tcp":
		parsed.Scheme = "mqtt"
	case "ssl", "mqtts":
		parsed.Scheme = "tls"
	}
	switch parsed.Scheme {
	case "mqtt", "tls", "ws", "wss":
	default:
		return nil, fmt.Errorf("unsupported MQTT URL scheme %q", parsed.Scheme)
	}
	return parsed, nil
}

func mqttTLSConfig(cfg MQTTConfig, serverURL *url.URL) (*tls.Config, error) {
	if serverURL.Scheme != "tls" && serverURL.Scheme != "wss" && !cfg.MTLS {
		return nil, nil
	}
	roots, _ := x509.SystemCertPool()
	if roots == nil {
		roots = x509.NewCertPool()
	}
	if len(cfg.CA) > 0 && !roots.AppendCertsFromPEM(cfg.CA) {
		return nil, fmt.Errorf("failed to parse MQTT CA")
	}
	tlsCfg := &tls.Config{
		RootCAs: roots, InsecureSkipVerify: cfg.SkipTLSVerify,
		MinVersion: tls.VersionTLS12, ServerName: serverURL.Hostname(),
	}
	if len(cfg.Certificate.Certificate) > 0 {
		tlsCfg.Certificates = []tls.Certificate{cfg.Certificate}
	}
	return tlsCfg, nil
}

// ParseDurationEnv provides one place for cmd packages to parse optional
// remote-protocol duration environment variables.
func ParseDurationEnv(value string, fallback time.Duration) time.Duration {
	if value == "" {
		return fallback
	}
	parsed, err := time.ParseDuration(value)
	if err != nil || parsed <= 0 {
		return fallback
	}
	return parsed
}

func ParseBytesEnv(value string, fallback int64) int64 {
	if value == "" {
		return fallback
	}
	parsed, err := strconv.ParseInt(value, 10, 64)
	if err != nil || parsed <= 0 {
		return fallback
	}
	return parsed
}

// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/absmach/agent/pkg/remote"
	"github.com/eclipse/paho.golang/autopaho"
	"github.com/eclipse/paho.golang/paho"
	"github.com/gofrs/uuid/v5"
)

// Response is the HTTP-friendly projection of a JSON-RPC response.
type Response struct {
	RequestID string          `json:"request_id"`
	Operation string          `json:"operation"`
	Value     json.RawMessage `json:"value,omitempty"`
	Error     string          `json:"error,omitempty"`
	ErrorCode int             `json:"error_code,omitempty"`
}

// Event is an MQTT data-channel publication forwarded to standalone UI clients.
type Event struct {
	AgentID string          `json:"agent_id"`
	Topic   string          `json:"topic"`
	Payload json.RawMessage `json:"payload"`
	Retain  bool            `json:"retain"`
}

type pendingRequest struct {
	agentID string
	method  string
	result  chan remote.Response
}

type ServiceHandler func(context.Context, json.RawMessage) (any, *remote.RPCError)

// Broker owns MQTT 5 correlation and event fan-out for the standalone gateway.
type Broker struct {
	ctx        context.Context
	cancel     context.CancelFunc
	client     *autopaho.ConnectionManager
	agents     map[string]Agent
	ttl        time.Duration
	clientID   string
	logger     *slog.Logger
	mu         sync.Mutex
	pending    map[string]pendingRequest
	subsMu     sync.RWMutex
	subs       map[chan Event]struct{}
	latest     map[string]map[string]Event
	servicesMu sync.RWMutex
	services   map[string]map[string]ServiceHandler
	closeOnce  sync.Once
}

func NewBroker(cfg Config, logger *slog.Logger) (*Broker, error) {
	ctx, cancel := context.WithCancel(context.Background())
	b := &Broker{
		ctx: ctx, cancel: cancel, agents: make(map[string]Agent), ttl: cfg.RequestTTL,
		clientID: cfg.MQTTClientID, logger: logger,
		pending: make(map[string]pendingRequest), subs: make(map[chan Event]struct{}),
		latest:   make(map[string]map[string]Event),
		services: make(map[string]map[string]ServiceHandler),
	}
	for _, configured := range cfg.Agents {
		b.agents[configured.ID] = configured
	}

	serverURL, err := gatewayMQTTURL(cfg.MQTTURL)
	if err != nil {
		cancel()
		return nil, err
	}
	tlsConfig, err := gatewayTLSConfig(cfg, serverURL)
	if err != nil {
		cancel()
		return nil, err
	}
	sessionSeconds := uint32(cfg.SessionExpiry / time.Second)
	clientConfig := autopaho.ClientConfig{
		ServerUrls:                    []*url.URL{serverURL},
		TlsCfg:                        tlsConfig,
		KeepAlive:                     30,
		CleanStartOnInitialConnection: true,
		SessionExpiryInterval:         sessionSeconds,
		ConnectUsername:               cfg.MQTTUsername,
		ConnectPassword:               []byte(cfg.MQTTPassword),
		OnConnectionUp: func(cm *autopaho.ConnectionManager, _ *paho.Connack) {
			b.subscribe(cm)
		},
		OnConnectError: func(err error) {
			logger.Warn("Gateway MQTT 5 connection failed", slog.Any("error", err))
		},
		ClientConfig: paho.ClientConfig{
			ClientID: cfg.MQTTClientID,
			OnPublishReceived: []func(paho.PublishReceived) (bool, error){
				func(received paho.PublishReceived) (bool, error) {
					b.handle(received.Packet)
					return true, nil
				},
			},
			OnClientError: func(err error) {
				logger.Warn("Gateway MQTT 5 client error", slog.Any("error", err))
			},
		},
	}
	cm, err := autopaho.NewConnection(ctx, clientConfig)
	if err != nil {
		cancel()
		return nil, err
	}
	b.client = cm
	awaitCtx, awaitCancel := context.WithTimeout(ctx, 15*time.Second)
	defer awaitCancel()
	if err := cm.AwaitConnection(awaitCtx); err != nil {
		cancel()
		return nil, err
	}
	return b, nil
}

// RegisterServiceMethod installs one logical Agent-to-server RPC method.
func (b *Broker) RegisterServiceMethod(serviceName, method string, handler ServiceHandler) {
	if serviceName == "" || method == "" || handler == nil {
		return
	}
	b.servicesMu.Lock()
	if b.services[serviceName] == nil {
		b.services[serviceName] = make(map[string]ServiceHandler)
	}
	b.services[serviceName][method] = handler
	b.servicesMu.Unlock()
}

func (b *Broker) subscribe(cm *autopaho.ConnectionManager) {
	subscriptions := make([]paho.SubscribeOptions, 0, len(b.agents)*3)
	for _, configured := range b.agents {
		subscriptions = append(subscriptions,
			paho.SubscribeOptions{Topic: controlTopic(configured, "res/"+b.clientID), QoS: 1},
			paho.SubscribeOptions{Topic: dataTopic(configured, "gateway/#"), QoS: 1},
			paho.SubscribeOptions{Topic: controlTopic(configured, "service/+/req"), QoS: 1},
		)
	}
	ctx, cancel := context.WithTimeout(b.ctx, 10*time.Second)
	defer cancel()
	if _, err := cm.Subscribe(ctx, &paho.Subscribe{Subscriptions: subscriptions}); err != nil {
		b.logger.Error("Gateway subscriptions failed", slog.Any("error", err))
	}
}

func (b *Broker) Agents() []Agent {
	out := make([]Agent, 0, len(b.agents))
	for _, configured := range b.agents {
		configured.CommandSecret = ""
		out = append(out, configured)
	}
	return out
}

func (b *Broker) Agent(id string) (Agent, bool) {
	configured, ok := b.agents[id]
	return configured, ok
}

func (b *Broker) Command(ctx context.Context, agentID, method, value string) (Response, error) {
	configured, ok := b.agents[agentID]
	if !ok {
		return Response{}, fmt.Errorf("agent not found")
	}
	id, err := uuid.NewV4()
	if err != nil {
		return Response{}, err
	}
	params := json.RawMessage(value)
	if len(params) == 0 {
		params = json.RawMessage(`{}`)
	}
	if !json.Valid(params) {
		return Response{}, fmt.Errorf("params must be valid JSON")
	}
	request := remote.Request{
		JSONRPC: remote.JSONRPCVersion, ID: id.String(), Method: method, Params: params,
	}
	payload, err := json.Marshal(request)
	if err != nil {
		return Response{}, err
	}
	correlation, _ := remote.CorrelationData(request.ID)
	responseTopic := controlTopic(configured, "res/"+b.clientID)
	deadline := time.Now().Add(b.ttl).UTC()
	expirySeconds := uint32(max(1, int64(b.ttl/time.Second)))
	format := byte(1)
	properties := &paho.PublishProperties{
		ResponseTopic: responseTopic, CorrelationData: correlation,
		ContentType: "application/json", PayloadFormat: &format,
		MessageExpiry: &expirySeconds,
		User: paho.UserProperties{
			{Key: "api-version", Value: remote.APIVersion},
			{Key: "request-deadline", Value: deadline.Format(time.RFC3339Nano)},
		},
	}

	result := make(chan remote.Response, 1)
	b.mu.Lock()
	b.pending[request.ID] = pendingRequest{agentID: agentID, method: method, result: result}
	b.mu.Unlock()
	defer func() {
		b.mu.Lock()
		delete(b.pending, request.ID)
		b.mu.Unlock()
	}()

	if err := b.publish(ctx, &paho.Publish{
		Topic: controlTopic(configured, "req"), Payload: payload,
		QoS: 1, Retain: false, Properties: properties,
	}); err != nil {
		return Response{}, err
	}

	timer := time.NewTimer(b.ttl)
	defer timer.Stop()
	select {
	case rpcResponse := <-result:
		response := Response{RequestID: request.ID, Operation: method, Value: rpcResponse.Result}
		if rpcResponse.Error != nil {
			response.Error = rpcResponse.Error.Message
			response.ErrorCode = rpcResponse.Error.Code
		}
		return response, nil
	case <-timer.C:
		return Response{}, fmt.Errorf("agent response timeout")
	case <-ctx.Done():
		return Response{}, ctx.Err()
	}
}

func (b *Broker) PublishDesired(ctx context.Context, agentID string, desired any) error {
	configured, ok := b.agents[agentID]
	if !ok {
		return fmt.Errorf("agent not found")
	}
	payload, err := json.Marshal(desired)
	if err != nil {
		return err
	}
	format := byte(1)
	return b.publish(ctx, &paho.Publish{
		Topic: controlTopic(configured, "gateway/state/desired"), Payload: payload,
		QoS: 1, Retain: true,
		Properties: &paho.PublishProperties{
			ContentType: "application/json", PayloadFormat: &format,
			User: paho.UserProperties{{Key: "api-version", Value: remote.APIVersion}},
		},
	})
}

func (b *Broker) PublishStream(ctx context.Context, agentID, sessionID, direction string, payload []byte, qos byte) error {
	configured, ok := b.agents[agentID]
	if !ok {
		return fmt.Errorf("agent not found")
	}
	if _, err := uuid.FromString(sessionID); err != nil {
		return fmt.Errorf("invalid stream session")
	}
	if direction != "in" && direction != "control" {
		return fmt.Errorf("invalid stream direction")
	}
	properties := &paho.PublishProperties{
		User: paho.UserProperties{{Key: "api-version", Value: remote.APIVersion}},
	}
	if direction == "control" {
		format := byte(1)
		properties.ContentType = "application/json"
		properties.PayloadFormat = &format
	}
	return b.publish(ctx, &paho.Publish{
		Topic:   controlTopic(configured, "gateway/streams/"+sessionID+"/"+direction),
		Payload: payload, QoS: qos, Retain: false, Properties: properties,
	})
}

func (b *Broker) Subscribe() (<-chan Event, func()) {
	ch := make(chan Event, 64)
	b.subsMu.Lock()
	b.subs[ch] = struct{}{}
	for _, byTopic := range b.latest {
		for _, event := range byTopic {
			ch <- event
		}
	}
	b.subsMu.Unlock()
	return ch, func() {
		b.subsMu.Lock()
		if _, ok := b.subs[ch]; ok {
			delete(b.subs, ch)
			close(ch)
		}
		b.subsMu.Unlock()
	}
}

func (b *Broker) handle(message *paho.Publish) {
	agentID, configured, ok := b.agentForTopic(message.Topic)
	if !ok {
		return
	}
	if strings.HasPrefix(message.Topic, controlTopic(configured, "res/")) {
		b.handleResponse(agentID, message)
		return
	}
	if strings.Contains(message.Topic, "/service/") && strings.HasSuffix(message.Topic, "/req") {
		go b.handleServiceRequest(configured, message)
		return
	}
	event := Event{
		AgentID: agentID, Topic: message.Topic,
		Payload: append(json.RawMessage(nil), message.Payload...), Retain: message.Retain,
	}
	b.subsMu.Lock()
	if message.Retain ||
		strings.HasSuffix(message.Topic, "/gateway/presence") ||
		strings.HasSuffix(message.Topic, "/gateway/state/reported") {
		if b.latest[agentID] == nil {
			b.latest[agentID] = make(map[string]Event)
		}
		b.latest[agentID][message.Topic] = event
	}
	defer b.subsMu.Unlock()
	for ch := range b.subs {
		select {
		case ch <- event:
		default:
		}
	}
}

func (b *Broker) handleResponse(agentID string, message *paho.Publish) {
	if message.Properties == nil ||
		len(message.Properties.CorrelationData) != 16 ||
		message.Properties.ContentType != "application/json" ||
		message.Properties.PayloadFormat == nil || *message.Properties.PayloadFormat != 1 ||
		message.Properties.User.Get("api-version") != remote.APIVersion {
		return
	}
	var response remote.Response
	if json.Unmarshal(message.Payload, &response) != nil ||
		!remote.CorrelationMatches(response.ID, message.Properties.CorrelationData) {
		return
	}
	b.mu.Lock()
	pending, ok := b.pending[response.ID]
	b.mu.Unlock()
	if !ok || pending.agentID != agentID {
		return
	}
	select {
	case pending.result <- response:
	default:
	}
}

// handleServiceRequest provides the reverse-RPC transport boundary. Logical
// server services are intentionally explicit; unavailable services return a
// JSON-RPC method-not-found response instead of silently consuming a request.
func (b *Broker) handleServiceRequest(configured Agent, message *paho.Publish) {
	if message.Properties == nil || message.Properties.ResponseTopic == "" ||
		len(message.Properties.CorrelationData) != 16 {
		return
	}
	serviceMarker := "/service/"
	start := strings.Index(message.Topic, serviceMarker)
	end := strings.LastIndex(message.Topic, "/req")
	if start < 0 || end <= start+len(serviceMarker) {
		return
	}
	serviceName := message.Topic[start+len(serviceMarker) : end]
	expectedResponsePrefix := controlTopic(configured, "service/"+serviceName+"/res/")
	if !strings.HasPrefix(message.Properties.ResponseTopic, expectedResponsePrefix) ||
		strings.ContainsAny(message.Properties.ResponseTopic, "+#") ||
		message.Properties.ContentType != "application/json" ||
		message.Properties.PayloadFormat == nil || *message.Properties.PayloadFormat != 1 ||
		message.Properties.MessageExpiry == nil || *message.Properties.MessageExpiry == 0 ||
		message.Properties.User.Get("api-version") != remote.APIVersion {
		return
	}
	deadline, err := time.Parse(time.RFC3339Nano, message.Properties.User.Get("request-deadline"))
	if err != nil || time.Now().After(deadline) {
		return
	}
	request, rpcErr := remote.DecodeRequest(message.Payload)
	if rpcErr == nil && !remote.CorrelationMatches(request.ID, message.Properties.CorrelationData) {
		rpcErr = &remote.RPCError{Code: remote.CodeInvalidRequest, Message: "JSON-RPC id does not match MQTT Correlation Data"}
	}
	var response remote.Response
	if rpcErr != nil {
		response = remote.Response{JSONRPC: remote.JSONRPCVersion, ID: request.ID, Error: rpcErr}
	} else {
		b.servicesMu.RLock()
		handler := b.services[serviceName][request.Method]
		b.servicesMu.RUnlock()
		if handler == nil {
			response = remote.ErrorResponse(request.ID, remote.CodeMethodNotFound, "server service method is not configured", nil)
		} else {
			result, handlerErr := handler(b.ctx, request.Params)
			if handlerErr != nil {
				response = remote.Response{JSONRPC: remote.JSONRPCVersion, ID: request.ID, Error: handlerErr}
			} else {
				response = remote.ResultResponse(request.ID, result)
			}
		}
	}
	payload, _ := json.Marshal(response)
	expiry := uint32(30)
	format := byte(1)
	_ = b.publish(b.ctx, &paho.Publish{
		Topic: message.Properties.ResponseTopic, Payload: payload, QoS: 1,
		Properties: &paho.PublishProperties{
			CorrelationData: message.Properties.CorrelationData,
			ContentType:     "application/json", PayloadFormat: &format, MessageExpiry: &expiry,
			User: paho.UserProperties{{Key: "api-version", Value: remote.APIVersion}},
		},
	})
}

func (b *Broker) agentForTopic(topic string) (string, Agent, bool) {
	for id, configured := range b.agents {
		controlPrefix := fmt.Sprintf("m/%s/c/%s/", configured.DomainID, configured.ControlChannel)
		dataPrefix := fmt.Sprintf("m/%s/c/%s/", configured.DomainID, configured.DataChannel)
		if strings.HasPrefix(topic, controlPrefix) || strings.HasPrefix(topic, dataPrefix) {
			return id, configured, true
		}
	}
	return "", Agent{}, false
}

func (b *Broker) publish(ctx context.Context, message *paho.Publish) error {
	publishCtx, cancel := context.WithTimeout(ctx, b.ttl)
	defer cancel()
	_, err := b.client.Publish(publishCtx, message)
	return err
}

func (b *Broker) Close() {
	b.closeOnce.Do(func() {
		b.cancel()
		if b.client != nil {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			_ = b.client.Disconnect(ctx)
			cancel()
		}
	})
}

func controlTopic(configured Agent, suffix string) string {
	return fmt.Sprintf("m/%s/c/%s/%s", configured.DomainID, configured.ControlChannel, suffix)
}

func dataTopic(configured Agent, suffix string) string {
	return fmt.Sprintf("m/%s/c/%s/%s", configured.DomainID, configured.DataChannel, suffix)
}

func gatewayMQTTURL(raw string) (*url.URL, error) {
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

func gatewayTLSConfig(cfg Config, serverURL *url.URL) (*tls.Config, error) {
	if serverURL.Scheme != "tls" && serverURL.Scheme != "wss" {
		return nil, nil
	}
	roots, _ := x509.SystemCertPool()
	if roots == nil {
		roots = x509.NewCertPool()
	}
	if cfg.MQTTCAPath != "" {
		pem, err := os.ReadFile(cfg.MQTTCAPath)
		if err != nil {
			return nil, err
		}
		if !roots.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("failed to parse gateway MQTT CA")
		}
	}
	tlsConfig := &tls.Config{
		RootCAs: roots, InsecureSkipVerify: cfg.MQTTSkipTLS,
		MinVersion: tls.VersionTLS12, ServerName: serverURL.Hostname(),
	}
	if cfg.MQTTCertPath != "" || cfg.MQTTKeyPath != "" {
		certificate, err := tls.LoadX509KeyPair(cfg.MQTTCertPath, cfg.MQTTKeyPath)
		if err != nil {
			return nil, err
		}
		tlsConfig.Certificates = []tls.Certificate{certificate}
	}
	return tlsConfig, nil
}

// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

package transport

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log/slog"
	"strings"

	"github.com/absmach/agent"
	"github.com/absmach/agent/pkg/coap"
	"github.com/absmach/agent/pkg/conn"
	paho "github.com/eclipse/paho.mqtt.golang"
)

type Factory struct {
	config  *agent.Config
	service agent.Service
	logger  *slog.Logger
}

func NewFactory(cfg *agent.Config, svc agent.Service, logger *slog.Logger) *Factory {
	return &Factory{
		config:  cfg,
		service: svc,
		logger:  logger,
	}
}

type TransportSetup struct {
	Broker    Broker
	Publisher Publisher
	Connector Connector
}

func (f *Factory) CreateTransport() (*TransportSetup, error) {
	switch strings.ToLower(f.config.Transport) {
	case "coap":
		return f.createCoAPTransport()
	case "mqtt":
		fallthrough
	default:
		return f.createMQTTTransport()
	}
}

func (f *Factory) createMQTTTransport() (*TransportSetup, error) {
	onConnect := func() {}
	var mqttClient paho.Client
	var err error

	mqttClient, err = connectToMQTT(f.config.MQTT, f.logger, func() {
		onConnect()
	})
	if err != nil {
		return nil, fmt.Errorf("failed to connect to MQTT broker: %w", err)
	}

	publisher := NewMQTTPublisher(mqttClient, f.config.DomainID, f.config.Channels.CtrlChan(), f.config.Channels.DataChan(), TopicControl)
	connector := NewMQTTConnector(mqttClient, f.config.DomainID, f.config.Channels.CtrlChan(), f.config.Channels.DataChan(), TopicControl)

	broker := conn.NewBroker(f.service, mqttClient, f.config.Channels.CtrlChan(), f.config.DomainID, f.logger)
	mqttBroker := NewMQTTBroker(broker, mqttClient, f.config.DomainID, f.config.Channels.CtrlChan(), f.config.Channels.DataChan(), TopicControl)

	onConnect = mqttBroker.Resubscribe

	return &TransportSetup{
		Broker:    mqttBroker,
		Publisher: publisher,
		Connector: connector,
	}, nil
}

func (f *Factory) createCoAPTransport() (*TransportSetup, error) {
	coapConfig := coap.Config{
		URL:            f.config.CoAP.URL,
		PSK:            f.config.CoAP.PSK,
		CertPath:       f.config.CoAP.CertPath,
		PrivKeyPath:    f.config.CoAP.PrivKeyPath,
		CAPath:         f.config.CoAP.CAPath,
		SkipTLSVer:     f.config.CoAP.SkipTLSVer,
		MaxObserve:     f.config.CoAP.MaxObserve,
		MaxRetransmits: f.config.CoAP.MaxRetransmits,
		KeepAlive:      f.config.CoAP.KeepAlive,
		ContentFormat:  f.config.CoAP.ContentFormat,
		Cert:           f.config.CoAP.Cert,
		Key:            f.config.CoAP.Key,
		CA:             f.config.CoAP.CA,
	}

	coapClient, err := coap.NewClient(coapConfig, f.logger)
	if err != nil {
		return nil, fmt.Errorf("failed to create CoAP client: %w", err)
	}

	publisher := NewCoAPPublisher(coapClient, f.config.DomainID, f.config.Channels.CtrlChan(), f.config.Channels.DataChan(), TopicControl, f.config.CoAP.ContentFormat)
	connector := NewCoAPConnector(coapClient)

	broker := coap.NewBroker(f.service, coapClient, f.config.Channels.CtrlChan(), f.config.DomainID, f.logger)
	coapBroker := NewCoAPBroker(broker, coapClient, f.config.DomainID, f.config.Channels.CtrlChan(), f.config.Channels.DataChan(), TopicControl, f.config.CoAP.ContentFormat)

	return &TransportSetup{
		Broker:    coapBroker,
		Publisher: publisher,
		Connector: connector,
	}, nil
}

func connectToMQTT(conf agent.MQTTConfig, logger *slog.Logger, onConnect func()) (paho.Client, error) {
	name := conf.Username
	conn := func(client paho.Client) {
		logger.Info("Client connected", slog.String("client_name", name))
		onConnect()
	}

	lost := func(client paho.Client, err error) {
		logger.Info("Client disconnected", slog.String("client_name", name))
	}

	opts := paho.NewClientOptions().
		AddBroker(conf.URL).
		SetClientID(name).
		SetCleanSession(true).
		SetAutoReconnect(true).
		SetOnConnectHandler(conn).
		SetConnectionLostHandler(lost)

	if conf.Username != "" && conf.Password != "" {
		opts.SetUsername(conf.Username)
		opts.SetPassword(conf.Password)
	}

	if conf.MTLS {
		cfg := &tls.Config{
			InsecureSkipVerify: conf.SkipTLSVer,
		}

		if conf.CA != nil {
			cfg.RootCAs = x509.NewCertPool()
			cfg.RootCAs.AppendCertsFromPEM(conf.CA)
		}
		if conf.Cert.Certificate != nil {
			cfg.Certificates = []tls.Certificate{conf.Cert}
		}

		opts.SetTLSConfig(cfg)
		opts.SetProtocolVersion(4)
	} else if strings.HasPrefix(conf.URL, "ssl://") || strings.HasPrefix(conf.URL, "tls://") {
		rootCAs, _ := x509.SystemCertPool()
		if rootCAs == nil {
			rootCAs = x509.NewCertPool()
		}
		cfg := &tls.Config{
			InsecureSkipVerify: conf.SkipTLSVer,
			RootCAs:            rootCAs,
		}
		opts.SetTLSConfig(cfg)
		opts.SetProtocolVersion(4)
	}
	client := paho.NewClient(opts)
	token := client.Connect()
	token.Wait()

	if token.Error() != nil {
		return nil, token.Error()
	}
	return client, nil
}

// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/absmach/agent/pkg/agent"
	"github.com/absmach/agent/pkg/agent/api"
	"github.com/absmach/agent/pkg/bootstrap"
	"github.com/absmach/agent/pkg/conn"
	"github.com/absmach/agent/pkg/edgex"
	"github.com/absmach/magistrala/pkg/errors"
	"github.com/absmach/magistrala/pkg/messaging/brokers"
	"github.com/caarlos0/env/v9"
	mqtt "github.com/eclipse/paho.mqtt.golang"
	kitprometheus "github.com/go-kit/kit/metrics/prometheus"
	stdprometheus "github.com/prometheus/client_golang/prometheus"
	"golang.org/x/sync/errgroup"
)

type config struct {
	ConfigFile             string `env:"MG_AGENT_CONFIG_FILE" envDefault:"config.toml"`
	LogLevel               string `env:"MG_AGENT_LOG_LEVEL" envDefault:"info"`
	EdgexURL               string `env:"MG_AGENT_EDGEX_URL" envDefault:"http://localhost:48090/api/v1/"`
	MqttURL                string `env:"MG_AGENT_MQTT_URL" envDefault:"localhost:1883"`
	HTTPPort               string `env:"MG_AGENT_HTTP_PORT" envDefault:"9999"`
	BootstrapURL           string `env:"MG_AGENT_BOOTSTRAP_URL" envDefault:"http://localhost:9013/things/bootstrap"`
	BootstrapID            string `env:"MG_AGENT_BOOTSTRAP_ID" envDefault:""`
	BootstrapKey           string `env:"MG_AGENT_BOOTSTRAP_KEY" envDefault:""`
	BootstrapRetries       string `env:"MG_AGENT_BOOTSTRAP_RETRIES" envDefault:"5"`
	BootstrapSkipTLS       string `env:"MG_AGENT_BOOTSTRAP_SKIP_TLS" envDefault:"false"`
	BootstrapRetryDelaySec string `env:"MG_AGENT_BOOTSTRAP_RETRY_DELAY_SECONDS" envDefault:"10"`
	ControlChannel         string `env:"MG_AGENT_CONTROL_CHANNEL" envDefault:""`
	DataChannel            string `env:"MG_AGENT_DATA_CHANNEL" envDefault:""`
	Encryption             string `env:"MG_AGENT_ENCRYPTION" envDefault:"false"`
	NatsURL                string `env:"MG_AGENT_NATS_URL" envDefault:"nats://localhost:4222"`
	MqttUsername           string `env:"MG_AGENT_MQTT_USERNAME" envDefault:""`
	MqttPassword           string `env:"MG_AGENT_MQTT_PASSWORD" envDefault:""`
	MqttSkipTLSVer         string `env:"MG_AGENT_MQTT_SKIP_TLS" envDefault:"true"`
	MqttMTLS               string `env:"MG_AGENT_MQTT_MTLS" envDefault:"false"`
	MqttCA                 string `env:"MG_AGENT_MQTT_CA" envDefault:"ca.crt"`
	MqttQoS                string `env:"MG_AGENT_MQTT_QOS" envDefault:"0"`
	MqttRetain             string `env:"MG_AGENT_MQTT_RETAIN" envDefault:"false"`
	MqttCert               string `env:"MG_AGENT_MQTT_CLIENT_CERT" envDefault:"thing.cert"`
	MqttPrivateKey         string `env:"MG_AGENT_MQTT_CLIENT_CERT" envDefault:"thing.key"`
	HeartbeatInterval      string `env:"MG_AGENT_HEARTBEAT_INTERVAL" envDefault:"10s"`
	TermSessionTimeout     string `env:"MG_AGENT_TERMINAL_SESSION_TIMEOUT" envDefault:"60s"`
}

var (
	errFailedToSetupMTLS       = errors.New("Failed to set up mtls certs")
	errFetchingBootstrapFailed = errors.New("Fetching bootstrap failed with error")
	errFailedToReadConfig      = errors.New("Failed to read config")
	errFailedToConfigHeartbeat = errors.New("Failed to configure heartbeat")
)

func main() {
	ctx, cancel := context.WithCancel(context.Background())
	g, ctx := errgroup.WithContext(ctx)

	c := config{}
	if err := env.Parse(&c); err != nil {
		log.Fatalf("failed to load configuration : %s", err.Error())
	}

	cfg, err := loadEnvConfig(c)
	if err != nil {
		log.Fatalf(fmt.Sprintf("Failed to load config: %s", err))
	}

	logger, err := initLogger(c.LogLevel)
	if err != nil {
		log.Fatalf(err.Error())
	}

	cfg, err = loadBootConfig(c, cfg, logger)
	if err != nil {
		logger.Error("Failed to load config", slog.Any("error", err))
	}

	pubsub, err := brokers.NewPubSub(ctx, cfg.Server.BrokerURL, logger)
	if err != nil {
		log.Fatal(fmt.Sprintf("Failed to connect to Broker: %s %s", err, cfg.Server.BrokerURL))
	}
	defer pubsub.Close()

	mqttClient, err := connectToMQTTBroker(cfg.MQTT, logger)
	if err != nil {
		logger.Error(err.Error())
		return
	}
	edgexClient := edgex.NewClient(cfg.Edgex.URL, logger)

	svc, err := agent.New(ctx, mqttClient, &cfg, edgexClient, pubsub, logger)
	if err != nil {
		logger.Error("Error in agent service", slog.Any("error", err))
		return
	}

	svc = api.LoggingMiddleware(svc, logger)
	svc = api.MetricsMiddleware(
		svc,
		kitprometheus.NewCounterFrom(stdprometheus.CounterOpts{
			Namespace: "agent",
			Subsystem: "api",
			Name:      "request_count",
			Help:      "Number of requests received.",
		}, []string{"method"}),
		kitprometheus.NewSummaryFrom(stdprometheus.SummaryOpts{
			Namespace: "agent",
			Subsystem: "api",
			Name:      "request_latency_microseconds",
			Help:      "Total duration of requests in microseconds.",
		}, []string{"method"}),
	)
	b := conn.NewBroker(svc, mqttClient, cfg.Channels.Control, pubsub, logger)

	srv := &http.Server{
		Addr:    fmt.Sprintf(":%s", cfg.Server.Port),
		Handler: api.MakeHandler(svc),
	}

	g.Go(func() error {
		return b.Subscribe(ctx)
	})

	g.Go(func() error {
		logger.Info("Agent service started", slog.String("port", cfg.Server.Port))
		return srv.ListenAndServe()
	})

	g.Go(func() error {
		return StopSignalHandler(ctx, cancel, logger, "agent", srv)
	})

	if err := g.Wait(); err != nil {
		logger.Error("Agent terminated", slog.Any("error", err))
	}
}

func loadEnvConfig(cfg config) (agent.Config, error) {
	sc := agent.ServerConfig{
		BrokerURL: cfg.NatsURL,
		Port:      cfg.HTTPPort,
	}
	cc := agent.ChanConfig{
		Control: cfg.ControlChannel,
		Data:    cfg.DataChannel,
	}
	interval, err := time.ParseDuration(cfg.HeartbeatInterval)
	if err != nil {
		return agent.Config{}, errors.Wrap(errFailedToConfigHeartbeat, err)
	}

	ch := agent.HeartbeatConfig{
		Interval: interval,
	}
	termSessionTimeout, err := time.ParseDuration(cfg.TermSessionTimeout)
	if err != nil {
		return agent.Config{}, err
	}
	ct := agent.TerminalConfig{
		SessionTimeout: termSessionTimeout,
	}
	ec := agent.EdgexConfig{URL: cfg.EdgexURL}
	lc := agent.LogConfig{Level: cfg.LogLevel}

	mtls, err := strconv.ParseBool(cfg.MqttMTLS)
	if err != nil {
		mtls = false
	}

	skipTLSVer, err := strconv.ParseBool(cfg.MqttSkipTLSVer)
	if err != nil {
		skipTLSVer = true
	}

	qos, err := strconv.Atoi(cfg.MqttQoS)
	if err != nil {
		qos = 0
	}

	retain, err := strconv.ParseBool(cfg.MqttRetain)
	if err != nil {
		retain = false
	}

	mc := agent.MQTTConfig{
		URL:         cfg.MqttURL,
		Username:    cfg.MqttUsername,
		Password:    cfg.MqttPassword,
		MTLS:        mtls,
		CAPath:      cfg.MqttCA,
		CertPath:    cfg.MqttCert,
		PrivKeyPath: cfg.MqttPrivateKey,
		SkipTLSVer:  skipTLSVer,
		QoS:         byte(qos),
		Retain:      retain,
	}

	file := cfg.ConfigFile
	c := agent.NewConfig(sc, cc, ec, lc, mc, ch, ct, file)
	mc, err = loadCertificate(c.MQTT)
	if err != nil {
		return c, errors.Wrap(errFailedToSetupMTLS, err)
	}

	c.MQTT = mc
	if err = agent.SaveConfig(c); err != nil {
		return c, err
	}
	return c, nil
}

func loadBootConfig(cfg config, c agent.Config, logger *slog.Logger) (agent.Config, error) {
	file := cfg.ConfigFile
	skipTLS, err := strconv.ParseBool(cfg.BootstrapSkipTLS)
	if err != nil {
		return agent.Config{}, err
	}
	bsConfig := bootstrap.Config{
		URL:           cfg.BootstrapURL,
		ID:            cfg.BootstrapID,
		Key:           cfg.BootstrapKey,
		Retries:       cfg.BootstrapRetries,
		RetryDelaySec: cfg.BootstrapRetryDelaySec,
		Encrypt:       cfg.Encryption,
		SkipTLS:       skipTLS,
	}

	if err := bootstrap.Bootstrap(bsConfig, logger, file); err != nil {
		return c, errors.Wrap(errFetchingBootstrapFailed, err)
	}

	bsc, err := agent.ReadConfig(file)
	if err != nil {
		return c, errors.Wrap(errFailedToReadConfig, err)
	}

	mc, err := loadCertificate(bsc.MQTT)
	if err != nil {
		return bsc, errors.Wrap(errFailedToSetupMTLS, err)
	}

	if bsc.Heartbeat.Interval <= 0 {
		bsc.Heartbeat.Interval = c.Heartbeat.Interval
	}

	if bsc.Terminal.SessionTimeout <= 0 {
		bsc.Terminal.SessionTimeout = c.Terminal.SessionTimeout
	}

	bsc.MQTT = mc
	return bsc, nil
}

func connectToMQTTBroker(conf agent.MQTTConfig, logger *slog.Logger) (mqtt.Client, error) {
	name := fmt.Sprintf("agent-%s", conf.Username)
	conn := func(client mqtt.Client) {
		logger.Info("Client connected", slog.String("client_name", name))
	}

	lost := func(client mqtt.Client, err error) {
		logger.Info("Client disconnected", slog.String("client_name", name))
	}

	opts := mqtt.NewClientOptions().
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
	}
	client := mqtt.NewClient(opts)
	token := client.Connect()
	token.Wait()

	if token.Error() != nil {
		return nil, token.Error()
	}
	return client, nil
}

func loadCertificate(cnfg agent.MQTTConfig) (agent.MQTTConfig, error) {
	c := cnfg

	if !c.MTLS {
		return c, nil
	}

	var caByte []byte
	var cc []byte
	var pk []byte
	var err error

	// Load CA cert from file
	if c.CAPath != "" {
		caByte, err = os.ReadFile(c.CAPath)
		if err != nil {
			return c, err
		}
		c.CA = caByte
	}

	// Load CA cert from string if file not present
	if len(c.CA) == 0 && c.CaCert != "" {
		c.CA = []byte(c.CaCert)
	}

	// Load client certificate from file if present
	if c.CertPath != "" {
		cc, err := os.ReadFile(c.CertPath)
		if err != nil {
			return c, err
		}
		pk, err := os.ReadFile(c.PrivKeyPath)
		if err != nil {
			return c, err
		}
		cert, err := tls.X509KeyPair(cc, pk)
		if err != nil {
			return c, err
		}
		c.Cert = cert
	}

	// Load client certificate from string if file not present
	if c.Cert.Certificate == nil && c.ClientCert != "" {
		cc = []byte(c.ClientCert)
		pk = []byte(c.ClientKey)
		cert, err := tls.X509KeyPair(cc, pk)
		if err != nil {
			return c, err
		}
		c.Cert = cert
	}

	return c, nil
}

func StopSignalHandler(ctx context.Context, cancel context.CancelFunc, logger *slog.Logger, svcName string, server *http.Server) error {
	c := make(chan os.Signal, 2)
	signal.Notify(c, syscall.SIGINT, syscall.SIGABRT)
	select {
	case sig := <-c:
		defer cancel()
		shutdownCtx, shutdownCancel := context.WithTimeout(ctx, 5*time.Second)
		defer shutdownCancel()
		if err := server.Shutdown(shutdownCtx); err != nil {
			return fmt.Errorf("Failed to shutdown %s server: %v", svcName, err)
		}
		return fmt.Errorf("%s service shutdown by signal: %s", svcName, sig)
	case <-ctx.Done():
		return nil
	}
}

func initLogger(levelText string) (*slog.Logger, error) {
	var level slog.Level
	if err := level.UnmarshalText([]byte(levelText)); err != nil {
		return &slog.Logger{}, fmt.Errorf(`{"level":"error","message":"%s: %s","ts":"%s"}`, err, levelText, time.RFC3339Nano)
	}

	logHandler := slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: level,
	})

	return slog.New(logHandler), nil
}

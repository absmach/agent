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
	"strings"
	"syscall"
	"time"

	"github.com/absmach/agent/pkg/agent"
	"github.com/absmach/agent/pkg/agent/api"
	"github.com/absmach/agent/pkg/bootstrap"
	"github.com/absmach/agent/pkg/conn"
	"github.com/absmach/agent/pkg/nodered"
	mglog "github.com/absmach/magistrala/logger"
	"github.com/absmach/magistrala/pkg/errors"
	"github.com/absmach/magistrala/pkg/messaging/brokers"
	"github.com/absmach/magistrala/pkg/prometheus"
	"github.com/caarlos0/env/v9"
	mqtt "github.com/eclipse/paho.mqtt.golang"
	"golang.org/x/sync/errgroup"
)

type config struct {
	ConfigFile          string `env:"MG_AGENT_CONFIG_FILE" envDefault:"config.toml"`
	LogLevel            string `env:"MG_AGENT_LOG_LEVEL" envDefault:"info"`
	NodeRedURL          string `env:"MG_AGENT_NODERED_URL" envDefault:"http://localhost:1880/"`
	MqttURL             string `env:"MG_AGENT_MQTT_URL" envDefault:"localhost:1883"`
	HTTPPort            string `env:"MG_AGENT_HTTP_PORT" envDefault:"9999"`
	AgentPort           string `env:"MG_AGENT_PORT" envDefault:""`
	BrokerURL           string `env:"MG_AGENT_BROKER_URL" envDefault:"amqp://guest:guest@localhost:5682/"`
	MqttSkipTLSVer      string `env:"MG_AGENT_MQTT_SKIP_TLS" envDefault:"true"`
	MqttMTLS            string `env:"MG_AGENT_MQTT_MTLS" envDefault:"false"`
	MqttCA              string `env:"MG_AGENT_MQTT_CA" envDefault:"ca.crt"`
	MqttQoS             string `env:"MG_AGENT_MQTT_QOS" envDefault:"0"`
	MqttRetain          string `env:"MG_AGENT_MQTT_RETAIN" envDefault:"false"`
	MqttCert            string `env:"MG_AGENT_MQTT_CLIENT_CERT" envDefault:"client.cert"`
	MqttPrivateKey      string `env:"MG_AGENT_MQTT_CLIENT_KEY" envDefault:"client.key"`
	HeartbeatInterval   string `env:"MG_AGENT_HEARTBEAT_INTERVAL" envDefault:"10s"`
	TermSessionTimeout  string `env:"MG_AGENT_TERMINAL_SESSION_TIMEOUT" envDefault:"60s"`
	BootstrapURL        string `env:"MG_AGENT_BOOTSTRAP_URL" envDefault:""`
	BootstrapID         string `env:"MG_AGENT_BOOTSTRAP_ID" envDefault:""`
	BootstrapKey        string `env:"MG_AGENT_BOOTSTRAP_KEY" envDefault:""`
	BootstrapRetries    string `env:"MG_AGENT_BOOTSTRAP_RETRIES" envDefault:"5"`
	BootstrapRetryDelay string `env:"MG_AGENT_BOOTSTRAP_RETRY_DELAY_SECONDS" envDefault:"10"`
	BootstrapSkipTLS    string `env:"MG_AGENT_BOOTSTRAP_SKIP_TLS" envDefault:"false"`
}

var (
	errFailedToSetupMTLS       = errors.New("Failed to set up mtls certs")
	errFailedToConfigHeartbeat = errors.New("Failed to configure heartbeat")
	errFetchingBootstrapFailed = errors.New("Fetching bootstrap failed with error")
	errFailedToReadConfig      = errors.New("Failed to read config")
	errInvalidRuntimeConfig    = errors.New("Invalid runtime config")
)

func main() {
	var exitCode int
	defer mglog.ExitWithError(&exitCode)

	ctx, cancel := context.WithCancel(context.Background())
	g, ctx := errgroup.WithContext(ctx)

	c := config{}
	if err := env.Parse(&c); err != nil {
		log.Printf("failed to load configuration : %s", err.Error())
		exitCode = 1
		return
	}

	cfg, err := loadEnvConfig(c)
	if err != nil {
		log.Printf("Failed to load config: %s", err)
		exitCode = 1
		return
	}

	logger, err := initLogger(cfg.Log.Level)
	if err != nil {
		log.Printf("Failed to create logger: %s", err)
		exitCode = 1
		return
	}

	cfg, err = loadBootConfig(cfg, c, logger)
	if err != nil {
		logger.Error("Failed to load bootstrap config", slog.Any("error", err))
	}

	if err := validateRuntimeConfig(cfg); err != nil {
		logger.Error("Failed to validate config", slog.Any("error", err), slog.String("config_file", cfg.File))
		exitCode = 1
		return
	}

	pubsub, err := brokers.NewPubSub(ctx, cfg.Server.BrokerURL, logger)
	if err != nil {
		logger.Error("Failed to connect to Broker", slog.Any("error", err), slog.String("broker_url", cfg.Server.BrokerURL))
		exitCode = 1
		return
	}
	defer pubsub.Close()

	// onReconnect is called by the MQTT connect handler on every (re)connect.
	// It is assigned after the broker is created so the closure captures it by reference.
	var onReconnect func()
	mqttClient, err := connectToMQTTBroker(cfg.MQTT, logger, func() {
		if onReconnect != nil {
			onReconnect()
		}
	})
	if err != nil {
		logger.Error(err.Error())
		exitCode = 1
		return
	}
	noderedClient := nodered.NewClient(cfg.NodeRed.URL, logger)

	svc, err := agent.New(ctx, mqttClient, &cfg, noderedClient, pubsub, logger)
	if err != nil {
		logger.Error("Error in agent service", slog.Any("error", err))
		exitCode = 1
		return
	}

	svc = api.NewLogging(svc, logger)
	counter, latency := prometheus.MakeMetrics("agent", "api")
	svc = api.NewMetrics(svc, counter, latency)
	b := conn.NewBroker(svc, mqttClient, cfg.Channels.ID, cfg.DomainID, pubsub, logger)
	onReconnect = b.Resubscribe

	srv := &http.Server{
		Addr:    fmt.Sprintf(":%s", cfg.Server.Port),
		Handler: api.MakeHandler(svc, logger, ""),
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

func validateRuntimeConfig(cfg agent.Config) error {
	missing := []string{}
	if cfg.DomainID == "" {
		missing = append(missing, "domain_id")
	}
	if cfg.Channels.ID == "" {
		missing = append(missing, "channels.id")
	}
	if cfg.MQTT.URL == "" {
		missing = append(missing, "mqtt.url")
	}
	if cfg.MQTT.Username == "" {
		missing = append(missing, "mqtt.username")
	}
	if cfg.MQTT.Password == "" {
		missing = append(missing, "mqtt.password")
	}
	if cfg.Server.BrokerURL == "" {
		missing = append(missing, "server.broker_url")
	}
	if len(missing) > 0 {
		return errors.New(fmt.Sprintf("%s: missing required TOML fields: %s", errInvalidRuntimeConfig, strings.Join(missing, ", ")))
	}
	return nil
}

func loadEnvConfig(cfg config) (agent.Config, error) {
	httpPort := cfg.HTTPPort
	if cfg.AgentPort != "" {
		httpPort = cfg.AgentPort
	}
	sc := agent.ServerConfig{
		BrokerURL: cfg.BrokerURL,
		Port:      httpPort,
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
	nc := agent.NodeRedConfig{URL: cfg.NodeRedURL}
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
		MTLS:        mtls,
		CAPath:      cfg.MqttCA,
		CertPath:    cfg.MqttCert,
		PrivKeyPath: cfg.MqttPrivateKey,
		SkipTLSVer:  skipTLSVer,
		QoS:         byte(qos),
		Retain:      retain,
	}

	file := cfg.ConfigFile
	cc := agent.ChanConfig{}
	c := agent.NewConfig(sc, cc, nc, lc, mc, ch, ct, file)

	if _, err := os.Stat(file); err == nil {
		fc, err := agent.ReadConfig(file)
		if err != nil {
			return c, errors.Wrap(errFailedToReadConfig, err)
		}
		c = mergeConfig(c, fc)
	} else if os.IsNotExist(err) {
		if err := agent.SaveConfig(c); err != nil {
			return c, err
		}
	} else {
		return c, err
	}

	mc, err = loadCertificate(c.MQTT)
	if err != nil {
		return c, errors.Wrap(errFailedToSetupMTLS, err)
	}

	c.MQTT = mc
	return c, nil
}

func mergeConfig(defaults, file agent.Config) agent.Config {
	c := file
	c.File = defaults.File

	if c.Server.Port == "" {
		c.Server.Port = defaults.Server.Port
	}
	if c.Server.BrokerURL == "" {
		c.Server.BrokerURL = defaults.Server.BrokerURL
	}
	if c.NodeRed.URL == "" {
		c.NodeRed.URL = defaults.NodeRed.URL
	}
	if c.Log.Level == "" {
		c.Log.Level = defaults.Log.Level
	}
	if c.MQTT.URL == "" {
		c.MQTT.URL = defaults.MQTT.URL
	}
	if c.MQTT.CAPath == "" {
		c.MQTT.CAPath = defaults.MQTT.CAPath
	}
	if c.MQTT.CertPath == "" {
		c.MQTT.CertPath = defaults.MQTT.CertPath
	}
	if c.MQTT.PrivKeyPath == "" {
		c.MQTT.PrivKeyPath = defaults.MQTT.PrivKeyPath
	}
	if c.MQTT.QoS == 0 {
		c.MQTT.QoS = defaults.MQTT.QoS
	}
	if c.Heartbeat.Interval <= 0 {
		c.Heartbeat.Interval = defaults.Heartbeat.Interval
	}
	if c.Terminal.SessionTimeout <= 0 {
		c.Terminal.SessionTimeout = defaults.Terminal.SessionTimeout
	}

	return c
}

func connectToMQTTBroker(conf agent.MQTTConfig, logger *slog.Logger, onConnect func()) (mqtt.Client, error) {
	name := conf.Username
	conn := func(client mqtt.Client) {
		logger.Info("Client connected", slog.String("client_name", name))
		onConnect()
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
	} else if strings.HasPrefix(conf.URL, "ssl://") || strings.HasPrefix(conf.URL, "tls://") {
		// Standard TLS using system cert pool (no client certs).
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
		return &slog.Logger{}, fmt.Errorf(`{"level":"error","message":"%s: %s","ts":"%s"}`, err, levelText, time.Now())
	}

	logHandler := slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: level,
	})

	return slog.New(logHandler), nil
}

func loadBootConfig(c agent.Config, cfg config, logger *slog.Logger) (agent.Config, error) {
	file := cfg.ConfigFile
	if cfg.BootstrapURL == "" || cfg.BootstrapID == "" || cfg.BootstrapKey == "" {
		return c, nil
	}

	skipTLS, err := strconv.ParseBool(cfg.BootstrapSkipTLS)
	if err != nil {
		skipTLS = false
	}

	bsConfig := bootstrap.Config{
		URL:           cfg.BootstrapURL,
		ID:            cfg.BootstrapID,
		Key:           cfg.BootstrapKey,
		Retries:       cfg.BootstrapRetries,
		RetryDelaySec: cfg.BootstrapRetryDelay,
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

	// Preserve non-zero values from initial config
	if bsc.Heartbeat.Interval <= 0 {
		bsc.Heartbeat.Interval = c.Heartbeat.Interval
	}

	if bsc.Terminal.SessionTimeout <= 0 {
		bsc.Terminal.SessionTimeout = c.Terminal.SessionTimeout
	}

	bsc.MQTT = mc
	return bsc, nil
}

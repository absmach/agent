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

	"github.com/absmach/agent"
	"github.com/absmach/agent/api"
	"github.com/absmach/agent/middleware"
	"github.com/absmach/agent/pkg/bootstrap"
	pkgconfig "github.com/absmach/agent/pkg/config"
	"github.com/absmach/agent/pkg/conn"
	"github.com/absmach/agent/pkg/devicemgr"
	"github.com/absmach/agent/pkg/iface"
	"github.com/absmach/agent/pkg/logstream"
	"github.com/absmach/agent/pkg/nodered"
	mglog "github.com/absmach/magistrala/logger"
	"github.com/absmach/magistrala/pkg/errors"
	"github.com/absmach/magistrala/pkg/prometheus"
	"github.com/caarlos0/env/v9"
	mqtt "github.com/eclipse/paho.mqtt.golang"
	"golang.org/x/sync/errgroup"
)

type config struct {
	LogLevel             string `env:"MG_AGENT_LOG_LEVEL"                     envDefault:"info"`
	NodeRedURL           string `env:"MG_AGENT_NODERED_URL"                   envDefault:"http://localhost:1880/"`
	MqttURL              string `env:"MG_AGENT_MQTT_URL"                      envDefault:"localhost:1883"`
	HTTPPort             string `env:"MG_AGENT_HTTP_PORT"                     envDefault:"9999"`
	MqttSkipTLSVer       string `env:"MG_AGENT_MQTT_SKIP_TLS"                 envDefault:"true"`
	MqttMTLS             string `env:"MG_AGENT_MQTT_MTLS"                     envDefault:"false"`
	MqttCA               string `env:"MG_AGENT_MQTT_CA"                       envDefault:"ca.crt"`
	MqttQoS              string `env:"MG_AGENT_MQTT_QOS"                      envDefault:"0"`
	MqttCmdQoS           string `env:"MG_AGENT_MQTT_CMD_QOS"                  envDefault:"1"`
	MqttRetain           string `env:"MG_AGENT_MQTT_RETAIN"                   envDefault:"false"`
	MqttCert             string `env:"MG_AGENT_MQTT_CLIENT_CERT"              envDefault:"client.cert"`
	MqttPrivateKey       string `env:"MG_AGENT_MQTT_CLIENT_KEY"               envDefault:"client.key"`
	HeartbeatInterval    string `env:"MG_AGENT_HEARTBEAT_INTERVAL"            envDefault:"10s"`
	TelemetryInterval    string `env:"MG_AGENT_TELEMETRY_INTERVAL"            envDefault:"0s"`
	TermSessionTimeout   string `env:"MG_AGENT_TERMINAL_SESSION_TIMEOUT"      envDefault:"60s"`
	OTAEnabled           string `env:"MG_AGENT_OTA_ENABLED"                   envDefault:"false"`
	OTABinaryPath        string `env:"MG_AGENT_OTA_BINARY_PATH"               envDefault:"/usr/local/bin/agent"`
	OTADownloadDir       string `env:"MG_AGENT_OTA_DOWNLOAD_DIR"              envDefault:"/tmp"`
	BootstrapURL         string `env:"MG_AGENT_BOOTSTRAP_URL"                 envDefault:""`
	BootstrapExternalID  string `env:"MG_AGENT_BOOTSTRAP_EXTERNAL_ID"         envDefault:""`
	BootstrapExternalKey string `env:"MG_AGENT_BOOTSTRAP_EXTERNAL_KEY"        envDefault:""`
	BootstrapRetries     string `env:"MG_AGENT_BOOTSTRAP_RETRIES"             envDefault:"5"`
	BootstrapRetryDelay  string `env:"MG_AGENT_BOOTSTRAP_RETRY_DELAY_SECONDS" envDefault:"10"`
	BootstrapSkipTLS     string `env:"MG_AGENT_BOOTSTRAP_SKIP_TLS"            envDefault:"false"`
	BootstrapCachePath   string `env:"MG_AGENT_BOOTSTRAP_CACHE_PATH"          envDefault:"/var/lib/agent/bootstrap.json"`
	ClientsURL           string `env:"MG_AGENT_CLIENTS_URL"                   envDefault:""`
	ChannelsURL          string `env:"MG_AGENT_CHANNELS_URL"                  envDefault:""`
	RulesEngineURL       string `env:"MG_AGENT_RULES_ENGINE_URL"              envDefault:""`
	ProvisionToken       string `env:"MG_PAT"                                 envDefault:""`
	DeviceDBPath         string `env:"MG_AGENT_DEVICE_DB_PATH"                envDefault:"/var/lib/agent/devices.db"`
	ConfigPath           string `env:"MG_AGENT_CONFIG_PATH"                   envDefault:"agent-config.json"`
	CommandSecret        string `env:"MG_AGENT_COMMAND_SECRET"                envDefault:""`
}

var (
	errFailedToSetupMTLS       = errors.New("Failed to set up mtls certs")
	errFailedToConfigHeartbeat = errors.New("Failed to configure heartbeat")
	errFetchingBootstrapFailed = errors.New("Fetching bootstrap failed with error")
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

	logger, levelVar, err := initLogger(cfg.Log.Level)
	if err != nil {
		log.Printf("Failed to create logger: %s", err)
		exitCode = 1
		return
	}
	stream := logstream.New()
	logger = slog.New(logstream.NewHandler(logger.Handler(), stream))

	store, err := pkgconfig.NewStore(c.ConfigPath)
	if err != nil {
		logger.Error("Failed to open persistent config store", slog.Any("error", err))
		exitCode = 1
		return
	}

	cfg = applyPersistedOverrides(cfg, store)

	if hasBootstrapConfig(c) {
		forceFetch := false
		if val, ok := store.Get("bs_valid"); ok && val == "0" {
			forceFetch = true
		}
		if forceFetch || !hasBootstrapCredentials(cfg) {
			cfg, err = loadBootConfig(cfg, c, logger, forceFetch)
			if err != nil {
				logger.Error("Failed to load bootstrap config", slog.Any("error", err))
				exitCode = 1
				return
			}
			persistBootstrapFields(store, cfg, logger)
			if err := store.Set("bs_valid", "1"); err != nil {
				logger.Warn("Failed to persist bs_valid flag", slog.Any("error", err))
			}
			cfg = applyPersistedOverrides(cfg, store)
		} else {
			logger.Info("Bootstrap data already present, skipping bootstrap fetch")
		}
	}

	// Sync the live log-level variable with any persisted log_level override.
	if val, ok := store.Get("log_level"); ok {
		var l slog.Level
		if err := l.UnmarshalText([]byte(val)); err == nil {
			levelVar.Set(l)
		}
	}

	if err := validateRuntimeConfig(cfg); err != nil {
		logger.Error("Failed to validate config", slog.Any("error", err))
		exitCode = 1
		return
	}

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

	// Bootstrap-based deployments receive all provision fields via the profile
	// template (clients_url, channels_url, rules_engine_url, token).
	// The env-var fallbacks below are only used in non-bootstrap setups.
	clientsURL := cfg.Provision.ClientsURL
	if clientsURL == "" {
		clientsURL = c.ClientsURL
	}
	channelsURL := cfg.Provision.ChannelsURL
	if channelsURL == "" {
		channelsURL = c.ChannelsURL
	}
	rulesEngineURL := cfg.Provision.RulesEngineURL
	if rulesEngineURL == "" {
		rulesEngineURL = c.RulesEngineURL
	}
	provisionToken := cfg.Provision.Token
	if provisionToken == "" {
		provisionToken = c.ProvisionToken
	}
	devices, err := devicemgr.New(c.DeviceDBPath, devicemgr.ProvisionConfig{
		ClientsURL:     clientsURL,
		ChannelsURL:    channelsURL,
		RulesEngineURL: rulesEngineURL,
		Token:          provisionToken,
		DomainID:       cfg.DomainID,
	}, iface.Config{})
	if err != nil {
		logger.Error("Failed to open device store", slog.Any("error", err))
		exitCode = 1
		return
	}
	defer func() {
		if err := devices.Close(); err != nil {
			logger.Error("Failed to close device store", slog.Any("error", err))
		}
	}()

	svc, err := agent.New(ctx, mqttClient, &cfg, noderedClient, logger, devices, store, levelVar, c.BootstrapCachePath)
	if err != nil {
		logger.Error("Error in agent service", slog.Any("error", err))
		exitCode = 1
		return
	}

	svc = middleware.NewLogging(svc, logger)
	counter, latency := prometheus.MakeMetrics("agent", "api")
	svc = middleware.NewMetrics(svc, counter, latency)
	b := conn.NewBroker(svc, mqttClient, cfg.Channels.CtrlChan(), cfg.DomainID, logger)
	onReconnect = b.Resubscribe

	srv := &http.Server{
		Addr:    fmt.Sprintf(":%s", cfg.Server.Port),
		Handler: api.MakeHandler(svc, logger, stream, ""),
	}

	g.Go(func() error {
		return b.Subscribe(ctx)
	})

	g.Go(func() error {
		logger.Info("Agent service started", slog.String("port", cfg.Server.Port))
		return srv.ListenAndServe()
	})

	g.Go(func() error {
		return StopSignalHandler(ctx, cancel, logger, "agent", srv, svc.Shutdown)
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
	if err := cfg.Channels.Validate(); err != nil {
		missing = append(missing, err.Error())
	}
	if cfg.MQTT.URL == "" {
		missing = append(missing, "mqtt.url")
	}
	if !cfg.MQTT.MTLS {
		if cfg.MQTT.Username == "" {
			missing = append(missing, "mqtt.username")
		}
		if cfg.MQTT.Password == "" {
			missing = append(missing, "mqtt.password")
		}
	}
	if cfg.Heartbeat.Interval <= 0 {
		missing = append(missing, "heartbeat.interval")
	}
	if len(missing) > 0 {
		return errors.New(fmt.Sprintf("%s: missing required runtime fields: %s", errInvalidRuntimeConfig, strings.Join(missing, ", ")))
	}
	return nil
}

func hasBootstrapConfig(cfg config) bool {
	return cfg.BootstrapURL != "" && cfg.BootstrapExternalID != "" && cfg.BootstrapExternalKey != ""
}

func hasBootstrapCredentials(cfg agent.Config) bool {
	if cfg.DomainID == "" {
		return false
	}
	if cfg.Channels.CtrlID == "" || cfg.Channels.DataID == "" {
		return false
	}
	if cfg.MQTT.URL == "" {
		return false
	}
	if cfg.MQTT.MTLS {
		if cfg.MQTT.ClientCert == "" || cfg.MQTT.ClientKey == "" {
			if cfg.MQTT.CertPath == "" || cfg.MQTT.PrivKeyPath == "" {
				return false
			}
		}
	} else if cfg.MQTT.Username == "" || cfg.MQTT.Password == "" {
		return false
	}
	return true
}

// persistBootstrapFields writes the critical bootstrap-derived fields to the
// persistent config store so they survive agent restarts and allow the
// bootstrap HTTP fetch to be skipped on subsequent runs.
//
// The MQTT password is stored in plaintext in agent-config.json. The file is
// created with 0o600 permissions (owner read/write only) and the password is
// needed to reconnect when mTLS is not in use.
func persistBootstrapFields(store pkgconfig.Store, cfg agent.Config, logger *slog.Logger) {
	if err := store.Set("domain_id", cfg.DomainID); err != nil {
		logger.Warn("Failed to persist domain_id", slog.Any("error", err))
	}
	if err := store.Set("channels_ctrl_id", cfg.Channels.CtrlID); err != nil {
		logger.Warn("Failed to persist channels_ctrl_id", slog.Any("error", err))
	}
	if err := store.Set("channels_data_id", cfg.Channels.DataID); err != nil {
		logger.Warn("Failed to persist channels_data_id", slog.Any("error", err))
	}
	if err := store.Set("mqtt_url", cfg.MQTT.URL); err != nil {
		logger.Warn("Failed to persist mqtt_url", slog.Any("error", err))
	}
	if err := store.Set("mqtt_username", cfg.MQTT.Username); err != nil {
		logger.Warn("Failed to persist mqtt_username", slog.Any("error", err))
	}
	if err := store.Set("mqtt_password", cfg.MQTT.Password); err != nil {
		logger.Warn("Failed to persist mqtt_password", slog.Any("error", err))
	}
}

func loadEnvConfig(cfg config) (agent.Config, error) {
	sc := agent.ServerConfig{
		Port: cfg.HTTPPort,
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

	telemetryInterval, err := time.ParseDuration(cfg.TelemetryInterval)
	if err != nil {
		return agent.Config{}, err
	}
	tlc := agent.TelemetryConfig{
		Interval: telemetryInterval,
	}

	nc := agent.NodeRedConfig{URL: cfg.NodeRedURL}
	lc := agent.LogConfig{Level: cfg.LogLevel}

	otaEnabled, err := strconv.ParseBool(cfg.OTAEnabled)
	if err != nil {
		otaEnabled = false
	}
	oc := agent.OTAConfig{
		Enabled:     otaEnabled,
		BinaryPath:  cfg.OTABinaryPath,
		DownloadDir: cfg.OTADownloadDir,
	}

	mtls, err := strconv.ParseBool(cfg.MqttMTLS)
	if err != nil {
		mtls = false
	}

	skipTLSVer, err := strconv.ParseBool(cfg.MqttSkipTLSVer)
	if err != nil {
		skipTLSVer = true
	}

	qos, err := strconv.ParseUint(cfg.MqttQoS, 10, 8)
	if err != nil || qos > 2 {
		qos = 0
	}

	cmdQoS, err := strconv.ParseUint(cfg.MqttCmdQoS, 10, 8)
	if err != nil || cmdQoS > 2 {
		cmdQoS = 1
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
		CmdQoS:      byte(cmdQoS),
		Retain:      retain,
	}

	c := agent.NewConfig(sc, agent.ChanConfig{}, nc, lc, mc, ch, ct, oc, tlc)
	c.CommandSecret = cfg.CommandSecret
	return c, nil
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

	var cc []byte
	var pk []byte

	// Prefer bootstrap-provided certificate material when present.
	if c.CaCert != "" {
		c.CA = []byte(c.CaCert)
	} else if c.CAPath != "" {
		caByte, err := os.ReadFile(c.CAPath)
		if err != nil {
			return c, err
		}
		c.CA = caByte
	}

	if c.ClientCert != "" && c.ClientKey != "" {
		cc = []byte(c.ClientCert)
		pk = []byte(c.ClientKey)
		cert, err := tls.X509KeyPair(cc, pk)
		if err != nil {
			return c, err
		}
		c.Cert = cert
	} else if c.CertPath != "" {
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

	return c, nil
}

func StopSignalHandler(ctx context.Context, cancel context.CancelFunc, logger *slog.Logger, svcName string, server *http.Server, shutdown func()) error {
	c := make(chan os.Signal, 2)
	signal.Notify(c, syscall.SIGINT, syscall.SIGTERM, syscall.SIGABRT)
	select {
	case sig := <-c:
		defer cancel()
		logger.Info("Received shutdown signal, performing graceful shutdown", slog.String("signal", sig.String()))
		shutdown()
		shutdownCtx, shutdownCancel := context.WithTimeout(ctx, 5*time.Second)
		defer shutdownCancel()
		if err := server.Shutdown(shutdownCtx); err != nil {
			return fmt.Errorf("failed to shutdown %s server: %v", svcName, err)
		}
		return fmt.Errorf("%s service shutdown by signal: %s", svcName, sig)
	case <-ctx.Done():
		return nil
	}
}

func initLogger(levelText string) (*slog.Logger, *slog.LevelVar, error) {
	var level slog.Level
	if err := level.UnmarshalText([]byte(levelText)); err != nil {
		return &slog.Logger{}, nil, fmt.Errorf(`{"level":"error","message":"%s: %s","ts":"%s"}`, err, levelText, time.Now())
	}

	var levelVar slog.LevelVar
	levelVar.Set(level)
	logHandler := slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: &levelVar,
	})

	return slog.New(logHandler), &levelVar, nil
}

func applyPersistedOverrides(cfg agent.Config, store pkgconfig.Store) agent.Config {
	for key, val := range store.All() {
		agent.ApplyConfigEntry(&cfg, key, val)
	}
	return cfg
}

func loadBootConfig(c agent.Config, cfg config, logger *slog.Logger, forceFetch bool) (agent.Config, error) {
	missing := []string{}
	if cfg.BootstrapURL == "" {
		missing = append(missing, "MG_AGENT_BOOTSTRAP_URL")
	}
	if cfg.BootstrapExternalID == "" {
		missing = append(missing, "MG_AGENT_BOOTSTRAP_EXTERNAL_ID")
	}
	if cfg.BootstrapExternalKey == "" {
		missing = append(missing, "MG_AGENT_BOOTSTRAP_EXTERNAL_KEY")
	}
	if len(missing) > 0 {
		return c, errors.New(fmt.Sprintf("bootstrap configuration is incomplete: missing %s", strings.Join(missing, ", ")))
	}

	skipTLS, err := strconv.ParseBool(cfg.BootstrapSkipTLS)
	if err != nil {
		skipTLS = false
	}

	bsConfig := bootstrap.Config{
		URL:           cfg.BootstrapURL,
		ID:            cfg.BootstrapExternalID,
		Key:           cfg.BootstrapExternalKey,
		Retries:       cfg.BootstrapRetries,
		RetryDelaySec: cfg.BootstrapRetryDelay,
		SkipTLS:       skipTLS,
		CachePath:     cfg.BootstrapCachePath,
	}

	bsc, err := bootstrap.FetchAgentConfig(bsConfig, c, logger, forceFetch)
	if err != nil {
		return c, errors.Wrap(errFetchingBootstrapFailed, err)
	}
	mc, err := loadCertificate(bsc.MQTT)
	if err != nil {
		return bsc, errors.Wrap(errFailedToSetupMTLS, err)
	}

	bsc.MQTT = mc
	return bsc, nil
}

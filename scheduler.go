// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/absmach/agent/pkg/devicemgr"
	mqtt "github.com/eclipse/paho.mqtt.golang"
)

const (
	schedulerReadSize     = 4096
	schedulerReconnectMin = 1 * time.Second
	schedulerReconnectMax = 30 * time.Second
)

// Scheduler manages per-device telemetry goroutines.
// Each active downstream device gets one goroutine that opens the physical
// interface, creates a dedicated MQTT connection as that device, then loops
// reading bytes and publishing to the device's Magistrala channel.
type Scheduler struct {
	devices  *devicemgr.Manager
	mqttCfg  MQTTConfig
	domainID string
	logger   *slog.Logger
	mu       sync.Mutex
	cancels  map[string]context.CancelFunc
}

func newScheduler(devices *devicemgr.Manager, mqttCfg MQTTConfig, domainID string, logger *slog.Logger) *Scheduler {
	return &Scheduler{
		devices:  devices,
		mqttCfg:  mqttCfg,
		domainID: domainID,
		logger:   logger,
		cancels:  make(map[string]context.CancelFunc),
	}
}

// Start launches goroutines for all devices already in the registry
// (persisted from a prior run). Call Stop to cancel them.
func (s *Scheduler) Start(ctx context.Context) error {
	devs, err := s.devices.List()
	if err != nil {
		return fmt.Errorf("scheduler start: %w", err)
	}
	for _, d := range devs {
		if d.ChannelID != "" {
			s.startDevice(ctx, d)
		}
	}
	return nil
}

// StartDevice launches the telemetry goroutine for a newly provisioned device.
// ctx controls the lifetime of the goroutine; pass context.Background() when
// the goroutine should outlive the caller (e.g. an HTTP request).
// A second call for the same device ID is a no-op.
func (s *Scheduler) StartDevice(ctx context.Context, d devicemgr.Device) {
	if d.ChannelID == "" {
		return
	}
	s.startDevice(ctx, d)
}

// Stop cancels all running device goroutines.
func (s *Scheduler) Stop() {
	s.mu.Lock()
	for _, cancel := range s.cancels {
		cancel()
	}
	s.cancels = make(map[string]context.CancelFunc)
	s.mu.Unlock()
}

// StopDevice cancels the telemetry goroutine for the given device ID and
// closes its physical interface so any blocked ReadIface returns immediately.
func (s *Scheduler) StopDevice(id string) {
	s.mu.Lock()
	cancel, ok := s.cancels[id]
	delete(s.cancels, id)
	s.mu.Unlock()
	if ok {
		cancel()
		// Closing the interface unblocks any in-progress ReadIface call.
		_ = s.devices.CloseIface(id)
	}
}

func (s *Scheduler) startDevice(ctx context.Context, d devicemgr.Device) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.cancels[d.ID]; ok {
		return
	}
	dctx, cancel := context.WithCancel(ctx)
	s.cancels[d.ID] = cancel
	go s.runDevice(dctx, d)
}

// runDevice is the per-device goroutine. It retries the connect→open→read
// cycle with exponential backoff after any failure.
func (s *Scheduler) runDevice(ctx context.Context, d devicemgr.Device) {
	log := s.logger.With(slog.String("device_id", d.ID), slog.String("device", d.Name))
	topic := fmt.Sprintf("m/%s/c/%s/msg", s.domainID, d.ChannelID)
	delay := schedulerReconnectMin

	for {
		mqttClient, err := s.connectDevice(d)
		if err != nil {
			log.Warn("Device MQTT connect failed", slog.Any("error", err))
			if !sleepCtx(ctx, delay) {
				return
			}
			delay = min(delay*2, schedulerReconnectMax)
			continue
		}

		if err := s.devices.OpenIface(d.ID); err != nil {
			log.Warn("Device interface open failed", slog.Any("error", err))
			go mqttClient.Disconnect(250)
			if !sleepCtx(ctx, delay) {
				return
			}
			delay = min(delay*2, schedulerReconnectMax)
			continue
		}

		delay = schedulerReconnectMin
		log.Info("Device telemetry started")
		s.readPublishLoop(ctx, mqttClient, d.ID, topic, log)
		_ = s.devices.CloseIface(d.ID)

		if ctx.Err() != nil {
			go mqttClient.Disconnect(250)
			return
		}
		mqttClient.Disconnect(250)
		if !sleepCtx(ctx, delay) {
			return
		}
		delay = min(delay*2, schedulerReconnectMax)
	}
}

// readPublishLoop reads from the device interface and publishes to MQTT until
// the interface returns an error or ctx is cancelled.
func (s *Scheduler) readPublishLoop(ctx context.Context, mqttClient mqtt.Client, deviceID, topic string, log *slog.Logger) {
	for {
		data, err := s.devices.ReadIface(deviceID, schedulerReadSize)
		if err != nil {
			if ctx.Err() == nil {
				log.Warn("Device read error", slog.Any("error", err))
			}
			return
		}
		if len(data) == 0 {
			if !sleepCtx(ctx, 5*time.Millisecond) {
				return
			}
			continue
		}

		token := mqttClient.Publish(topic, s.mqttCfg.QoS, false, data)
		token.Wait()
		if err := token.Error(); err != nil {
			log.Warn("Device publish failed", slog.Any("error", err))
			return
		}
		_ = s.devices.MarkSeen(deviceID)
	}
}

// connectDevice creates a fresh MQTT connection authenticated as the device.
// TLS settings are inherited from the gateway's MQTT config (same broker).
func (s *Scheduler) connectDevice(d devicemgr.Device) (mqtt.Client, error) {
	// Magistrala uses the Client ID as the MQTT username for device auth.
	opts := mqtt.NewClientOptions().
		AddBroker(s.mqttCfg.URL).
		SetClientID(d.ID).
		SetUsername(d.ID).
		SetPassword(d.Key).
		SetCleanSession(true).
		SetAutoReconnect(false)

	if s.mqttCfg.MTLS {
		cfg := &tls.Config{InsecureSkipVerify: s.mqttCfg.SkipTLSVer}
		if s.mqttCfg.CA != nil {
			cfg.RootCAs = x509.NewCertPool()
			cfg.RootCAs.AppendCertsFromPEM(s.mqttCfg.CA)
		}
		opts.SetTLSConfig(cfg)
		opts.SetProtocolVersion(4)
	} else if strings.HasPrefix(s.mqttCfg.URL, "ssl://") || strings.HasPrefix(s.mqttCfg.URL, "tls://") {
		rootCAs, _ := x509.SystemCertPool()
		if rootCAs == nil {
			rootCAs = x509.NewCertPool()
		}
		opts.SetTLSConfig(&tls.Config{
			InsecureSkipVerify: s.mqttCfg.SkipTLSVer,
			RootCAs:            rootCAs,
		})
		opts.SetProtocolVersion(4)
	}

	client := mqtt.NewClient(opts)
	token := client.Connect()
	token.Wait()
	if err := token.Error(); err != nil {
		return nil, err
	}
	return client, nil
}

// sleepCtx waits for d or until ctx is done. Returns true if the timer fired.
func sleepCtx(ctx context.Context, d time.Duration) bool {
	select {
	case <-ctx.Done():
		return false
	case <-time.After(d):
		return true
	}
}

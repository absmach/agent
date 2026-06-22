// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

package coap

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"log"
	"log/slog"
	"os"
	"sync"
	"sync/atomic"
	"time"

	piondtls "github.com/pion/dtls/v3"
	"github.com/plgd-dev/go-coap/v3/dtls"
	"github.com/plgd-dev/go-coap/v3/message"
	"github.com/plgd-dev/go-coap/v3/message/codes"
	"github.com/plgd-dev/go-coap/v3/message/pool"
	"github.com/plgd-dev/go-coap/v3/mux"
	"github.com/plgd-dev/go-coap/v3/options"
	"github.com/plgd-dev/go-coap/v3/udp"
	"github.com/plgd-dev/go-coap/v3/udp/client"
)

var (
	ErrInvalidMsgCode = errors.New("message can be GET, POST, PUT or DELETE")
	ErrDialFailed     = errors.New("failed to dial the connection")
	ErrNotConnected   = errors.New("client not connected")
)

type Config struct {
	URL            string
	PSK            string
	PSKIdentity    string
	CertPath       string
	PrivKeyPath    string
	CAPath         string
	SkipTLSVer     bool
	MaxObserve     uint
	MaxRetransmits uint
	KeepAlive      uint64
	ContentFormat  int
	Cert           string
	Key            string
	CA             string
}

type Client struct {
	conn         *client.Conn
	connected    atomic.Bool
	config       Config
	logger       *slog.Logger
	observations map[string]mux.Observation
	obsMu        sync.Mutex
}

type MessageHandler func(payload []byte)

func NewClient(cfg Config, logger *slog.Logger) (*Client, error) {
	dtlsConfig, err := createDTLSConfig(cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to create DTLS config: %w", err)
	}

	var dialOptions []udp.Option
	if cfg.KeepAlive > 0 {
		dialOptions = append(dialOptions, options.WithKeepAlive(10, time.Duration(cfg.KeepAlive)*time.Second, onInactive))
	}

	var c *client.Conn
	if dtlsConfig != nil {
		c, err = dtls.Dial(cfg.URL, dtlsConfig, dialOptions...)
	} else {
		c, err = udp.Dial(cfg.URL, dialOptions...)
	}
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrDialFailed, err)
	}

	client := &Client{
		conn:         c,
		connected:    atomic.Bool{},
		config:       cfg,
		logger:       logger,
		observations: make(map[string]mux.Observation),
	}
	client.connected.Store(true)

	return client, nil
}

func (c *Client) Send(ctx context.Context, path string, msgCode codes.Code, cf message.MediaType, payload io.ReadSeeker, opts ...message.Option) (*pool.Message, error) {
	if !c.connected.Load() {
		return nil, ErrNotConnected
	}

	if _, ok := ctx.Deadline(); !ok {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, time.Minute)
		defer cancel()
	}

	switch msgCode {
	case codes.GET:
		return c.conn.Get(ctx, path, opts...)
	case codes.POST:
		return c.conn.Post(ctx, path, cf, payload, opts...)
	case codes.PUT:
		return c.conn.Put(ctx, path, cf, payload, opts...)
	case codes.DELETE:
		return c.conn.Delete(ctx, path, opts...)
	default:
		return nil, ErrInvalidMsgCode
	}
}

func (c *Client) Observe(ctx context.Context, path string, handler MessageHandler, opts ...message.Option) (mux.Observation, error) {
	if !c.connected.Load() {
		return nil, ErrNotConnected
	}

	c.obsMu.Lock()
	defer c.obsMu.Unlock()

	obsCtx, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()

	obs, err := c.conn.Observe(obsCtx, path, func(res *pool.Message) {
		body, err := res.ReadBody()
		if err != nil {
			c.logger.Warn("Error reading CoAP message body", slog.Any("error", err))
			return
		}

		if handler != nil {
			handler(body)
		}
	}, opts...)
	if err != nil {
		return nil, fmt.Errorf("failed to observe resource: %w", err)
	}

	c.observations[path] = obs
	return obs, nil
}

func (c *Client) CancelObserve(ctx context.Context, path string, opts ...message.Option) error {
	c.obsMu.Lock()
	defer c.obsMu.Unlock()

	obs, ok := c.observations[path]
	if !ok {
		return fmt.Errorf("no observation for path %s", path)
	}

	if err := obs.Cancel(ctx, opts...); err != nil {
		return fmt.Errorf("failed to cancel observation: %w", err)
	}

	delete(c.observations, path)
	return nil
}

func (c *Client) IsConnected() bool {
	return c.connected.Load()
}

func (c *Client) Disconnect() error {
	c.obsMu.Lock()
	defer c.obsMu.Unlock()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	for path, obs := range c.observations {
		if err := obs.Cancel(ctx); err != nil {
			c.logger.Warn("Failed to cancel observation on disconnect",
				slog.String("path", path),
				slog.Any("error", err))
		}
		delete(c.observations, path)
	}

	c.connected.Store(false)
	if err := c.conn.Close(); err != nil {
		return fmt.Errorf("failed to close connection: %w", err)
	}

	return nil
}

func (c *Client) Ping(ctx context.Context) error {
	if !c.connected.Load() {
		return ErrNotConnected
	}
	return c.conn.Ping(ctx)
}

func createDTLSConfig(cfg Config) (*piondtls.Config, error) { //nolint:staticcheck
	if cfg.PSK == "" && cfg.CertPath == "" {
		return nil, nil
	}

	dc := &piondtls.Config{ //nolint:staticcheck
		InsecureSkipVerify: cfg.SkipTLSVer,
	}

	if cfg.PSK != "" {
		dc.PSK = func(b []byte) ([]byte, error) {
			return []byte(cfg.PSK), nil
		}
		dc.PSKIdentityHint = []byte(cfg.PSKIdentity)
		dc.CipherSuites = []piondtls.CipherSuiteID{
			piondtls.TLS_PSK_WITH_AES_128_CCM,
			piondtls.TLS_PSK_WITH_AES_128_CCM_8,
			piondtls.TLS_PSK_WITH_AES_256_CCM_8,
			piondtls.TLS_PSK_WITH_AES_128_GCM_SHA256,
			piondtls.TLS_PSK_WITH_AES_128_CBC_SHA256,
		}
	}

	if cfg.CertPath != "" && cfg.PrivKeyPath != "" {
		var cert tls.Certificate
		var err error

		if cfg.Cert != "" && cfg.Key != "" {
			cert, err = tls.X509KeyPair([]byte(cfg.Cert), []byte(cfg.Key))
		} else {
			cert, err = tls.LoadX509KeyPair(cfg.CertPath, cfg.PrivKeyPath)
		}
		if err != nil {
			return nil, fmt.Errorf("failed to load certificates: %w", err)
		}
		dc.Certificates = []tls.Certificate{cert}
	}

	if cfg.CAPath != "" {
		rootCA, err := loadCertFile(cfg.CAPath)
		if err != nil {
			return nil, fmt.Errorf("failed to load CA file: %w", err)
		}
		if len(rootCA) > 0 {
			if dc.RootCAs == nil {
				dc.RootCAs = x509.NewCertPool()
			}
			if !dc.RootCAs.AppendCertsFromPEM(rootCA) {
				return nil, errors.New("failed to append root CA to pool")
			}
		}
	} else if cfg.CA != "" {
		if dc.RootCAs == nil {
			dc.RootCAs = x509.NewCertPool()
		}
		if !dc.RootCAs.AppendCertsFromPEM([]byte(cfg.CA)) {
			return nil, errors.New("failed to append root CA from config")
		}
	}

	return dc, nil
}

func loadCertFile(certFile string) ([]byte, error) {
	if certFile == "" {
		return []byte{}, nil
	}
	return os.ReadFile(certFile)
}

func onInactive(cc *client.Conn) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := cc.Ping(ctx); err != nil {
		log.Printf("Error pinging CoAP server: %v", err)
	}
}

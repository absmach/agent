// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"log/slog"
	"net/http"
	"os"

	"github.com/absmach/agent/gateway"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	cfg, err := gateway.LoadConfig()
	if err != nil {
		logger.Error("Invalid gateway configuration", slog.Any("error", err))
		os.Exit(1)
	}
	broker, err := gateway.NewBroker(cfg, logger)
	if err != nil {
		logger.Error("Gateway MQTT connection failed", slog.Any("error", err))
		os.Exit(1)
	}
	defer broker.Close()
	logger.Info("Agent gateway started", slog.String("address", cfg.Address))
	if err := http.ListenAndServe(cfg.Address, gateway.NewHandler(broker, cfg.AuthTokens, logger)); err != nil {
		logger.Error("Gateway stopped", slog.Any("error", err))
		os.Exit(1)
	}
}

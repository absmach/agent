// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

package api_test

import (
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"
	"testing"
	"time"

	dockertest "github.com/ory/dockertest/v3"
)

const (
	username      = "magistrala-mqtt"
	broker        = "eclipse-mosquitto"
	brokerVersion = "1.6.13"
	poolMaxWait   = 120 * time.Second
)

var mqttAddress string

func TestMain(m *testing.M) {
	pool, err := dockertest.NewPool("")
	if err != nil {
		log.Fatalf("Could not connect to docker: %s", err)
	}

	mqttContainer, err := pool.Run(broker, brokerVersion, []string{})
	if err != nil {
		log.Fatalf("Could not start container: %s", err)
	}
	handleInterrupt(pool, mqttContainer)

	pool.MaxWait = poolMaxWait
	if err := pool.Retry(func() error {
		mqttAddress = fmt.Sprintf("%s:%s", "localhost", mqttContainer.GetPort("1883/tcp"))
		conn, err := net.DialTimeout("tcp", mqttAddress, time.Second)
		if err != nil {
			return err
		}
		return conn.Close()
	}); err != nil {
		log.Fatalf("Could not connect to docker: %s", err)
	}

	code := m.Run()
	if err := pool.Purge(mqttContainer); err != nil {
		log.Fatalf("Could not purge container: %s", err)
	}

	os.Exit(code)
}

func handleInterrupt(pool *dockertest.Pool, container *dockertest.Resource) {
	c := make(chan os.Signal, 2)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)

	go func() {
		<-c
		if err := pool.Purge(container); err != nil {
			log.Fatalf("Could not purge container: %s", err)
		}
		os.Exit(0)
	}()
}

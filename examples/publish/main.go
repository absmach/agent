// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"flag"
	"log"
	"os"

	mflog "github.com/absmach/magistrala/logger"
	"github.com/absmach/magistrala/pkg/messaging"
	"github.com/absmach/magistrala/pkg/messaging/brokers"
	"github.com/nats-io/nats.go"
)

func main() {
	ctx := context.Background()

	var urls = flag.String("s", nats.DefaultURL, "The nats server URLs (separated by comma)")
	var showHelp = flag.Bool("h", false, "Show help message")

	log.SetFlags(0)
	flag.Usage = usage
	flag.Parse()

	if *showHelp {
		showUsageAndExit(0)
	}

	args := flag.Args()
	if len(args) != 2 {
		showUsageAndExit(1)
	}

	subj, msg := args[0], []byte(args[1])

	logger, err := mflog.New(os.Stdout, "info")
	if err != nil {
		log.Fatalf("failed to init logger: %s", err)
	}

	ps, err := brokers.NewPublisher(ctx, *urls)
	if err != nil {
		logger.Error(err.Error())
		return
	}
	defer ps.Close()

	if err := ps.Publish(context.Background(), subj, &messaging.Message{
		Channel: subj,
		Payload: msg,
	}); err != nil {
		logger.Error(err.Error())
		return
	}
	logger.Info("Message published")
}

func usage() {
	log.Printf("Usage: publish [-s server] <channel> <msg>\n")
	flag.PrintDefaults()
}

func showUsageAndExit(exitcode int) {
	usage()
	os.Exit(exitcode)
}

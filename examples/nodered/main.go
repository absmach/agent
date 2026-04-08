// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

// Package main provides an example of interacting with the agent's Node-RED
// management endpoint. Supported commands:
//
//	nodered-ping                   - Check if Node-RED is reachable
//	nodered-flows                  - Fetch current flows from Node-RED
//	nodered-state                  - Get the current flow runtime state
//	nodered-deploy   <flows.json>  - Deploy flows from a JSON file path or raw JSON string
//	nodered-add-flow <flow.json>   - Add a single flow from a JSON file path or raw JSON string
package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
)

const defaultAgentURL = "http://localhost:9999"

type nodeRedRequest struct {
	Command string `json:"command"`
	Flows   string `json:"flows,omitempty"`
}

func main() {
	agentURL := flag.String("agent", defaultAgentURL, "Agent HTTP URL")
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: nodered [flags] <command> [flows-file-or-json]\n\n")
		fmt.Fprintf(os.Stderr, "Commands:\n")
		fmt.Fprintf(os.Stderr, "  nodered-ping                   Check if Node-RED is reachable\n")
		fmt.Fprintf(os.Stderr, "  nodered-flows                  Fetch current flows from Node-RED\n")
		fmt.Fprintf(os.Stderr, "  nodered-state                  Get the current flow runtime state\n")
		fmt.Fprintf(os.Stderr, "  nodered-deploy   <flows>       Deploy flows (file path or raw JSON)\n")
		fmt.Fprintf(os.Stderr, "  nodered-add-flow <flow>        Add a single flow (file path or raw JSON)\n\n")
		fmt.Fprintf(os.Stderr, "Flags:\n")
		flag.PrintDefaults()
	}
	flag.Parse()

	args := flag.Args()
	if len(args) < 1 {
		flag.Usage()
		os.Exit(1)
	}

	command := args[0]

	var flows string
	switch command {
	case "nodered-deploy", "nodered-add-flow":
		if len(args) < 2 {
			log.Fatalf("%s requires a flows argument (file path or raw JSON)", command)
		}
		raw := readFlows(args[1])
		flows = base64.StdEncoding.EncodeToString(raw)
	case "nodered-ping", "nodered-flows", "nodered-state":
		// no argument needed
	default:
		log.Fatalf("unknown command %q; run with -h for usage", command)
	}

	req := nodeRedRequest{Command: command, Flows: flows}
	body, err := json.Marshal(req)
	if err != nil {
		log.Fatalf("failed to encode request: %s", err)
	}

	resp, err := http.Post(*agentURL+"/nodered", "application/json", bytes.NewReader(body))
	if err != nil {
		log.Fatalf("failed to send request: %s", err)
	}

	respBody, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		log.Fatalf("failed to read response: %s", err)
	}

	if resp.StatusCode != http.StatusOK {
		log.Fatalf("agent returned %d: %s", resp.StatusCode, respBody)
	}

	fmt.Printf("%s\n", respBody)
}

// readFlows reads flow JSON either from a file path or returns the argument as-is if it looks like JSON.
func readFlows(arg string) []byte {
	if len(arg) > 0 && arg[0] == '[' || arg[0] == '{' {
		return []byte(arg)
	}
	data, err := os.ReadFile(arg)
	if err != nil {
		log.Fatalf("failed to read flows file %q: %s", arg, err)
	}
	return data
}

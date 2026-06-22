// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"encoding/json"
	"net/http"
	"os"
	"strings"

	"github.com/absmach/agent"
)

const (
	healthContentType = "application/health+json"
	healthStatusPass  = "pass"
	healthStatusFail  = "fail"
)

type healthInfo struct {
	Status      string `json:"status"`
	Version     string `json:"version"`
	Commit      string `json:"commit"`
	Description string `json:"description"`
	BuildTime   string `json:"build_time"`
	InstanceID  string `json:"instance_id"`
}

func getInstanceID() string {
	if hostname, err := os.Hostname(); err == nil && hostname != "" {
		return hostname
	}

	if data, err := os.ReadFile("/proc/self/cgroup"); err == nil {
		lines := strings.SplitSeq(string(data), "\n")
		for line := range lines {
			if strings.Contains(line, "docker") || strings.Contains(line, "kubepods") {
				parts := strings.Split(line, "/")
				for i := len(parts) - 1; i >= 0; i-- {
					if parts[i] != "" && len(parts[i]) >= 12 {
						return parts[i][:12]
					}
				}
			}
		}
	}

	return "unknown"
}

func health(svc agent.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Add("Content-Type", healthContentType)
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}

		status := healthStatusPass
		if !svc.Health() {
			status = healthStatusFail
		}

		res := healthInfo{
			Status:      status,
			Version:     agent.Version,
			Commit:      agent.Commit,
			Description: "agent service",
			BuildTime:   agent.BuildTime,
			InstanceID:  getInstanceID(),
		}

		w.WriteHeader(http.StatusOK)
		if err := json.NewEncoder(w).Encode(res); err != nil {
			w.WriteHeader(http.StatusInternalServerError)
		}
	}
}

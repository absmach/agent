// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"bufio"
	"context"
	"fmt"
	"log/slog"
	"os"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	senml "github.com/absmach/senml"
)

type cpuSnapshot struct {
	idle  uint64
	total uint64
}

func (a *agent) periodicTelemetry(ctx context.Context, topic string, interval time.Duration, qos byte) {
	var previousCPU *cpuSnapshot
	publish := func() {
		payload, nextCPU, err := a.telemetryPayload(previousCPU)
		if err != nil {
			a.logger.Warn("failed to encode telemetry", slog.Any("error", err))
			return
		}
		previousCPU = nextCPU

		token := a.mqttClient.Publish(topic, qos, false, payload)
		token.Wait()
		if err := token.Error(); err != nil {
			a.logger.Warn("telemetry publish failed", slog.Any("error", err))
		}
	}

	publish()
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			publish()
		case <-ctx.Done():
			return
		}
	}
}

func (a *agent) telemetryPayload(previousCPU *cpuSnapshot) ([]byte, *cpuSnapshot, error) {
	pack, nextCPU := collectTelemetry(previousCPU)
	payload, err := senml.Encode(pack, senml.JSON)
	if err != nil {
		return nil, nextCPU, err
	}
	return payload, nextCPU, nil
}

func collectTelemetry(previousCPU *cpuSnapshot) (senml.Pack, *cpuSnapshot) {
	records := []senml.Record{}

	if currentCPU, err := readCPUSnapshot(); err == nil {
		cpuUsage := cpuUsagePercent(previousCPU, currentCPU)
		records = append(records, senml.Record{Name: "cpu_usage", Unit: "%", Value: &cpuUsage})
		previousCPU = currentCPU
	}

	if memoryUsed, memoryFree, err := readMemoryStats(); err == nil {
		used := float64(memoryUsed)
		free := float64(memoryFree)
		records = append(records,
			senml.Record{Name: "memory_used", Unit: "By", Value: &used},
			senml.Record{Name: "memory_free", Unit: "By", Value: &free},
		)
	}

	if diskUsed, diskFree, err := readDiskStats("/"); err == nil {
		used := float64(diskUsed)
		free := float64(diskFree)
		records = append(records,
			senml.Record{Name: "disk_used", Unit: "By", Value: &used},
			senml.Record{Name: "disk_free", Unit: "By", Value: &free},
		)
	}

	uptime := time.Since(startTime).Seconds()
	records = append(records, senml.Record{Name: "uptime", Unit: "s", Value: &uptime})

	for _, stat := range readNetworkStats() {
		rx := float64(stat.rxBytes)
		tx := float64(stat.txBytes)
		name := sanitizeMetricName(stat.name)
		records = append(records,
			senml.Record{Name: fmt.Sprintf("net_%s_rx_bytes", name), Unit: "By", Value: &rx},
			senml.Record{Name: fmt.Sprintf("net_%s_tx_bytes", name), Unit: "By", Value: &tx},
		)
	}

	return senml.Pack{Records: records}, previousCPU
}

func readCPUSnapshot() (*cpuSnapshot, error) {
	b, err := os.ReadFile("/proc/stat")
	if err != nil {
		return nil, err
	}
	line, _, _ := strings.Cut(string(b), "\n")
	fields := strings.Fields(line)
	if len(fields) < 5 || fields[0] != "cpu" {
		return nil, fmt.Errorf("invalid /proc/stat cpu line")
	}

	var total uint64
	values := make([]uint64, 0, len(fields)-1)
	for _, field := range fields[1:] {
		value, err := strconv.ParseUint(field, 10, 64)
		if err != nil {
			return nil, err
		}
		total += value
		values = append(values, value)
	}
	idle := values[3]
	if len(values) > 4 {
		idle += values[4]
	}
	return &cpuSnapshot{idle: idle, total: total}, nil
}

func cpuUsagePercent(previous, current *cpuSnapshot) float64 {
	if current == nil || current.total == 0 {
		return 0
	}
	idle := current.idle
	total := current.total
	if previous != nil && current.total > previous.total {
		idle = current.idle - previous.idle
		total = current.total - previous.total
	}
	if total == 0 || idle > total {
		return 0
	}
	return 100 * float64(total-idle) / float64(total)
}

func readMemoryStats() (uint64, uint64, error) {
	file, err := os.Open("/proc/meminfo")
	if err != nil {
		var mem runtime.MemStats
		runtime.ReadMemStats(&mem)
		if mem.HeapSys < mem.HeapAlloc {
			return mem.HeapAlloc, 0, nil
		}
		return mem.HeapAlloc, mem.HeapSys - mem.HeapAlloc, nil
	}
	defer file.Close()

	var total, available, free uint64
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 2 {
			continue
		}
		value, err := strconv.ParseUint(fields[1], 10, 64)
		if err != nil {
			continue
		}
		value *= 1024
		switch fields[0] {
		case "MemTotal:":
			total = value
		case "MemAvailable:":
			available = value
		case "MemFree:":
			free = value
		}
	}
	if err := scanner.Err(); err != nil {
		return 0, 0, err
	}
	if available == 0 {
		available = free
	}
	if total == 0 || total < available {
		return 0, 0, fmt.Errorf("invalid /proc/meminfo values")
	}
	return total - available, available, nil
}

func readDiskStats(path string) (uint64, uint64, error) {
	var stat syscall.Statfs_t
	if err := syscall.Statfs(path, &stat); err != nil {
		return 0, 0, err
	}
	blockSize := uint64(stat.Bsize)
	total := stat.Blocks * blockSize
	free := stat.Bavail * blockSize
	if total < free {
		return 0, 0, fmt.Errorf("invalid disk stats")
	}
	return total - free, free, nil
}

type networkStat struct {
	name    string
	rxBytes uint64
	txBytes uint64
}

func readNetworkStats() []networkStat {
	file, err := os.Open("/proc/net/dev")
	if err != nil {
		return nil
	}
	defer file.Close()

	stats := []networkStat{}
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if !strings.Contains(line, ":") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 17 {
			continue
		}
		name := strings.TrimSuffix(fields[0], ":")
		rxBytes, rxErr := strconv.ParseUint(fields[1], 10, 64)
		txBytes, txErr := strconv.ParseUint(fields[9], 10, 64)
		if rxErr != nil || txErr != nil {
			continue
		}
		stats = append(stats, networkStat{name: name, rxBytes: rxBytes, txBytes: txBytes})
	}
	sort.Slice(stats, func(i, j int) bool {
		return stats[i].name < stats[j].name
	})
	return stats
}

func sanitizeMetricName(name string) string {
	var b strings.Builder
	for _, r := range name {
		switch {
		case r >= 'a' && r <= 'z':
			b.WriteRune(r)
		case r >= 'A' && r <= 'Z':
			b.WriteRune(r + ('a' - 'A'))
		case r >= '0' && r <= '9':
			b.WriteRune(r)
		default:
			b.WriteByte('_')
		}
	}
	if b.Len() == 0 {
		return "unknown"
	}
	return b.String()
}

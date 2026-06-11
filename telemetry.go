// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"bufio"
	"os"
	"strconv"
	"strings"
	"syscall"
)

func readCPUTemperature() (float64, bool) {
	for _, path := range []string{
		"/sys/class/thermal/thermal_zone0/temp",
		"/sys/class/thermal/thermal_zone1/temp",
	} {
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		temp, err := strconv.ParseFloat(strings.TrimSpace(string(data)), 64)
		if err != nil {
			continue
		}
		return temp / 1000.0, true
	}
	return 0, false
}

func readMemoryStats() (total, free, available uint64, ok bool) {
	f, err := os.Open("/proc/meminfo")
	if err != nil {
		return 0, 0, 0, false
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		switch {
		case strings.HasPrefix(line, "MemTotal:"):
			total = parseMemInfoValue(line)
		case strings.HasPrefix(line, "MemFree:"):
			free = parseMemInfoValue(line)
		case strings.HasPrefix(line, "MemAvailable:"):
			available = parseMemInfoValue(line)
		}
	}
	if total == 0 {
		return 0, 0, 0, false
	}
	return total, free, available, true
}

func parseMemInfoValue(line string) uint64 {
	parts := strings.Fields(line)
	if len(parts) < 2 {
		return 0
	}
	val, err := strconv.ParseUint(parts[1], 10, 64)
	if err != nil {
		return 0
	}
	return val * 1024
}

func readLoadAverage() (load1, load5, load15 float64, ok bool) {
	data, err := os.ReadFile("/proc/loadavg")
	if err != nil {
		return 0, 0, 0, false
	}
	parts := strings.Fields(string(data))
	if len(parts) < 3 {
		return 0, 0, 0, false
	}
	l1, err1 := strconv.ParseFloat(parts[0], 64)
	l5, err5 := strconv.ParseFloat(parts[1], 64)
	l15, err15 := strconv.ParseFloat(parts[2], 64)
	if err1 != nil || err5 != nil || err15 != nil {
		return 0, 0, 0, false
	}
	return l1, l5, l15, true
}

func defaultInterface() (string, bool) {
	data, err := os.ReadFile("/proc/net/route")
	if err != nil {
		return "", false
	}
	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	for scanner.Scan() {
		line := scanner.Text()
		parts := strings.Fields(line)
		if len(parts) < 2 {
			continue
		}
		if parts[1] == "00000000" {
			return parts[0], true
		}
	}
	return "", false
}

func readInterfaceRSSI() (rssi float64, ok bool) {
	iface, found := defaultInterface()
	if !found {
		return 0, false
	}

	operstate, err := os.ReadFile("/sys/class/net/" + iface + "/operstate")
	if err != nil || strings.TrimSpace(string(operstate)) != "up" {
		return 0, false
	}

	data, err := os.ReadFile("/proc/net/wireless")
	if err != nil {
		return 0, false
	}
	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	for scanner.Scan() {
		line := scanner.Text()
		if !strings.HasPrefix(line, iface) {
			continue
		}
		parts := strings.Fields(line)
		if len(parts) < 4 {
			continue
		}
		link := strings.TrimRight(parts[2], ".")
		rssi, err := strconv.ParseFloat(link, 64)
		if err != nil {
			continue
		}
		return rssi, true
	}
	return 0, false
}

func readDiskUsagePercent() (float64, bool) {
	var stat syscall.Statfs_t
	if err := syscall.Statfs("/", &stat); err != nil {
		return 0, false
	}
	total := stat.Blocks * uint64(stat.Bsize)
	free := stat.Bfree * uint64(stat.Bsize)
	if total == 0 {
		return 0, false
	}
	used := total - free
	return float64(used) / float64(total) * 100, true
}

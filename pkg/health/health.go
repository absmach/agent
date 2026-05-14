// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

package health

import (
	"bufio"
	"os"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// Metrics holds a point-in-time snapshot of gateway health.
type Metrics struct {
	Timestamp    time.Time `json:"timestamp"`
	Uptime       float64   `json:"uptime_seconds"`
	CPUUsage     float64   `json:"cpu_usage_percent"`
	MemAvailable uint64    `json:"mem_available_bytes"`
	DiskFree     uint64    `json:"disk_free_bytes"`
	NetRxBytes   uint64    `json:"net_rx_bytes"`
	NetTxBytes   uint64    `json:"net_tx_bytes"`
	Goroutines   int       `json:"goroutines"`
	Version      string    `json:"version"`
}

type cpuSample struct {
	total uint64
	idle  uint64
}

type netSample struct {
	rx uint64
	tx uint64
}

// Collector samples system metrics and computes deltas between calls.
type Collector struct {
	startTime time.Time
	prevCPU   cpuSample
	prevNet   netSample
	prevTime  time.Time
	version   string
}

// NewCollector initialises a Collector, priming the delta baseline.
func NewCollector(version string) *Collector {
	c := &Collector{
		startTime: time.Now(),
		prevTime:  time.Now(),
		version:   version,
	}
	c.prevCPU, _ = readCPU()
	c.prevNet, _ = readNet()
	return c
}

// Collect reads current system stats, computes deltas from the previous call,
// and returns a Metrics snapshot. It is safe to call concurrently.
func (c *Collector) Collect() Metrics {
	now := time.Now()

	cpu, _ := readCPU()
	net, _ := readNet()
	mem, _ := readMem()
	disk, _ := readDisk()

	var cpuPct float64
	if dTotal := cpu.total - c.prevCPU.total; dTotal > 0 {
		dIdle := cpu.idle - c.prevCPU.idle
		cpuPct = (1 - float64(dIdle)/float64(dTotal)) * 100
	}

	m := Metrics{
		Timestamp:    now,
		Uptime:       now.Sub(c.startTime).Seconds(),
		CPUUsage:     cpuPct,
		MemAvailable: mem,
		DiskFree:     disk,
		NetRxBytes:   net.rx - c.prevNet.rx,
		NetTxBytes:   net.tx - c.prevNet.tx,
		Goroutines:   runtime.NumGoroutine(),
		Version:      c.version,
	}

	c.prevCPU = cpu
	c.prevNet = net
	c.prevTime = now

	return m
}

// readCPU reads the aggregate CPU counters from /proc/stat.
func readCPU() (cpuSample, error) {
	f, err := os.Open("/proc/stat")
	if err != nil {
		return cpuSample{}, err
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		if !strings.HasPrefix(line, "cpu ") {
			continue
		}
		fields := strings.Fields(line)[1:] // skip "cpu" label
		var vals [10]uint64
		for i := 0; i < len(fields) && i < 10; i++ {
			vals[i], _ = strconv.ParseUint(fields[i], 10, 64)
		}
		// user nice system idle iowait irq softirq steal guest guest_nice
		idle := vals[3] + vals[4]
		total := vals[0] + vals[1] + vals[2] + vals[3] + vals[4] + vals[5] + vals[6] + vals[7]
		return cpuSample{total: total, idle: idle}, nil
	}
	return cpuSample{}, nil
}

// readMem returns MemAvailable in bytes from /proc/meminfo.
func readMem() (uint64, error) {
	f, err := os.Open("/proc/meminfo")
	if err != nil {
		return 0, err
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		if !strings.HasPrefix(line, "MemAvailable:") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			break
		}
		kb, err := strconv.ParseUint(fields[1], 10, 64)
		if err != nil {
			return 0, err
		}
		return kb * 1024, nil
	}
	return 0, nil
}

// readDisk returns free bytes on the root filesystem via Statfs.
func readDisk() (uint64, error) {
	var fs syscall.Statfs_t
	if err := syscall.Statfs("/", &fs); err != nil {
		return 0, err
	}
	return fs.Bavail * uint64(fs.Bsize), nil
}

// readNet sums rx/tx bytes across all non-loopback interfaces from /proc/net/dev.
func readNet() (netSample, error) {
	f, err := os.Open("/proc/net/dev")
	if err != nil {
		return netSample{}, err
	}
	defer f.Close()

	var sample netSample
	scanner := bufio.NewScanner(f)
	// Skip two header lines.
	scanner.Scan()
	scanner.Scan()
	for scanner.Scan() {
		line := scanner.Text()
		// Format: "  eth0: rx_bytes packets errs ... tx_bytes ..."
		colonIdx := strings.Index(line, ":")
		if colonIdx < 0 {
			continue
		}
		iface := strings.TrimSpace(line[:colonIdx])
		if iface == "lo" {
			continue
		}
		fields := strings.Fields(line[colonIdx+1:])
		if len(fields) < 9 {
			continue
		}
		rx, _ := strconv.ParseUint(fields[0], 10, 64)
		tx, _ := strconv.ParseUint(fields[8], 10, 64)
		sample.rx += rx
		sample.tx += tx
	}
	return sample, nil
}

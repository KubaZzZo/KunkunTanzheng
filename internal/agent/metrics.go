package agent

import (
	"bufio"
	"fmt"
	"math"
	"strconv"
	"strings"
	"time"
)

type CPUStats struct {
	User    uint64
	Nice    uint64
	System  uint64
	Idle    uint64
	IOWait  uint64
	IRQ     uint64
	SoftIRQ uint64
	Steal   uint64
}

func ParseCPUStat(content []byte) (CPUStats, error) {
	for _, line := range strings.Split(string(content), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 9 || fields[0] != "cpu" {
			continue
		}
		values := make([]uint64, 8)
		for i := range values {
			value, err := strconv.ParseUint(fields[i+1], 10, 64)
			if err != nil {
				return CPUStats{}, fmt.Errorf("parse CPU counter %q: %w", fields[i+1], err)
			}
			values[i] = value
		}
		return CPUStats{
			User: values[0], Nice: values[1], System: values[2], Idle: values[3],
			IOWait: values[4], IRQ: values[5], SoftIRQ: values[6], Steal: values[7],
		}, nil
	}
	return CPUStats{}, fmt.Errorf("CPU aggregate line not found")
}

func (s CPUStats) Total() uint64 {
	return s.User + s.Nice + s.System + s.Idle + s.IOWait + s.IRQ + s.SoftIRQ + s.Steal
}

func (s CPUStats) IdleTicks() uint64 {
	return s.Idle + s.IOWait
}

func CPUPercent(previous, current CPUStats) float64 {
	if current.User < previous.User || current.Nice < previous.Nice ||
		current.System < previous.System || current.Idle < previous.Idle ||
		current.IOWait < previous.IOWait || current.IRQ < previous.IRQ ||
		current.SoftIRQ < previous.SoftIRQ || current.Steal < previous.Steal {
		return 0
	}
	totalDelta := current.Total() - previous.Total()
	if totalDelta == 0 {
		return 0
	}
	idleDelta := current.IdleTicks() - previous.IdleTicks()
	if idleDelta > totalDelta {
		return 0
	}
	busy := totalDelta - idleDelta
	percent := 100 * float64(busy) / float64(totalDelta)
	if percent < 0 || math.IsNaN(percent) || math.IsInf(percent, 0) {
		return 0
	}
	if percent > 100 {
		return 100
	}
	return percent
}

type MemoryStats struct {
	TotalBytes     uint64
	AvailableBytes uint64
}

func ParseMemInfo(content []byte) (MemoryStats, error) {
	var stats MemoryStats
	seenTotal, seenAvailable := false, false
	scanner := bufio.NewScanner(strings.NewReader(string(content)))
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 2 {
			continue
		}
		key := strings.TrimSuffix(fields[0], ":")
		if key != "MemTotal" && key != "MemAvailable" {
			continue
		}
		value, err := parseMemoryValue(fields[1], fields[2:])
		if err != nil {
			return MemoryStats{}, fmt.Errorf("parse %s: %w", key, err)
		}
		if key == "MemTotal" {
			stats.TotalBytes, seenTotal = value, true
		} else {
			stats.AvailableBytes, seenAvailable = value, true
		}
	}
	if err := scanner.Err(); err != nil {
		return MemoryStats{}, fmt.Errorf("scan meminfo: %w", err)
	}
	if !seenTotal || !seenAvailable {
		return MemoryStats{}, fmt.Errorf("MemTotal and MemAvailable are required")
	}
	if stats.AvailableBytes > stats.TotalBytes {
		stats.AvailableBytes = stats.TotalBytes
	}
	return stats, nil
}

func parseMemoryValue(raw string, unit []string) (uint64, error) {
	value, err := strconv.ParseUint(raw, 10, 64)
	if err != nil {
		return 0, err
	}
	multiplier := uint64(1)
	if len(unit) > 0 {
		switch strings.ToLower(unit[0]) {
		case "kb":
			multiplier = 1024
		case "mb":
			multiplier = 1024 * 1024
		case "gb":
			multiplier = 1024 * 1024 * 1024
		case "b":
		default:
			return 0, fmt.Errorf("unsupported unit %q", unit[0])
		}
	}
	if value > ^uint64(0)/multiplier {
		return 0, fmt.Errorf("value overflows uint64")
	}
	return value * multiplier, nil
}

func (s MemoryStats) UsedBytes() uint64 {
	if s.AvailableBytes >= s.TotalBytes {
		return 0
	}
	return s.TotalBytes - s.AvailableBytes
}

func ParseLoad1(content []byte) (float64, error) {
	fields := strings.Fields(string(content))
	if len(fields) == 0 {
		return 0, fmt.Errorf("load average is empty")
	}
	load, err := strconv.ParseFloat(fields[0], 64)
	if err != nil || math.IsNaN(load) || math.IsInf(load, 0) || load < 0 {
		if err == nil {
			err = fmt.Errorf("load must be finite and non-negative")
		}
		return 0, fmt.Errorf("parse load1: %w", err)
	}
	return load, nil
}

type NetCounters struct {
	ReceiveBytes  uint64
	TransmitBytes uint64
}

func ParseNetDev(content []byte) (NetCounters, error) {
	var counters NetCounters
	sawInterface := false
	for _, line := range strings.Split(string(content), "\n") {
		colon := strings.IndexByte(line, ':')
		if colon < 0 {
			continue
		}
		name := strings.TrimSpace(line[:colon])
		if name == "" || name == "lo" {
			continue
		}
		fields := strings.Fields(line[colon+1:])
		if len(fields) < 9 {
			return NetCounters{}, fmt.Errorf("interface %q has incomplete counters", name)
		}
		receive, err := strconv.ParseUint(fields[0], 10, 64)
		if err != nil {
			return NetCounters{}, fmt.Errorf("parse receive counter for %q: %w", name, err)
		}
		transmit, err := strconv.ParseUint(fields[8], 10, 64)
		if err != nil {
			return NetCounters{}, fmt.Errorf("parse transmit counter for %q: %w", name, err)
		}
		counters.ReceiveBytes += receive
		counters.TransmitBytes += transmit
		sawInterface = true
	}
	if !sawInterface {
		return NetCounters{}, fmt.Errorf("no network interface counters found")
	}
	return counters, nil
}

func CounterRate(previous, current uint64, elapsed time.Duration) float64 {
	if elapsed <= 0 || current < previous {
		return 0
	}
	return float64(current-previous) / elapsed.Seconds()
}

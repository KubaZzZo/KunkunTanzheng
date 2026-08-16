package agent

import (
	"strings"
	"testing"
	"time"
)

func TestParseCPUStat(t *testing.T) {
	stats, err := ParseCPUStat([]byte("cpu  100 20 30 400 50 6 7 8 0 0\n"))
	if err != nil {
		t.Fatalf("ParseCPUStat() error = %v", err)
	}
	if stats.Total() != 621 || stats.IdleTicks() != 450 {
		t.Fatalf("CPU stats total/idle = %d/%d, want 621/450", stats.Total(), stats.IdleTicks())
	}
}

func TestCPUPercentUsesAdjacentSamples(t *testing.T) {
	previous := CPUStats{User: 100, Nice: 0, System: 50, Idle: 400, IOWait: 50}
	current := CPUStats{User: 115, Nice: 0, System: 55, Idle: 425, IOWait: 55}

	if got := CPUPercent(previous, current); got != 40 {
		t.Fatalf("CPUPercent() = %v, want 40", got)
	}
}

func TestCPUPercentReturnsZeroAfterCounterReset(t *testing.T) {
	previous := CPUStats{User: 100, System: 50, Idle: 400}
	current := CPUStats{User: 2, System: 1, Idle: 5}

	if got := CPUPercent(previous, current); got != 0 {
		t.Fatalf("CPUPercent() = %v, want 0 after reset", got)
	}
}

func TestParseMemoryAndLoad(t *testing.T) {
	mem, err := ParseMemInfo([]byte("MemTotal:       4096 kB\nMemAvailable:   1024 kB\n"))
	if err != nil {
		t.Fatalf("ParseMemInfo() error = %v", err)
	}
	if got := mem.UsedBytes(); got != 3*1024*1024 {
		t.Fatalf("UsedBytes() = %d, want %d", got, 3*1024*1024)
	}

	load, err := ParseLoad1([]byte("1.25 0.50 0.25 1/100 12345\n"))
	if err != nil {
		t.Fatalf("ParseLoad1() error = %v", err)
	}
	if load != 1.25 {
		t.Fatalf("ParseLoad1() = %v, want 1.25", load)
	}
}

func TestParseNetDevAndCounterRate(t *testing.T) {
	content := strings.Join([]string{
		"Inter-|   Receive                                                |  Transmit",
		" face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed",
		"  lo: 100 1 0 0 0 0 0 0 200 1 0 0 0 0 0 0 0",
		"eth0: 300 1 0 0 0 0 0 0 500 1 0 0 0 0 0 0 0",
		"docker0: 700 1 0 0 0 0 0 0 900 1 0 0 0 0 0 0 0",
		"veth1234: 1100 1 0 0 0 0 0 0 1300 1 0 0 0 0 0 0 0",
		"br-abcdef: 1500 1 0 0 0 0 0 0 1700 1 0 0 0 0 0 0 0",
	}, "\n")
	counters, err := ParseNetDev([]byte(content))
	if err != nil {
		t.Fatalf("ParseNetDev() error = %v", err)
	}
	if counters.ReceiveBytes != 300 || counters.TransmitBytes != 500 {
		t.Fatalf("network counters = %#v, want eth0 only", counters)
	}

	rate := CounterRate(100, 160, 30*time.Second)
	if rate != 2 {
		t.Fatalf("CounterRate() = %v, want 2", rate)
	}
	if got := CounterRate(160, 10, 30*time.Second); got != 0 {
		t.Fatalf("CounterRate() after reset = %v, want 0", got)
	}
}

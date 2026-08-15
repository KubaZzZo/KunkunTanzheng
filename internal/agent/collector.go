package agent

import (
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/kunkuntanzheng/server-probe/internal/probe"
)

type FileReader func(string) ([]byte, error)
type DiskUsageReader func(string) (uint64, error)

type Collector struct {
	readFile FileReader
	rootDisk DiskUsageReader

	mu       sync.Mutex
	previous *counterSample
}

type counterSample struct {
	at  time.Time
	cpu CPUStats
	net NetCounters
}

func NewCollector(readFile FileReader, rootDisk DiskUsageReader) *Collector {
	if readFile == nil {
		readFile = os.ReadFile
	}
	if rootDisk == nil {
		rootDisk = RootFilesystemUsedBytes
	}
	return &Collector{readFile: readFile, rootDisk: rootDisk}
}

func (c *Collector) Sample(nodeID string) (probe.Report, error) {
	return c.SampleAt(nodeID, time.Now().UTC())
}

func (c *Collector) SampleAt(nodeID string, sampledAt time.Time) (probe.Report, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	cpuContent, err := c.readFile("/proc/stat")
	if err != nil {
		return probe.Report{}, fmt.Errorf("read /proc/stat: %w", err)
	}
	cpu, err := ParseCPUStat(cpuContent)
	if err != nil {
		return probe.Report{}, err
	}
	memContent, err := c.readFile("/proc/meminfo")
	if err != nil {
		return probe.Report{}, fmt.Errorf("read /proc/meminfo: %w", err)
	}
	memory, err := ParseMemInfo(memContent)
	if err != nil {
		return probe.Report{}, err
	}
	loadContent, err := c.readFile("/proc/loadavg")
	if err != nil {
		return probe.Report{}, fmt.Errorf("read /proc/loadavg: %w", err)
	}
	load1, err := ParseLoad1(loadContent)
	if err != nil {
		return probe.Report{}, err
	}
	netContent, err := c.readFile("/proc/net/dev")
	if err != nil {
		return probe.Report{}, fmt.Errorf("read /proc/net/dev: %w", err)
	}
	net, err := ParseNetDev(netContent)
	if err != nil {
		return probe.Report{}, err
	}
	diskUsed, err := c.rootDisk("/")
	if err != nil {
		return probe.Report{}, fmt.Errorf("read root filesystem usage: %w", err)
	}

	report := probe.Report{
		NodeID:                  nodeID,
		MemoryUsedBytes:         memory.UsedBytes(),
		RootFilesystemUsedBytes: diskUsed,
		Load1:                   load1,
	}
	if c.previous != nil {
		report.CPUPercent = CPUPercent(c.previous.cpu, cpu)
		elapsed := sampledAt.Sub(c.previous.at)
		report.IngressBytesPerSecond = CounterRate(c.previous.net.ReceiveBytes, net.ReceiveBytes, elapsed)
		report.EgressBytesPerSecond = CounterRate(c.previous.net.TransmitBytes, net.TransmitBytes, elapsed)
	}
	if err := report.Validate(); err != nil {
		return probe.Report{}, fmt.Errorf("validate collected report: %w", err)
	}
	c.previous = &counterSample{at: sampledAt, cpu: cpu, net: net}
	return report, nil
}

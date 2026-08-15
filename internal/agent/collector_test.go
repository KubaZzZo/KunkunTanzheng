package agent

import (
	"errors"
	"testing"
	"time"
)

func TestCollectorUsesAdjacentSamplesAndRootDiskUsage(t *testing.T) {
	files := map[string][]byte{
		"/proc/stat":    []byte("cpu 100 0 50 400 50 0 0 0\n"),
		"/proc/meminfo": []byte("MemTotal: 4096 kB\nMemAvailable: 1024 kB\n"),
		"/proc/loadavg": []byte("1.25 0.50 0.25 1/100 123\n"),
		"/proc/net/dev": []byte("eth0: 100 0 0 0 0 0 0 0 200 0 0 0 0 0 0 0 0\n"),
	}
	now := time.Date(2026, 8, 15, 0, 0, 0, 0, time.UTC)
	collector := NewCollector(func(path string) ([]byte, error) {
		value, ok := files[path]
		if !ok {
			return nil, errors.New("missing fixture")
		}
		return value, nil
	}, func(string) (uint64, error) { return 7 * 1024 * 1024, nil })

	first, err := collector.SampleAt("node-01", now)
	if err != nil {
		t.Fatalf("first SampleAt() error = %v", err)
	}
	if first.CPUPercent != 0 || first.IngressBytesPerSecond != 0 || first.EgressBytesPerSecond != 0 {
		t.Fatalf("first sample rates = %#v, want zeros", first)
	}
	if first.MemoryUsedBytes != 3*1024*1024 || first.RootFilesystemUsedBytes != 7*1024*1024 {
		t.Fatalf("first sample memory/disk = %d/%d", first.MemoryUsedBytes, first.RootFilesystemUsedBytes)
	}

	files["/proc/stat"] = []byte("cpu 110 0 60 430 50 0 0 0\n")
	files["/proc/net/dev"] = []byte("eth0: 160 0 0 0 0 0 0 0 320 0 0 0 0 0 0 0 0\n")
	second, err := collector.SampleAt("node-01", now.Add(30*time.Second))
	if err != nil {
		t.Fatalf("second SampleAt() error = %v", err)
	}
	if second.CPUPercent != 40 {
		t.Fatalf("second CPUPercent = %v, want 40", second.CPUPercent)
	}
	if second.IngressBytesPerSecond != 2 || second.EgressBytesPerSecond != 4 {
		t.Fatalf("second network rates = %v/%v, want 2/4", second.IngressBytesPerSecond, second.EgressBytesPerSecond)
	}
}

package probe

import (
	"encoding/json"
	"fmt"
	"math"
	"strings"
	"time"
)

const MaxReportJSONBytes = 8 * 1024

type Report struct {
	NodeID                  string  `json:"node_id"`
	CPUPercent              float64 `json:"cpu_percent"`
	MemoryUsedBytes         uint64  `json:"memory_used_bytes"`
	RootFilesystemUsedBytes uint64  `json:"root_filesystem_used_bytes"`
	Load1                   float64 `json:"load1"`
	IngressBytesPerSecond   float64 `json:"ingress_bytes_per_second"`
	EgressBytesPerSecond    float64 `json:"egress_bytes_per_second"`
}

func ParseReportJSON(payload []byte) (Report, error) {
	if len(payload) > MaxReportJSONBytes {
		return Report{}, fmt.Errorf("report JSON exceeds %d bytes", MaxReportJSONBytes)
	}

	var report Report
	if err := json.Unmarshal(payload, &report); err != nil {
		return Report{}, fmt.Errorf("unmarshal report JSON: %w", err)
	}
	if err := report.Validate(); err != nil {
		return Report{}, err
	}
	return report, nil
}

func (r Report) Validate() error {
	if strings.TrimSpace(r.NodeID) == "" {
		return fmt.Errorf("node ID is required")
	}
	if !finiteNonNegative(r.CPUPercent) {
		return fmt.Errorf("CPU percentage must be finite and non-negative")
	}
	if r.CPUPercent > 100 {
		return fmt.Errorf("CPU percentage must not exceed 100")
	}
	if !finiteNonNegative(r.Load1) {
		return fmt.Errorf("load1 must be finite and non-negative")
	}
	if !finiteNonNegative(r.IngressBytesPerSecond) {
		return fmt.Errorf("ingress bytes per second must be finite and non-negative")
	}
	if !finiteNonNegative(r.EgressBytesPerSecond) {
		return fmt.Errorf("egress bytes per second must be finite and non-negative")
	}

	payload, err := json.Marshal(r)
	if err != nil {
		return fmt.Errorf("marshal report: %w", err)
	}
	if len(payload) > MaxReportJSONBytes {
		return fmt.Errorf("report JSON exceeds %d bytes", MaxReportJSONBytes)
	}

	return nil
}

func finiteNonNegative(value float64) bool {
	return !math.IsNaN(value) && !math.IsInf(value, 0) && value >= 0
}

type NodeState string

const (
	StatePending NodeState = "pending"
	StateOnline  NodeState = "online"
	StateDelayed NodeState = "delayed"
	StateOffline NodeState = "offline"
)

func NodeStateAt(lastValidReport *time.Time, serverReceiveTime time.Time, certificateRevoked bool) NodeState {
	if certificateRevoked {
		return StateOffline
	}
	if lastValidReport == nil {
		return StatePending
	}

	age := serverReceiveTime.Sub(*lastValidReport)
	if age <= 90*time.Second {
		return StateOnline
	}
	if age <= 180*time.Second {
		return StateDelayed
	}
	return StateOffline
}

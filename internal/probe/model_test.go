package probe

import (
	"encoding/json"
	"math"
	"strings"
	"testing"
	"time"
)

func validReport() Report {
	return Report{
		NodeID:                  "node-01",
		CPUPercent:              42.5,
		MemoryUsedBytes:         1_073_741_824,
		RootFilesystemUsedBytes: 10_737_418_240,
		Load1:                   1.25,
		IngressBytesPerSecond:   256.5,
		EgressBytesPerSecond:    128.25,
	}
}

func TestReportValidateAcceptsValidBoundedReport(t *testing.T) {
	report := validReport()

	if err := report.Validate(); err != nil {
		t.Fatalf("Validate() error = %v", err)
	}
}

func TestReportValidateRejectsInvalidReports(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*Report)
	}{
		{
			name: "missing node ID",
			mutate: func(report *Report) {
				report.NodeID = ""
			},
		},
		{
			name: "whitespace node ID",
			mutate: func(report *Report) {
				report.NodeID = " \t"
			},
		},
		{
			name: "negative CPU percentage",
			mutate: func(report *Report) {
				report.CPUPercent = -0.1
			},
		},
		{
			name: "CPU percentage above 100",
			mutate: func(report *Report) {
				report.CPUPercent = 100.1
			},
		},
		{
			name: "non-finite CPU percentage",
			mutate: func(report *Report) {
				report.CPUPercent = math.Inf(1)
			},
		},
		{
			name: "negative load",
			mutate: func(report *Report) {
				report.Load1 = -1
			},
		},
		{
			name: "non-finite ingress rate",
			mutate: func(report *Report) {
				report.IngressBytesPerSecond = math.NaN()
			},
		},
		{
			name: "negative egress rate",
			mutate: func(report *Report) {
				report.EgressBytesPerSecond = -1
			},
		},
		{
			name: "oversized JSON payload",
			mutate: func(report *Report) {
				report.NodeID = strings.Repeat("a", MaxReportJSONBytes)
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			report := validReport()
			test.mutate(&report)

			if err := report.Validate(); err == nil {
				t.Fatal("Validate() error = nil, want error")
			}
		})
	}
}

func TestNodeStateBoundaries(t *testing.T) {
	now := time.Date(2026, 8, 15, 0, 0, 0, 0, time.UTC)
	tests := []struct {
		name       string
		lastReport *time.Time
		want       NodeState
	}{
		{
			name: "pending without a valid report",
			want: StatePending,
		},
		{
			name:       "online at 90 seconds",
			lastReport: timePtr(now.Add(-90 * time.Second)),
			want:       StateOnline,
		},
		{
			name:       "delayed after 90 seconds",
			lastReport: timePtr(now.Add(-90*time.Second - time.Nanosecond)),
			want:       StateDelayed,
		},
		{
			name:       "delayed at 180 seconds",
			lastReport: timePtr(now.Add(-180 * time.Second)),
			want:       StateDelayed,
		},
		{
			name:       "offline after 180 seconds",
			lastReport: timePtr(now.Add(-180*time.Second - time.Nanosecond)),
			want:       StateOffline,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := NodeStateAt(test.lastReport, now, false); got != test.want {
				t.Fatalf("NodeStateAt() = %q, want %q", got, test.want)
			}
		})
	}
}

func TestNodeStateAtRevocationTakesPriority(t *testing.T) {
	now := time.Date(2026, 8, 15, 0, 0, 0, 0, time.UTC)
	receivedAt := now

	if got := NodeStateAt(&receivedAt, now, true); got != StateOffline {
		t.Fatalf("NodeStateAt() = %q, want %q", got, StateOffline)
	}
}

func TestReportJSONRoundTrip(t *testing.T) {
	want := validReport()

	encoded, err := json.Marshal(want)
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}

	var got Report
	if err := json.Unmarshal(encoded, &got); err != nil {
		t.Fatalf("json.Unmarshal() error = %v", err)
	}

	if got != want {
		t.Fatalf("JSON round-trip = %#v, want %#v", got, want)
	}
	if err := got.Validate(); err != nil {
		t.Fatalf("round-tripped report Validate() error = %v", err)
	}
}

func TestParseReportJSONReturnsValidatedReport(t *testing.T) {
	want := validReport()
	payload, err := json.Marshal(want)
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}

	got, err := ParseReportJSON(payload)
	if err != nil {
		t.Fatalf("ParseReportJSON() error = %v", err)
	}
	if got != want {
		t.Fatalf("ParseReportJSON() = %#v, want %#v", got, want)
	}
}

func TestParseReportJSONRejectsOversizedLeadingWhitespace(t *testing.T) {
	payload, err := json.Marshal(validReport())
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}
	payload = append([]byte(strings.Repeat(" ", MaxReportJSONBytes-len(payload)+1)), payload...)
	if !json.Valid(payload) {
		t.Fatal("test payload must be syntactically valid JSON")
	}

	if _, err := ParseReportJSON(payload); err == nil {
		t.Fatal("ParseReportJSON() error = nil, want error for oversized raw payload")
	}
}

func timePtr(value time.Time) *time.Time {
	return &value
}

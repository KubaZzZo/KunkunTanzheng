package server

import (
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"net/http"
	"strings"
	"time"
)

//go:embed templates/*.html static/app.css static/trend.js
var webAssets embed.FS

type MonitorHandler struct {
	store              *Store
	enrollment         EnrollmentService
	reportEndpoint     string
	enrollmentEndpoint string
	now                func() time.Time
	templates          *template.Template
}

type pageData struct {
	Title         string
	Nodes         []Node
	Node          Node
	Samples       []Sample
	TrendJSON     string
	Query         string
	StateFilter   string
	AgentCommand  string
	Error         string
	DisplayName   string
	TrafficIn24h  uint64
	TrafficOut24h uint64
}

func NewMonitorHandler(store *Store, enrollment EnrollmentService, reportEndpoint, enrollmentEndpoint string, now func() time.Time) *MonitorHandler {
	if now == nil {
		now = time.Now
	}
	handler := &MonitorHandler{
		store:              store,
		enrollment:         enrollment,
		reportEndpoint:     reportEndpoint,
		enrollmentEndpoint: enrollmentEndpoint,
		now:                now,
		templates: template.Must(template.New("web").Funcs(template.FuncMap{
			"formatBytes": formatBytes,
			"formatRate":  formatRate,
		}).ParseFS(webAssets, "templates/*.html")),
	}
	return handler
}

func formatBytes(value uint64) string {
	const base = 1024.0
	units := []string{"B", "KB", "MB", "GB", "TB"}
	number := float64(value)
	unit := 0
	for number >= base && unit < len(units)-1 {
		number /= base
		unit++
	}
	return fmt.Sprintf("%.2f %s", number, units[unit])
}

func formatRate(value float64) string {
	if value < 0 {
		value = 0
	}
	const base = 1024.0
	units := []string{"B/s", "KB/s", "MB/s", "GB/s", "TB/s"}
	unit := 0
	for value >= base && unit < len(units)-1 {
		value /= base
		unit++
	}
	return fmt.Sprintf("%.2f %s", value, units[unit])
}

func (h *MonitorHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/static/app.css" && r.Method == http.MethodGet {
		h.serveCSS(w)
		return
	}
	if r.URL.Path == "/static/trend.js" && r.Method == http.MethodGet {
		h.serveTrendScript(w)
		return
	}
	if r.URL.Path != "/" && r.URL.Path != "/nodes" && !strings.HasPrefix(r.URL.Path, "/nodes/") {
		http.NotFound(w, r)
		return
	}
	switch {
	case r.URL.Path == "/" && r.Method == http.MethodGet:
		h.dashboard(w, r)
	case r.URL.Path == "/nodes" && r.Method == http.MethodPost:
		h.createNode(w, r)
	case strings.HasPrefix(r.URL.Path, "/nodes/"):
		h.nodeRoute(w, r)
	default:
		http.NotFound(w, r)
	}
}

func (h *MonitorHandler) dashboard(w http.ResponseWriter, r *http.Request) {
	nodes, err := h.store.ListNodes(r.Context(), h.now().UTC())
	if err != nil {
		http.Error(w, "service unavailable", http.StatusServiceUnavailable)
		return
	}
	query := strings.TrimSpace(r.URL.Query().Get("q"))
	state := strings.TrimSpace(r.URL.Query().Get("state"))
	filtered := nodes[:0]
	for _, node := range nodes {
		if query != "" && !strings.Contains(strings.ToLower(node.DisplayName), strings.ToLower(query)) {
			continue
		}
		if state != "" && string(node.State) != state {
			continue
		}
		filtered = append(filtered, node)
	}
	h.render(w, http.StatusOK, "dashboard.html", pageData{Title: "服务器", Nodes: filtered, Query: query, StateFilter: state})
}

func (h *MonitorHandler) createNode(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}
	node, err := h.store.CreateNode(r.Context(), r.Form.Get("display_name"), h.now().UTC())
	if err != nil {
		h.render(w, http.StatusBadRequest, "dashboard.html", pageData{Title: "服务器", Error: "无法创建服务器。"})
		return
	}
	code, err := h.enrollment.CreateEnrollmentCode(r.Context(), node.ID)
	if err != nil {
		_ = h.store.RemoveNode(r.Context(), node.ID)
		http.Error(w, "service unavailable", http.StatusServiceUnavailable)
		return
	}
	command := fmt.Sprintf("PROBE_NODE_ID=%s PROBE_ENDPOINT=%s PROBE_ENROLL_ENDPOINT=%s PROBE_ENROLL_CODE=%s /usr/local/bin/probe-agent", shellQuote(node.ID), shellQuote(h.reportEndpoint), shellQuote(h.enrollmentEndpoint), shellQuote(code))
	h.render(w, http.StatusCreated, "enrollment.html", pageData{Title: "注册服务器", AgentCommand: command})
}

func (h *MonitorHandler) nodeRoute(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/nodes/")
	parts := strings.Split(path, "/")
	if len(parts) == 0 || parts[0] == "" || len(parts) > 2 {
		http.NotFound(w, r)
		return
	}
	nodeID := parts[0]
	if len(parts) == 1 {
		if r.Method != http.MethodGet {
			http.NotFound(w, r)
			return
		}
		h.nodeDetail(w, r, nodeID)
		return
	}
	if r.Method != http.MethodPost {
		http.NotFound(w, r)
		return
	}
	var err error
	switch parts[1] {
	case "disable":
		err = h.store.DisableNode(r.Context(), nodeID)
	case "remove":
		err = h.store.RemoveNode(r.Context(), nodeID)
	case "rename":
		h.renameNode(w, r, nodeID)
		return
	default:
		http.NotFound(w, r)
		return
	}
	if err != nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	if parts[1] == "remove" {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, "/nodes/"+nodeID, http.StatusSeeOther)
}

func (h *MonitorHandler) nodeDetail(w http.ResponseWriter, r *http.Request, nodeID string) {
	h.renderNodeDetail(w, r, nodeID, http.StatusOK, "", "")
}

func (h *MonitorHandler) renameNode(w http.ResponseWriter, r *http.Request, nodeID string) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}
	displayName := r.Form.Get("display_name")
	if err := h.store.RenameNode(r.Context(), nodeID, displayName); err != nil {
		if errors.Is(err, ErrNodeNotFound) {
			http.NotFound(w, r)
			return
		}
		h.renderNodeDetail(w, r, nodeID, http.StatusBadRequest, displayName, err.Error())
		return
	}
	http.Redirect(w, r, "/nodes/"+nodeID, http.StatusSeeOther)
}

func (h *MonitorHandler) renderNodeDetail(w http.ResponseWriter, r *http.Request, nodeID string, status int, displayName, message string) {
	node, err := h.store.Node(r.Context(), nodeID, h.now().UTC())
	if err != nil {
		http.NotFound(w, r)
		return
	}
	samples, err := h.store.SamplesSince(r.Context(), nodeID, h.now().UTC().Add(-24*time.Hour))
	if err != nil {
		http.Error(w, "service unavailable", http.StatusServiceUnavailable)
		return
	}
	trafficIn, trafficOut := trafficUsage(samples)
	if displayName == "" && message == "" {
		displayName = node.DisplayName
	}
	h.render(w, status, "node.html", pageData{Title: node.DisplayName, Node: node, TrendJSON: trendJSON(samples), Error: message, DisplayName: displayName, TrafficIn24h: trafficIn, TrafficOut24h: trafficOut})
}

func trafficUsage(samples []Sample) (uint64, uint64) {
	var inbound, outbound float64
	for index := 1; index < len(samples); index++ {
		seconds := samples[index].ReceivedAt.Sub(samples[index-1].ReceivedAt).Seconds()
		if seconds <= 0 {
			continue
		}
		inbound += samples[index].IngressBytesPerSecond * seconds
		outbound += samples[index].EgressBytesPerSecond * seconds
	}
	return uint64(inbound), uint64(outbound)
}

func (h *MonitorHandler) render(w http.ResponseWriter, status int, name string, data pageData) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	if err := h.templates.ExecuteTemplate(w, name, data); err != nil {
		return
	}
}

func (h *MonitorHandler) serveCSS(w http.ResponseWriter) {
	contents, err := webAssets.ReadFile("static/app.css")
	if err != nil {
		http.NotFound(w, nil)
		return
	}
	w.Header().Set("Content-Type", "text/css; charset=utf-8")
	_, _ = w.Write(contents)
}

func (h *MonitorHandler) serveTrendScript(w http.ResponseWriter) {
	contents, err := webAssets.ReadFile("static/trend.js")
	if err != nil {
		http.NotFound(w, nil)
		return
	}
	w.Header().Set("Content-Type", "text/javascript; charset=utf-8")
	_, _ = w.Write(contents)
}

type trendPoint struct {
	ReceivedAt int64   `json:"received_at"`
	CPU        float64 `json:"cpu"`
	Memory     uint64  `json:"memory"`
	Disk       uint64  `json:"disk"`
	Ingress    float64 `json:"ingress"`
	Egress     float64 `json:"egress"`
}

func trendJSON(samples []Sample) string {
	const maximumPoints = 144
	if len(samples) == 0 {
		return ""
	}
	stride := (len(samples) + maximumPoints - 1) / maximumPoints
	points := make([]trendPoint, 0, (len(samples)+stride-1)/stride)
	for index := stride - 1; index < len(samples); index += stride {
		sample := samples[index]
		points = append(points, trendPoint{
			ReceivedAt: sample.ReceivedAt.UnixMilli(),
			CPU:        sample.CPUPercent,
			Memory:     sample.MemoryUsedBytes,
			Disk:       sample.RootFilesystemUsedBytes,
			Ingress:    sample.IngressBytesPerSecond,
			Egress:     sample.EgressBytesPerSecond,
		})
	}
	if last := samples[len(samples)-1]; points[len(points)-1].ReceivedAt != last.ReceivedAt.UnixMilli() {
		points = append(points, trendPoint{
			ReceivedAt: last.ReceivedAt.UnixMilli(),
			CPU:        last.CPUPercent,
			Memory:     last.MemoryUsedBytes,
			Disk:       last.RootFilesystemUsedBytes,
			Ingress:    last.IngressBytesPerSecond,
			Egress:     last.EgressBytesPerSecond,
		})
	}
	encoded, err := json.Marshal(points)
	if err != nil {
		return ""
	}
	return string(encoded)
}

func shellQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "'\\''") + "'"
}

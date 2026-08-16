package server

import (
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"math"
	"math/big"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/kunkuntanzheng/server-probe/internal/probe"
)

const (
	clientCertificateHeader      = "X-Probe-Client-Certificate"
	clientCertificateSerialQuery = "probe_cert_serial"
)

type IngestService struct {
	Store         *Store
	CA            *CertificateAuthority
	Now           func() time.Time
	ReportLimiter *SlidingWindowLimiter
}

func (s IngestService) HandleReport(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.NotFound(w, r)
		return
	}
	now := s.now()
	nodeID, err := s.nodeForRequest(r, now)
	if err != nil {
		unauthorized(w)
		return
	}
	body := http.MaxBytesReader(w, r.Body, probe.MaxReportJSONBytes)
	payload, err := io.ReadAll(body)
	if err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			http.Error(w, "request too large", http.StatusRequestEntityTooLarge)
			return
		}
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}
	report, err := probe.ParseReportJSON(payload)
	if err != nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}
	if report.NodeID != nodeID {
		unauthorized(w)
		return
	}
	if s.ReportLimiter != nil {
		allowed, retryAfter := s.ReportLimiter.Allow(nodeID)
		if !allowed {
			seconds := int(math.Ceil(retryAfter.Seconds()))
			if seconds < 1 {
				seconds = 1
			}
			w.Header().Set("Retry-After", strconv.Itoa(seconds))
			http.Error(w, "rate limited", http.StatusTooManyRequests)
			return
		}
	}
	if s.Store == nil {
		http.Error(w, "service unavailable", http.StatusServiceUnavailable)
		return
	}
	if err := s.Store.RecordReport(r.Context(), report, now); err != nil {
		if errors.Is(err, ErrNodeDisabled) || errors.Is(err, ErrNodeNotFound) {
			unauthorized(w)
			return
		}
		http.Error(w, "service unavailable", http.StatusServiceUnavailable)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s IngestService) nodeForRequest(r *http.Request, now time.Time) (string, error) {
	nodeID, _, err := s.clientIdentity(r, now)
	return nodeID, err
}

func (s IngestService) clientIdentity(r *http.Request, now time.Time) (string, string, error) {
	if s.Store == nil || s.CA == nil {
		return "", "", fmt.Errorf("ingest service is not configured")
	}
	certificate, intermediates, err := requestClientCertificate(r)
	if err != nil {
		serialNumber := normalizeCertificateSerial(r.URL.Query().Get(clientCertificateSerialQuery))
		if serialNumber == "" {
			return "", "", err
		}
		nodeID, lookupErr := s.Store.NodeForCertificate(r.Context(), serialNumber, now)
		if lookupErr != nil {
			return "", "", lookupErr
		}
		return nodeID, serialNumber, nil
	}
	return s.nodeIdentityFromCertificate(r, now, certificate, intermediates)
}

func normalizeCertificateSerial(raw string) string {
	serial := strings.TrimSpace(raw)
	if serial == "" {
		return ""
	}
	if decimal, ok := new(big.Int).SetString(serial, 10); ok {
		return decimal.Text(16)
	}
	return serial
}

func (s IngestService) nodeIdentityFromCertificate(r *http.Request, now time.Time, certificate *x509.Certificate, intermediates *x509.CertPool) (string, string, error) {
	if certificate == nil {
		return "", "", fmt.Errorf("client certificate is missing")
	}
	roots := x509.NewCertPool()
	roots.AddCert(s.CA.Certificate())
	if _, err := certificate.Verify(x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediates,
		CurrentTime:   now,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}); err != nil {
		return "", "", fmt.Errorf("verify client certificate: %w", err)
	}
	serialNumber := certificate.SerialNumber.Text(16)
	nodeID, err := s.Store.NodeForCertificate(r.Context(), serialNumber, now)
	if err != nil {
		return "", "", err
	}
	if certificate.Subject.CommonName != nodeID {
		return "", "", fmt.Errorf("certificate subject does not match node")
	}
	return nodeID, serialNumber, nil
}

func requestClientCertificate(r *http.Request) (*x509.Certificate, *x509.CertPool, error) {
	if r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
		intermediates := x509.NewCertPool()
		for _, certificate := range r.TLS.PeerCertificates[1:] {
			intermediates.AddCert(certificate)
		}
		return r.TLS.PeerCertificates[0], intermediates, nil
	}
	encoded := r.Header.Get(clientCertificateHeader)
	if encoded == "" {
		return nil, nil, fmt.Errorf("client certificate is missing")
	}
	der, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, nil, fmt.Errorf("decode proxied client certificate: %w", err)
	}
	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, nil, fmt.Errorf("parse proxied client certificate: %w", err)
	}
	return certificate, x509.NewCertPool(), nil
}

func (s IngestService) now() time.Time {
	if s.Now == nil {
		return time.Now().UTC()
	}
	return s.Now().UTC()
}

func unauthorized(w http.ResponseWriter) {
	w.Header().Set("WWW-Authenticate", "TLSClientCert")
	http.Error(w, "unauthorized", http.StatusUnauthorized)
}

type SlidingWindowLimiter struct {
	mu     sync.Mutex
	limit  int
	window time.Duration
	now    func() time.Time
	events map[string][]time.Time
}

const maxSlidingWindowKeys = 4096

func NewSlidingWindowLimiter(limit int, window time.Duration, now func() time.Time) *SlidingWindowLimiter {
	if now == nil {
		now = time.Now
	}
	return &SlidingWindowLimiter{limit: limit, window: window, now: now, events: make(map[string][]time.Time)}
}

func (l *SlidingWindowLimiter) Allow(key string) (bool, time.Duration) {
	if l == nil || l.limit <= 0 || l.window <= 0 {
		return true, 0
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now().UTC()
	l.pruneExpiredLocked(now)
	if _, exists := l.events[key]; !exists && len(l.events) >= maxSlidingWindowKeys {
		l.evictOldestLocked()
	}
	events := l.recentEventsLocked(key, now)
	if len(events) >= l.limit {
		l.events[key] = events
		return false, events[0].Add(l.window).Sub(now)
	}
	events = append(events, now)
	l.events[key] = events
	return true, 0
}

func (l *SlidingWindowLimiter) Check(key string) (bool, time.Duration) {
	if l == nil || l.limit <= 0 || l.window <= 0 {
		return true, 0
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now().UTC()
	l.pruneExpiredLocked(now)
	events := l.recentEventsLocked(key, now)
	if len(events) >= l.limit {
		l.events[key] = events
		return false, events[0].Add(l.window).Sub(now)
	}
	l.events[key] = events
	return true, 0
}

func (l *SlidingWindowLimiter) recentEventsLocked(key string, now time.Time) []time.Time {
	cutoff := now.Add(-l.window)
	events := l.events[key]
	first := 0
	for first < len(events) && !events[first].After(cutoff) {
		first++
	}
	if first == len(events) {
		delete(l.events, key)
		return nil
	}
	events = events[first:]
	l.events[key] = events
	return events
}

func (l *SlidingWindowLimiter) pruneExpiredLocked(now time.Time) {
	cutoff := now.Add(-l.window)
	for key, events := range l.events {
		first := 0
		for first < len(events) && !events[first].After(cutoff) {
			first++
		}
		if first == len(events) {
			delete(l.events, key)
			continue
		}
		l.events[key] = events[first:]
	}
}

func (l *SlidingWindowLimiter) evictOldestLocked() {
	var oldestKey string
	var oldest time.Time
	for key, events := range l.events {
		if len(events) == 0 {
			delete(l.events, key)
			continue
		}
		if oldestKey == "" || events[0].Before(oldest) {
			oldestKey, oldest = key, events[0]
		}
	}
	if oldestKey != "" {
		delete(l.events, oldestKey)
	}
}

package agent

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/kunkuntanzheng/server-probe/internal/probe"
)

var (
	ErrAuthentication = errors.New("agent authentication failed")
	ErrRetryable      = errors.New("agent report request is retryable")
)

type RateLimitError struct {
	After time.Duration
}

func (e *RateLimitError) Error() string {
	return fmt.Sprintf("report rate limited; retry after %s", e.After)
}

func (e *RateLimitError) Unwrap() error { return ErrRetryable }

type HTTPError struct {
	StatusCode int
}

func (e *HTTPError) Error() string {
	return fmt.Sprintf("report request failed with HTTP %d", e.StatusCode)
}

func (e *HTTPError) Unwrap() error {
	if e.StatusCode >= 500 {
		return ErrRetryable
	}
	return nil
}

type Reporter struct {
	Client       *http.Client
	Endpoint     string
	Wait         func(context.Context, time.Duration) error
	BeforeReport func(context.Context) error
}

func (r *Reporter) Send(ctx context.Context, report probe.Report) error {
	if err := report.Validate(); err != nil {
		return fmt.Errorf("validate report: %w", err)
	}
	payload, err := json.Marshal(report)
	if err != nil {
		return fmt.Errorf("marshal report: %w", err)
	}
	if len(payload) > probe.MaxReportJSONBytes {
		return fmt.Errorf("report body exceeds %d bytes", probe.MaxReportJSONBytes)
	}
	parsed, err := url.Parse(r.Endpoint)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" {
		return fmt.Errorf("report endpoint must be an HTTPS URL")
	}

	request, err := http.NewRequestWithContext(ctx, http.MethodPost, r.Endpoint, bytes.NewReader(payload))
	if err != nil {
		return fmt.Errorf("create report request: %w", err)
	}
	request.Header.Set("Content-Type", "application/json")
	client := r.Client
	if client == nil {
		client = &http.Client{Timeout: 15 * time.Second}
	}
	response, err := client.Do(request)
	if err != nil {
		return fmt.Errorf("send report request: %w", err)
	}
	defer response.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 1024))

	switch {
	case response.StatusCode >= 200 && response.StatusCode < 300:
		return nil
	case response.StatusCode == http.StatusUnauthorized || response.StatusCode == http.StatusForbidden:
		return fmt.Errorf("%w: HTTP %d", ErrAuthentication, response.StatusCode)
	case response.StatusCode == http.StatusTooManyRequests:
		return &RateLimitError{After: retryAfter(response.Header.Get("Retry-After"))}
	default:
		return &HTTPError{StatusCode: response.StatusCode}
	}
}

func (r *Reporter) SendWithRetry(ctx context.Context, report probe.Report) error {
	wait := r.Wait
	if wait == nil {
		wait = waitContext
	}
	for attempt := 0; attempt < 7; attempt++ {
		err := r.Send(ctx, report)
		if err == nil || errors.Is(err, ErrAuthentication) {
			return err
		}
		if !errors.Is(err, ErrRetryable) || attempt == 6 {
			return err
		}
		delay := time.Duration(1<<attempt) * time.Second
		var rateLimit *RateLimitError
		if errors.As(err, &rateLimit) {
			delay = rateLimit.After
		}
		if err := wait(ctx, delay); err != nil {
			return err
		}
	}
	return nil
}

func (r *Reporter) Run(ctx context.Context, sample func() (probe.Report, error), interval time.Duration, logf func(error)) error {
	if interval <= 0 {
		interval = 30 * time.Second
	}
	if logf == nil {
		logf = func(error) {}
	}
	for {
		if r.BeforeReport != nil {
			if err := r.BeforeReport(ctx); err != nil {
				if errors.Is(err, ErrAuthentication) {
					return err
				}
				logf(err)
			}
		}
		report, err := sample()
		if err != nil {
			logf(err)
		} else if err := r.SendWithRetry(ctx, report); err != nil {
			if errors.Is(err, ErrAuthentication) {
				return err
			}
			logf(err)
		}
		timer := time.NewTimer(interval)
		select {
		case <-ctx.Done():
			if !timer.Stop() {
				<-timer.C
			}
			return ctx.Err()
		case <-timer.C:
		}
	}
}

func waitContext(ctx context.Context, delay time.Duration) error {
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func retryAfter(raw string) time.Duration {
	seconds, err := strconv.Atoi(strings.TrimSpace(raw))
	if err != nil || seconds < 0 || seconds > 3600 {
		return time.Second
	}
	return time.Duration(seconds) * time.Second
}

func NewMTLSClient(certFile, keyFile, caFile string) (*http.Client, error) {
	certificate, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("load client certificate: %w", err)
	}
	caPEM, err := os.ReadFile(caFile)
	if err != nil {
		return nil, fmt.Errorf("read CA certificate: %w", err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(caPEM) {
		return nil, fmt.Errorf("parse CA certificate")
	}
	transport := &http.Transport{TLSClientConfig: &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{certificate},
	}}
	return &http.Client{Transport: transport, Timeout: 15 * time.Second}, nil
}

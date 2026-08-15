package server

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestEnrollmentHandlerIssuesCertificateWithoutNodeData(t *testing.T) {
	ctx := context.Background()
	now := time.Now().UTC()
	store := openTestStore(t)
	node, err := store.CreateNode(ctx, "web-01", now)
	if err != nil {
		t.Fatalf("CreateNode() error = %v", err)
	}
	ca, err := LoadOrCreateCertificateAuthority(t.TempDir())
	if err != nil {
		t.Fatalf("LoadOrCreateCertificateAuthority() error = %v", err)
	}
	service := EnrollmentService{Store: store, CA: ca, Now: func() time.Time { return now }}
	code, err := service.CreateEnrollmentCode(ctx, node.ID)
	if err != nil {
		t.Fatalf("CreateEnrollmentCode() error = %v", err)
	}
	handler := EnrollmentHandler{Service: service, Limiter: NewSlidingWindowLimiter(5, 15*time.Minute, func() time.Time { return now })}
	payload, err := json.Marshal(map[string]string{"code": code, "csr_pem": string(newTestCSR(t))})
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}
	request := httptest.NewRequest(http.MethodPost, "/v1/enroll", bytes.NewReader(payload))
	request.RemoteAddr = "198.51.100.10:1234"
	response := httptest.NewRecorder()
	handler.HandleEnroll(response, request)
	if response.Code != http.StatusCreated {
		t.Fatalf("enrollment status = %d, want 201; body=%s", response.Code, response.Body.String())
	}
	var body map[string]any
	if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if _, ok := body["certificate_pem"]; !ok {
		t.Fatalf("response = %#v, missing certificate", body)
	}
	if _, ok := body["node_id"]; ok {
		t.Fatalf("response = %#v, must not reveal node data", body)
	}
}

func TestEnrollmentHandlerRateLimitsSourceIP(t *testing.T) {
	now := time.Now().UTC()
	handler := EnrollmentHandler{Limiter: NewSlidingWindowLimiter(1, time.Minute, func() time.Time { return now })}
	for i := 0; i < 2; i++ {
		request := httptest.NewRequest(http.MethodPost, "/v1/enroll", strings.NewReader(`{}`))
		request.RemoteAddr = "198.51.100.10:1234"
		response := httptest.NewRecorder()
		handler.HandleEnroll(response, request)
		if i == 0 && response.Code == http.StatusTooManyRequests {
			t.Fatal("first request unexpectedly limited")
		}
		if i == 1 && response.Code != http.StatusTooManyRequests {
			t.Fatalf("second request status = %d, want 429", response.Code)
		}
	}
}

func TestSourceIPUsesForwardedClientAddressFromProxy(t *testing.T) {
	request := httptest.NewRequest(http.MethodPost, "/v1/enroll", nil)
	request.RemoteAddr = "172.20.0.2:49001"
	request.Header.Set("X-Forwarded-For", "198.51.100.25, 172.20.0.2")
	if got := sourceIP(request); got != "198.51.100.25" {
		t.Fatalf("sourceIP() = %q, want forwarded client address", got)
	}
}

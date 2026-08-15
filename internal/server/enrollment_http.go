package server

import (
	"encoding/json"
	"errors"
	"io"
	"math"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"
)

const maxEnrollmentJSONBytes = 16 * 1024

type EnrollmentHandler struct {
	Service EnrollmentService
	Limiter *SlidingWindowLimiter
}

type enrollmentRequest struct {
	Code   string `json:"code"`
	CSRPEM string `json:"csr_pem"`
}

type enrollmentResponse struct {
	CertificatePEM string    `json:"certificate_pem"`
	CAPEM          string    `json:"ca_pem"`
	ExpiresAt      time.Time `json:"expires_at"`
}

func (h EnrollmentHandler) HandleEnroll(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.NotFound(w, r)
		return
	}
	if h.Limiter != nil {
		allowed, retryAfter := h.Limiter.Allow(sourceIP(r))
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
	body := http.MaxBytesReader(w, r.Body, maxEnrollmentJSONBytes)
	decoder := json.NewDecoder(body)
	decoder.DisallowUnknownFields()
	var request enrollmentRequest
	if err := decoder.Decode(&request); err != nil {
		http.Error(w, "invalid enrollment request", http.StatusBadRequest)
		return
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		http.Error(w, "invalid enrollment request", http.StatusBadRequest)
		return
	}
	if strings.TrimSpace(request.Code) == "" || strings.TrimSpace(request.CSRPEM) == "" {
		http.Error(w, "invalid enrollment request", http.StatusBadRequest)
		return
	}
	issued, err := h.Service.Enroll(r.Context(), request.Code, []byte(request.CSRPEM))
	if err != nil {
		switch {
		case errors.Is(err, ErrEnrollmentCodeInvalid), errors.Is(err, ErrEnrollmentCodeUsed), errors.Is(err, ErrEnrollmentCodeExpired), errors.Is(err, ErrNodeDisabled):
			http.Error(w, "enrollment rejected", http.StatusUnauthorized)
		default:
			http.Error(w, "invalid enrollment request", http.StatusBadRequest)
		}
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(enrollmentResponse{
		CertificatePEM: string(issued.CertificatePEM),
		CAPEM:          string(issued.CAPEM),
		ExpiresAt:      issued.NotAfter,
	})
}

func sourceIP(r *http.Request) string {
	for _, value := range strings.Split(r.Header.Get("X-Forwarded-For"), ",") {
		candidate := strings.TrimSpace(value)
		if net.ParseIP(candidate) != nil {
			return candidate
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err == nil && host != "" {
		return host
	}
	if strings.TrimSpace(r.RemoteAddr) != "" {
		return r.RemoteAddr
	}
	return "unknown"
}

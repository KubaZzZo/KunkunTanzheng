package server

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
)

type CertificateRenewalHandler struct {
	Ingest IngestService
	CA     *CertificateAuthority
}

type renewalRequest struct {
	CSRPEM string `json:"csr_pem"`
}

func (h CertificateRenewalHandler) HandleRenew(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.NotFound(w, r)
		return
	}
	now := h.Ingest.now()
	nodeID, err := h.Ingest.nodeForRequest(r, now)
	if err != nil {
		unauthorized(w)
		return
	}
	certificate, _, err := requestClientCertificate(r)
	if err != nil {
		unauthorized(w)
		return
	}
	body := http.MaxBytesReader(w, r.Body, maxEnrollmentJSONBytes)
	decoder := json.NewDecoder(body)
	decoder.DisallowUnknownFields()
	var request renewalRequest
	if err := decoder.Decode(&request); err != nil || strings.TrimSpace(request.CSRPEM) == "" {
		http.Error(w, "invalid renewal request", http.StatusBadRequest)
		return
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		http.Error(w, "invalid renewal request", http.StatusBadRequest)
		return
	}
	if h.CA == nil || h.Ingest.Store == nil {
		http.Error(w, "service unavailable", http.StatusServiceUnavailable)
		return
	}
	issued, err := h.CA.IssueClientCertificate(nodeID, []byte(request.CSRPEM), now)
	if err != nil {
		http.Error(w, "invalid renewal request", http.StatusBadRequest)
		return
	}
	if _, err := h.Ingest.Store.RenewCertificate(r.Context(), certificate.SerialNumber.Text(16), issued.SerialNumber, now, issued.NotAfter); err != nil {
		if errors.Is(err, ErrCertificateUnknown) || errors.Is(err, ErrCertificateRevoked) || errors.Is(err, ErrCertificateExpired) {
			unauthorized(w)
			return
		}
		http.Error(w, "service unavailable", http.StatusServiceUnavailable)
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

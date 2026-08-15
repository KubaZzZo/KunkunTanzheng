package server

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestCertificateRenewalRequiresActiveClientCertificate(t *testing.T) {
	fixture := newIngestFixture(t)
	handler := CertificateRenewalHandler{Ingest: fixture.ingest, CA: fixture.ingest.CA}
	payload, err := json.Marshal(map[string]string{"csr_pem": string(newTestCSR(t))})
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}
	request := httptest.NewRequest(http.MethodPost, "/v1/certificates/renew", bytes.NewReader(payload))
	request.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{fixture.certificate}}
	response := httptest.NewRecorder()
	handler.HandleRenew(response, request)
	if response.Code != http.StatusCreated {
		t.Fatalf("renewal status = %d, want 201; body=%s", response.Code, response.Body.String())
	}
	var body enrollmentResponse
	if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode renewal response: %v", err)
	}
	certificate := parseCertificatePEM(t, []byte(body.CertificatePEM))
	if certificate.SerialNumber.Cmp(fixture.certificate.SerialNumber) == 0 {
		t.Fatal("renewal reused existing certificate serial")
	}

	if err := fixture.store.DisableNode(request.Context(), fixture.node.ID); err != nil {
		t.Fatalf("DisableNode() error = %v", err)
	}
	response = httptest.NewRecorder()
	handler.HandleRenew(response, request)
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("revoked renewal status = %d, want 401", response.Code)
	}
}

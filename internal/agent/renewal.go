package agent

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"time"
)

const certificateRenewalWindow = 7 * 24 * time.Hour

type CertificateRenewer struct {
	Client          *http.Client
	Endpoint        string
	CertificatePath string
	KeyPath         string
	CAPath          string
	Now             func() time.Time
}

type renewalRequest struct {
	CSRPEM string `json:"csr_pem"`
}

func (r CertificateRenewer) RenewIfDue(ctx context.Context) (bool, error) {
	certificatePEM, err := os.ReadFile(r.CertificatePath)
	if err != nil {
		return false, fmt.Errorf("read current certificate: %w", err)
	}
	keyPEM, err := os.ReadFile(r.KeyPath)
	if err != nil {
		return false, fmt.Errorf("read current private key: %w", err)
	}
	caPEM, err := os.ReadFile(r.CAPath)
	if err != nil {
		return false, fmt.Errorf("read current CA certificate: %w", err)
	}
	certificate, privateKey, err := parseAgentCredential(certificatePEM, keyPEM)
	if err != nil {
		return false, err
	}
	now := r.now()
	if !now.Before(certificate.NotAfter) {
		return false, fmt.Errorf("%w: client certificate has expired", ErrAuthentication)
	}
	if certificate.NotAfter.After(now.Add(certificateRenewalWindow)) {
		return false, nil
	}
	parsed, err := url.Parse(r.Endpoint)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" {
		return false, fmt.Errorf("renewal endpoint must be an HTTPS URL")
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, privateKey)
	if err != nil {
		return false, fmt.Errorf("create renewal certificate request: %w", err)
	}
	payload, err := json.Marshal(renewalRequest{CSRPEM: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER}))})
	if err != nil {
		return false, fmt.Errorf("marshal renewal request: %w", err)
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, r.Endpoint, bytes.NewReader(payload))
	if err != nil {
		return false, fmt.Errorf("create renewal request: %w", err)
	}
	request.Header.Set("Content-Type", "application/json")
	client := r.Client
	if client == nil {
		client = &http.Client{Timeout: 15 * time.Second}
	}
	response, err := client.Do(request)
	if err != nil {
		return false, fmt.Errorf("send renewal request: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode == http.StatusUnauthorized || response.StatusCode == http.StatusForbidden {
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 1024))
		return false, fmt.Errorf("%w: HTTP %d", ErrAuthentication, response.StatusCode)
	}
	if response.StatusCode != http.StatusCreated {
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 1024))
		return false, fmt.Errorf("renewal endpoint rejected request with HTTP %d", response.StatusCode)
	}
	material, err := readEnrollmentResponse(response.Body)
	if err != nil {
		return false, err
	}
	if !sameCACertificate(caPEM, []byte(material.CAPEM)) {
		return false, fmt.Errorf("renewal response changed the certificate authority")
	}
	if err := verifyEnrollmentMaterial([]byte(material.CertificatePEM), caPEM, privateKey); err != nil {
		return false, err
	}
	if err := writeCredential(r.CertificatePath, []byte(material.CertificatePEM)); err != nil {
		return false, err
	}
	return true, nil
}

func (r CertificateRenewer) now() time.Time {
	if r.Now == nil {
		return time.Now().UTC()
	}
	return r.Now().UTC()
}

func parseAgentCredential(certificatePEM, keyPEM []byte) (*x509.Certificate, *ecdsa.PrivateKey, error) {
	certificateBlock, _ := pem.Decode(certificatePEM)
	if certificateBlock == nil {
		return nil, nil, fmt.Errorf("parse current certificate PEM")
	}
	certificate, err := x509.ParseCertificate(certificateBlock.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("parse current certificate: %w", err)
	}
	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil {
		return nil, nil, fmt.Errorf("parse current private key PEM")
	}
	privateKey, err := x509.ParseECPrivateKey(keyBlock.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("parse current private key: %w", err)
	}
	if _, err := tls.X509KeyPair(certificatePEM, keyPEM); err != nil {
		return nil, nil, err
	}
	return certificate, privateKey, nil
}

func sameCACertificate(left, right []byte) bool {
	leftBlock, _ := pem.Decode(left)
	rightBlock, _ := pem.Decode(right)
	return leftBlock != nil && rightBlock != nil && bytes.Equal(leftBlock.Bytes, rightBlock.Bytes)
}

func readEnrollmentResponse(body io.Reader) (enrollmentResponse, error) {
	bodyBytes, err := io.ReadAll(io.LimitReader(body, maxEnrollmentResponseBytes+1))
	if err != nil {
		return enrollmentResponse{}, fmt.Errorf("read enrollment response: %w", err)
	}
	if len(bodyBytes) > maxEnrollmentResponseBytes {
		return enrollmentResponse{}, fmt.Errorf("enrollment response exceeds %d bytes", maxEnrollmentResponseBytes)
	}
	var material enrollmentResponse
	decoder := json.NewDecoder(bytes.NewReader(bodyBytes))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&material); err != nil {
		return enrollmentResponse{}, fmt.Errorf("decode enrollment response: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return enrollmentResponse{}, fmt.Errorf("decode enrollment response: trailing JSON")
	}
	return material, nil
}

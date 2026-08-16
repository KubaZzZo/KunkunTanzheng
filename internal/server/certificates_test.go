package server

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"testing"
	"time"
)

func TestEnrollmentIssuesOneTimeNodeCertificate(t *testing.T) {
	ctx := context.Background()
	store := openTestStore(t)
	now := time.Date(2026, 8, 15, 0, 0, 0, 0, time.UTC)
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
	csr := newTestCSR(t)
	issued, err := service.Enroll(ctx, code, csr)
	if err != nil {
		t.Fatalf("Enroll() error = %v", err)
	}
	certificate := parseCertificatePEM(t, issued.CertificatePEM)
	if certificate.Subject.CommonName != node.ID {
		t.Fatalf("certificate common name = %q, want %q", certificate.Subject.CommonName, node.ID)
	}
	if certificate.NotAfter.Sub(now) != 30*24*time.Hour {
		t.Fatalf("certificate lifetime = %s, want 30 days", certificate.NotAfter.Sub(now))
	}
	if err := certificate.CheckSignatureFrom(ca.Certificate()); err != nil {
		t.Fatalf("certificate issuer verification error = %v", err)
	}
	if len(issued.CAPEM) == 0 {
		t.Fatal("Enroll() did not return CA certificate")
	}
	replayed, err := service.Enroll(ctx, code, csr)
	if err != nil {
		t.Fatalf("replayed Enroll() error = %v", err)
	}
	if string(replayed.CertificatePEM) != string(issued.CertificatePEM) {
		t.Fatal("replayed enrollment returned a different certificate")
	}

	nodeID, err := store.NodeForCertificate(ctx, certificate.SerialNumber.Text(16), now)
	if err != nil || nodeID != node.ID {
		t.Fatalf("NodeForCertificate() = %q, %v; want %q, nil", nodeID, err, node.ID)
	}
}

func TestEnrollmentRejectsExpiredCodeAndDisabledNodeCertificate(t *testing.T) {
	ctx := context.Background()
	store := openTestStore(t)
	now := time.Date(2026, 8, 15, 0, 0, 0, 0, time.UTC)
	node, err := store.CreateNode(ctx, "db-01", now)
	if err != nil {
		t.Fatalf("CreateNode() error = %v", err)
	}
	ca, err := LoadOrCreateCertificateAuthority(t.TempDir())
	if err != nil {
		t.Fatalf("LoadOrCreateCertificateAuthority() error = %v", err)
	}
	clock := now
	service := EnrollmentService{Store: store, CA: ca, Now: func() time.Time { return clock }}
	code, err := service.CreateEnrollmentCode(ctx, node.ID)
	if err != nil {
		t.Fatalf("CreateEnrollmentCode() error = %v", err)
	}
	clock = clock.Add(10*time.Minute + time.Second)
	if _, err := service.Enroll(ctx, code, newTestCSR(t)); !errors.Is(err, ErrEnrollmentCodeExpired) {
		t.Fatalf("expired Enroll() error = %v, want ErrEnrollmentCodeExpired", err)
	}

	clock = now
	validCode, err := service.CreateEnrollmentCode(ctx, node.ID)
	if err != nil {
		t.Fatalf("CreateEnrollmentCode(valid) error = %v", err)
	}
	issued, err := service.Enroll(ctx, validCode, newTestCSR(t))
	if err != nil {
		t.Fatalf("Enroll(valid) error = %v", err)
	}
	if err := store.DisableNode(ctx, node.ID); err != nil {
		t.Fatalf("DisableNode() error = %v", err)
	}
	certificate := parseCertificatePEM(t, issued.CertificatePEM)
	if _, err := store.NodeForCertificate(ctx, certificate.SerialNumber.Text(16), now); !errors.Is(err, ErrCertificateRevoked) {
		t.Fatalf("NodeForCertificate(disabled) error = %v, want ErrCertificateRevoked", err)
	}
}

func newTestCSR(t *testing.T) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}
	encoded, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, key)
	if err != nil {
		t.Fatalf("CreateCertificateRequest() error = %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: encoded})
}

func parseCertificatePEM(t *testing.T, encoded []byte) *x509.Certificate {
	t.Helper()
	block, _ := pem.Decode(encoded)
	if block == nil {
		t.Fatal("certificate PEM has no block")
	}
	certificate, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("ParseCertificate() error = %v", err)
	}
	return certificate
}

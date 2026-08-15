package agent

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/kunkuntanzheng/server-probe/internal/server"
)

func TestEnrollmentClientWritesVerifiedCredentials(t *testing.T) {
	ctx := context.Background()
	now := time.Now().UTC()
	store, err := server.Open(":memory:")
	if err != nil {
		t.Fatalf("server.Open() error = %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	node, err := store.CreateNode(ctx, "agent-node", now)
	if err != nil {
		t.Fatalf("CreateNode() error = %v", err)
	}
	ca, err := server.LoadOrCreateCertificateAuthority(t.TempDir())
	if err != nil {
		t.Fatalf("LoadOrCreateCertificateAuthority() error = %v", err)
	}
	service := server.EnrollmentService{Store: store, CA: ca, Now: func() time.Time { return now }}
	code, err := service.CreateEnrollmentCode(ctx, node.ID)
	if err != nil {
		t.Fatalf("CreateEnrollmentCode() error = %v", err)
	}
	serverHTTP := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		server.EnrollmentHandler{Service: service}.HandleEnroll(w, r)
	}))
	defer serverHTTP.Close()

	directory := filepath.Join(t.TempDir(), "credentials")
	client := EnrollmentClient{Client: serverHTTP.Client(), Endpoint: serverHTTP.URL}
	if err := client.Enroll(ctx, code, filepath.Join(directory, "client.crt"), filepath.Join(directory, "client.key"), filepath.Join(directory, "ca.crt")); err != nil {
		t.Fatalf("Enroll() error = %v", err)
	}
	for _, name := range []string{"client.crt", "client.key", "ca.crt"} {
		contents, err := os.ReadFile(filepath.Join(directory, name))
		if err != nil || len(contents) == 0 {
			t.Fatalf("credential %s: contents=%d, error=%v", name, len(contents), err)
		}
	}
	if runtime.GOOS != "windows" {
		info, err := os.Stat(filepath.Join(directory, "client.key"))
		if err != nil {
			t.Fatalf("Stat(client.key) error = %v", err)
		}
		if info.Mode().Perm()&0o077 != 0 {
			t.Fatalf("client key permissions = %o, want no group/other access", info.Mode().Perm())
		}
	}
}

func TestCertificateRenewerReplacesCertificateBeforeExpiry(t *testing.T) {
	ctx := context.Background()
	ca, err := server.LoadOrCreateCertificateAuthority(t.TempDir())
	if err != nil {
		t.Fatalf("LoadOrCreateCertificateAuthority() error = %v", err)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, key)
	if err != nil {
		t.Fatalf("CreateCertificateRequest() error = %v", err)
	}
	issued, err := ca.IssueClientCertificate("node-01", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csr}), time.Now().UTC())
	if err != nil {
		t.Fatalf("IssueClientCertificate() error = %v", err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("MarshalECPrivateKey() error = %v", err)
	}
	directory := t.TempDir()
	certificatePath := filepath.Join(directory, "client.crt")
	keyPath := filepath.Join(directory, "client.key")
	caPath := filepath.Join(directory, "ca.crt")
	if err := os.WriteFile(certificatePath, issued.CertificatePEM, 0o600); err != nil {
		t.Fatalf("WriteFile(certificate) error = %v", err)
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		t.Fatalf("WriteFile(key) error = %v", err)
	}
	if err := os.WriteFile(caPath, issued.CAPEM, 0o600); err != nil {
		t.Fatalf("WriteFile(CA) error = %v", err)
	}

	var renewals int
	serverHTTP := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		renewals++
		var request renewalRequest
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			t.Fatalf("decode renewal request: %v", err)
		}
		renewed, err := ca.IssueClientCertificate("node-01", []byte(request.CSRPEM), time.Now().UTC())
		if err != nil {
			t.Fatalf("IssueClientCertificate() error = %v", err)
		}
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(enrollmentResponse{CertificatePEM: string(renewed.CertificatePEM), CAPEM: string(renewed.CAPEM), ExpiresAt: renewed.NotAfter})
	}))
	defer serverHTTP.Close()

	renewer := CertificateRenewer{
		Client:          serverHTTP.Client(),
		Endpoint:        serverHTTP.URL,
		CertificatePath: certificatePath,
		KeyPath:         keyPath,
		CAPath:          caPath,
		Now:             func() time.Time { return issued.NotAfter.Add(-6 * 24 * time.Hour) },
	}
	renewed, err := renewer.RenewIfDue(ctx)
	if err != nil {
		t.Fatalf("RenewIfDue() error = %v", err)
	}
	if !renewed || renewals != 1 {
		t.Fatalf("renewed/requests = %t/%d, want true/1", renewed, renewals)
	}
	contents, err := os.ReadFile(certificatePath)
	if err != nil {
		t.Fatalf("ReadFile(replaced certificate) error = %v", err)
	}
	if bytes.Equal(contents, issued.CertificatePEM) {
		t.Fatal("RenewIfDue() did not replace the certificate")
	}
}

func TestCertificateRenewerStopsWhenCertificateIsExpired(t *testing.T) {
	directory := t.TempDir()
	certificatePath := filepath.Join(directory, "client.crt")
	keyPath := filepath.Join(directory, "client.key")
	caPath := filepath.Join(directory, "ca.crt")
	certificate, key, caPEM := renewalCredential(t)
	if err := os.WriteFile(certificatePath, certificate, 0o600); err != nil {
		t.Fatalf("WriteFile(certificate) error = %v", err)
	}
	if err := os.WriteFile(keyPath, key, 0o600); err != nil {
		t.Fatalf("WriteFile(key) error = %v", err)
	}
	if err := os.WriteFile(caPath, caPEM, 0o600); err != nil {
		t.Fatalf("WriteFile(CA) error = %v", err)
	}
	called := false
	client := &http.Client{Transport: roundTripper(func(*http.Request) (*http.Response, error) {
		called = true
		return nil, nil
	})}
	renewer := CertificateRenewer{
		Client: client, Endpoint: "https://ingest.example.test/v1/certificates/renew", CertificatePath: certificatePath, KeyPath: keyPath, CAPath: caPath,
		Now: func() time.Time { return time.Now().UTC().AddDate(0, 0, 31) },
	}
	_, err := renewer.RenewIfDue(context.Background())
	if !errors.Is(err, ErrAuthentication) {
		t.Fatalf("RenewIfDue() error = %v, want ErrAuthentication", err)
	}
	if called {
		t.Fatal("RenewIfDue() made a request with an expired certificate")
	}
}

func renewalCredential(t *testing.T) ([]byte, []byte, []byte) {
	t.Helper()
	ca, err := server.LoadOrCreateCertificateAuthority(t.TempDir())
	if err != nil {
		t.Fatalf("LoadOrCreateCertificateAuthority() error = %v", err)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, key)
	if err != nil {
		t.Fatalf("CreateCertificateRequest() error = %v", err)
	}
	issued, err := ca.IssueClientCertificate("node-01", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csr}), time.Now().UTC())
	if err != nil {
		t.Fatalf("IssueClientCertificate() error = %v", err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("MarshalECPrivateKey() error = %v", err)
	}
	return issued.CertificatePEM, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), issued.CAPEM
}

type roundTripper func(*http.Request) (*http.Response, error)

func (fn roundTripper) RoundTrip(request *http.Request) (*http.Response, error) { return fn(request) }

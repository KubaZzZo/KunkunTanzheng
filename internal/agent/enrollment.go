package agent

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
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
	"path/filepath"
	"strings"
	"time"
)

const maxEnrollmentResponseBytes = 32 * 1024

type EnrollmentClient struct {
	Client   *http.Client
	Endpoint string
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

func (c EnrollmentClient) Enroll(ctx context.Context, code, certificatePath, keyPath, caPath string) error {
	if strings.TrimSpace(code) == "" {
		return fmt.Errorf("enrollment code is required")
	}
	parsed, err := url.Parse(c.Endpoint)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" {
		return fmt.Errorf("enrollment endpoint must be an HTTPS URL")
	}
	if err := secureDirectory(filepath.Dir(keyPath)); err != nil {
		return err
	}
	privateKey, err := loadOrCreatePrivateKey(keyPath)
	if err != nil {
		return err
	}
	requestDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, privateKey)
	if err != nil {
		return fmt.Errorf("create certificate request: %w", err)
	}
	payload, err := json.Marshal(enrollmentRequest{Code: code, CSRPEM: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: requestDER}))})
	if err != nil {
		return fmt.Errorf("marshal enrollment request: %w", err)
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, c.Endpoint, bytes.NewReader(payload))
	if err != nil {
		return fmt.Errorf("create enrollment request: %w", err)
	}
	request.Header.Set("Content-Type", "application/json")
	client := c.Client
	if client == nil {
		client = &http.Client{Timeout: 15 * time.Second}
	}
	response, err := client.Do(request)
	if err != nil {
		return fmt.Errorf("send enrollment request: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusCreated {
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 1024))
		return fmt.Errorf("enrollment endpoint rejected request")
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, maxEnrollmentResponseBytes+1))
	if err != nil {
		return fmt.Errorf("read enrollment response: %w", err)
	}
	if len(body) > maxEnrollmentResponseBytes {
		return fmt.Errorf("enrollment response exceeds %d bytes", maxEnrollmentResponseBytes)
	}
	var material enrollmentResponse
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&material); err != nil {
		return fmt.Errorf("decode enrollment response: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return fmt.Errorf("decode enrollment response: trailing JSON")
	}
	if err := verifyEnrollmentMaterial([]byte(material.CertificatePEM), []byte(material.CAPEM), privateKey); err != nil {
		return err
	}
	keyDER, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		return fmt.Errorf("marshal agent private key: %w", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	for _, path := range []string{certificatePath, keyPath, caPath} {
		if err := secureDirectory(filepath.Dir(path)); err != nil {
			return err
		}
	}
	if err := writeCredential(keyPath, keyPEM); err != nil {
		return err
	}
	if err := writeCredential(certificatePath, []byte(material.CertificatePEM)); err != nil {
		return err
	}
	if err := writeCredential(caPath, []byte(material.CAPEM)); err != nil {
		return err
	}
	return nil
}

func loadOrCreatePrivateKey(path string) (*ecdsa.PrivateKey, error) {
	if contents, err := os.ReadFile(path); err == nil {
		block, _ := pem.Decode(contents)
		if block == nil {
			return nil, fmt.Errorf("parse existing agent private key PEM")
		}
		key, err := x509.ParseECPrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parse existing agent private key: %w", err)
		}
		return key, nil
	} else if !os.IsNotExist(err) {
		return nil, fmt.Errorf("read existing agent private key: %w", err)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate agent private key: %w", err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("marshal agent private key: %w", err)
	}
	if err := writeCredential(path, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})); err != nil {
		return nil, err
	}
	return key, nil
}

func verifyEnrollmentMaterial(certificatePEM, caPEM []byte, privateKey *ecdsa.PrivateKey) error {
	certificateBlock, _ := pem.Decode(certificatePEM)
	caBlock, _ := pem.Decode(caPEM)
	if certificateBlock == nil || caBlock == nil {
		return fmt.Errorf("enrollment response contains invalid certificate PEM")
	}
	certificate, err := x509.ParseCertificate(certificateBlock.Bytes)
	if err != nil {
		return fmt.Errorf("parse enrolled certificate: %w", err)
	}
	ca, err := x509.ParseCertificate(caBlock.Bytes)
	if err != nil || !ca.IsCA {
		return fmt.Errorf("parse enrollment CA certificate")
	}
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	if _, err := certificate.Verify(x509.VerifyOptions{Roots: roots, CurrentTime: time.Now().UTC(), KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err != nil {
		return fmt.Errorf("verify enrolled certificate: %w", err)
	}
	keyDER, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		return fmt.Errorf("marshal enrolled private key: %w", err)
	}
	if _, err := tls.X509KeyPair(certificatePEM, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})); err != nil {
		return fmt.Errorf("verify enrolled private key: %w", err)
	}
	return nil
}

func secureDirectory(path string) error {
	if err := os.MkdirAll(path, 0o700); err != nil {
		return fmt.Errorf("create credential directory: %w", err)
	}
	if err := os.Chmod(path, 0o700); err != nil {
		return fmt.Errorf("secure credential directory: %w", err)
	}
	return nil
}

func writeCredential(path string, contents []byte) error {
	temporary := path + ".tmp"
	if err := os.WriteFile(temporary, contents, 0o600); err != nil {
		return fmt.Errorf("write credential %s: %w", filepath.Base(path), err)
	}
	if err := os.Chmod(temporary, 0o600); err != nil {
		return fmt.Errorf("secure credential %s: %w", filepath.Base(path), err)
	}
	if err := os.Rename(temporary, path); err != nil {
		return fmt.Errorf("replace credential %s: %w", filepath.Base(path), err)
	}
	return nil
}

package server

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"database/sql"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	caCertificateName = "agent-ca.crt"
	caPrivateKeyName  = "agent-ca.key"
)

type CertificateAuthority struct {
	certificate    *x509.Certificate
	privateKey     *ecdsa.PrivateKey
	certificatePEM []byte
}

func LoadOrCreateCertificateAuthority(directory string) (*CertificateAuthority, error) {
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return nil, fmt.Errorf("create CA directory: %w", err)
	}
	if err := os.Chmod(directory, 0o700); err != nil {
		return nil, fmt.Errorf("secure CA directory: %w", err)
	}
	certificatePath := filepath.Join(directory, caCertificateName)
	keyPath := filepath.Join(directory, caPrivateKeyName)
	certificatePEM, certificateErr := os.ReadFile(certificatePath)
	keyPEM, keyErr := os.ReadFile(keyPath)
	if certificateErr == nil && keyErr == nil {
		return parseCertificateAuthority(certificatePEM, keyPEM)
	}
	if (certificateErr == nil) != (keyErr == nil) {
		return nil, fmt.Errorf("CA certificate and private key must both exist")
	}
	if certificateErr != nil && !os.IsNotExist(certificateErr) {
		return nil, fmt.Errorf("read CA certificate: %w", certificateErr)
	}
	if keyErr != nil && !os.IsNotExist(keyErr) {
		return nil, fmt.Errorf("read CA key: %w", keyErr)
	}

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate CA private key: %w", err)
	}
	serial, err := randomSerialNumber()
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "server-probe agent CA"},
		NotBefore:             now.Add(-5 * time.Minute),
		NotAfter:              now.AddDate(10, 0, 0),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return nil, fmt.Errorf("create CA certificate: %w", err)
	}
	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("parse generated CA certificate: %w", err)
	}
	privateKeyDER, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		return nil, fmt.Errorf("marshal CA private key: %w", err)
	}
	certificatePEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: privateKeyDER})
	if err := writePrivateFile(keyPath, keyPEM, 0o600); err != nil {
		return nil, err
	}
	if err := writePrivateFile(certificatePath, certificatePEM, 0o644); err != nil {
		return nil, err
	}
	return &CertificateAuthority{certificate: certificate, privateKey: privateKey, certificatePEM: certificatePEM}, nil
}

func (ca *CertificateAuthority) Certificate() *x509.Certificate { return ca.certificate }

func (ca *CertificateAuthority) CertificatePEM() []byte {
	return append([]byte(nil), ca.certificatePEM...)
}

func (ca *CertificateAuthority) IssueClientCertificate(nodeID string, csrPEM []byte, now time.Time) (IssuedCertificate, error) {
	block, rest := pem.Decode(csrPEM)
	if block == nil || (block.Type != "CERTIFICATE REQUEST" && block.Type != "NEW CERTIFICATE REQUEST") || len(strings.TrimSpace(string(rest))) != 0 {
		return IssuedCertificate{}, fmt.Errorf("invalid certificate request PEM")
	}
	request, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return IssuedCertificate{}, fmt.Errorf("parse certificate request: %w", err)
	}
	if err := request.CheckSignature(); err != nil {
		return IssuedCertificate{}, fmt.Errorf("verify certificate request: %w", err)
	}
	serial, err := randomSerialNumber()
	if err != nil {
		return IssuedCertificate{}, err
	}
	now = now.UTC()
	expiresAt := now.AddDate(0, 0, 30)
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: nodeID},
		NotBefore:    now.Add(-5 * time.Minute),
		NotAfter:     expiresAt,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, ca.certificate, request.PublicKey, ca.privateKey)
	if err != nil {
		return IssuedCertificate{}, fmt.Errorf("issue client certificate: %w", err)
	}
	return IssuedCertificate{
		CertificatePEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		CAPEM:          ca.CertificatePEM(),
		SerialNumber:   serial.Text(16),
		NotAfter:       expiresAt,
	}, nil
}

type IssuedCertificate struct {
	CertificatePEM []byte
	CAPEM          []byte
	SerialNumber   string
	NotAfter       time.Time
}

type EnrollmentService struct {
	Store *Store
	CA    *CertificateAuthority
	Now   func() time.Time
}

func (s EnrollmentService) CreateEnrollmentCode(ctx context.Context, nodeID string) (string, error) {
	if s.Store == nil {
		return "", fmt.Errorf("enrollment store is required")
	}
	now := s.now()
	bytes := make([]byte, 24)
	if _, err := rand.Read(bytes); err != nil {
		return "", fmt.Errorf("generate enrollment code: %w", err)
	}
	code := base64.RawURLEncoding.EncodeToString(bytes)
	if err := s.Store.CreateEnrollmentCode(ctx, nodeID, code, now.Add(10*time.Minute)); err != nil {
		return "", err
	}
	return code, nil
}

func (s EnrollmentService) Enroll(ctx context.Context, code string, csrPEM []byte) (IssuedCertificate, error) {
	if s.Store == nil || s.CA == nil {
		return IssuedCertificate{}, fmt.Errorf("enrollment service is not configured")
	}
	now := s.now()
	// The code identifies the node only inside the transaction; issue first so the certificate never leaves the service unless it is persisted.
	nodeID, err := s.Store.NodeForEnrollmentCode(ctx, code, now)
	if err != nil {
		return IssuedCertificate{}, err
	}
	issued, err := s.CA.IssueClientCertificate(nodeID, csrPEM, now)
	if err != nil {
		return IssuedCertificate{}, err
	}
	if _, err := s.Store.EnrollCertificate(ctx, code, issued.SerialNumber, now, issued.NotAfter); err != nil {
		return IssuedCertificate{}, err
	}
	return issued, nil
}

func (s EnrollmentService) now() time.Time {
	if s.Now == nil {
		return time.Now().UTC()
	}
	return s.Now().UTC()
}

func (s *Store) NodeForEnrollmentCode(ctx context.Context, code string, at time.Time) (string, error) {
	codeHash := sha256.Sum256([]byte(code))
	var nodeID string
	var expiresAt int64
	var usedAt sql.NullInt64
	err := s.db.QueryRowContext(ctx, "SELECT node_id, expires_at, used_at FROM enrollment_codes WHERE code_hash = ?", codeHash[:]).Scan(&nodeID, &expiresAt, &usedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return "", ErrEnrollmentCodeInvalid
	}
	if err != nil {
		return "", fmt.Errorf("read enrollment code: %w", err)
	}
	if usedAt.Valid {
		return "", ErrEnrollmentCodeUsed
	}
	if at.UTC().UnixMilli() >= expiresAt {
		return "", ErrEnrollmentCodeExpired
	}
	return nodeID, nil
}

func parseCertificateAuthority(certificatePEM, keyPEM []byte) (*CertificateAuthority, error) {
	certificateBlock, _ := pem.Decode(certificatePEM)
	if certificateBlock == nil {
		return nil, fmt.Errorf("parse CA certificate PEM")
	}
	certificate, err := x509.ParseCertificate(certificateBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse CA certificate: %w", err)
	}
	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil {
		return nil, fmt.Errorf("parse CA private key PEM")
	}
	privateKey, err := x509.ParseECPrivateKey(keyBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse CA private key: %w", err)
	}
	if !certificate.IsCA {
		return nil, fmt.Errorf("certificate is not a CA")
	}
	return &CertificateAuthority{certificate: certificate, privateKey: privateKey, certificatePEM: certificatePEM}, nil
}

func randomSerialNumber() (*big.Int, error) {
	limit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, limit)
	if err != nil {
		return nil, fmt.Errorf("generate certificate serial: %w", err)
	}
	if serial.Sign() == 0 {
		return big.NewInt(1), nil
	}
	return serial, nil
}

func writePrivateFile(path string, contents []byte, mode os.FileMode) error {
	temporary := path + ".tmp"
	if err := os.WriteFile(temporary, contents, mode); err != nil {
		return fmt.Errorf("write %s: %w", filepath.Base(path), err)
	}
	if err := os.Chmod(temporary, mode); err != nil {
		return fmt.Errorf("secure %s: %w", filepath.Base(path), err)
	}
	if err := os.Rename(temporary, path); err != nil {
		return fmt.Errorf("replace %s: %w", filepath.Base(path), err)
	}
	return nil
}

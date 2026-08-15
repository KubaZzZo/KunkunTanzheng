package server

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestAuthServiceBootstrapsAndAuthenticatesWithTOTP(t *testing.T) {
	ctx := context.Background()
	store := openTestStore(t)
	now := time.Date(2026, 8, 15, 0, 0, 0, 0, time.UTC)
	auth, err := NewAuthService(store, strings.Repeat("k", 32), func() time.Time { return now })
	if err != nil {
		t.Fatalf("NewAuthService() error = %v", err)
	}
	secret, err := GenerateTOTPSecret()
	if err != nil {
		t.Fatalf("GenerateTOTPSecret() error = %v", err)
	}
	recoveryCodes, err := auth.Bootstrap(ctx, "correct horse battery staple", secret, TOTPCode(secret, now))
	if err != nil {
		t.Fatalf("Bootstrap() error = %v", err)
	}
	if len(recoveryCodes) != 10 {
		t.Fatalf("recovery code count = %d, want 10", len(recoveryCodes))
	}

	session, err := auth.Authenticate(ctx, "correct horse battery staple", TOTPCode(secret, now))
	if err != nil {
		t.Fatalf("Authenticate(TOTP) error = %v", err)
	}
	if session.Token == "" || session.CSRFToken == "" || !session.ExpiresAt.Equal(now.Add(12*time.Hour)) {
		t.Fatalf("session = %#v", session)
	}
	if _, err := auth.Session(ctx, session.Token); err != nil {
		t.Fatalf("Session() error = %v", err)
	}
	if _, err := auth.Authenticate(ctx, "wrong", TOTPCode(secret, now)); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("wrong password error = %v, want ErrInvalidCredentials", err)
	}
}

func TestAuthServiceConsumesRecoveryCodeOnce(t *testing.T) {
	ctx := context.Background()
	store := openTestStore(t)
	now := time.Date(2026, 8, 15, 0, 0, 0, 0, time.UTC)
	auth, err := NewAuthService(store, strings.Repeat("s", 32), func() time.Time { return now })
	if err != nil {
		t.Fatalf("NewAuthService() error = %v", err)
	}
	secret, err := GenerateTOTPSecret()
	if err != nil {
		t.Fatalf("GenerateTOTPSecret() error = %v", err)
	}
	codes, err := auth.Bootstrap(ctx, "password", secret, TOTPCode(secret, now))
	if err != nil {
		t.Fatalf("Bootstrap() error = %v", err)
	}
	if _, err := auth.Authenticate(ctx, "password", codes[0]); err != nil {
		t.Fatalf("Authenticate(recovery) error = %v", err)
	}
	if _, err := auth.Authenticate(ctx, "password", codes[0]); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("reused recovery error = %v, want ErrInvalidCredentials", err)
	}
}

func TestHashPasswordUsesRequiredArgon2idParameters(t *testing.T) {
	hash, err := HashPassword("password")
	if err != nil {
		t.Fatalf("HashPassword() error = %v", err)
	}
	if !strings.Contains(hash, "m=65536,t=3,p=1") {
		t.Fatalf("hash = %q, missing required Argon2id parameters", hash)
	}
	if !VerifyPassword(hash, "password") || VerifyPassword(hash, "wrong") {
		t.Fatal("VerifyPassword() did not distinguish correct and wrong password")
	}
}

func TestTOTPCodeRejectsTimesBeforeUnixEpoch(t *testing.T) {
	secret := "JBSWY3DPEHPK3PXP"
	if got := TOTPCode(secret, time.Unix(-30, 0)); got != "" {
		t.Fatalf("TOTPCode() = %q, want empty code before Unix epoch", got)
	}
}

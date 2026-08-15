package server

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestSetupManagerCompletesOnlyOnce(t *testing.T) {
	now := time.Date(2026, 8, 15, 0, 0, 0, 0, time.UTC)
	auth, err := NewAuthService(openTestStore(t), strings.Repeat("z", 32), func() time.Time { return now })
	if err != nil {
		t.Fatalf("NewAuthService() error = %v", err)
	}
	setup, err := NewSetupManager(auth, func() time.Time { return now })
	if err != nil {
		t.Fatalf("NewSetupManager() error = %v", err)
	}
	token, secret, ok := setup.Pending()
	if !ok || token == "" || secret == "" {
		t.Fatalf("Pending() = %q, %q, %v", token, secret, ok)
	}
	if _, err := setup.Complete(context.Background(), token, "password", TOTPCode(secret, now)); err != nil {
		t.Fatalf("Complete() error = %v", err)
	}
	if _, _, ok := setup.Pending(); ok {
		t.Fatal("setup remains pending after completion")
	}
	if _, err := setup.Complete(context.Background(), token, "password", TOTPCode(secret, now)); !errors.Is(err, ErrSetupUnavailable) {
		t.Fatalf("second Complete() error = %v, want ErrSetupUnavailable", err)
	}
}

package server

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"sync"
	"time"
)

var ErrSetupUnavailable = errors.New("setup is unavailable")

type SetupManager struct {
	auth *AuthService
	now  func() time.Time

	mu      sync.Mutex
	token   string
	secret  string
	expires time.Time
}

func NewSetupManager(auth *AuthService, now func() time.Time) (*SetupManager, error) {
	if auth == nil {
		return nil, fmt.Errorf("auth service is required")
	}
	if now == nil {
		now = time.Now
	}
	manager := &SetupManager{auth: auth, now: now}
	var id int
	err := auth.store.db.QueryRowContext(context.Background(), "SELECT id FROM admins WHERE id = 1").Scan(&id)
	if err == nil {
		return manager, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return nil, fmt.Errorf("check administrator setup: %w", err)
	}
	token, err := randomToken(32)
	if err != nil {
		return nil, err
	}
	secret, err := GenerateTOTPSecret()
	if err != nil {
		return nil, err
	}
	manager.token = token
	manager.secret = secret
	manager.expires = now().UTC().Add(30 * time.Minute)
	return manager, nil
}

func (s *SetupManager) Pending() (string, string, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.token == "" || !s.now().UTC().Before(s.expires) {
		s.token, s.secret = "", ""
		return "", "", false
	}
	return s.token, s.secret, true
}

func (s *SetupManager) Complete(ctx context.Context, token, password, verificationCode string) ([]string, error) {
	s.mu.Lock()
	if s.token == "" || !s.now().UTC().Before(s.expires) || token != s.token {
		s.mu.Unlock()
		return nil, ErrSetupUnavailable
	}
	secret := s.secret
	s.mu.Unlock()

	recoveryCodes, err := s.auth.Bootstrap(ctx, password, secret, verificationCode)
	if err != nil {
		return nil, err
	}
	s.mu.Lock()
	s.token, s.secret = "", ""
	s.mu.Unlock()
	return recoveryCodes, nil
}

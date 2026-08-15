package server

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestLoginHandlerSetsStrictSecureSessionCookie(t *testing.T) {
	auth, secret, now := newAuthFixture(t)
	handler := LoginHandler{Auth: auth, IPLimiter: NewSlidingWindowLimiter(5, 15*time.Minute, func() time.Time { return now }), AccountLimiter: NewSlidingWindowLimiter(5, 15*time.Minute, func() time.Time { return now })}
	form := url.Values{"password": {"password"}, "totp": {TOTPCode(secret, now)}}
	request := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(form.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.RemoteAddr = "198.51.100.10:1234"
	response := httptest.NewRecorder()
	handler.HandleLogin(response, request)
	if response.Code != http.StatusSeeOther {
		t.Fatalf("login status = %d, want 303", response.Code)
	}
	cookies := response.Result().Cookies()
	if len(cookies) != 1 || !cookies[0].Secure || !cookies[0].HttpOnly || cookies[0].SameSite != http.SameSiteStrictMode || cookies[0].Name != sessionCookieName {
		t.Fatalf("session cookies = %#v", cookies)
	}
}

func TestLoginHandlerDoesNotCountSuccessfulLoginsAgainstFailureLimit(t *testing.T) {
	auth, secret, now := newAuthFixture(t)
	handler := LoginHandler{Auth: auth, IPLimiter: NewSlidingWindowLimiter(1, 15*time.Minute, func() time.Time { return now }), AccountLimiter: NewSlidingWindowLimiter(1, 15*time.Minute, func() time.Time { return now })}
	successForm := url.Values{"password": {"password"}, "totp": {TOTPCode(secret, now)}}
	success := httptest.NewRecorder()
	successRequest := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(successForm.Encode()))
	successRequest.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	successRequest.RemoteAddr = "198.51.100.10:1234"
	handler.HandleLogin(success, successRequest)
	if success.Code != http.StatusSeeOther {
		t.Fatalf("successful login status = %d, want 303", success.Code)
	}

	failureForm := url.Values{"password": {"wrong"}, "totp": {TOTPCode(secret, now)}}
	failure := httptest.NewRecorder()
	failureRequest := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(failureForm.Encode()))
	failureRequest.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	failureRequest.RemoteAddr = "198.51.100.10:1234"
	handler.HandleLogin(failure, failureRequest)
	if failure.Code != http.StatusUnauthorized {
		t.Fatalf("first failed login after success status = %d, want 401", failure.Code)
	}
}

func TestCSRFProtectionRejectsWrongOriginAndToken(t *testing.T) {
	auth, secret, now := newAuthFixture(t)
	session, err := auth.Authenticate(context.Background(), "password", TOTPCode(secret, now))
	if err != nil {
		t.Fatalf("Authenticate() error = %v", err)
	}
	guard := RequestGuard{Auth: auth}
	request := httptest.NewRequest(http.MethodPost, "https://monitor.example.test/nodes", strings.NewReader("csrf="+url.QueryEscape(session.CSRFToken)))
	request.Host = "monitor.example.test"
	request.Header.Set("Origin", "https://evil.example.test")
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.AddCookie(&http.Cookie{Name: sessionCookieName, Value: session.Token})
	if _, ok := guard.MutationSession(httptest.NewRecorder(), request); ok {
		t.Fatal("MutationSession() accepted cross-origin request")
	}

	request.Header.Set("Origin", "https://monitor.example.test")
	request.Form = url.Values{"csrf": {"wrong"}}
	if _, ok := guard.MutationSession(httptest.NewRecorder(), request); ok {
		t.Fatal("MutationSession() accepted invalid CSRF token")
	}
}

func newAuthFixture(t *testing.T) (*AuthService, string, time.Time) {
	t.Helper()
	now := time.Date(2026, 8, 15, 0, 0, 0, 0, time.UTC)
	auth, err := NewAuthService(openTestStore(t), strings.Repeat("a", 32), func() time.Time { return now })
	if err != nil {
		t.Fatalf("NewAuthService() error = %v", err)
	}
	secret, err := GenerateTOTPSecret()
	if err != nil {
		t.Fatalf("GenerateTOTPSecret() error = %v", err)
	}
	if _, err := auth.Bootstrap(context.Background(), "password", secret, TOTPCode(secret, now)); err != nil {
		t.Fatalf("Bootstrap() error = %v", err)
	}
	return auth, secret, now
}

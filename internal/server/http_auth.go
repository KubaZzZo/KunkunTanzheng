package server

import (
	"crypto/subtle"
	"net/http"
	"net/url"
	"strconv"
	"time"
)

const sessionCookieName = "probe_session"

type LoginHandler struct {
	Auth           *AuthService
	IPLimiter      *SlidingWindowLimiter
	AccountLimiter *SlidingWindowLimiter
}

func (h LoginHandler) HandleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.NotFound(w, r)
		return
	}
	if !checkLoginLimit(w, h.IPLimiter, sourceIP(r)) || !checkLoginLimit(w, h.AccountLimiter, "administrator") {
		return
	}
	if err := r.ParseForm(); err != nil {
		if !recordLoginFailure(w, h.IPLimiter, sourceIP(r)) || !recordLoginFailure(w, h.AccountLimiter, "administrator") {
			return
		}
		http.Error(w, "invalid credentials", http.StatusUnauthorized)
		return
	}
	if h.Auth == nil {
		http.Error(w, "service unavailable", http.StatusServiceUnavailable)
		return
	}
	session, err := h.Auth.Authenticate(r.Context(), r.Form.Get("password"), r.Form.Get("totp"))
	if err != nil {
		if !recordLoginFailure(w, h.IPLimiter, sourceIP(r)) || !recordLoginFailure(w, h.AccountLimiter, "administrator") {
			return
		}
		http.Error(w, "invalid credentials", http.StatusUnauthorized)
		return
	}
	writeSessionCookie(w, session)
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func checkLoginLimit(w http.ResponseWriter, limiter *SlidingWindowLimiter, key string) bool {
	if limiter == nil {
		return true
	}
	allowed, retryAfter := limiter.Check(key)
	if allowed {
		return true
	}
	writeLoginRateLimit(w, retryAfter)
	return false
}

func recordLoginFailure(w http.ResponseWriter, limiter *SlidingWindowLimiter, key string) bool {
	if limiter == nil {
		return true
	}
	allowed, retryAfter := limiter.Allow(key)
	if allowed {
		return true
	}
	writeLoginRateLimit(w, retryAfter)
	return false
}

func writeLoginRateLimit(w http.ResponseWriter, retryAfter time.Duration) {
	seconds := int(retryAfter.Round(time.Second).Seconds())
	if seconds < 1 {
		seconds = 1
	}
	w.Header().Set("Retry-After", strconv.Itoa(seconds))
	http.Error(w, "rate limited", http.StatusTooManyRequests)
}

type RequestGuard struct {
	Auth *AuthService
}

func (g RequestGuard) Session(r *http.Request) (Session, bool) {
	if g.Auth == nil {
		return Session{}, false
	}
	cookie, err := r.Cookie(sessionCookieName)
	if err != nil || cookie.Value == "" {
		return Session{}, false
	}
	session, err := g.Auth.Session(r.Context(), cookie.Value)
	if err != nil {
		return Session{}, false
	}
	return session, true
}

func (g RequestGuard) MutationSession(w http.ResponseWriter, r *http.Request) (Session, bool) {
	session, ok := g.Session(r)
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return Session{}, false
	}
	if !sameOrigin(r) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return Session{}, false
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return Session{}, false
	}
	token := r.Header.Get("X-CSRF-Token")
	if token == "" {
		token = r.Form.Get("csrf")
	}
	if token == "" || subtle.ConstantTimeCompare([]byte(token), []byte(session.CSRFToken)) != 1 {
		http.Error(w, "forbidden", http.StatusForbidden)
		return Session{}, false
	}
	return session, true
}

func (g RequestGuard) HandleLogout(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.NotFound(w, r)
		return
	}
	session, ok := g.MutationSession(w, r)
	if !ok {
		return
	}
	if err := g.Auth.Logout(r.Context(), session.Token); err != nil {
		http.Error(w, "service unavailable", http.StatusServiceUnavailable)
		return
	}
	clearSessionCookie(w)
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

func writeSessionCookie(w http.ResponseWriter, session Session) {
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    session.Token,
		Path:     "/",
		Expires:  session.ExpiresAt,
		MaxAge:   int(sessionLifetime.Seconds()),
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
	})
}

func clearSessionCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
	})
}

func sameOrigin(r *http.Request) bool {
	origin := r.Header.Get("Origin")
	if origin == "" {
		return false
	}
	parsed, err := url.Parse(origin)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" {
		return false
	}
	return parsed.Host == r.Host
}

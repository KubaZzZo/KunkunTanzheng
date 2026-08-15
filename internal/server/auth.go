package server

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/base32"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"golang.org/x/crypto/argon2"
)

const (
	argonMemory      uint32 = 64 * 1024
	argonIterations  uint32 = 3
	argonParallelism uint8  = 1
	argonKeyLength   uint32 = 32
	sessionLifetime         = 12 * time.Hour
)

var (
	ErrInvalidCredentials = errors.New("invalid credentials")
	ErrAdminExists        = errors.New("administrator already exists")
	ErrSessionExpired     = errors.New("session has expired")
)

type AuthService struct {
	store *Store
	key   []byte
	now   func() time.Time
}

type Session struct {
	Token     string
	CSRFToken string
	ExpiresAt time.Time
}

func NewAuthService(store *Store, key string, now func() time.Time) (*AuthService, error) {
	if store == nil {
		return nil, fmt.Errorf("auth store is required")
	}
	if len(key) != 32 {
		return nil, fmt.Errorf("auth encryption key must be 32 bytes")
	}
	if now == nil {
		now = time.Now
	}
	return &AuthService{store: store, key: []byte(key), now: now}, nil
}

func HashPassword(password string) (string, error) {
	if password == "" {
		return "", fmt.Errorf("password is required")
	}
	salt := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return "", fmt.Errorf("generate password salt: %w", err)
	}
	hash := argon2.IDKey([]byte(password), salt, argonIterations, argonMemory, argonParallelism, argonKeyLength)
	return fmt.Sprintf("$argon2id$v=19$m=%d,t=%d,p=%d$%s$%s", argonMemory, argonIterations, argonParallelism,
		base64.RawStdEncoding.EncodeToString(salt), base64.RawStdEncoding.EncodeToString(hash)), nil
}

func VerifyPassword(encoded, password string) bool {
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[1] != "argon2id" || parts[2] != "v=19" || parts[3] != "m=65536,t=3,p=1" {
		return false
	}
	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return false
	}
	expected, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil || len(expected) != int(argonKeyLength) {
		return false
	}
	actual := argon2.IDKey([]byte(password), salt, argonIterations, argonMemory, argonParallelism, argonKeyLength)
	return subtle.ConstantTimeCompare(actual, expected) == 1
}

func GenerateTOTPSecret() (string, error) {
	secret := make([]byte, 20)
	if _, err := io.ReadFull(rand.Reader, secret); err != nil {
		return "", fmt.Errorf("generate TOTP secret: %w", err)
	}
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(secret), nil
}

func TOTPCode(secret string, at time.Time) string {
	decoded, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(strings.ToUpper(strings.TrimSpace(secret)))
	if err != nil || len(decoded) == 0 {
		return ""
	}
	seconds := at.UTC().Unix()
	if seconds < 0 {
		return ""
	}
	return totpCodeForCounter(decoded, uint64(seconds/30))
}

func VerifyTOTP(secret, code string, at time.Time) bool {
	for offset := int64(-1); offset <= 1; offset++ {
		candidateTime := at.Add(time.Duration(offset) * 30 * time.Second)
		candidate := TOTPCode(secret, candidateTime)
		if candidate != "" && subtle.ConstantTimeCompare([]byte(candidate), []byte(strings.TrimSpace(code))) == 1 {
			return true
		}
	}
	return false
}

func totpCodeForCounter(secret []byte, counter uint64) string {
	var value [8]byte
	binary.BigEndian.PutUint64(value[:], counter)
	mac := hmac.New(sha1.New, secret)
	_, _ = mac.Write(value[:])
	digest := mac.Sum(nil)
	offset := digest[len(digest)-1] & 0x0f
	code := (uint32(digest[offset])&0x7f)<<24 | uint32(digest[offset+1])<<16 | uint32(digest[offset+2])<<8 | uint32(digest[offset+3])
	return fmt.Sprintf("%06d", code%1_000_000)
}

func (s *AuthService) Bootstrap(ctx context.Context, password, totpSecret, verificationCode string) ([]string, error) {
	if !VerifyTOTP(totpSecret, verificationCode, s.currentTime()) {
		return nil, ErrInvalidCredentials
	}
	passwordHash, err := HashPassword(password)
	if err != nil {
		return nil, err
	}
	encryptedSecret, err := s.encrypt([]byte(totpSecret))
	if err != nil {
		return nil, err
	}
	recoveryCodes, recoveryHashes, err := generateRecoveryCodes()
	if err != nil {
		return nil, err
	}
	encodedHashes, err := json.Marshal(recoveryHashes)
	if err != nil {
		return nil, fmt.Errorf("encode recovery hashes: %w", err)
	}
	now := s.currentTime()
	result, err := s.store.db.ExecContext(ctx, `INSERT INTO admins(id, password_hash, totp_secret_encrypted, recovery_code_hashes, created_at)
        VALUES (1, ?, ?, ?, ?)`, passwordHash, encryptedSecret, encodedHashes, now.UnixMilli())
	if err != nil {
		if strings.Contains(err.Error(), "constraint") || strings.Contains(err.Error(), "UNIQUE") {
			return nil, ErrAdminExists
		}
		return nil, fmt.Errorf("create administrator: %w", err)
	}
	if changed, err := result.RowsAffected(); err != nil || changed != 1 {
		return nil, fmt.Errorf("create administrator: unexpected row count")
	}
	return recoveryCodes, nil
}

func (s *AuthService) Authenticate(ctx context.Context, password, secondFactor string) (Session, error) {
	var passwordHash string
	var encryptedSecret, encodedRecovery []byte
	err := s.store.db.QueryRowContext(ctx, "SELECT password_hash, totp_secret_encrypted, recovery_code_hashes FROM admins WHERE id = 1").Scan(&passwordHash, &encryptedSecret, &encodedRecovery)
	if err != nil {
		return Session{}, ErrInvalidCredentials
	}
	if !VerifyPassword(passwordHash, password) {
		return Session{}, ErrInvalidCredentials
	}
	secret, err := s.decrypt(encryptedSecret)
	if err != nil {
		return Session{}, ErrInvalidCredentials
	}
	valid := VerifyTOTP(string(secret), secondFactor, s.currentTime())
	if !valid {
		valid, err = s.consumeRecoveryCode(ctx, encodedRecovery, secondFactor)
		if err != nil || !valid {
			return Session{}, ErrInvalidCredentials
		}
	}
	return s.newSession(ctx)
}

func (s *AuthService) Session(ctx context.Context, token string) (Session, error) {
	hash := hashSessionToken(token)
	var expiresAt int64
	var csrfToken string
	err := s.store.db.QueryRowContext(ctx, "SELECT expires_at, csrf_token FROM sessions WHERE id = ?", hash).Scan(&expiresAt, &csrfToken)
	if errors.Is(err, sql.ErrNoRows) {
		return Session{}, ErrSessionExpired
	}
	if err != nil {
		return Session{}, fmt.Errorf("read session: %w", err)
	}
	expires := time.UnixMilli(expiresAt).UTC()
	if !s.currentTime().Before(expires) {
		_, _ = s.store.db.ExecContext(ctx, "DELETE FROM sessions WHERE id = ?", hash)
		return Session{}, ErrSessionExpired
	}
	return Session{Token: token, CSRFToken: csrfToken, ExpiresAt: expires}, nil
}

func (s *AuthService) Logout(ctx context.Context, token string) error {
	if _, err := s.store.db.ExecContext(ctx, "DELETE FROM sessions WHERE id = ?", hashSessionToken(token)); err != nil {
		return fmt.Errorf("delete session: %w", err)
	}
	return nil
}

func (s *AuthService) newSession(ctx context.Context) (Session, error) {
	token, err := randomToken(32)
	if err != nil {
		return Session{}, err
	}
	csrfToken, err := randomToken(32)
	if err != nil {
		return Session{}, err
	}
	now := s.currentTime()
	expiresAt := now.Add(sessionLifetime)
	if _, err := s.store.db.ExecContext(ctx, "INSERT INTO sessions(id, expires_at, csrf_token, created_at) VALUES (?, ?, ?, ?)", hashSessionToken(token), expiresAt.UnixMilli(), csrfToken, now.UnixMilli()); err != nil {
		return Session{}, fmt.Errorf("create session: %w", err)
	}
	return Session{Token: token, CSRFToken: csrfToken, ExpiresAt: expiresAt}, nil
}

func (s *AuthService) consumeRecoveryCode(ctx context.Context, encodedRecovery []byte, code string) (bool, error) {
	wanted := hashRecoveryCode(code)
	tx, err := s.store.db.BeginTx(ctx, nil)
	if err != nil {
		return false, fmt.Errorf("begin recovery code check: %w", err)
	}
	defer tx.Rollback()
	var current []byte
	if err := tx.QueryRowContext(ctx, "SELECT recovery_code_hashes FROM admins WHERE id = 1").Scan(&current); err != nil {
		return false, fmt.Errorf("read recovery codes: %w", err)
	}
	if len(current) == 0 {
		current = encodedRecovery
	}
	var hashes []string
	if err := json.Unmarshal(current, &hashes); err != nil {
		return false, fmt.Errorf("decode recovery codes: %w", err)
	}
	index := -1
	for i, hash := range hashes {
		if subtle.ConstantTimeCompare([]byte(hash), []byte(wanted)) == 1 {
			index = i
		}
	}
	if index < 0 {
		return false, nil
	}
	hashes = append(hashes[:index], hashes[index+1:]...)
	updated, err := json.Marshal(hashes)
	if err != nil {
		return false, fmt.Errorf("encode remaining recovery codes: %w", err)
	}
	if _, err := tx.ExecContext(ctx, "UPDATE admins SET recovery_code_hashes = ? WHERE id = 1", updated); err != nil {
		return false, fmt.Errorf("consume recovery code: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return false, fmt.Errorf("commit recovery code use: %w", err)
	}
	return true, nil
}

func (s *AuthService) encrypt(plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(s.key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	return gcm.Seal(nonce, nonce, plaintext, nil), nil
}

func (s *AuthService) decrypt(ciphertext []byte) ([]byte, error) {
	block, err := aes.NewCipher(s.key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	if len(ciphertext) < gcm.NonceSize() {
		return nil, fmt.Errorf("ciphertext is too short")
	}
	return gcm.Open(nil, ciphertext[:gcm.NonceSize()], ciphertext[gcm.NonceSize():], nil)
}

func (s *AuthService) currentTime() time.Time { return s.now().UTC() }

func generateRecoveryCodes() ([]string, []string, error) {
	codes := make([]string, 10)
	hashes := make([]string, 10)
	for i := range codes {
		code, err := randomToken(8)
		if err != nil {
			return nil, nil, err
		}
		codes[i] = code
		hashes[i] = hashRecoveryCode(code)
	}
	return codes, hashes, nil
}

func randomToken(length int) (string, error) {
	bytes := make([]byte, length)
	if _, err := io.ReadFull(rand.Reader, bytes); err != nil {
		return "", fmt.Errorf("generate random token: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(bytes), nil
}

func hashSessionToken(token string) string {
	digest := sha256.Sum256([]byte(token))
	return hex.EncodeToString(digest[:])
}

func hashRecoveryCode(code string) string {
	digest := sha256.Sum256([]byte(strings.TrimSpace(code)))
	return hex.EncodeToString(digest[:])
}

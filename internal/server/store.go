package server

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	_ "modernc.org/sqlite"

	"github.com/kunkuntanzheng/server-probe/internal/probe"
)

const MaxNodes = 50

var (
	ErrNodeNotFound             = errors.New("node not found")
	ErrNodeDisabled             = errors.New("node is disabled")
	ErrNodeLimit                = errors.New("node limit reached")
	ErrEnrollmentCodeInvalid    = errors.New("enrollment code is invalid")
	ErrEnrollmentCodeUsed       = errors.New("enrollment code was already used")
	ErrEnrollmentCodeExpired    = errors.New("enrollment code has expired")
	ErrCertificateUnknown       = errors.New("certificate is unknown")
	ErrCertificateRevoked       = errors.New("certificate is revoked")
	ErrCertificateExpired       = errors.New("certificate has expired")
	ErrCertificateRenewalNotDue = errors.New("certificate renewal is not due")
	ErrEnrollmentReplayNotFound = errors.New("enrollment replay not found")
)

type Store struct {
	db *sql.DB
}

type Node struct {
	ID           string
	DisplayName  string
	CreatedAt    time.Time
	LastReportAt *time.Time
	Disabled     bool
	State        probe.NodeState
	LatestSample *Sample
}

type Sample struct {
	NodeID                  string
	ReceivedAt              time.Time
	CPUPercent              float64
	MemoryUsedBytes         uint64
	RootFilesystemUsedBytes uint64
	Load1                   float64
	IngressBytesPerSecond   float64
	EgressBytesPerSecond    float64
}

func Open(path string) (*Store, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("open SQLite database: %w", err)
	}
	db.SetMaxOpenConns(1)
	store := &Store{db: db}
	if err := store.migrate(context.Background()); err != nil {
		_ = db.Close()
		return nil, err
	}
	return store, nil
}

func (s *Store) Close() error { return s.db.Close() }

func (s *Store) migrate(ctx context.Context) error {
	if _, err := s.db.ExecContext(ctx, "PRAGMA journal_mode=WAL"); err != nil {
		return fmt.Errorf("enable WAL: %w", err)
	}
	if _, err := s.db.ExecContext(ctx, "PRAGMA foreign_keys=ON"); err != nil {
		return fmt.Errorf("enable foreign keys: %w", err)
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin migration: %w", err)
	}
	defer tx.Rollback()
	statements := []string{
		`CREATE TABLE IF NOT EXISTS admins (
            id INTEGER PRIMARY KEY CHECK (id = 1), password_hash TEXT NOT NULL,
            totp_secret_encrypted BLOB NOT NULL, recovery_code_hashes BLOB NOT NULL,
            created_at INTEGER NOT NULL
        )`,
		`CREATE TABLE IF NOT EXISTS sessions (
		    id TEXT PRIMARY KEY, expires_at INTEGER NOT NULL, csrf_token TEXT NOT NULL,
		    created_at INTEGER NOT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS nodes (
            id TEXT PRIMARY KEY, display_name TEXT NOT NULL, created_at INTEGER NOT NULL,
            last_report_at INTEGER, disabled INTEGER NOT NULL DEFAULT 0 CHECK (disabled IN (0, 1))
        )`,
		`CREATE TABLE IF NOT EXISTS enrollment_codes (
            code_hash BLOB PRIMARY KEY, node_id TEXT NOT NULL UNIQUE, expires_at INTEGER NOT NULL,
            used_at INTEGER, FOREIGN KEY (node_id) REFERENCES nodes(id) ON DELETE CASCADE
        )`,
		`CREATE TABLE IF NOT EXISTS enrollment_results (
            code_hash BLOB PRIMARY KEY, node_id TEXT NOT NULL, serial_number TEXT NOT NULL,
            certificate_pem BLOB NOT NULL, public_key_der BLOB NOT NULL, expires_at INTEGER NOT NULL,
            FOREIGN KEY (node_id) REFERENCES nodes(id) ON DELETE CASCADE
        )`,
		`CREATE TABLE IF NOT EXISTS agent_certificates (
            serial_number TEXT PRIMARY KEY, node_id TEXT NOT NULL, issued_at INTEGER NOT NULL,
            expires_at INTEGER NOT NULL, revoked_at INTEGER,
            FOREIGN KEY (node_id) REFERENCES nodes(id) ON DELETE CASCADE
        )`,
		`CREATE TABLE IF NOT EXISTS samples (
            id INTEGER PRIMARY KEY AUTOINCREMENT, node_id TEXT NOT NULL, received_at INTEGER NOT NULL,
            cpu_percent REAL NOT NULL, memory_used_bytes INTEGER NOT NULL,
            root_filesystem_used_bytes INTEGER NOT NULL, load1 REAL NOT NULL,
            ingress_bytes_per_second REAL NOT NULL, egress_bytes_per_second REAL NOT NULL,
            FOREIGN KEY (node_id) REFERENCES nodes(id) ON DELETE CASCADE
        )`,
		`CREATE INDEX IF NOT EXISTS samples_node_received_at_idx ON samples(node_id, received_at)`,
		`CREATE INDEX IF NOT EXISTS nodes_last_report_at_idx ON nodes(last_report_at)`,
		`CREATE INDEX IF NOT EXISTS agent_certificates_node_id_idx ON agent_certificates(node_id)`,
	}
	for _, statement := range statements {
		if _, err := tx.ExecContext(ctx, statement); err != nil {
			return fmt.Errorf("apply migration: %w", err)
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit migration: %w", err)
	}
	return nil
}

func (s *Store) CreateNode(ctx context.Context, displayName string, createdAt time.Time) (Node, error) {
	var err error
	displayName, err = normalizeDisplayName(displayName)
	if err != nil {
		return Node{}, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return Node{}, fmt.Errorf("begin create node: %w", err)
	}
	defer tx.Rollback()
	var count int
	if err := tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM nodes").Scan(&count); err != nil {
		return Node{}, fmt.Errorf("count nodes: %w", err)
	}
	if count >= MaxNodes {
		return Node{}, ErrNodeLimit
	}
	id, err := randomID()
	if err != nil {
		return Node{}, err
	}
	createdAt = createdAt.UTC()
	if _, err := tx.ExecContext(ctx, "INSERT INTO nodes(id, display_name, created_at) VALUES (?, ?, ?)", id, displayName, createdAt.UnixMilli()); err != nil {
		return Node{}, fmt.Errorf("insert node: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return Node{}, fmt.Errorf("commit create node: %w", err)
	}
	return Node{ID: id, DisplayName: displayName, CreatedAt: createdAt, State: probe.StatePending}, nil
}

func normalizeDisplayName(displayName string) (string, error) {
	displayName = strings.TrimSpace(displayName)
	if displayName == "" || len(displayName) > 128 {
		return "", fmt.Errorf("display name must be between 1 and 128 bytes")
	}
	return displayName, nil
}

func (s *Store) RenameNode(ctx context.Context, nodeID, displayName string) error {
	displayName, err := normalizeDisplayName(displayName)
	if err != nil {
		return err
	}
	result, err := s.db.ExecContext(ctx, "UPDATE nodes SET display_name = ? WHERE id = ?", displayName, nodeID)
	if err != nil {
		return fmt.Errorf("rename node: %w", err)
	}
	changed, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("count renamed nodes: %w", err)
	}
	if changed == 0 {
		return ErrNodeNotFound
	}
	return nil
}

func (s *Store) DisableNode(ctx context.Context, nodeID string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin disable node: %w", err)
	}
	defer tx.Rollback()
	result, err := tx.ExecContext(ctx, "UPDATE nodes SET disabled = 1 WHERE id = ?", nodeID)
	if err != nil {
		return fmt.Errorf("disable node: %w", err)
	}
	changed, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("read disabled node count: %w", err)
	}
	if changed == 0 {
		return ErrNodeNotFound
	}
	if _, err := tx.ExecContext(ctx, "UPDATE agent_certificates SET revoked_at = ? WHERE node_id = ? AND revoked_at IS NULL", time.Now().UTC().UnixMilli(), nodeID); err != nil {
		return fmt.Errorf("revoke node certificates: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit disable node: %w", err)
	}
	return nil
}

func (s *Store) CreateEnrollmentCode(ctx context.Context, nodeID, code string, expiresAt time.Time) error {
	codeHash := sha256.Sum256([]byte(code))
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin create enrollment code: %w", err)
	}
	defer tx.Rollback()
	var disabled int
	err = tx.QueryRowContext(ctx, "SELECT disabled FROM nodes WHERE id = ?", nodeID).Scan(&disabled)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrNodeNotFound
	}
	if err != nil {
		return fmt.Errorf("read enrollment node: %w", err)
	}
	if disabled != 0 {
		return ErrNodeDisabled
	}
	if _, err := tx.ExecContext(ctx, "DELETE FROM enrollment_codes WHERE node_id = ?", nodeID); err != nil {
		return fmt.Errorf("replace enrollment code: %w", err)
	}
	if _, err := tx.ExecContext(ctx, "INSERT INTO enrollment_codes(code_hash, node_id, expires_at) VALUES (?, ?, ?)", codeHash[:], nodeID, expiresAt.UTC().UnixMilli()); err != nil {
		return fmt.Errorf("insert enrollment code: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit enrollment code: %w", err)
	}
	return nil
}

func (s *Store) EnrollCertificate(ctx context.Context, code, serialNumber string, certificatePEM, publicKeyDER []byte, issuedAt, expiresAt time.Time) (string, error) {
	codeHash := sha256.Sum256([]byte(code))
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return "", fmt.Errorf("begin enroll certificate: %w", err)
	}
	defer tx.Rollback()
	var nodeID string
	var expiration int64
	var usedAt sql.NullInt64
	err = tx.QueryRowContext(ctx, "SELECT node_id, expires_at, used_at FROM enrollment_codes WHERE code_hash = ?", codeHash[:]).Scan(&nodeID, &expiration, &usedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return "", ErrEnrollmentCodeInvalid
	}
	if err != nil {
		return "", fmt.Errorf("read enrollment code: %w", err)
	}
	if usedAt.Valid {
		return "", ErrEnrollmentCodeUsed
	}
	issuedAt = issuedAt.UTC()
	if issuedAt.UnixMilli() >= expiration {
		return "", ErrEnrollmentCodeExpired
	}
	var disabled int
	if err := tx.QueryRowContext(ctx, "SELECT disabled FROM nodes WHERE id = ?", nodeID).Scan(&disabled); err != nil {
		return "", fmt.Errorf("read enrolled node: %w", err)
	}
	if disabled != 0 {
		return "", ErrNodeDisabled
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO agent_certificates(serial_number, node_id, issued_at, expires_at)
        VALUES (?, ?, ?, ?)`, serialNumber, nodeID, issuedAt.UnixMilli(), expiresAt.UTC().UnixMilli()); err != nil {
		return "", fmt.Errorf("insert agent certificate: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO enrollment_results(code_hash, node_id, serial_number, certificate_pem, public_key_der, expires_at)
        VALUES (?, ?, ?, ?, ?, ?)`, codeHash[:], nodeID, serialNumber, certificatePEM, publicKeyDER, expiresAt.UTC().UnixMilli()); err != nil {
		return "", fmt.Errorf("store enrollment result: %w", err)
	}
	if _, err := tx.ExecContext(ctx, "UPDATE enrollment_codes SET used_at = ? WHERE code_hash = ?", issuedAt.UnixMilli(), codeHash[:]); err != nil {
		return "", fmt.Errorf("consume enrollment code: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return "", fmt.Errorf("commit enrollment certificate: %w", err)
	}
	return nodeID, nil
}

type EnrollmentReplay struct {
	NodeID         string
	SerialNumber   string
	CertificatePEM []byte
	PublicKeyDER   []byte
	ExpiresAt      time.Time
}

func (s *Store) EnrollmentReplay(ctx context.Context, code string, publicKeyDER []byte) (EnrollmentReplay, error) {
	codeHash := sha256.Sum256([]byte(code))
	var replay EnrollmentReplay
	var expiresAt int64
	err := s.db.QueryRowContext(ctx, `SELECT node_id, serial_number, certificate_pem, public_key_der, expires_at
        FROM enrollment_results WHERE code_hash = ?`, codeHash[:]).Scan(
		&replay.NodeID, &replay.SerialNumber, &replay.CertificatePEM, &replay.PublicKeyDER, &expiresAt)
	if errors.Is(err, sql.ErrNoRows) {
		return EnrollmentReplay{}, ErrEnrollmentReplayNotFound
	}
	if err != nil {
		return EnrollmentReplay{}, fmt.Errorf("read enrollment replay: %w", err)
	}
	if !bytes.Equal(replay.PublicKeyDER, publicKeyDER) {
		return EnrollmentReplay{}, ErrEnrollmentCodeUsed
	}
	replay.ExpiresAt = time.UnixMilli(expiresAt).UTC()
	return replay, nil
}

func (s *Store) NodeForCertificate(ctx context.Context, serialNumber string, at time.Time) (string, error) {
	var nodeID string
	var expiration int64
	var revokedAt sql.NullInt64
	var disabled int
	err := s.db.QueryRowContext(ctx, `SELECT c.node_id, c.expires_at, c.revoked_at, n.disabled
        FROM agent_certificates c JOIN nodes n ON n.id = c.node_id
        WHERE c.serial_number = ?`, serialNumber).Scan(&nodeID, &expiration, &revokedAt, &disabled)
	if errors.Is(err, sql.ErrNoRows) {
		return "", ErrCertificateUnknown
	}
	if err != nil {
		return "", fmt.Errorf("read certificate: %w", err)
	}
	if revokedAt.Valid || disabled != 0 {
		return "", ErrCertificateRevoked
	}
	if at.UTC().UnixMilli() >= expiration {
		return "", ErrCertificateExpired
	}
	return nodeID, nil
}

func (s *Store) RenewCertificate(ctx context.Context, currentSerial, newSerial string, issuedAt, expiresAt time.Time) (string, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return "", fmt.Errorf("begin certificate renewal: %w", err)
	}
	defer tx.Rollback()
	var nodeID string
	var expiration int64
	var revokedAt sql.NullInt64
	var disabled int
	err = tx.QueryRowContext(ctx, `SELECT c.node_id, c.expires_at, c.revoked_at, n.disabled
        FROM agent_certificates c JOIN nodes n ON n.id = c.node_id
        WHERE c.serial_number = ?`, currentSerial).Scan(&nodeID, &expiration, &revokedAt, &disabled)
	if errors.Is(err, sql.ErrNoRows) {
		return "", ErrCertificateUnknown
	}
	if err != nil {
		return "", fmt.Errorf("read certificate for renewal: %w", err)
	}
	issuedAt = issuedAt.UTC()
	if revokedAt.Valid || disabled != 0 {
		return "", ErrCertificateRevoked
	}
	if issuedAt.UnixMilli() >= expiration {
		return "", ErrCertificateExpired
	}
	if issuedAt.Before(time.UnixMilli(expiration).UTC().Add(-7 * 24 * time.Hour)) {
		return "", ErrCertificateRenewalNotDue
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO agent_certificates(serial_number, node_id, issued_at, expires_at)
        VALUES (?, ?, ?, ?)`, newSerial, nodeID, issuedAt.UnixMilli(), expiresAt.UTC().UnixMilli()); err != nil {
		return "", fmt.Errorf("insert renewed certificate: %w", err)
	}
	if _, err := tx.ExecContext(ctx, "UPDATE agent_certificates SET revoked_at = ? WHERE serial_number = ? AND revoked_at IS NULL", issuedAt.UnixMilli(), currentSerial); err != nil {
		return "", fmt.Errorf("revoke previous certificate: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return "", fmt.Errorf("commit certificate renewal: %w", err)
	}
	return nodeID, nil
}

func (s *Store) RecordReport(ctx context.Context, report probe.Report, receivedAt time.Time) error {
	if err := report.Validate(); err != nil {
		return fmt.Errorf("validate report: %w", err)
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin record report: %w", err)
	}
	defer tx.Rollback()
	var disabled int
	err = tx.QueryRowContext(ctx, "SELECT disabled FROM nodes WHERE id = ?", report.NodeID).Scan(&disabled)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrNodeNotFound
	}
	if err != nil {
		return fmt.Errorf("read report node: %w", err)
	}
	if disabled != 0 {
		return ErrNodeDisabled
	}
	receivedAt = receivedAt.UTC()
	receivedMillis := receivedAt.UnixMilli()
	if _, err := tx.ExecContext(ctx, `INSERT INTO samples(
        node_id, received_at, cpu_percent, memory_used_bytes, root_filesystem_used_bytes,
        load1, ingress_bytes_per_second, egress_bytes_per_second
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		report.NodeID, receivedMillis, report.CPUPercent, report.MemoryUsedBytes,
		report.RootFilesystemUsedBytes, report.Load1, report.IngressBytesPerSecond,
		report.EgressBytesPerSecond); err != nil {
		return fmt.Errorf("insert sample: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `UPDATE nodes SET last_report_at = ?
        WHERE id = ? AND (last_report_at IS NULL OR last_report_at < ?)`, receivedMillis, report.NodeID, receivedMillis); err != nil {
		return fmt.Errorf("update node last report: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit report: %w", err)
	}
	return nil
}

func (s *Store) Node(ctx context.Context, nodeID string, at time.Time) (Node, error) {
	var node Node
	var createdAt int64
	var lastReport sql.NullInt64
	var disabled int
	err := s.db.QueryRowContext(ctx, `SELECT id, display_name, created_at, last_report_at, disabled
        FROM nodes WHERE id = ?`, nodeID).Scan(&node.ID, &node.DisplayName, &createdAt, &lastReport, &disabled)
	if errors.Is(err, sql.ErrNoRows) {
		return Node{}, ErrNodeNotFound
	}
	if err != nil {
		return Node{}, fmt.Errorf("read node: %w", err)
	}
	node.CreatedAt = time.UnixMilli(createdAt).UTC()
	node.Disabled = disabled != 0
	if lastReport.Valid {
		value := time.UnixMilli(lastReport.Int64).UTC()
		node.LastReportAt = &value
	}
	node.State = probe.NodeStateAt(node.LastReportAt, at.UTC(), node.Disabled)
	sample, err := s.latestSample(ctx, node.ID)
	if err != nil {
		return Node{}, err
	}
	node.LatestSample = sample
	return node, nil
}

func (s *Store) ListNodes(ctx context.Context, at time.Time) ([]Node, error) {
	rows, err := s.db.QueryContext(ctx, "SELECT id FROM nodes ORDER BY display_name COLLATE NOCASE ASC, id ASC")
	if err != nil {
		return nil, fmt.Errorf("list node IDs: %w", err)
	}
	defer rows.Close()
	ids := make([]string, 0)
	for rows.Next() {
		var nodeID string
		if err := rows.Scan(&nodeID); err != nil {
			return nil, fmt.Errorf("scan node ID: %w", err)
		}
		ids = append(ids, nodeID)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate node IDs: %w", err)
	}
	if err := rows.Close(); err != nil {
		return nil, fmt.Errorf("close node IDs: %w", err)
	}
	nodes := make([]Node, 0, len(ids))
	for _, nodeID := range ids {
		node, err := s.Node(ctx, nodeID, at)
		if err != nil {
			return nil, err
		}
		nodes = append(nodes, node)
	}
	return nodes, nil
}

func (s *Store) RemoveNode(ctx context.Context, nodeID string) error {
	result, err := s.db.ExecContext(ctx, "DELETE FROM nodes WHERE id = ?", nodeID)
	if err != nil {
		return fmt.Errorf("remove node: %w", err)
	}
	changed, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("read removed node count: %w", err)
	}
	if changed == 0 {
		return ErrNodeNotFound
	}
	return nil
}

func (s *Store) latestSample(ctx context.Context, nodeID string) (*Sample, error) {
	var sample Sample
	var receivedAt int64
	err := s.db.QueryRowContext(ctx, `SELECT node_id, received_at, cpu_percent, memory_used_bytes,
        root_filesystem_used_bytes, load1, ingress_bytes_per_second, egress_bytes_per_second
        FROM samples WHERE node_id = ? ORDER BY received_at DESC LIMIT 1`, nodeID).Scan(
		&sample.NodeID, &receivedAt, &sample.CPUPercent, &sample.MemoryUsedBytes,
		&sample.RootFilesystemUsedBytes, &sample.Load1, &sample.IngressBytesPerSecond, &sample.EgressBytesPerSecond,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read latest sample: %w", err)
	}
	sample.ReceivedAt = time.UnixMilli(receivedAt).UTC()
	return &sample, nil
}

func (s *Store) SamplesSince(ctx context.Context, nodeID string, since time.Time) ([]Sample, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT node_id, received_at, cpu_percent, memory_used_bytes,
        root_filesystem_used_bytes, load1, ingress_bytes_per_second, egress_bytes_per_second
        FROM samples WHERE node_id = ? AND received_at >= ? ORDER BY received_at ASC`, nodeID, since.UTC().UnixMilli())
	if err != nil {
		return nil, fmt.Errorf("query samples: %w", err)
	}
	defer rows.Close()
	samples := make([]Sample, 0)
	for rows.Next() {
		var sample Sample
		var receivedAt int64
		if err := rows.Scan(&sample.NodeID, &receivedAt, &sample.CPUPercent, &sample.MemoryUsedBytes,
			&sample.RootFilesystemUsedBytes, &sample.Load1, &sample.IngressBytesPerSecond, &sample.EgressBytesPerSecond); err != nil {
			return nil, fmt.Errorf("scan sample: %w", err)
		}
		sample.ReceivedAt = time.UnixMilli(receivedAt).UTC()
		samples = append(samples, sample)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate samples: %w", err)
	}
	return samples, nil
}

func (s *Store) PurgeSamplesBefore(ctx context.Context, cutoff time.Time) error {
	if _, err := s.db.ExecContext(ctx, "DELETE FROM samples WHERE received_at < ?", cutoff.UTC().UnixMilli()); err != nil {
		return fmt.Errorf("purge samples: %w", err)
	}
	return nil
}

func (s *Store) MaintainSamples(ctx context.Context, now time.Time, maxDatabaseBytes int64) error {
	if err := s.PurgeSamplesBefore(ctx, now.UTC().Add(-30*24*time.Hour)); err != nil {
		return err
	}
	if maxDatabaseBytes <= 0 {
		maxDatabaseBytes = 2 * 1024 * 1024 * 1024
	}
	for {
		size, err := s.databaseSize(ctx)
		if err != nil {
			return err
		}
		if size <= maxDatabaseBytes {
			return nil
		}
		result, err := s.db.ExecContext(ctx, `DELETE FROM samples WHERE id = (
            SELECT id FROM samples ORDER BY received_at ASC, id ASC LIMIT 1
        )`)
		if err != nil {
			return fmt.Errorf("prune oversized database: %w", err)
		}
		removed, err := result.RowsAffected()
		if err != nil {
			return fmt.Errorf("read pruned sample count: %w", err)
		}
		if removed == 0 {
			// SQLite retains freed pages until a vacuum; all raw samples are gone and new reports can reuse those pages.
			return nil
		}
	}
}

func (s *Store) BackupTo(ctx context.Context, destination string) error {
	if err := os.MkdirAll(filepath.Dir(destination), 0o700); err != nil {
		return fmt.Errorf("create backup directory: %w", err)
	}
	if err := os.Remove(destination); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("replace backup destination: %w", err)
	}
	if _, err := s.db.ExecContext(ctx, "PRAGMA wal_checkpoint(TRUNCATE)"); err != nil {
		return fmt.Errorf("checkpoint database for backup: %w", err)
	}
	if _, err := s.db.ExecContext(ctx, backupStatement(), destination); err != nil {
		return fmt.Errorf("create SQLite backup: %w", err)
	}
	if err := os.Chmod(destination, 0o600); err != nil {
		return fmt.Errorf("secure backup: %w", err)
	}
	return nil
}

func backupStatement() string { return "VACUUM INTO ?" }

func (s *Store) BackupDaily(ctx context.Context, directory string, now time.Time) (string, error) {
	now = now.UTC()
	destination := filepath.Join(directory, "probe-"+now.Format("2006-01-02")+".db")
	if err := s.BackupTo(ctx, destination); err != nil {
		return "", err
	}
	backups, err := filepath.Glob(filepath.Join(directory, "probe-*.db"))
	if err != nil {
		return "", fmt.Errorf("list backups: %w", err)
	}
	sort.Strings(backups)
	for len(backups) > 7 {
		if err := os.Remove(backups[0]); err != nil {
			return "", fmt.Errorf("remove old backup: %w", err)
		}
		backups = backups[1:]
	}
	return destination, nil
}

func (s *Store) databaseSize(ctx context.Context) (int64, error) {
	var pageCount, pageSize int64
	if err := s.db.QueryRowContext(ctx, "PRAGMA page_count").Scan(&pageCount); err != nil {
		return 0, fmt.Errorf("read database page count: %w", err)
	}
	if err := s.db.QueryRowContext(ctx, "PRAGMA page_size").Scan(&pageSize); err != nil {
		return 0, fmt.Errorf("read database page size: %w", err)
	}
	if pageCount < 0 || pageSize < 0 || (pageSize > 0 && pageCount > int64(^uint64(0)>>1)/pageSize) {
		return 0, fmt.Errorf("invalid database size")
	}
	return pageCount * pageSize, nil
}

func randomID() (string, error) {
	bytes := make([]byte, 16)
	if _, err := rand.Read(bytes); err != nil {
		return "", fmt.Errorf("generate node ID: %w", err)
	}
	return hex.EncodeToString(bytes), nil
}

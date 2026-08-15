package main

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/kunkuntanzheng/server-probe/internal/server"
)

type config struct {
	ListenAddress          string
	DataDirectory          string
	SecretsDirectory       string
	AgentCADirectory       string
	AgentCAPublicDirectory string
	MonitorHost            string
	IngestHost             string
	EnrollHost             string
	BackupDirectory        string
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	config, err := loadConfig(os.LookupEnv)
	if err != nil {
		log.Printf("invalid configuration: %v", err)
		return
	}
	if err := os.MkdirAll(config.DataDirectory, 0o700); err != nil {
		log.Printf("create data directory: %v", err)
		return
	}
	if err := os.Chmod(config.DataDirectory, 0o700); err != nil {
		log.Printf("secure data directory: %v", err)
		return
	}
	store, err := server.Open(filepath.Join(config.DataDirectory, "probe.db"))
	if err != nil {
		log.Printf("open database: %v", err)
		return
	}
	defer store.Close()
	go runMaintenance(ctx, store, config.BackupDirectory)
	ca, err := server.LoadOrCreateCertificateAuthority(config.AgentCADirectory)
	if err != nil {
		log.Printf("initialize certificate authority: %v", err)
		return
	}
	if err := publishAgentCAPublicCertificate(filepath.Join(config.AgentCAPublicDirectory, "agent-ca.crt"), ca.CertificatePEM()); err != nil {
		log.Printf("publish agent CA certificate: %v", err)
		return
	}
	key, err := loadOrCreateKey(filepath.Join(config.SecretsDirectory, "auth.key"))
	if err != nil {
		log.Printf("initialize application key: %v", err)
		return
	}
	auth, err := server.NewAuthService(store, key, nil)
	if err != nil {
		log.Printf("initialize authentication: %v", err)
		return
	}
	enrollment := server.EnrollmentService{Store: store, CA: ca}
	monitor := server.NewMonitorHandler(store, auth, enrollment,
		"https://"+config.IngestHost+"/v1/reports",
		"https://"+config.EnrollHost+"/v1/enroll", nil)
	setup, err := server.NewSetupManager(auth, nil)
	if err != nil {
		log.Printf("initialize setup: %v", err)
		return
	}
	if token, _, pending := setup.Pending(); pending {
		log.Printf("initial setup URL: https://%s/setup?token=%s", config.MonitorHost, token)
	}
	ingest := server.IngestService{Store: store, CA: ca, ReportLimiter: server.NewSlidingWindowLimiter(4, time.Minute, nil)}
	application := server.NewApplication(
		server.ApplicationConfig{MonitorHost: config.MonitorHost, IngestHost: config.IngestHost, EnrollHost: config.EnrollHost},
		monitor,
		ingest,
		server.EnrollmentHandler{Service: enrollment, Limiter: server.NewSlidingWindowLimiter(5, 15*time.Minute, nil)},
		server.CertificateRenewalHandler{Ingest: ingest, CA: ca},
		setup,
	)

	httpServer := &http.Server{
		Addr:              config.ListenAddress,
		Handler:           application,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
	go func() {
		<-ctx.Done()
		shutdownContext, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		_ = httpServer.Shutdown(shutdownContext)
	}()
	if err := httpServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Printf("serve: %v", err)
	}
}

func loadConfig(lookup func(string) (string, bool)) (config, error) {
	monitorHost, err := required(lookup, "PROBE_MONITOR_HOST")
	if err != nil {
		return config{}, err
	}
	ingestHost, err := required(lookup, "PROBE_INGEST_HOST")
	if err != nil {
		return config{}, err
	}
	enrollHost, err := required(lookup, "PROBE_ENROLL_HOST")
	if err != nil {
		return config{}, err
	}
	if monitorHost == ingestHost || monitorHost == enrollHost || ingestHost == enrollHost {
		return config{}, fmt.Errorf("public host names must be distinct")
	}
	dataDirectory := optional(lookup, "PROBE_DATA_DIRECTORY", "/var/lib/server-probe")
	secretsDirectory := optional(lookup, "PROBE_SECRETS_DIRECTORY", "/var/lib/server-probe-secrets")
	agentCADirectory := optional(lookup, "PROBE_AGENT_CA_DIRECTORY", "/var/lib/server-probe-agent-ca")
	agentCAPublicDirectory := optional(lookup, "PROBE_AGENT_CA_PUBLIC_DIRECTORY", "/var/lib/server-probe-agent-ca-public")
	privateDirectories := []string{dataDirectory, secretsDirectory, agentCADirectory, agentCAPublicDirectory}
	for index, directory := range privateDirectories {
		for _, other := range privateDirectories[index+1:] {
			if filepath.Clean(directory) == filepath.Clean(other) {
				return config{}, fmt.Errorf("private persistence directories must be distinct")
			}
		}
	}
	return config{
		ListenAddress:          optional(lookup, "PROBE_LISTEN_ADDRESS", ":8080"),
		DataDirectory:          dataDirectory,
		SecretsDirectory:       secretsDirectory,
		AgentCADirectory:       agentCADirectory,
		AgentCAPublicDirectory: agentCAPublicDirectory,
		MonitorHost:            monitorHost,
		IngestHost:             ingestHost,
		EnrollHost:             enrollHost,
		BackupDirectory:        optional(lookup, "PROBE_BACKUP_DIRECTORY", filepath.Join(dataDirectory, "backups")),
	}, nil
}

func publishAgentCAPublicCertificate(destination string, certificatePEM []byte) error {
	if len(certificatePEM) == 0 {
		return fmt.Errorf("agent CA certificate is empty")
	}
	if err := os.MkdirAll(filepath.Dir(destination), 0o755); err != nil {
		return fmt.Errorf("create public CA directory: %w", err)
	}
	temporary := destination + ".tmp"
	if err := os.WriteFile(temporary, certificatePEM, 0o644); err != nil {
		return fmt.Errorf("write public CA certificate: %w", err)
	}
	if err := os.Chmod(temporary, 0o644); err != nil {
		return fmt.Errorf("secure public CA certificate: %w", err)
	}
	if err := os.Rename(temporary, destination); err != nil {
		return fmt.Errorf("publish public CA certificate: %w", err)
	}
	return nil
}

func runMaintenance(ctx context.Context, store *server.Store, backupDirectory string) {
	run := func() {
		now := time.Now().UTC()
		if err := store.MaintainSamples(ctx, now, 2*1024*1024*1024); err != nil {
			log.Printf("maintain samples: %v", err)
			return
		}
		if _, err := store.BackupDaily(ctx, backupDirectory, now); err != nil {
			log.Printf("create daily backup: %v", err)
		}
	}
	run()
	ticker := time.NewTicker(24 * time.Hour)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			run()
		}
	}
}

func required(lookup func(string) (string, bool), name string) (string, error) {
	value, ok := lookup(name)
	if !ok || strings.TrimSpace(value) == "" {
		return "", fmt.Errorf("%s is required", name)
	}
	return strings.TrimSpace(value), nil
}

func optional(lookup func(string) (string, bool), name, fallback string) string {
	value, ok := lookup(name)
	if !ok || strings.TrimSpace(value) == "" {
		return fallback
	}
	return strings.TrimSpace(value)
}

func loadOrCreateKey(path string) (string, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return "", err
	}
	if contents, err := os.ReadFile(path); err == nil {
		if len(contents) != 32 {
			return "", fmt.Errorf("application key has invalid length")
		}
		return string(contents), nil
	} else if !os.IsNotExist(err) {
		return "", err
	}
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return "", err
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if errors.Is(err, os.ErrExist) {
		return loadOrCreateKey(path)
	}
	if err != nil {
		return "", err
	}
	if _, err := file.Write(key); err != nil {
		_ = file.Close()
		return "", err
	}
	if err := file.Close(); err != nil {
		return "", err
	}
	return string(key), nil
}

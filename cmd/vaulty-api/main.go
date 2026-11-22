// Command vaulty-api is the Vaulty REST API. This file is the composition
// root: it wires adapters (DB, vault, OAuth, HTTP) to the core services.
package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/gin-gonic/gin"

	httpapi "github.com/linustorvaldss/vaulty/internal/adapter/http"
	"github.com/linustorvaldss/vaulty/internal/adapter/oauth"
	"github.com/linustorvaldss/vaulty/internal/adapter/security"
	"github.com/linustorvaldss/vaulty/internal/adapter/store"
	"github.com/linustorvaldss/vaulty/internal/adapter/vault/awssm"
	"github.com/linustorvaldss/vaulty/internal/adapter/vault/local"
	"github.com/linustorvaldss/vaulty/internal/config"
	"github.com/linustorvaldss/vaulty/internal/port"
	"github.com/linustorvaldss/vaulty/internal/service"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	if err := run(logger); err != nil {
		logger.Error("fatal", "err", err)
		os.Exit(1)
	}
}

func run(logger *slog.Logger) error {
	cfg, err := config.Load()
	if err != nil {
		return err
	}
	ctx := context.Background()

	// ---- persistence ----
	db, err := store.Open(cfg.DatabaseURL, cfg.DBDebug)
	if err != nil {
		return fmt.Errorf("database: %w", err)
	}
	defer db.Close()
	if err := db.Migrate(); err != nil {
		return fmt.Errorf("migrate: %w", err)
	}

	// ---- secret vault ----
	var (
		vault    port.SecretVault
		verifier port.CloudVerifier
	)
	if cfg.AWSVerifyEnabled || cfg.VaultDriver == "awssm" {
		awsCfg, err := awsconfig.LoadDefaultConfig(ctx, awsconfig.WithRegion(cfg.AWSRegion))
		if err != nil {
			return fmt.Errorf("aws config: %w", err)
		}
		verifier = &awssm.Verifier{Base: awsCfg}
		if cfg.VaultDriver == "awssm" {
			vault = awssm.New(awsCfg, awssm.Config{
				KMSKeyID: cfg.AWSKMSKeyID, Prefix: cfg.AWSSecretPrefix,
				ForceDelete: cfg.AWSForceDelete, RecoveryDays: cfg.AWSRecoveryDays,
			}, db.Clouds())
		}
	}
	if cfg.VaultDriver == "local" {
		key, err := localVaultKey(cfg, logger)
		if err != nil {
			return err
		}
		if vault, err = local.New(db.DB(), key); err != nil {
			return err
		}
		logger.Warn("using LOCAL vault driver (AES-GCM in database); use VAULT_DRIVER=awssm in production")
	}

	// ---- auth ----
	secret := cfg.JWTSecret
	if secret == "" {
		secret = randomB64(48)
		logger.Warn("JWT_SECRET not set; using an ephemeral secret (sessions reset on restart)")
	}
	sessions, err := security.NewJWT(secret, cfg.SessionTTL)
	if err != nil {
		return err
	}
	providers := map[string]port.OAuthProvider{}
	if cfg.Google.Enabled() {
		providers["google"] = oauth.Google(oauth.Credentials(cfg.Google))
	}
	if cfg.GitHub.Enabled() {
		providers["github"] = oauth.GitHub(oauth.Credentials(cfg.GitHub))
	}
	if cfg.GitLab.Enabled() {
		providers["gitlab"] = oauth.GitLab(oauth.Credentials(cfg.GitLab), cfg.GitLabURL)
	}
	if cfg.OIDC.Enabled() && cfg.OIDCAuthURL != "" {
		p := oauth.Generic(oauth.GenericConfig{
			Name: cfg.OIDCName, Credentials: oauth.Credentials(cfg.OIDC),
			AuthURL: cfg.OIDCAuthURL, TokenURL: cfg.OIDCToken, UserInfoURL: cfg.OIDCUser, Scopes: cfg.OIDCScopes,
		})
		providers[p.Name()] = p
	}

	// ---- core ----
	svc := service.New(service.Deps{
		Store: db, Vault: vault, Verifier: verifier,
		Hasher: security.Bcrypt{}, Sessions: sessions, Providers: providers, Logger: logger,
		AppURL: cfg.AppURL, APIURL: cfg.APIURL, AllowedRedirects: append([]string{cfg.AppURL}, cfg.CORSOrigins...),
	})

	// ---- HTTP ----
	if cfg.IsProduction() {
		gin.SetMode(gin.ReleaseMode)
	}
	router := httpapi.NewRouter(svc, httpapi.Options{
		CORSOrigins: cfg.CORSOrigins, Logger: logger, SecureCookies: strings.HasPrefix(cfg.APIURL, "https://"),
	})
	srv := &http.Server{
		Addr: ":" + cfg.Port, Handler: router,
		ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 30 * time.Second, WriteTimeout: 60 * time.Second,
	}

	errCh := make(chan error, 1)
	go func() {
		logger.Info("vaulty api listening", "addr", srv.Addr, "env", cfg.Env, "vault", cfg.VaultDriver, "oauth", svc.ProviderNames())
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
	}()
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	select {
	case err := <-errCh:
		return err
	case <-stop:
	}
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	return srv.Shutdown(shutdownCtx)
}

// localVaultKey returns LOCAL_VAULT_KEY, or in development a key persisted in
// .vaulty-local.key so local data survives restarts.
func localVaultKey(cfg *config.Config, logger *slog.Logger) (string, error) {
	if cfg.LocalVaultKey != "" {
		return cfg.LocalVaultKey, nil
	}
	if cfg.IsProduction() {
		return "", errors.New("LOCAL_VAULT_KEY is required")
	}
	const path = ".vaulty-local.key"
	if b, err := os.ReadFile(path); err == nil {
		return strings.TrimSpace(string(b)), nil
	}
	key := randomB64(32)
	if err := os.WriteFile(path, []byte(key+"\n"), 0o600); err != nil {
		return "", err
	}
	logger.Warn("generated development vault key", "path", path)
	return key, nil
}

func randomB64(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return base64.StdEncoding.EncodeToString(b)
}

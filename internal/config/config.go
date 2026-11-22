// Package config loads server configuration from environment variables
// (optionally from a .env file).
package config

import (
	"errors"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/joho/godotenv"
)

type OAuthClient struct {
	ClientID     string
	ClientSecret string
}

func (o OAuthClient) Enabled() bool { return o.ClientID != "" && o.ClientSecret != "" }

type Config struct {
	Env  string // development | production
	Port string

	DatabaseURL string // postgres://... | sqlite://vaulty.db
	DBDebug     bool

	AppURL      string   // web frontend
	APIURL      string   // public URL of this API
	CORSOrigins []string // allowed browser origins

	JWTSecret  string
	SessionTTL time.Duration

	// Vault: "awssm" (AWS Secrets Manager + KMS) or "local" (AES-GCM in DB).
	VaultDriver      string
	LocalVaultKey    string
	AWSRegion        string
	AWSKMSKeyID      string
	AWSSecretPrefix  string
	AWSForceDelete   bool
	AWSRecoveryDays  int64
	AWSVerifyEnabled bool

	Google      OAuthClient
	GitHub      OAuthClient
	GitLab      OAuthClient
	GitLabURL   string
	OIDC        OAuthClient
	OIDCName    string
	OIDCAuthURL string
	OIDCToken   string
	OIDCUser    string
	OIDCScopes  []string
}

func (c *Config) IsProduction() bool { return c.Env == "production" }

func get(key, def string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}
	return def
}

func getBool(key string, def bool) bool {
	b, err := strconv.ParseBool(os.Getenv(key))
	if err != nil {
		return def
	}
	return b
}

func list(key string) []string {
	var out []string
	for _, s := range strings.Split(os.Getenv(key), ",") {
		if s = strings.TrimSpace(s); s != "" {
			out = append(out, s)
		}
	}
	return out
}

func Load() (*Config, error) {
	_ = godotenv.Load() // optional .env

	c := &Config{
		Env:             get("ENV", "development"),
		Port:            get("PORT", "8080"),
		DatabaseURL:     get("DATABASE_URL", "sqlite://vaulty.db"),
		DBDebug:         getBool("DB_DEBUG", false),
		AppURL:          get("APP_URL", "http://localhost:3000"),
		JWTSecret:       os.Getenv("JWT_SECRET"),
		VaultDriver:     get("VAULT_DRIVER", "local"),
		LocalVaultKey:   os.Getenv("LOCAL_VAULT_KEY"),
		AWSRegion:       get("AWS_REGION", "us-east-1"),
		AWSKMSKeyID:     os.Getenv("AWS_KMS_KEY_ID"),
		AWSSecretPrefix: get("AWS_SECRET_PREFIX", "vaulty"),
		AWSForceDelete:  getBool("AWS_SECRET_FORCE_DELETE", false),
		GitLabURL:       get("OAUTH_GITLAB_URL", "https://gitlab.com"),
		OIDCName:        get("OAUTH_OIDC_NAME", "oidc"),
		OIDCAuthURL:     os.Getenv("OAUTH_OIDC_AUTH_URL"),
		OIDCToken:       os.Getenv("OAUTH_OIDC_TOKEN_URL"),
		OIDCUser:        os.Getenv("OAUTH_OIDC_USERINFO_URL"),
		OIDCScopes:      list("OAUTH_OIDC_SCOPES"),
		CORSOrigins:     list("CORS_ORIGINS"),
	}
	c.APIURL = get("API_URL", "http://localhost:"+c.Port)
	if len(c.CORSOrigins) == 0 {
		c.CORSOrigins = []string{c.AppURL}
	}
	ttl, err := time.ParseDuration(get("SESSION_TTL", "24h"))
	if err != nil {
		return nil, errors.New("SESSION_TTL must be a duration like 24h")
	}
	c.SessionTTL = ttl
	days, err := strconv.ParseInt(get("AWS_SECRET_RECOVERY_DAYS", "7"), 10, 64)
	if err != nil || days < 7 || days > 30 {
		return nil, errors.New("AWS_SECRET_RECOVERY_DAYS must be between 7 and 30")
	}
	c.AWSRecoveryDays = days
	c.AWSVerifyEnabled = getBool("AWS_ENABLED", c.VaultDriver == "awssm")

	c.Google = OAuthClient{os.Getenv("OAUTH_GOOGLE_CLIENT_ID"), os.Getenv("OAUTH_GOOGLE_CLIENT_SECRET")}
	c.GitHub = OAuthClient{os.Getenv("OAUTH_GITHUB_CLIENT_ID"), os.Getenv("OAUTH_GITHUB_CLIENT_SECRET")}
	c.GitLab = OAuthClient{os.Getenv("OAUTH_GITLAB_CLIENT_ID"), os.Getenv("OAUTH_GITLAB_CLIENT_SECRET")}
	c.OIDC = OAuthClient{os.Getenv("OAUTH_OIDC_CLIENT_ID"), os.Getenv("OAUTH_OIDC_CLIENT_SECRET")}

	switch c.VaultDriver {
	case "awssm", "local":
	default:
		return nil, errors.New("VAULT_DRIVER must be awssm or local")
	}
	if c.IsProduction() {
		if c.VaultDriver != "awssm" {
			return nil, errors.New("production requires VAULT_DRIVER=awssm")
		}
		if len(c.JWTSecret) < 32 {
			return nil, errors.New("production requires JWT_SECRET (>= 32 chars)")
		}
		if strings.HasPrefix(c.DatabaseURL, "sqlite://") {
			return nil, errors.New("production requires a postgres DATABASE_URL")
		}
	}
	return c, nil
}

// Package service implements Vaulty's use cases on top of the ports.
package service

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"log/slog"
	"time"

	"github.com/google/uuid"

	"github.com/linustorvaldss/vaulty/internal/domain"
	"github.com/linustorvaldss/vaulty/internal/port"
)

type Deps struct {
	Store     port.Store
	Vault     port.SecretVault
	Verifier  port.CloudVerifier
	Hasher    port.PasswordHasher
	Sessions  port.SessionIssuer
	Providers map[string]port.OAuthProvider
	Logger    *slog.Logger

	// AppURL is the web frontend base URL (share links, OAuth redirects).
	AppURL string
	// APIURL is this API's public base URL (OAuth callbacks).
	APIURL string
	// AllowedRedirects are URL prefixes accepted as post-login redirects.
	AllowedRedirects []string
}

// Service is the application facade used by the HTTP adapter.
type Service struct {
	Deps
}

func New(d Deps) *Service {
	if d.Logger == nil {
		d.Logger = slog.Default()
	}
	if d.Providers == nil {
		d.Providers = map[string]port.OAuthProvider{}
	}
	return &Service{Deps: d}
}

// Principal is the authenticated caller.
type Principal struct {
	User *domain.User
	// Set when the caller used an access token (CLI/CI).
	TokenID       string
	TokenTenantID string
	ReadOnly      bool
}

// Scope is a principal acting inside a tenant with a given role.
type Scope struct {
	Principal
	Tenant *domain.Tenant
	Role   domain.Role
}

func (s *Scope) UserID() string   { return s.User.ID }
func (s *Scope) TenantID() string { return s.Tenant.ID }

// can checks the role; write operations are denied for read-only tokens.
func (s *Scope) can(min domain.Role, write bool) error {
	if write && s.ReadOnly {
		return domain.Forbidden("this access token is read-only")
	}
	if !s.Role.Allows(min) {
		return domain.Forbidden("requires %s role in this workspace", min)
	}
	return nil
}

// ResolveScope picks the tenant for a request: the token's tenant, the
// requested tenant, or the user's personal tenant, and checks membership.
func (s *Service) ResolveScope(ctx context.Context, p *Principal, tenantID string) (*Scope, error) {
	if p == nil || p.User == nil {
		return nil, domain.Unauthorized("authentication required")
	}
	if p.TokenTenantID != "" {
		if tenantID != "" && tenantID != p.TokenTenantID {
			return nil, domain.Forbidden("access token is not valid for this workspace")
		}
		tenantID = p.TokenTenantID
	}
	var (
		t   *domain.Tenant
		err error
	)
	if tenantID == "" {
		t, err = s.Store.Tenants().GetPersonal(ctx, p.User.ID)
	} else {
		t, err = s.Store.Tenants().Get(ctx, tenantID)
	}
	if err != nil {
		if domain.KindOf(err) == domain.KindNotFound {
			return nil, domain.Forbidden("workspace not found or access denied")
		}
		return nil, err
	}
	m, err := s.Store.Memberships().Get(ctx, t.ID, p.User.ID)
	if err != nil {
		if domain.KindOf(err) == domain.KindNotFound {
			return nil, domain.Forbidden("workspace not found or access denied")
		}
		return nil, err
	}
	return &Scope{Principal: *p, Tenant: t, Role: m.Role}, nil
}

// ---------- helpers ----------

func newID() string { return uuid.NewString() }

func now() time.Time { return time.Now().UTC() }

func randomToken(prefix string) string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic(err) // crypto/rand never fails on supported platforms
	}
	return prefix + base64.RawURLEncoding.EncodeToString(b)
}

func hashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

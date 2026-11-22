// Package port defines the interfaces the core depends on. Adapters
// (database, AWS, OAuth providers) implement them.
package port

import (
	"context"
	"time"

	"github.com/linustorvaldss/vaulty/internal/domain"
)

// ---------- Persistence ----------

// Store groups all repositories and supports transactions.
type Store interface {
	Users() UserRepository
	Identities() IdentityRepository
	Tenants() TenantRepository
	Memberships() MembershipRepository
	Clouds() CloudConnectionRepository
	Projects() ProjectRepository
	Environments() EnvironmentRepository
	Secrets() SecretRepository
	Tokens() AccessTokenRepository
	Shares() ShareLinkRepository

	// WithTx runs fn inside a transaction. The Store passed to fn is bound
	// to that transaction.
	WithTx(ctx context.Context, fn func(tx Store) error) error
}

type UserRepository interface {
	Create(ctx context.Context, u *domain.User) error
	Update(ctx context.Context, u *domain.User) error
	Get(ctx context.Context, id string) (*domain.User, error)
	GetByEmail(ctx context.Context, email string) (*domain.User, error)
}

type IdentityRepository interface {
	Create(ctx context.Context, i *domain.Identity) error
	Get(ctx context.Context, provider, subject string) (*domain.Identity, error)
	ListByUser(ctx context.Context, userID string) ([]domain.Identity, error)
}

type TenantRepository interface {
	Create(ctx context.Context, t *domain.Tenant) error
	Get(ctx context.Context, id string) (*domain.Tenant, error)
	GetPersonal(ctx context.Context, ownerID string) (*domain.Tenant, error)
	SlugExists(ctx context.Context, slug string) (bool, error)
}

type MembershipRepository interface {
	Upsert(ctx context.Context, m *domain.Membership) error
	Get(ctx context.Context, tenantID, userID string) (*domain.Membership, error)
	Delete(ctx context.Context, tenantID, userID string) error
	ListTenantsForUser(ctx context.Context, userID string) ([]domain.TenantWithRole, error)
	ListMembers(ctx context.Context, tenantID string) ([]domain.MemberView, error)
}

type CloudConnectionRepository interface {
	Upsert(ctx context.Context, c *domain.CloudConnection) error
	Get(ctx context.Context, tenantID, provider string) (*domain.CloudConnection, error)
	Delete(ctx context.Context, tenantID, provider string) error
}

type ProjectRepository interface {
	Create(ctx context.Context, p *domain.Project) error
	Update(ctx context.Context, p *domain.Project) error
	Delete(ctx context.Context, tenantID, id string) error
	// Get finds a project by id or slug inside a tenant.
	Get(ctx context.Context, tenantID, idOrSlug string) (*domain.Project, error)
	List(ctx context.Context, tenantID string) ([]domain.Project, error)
}

type EnvironmentRepository interface {
	Create(ctx context.Context, e *domain.Environment) error
	Delete(ctx context.Context, tenantID, id string) error
	// Get finds an environment by id or slug inside a project.
	Get(ctx context.Context, tenantID, projectID, idOrSlug string) (*domain.Environment, error)
	List(ctx context.Context, tenantID, projectID string) ([]domain.Environment, error)
}

type SecretRepository interface {
	Create(ctx context.Context, s *domain.Secret) error
	Update(ctx context.Context, s *domain.Secret) error
	Delete(ctx context.Context, tenantID, id string) error
	GetByKey(ctx context.Context, tenantID, environmentID, key string) (*domain.Secret, error)
	List(ctx context.Context, tenantID, environmentID string) ([]domain.Secret, error)
	ListByProject(ctx context.Context, tenantID, projectID string) ([]domain.Secret, error)
}

type AccessTokenRepository interface {
	Create(ctx context.Context, t *domain.AccessToken) error
	GetByHash(ctx context.Context, hash string) (*domain.AccessToken, error)
	List(ctx context.Context, userID string) ([]domain.AccessToken, error)
	Delete(ctx context.Context, userID, id string) error
	TouchLastUsed(ctx context.Context, id string, at time.Time) error
}

type ShareLinkRepository interface {
	Create(ctx context.Context, s *domain.ShareLink) error
	GetByHash(ctx context.Context, hash string) (*domain.ShareLink, error)
	List(ctx context.Context, tenantID, environmentID string) ([]domain.ShareLink, error)
	Revoke(ctx context.Context, tenantID, id string, at time.Time) error
	// IncrementViews atomically increments the counter only while it is
	// below maxViews (0 = unlimited). Returns false if the limit was reached.
	IncrementViews(ctx context.Context, id string, maxViews int) (bool, error)
}

// ---------- Secret values ----------

// VaultRef identifies one secret value inside a vault.
type VaultRef struct {
	TenantID      string
	ProjectID     string
	EnvironmentID string
	SecretID      string
	Key           string // informational (tags), never part of the identity
}

// SecretVault stores secret values. Production: AWS Secrets Manager with a
// KMS customer managed key. Local/dev: AES-GCM encrypted rows.
type SecretVault interface {
	Put(ctx context.Context, ref VaultRef, value string) error
	Get(ctx context.Context, ref VaultRef) (string, error)
	// GetMany returns values keyed by SecretID.
	GetMany(ctx context.Context, refs []VaultRef) (map[string]string, error)
	Delete(ctx context.Context, ref VaultRef) error
}

// CloudVerifier checks a tenant's cloud connection (assume role, KMS key).
type CloudVerifier interface {
	Verify(ctx context.Context, c *domain.CloudConnection) error
}

// ---------- Auth ----------

// ExternalProfile is what an OAuth provider tells us about the user.
type ExternalProfile struct {
	Provider      string
	Subject       string
	Email         string
	EmailVerified bool
	Name          string
	AvatarURL     string
}

type OAuthProvider interface {
	Name() string
	AuthCodeURL(state, redirectURI string) string
	Exchange(ctx context.Context, code, redirectURI string) (*ExternalProfile, error)
}

type PasswordHasher interface {
	Hash(password string) (string, error)
	Compare(hash, password string) bool
}

// Claims carried by a session token (JWT).
type Claims struct {
	UserID string
	Email  string
}

type SessionIssuer interface {
	Issue(c Claims) (token string, expiresAt time.Time, err error)
	Parse(token string) (*Claims, error)
	// SignState / ParseState protect the OAuth "state" parameter.
	SignState(payload map[string]string, ttl time.Duration) (string, error)
	ParseState(state string) (map[string]string, error)
}

package domain

import (
	"regexp"
	"strings"
	"time"
)

// ---------- Identity & tenancy ----------

type User struct {
	ID            string    `json:"id"`
	Email         string    `json:"email"`
	Name          string    `json:"name"`
	AvatarURL     string    `json:"avatar_url,omitempty"`
	PasswordHash  string    `json:"-"`
	EmailVerified bool      `json:"email_verified"`
	CreatedAt     time.Time `json:"created_at"`
	UpdatedAt     time.Time `json:"updated_at"`
}

// Identity links a user to an external auth provider account.
type Identity struct {
	ID        string    `json:"id"`
	UserID    string    `json:"user_id"`
	Provider  string    `json:"provider"` // google, github, gitlab, oidc, email
	Subject   string    `json:"subject"`  // provider's stable user id
	Email     string    `json:"email"`
	CreatedAt time.Time `json:"created_at"`
}

type TenantKind string

const (
	TenantPersonal     TenantKind = "personal"
	TenantOrganization TenantKind = "organization"
)

type Tenant struct {
	ID        string     `json:"id"`
	Name      string     `json:"name"`
	Slug      string     `json:"slug"`
	Kind      TenantKind `json:"kind"`
	OwnerID   string     `json:"owner_id"`
	CreatedAt time.Time  `json:"created_at"`
}

type Role string

const (
	RoleOwner  Role = "owner"
	RoleAdmin  Role = "admin"
	RoleMember Role = "member"
	RoleViewer Role = "viewer"
)

var roleRank = map[Role]int{RoleViewer: 1, RoleMember: 2, RoleAdmin: 3, RoleOwner: 4}

// Allows reports whether r grants at least the permissions of min.
func (r Role) Allows(min Role) bool { return roleRank[r] >= roleRank[min] }
func (r Role) Valid() bool         { return roleRank[r] > 0 }

type Membership struct {
	TenantID  string    `json:"tenant_id"`
	UserID    string    `json:"user_id"`
	Role      Role      `json:"role"`
	CreatedAt time.Time `json:"created_at"`
}

// TenantWithRole is what a user sees when listing their tenants.
type TenantWithRole struct {
	Tenant
	Role Role `json:"role"`
}

type MemberView struct {
	UserID string `json:"user_id"`
	Email  string `json:"email"`
	Name   string `json:"name"`
	Role   Role   `json:"role"`
}

// ---------- Cloud ----------

const CloudAWS = "aws"

// CloudConnection is a tenant's own AWS account where its secrets live.
// When absent, secrets are stored in the platform's AWS account.
type CloudConnection struct {
	TenantID   string     `json:"tenant_id"`
	Provider   string     `json:"provider"`
	Region     string     `json:"region"`
	RoleARN    string     `json:"role_arn"`
	ExternalID string     `json:"external_id"`
	KMSKeyID   string     `json:"kms_key_id,omitempty"`
	Status     string     `json:"status"` // pending, verified, error
	LastError  string     `json:"last_error,omitempty"`
	VerifiedAt *time.Time `json:"verified_at,omitempty"`
	CreatedAt  time.Time  `json:"created_at"`
	UpdatedAt  time.Time  `json:"updated_at"`
}

// ---------- Projects / environments / secrets ----------

type Project struct {
	ID          string    `json:"id"`
	TenantID    string    `json:"tenant_id"`
	Name        string    `json:"name"`
	Slug        string    `json:"slug"`
	Description string    `json:"description"`
	CreatedBy   string    `json:"created_by"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// DefaultEnvironments are created with every new project.
var DefaultEnvironments = []string{"development", "staging", "production"}

type Environment struct {
	ID        string    `json:"id"`
	TenantID  string    `json:"tenant_id"`
	ProjectID string    `json:"project_id"`
	Name      string    `json:"name"`
	Slug      string    `json:"slug"`
	CreatedAt time.Time `json:"created_at"`
}

// Secret holds metadata in the database. Value is never persisted by the
// repository; it lives in the SecretVault (AWS Secrets Manager + KMS).
type Secret struct {
	ID            string    `json:"id"`
	TenantID      string    `json:"tenant_id"`
	ProjectID     string    `json:"project_id"`
	EnvironmentID string    `json:"environment_id"`
	Key           string    `json:"key"`
	Type          string    `json:"type"`
	Description   string    `json:"description,omitempty"`
	Version       int       `json:"version"`
	CreatedBy     string    `json:"created_by"`
	UpdatedBy     string    `json:"updated_by"`
	CreatedAt     time.Time `json:"created_at"`
	UpdatedAt     time.Time `json:"updated_at"`
	Value         *string   `json:"value,omitempty"`
}

var secretTypes = map[string]bool{
	"string": true, "json": true, "file": true, "token": true,
	"email": true, "uuid": true, "url": true, "number": true, "boolean": true,
}

func ValidSecretType(t string) bool { return secretTypes[t] }

var keyRe = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_.\-]*$`)

const (
	MaxKeyLength   = 256
	MaxValueLength = 64 * 1024 // AWS Secrets Manager limit per secret
)

func ValidateSecretKey(key string) error {
	if key == "" {
		return Invalid("secret key is required")
	}
	if len(key) > MaxKeyLength {
		return Invalid("secret key %q exceeds %d characters", key, MaxKeyLength)
	}
	if !keyRe.MatchString(key) {
		return Invalid("secret key %q must start with a letter or _ and contain only letters, digits, _ . -", key)
	}
	return nil
}

func ValidateSecretValue(key, value string) error {
	if len(value) > MaxValueLength {
		return Invalid("value of %q exceeds %d bytes", key, MaxValueLength)
	}
	return nil
}

// ---------- Access tokens (CLI / CI) ----------

const AccessTokenPrefix = "vty_"

type AccessToken struct {
	ID         string     `json:"id"`
	UserID     string     `json:"user_id"`
	TenantID   string     `json:"tenant_id"`
	Name       string     `json:"name"`
	Prefix     string     `json:"prefix"` // first chars, shown in UI to identify the token
	Hash       string     `json:"-"`
	ReadOnly   bool       `json:"read_only"`
	ExpiresAt  *time.Time `json:"expires_at,omitempty"`
	LastUsedAt *time.Time `json:"last_used_at,omitempty"`
	CreatedAt  time.Time  `json:"created_at"`
}

// ---------- Share links ----------

const ShareTokenPrefix = "vsh_"

type ShareLink struct {
	ID             string     `json:"id"`
	TenantID       string     `json:"tenant_id"`
	ProjectID      string     `json:"project_id"`
	EnvironmentID  string     `json:"environment_id"`
	TokenHash      string     `json:"-"`
	Keys           []string   `json:"keys,omitempty"` // empty = all keys
	PassphraseHash string     `json:"-"`
	HasPassphrase  bool       `json:"has_passphrase"`
	MaxViews       int        `json:"max_views"` // 0 = unlimited
	Views          int        `json:"views"`
	ExpiresAt      time.Time  `json:"expires_at"`
	RevokedAt      *time.Time `json:"revoked_at,omitempty"`
	CreatedBy      string     `json:"created_by"`
	CreatedAt      time.Time  `json:"created_at"`
}

// ---------- helpers ----------

var nonSlug = regexp.MustCompile(`[^a-z0-9]+`)

// Slugify turns "My App!" into "my-app".
func Slugify(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	s = nonSlug.ReplaceAllString(s, "-")
	return strings.Trim(s, "-")
}

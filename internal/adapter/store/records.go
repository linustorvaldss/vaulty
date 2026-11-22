package store

import (
	"encoding/json"
	"time"

	"github.com/linustorvaldss/vaulty/internal/domain"
)

// Persistence records. They are kept separate from domain types so the core
// has no ORM dependency. All ids are UUID strings (portable across Postgres
// and SQLite).

type userRecord struct {
	ID            string `gorm:"primaryKey;size:36"`
	Email         string `gorm:"size:320;not null;uniqueIndex"`
	Name          string `gorm:"size:255;not null"`
	AvatarURL     string `gorm:"size:1024"`
	PasswordHash  string `gorm:"size:255"`
	EmailVerified bool   `gorm:"not null;default:false"`
	CreatedAt     time.Time
	UpdatedAt     time.Time
}

func (userRecord) TableName() string { return "users" }

func (r userRecord) toDomain() *domain.User {
	return &domain.User{ID: r.ID, Email: r.Email, Name: r.Name, AvatarURL: r.AvatarURL, PasswordHash: r.PasswordHash,
		EmailVerified: r.EmailVerified, CreatedAt: r.CreatedAt, UpdatedAt: r.UpdatedAt}
}

func userFrom(u *domain.User) *userRecord {
	return &userRecord{ID: u.ID, Email: u.Email, Name: u.Name, AvatarURL: u.AvatarURL, PasswordHash: u.PasswordHash,
		EmailVerified: u.EmailVerified, CreatedAt: u.CreatedAt, UpdatedAt: u.UpdatedAt}
}

type identityRecord struct {
	ID        string `gorm:"primaryKey;size:36"`
	UserID    string `gorm:"size:36;not null;index"`
	Provider  string `gorm:"size:32;not null;uniqueIndex:ux_identity_provider_subject"`
	Subject   string `gorm:"size:255;not null;uniqueIndex:ux_identity_provider_subject"`
	Email     string `gorm:"size:320"`
	CreatedAt time.Time
}

func (identityRecord) TableName() string { return "identities" }

func (r identityRecord) toDomain() domain.Identity {
	return domain.Identity{ID: r.ID, UserID: r.UserID, Provider: r.Provider, Subject: r.Subject, Email: r.Email, CreatedAt: r.CreatedAt}
}

type tenantRecord struct {
	ID        string `gorm:"primaryKey;size:36"`
	Name      string `gorm:"size:255;not null"`
	Slug      string `gorm:"size:128;not null;uniqueIndex"`
	Kind      string `gorm:"size:32;not null"`
	OwnerID   string `gorm:"size:36;not null;index"`
	CreatedAt time.Time
}

func (tenantRecord) TableName() string { return "tenants" }

func (r tenantRecord) toDomain() *domain.Tenant {
	return &domain.Tenant{ID: r.ID, Name: r.Name, Slug: r.Slug, Kind: domain.TenantKind(r.Kind), OwnerID: r.OwnerID, CreatedAt: r.CreatedAt}
}

type membershipRecord struct {
	TenantID  string `gorm:"primaryKey;size:36"`
	UserID    string `gorm:"primaryKey;size:36;index"`
	Role      string `gorm:"size:16;not null"`
	CreatedAt time.Time
}

func (membershipRecord) TableName() string { return "memberships" }

type cloudRecord struct {
	TenantID   string `gorm:"primaryKey;size:36"`
	Provider   string `gorm:"primaryKey;size:16"`
	Region     string `gorm:"size:32"`
	RoleARN    string `gorm:"size:2048"`
	ExternalID string `gorm:"size:128"`
	KMSKeyID   string `gorm:"size:2048"`
	Status     string `gorm:"size:16"`
	LastError  string `gorm:"size:2048"`
	VerifiedAt *time.Time
	CreatedAt  time.Time
	UpdatedAt  time.Time
}

func (cloudRecord) TableName() string { return "cloud_connections" }

func (r cloudRecord) toDomain() *domain.CloudConnection {
	return &domain.CloudConnection{TenantID: r.TenantID, Provider: r.Provider, Region: r.Region, RoleARN: r.RoleARN,
		ExternalID: r.ExternalID, KMSKeyID: r.KMSKeyID, Status: r.Status, LastError: r.LastError,
		VerifiedAt: r.VerifiedAt, CreatedAt: r.CreatedAt, UpdatedAt: r.UpdatedAt}
}

func cloudFrom(c *domain.CloudConnection) *cloudRecord {
	return &cloudRecord{TenantID: c.TenantID, Provider: c.Provider, Region: c.Region, RoleARN: c.RoleARN,
		ExternalID: c.ExternalID, KMSKeyID: c.KMSKeyID, Status: c.Status, LastError: c.LastError,
		VerifiedAt: c.VerifiedAt, CreatedAt: c.CreatedAt, UpdatedAt: c.UpdatedAt}
}

type projectRecord struct {
	ID          string `gorm:"primaryKey;size:36"`
	TenantID    string `gorm:"size:36;not null;uniqueIndex:ux_project_tenant_slug"`
	Name        string `gorm:"size:255;not null"`
	Slug        string `gorm:"size:128;not null;uniqueIndex:ux_project_tenant_slug"`
	Description string `gorm:"type:text"`
	CreatedBy   string `gorm:"size:36"`
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

func (projectRecord) TableName() string { return "projects" }

func (r projectRecord) toDomain() domain.Project {
	return domain.Project{ID: r.ID, TenantID: r.TenantID, Name: r.Name, Slug: r.Slug, Description: r.Description,
		CreatedBy: r.CreatedBy, CreatedAt: r.CreatedAt, UpdatedAt: r.UpdatedAt}
}

func projectFrom(p *domain.Project) *projectRecord {
	return &projectRecord{ID: p.ID, TenantID: p.TenantID, Name: p.Name, Slug: p.Slug, Description: p.Description,
		CreatedBy: p.CreatedBy, CreatedAt: p.CreatedAt, UpdatedAt: p.UpdatedAt}
}

type environmentRecord struct {
	ID        string `gorm:"primaryKey;size:36"`
	TenantID  string `gorm:"size:36;not null;index"`
	ProjectID string `gorm:"size:36;not null;uniqueIndex:ux_env_project_slug"`
	Name      string `gorm:"size:128;not null"`
	Slug      string `gorm:"size:128;not null;uniqueIndex:ux_env_project_slug"`
	CreatedAt time.Time
}

func (environmentRecord) TableName() string { return "environments" }

func (r environmentRecord) toDomain() domain.Environment {
	return domain.Environment{ID: r.ID, TenantID: r.TenantID, ProjectID: r.ProjectID, Name: r.Name, Slug: r.Slug, CreatedAt: r.CreatedAt}
}

type secretRecord struct {
	ID            string `gorm:"primaryKey;size:36"`
	TenantID      string `gorm:"size:36;not null;index"`
	ProjectID     string `gorm:"size:36;not null;index"`
	EnvironmentID string `gorm:"size:36;not null;uniqueIndex:ux_secret_env_key"`
	Key           string `gorm:"size:256;not null;uniqueIndex:ux_secret_env_key"`
	Type          string `gorm:"size:16;not null"`
	Description   string `gorm:"type:text"`
	Version       int    `gorm:"not null"`
	CreatedBy     string `gorm:"size:36"`
	UpdatedBy     string `gorm:"size:36"`
	CreatedAt     time.Time
	UpdatedAt     time.Time
}

func (secretRecord) TableName() string { return "secrets" }

func (r secretRecord) toDomain() domain.Secret {
	return domain.Secret{ID: r.ID, TenantID: r.TenantID, ProjectID: r.ProjectID, EnvironmentID: r.EnvironmentID,
		Key: r.Key, Type: r.Type, Description: r.Description, Version: r.Version,
		CreatedBy: r.CreatedBy, UpdatedBy: r.UpdatedBy, CreatedAt: r.CreatedAt, UpdatedAt: r.UpdatedAt}
}

func secretFrom(s *domain.Secret) *secretRecord {
	return &secretRecord{ID: s.ID, TenantID: s.TenantID, ProjectID: s.ProjectID, EnvironmentID: s.EnvironmentID,
		Key: s.Key, Type: s.Type, Description: s.Description, Version: s.Version,
		CreatedBy: s.CreatedBy, UpdatedBy: s.UpdatedBy, CreatedAt: s.CreatedAt, UpdatedAt: s.UpdatedAt}
}

type tokenRecord struct {
	ID         string `gorm:"primaryKey;size:36"`
	UserID     string `gorm:"size:36;not null;index"`
	TenantID   string `gorm:"size:36;not null;index"`
	Name       string `gorm:"size:255;not null"`
	Prefix     string `gorm:"size:32"`
	Hash       string `gorm:"size:64;not null;uniqueIndex"`
	ReadOnly   bool   `gorm:"not null;default:false"`
	ExpiresAt  *time.Time
	LastUsedAt *time.Time
	CreatedAt  time.Time
}

func (tokenRecord) TableName() string { return "access_tokens" }

func (r tokenRecord) toDomain() domain.AccessToken {
	return domain.AccessToken{ID: r.ID, UserID: r.UserID, TenantID: r.TenantID, Name: r.Name, Prefix: r.Prefix,
		Hash: r.Hash, ReadOnly: r.ReadOnly, ExpiresAt: r.ExpiresAt, LastUsedAt: r.LastUsedAt, CreatedAt: r.CreatedAt}
}

type shareRecord struct {
	ID             string `gorm:"primaryKey;size:36"`
	TenantID       string `gorm:"size:36;not null;index"`
	ProjectID      string `gorm:"size:36;not null;index"`
	EnvironmentID  string `gorm:"size:36;not null;index"`
	TokenHash      string `gorm:"size:64;not null;uniqueIndex"`
	Keys           string `gorm:"type:text"` // JSON array
	PassphraseHash string `gorm:"size:255"`
	MaxViews       int    `gorm:"not null;default:0"`
	Views          int    `gorm:"not null;default:0"`
	ExpiresAt      time.Time
	RevokedAt      *time.Time
	CreatedBy      string `gorm:"size:36"`
	CreatedAt      time.Time
}

func (shareRecord) TableName() string { return "share_links" }

func (r shareRecord) toDomain() domain.ShareLink {
	var keys []string
	if r.Keys != "" {
		_ = json.Unmarshal([]byte(r.Keys), &keys)
	}
	return domain.ShareLink{ID: r.ID, TenantID: r.TenantID, ProjectID: r.ProjectID, EnvironmentID: r.EnvironmentID,
		TokenHash: r.TokenHash, Keys: keys, PassphraseHash: r.PassphraseHash, HasPassphrase: r.PassphraseHash != "",
		MaxViews: r.MaxViews, Views: r.Views, ExpiresAt: r.ExpiresAt, RevokedAt: r.RevokedAt,
		CreatedBy: r.CreatedBy, CreatedAt: r.CreatedAt}
}

func shareFrom(s *domain.ShareLink) *shareRecord {
	keys := ""
	if len(s.Keys) > 0 {
		b, _ := json.Marshal(s.Keys)
		keys = string(b)
	}
	return &shareRecord{ID: s.ID, TenantID: s.TenantID, ProjectID: s.ProjectID, EnvironmentID: s.EnvironmentID,
		TokenHash: s.TokenHash, Keys: keys, PassphraseHash: s.PassphraseHash, MaxViews: s.MaxViews, Views: s.Views,
		ExpiresAt: s.ExpiresAt, RevokedAt: s.RevokedAt, CreatedBy: s.CreatedBy, CreatedAt: s.CreatedAt}
}

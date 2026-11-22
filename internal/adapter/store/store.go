// Package store implements the persistence ports with GORM. It supports
// PostgreSQL (production) and SQLite (local development and tests).
package store

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"github.com/glebarez/sqlite"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
	"gorm.io/gorm/logger"

	"github.com/linustorvaldss/vaulty/internal/domain"
	"github.com/linustorvaldss/vaulty/internal/port"
)

type Store struct{ db *gorm.DB }

// Open connects using a URL: postgres://... or sqlite://path/to.db or
// sqlite://:memory:.
func Open(url string, debug bool) (*Store, error) {
	var dial gorm.Dialector
	switch {
	case strings.HasPrefix(url, "postgres://"), strings.HasPrefix(url, "postgresql://"):
		dial = postgres.Open(url)
	case strings.HasPrefix(url, "sqlite://"):
		path := strings.TrimPrefix(url, "sqlite://")
		if path == ":memory:" {
			path = "file::memory:?cache=shared"
		}
		if !strings.Contains(path, "?") {
			path += "?_pragma=foreign_keys(1)&_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)"
		}
		dial = sqlite.Open(path)
	default:
		return nil, fmt.Errorf("unsupported DATABASE_URL %q (use postgres:// or sqlite://)", url)
	}
	level := logger.Warn
	if debug {
		level = logger.Info
	}
	gormLog := logger.New(log.New(os.Stderr, "", log.LstdFlags), logger.Config{
		SlowThreshold: 500 * time.Millisecond, LogLevel: level, IgnoreRecordNotFoundError: true,
	})
	db, err := gorm.Open(dial, &gorm.Config{Logger: gormLog, TranslateError: true,
		NowFunc: func() time.Time { return time.Now().UTC() }})
	if err != nil {
		return nil, err
	}
	if strings.HasPrefix(url, "sqlite://") {
		sqlDB, _ := db.DB()
		sqlDB.SetMaxOpenConns(1) // SQLite allows a single writer
	}
	return &Store{db: db}, nil
}

// Migrate creates/updates tables.
func (s *Store) Migrate() error {
	return s.db.AutoMigrate(&userRecord{}, &identityRecord{}, &tenantRecord{}, &membershipRecord{},
		&cloudRecord{}, &projectRecord{}, &environmentRecord{}, &secretRecord{}, &tokenRecord{},
		&shareRecord{})
}

func (s *Store) DB() *gorm.DB { return s.db }

func (s *Store) Close() error {
	sqlDB, err := s.db.DB()
	if err != nil {
		return err
	}
	return sqlDB.Close()
}

func (s *Store) WithTx(ctx context.Context, fn func(tx port.Store) error) error {
	return s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		return fn(&Store{db: tx})
	})
}

func (s *Store) Users() port.UserRepository             { return users{s.db} }
func (s *Store) Identities() port.IdentityRepository    { return identities{s.db} }
func (s *Store) Tenants() port.TenantRepository         { return tenants{s.db} }
func (s *Store) Memberships() port.MembershipRepository { return memberships{s.db} }
func (s *Store) Clouds() port.CloudConnectionRepository { return clouds{s.db} }
func (s *Store) Projects() port.ProjectRepository       { return projects{s.db} }
func (s *Store) Environments() port.EnvironmentRepository {
	return environments{s.db}
}
func (s *Store) Secrets() port.SecretRepository     { return secrets{s.db} }
func (s *Store) Tokens() port.AccessTokenRepository { return tokens{s.db} }
func (s *Store) Shares() port.ShareLinkRepository   { return shares{s.db} }

// mapErr converts GORM errors into domain errors.
func mapErr(err error, what string) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, gorm.ErrRecordNotFound):
		return domain.NotFound("%s not found", what)
	case errors.Is(err, gorm.ErrDuplicatedKey), strings.Contains(err.Error(), "UNIQUE constraint failed"):
		return domain.Conflict("%s already exists", what)
	default:
		return err
	}
}

func affected(res *gorm.DB, what string) error {
	if res.Error != nil {
		return mapErr(res.Error, what)
	}
	if res.RowsAffected == 0 {
		return domain.NotFound("%s not found", what)
	}
	return nil
}

// ---------- users ----------

type users struct{ db *gorm.DB }

func (r users) Create(ctx context.Context, u *domain.User) error {
	return mapErr(r.db.WithContext(ctx).Create(userFrom(u)).Error, "user")
}
func (r users) Update(ctx context.Context, u *domain.User) error {
	return mapErr(r.db.WithContext(ctx).Save(userFrom(u)).Error, "user")
}
func (r users) Get(ctx context.Context, id string) (*domain.User, error) {
	var rec userRecord
	if err := r.db.WithContext(ctx).First(&rec, "id = ?", id).Error; err != nil {
		return nil, mapErr(err, "user")
	}
	return rec.toDomain(), nil
}
func (r users) GetByEmail(ctx context.Context, email string) (*domain.User, error) {
	var rec userRecord
	if err := r.db.WithContext(ctx).First(&rec, "email = ?", email).Error; err != nil {
		return nil, mapErr(err, "user")
	}
	return rec.toDomain(), nil
}

// ---------- identities ----------

type identities struct{ db *gorm.DB }

func (r identities) Create(ctx context.Context, i *domain.Identity) error {
	rec := identityRecord{ID: i.ID, UserID: i.UserID, Provider: i.Provider, Subject: i.Subject, Email: i.Email, CreatedAt: i.CreatedAt}
	return mapErr(r.db.WithContext(ctx).Create(&rec).Error, "identity")
}
func (r identities) Get(ctx context.Context, provider, subject string) (*domain.Identity, error) {
	var rec identityRecord
	if err := r.db.WithContext(ctx).First(&rec, "provider = ? AND subject = ?", provider, subject).Error; err != nil {
		return nil, mapErr(err, "identity")
	}
	d := rec.toDomain()
	return &d, nil
}
func (r identities) ListByUser(ctx context.Context, userID string) ([]domain.Identity, error) {
	var recs []identityRecord
	if err := r.db.WithContext(ctx).Where("user_id = ?", userID).Order("created_at").Find(&recs).Error; err != nil {
		return nil, err
	}
	out := make([]domain.Identity, len(recs))
	for i, rec := range recs {
		out[i] = rec.toDomain()
	}
	return out, nil
}

// ---------- tenants ----------

type tenants struct{ db *gorm.DB }

func (r tenants) Create(ctx context.Context, t *domain.Tenant) error {
	rec := tenantRecord{ID: t.ID, Name: t.Name, Slug: t.Slug, Kind: string(t.Kind), OwnerID: t.OwnerID, CreatedAt: t.CreatedAt}
	return mapErr(r.db.WithContext(ctx).Create(&rec).Error, "workspace")
}
func (r tenants) Get(ctx context.Context, id string) (*domain.Tenant, error) {
	var rec tenantRecord
	if err := r.db.WithContext(ctx).First(&rec, "id = ? OR slug = ?", id, id).Error; err != nil {
		return nil, mapErr(err, "workspace")
	}
	return rec.toDomain(), nil
}
func (r tenants) GetPersonal(ctx context.Context, ownerID string) (*domain.Tenant, error) {
	var rec tenantRecord
	if err := r.db.WithContext(ctx).First(&rec, "owner_id = ? AND kind = ?", ownerID, domain.TenantPersonal).Error; err != nil {
		return nil, mapErr(err, "workspace")
	}
	return rec.toDomain(), nil
}
func (r tenants) SlugExists(ctx context.Context, slug string) (bool, error) {
	var n int64
	err := r.db.WithContext(ctx).Model(&tenantRecord{}).Where("slug = ?", slug).Count(&n).Error
	return n > 0, err
}

// ---------- memberships ----------

type memberships struct{ db *gorm.DB }

func (r memberships) Upsert(ctx context.Context, m *domain.Membership) error {
	rec := membershipRecord{TenantID: m.TenantID, UserID: m.UserID, Role: string(m.Role), CreatedAt: m.CreatedAt}
	return r.db.WithContext(ctx).Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "tenant_id"}, {Name: "user_id"}},
		DoUpdates: clause.AssignmentColumns([]string{"role"}),
	}).Create(&rec).Error
}
func (r memberships) Get(ctx context.Context, tenantID, userID string) (*domain.Membership, error) {
	var rec membershipRecord
	if err := r.db.WithContext(ctx).First(&rec, "tenant_id = ? AND user_id = ?", tenantID, userID).Error; err != nil {
		return nil, mapErr(err, "membership")
	}
	return &domain.Membership{TenantID: rec.TenantID, UserID: rec.UserID, Role: domain.Role(rec.Role), CreatedAt: rec.CreatedAt}, nil
}
func (r memberships) Delete(ctx context.Context, tenantID, userID string) error {
	return affected(r.db.WithContext(ctx).Delete(&membershipRecord{}, "tenant_id = ? AND user_id = ?", tenantID, userID), "membership")
}
func (r memberships) ListTenantsForUser(ctx context.Context, userID string) ([]domain.TenantWithRole, error) {
	type row struct {
		ID, Name, Slug, Kind, OwnerID, Role string
		CreatedAt                           time.Time
	}
	var rows []row
	err := r.db.WithContext(ctx).Table("tenants").
		Select("tenants.id, tenants.name, tenants.slug, tenants.kind, tenants.owner_id, tenants.created_at, memberships.role").
		Joins("JOIN memberships ON memberships.tenant_id = tenants.id").
		Where("memberships.user_id = ?", userID).
		Order("tenants.kind DESC, tenants.created_at").Scan(&rows).Error
	if err != nil {
		return nil, err
	}
	out := make([]domain.TenantWithRole, len(rows))
	for i, rw := range rows {
		t := tenantRecord{ID: rw.ID, Name: rw.Name, Slug: rw.Slug, Kind: rw.Kind, OwnerID: rw.OwnerID, CreatedAt: rw.CreatedAt}
		out[i] = domain.TenantWithRole{Tenant: *t.toDomain(), Role: domain.Role(rw.Role)}
	}
	return out, nil
}
func (r memberships) ListMembers(ctx context.Context, tenantID string) ([]domain.MemberView, error) {
	var out []domain.MemberView
	err := r.db.WithContext(ctx).Table("memberships").
		Select("users.id AS user_id, users.email, users.name, memberships.role").
		Joins("JOIN users ON users.id = memberships.user_id").
		Where("memberships.tenant_id = ?", tenantID).
		Order("memberships.created_at").Scan(&out).Error
	return out, err
}

// ---------- cloud connections ----------

type clouds struct{ db *gorm.DB }

func (r clouds) Upsert(ctx context.Context, c *domain.CloudConnection) error {
	return r.db.WithContext(ctx).Save(cloudFrom(c)).Error
}
func (r clouds) Get(ctx context.Context, tenantID, provider string) (*domain.CloudConnection, error) {
	var rec cloudRecord
	if err := r.db.WithContext(ctx).First(&rec, "tenant_id = ? AND provider = ?", tenantID, provider).Error; err != nil {
		return nil, mapErr(err, "cloud connection")
	}
	return rec.toDomain(), nil
}
func (r clouds) Delete(ctx context.Context, tenantID, provider string) error {
	return affected(r.db.WithContext(ctx).Delete(&cloudRecord{}, "tenant_id = ? AND provider = ?", tenantID, provider), "cloud connection")
}

// ---------- projects ----------

type projects struct{ db *gorm.DB }

func (r projects) Create(ctx context.Context, p *domain.Project) error {
	return mapErr(r.db.WithContext(ctx).Create(projectFrom(p)).Error, "project")
}
func (r projects) Update(ctx context.Context, p *domain.Project) error {
	return mapErr(r.db.WithContext(ctx).Save(projectFrom(p)).Error, "project")
}
func (r projects) Delete(ctx context.Context, tenantID, id string) error {
	return r.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := tx.Delete(&shareRecord{}, "tenant_id = ? AND project_id = ?", tenantID, id).Error; err != nil {
			return err
		}
		if err := tx.Delete(&environmentRecord{}, "tenant_id = ? AND project_id = ?", tenantID, id).Error; err != nil {
			return err
		}
		return affected(tx.Delete(&projectRecord{}, "tenant_id = ? AND id = ?", tenantID, id), "project")
	})
}
func (r projects) Get(ctx context.Context, tenantID, idOrSlug string) (*domain.Project, error) {
	var rec projectRecord
	if err := r.db.WithContext(ctx).First(&rec, "tenant_id = ? AND (id = ? OR slug = ?)", tenantID, idOrSlug, idOrSlug).Error; err != nil {
		return nil, mapErr(err, "project")
	}
	d := rec.toDomain()
	return &d, nil
}
func (r projects) List(ctx context.Context, tenantID string) ([]domain.Project, error) {
	var recs []projectRecord
	if err := r.db.WithContext(ctx).Where("tenant_id = ?", tenantID).Order("name").Find(&recs).Error; err != nil {
		return nil, err
	}
	out := make([]domain.Project, len(recs))
	for i, rec := range recs {
		out[i] = rec.toDomain()
	}
	return out, nil
}

// ---------- environments ----------

type environments struct{ db *gorm.DB }

func (r environments) Create(ctx context.Context, e *domain.Environment) error {
	rec := environmentRecord{ID: e.ID, TenantID: e.TenantID, ProjectID: e.ProjectID, Name: e.Name, Slug: e.Slug, CreatedAt: e.CreatedAt}
	return mapErr(r.db.WithContext(ctx).Create(&rec).Error, "environment")
}
func (r environments) Delete(ctx context.Context, tenantID, id string) error {
	return r.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := tx.Delete(&shareRecord{}, "tenant_id = ? AND environment_id = ?", tenantID, id).Error; err != nil {
			return err
		}
		return affected(tx.Delete(&environmentRecord{}, "tenant_id = ? AND id = ?", tenantID, id), "environment")
	})
}
func (r environments) Get(ctx context.Context, tenantID, projectID, idOrSlug string) (*domain.Environment, error) {
	var rec environmentRecord
	err := r.db.WithContext(ctx).First(&rec, "tenant_id = ? AND project_id = ? AND (id = ? OR slug = ?)",
		tenantID, projectID, idOrSlug, idOrSlug).Error
	if err != nil {
		return nil, mapErr(err, "environment")
	}
	d := rec.toDomain()
	return &d, nil
}
func (r environments) List(ctx context.Context, tenantID, projectID string) ([]domain.Environment, error) {
	var recs []environmentRecord
	if err := r.db.WithContext(ctx).Where("tenant_id = ? AND project_id = ?", tenantID, projectID).Order("created_at, name").Find(&recs).Error; err != nil {
		return nil, err
	}
	out := make([]domain.Environment, len(recs))
	for i, rec := range recs {
		out[i] = rec.toDomain()
	}
	return out, nil
}

// ---------- secrets (metadata only) ----------

type secrets struct{ db *gorm.DB }

func (r secrets) Create(ctx context.Context, s *domain.Secret) error {
	return mapErr(r.db.WithContext(ctx).Create(secretFrom(s)).Error, "secret "+s.Key)
}
func (r secrets) Update(ctx context.Context, s *domain.Secret) error {
	return mapErr(r.db.WithContext(ctx).Save(secretFrom(s)).Error, "secret "+s.Key)
}
func (r secrets) Delete(ctx context.Context, tenantID, id string) error {
	return affected(r.db.WithContext(ctx).Delete(&secretRecord{}, "tenant_id = ? AND id = ?", tenantID, id), "secret")
}
func (r secrets) GetByKey(ctx context.Context, tenantID, environmentID, key string) (*domain.Secret, error) {
	var rec secretRecord
	if err := r.db.WithContext(ctx).First(&rec, "tenant_id = ? AND environment_id = ? AND key = ?", tenantID, environmentID, key).Error; err != nil {
		return nil, mapErr(err, "secret "+key)
	}
	d := rec.toDomain()
	return &d, nil
}
func (r secrets) list(ctx context.Context, where string, args ...any) ([]domain.Secret, error) {
	var recs []secretRecord
	if err := r.db.WithContext(ctx).Where(where, args...).Order("key").Find(&recs).Error; err != nil {
		return nil, err
	}
	out := make([]domain.Secret, len(recs))
	for i, rec := range recs {
		out[i] = rec.toDomain()
	}
	return out, nil
}
func (r secrets) List(ctx context.Context, tenantID, environmentID string) ([]domain.Secret, error) {
	return r.list(ctx, "tenant_id = ? AND environment_id = ?", tenantID, environmentID)
}
func (r secrets) ListByProject(ctx context.Context, tenantID, projectID string) ([]domain.Secret, error) {
	return r.list(ctx, "tenant_id = ? AND project_id = ?", tenantID, projectID)
}

// ---------- access tokens ----------

type tokens struct{ db *gorm.DB }

func (r tokens) Create(ctx context.Context, t *domain.AccessToken) error {
	rec := tokenRecord{ID: t.ID, UserID: t.UserID, TenantID: t.TenantID, Name: t.Name, Prefix: t.Prefix, Hash: t.Hash,
		ReadOnly: t.ReadOnly, ExpiresAt: t.ExpiresAt, LastUsedAt: t.LastUsedAt, CreatedAt: t.CreatedAt}
	return mapErr(r.db.WithContext(ctx).Create(&rec).Error, "access token")
}
func (r tokens) GetByHash(ctx context.Context, hash string) (*domain.AccessToken, error) {
	var rec tokenRecord
	if err := r.db.WithContext(ctx).First(&rec, "hash = ?", hash).Error; err != nil {
		return nil, mapErr(err, "access token")
	}
	d := rec.toDomain()
	return &d, nil
}
func (r tokens) List(ctx context.Context, userID string) ([]domain.AccessToken, error) {
	var recs []tokenRecord
	if err := r.db.WithContext(ctx).Where("user_id = ?", userID).Order("created_at DESC").Find(&recs).Error; err != nil {
		return nil, err
	}
	out := make([]domain.AccessToken, len(recs))
	for i, rec := range recs {
		out[i] = rec.toDomain()
	}
	return out, nil
}
func (r tokens) Delete(ctx context.Context, userID, id string) error {
	return affected(r.db.WithContext(ctx).Delete(&tokenRecord{}, "user_id = ? AND id = ?", userID, id), "access token")
}
func (r tokens) TouchLastUsed(ctx context.Context, id string, at time.Time) error {
	return r.db.WithContext(ctx).Model(&tokenRecord{}).Where("id = ?", id).Update("last_used_at", at).Error
}

// ---------- share links ----------

type shares struct{ db *gorm.DB }

func (r shares) Create(ctx context.Context, s *domain.ShareLink) error {
	return mapErr(r.db.WithContext(ctx).Create(shareFrom(s)).Error, "share link")
}
func (r shares) GetByHash(ctx context.Context, hash string) (*domain.ShareLink, error) {
	var rec shareRecord
	if err := r.db.WithContext(ctx).First(&rec, "token_hash = ?", hash).Error; err != nil {
		return nil, mapErr(err, "share link")
	}
	d := rec.toDomain()
	return &d, nil
}
func (r shares) List(ctx context.Context, tenantID, environmentID string) ([]domain.ShareLink, error) {
	var recs []shareRecord
	if err := r.db.WithContext(ctx).Where("tenant_id = ? AND environment_id = ?", tenantID, environmentID).
		Order("created_at DESC").Find(&recs).Error; err != nil {
		return nil, err
	}
	out := make([]domain.ShareLink, len(recs))
	for i, rec := range recs {
		out[i] = rec.toDomain()
	}
	return out, nil
}
func (r shares) Revoke(ctx context.Context, tenantID, id string, at time.Time) error {
	return affected(r.db.WithContext(ctx).Model(&shareRecord{}).
		Where("tenant_id = ? AND id = ? AND revoked_at IS NULL", tenantID, id).
		Update("revoked_at", at), "share link")
}
func (r shares) IncrementViews(ctx context.Context, id string, maxViews int) (bool, error) {
	q := r.db.WithContext(ctx).Model(&shareRecord{}).Where("id = ?", id)
	if maxViews > 0 {
		q = q.Where("views < ?", maxViews)
	}
	res := q.Update("views", gorm.Expr("views + 1"))
	return res.RowsAffected == 1, res.Error
}

package service

import (
	"context"
	"strings"
	"time"

	"github.com/linustorvaldss/vaulty/internal/domain"
	"github.com/linustorvaldss/vaulty/internal/parser"
)

const (
	defaultShareTTL = 24 * time.Hour
	maxShareTTL     = 30 * 24 * time.Hour
)

type ShareInput struct {
	Keys           []string `json:"keys"`             // empty = whole environment
	ExpiresInHours int      `json:"expires_in_hours"` // default 24, max 720
	MaxViews       int      `json:"max_views"`        // 0 = unlimited
	Passphrase     string   `json:"passphrase"`
}

type CreatedShare struct {
	domain.ShareLink
	Token  string `json:"token"`   // shown only once
	URL    string `json:"url"`     // web page that renders the share
	APIURL string `json:"api_url"` // raw endpoint (?format=dotenv|json|yaml|shell)
}

// CreateShareLink creates a link that exposes an environment (or a subset of
// its keys) without authentication until it expires, is revoked or runs out
// of views. Values are read live, so updates are reflected.
func (s *Service) CreateShareLink(ctx context.Context, sc *Scope, projectRef, envRef string, in ShareInput) (*CreatedShare, error) {
	if err := sc.can(domain.RoleMember, true); err != nil {
		return nil, err
	}
	_, env, err := s.resolveEnv(ctx, sc, projectRef, envRef)
	if err != nil {
		return nil, err
	}
	ttl := defaultShareTTL
	if in.ExpiresInHours != 0 {
		ttl = time.Duration(in.ExpiresInHours) * time.Hour
	}
	if ttl <= 0 || ttl > maxShareTTL {
		return nil, domain.Invalid("expires_in_hours must be between 1 and %d", int(maxShareTTL.Hours()))
	}
	if in.MaxViews < 0 {
		return nil, domain.Invalid("max_views cannot be negative")
	}
	for _, k := range in.Keys {
		if _, err := s.Store.Secrets().GetByKey(ctx, sc.TenantID(), env.ID, k); err != nil {
			return nil, domain.Invalid("secret %q does not exist in %s", k, env.Slug)
		}
	}

	raw := randomToken(domain.ShareTokenPrefix)
	link := &domain.ShareLink{
		ID: newID(), TenantID: sc.TenantID(), ProjectID: env.ProjectID, EnvironmentID: env.ID,
		TokenHash: hashToken(raw), Keys: in.Keys, MaxViews: in.MaxViews,
		ExpiresAt: now().Add(ttl), CreatedBy: sc.UserID(), CreatedAt: now(),
	}
	if in.Passphrase != "" {
		if link.PassphraseHash, err = s.Hasher.Hash(in.Passphrase); err != nil {
			return nil, err
		}
		link.HasPassphrase = true
	}
	if err := s.Store.Shares().Create(ctx, link); err != nil {
		return nil, err
	}
	return &CreatedShare{
		ShareLink: *link,
		Token:     raw,
		URL:       strings.TrimRight(s.AppURL, "/") + "/share/" + raw,
		APIURL:    strings.TrimRight(s.APIURL, "/") + "/api/v1/shared/" + raw,
	}, nil
}

func (s *Service) ListShareLinks(ctx context.Context, sc *Scope, projectRef, envRef string) ([]domain.ShareLink, error) {
	if err := sc.can(domain.RoleMember, false); err != nil {
		return nil, err
	}
	_, env, err := s.resolveEnv(ctx, sc, projectRef, envRef)
	if err != nil {
		return nil, err
	}
	return s.Store.Shares().List(ctx, sc.TenantID(), env.ID)
}

func (s *Service) RevokeShareLink(ctx context.Context, sc *Scope, id string) error {
	if err := sc.can(domain.RoleMember, true); err != nil {
		return err
	}
	return s.Store.Shares().Revoke(ctx, sc.TenantID(), id, now())
}

type SharedEnv struct {
	Project     string         `json:"project"`
	Environment string         `json:"environment"`
	ExpiresAt   time.Time      `json:"expires_at"`
	ViewsLeft   *int           `json:"views_left,omitempty"`
	Secrets     []parser.Entry `json:"secrets"`
}

// OpenShareLink is the public (unauthenticated) read of a share link.
func (s *Service) OpenShareLink(ctx context.Context, token, passphrase string) (*SharedEnv, error) {
	if !strings.HasPrefix(token, domain.ShareTokenPrefix) {
		return nil, domain.NotFound("share link not found")
	}
	link, err := s.Store.Shares().GetByHash(ctx, hashToken(token))
	if err != nil {
		return nil, domain.NotFound("share link not found")
	}
	switch {
	case link.RevokedAt != nil:
		return nil, domain.Gone("share link was revoked")
	case now().After(link.ExpiresAt):
		return nil, domain.Gone("share link expired")
	}
	if link.HasPassphrase && !s.Hasher.Compare(link.PassphraseHash, passphrase) {
		return nil, domain.Unauthorized("passphrase required")
	}
	ok, err := s.Store.Shares().IncrementViews(ctx, link.ID, link.MaxViews)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, domain.Gone("share link reached its view limit")
	}

	project, err := s.Store.Projects().Get(ctx, link.TenantID, link.ProjectID)
	if err != nil {
		return nil, err
	}
	env, err := s.Store.Environments().Get(ctx, link.TenantID, link.ProjectID, link.EnvironmentID)
	if err != nil {
		return nil, err
	}
	secrets, err := s.Store.Secrets().List(ctx, link.TenantID, env.ID)
	if err != nil {
		return nil, err
	}
	var only map[string]bool
	if len(link.Keys) > 0 {
		only = map[string]bool{}
		for _, k := range link.Keys {
			only[k] = true
		}
		filtered := secrets[:0]
		for _, sec := range secrets {
			if only[sec.Key] {
				filtered = append(filtered, sec)
			}
		}
		secrets = filtered
	}
	if len(secrets) > 0 {
		if err := s.fillValues(ctx, secrets); err != nil {
			return nil, err
		}
	}
	out := &SharedEnv{Project: project.Name, Environment: env.Name, ExpiresAt: link.ExpiresAt, Secrets: toEntries(secrets, only)}
	if link.MaxViews > 0 {
		left := link.MaxViews - link.Views - 1
		out.ViewsLeft = &left
	}
	return out, nil
}

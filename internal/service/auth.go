package service

import (
	"context"
	"fmt"
	"net/mail"
	"sort"
	"strings"
	"time"

	"github.com/linustorvaldss/vaulty/internal/domain"
	"github.com/linustorvaldss/vaulty/internal/port"
)

const ProviderEmail = "email"

type Session struct {
	Token     string       `json:"token"`
	ExpiresAt time.Time    `json:"expires_at"`
	User      *domain.User `json:"user"`
}

type RegisterInput struct {
	Name     string `json:"name"`
	Email    string `json:"email"`
	Password string `json:"password"`
}

func normalizeEmail(e string) (string, error) {
	e = strings.ToLower(strings.TrimSpace(e))
	addr, err := mail.ParseAddress(e)
	if err != nil || addr.Address != e {
		return "", domain.Invalid("invalid email address")
	}
	return e, nil
}

// Register creates an email/password account and its personal tenant.
func (s *Service) Register(ctx context.Context, in RegisterInput) (*Session, error) {
	email, err := normalizeEmail(in.Email)
	if err != nil {
		return nil, err
	}
	if len(in.Password) < 10 {
		return nil, domain.Invalid("password must be at least 10 characters")
	}
	if len(in.Password) > 72 {
		return nil, domain.Invalid("password must be at most 72 characters")
	}
	name := strings.TrimSpace(in.Name)
	if name == "" {
		name = strings.Split(email, "@")[0]
	}
	hash, err := s.Hasher.Hash(in.Password)
	if err != nil {
		return nil, err
	}

	var user *domain.User
	err = s.Store.WithTx(ctx, func(tx port.Store) error {
		if _, err := tx.Users().GetByEmail(ctx, email); err == nil {
			return domain.Conflict("an account with this email already exists")
		} else if domain.KindOf(err) != domain.KindNotFound {
			return err
		}
		u, err := s.createUserWithTenant(ctx, tx, &domain.User{Email: email, Name: name, PasswordHash: hash})
		if err != nil {
			return err
		}
		user = u
		return tx.Identities().Create(ctx, &domain.Identity{
			ID: newID(), UserID: u.ID, Provider: ProviderEmail, Subject: email, Email: email, CreatedAt: now(),
		})
	})
	if err != nil {
		return nil, err
	}
	return s.issueSession(user)
}

// Login authenticates with email and password.
func (s *Service) Login(ctx context.Context, email, password string) (*Session, error) {
	email = strings.ToLower(strings.TrimSpace(email))
	u, err := s.Store.Users().GetByEmail(ctx, email)
	if err != nil || u.PasswordHash == "" || !s.Hasher.Compare(u.PasswordHash, password) {
		if err != nil && domain.KindOf(err) != domain.KindNotFound {
			return nil, err
		}
		return nil, domain.Unauthorized("invalid email or password")
	}
	return s.issueSession(u)
}

// ---------- OAuth (Google, GitHub, GitLab, generic OAuth2/OIDC) ----------

func (s *Service) ProviderNames() []string {
	names := []string{ProviderEmail}
	for n := range s.Providers {
		names = append(names, n)
	}
	sort.Strings(names[1:])
	return names
}

func (s *Service) callbackURL(provider string) string {
	return strings.TrimRight(s.APIURL, "/") + "/api/v1/auth/oauth/" + provider + "/callback"
}

func (s *Service) redirectAllowed(u string) bool {
	if u == "" {
		return true
	}
	for _, p := range s.AllowedRedirects {
		if p != "" && (u == p || strings.HasPrefix(u, strings.TrimRight(p, "/")+"/")) {
			return true
		}
	}
	return false
}

// OAuthStart returns the provider URL to redirect the browser to, and a
// nonce the HTTP adapter must bind to the browser (cookie).
func (s *Service) OAuthStart(provider, redirectAfter string) (authURL, nonce string, err error) {
	p, ok := s.Providers[provider]
	if !ok {
		return "", "", domain.NotFound("auth provider %q is not configured", provider)
	}
	if !s.redirectAllowed(redirectAfter) {
		return "", "", domain.Invalid("redirect_uri is not allowed")
	}
	nonce = randomToken("")
	state, err := s.Sessions.SignState(map[string]string{"p": provider, "r": redirectAfter, "n": nonce}, 10*time.Minute)
	if err != nil {
		return "", "", err
	}
	return p.AuthCodeURL(state, s.callbackURL(provider)), nonce, nil
}

// OAuthCallback finishes the flow and returns a session plus where to send
// the browser afterwards.
func (s *Service) OAuthCallback(ctx context.Context, provider, code, state, nonce string) (*Session, string, error) {
	p, ok := s.Providers[provider]
	if !ok {
		return nil, "", domain.NotFound("auth provider %q is not configured", provider)
	}
	claims, err := s.Sessions.ParseState(state)
	if err != nil || claims["p"] != provider || nonce == "" || claims["n"] != nonce {
		return nil, "", domain.Unauthorized("invalid or expired OAuth state")
	}
	if code == "" {
		return nil, "", domain.Invalid("missing authorization code")
	}
	profile, err := p.Exchange(ctx, code, s.callbackURL(provider))
	if err != nil {
		return nil, "", domain.Unauthorized("oauth exchange failed: %v", err)
	}
	user, err := s.loginWithProfile(ctx, profile)
	if err != nil {
		return nil, "", err
	}
	sess, err := s.issueSession(user)
	return sess, claims["r"], err
}

func (s *Service) loginWithProfile(ctx context.Context, p *port.ExternalProfile) (*domain.User, error) {
	if p.Subject == "" {
		return nil, domain.Unauthorized("provider returned no user id")
	}
	var user *domain.User
	err := s.Store.WithTx(ctx, func(tx port.Store) error {
		// 1. Known identity.
		if id, err := tx.Identities().Get(ctx, p.Provider, p.Subject); err == nil {
			u, err := tx.Users().Get(ctx, id.UserID)
			user = u
			return err
		} else if domain.KindOf(err) != domain.KindNotFound {
			return err
		}

		email, err := normalizeEmail(p.Email)
		if err != nil {
			return domain.Unauthorized("%s account has no usable email address", p.Provider)
		}

		// 2. Existing user with same email: link only if the provider verified it.
		existing, err := tx.Users().GetByEmail(ctx, email)
		switch {
		case err == nil:
			if !p.EmailVerified {
				return domain.Conflict("an account with this email exists; sign in with your original method")
			}
			user = existing
			if !existing.EmailVerified {
				existing.EmailVerified = true
				existing.UpdatedAt = now()
				if err := tx.Users().Update(ctx, existing); err != nil {
					return err
				}
			}
		case domain.KindOf(err) == domain.KindNotFound:
			// 3. New user + personal tenant.
			name := p.Name
			if name == "" {
				name = strings.Split(email, "@")[0]
			}
			user, err = s.createUserWithTenant(ctx, tx, &domain.User{
				Email: email, Name: name, AvatarURL: p.AvatarURL, EmailVerified: p.EmailVerified,
			})
			if err != nil {
				return err
			}
		default:
			return err
		}
		return tx.Identities().Create(ctx, &domain.Identity{
			ID: newID(), UserID: user.ID, Provider: p.Provider, Subject: p.Subject, Email: email, CreatedAt: now(),
		})
	})
	return user, err
}

// createUserWithTenant creates the user, their personal tenant and owner membership.
func (s *Service) createUserWithTenant(ctx context.Context, tx port.Store, u *domain.User) (*domain.User, error) {
	t := now()
	u.ID, u.CreatedAt, u.UpdatedAt = newID(), t, t
	if err := tx.Users().Create(ctx, u); err != nil {
		return nil, err
	}
	slug, err := uniqueTenantSlug(ctx, tx, u.Name)
	if err != nil {
		return nil, err
	}
	tenant := &domain.Tenant{
		ID: newID(), Name: fmt.Sprintf("%s's workspace", u.Name), Slug: slug,
		Kind: domain.TenantPersonal, OwnerID: u.ID, CreatedAt: t,
	}
	if err := tx.Tenants().Create(ctx, tenant); err != nil {
		return nil, err
	}
	if err := tx.Memberships().Upsert(ctx, &domain.Membership{TenantID: tenant.ID, UserID: u.ID, Role: domain.RoleOwner, CreatedAt: t}); err != nil {
		return nil, err
	}
	return u, nil
}

func uniqueTenantSlug(ctx context.Context, tx port.Store, name string) (string, error) {
	base := domain.Slugify(name)
	if base == "" {
		base = "workspace"
	}
	slug := base
	for i := 0; i < 5; i++ {
		exists, err := tx.Tenants().SlugExists(ctx, slug)
		if err != nil {
			return "", err
		}
		if !exists {
			return slug, nil
		}
		slug = base + "-" + strings.ToLower(randomToken("")[:6])
	}
	return base + "-" + newID()[:8], nil
}

func (s *Service) issueSession(u *domain.User) (*Session, error) {
	tok, exp, err := s.Sessions.Issue(port.Claims{UserID: u.ID, Email: u.Email})
	if err != nil {
		return nil, err
	}
	return &Session{Token: tok, ExpiresAt: exp, User: u}, nil
}

// Authenticate resolves a bearer credential: a session JWT or an access token.
func (s *Service) Authenticate(ctx context.Context, bearer string) (*Principal, error) {
	if bearer == "" {
		return nil, domain.Unauthorized("missing credentials")
	}
	if strings.HasPrefix(bearer, domain.AccessTokenPrefix) {
		return s.authenticateAccessToken(ctx, bearer)
	}
	claims, err := s.Sessions.Parse(bearer)
	if err != nil {
		return nil, domain.Unauthorized("invalid or expired session")
	}
	u, err := s.Store.Users().Get(ctx, claims.UserID)
	if err != nil {
		return nil, domain.Unauthorized("invalid or expired session")
	}
	return &Principal{User: u}, nil
}

func (s *Service) authenticateAccessToken(ctx context.Context, raw string) (*Principal, error) {
	t, err := s.Store.Tokens().GetByHash(ctx, hashToken(raw))
	if err != nil {
		return nil, domain.Unauthorized("invalid access token")
	}
	if t.ExpiresAt != nil && now().After(*t.ExpiresAt) {
		return nil, domain.Unauthorized("access token expired")
	}
	u, err := s.Store.Users().Get(ctx, t.UserID)
	if err != nil {
		return nil, domain.Unauthorized("invalid access token")
	}
	if err := s.Store.Tokens().TouchLastUsed(ctx, t.ID, now()); err != nil {
		s.Logger.Warn("touch token last_used", "err", err)
	}
	return &Principal{User: u, TokenID: t.ID, TokenTenantID: t.TenantID, ReadOnly: t.ReadOnly}, nil
}

type MeView struct {
	User       *domain.User            `json:"user"`
	Tenants    []domain.TenantWithRole `json:"tenants"`
	Identities []domain.Identity       `json:"identities"`
	// Token info when authenticated with an access token.
	TokenTenantID string `json:"token_tenant_id,omitempty"`
	ReadOnly      bool   `json:"read_only,omitempty"`
}

func (s *Service) Me(ctx context.Context, p *Principal) (*MeView, error) {
	tenants, err := s.Store.Memberships().ListTenantsForUser(ctx, p.User.ID)
	if err != nil {
		return nil, err
	}
	ids, err := s.Store.Identities().ListByUser(ctx, p.User.ID)
	if err != nil {
		return nil, err
	}
	return &MeView{User: p.User, Tenants: tenants, Identities: ids, TokenTenantID: p.TokenTenantID, ReadOnly: p.ReadOnly}, nil
}

// Package oauth implements port.OAuthProvider for Google, GitHub, GitLab and
// any generic OAuth 2.0 / OpenID Connect provider.
package oauth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"golang.org/x/oauth2"

	"github.com/linustorvaldss/vaulty/internal/port"
)

type Credentials struct {
	ClientID     string
	ClientSecret string
}

// Provider is a configurable OAuth2 authorization-code provider.
type Provider struct {
	name    string
	conf    oauth2.Config
	profile func(ctx context.Context, c *http.Client) (*port.ExternalProfile, error)
}

var _ port.OAuthProvider = (*Provider)(nil)

func (p *Provider) Name() string { return p.name }

func (p *Provider) config(redirectURI string) *oauth2.Config {
	c := p.conf
	c.RedirectURL = redirectURI
	return &c
}

func (p *Provider) AuthCodeURL(state, redirectURI string) string {
	return p.config(redirectURI).AuthCodeURL(state, oauth2.AccessTypeOnline)
}

func (p *Provider) Exchange(ctx context.Context, code, redirectURI string) (*port.ExternalProfile, error) {
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	cfg := p.config(redirectURI)
	tok, err := cfg.Exchange(ctx, code)
	if err != nil {
		return nil, err
	}
	prof, err := p.profile(ctx, cfg.Client(ctx, tok))
	if err != nil {
		return nil, err
	}
	prof.Provider = p.name
	return prof, nil
}

func getJSON(ctx context.Context, c *http.Client, url string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	res, err := c.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return fmt.Errorf("GET %s: %s", url, res.Status)
	}
	return json.NewDecoder(res.Body).Decode(out)
}

// oidcUserInfo reads a standard OpenID Connect userinfo response.
func oidcUserInfo(url string) func(context.Context, *http.Client) (*port.ExternalProfile, error) {
	return func(ctx context.Context, c *http.Client) (*port.ExternalProfile, error) {
		var u map[string]any
		if err := getJSON(ctx, c, url, &u); err != nil {
			return nil, err
		}
		p := &port.ExternalProfile{
			Subject:   str(u, "sub", "id"),
			Email:     str(u, "email"),
			Name:      str(u, "name", "preferred_username", "nickname"),
			AvatarURL: str(u, "picture", "avatar_url"),
		}
		switch v := u["email_verified"].(type) {
		case bool:
			p.EmailVerified = v
		case string:
			p.EmailVerified = v == "true"
		}
		if p.Subject == "" {
			return nil, errors.New("userinfo response has no subject")
		}
		return p, nil
	}
}

func str(m map[string]any, keys ...string) string {
	for _, k := range keys {
		switch v := m[k].(type) {
		case string:
			if v != "" {
				return v
			}
		case float64:
			return fmt.Sprintf("%.0f", v)
		}
	}
	return ""
}

// ---------- concrete providers ----------

func Google(c Credentials) *Provider {
	return &Provider{
		name: "google",
		conf: oauth2.Config{
			ClientID: c.ClientID, ClientSecret: c.ClientSecret,
			Endpoint: oauth2.Endpoint{
				AuthURL:  "https://accounts.google.com/o/oauth2/v2/auth",
				TokenURL: "https://oauth2.googleapis.com/token",
			},
			Scopes: []string{"openid", "email", "profile"},
		},
		profile: oidcUserInfo("https://openidconnect.googleapis.com/v1/userinfo"),
	}
}

func GitHub(c Credentials) *Provider {
	return &Provider{
		name: "github",
		conf: oauth2.Config{
			ClientID: c.ClientID, ClientSecret: c.ClientSecret,
			Endpoint: oauth2.Endpoint{
				AuthURL:  "https://github.com/login/oauth/authorize",
				TokenURL: "https://github.com/login/oauth/access_token",
			},
			Scopes: []string{"read:user", "user:email"},
		},
		profile: githubProfile,
	}
}

func githubProfile(ctx context.Context, c *http.Client) (*port.ExternalProfile, error) {
	var u struct {
		ID        int64  `json:"id"`
		Login     string `json:"login"`
		Name      string `json:"name"`
		AvatarURL string `json:"avatar_url"`
	}
	if err := getJSON(ctx, c, "https://api.github.com/user", &u); err != nil {
		return nil, err
	}
	// Public profile email may be hidden; use the primary verified one.
	var emails []struct {
		Email    string `json:"email"`
		Primary  bool   `json:"primary"`
		Verified bool   `json:"verified"`
	}
	if err := getJSON(ctx, c, "https://api.github.com/user/emails", &emails); err != nil {
		return nil, err
	}
	p := &port.ExternalProfile{Subject: fmt.Sprint(u.ID), Name: u.Name, AvatarURL: u.AvatarURL}
	if p.Name == "" {
		p.Name = u.Login
	}
	for _, e := range emails {
		if e.Primary {
			p.Email, p.EmailVerified = e.Email, e.Verified
		}
	}
	return p, nil
}

// GitLab supports gitlab.com and self-managed instances (baseURL).
func GitLab(c Credentials, baseURL string) *Provider {
	if baseURL == "" {
		baseURL = "https://gitlab.com"
	}
	baseURL = strings.TrimRight(baseURL, "/")
	return &Provider{
		name: "gitlab",
		conf: oauth2.Config{
			ClientID: c.ClientID, ClientSecret: c.ClientSecret,
			Endpoint: oauth2.Endpoint{AuthURL: baseURL + "/oauth/authorize", TokenURL: baseURL + "/oauth/token"},
			Scopes:   []string{"openid", "email", "profile"},
		},
		profile: oidcUserInfo(baseURL + "/oauth/userinfo"),
	}
}

// GenericConfig configures any OAuth 2.0 / OIDC provider (Okta, Auth0,
// Keycloak, Azure AD, ...). The userinfo endpoint must return OIDC claims
// (sub, email, email_verified, name, picture).
type GenericConfig struct {
	Name        string
	Credentials Credentials
	AuthURL     string
	TokenURL    string
	UserInfoURL string
	Scopes      []string
}

func Generic(c GenericConfig) *Provider {
	if c.Name == "" {
		c.Name = "oidc"
	}
	if len(c.Scopes) == 0 {
		c.Scopes = []string{"openid", "email", "profile"}
	}
	return &Provider{
		name: c.Name,
		conf: oauth2.Config{
			ClientID: c.Credentials.ClientID, ClientSecret: c.Credentials.ClientSecret,
			Endpoint: oauth2.Endpoint{AuthURL: c.AuthURL, TokenURL: c.TokenURL},
			Scopes:   c.Scopes,
		},
		profile: oidcUserInfo(c.UserInfoURL),
	}
}

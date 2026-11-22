// Package client is a small Go client for the Vaulty REST API, used by the CLI.
package client

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/url"
	"path/filepath"
	"strings"
	"time"
)

type Client struct {
	BaseURL string
	Token   string
	Tenant  string
	HTTP    *http.Client
}

func New(baseURL, token string) *Client {
	return &Client{BaseURL: strings.TrimRight(baseURL, "/"), Token: token, HTTP: &http.Client{Timeout: 60 * time.Second}}
}

type APIError struct {
	Status  int
	Code    string
	Message string
}

func (e *APIError) Error() string { return fmt.Sprintf("%s (HTTP %d)", e.Message, e.Status) }

func (c *Client) do(ctx context.Context, method, path string, query url.Values, body io.Reader, ctype string) ([]byte, error) {
	u := c.BaseURL + "/api/v1" + path
	if len(query) > 0 {
		u += "?" + query.Encode()
	}
	req, err := http.NewRequestWithContext(ctx, method, u, body)
	if err != nil {
		return nil, err
	}
	if c.Token != "" {
		req.Header.Set("Authorization", "Bearer "+c.Token)
	}
	if c.Tenant != "" {
		req.Header.Set("X-Tenant-ID", c.Tenant)
	}
	if ctype != "" {
		req.Header.Set("Content-Type", ctype)
	}
	req.Header.Set("User-Agent", "vaulty-cli")
	res, err := c.HTTP.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	data, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, err
	}
	if res.StatusCode >= 300 {
		var e struct {
			Error struct {
				Code    string `json:"code"`
				Message string `json:"message"`
			} `json:"error"`
		}
		_ = json.Unmarshal(data, &e)
		if e.Error.Message == "" {
			e.Error.Message = res.Status
		}
		return nil, &APIError{Status: res.StatusCode, Code: e.Error.Code, Message: e.Error.Message}
	}
	return data, nil
}

func (c *Client) json(ctx context.Context, method, path string, in, out any) error {
	var body io.Reader
	ctype := ""
	if in != nil {
		b, err := json.Marshal(in)
		if err != nil {
			return err
		}
		body, ctype = bytes.NewReader(b), "application/json"
	}
	data, err := c.do(ctx, method, path, nil, body, ctype)
	if err != nil || out == nil {
		return err
	}
	return json.Unmarshal(data, out)
}

func envPath(project, env string) string {
	return "/projects/" + url.PathEscape(project) + "/environments/" + url.PathEscape(env)
}

// ---------- typed responses (only fields the CLI needs) ----------

type Me struct {
	User struct {
		ID    string `json:"id"`
		Email string `json:"email"`
		Name  string `json:"name"`
	} `json:"user"`
	Tenants []struct {
		ID   string `json:"id"`
		Name string `json:"name"`
		Slug string `json:"slug"`
		Kind string `json:"kind"`
		Role string `json:"role"`
	} `json:"tenants"`
	TokenTenantID string `json:"token_tenant_id"`
	ReadOnly      bool   `json:"read_only"`
}

type Project struct {
	ID           string `json:"id"`
	Name         string `json:"name"`
	Slug         string `json:"slug"`
	Environments []struct {
		Name string `json:"name"`
		Slug string `json:"slug"`
	} `json:"environments"`
}

type Secret struct {
	Key       string    `json:"key"`
	Type      string    `json:"type"`
	Version   int       `json:"version"`
	UpdatedAt time.Time `json:"updated_at"`
	Value     *string   `json:"value"`
}

type ImportItem struct {
	Key    string `json:"key"`
	Action string `json:"action"`
	Line   int    `json:"line"`
	Error  string `json:"error"`
}

type ImportResult struct {
	Format  string         `json:"format"`
	DryRun  bool           `json:"dry_run"`
	Items   []ImportItem   `json:"items"`
	Summary map[string]int `json:"summary"`
	Issues  []struct {
		Line    int    `json:"line"`
		Message string `json:"message"`
	} `json:"issues"`
}

// ---------- calls ----------

func (c *Client) Me(ctx context.Context) (*Me, error) {
	var m Me
	return &m, c.json(ctx, http.MethodGet, "/me", nil, &m)
}

func (c *Client) Projects(ctx context.Context) ([]Project, error) {
	var r struct{ Items []Project }
	err := c.json(ctx, http.MethodGet, "/projects", nil, &r)
	return r.Items, err
}

func (c *Client) Project(ctx context.Context, ref string) (*Project, error) {
	var p Project
	return &p, c.json(ctx, http.MethodGet, "/projects/"+url.PathEscape(ref), nil, &p)
}

// Export returns the environment rendered in format (dotenv, json, yaml, shell).
func (c *Client) Export(ctx context.Context, project, env, format string) ([]byte, error) {
	return c.do(ctx, http.MethodGet, envPath(project, env)+"/secrets/export", url.Values{"format": {format}}, nil, "")
}

// ExportMap returns the environment as a map.
func (c *Client) ExportMap(ctx context.Context, project, env string) (map[string]string, error) {
	data, err := c.Export(ctx, project, env, "json")
	if err != nil {
		return nil, err
	}
	m := map[string]string{}
	return m, json.Unmarshal(data, &m)
}

func (c *Client) ListSecrets(ctx context.Context, project, env string, reveal bool) ([]Secret, error) {
	var r struct{ Items []Secret }
	data, err := c.do(ctx, http.MethodGet, envPath(project, env)+"/secrets", url.Values{"reveal": {fmt.Sprint(reveal)}}, nil, "")
	if err != nil {
		return nil, err
	}
	err = json.Unmarshal(data, &r)
	return r.Items, err
}

func (c *Client) GetSecret(ctx context.Context, project, env, key string) (*Secret, error) {
	var s Secret
	return &s, c.json(ctx, http.MethodGet, envPath(project, env)+"/secrets/"+url.PathEscape(key), nil, &s)
}

func (c *Client) SetSecret(ctx context.Context, project, env, key, value string) error {
	return c.json(ctx, http.MethodPut, envPath(project, env)+"/secrets/"+url.PathEscape(key), map[string]any{"value": value}, nil)
}

func (c *Client) DeleteSecret(ctx context.Context, project, env, key string) error {
	return c.json(ctx, http.MethodDelete, envPath(project, env)+"/secrets/"+url.PathEscape(key), nil, nil)
}

type ImportOptions struct {
	Format    string
	Strategy  string
	DryRun    bool
	Normalize bool
	Separator string
	Prefix    string
}

// Import uploads a file (.env, json, xml, yaml, settings.json) as multipart.
func (c *Client) Import(ctx context.Context, project, env, filename string, data []byte, o ImportOptions) (*ImportResult, error) {
	var buf bytes.Buffer
	w := multipart.NewWriter(&buf)
	fw, err := w.CreateFormFile("file", filepath.Base(filename))
	if err != nil {
		return nil, err
	}
	if _, err := fw.Write(data); err != nil {
		return nil, err
	}
	if err := w.Close(); err != nil {
		return nil, err
	}
	q := url.Values{}
	for k, v := range map[string]string{"format": o.Format, "strategy": o.Strategy, "separator": o.Separator, "prefix": o.Prefix} {
		if v != "" {
			q.Set(k, v)
		}
	}
	if o.DryRun {
		q.Set("dry_run", "true")
	}
	if o.Normalize {
		q.Set("normalize", "true")
	}
	out, err := c.do(ctx, http.MethodPost, envPath(project, env)+"/secrets/import", q, &buf, w.FormDataContentType())
	if err != nil {
		return nil, err
	}
	var r ImportResult
	return &r, json.Unmarshal(out, &r)
}

type ShareResult struct {
	URL       string    `json:"url"`
	APIURL    string    `json:"api_url"`
	ExpiresAt time.Time `json:"expires_at"`
	MaxViews  int       `json:"max_views"`
}

func (c *Client) Share(ctx context.Context, project, env string, in map[string]any) (*ShareResult, error) {
	var r ShareResult
	return &r, c.json(ctx, http.MethodPost, envPath(project, env)+"/shares", in, &r)
}

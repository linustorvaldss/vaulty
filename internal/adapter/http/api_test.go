package httpapi_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"

	httpapi "github.com/linustorvaldss/vaulty/internal/adapter/http"
	"github.com/linustorvaldss/vaulty/internal/adapter/security"
	"github.com/linustorvaldss/vaulty/internal/adapter/store"
	"github.com/linustorvaldss/vaulty/internal/adapter/vault/local"
	"github.com/linustorvaldss/vaulty/internal/port"
	"github.com/linustorvaldss/vaulty/internal/service"
)

// fakeProvider simulates an OAuth provider: the "code" is the subject.
type fakeProvider struct{ name string }

func (f fakeProvider) Name() string { return f.name }
func (f fakeProvider) AuthCodeURL(state, redirect string) string {
	return "https://idp.example/auth?state=" + url.QueryEscape(state)
}
func (f fakeProvider) Exchange(_ context.Context, code, _ string) (*port.ExternalProfile, error) {
	return &port.ExternalProfile{Provider: f.name, Subject: code, Email: code + "@example.com", EmailVerified: true, Name: code}, nil
}

type env struct {
	t   *testing.T
	srv *httptest.Server
}

var dbN int

func setup(t *testing.T) *env {
	t.Helper()
	gin.SetMode(gin.TestMode)
	dbN++
	db, err := store.Open(fmt.Sprintf("sqlite://file:t%d_%d?mode=memory&cache=shared&_pragma=foreign_keys(1)", time.Now().UnixNano(), dbN), false)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	if err := db.Migrate(); err != nil {
		t.Fatal(err)
	}
	vault, err := local.New(db.DB(), base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{7}, 32)))
	if err != nil {
		t.Fatal(err)
	}
	jwt, _ := security.NewJWT(strings.Repeat("s", 32), time.Hour)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	svc := service.New(service.Deps{
		Store: db, Vault: vault, Hasher: security.Bcrypt{Cost: 4}, Sessions: jwt, Logger: logger,
		Providers: map[string]port.OAuthProvider{"github": fakeProvider{"github"}},
		AppURL:    "http://app.test", APIURL: "http://api.test", AllowedRedirects: []string{"http://app.test"},
	})
	srv := httptest.NewServer(httpapi.NewRouter(svc, httpapi.Options{Logger: logger}))
	t.Cleanup(srv.Close)
	return &env{t: t, srv: srv}
}

type resp struct {
	status int
	body   []byte
	header http.Header
}

func (r resp) json(v any) {
	_ = json.Unmarshal(r.body, v)
}

func (e *env) do(method, path, token string, body any, headers ...string) resp {
	e.t.Helper()
	var rd io.Reader
	ctype := ""
	switch b := body.(type) {
	case nil:
	case []byte:
		rd = bytes.NewReader(b)
	default:
		data, _ := json.Marshal(b)
		rd, ctype = bytes.NewReader(data), "application/json"
	}
	req, _ := http.NewRequest(method, e.srv.URL+path, rd)
	if ctype != "" {
		req.Header.Set("Content-Type", ctype)
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	for i := 0; i+1 < len(headers); i += 2 {
		req.Header.Set(headers[i], headers[i+1])
	}
	cl := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	res, err := cl.Do(req)
	if err != nil {
		e.t.Fatal(err)
	}
	defer res.Body.Close()
	data, _ := io.ReadAll(res.Body)
	return resp{status: res.StatusCode, body: data, header: res.Header}
}

func (e *env) must(want int, r resp) resp {
	e.t.Helper()
	if r.status != want {
		e.t.Fatalf("status %d, want %d: %s", r.status, want, r.body)
	}
	return r
}

func (e *env) register(email string) string {
	var s struct{ Token string }
	e.must(201, e.do("POST", "/api/v1/auth/register", "", map[string]string{"email": email, "password": "correct-horse-battery", "name": "Ada"})).json(&s)
	return s.Token
}

func TestEndToEnd(t *testing.T) {
	e := setup(t)

	// --- auth ---
	tok := e.register("ada@example.com")
	e.must(409, e.do("POST", "/api/v1/auth/register", "", map[string]string{"email": "ada@example.com", "password": "correct-horse-battery"}))
	e.must(401, e.do("POST", "/api/v1/auth/login", "", map[string]string{"email": "ada@example.com", "password": "wrong-password!"}))
	e.must(200, e.do("POST", "/api/v1/auth/login", "", map[string]string{"email": "ada@example.com", "password": "correct-horse-battery"}))
	e.must(401, e.do("GET", "/api/v1/me", "", nil))

	var me struct {
		Tenants []struct{ ID, Kind, Role string }
	}
	e.must(200, e.do("GET", "/api/v1/me", tok, nil)).json(&me)
	if len(me.Tenants) != 1 || me.Tenants[0].Kind != "personal" || me.Tenants[0].Role != "owner" {
		t.Fatalf("tenants = %+v", me.Tenants)
	}

	// --- projects / environments ---
	var proj struct {
		Slug         string
		Environments []struct{ Slug string }
	}
	e.must(201, e.do("POST", "/api/v1/projects", tok, map[string]string{"name": "My API"})).json(&proj)
	if proj.Slug != "my-api" || len(proj.Environments) != 3 {
		t.Fatalf("project = %+v", proj)
	}
	e.must(409, e.do("POST", "/api/v1/projects", tok, map[string]string{"name": "My API"}))
	e.must(201, e.do("POST", "/api/v1/projects/my-api/environments", tok, map[string]string{"name": "QA"}))

	// --- secrets CRUD ---
	base := "/api/v1/projects/my-api/environments/development/secrets"
	e.must(201, e.do("POST", base, tok, map[string]any{"key": "DB_URL", "value": "postgres://x"}))
	e.must(409, e.do("POST", base, tok, map[string]any{"key": "DB_URL", "value": "y"}))
	e.must(400, e.do("POST", base, tok, map[string]any{"key": "1BAD", "value": "y"}))
	e.must(200, e.do("PUT", base+"/DB_URL", tok, map[string]any{"value": "postgres://prod"}))
	e.must(201, e.do("PUT", base+"/API_KEY", tok, map[string]any{"value": "k1", "type": "token"}))

	var sec struct {
		Value   string
		Version int
	}
	e.must(200, e.do("GET", base+"/DB_URL", tok, nil)).json(&sec)
	if sec.Value != "postgres://prod" || sec.Version != 2 {
		t.Fatalf("secret = %+v", sec)
	}
	var list struct {
		Items []struct {
			Key   string
			Value *string
		}
	}
	e.must(200, e.do("GET", base, tok, nil)).json(&list)
	if len(list.Items) != 2 || list.Items[0].Value != nil {
		t.Fatalf("list without reveal leaked values: %+v", list.Items)
	}

	// --- import (raw body .env) ---
	envFile := []byte("export NEW_ONE=1\nDB_URL=postgres://prod\nAPI_KEY=k2\n1BAD=x\n")
	var imp struct {
		Summary map[string]int
		Items   []struct{ Key, Action string }
	}
	e.must(200, e.do("POST", base+"/import?filename=.env&dry_run=true", tok, envFile)).json(&imp)
	if imp.Summary["created"] != 1 || imp.Summary["unchanged"] != 1 || imp.Summary["updated"] != 1 || imp.Summary["error"] != 1 {
		t.Fatalf("dry run = %+v", imp)
	}
	e.must(200, e.do("POST", base+"/import?filename=.env", tok, envFile))

	// --- import (multipart appsettings.json into staging, normalized) ---
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	fw, _ := mw.CreateFormFile("file", "appsettings.json")
	fw.Write([]byte(`{ // comment
  "ConnectionStrings": {"Main": "Server=."},
  "Feature.Flag": true,
}`))
	mw.Close()
	e.must(200, e.do("POST", "/api/v1/projects/my-api/environments/staging/secrets/import?normalize=true", tok, buf.Bytes(),
		"Content-Type", mw.FormDataContentType()))

	// --- export ---
	r := e.must(200, e.do("GET", "/api/v1/projects/my-api/environments/staging/secrets/export?format=dotenv", tok, nil))
	if got := string(r.body); got != "CONNECTIONSTRINGS__MAIN=Server=.\nFEATURE_FLAG=true\n" {
		t.Fatalf("export = %q", got)
	}
	var exported map[string]string
	e.must(200, e.do("GET", base+"/export?format=json", tok, nil)).json(&exported)
	if exported["API_KEY"] != "k2" || exported["NEW_ONE"] != "1" || len(exported) != 3 {
		t.Fatalf("export json = %v", exported)
	}

	// --- access token for CLI (read-only) ---
	var pat struct{ Token, ID string }
	e.must(201, e.do("POST", "/api/v1/tokens", tok, map[string]any{"name": "laptop", "read_only": true})).json(&pat)
	if !strings.HasPrefix(pat.Token, "vty_") {
		t.Fatalf("token = %q", pat.Token)
	}
	e.must(200, e.do("GET", base+"/export", pat.Token, nil))
	e.must(403, e.do("PUT", base+"/X", pat.Token, map[string]any{"value": "1"}))
	e.must(403, e.do("POST", "/api/v1/tokens", pat.Token, map[string]any{"name": "nested"}))
	e.must(204, e.do("DELETE", "/api/v1/tokens/"+pat.ID, tok, nil))
	e.must(401, e.do("GET", base+"/export", pat.Token, nil))

	// --- share links ---
	var share struct {
		Token, URL, ID string
	}
	e.must(201, e.do("POST", "/api/v1/projects/my-api/environments/development/shares", tok,
		map[string]any{"keys": []string{"API_KEY"}, "max_views": 2, "passphrase": "open sesame"})).json(&share)
	if share.URL != "http://app.test/share/"+share.Token {
		t.Fatalf("share url = %s", share.URL)
	}
	e.must(401, e.do("GET", "/api/v1/shared/"+share.Token, "", nil))
	r = e.must(200, e.do("GET", "/api/v1/shared/"+share.Token+"?format=dotenv", "", nil, "X-Share-Passphrase", "open sesame"))
	if string(r.body) != "API_KEY=k2\n" {
		t.Fatalf("shared = %q", r.body)
	}
	e.must(200, e.do("POST", "/api/v1/shared/"+share.Token, "", map[string]string{"passphrase": "open sesame"}))
	e.must(410, e.do("POST", "/api/v1/shared/"+share.Token, "", map[string]string{"passphrase": "open sesame"}))
	e.must(404, e.do("GET", "/api/v1/shared/vsh_nope", "", nil))

	var s2 struct{ Token, ID string }
	e.must(201, e.do("POST", "/api/v1/projects/my-api/environments/development/shares", tok, map[string]any{})).json(&s2)
	e.must(204, e.do("DELETE", "/api/v1/shares/"+s2.ID, tok, nil))
	e.must(410, e.do("GET", "/api/v1/shared/"+s2.Token, "", nil))

	// --- delete ---
	e.must(204, e.do("DELETE", base+"/NEW_ONE", tok, nil))
	e.must(404, e.do("GET", base+"/NEW_ONE", tok, nil))
	e.must(204, e.do("DELETE", "/api/v1/projects/my-api", tok, nil))
	e.must(404, e.do("GET", "/api/v1/projects/my-api", tok, nil))
}

func TestTenantIsolationAndOrgs(t *testing.T) {
	e := setup(t)
	ada := e.register("ada@example.com")
	bob := e.register("bob@example.com")

	e.must(201, e.do("POST", "/api/v1/projects", ada, map[string]string{"name": "secret-proj"}))
	e.must(201, e.do("PUT", "/api/v1/projects/secret-proj/environments/production/secrets/K", ada, map[string]any{"value": "v"}))

	// Bob cannot see Ada's personal workspace.
	e.must(404, e.do("GET", "/api/v1/projects/secret-proj", bob, nil))
	var adaMe struct{ Tenants []struct{ ID string } }
	e.must(200, e.do("GET", "/api/v1/me", ada, nil)).json(&adaMe)
	e.must(403, e.do("GET", "/api/v1/projects", bob, nil, "X-Tenant-ID", adaMe.Tenants[0].ID))

	// Organizations: Ada creates one and adds Bob as viewer.
	var org struct{ ID, Slug string }
	e.must(201, e.do("POST", "/api/v1/tenants", ada, map[string]string{"name": "Acme Inc"})).json(&org)
	e.must(201, e.do("POST", "/api/v1/projects", ada, map[string]string{"name": "web"}, "X-Tenant-ID", org.Slug))
	e.must(400, e.do("POST", "/api/v1/tenant/members", ada, map[string]string{"email": "bob@example.com", "role": "viewer"}))
	e.must(201, e.do("POST", "/api/v1/tenant/members", ada, map[string]string{"email": "bob@example.com", "role": "viewer"}, "X-Tenant-ID", org.ID))

	e.must(200, e.do("GET", "/api/v1/projects/web", bob, nil, "X-Tenant-ID", org.ID))
	e.must(403, e.do("POST", "/api/v1/projects", bob, map[string]string{"name": "x"}, "X-Tenant-ID", org.ID))

	// Access tokens are bound to their workspace.
	var pat struct{ Token string }
	e.must(201, e.do("POST", "/api/v1/tokens", ada, map[string]any{"name": "ci"}, "X-Tenant-ID", org.ID)).json(&pat)
	e.must(200, e.do("GET", "/api/v1/projects/web", pat.Token, nil))
	e.must(404, e.do("GET", "/api/v1/projects/secret-proj", pat.Token, nil))
	e.must(403, e.do("GET", "/api/v1/projects", pat.Token, nil, "X-Tenant-ID", adaMe.Tenants[0].ID))

	// Cloud connection requires admin and is blocked while secrets exist.
	e.must(409, e.do("PUT", "/api/v1/cloud/aws", ada, map[string]string{"region": "us-east-1", "role_arn": "arn:aws:iam::123456789012:role/vaulty"}))
	var cc struct{ ExternalID string `json:"external_id"`; Status string }
	e.must(200, e.do("PUT", "/api/v1/cloud/aws", ada, map[string]string{"region": "us-east-1", "role_arn": "arn:aws:iam::123456789012:role/vaulty"}, "X-Tenant-ID", org.ID)).json(&cc)
	if cc.Status != "pending" || !strings.HasPrefix(cc.ExternalID, "vaulty-") {
		t.Fatalf("cloud = %+v", cc)
	}
	e.must(403, e.do("GET", "/api/v1/cloud/aws", bob, nil, "X-Tenant-ID", org.ID))
}

func TestOAuthFlow(t *testing.T) {
	e := setup(t)
	e.must(404, e.do("GET", "/api/v1/auth/oauth/google/start", "", nil))
	e.must(400, e.do("GET", "/api/v1/auth/oauth/github/start?redirect_uri=https://evil.test/x", "", nil))

	r := e.must(302, e.do("GET", "/api/v1/auth/oauth/github/start?redirect_uri=http://app.test/auth/callback", "", nil))
	loc, _ := url.Parse(r.header.Get("Location"))
	state := loc.Query().Get("state")
	var nonce string
	for _, c := range (&http.Response{Header: r.header}).Cookies() {
		if c.Name == "vaulty_oauth_nonce" {
			nonce = c.Value
		}
	}
	if state == "" || nonce == "" {
		t.Fatal("missing state or nonce cookie")
	}

	cb := "/api/v1/auth/oauth/github/callback?code=octocat&state=" + url.QueryEscape(state)
	e.must(401, e.do("GET", cb, "", nil)) // no nonce cookie: CSRF protection
	r = e.must(302, e.do("GET", cb, "", nil, "Cookie", "vaulty_oauth_nonce="+nonce))
	dest, _ := url.Parse(r.header.Get("Location"))
	frag, _ := url.ParseQuery(dest.Fragment)
	if dest.Host != "app.test" || frag.Get("token") == "" {
		t.Fatalf("redirect = %s", r.header.Get("Location"))
	}

	// Same email registered with password + verified OAuth email => linked.
	var me struct {
		User       struct{ Email string }
		Identities []struct{ Provider string }
	}
	e.must(200, e.do("GET", "/api/v1/me", frag.Get("token"), nil)).json(&me)
	if me.User.Email != "octocat@example.com" || len(me.Identities) != 1 || me.Identities[0].Provider != "github" {
		t.Fatalf("me = %+v", me)
	}
}

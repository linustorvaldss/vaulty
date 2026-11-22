package httpapi

import (
	"io"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/linustorvaldss/vaulty/internal/domain"
	"github.com/linustorvaldss/vaulty/internal/parser"
	"github.com/linustorvaldss/vaulty/internal/service"
)

// ---------- auth ----------

func (a *API) register(c *gin.Context) {
	var in service.RegisterInput
	if !a.bind(c, &in) {
		return
	}
	sess, err := a.svc.Register(c.Request.Context(), in)
	if err != nil {
		a.fail(c, err)
		return
	}
	c.JSON(http.StatusCreated, sess)
}

func (a *API) login(c *gin.Context) {
	var in struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	if !a.bind(c, &in) {
		return
	}
	sess, err := a.svc.Login(c.Request.Context(), in.Email, in.Password)
	if err != nil {
		a.fail(c, err)
		return
	}
	c.JSON(http.StatusOK, sess)
}

func (a *API) providers(c *gin.Context) {
	c.JSON(http.StatusOK, items(a.svc.ProviderNames()))
}

const oauthCookie = "vaulty_oauth_nonce"

// oauthStart redirects to the provider. ?redirect_uri= is where the browser
// lands afterwards (must be under an allowed origin, e.g. the web app).
func (a *API) oauthStart(c *gin.Context) {
	provider := c.Param("provider")
	authURL, nonce, err := a.svc.OAuthStart(provider, c.Query("redirect_uri"))
	if err != nil {
		a.fail(c, err)
		return
	}
	c.SetSameSite(http.SameSiteLaxMode)
	c.SetCookie(oauthCookie, nonce, 600, "/api/v1/auth/oauth/"+provider, "", a.opts.SecureCookies, true)
	c.Redirect(http.StatusFound, authURL)
}

// oauthCallback redirects to <redirect_uri>#token=...&expires_at=... (the
// fragment never reaches servers or logs). Without redirect_uri it returns JSON.
func (a *API) oauthCallback(c *gin.Context) {
	provider := c.Param("provider")
	nonce, _ := c.Cookie(oauthCookie)
	c.SetCookie(oauthCookie, "", -1, "/api/v1/auth/oauth/"+provider, "", a.opts.SecureCookies, true)

	if e := c.Query("error"); e != "" {
		a.fail(c, domain.Unauthorized("provider error: %s", e))
		return
	}
	sess, redirect, err := a.svc.OAuthCallback(c.Request.Context(), provider, c.Query("code"), c.Query("state"), nonce)
	if err != nil {
		a.fail(c, err)
		return
	}
	if redirect == "" {
		c.JSON(http.StatusOK, sess)
		return
	}
	frag := url.Values{"token": {sess.Token}, "expires_at": {sess.ExpiresAt.Format(time.RFC3339)}}
	c.Redirect(http.StatusFound, redirect+"#"+frag.Encode())
}

func (a *API) me(c *gin.Context) {
	v, err := a.svc.Me(c.Request.Context(), principal(c))
	if err != nil {
		a.fail(c, err)
		return
	}
	c.JSON(http.StatusOK, v)
}

// ---------- tenants ----------

func (a *API) listTenants(c *gin.Context) {
	v, err := a.svc.ListTenants(c.Request.Context(), principal(c))
	if err != nil {
		a.fail(c, err)
		return
	}
	c.JSON(http.StatusOK, items(v))
}

func (a *API) createTenant(c *gin.Context) {
	var in struct {
		Name string `json:"name"`
	}
	if !a.bind(c, &in) {
		return
	}
	t, err := a.svc.CreateOrganization(c.Request.Context(), principal(c), in.Name)
	if err != nil {
		a.fail(c, err)
		return
	}
	c.JSON(http.StatusCreated, t)
}

func (a *API) listMembers(c *gin.Context) {
	v, err := a.svc.ListMembers(c.Request.Context(), scope(c))
	if err != nil {
		a.fail(c, err)
		return
	}
	c.JSON(http.StatusOK, items(v))
}

func (a *API) addMember(c *gin.Context) {
	var in struct {
		Email string      `json:"email"`
		Role  domain.Role `json:"role"`
	}
	if !a.bind(c, &in) {
		return
	}
	m, err := a.svc.AddMember(c.Request.Context(), scope(c), in.Email, in.Role)
	if err != nil {
		a.fail(c, err)
		return
	}
	c.JSON(http.StatusCreated, m)
}

func (a *API) removeMember(c *gin.Context) {
	if err := a.svc.RemoveMember(c.Request.Context(), scope(c), c.Param("userID")); err != nil {
		a.fail(c, err)
		return
	}
	c.Status(http.StatusNoContent)
}

// ---------- cloud ----------

func (a *API) getAWS(c *gin.Context) {
	v, err := a.svc.GetAWSConnection(c.Request.Context(), scope(c))
	if err != nil {
		a.fail(c, err)
		return
	}
	c.JSON(http.StatusOK, v)
}

func (a *API) setAWS(c *gin.Context) {
	var in service.AWSConnectionInput
	if !a.bind(c, &in) {
		return
	}
	v, err := a.svc.SetAWSConnection(c.Request.Context(), scope(c), in)
	if err != nil {
		a.fail(c, err)
		return
	}
	c.JSON(http.StatusOK, v)
}

func (a *API) verifyAWS(c *gin.Context) {
	v, err := a.svc.VerifyAWSConnection(c.Request.Context(), scope(c))
	if err != nil {
		a.fail(c, err)
		return
	}
	c.JSON(http.StatusOK, v)
}

func (a *API) deleteAWS(c *gin.Context) {
	if err := a.svc.DeleteAWSConnection(c.Request.Context(), scope(c)); err != nil {
		a.fail(c, err)
		return
	}
	c.Status(http.StatusNoContent)
}

// ---------- access tokens ----------

func (a *API) createToken(c *gin.Context) {
	var in service.CreateTokenInput
	if !a.bind(c, &in) {
		return
	}
	t, err := a.svc.CreateAccessToken(c.Request.Context(), scope(c), in)
	if err != nil {
		a.fail(c, err)
		return
	}
	c.JSON(http.StatusCreated, t)
}

func (a *API) listTokens(c *gin.Context) {
	v, err := a.svc.ListAccessTokens(c.Request.Context(), principal(c))
	if err != nil {
		a.fail(c, err)
		return
	}
	c.JSON(http.StatusOK, items(v))
}

func (a *API) deleteToken(c *gin.Context) {
	if err := a.svc.DeleteAccessToken(c.Request.Context(), principal(c), c.Param("id")); err != nil {
		a.fail(c, err)
		return
	}
	c.Status(http.StatusNoContent)
}

// ---------- projects & environments ----------

func (a *API) listProjects(c *gin.Context) {
	v, err := a.svc.ListProjects(c.Request.Context(), scope(c))
	if err != nil {
		a.fail(c, err)
		return
	}
	c.JSON(http.StatusOK, items(v))
}

func (a *API) createProject(c *gin.Context) {
	var in service.ProjectInput
	if !a.bind(c, &in) {
		return
	}
	v, err := a.svc.CreateProject(c.Request.Context(), scope(c), in)
	if err != nil {
		a.fail(c, err)
		return
	}
	c.JSON(http.StatusCreated, v)
}

func (a *API) getProject(c *gin.Context) {
	v, err := a.svc.GetProject(c.Request.Context(), scope(c), c.Param("project"))
	if err != nil {
		a.fail(c, err)
		return
	}
	c.JSON(http.StatusOK, v)
}

func (a *API) updateProject(c *gin.Context) {
	var in service.ProjectPatch
	if !a.bind(c, &in) {
		return
	}
	v, err := a.svc.UpdateProject(c.Request.Context(), scope(c), c.Param("project"), in)
	if err != nil {
		a.fail(c, err)
		return
	}
	c.JSON(http.StatusOK, v)
}

func (a *API) deleteProject(c *gin.Context) {
	if err := a.svc.DeleteProject(c.Request.Context(), scope(c), c.Param("project")); err != nil {
		a.fail(c, err)
		return
	}
	c.Status(http.StatusNoContent)
}

func (a *API) listEnvironments(c *gin.Context) {
	v, err := a.svc.ListEnvironments(c.Request.Context(), scope(c), c.Param("project"))
	if err != nil {
		a.fail(c, err)
		return
	}
	c.JSON(http.StatusOK, items(v))
}

func (a *API) createEnvironment(c *gin.Context) {
	var in struct {
		Name string `json:"name"`
	}
	if !a.bind(c, &in) {
		return
	}
	v, err := a.svc.CreateEnvironment(c.Request.Context(), scope(c), c.Param("project"), in.Name)
	if err != nil {
		a.fail(c, err)
		return
	}
	c.JSON(http.StatusCreated, v)
}

func (a *API) deleteEnvironment(c *gin.Context) {
	if err := a.svc.DeleteEnvironment(c.Request.Context(), scope(c), c.Param("project"), c.Param("env")); err != nil {
		a.fail(c, err)
		return
	}
	c.Status(http.StatusNoContent)
}

// ---------- secrets ----------

func (a *API) listSecrets(c *gin.Context) {
	reveal, _ := strconv.ParseBool(c.Query("reveal"))
	v, err := a.svc.ListSecrets(c.Request.Context(), scope(c), c.Param("project"), c.Param("env"), reveal)
	if err != nil {
		a.fail(c, err)
		return
	}
	c.JSON(http.StatusOK, items(v))
}

func (a *API) createSecret(c *gin.Context) {
	var in service.SecretInput
	if !a.bind(c, &in) {
		return
	}
	v, err := a.svc.CreateSecret(c.Request.Context(), scope(c), c.Param("project"), c.Param("env"), in)
	if err != nil {
		a.fail(c, err)
		return
	}
	c.JSON(http.StatusCreated, v)
}

func (a *API) getSecret(c *gin.Context) {
	v, err := a.svc.GetSecret(c.Request.Context(), scope(c), c.Param("project"), c.Param("env"), c.Param("key"))
	if err != nil {
		a.fail(c, err)
		return
	}
	c.JSON(http.StatusOK, v)
}

func (a *API) putSecret(c *gin.Context) {
	var in service.SecretInput
	if !a.bind(c, &in) {
		return
	}
	in.Key = c.Param("key")
	v, created, err := a.svc.UpsertSecret(c.Request.Context(), scope(c), c.Param("project"), c.Param("env"), in)
	if err != nil {
		a.fail(c, err)
		return
	}
	status := http.StatusOK
	if created {
		status = http.StatusCreated
	}
	c.JSON(status, v)
}

func (a *API) deleteSecret(c *gin.Context) {
	if err := a.svc.DeleteSecret(c.Request.Context(), scope(c), c.Param("project"), c.Param("env"), c.Param("key")); err != nil {
		a.fail(c, err)
		return
	}
	c.Status(http.StatusNoContent)
}

// importSecrets accepts multipart/form-data (field "file") or a raw body.
// Query: format=auto|dotenv|json|xml|yaml, strategy=overwrite|skip|fail,
// dry_run=true, separator=__, normalize=true, prefix=APP_.
func (a *API) importSecrets(c *gin.Context) {
	var (
		data     []byte
		filename = c.Query("filename")
		err      error
	)
	if fh, ferr := c.FormFile("file"); ferr == nil {
		f, err := fh.Open()
		if err != nil {
			a.fail(c, domain.Invalid("cannot read uploaded file"))
			return
		}
		defer f.Close()
		data, err = io.ReadAll(f)
		if err != nil {
			a.fail(c, err)
			return
		}
		filename = fh.Filename
	} else {
		if data, err = io.ReadAll(c.Request.Body); err != nil {
			a.fail(c, err)
			return
		}
	}
	if len(data) == 0 {
		a.fail(c, domain.Invalid("empty file"))
		return
	}
	dry, _ := strconv.ParseBool(c.Query("dry_run"))
	norm, _ := strconv.ParseBool(c.Query("normalize"))
	res, err := a.svc.ImportSecrets(c.Request.Context(), scope(c), c.Param("project"), c.Param("env"), service.ImportInput{
		Data: data, Filename: filename, Format: parser.Format(c.Query("format")),
		Strategy: service.ImportStrategy(c.Query("strategy")), DryRun: dry,
		Options: parser.Options{Separator: c.Query("separator"), Normalize: norm, Prefix: c.Query("prefix")},
	})
	if err != nil {
		a.fail(c, err)
		return
	}
	c.JSON(http.StatusOK, res)
}

// exportSecrets renders an environment: format=dotenv|json|yaml|shell.
func (a *API) exportSecrets(c *gin.Context) {
	entries, err := a.svc.ExportSecrets(c.Request.Context(), scope(c), c.Param("project"), c.Param("env"))
	if err != nil {
		a.fail(c, err)
		return
	}
	a.render(c, entries, c.DefaultQuery("format", "dotenv"))
}

func (a *API) render(c *gin.Context, entries []parser.Entry, format string) {
	body, ctype, err := parser.Render(entries, parser.Format(format))
	if err != nil {
		a.fail(c, domain.Invalid("%v", err))
		return
	}
	c.Data(http.StatusOK, ctype, body)
}

// ---------- share links ----------

func (a *API) createShare(c *gin.Context) {
	var in service.ShareInput
	if !a.bind(c, &in) {
		return
	}
	v, err := a.svc.CreateShareLink(c.Request.Context(), scope(c), c.Param("project"), c.Param("env"), in)
	if err != nil {
		a.fail(c, err)
		return
	}
	c.JSON(http.StatusCreated, v)
}

func (a *API) listShares(c *gin.Context) {
	v, err := a.svc.ListShareLinks(c.Request.Context(), scope(c), c.Param("project"), c.Param("env"))
	if err != nil {
		a.fail(c, err)
		return
	}
	c.JSON(http.StatusOK, items(v))
}

func (a *API) revokeShare(c *gin.Context) {
	if err := a.svc.RevokeShareLink(c.Request.Context(), scope(c), c.Param("id")); err != nil {
		a.fail(c, err)
		return
	}
	c.Status(http.StatusNoContent)
}

// openShare is public. Passphrase: X-Share-Passphrase header or JSON body
// {"passphrase": "..."} (POST). ?format=dotenv|json|yaml|shell returns the
// raw file; without it the response is JSON with metadata.
func (a *API) openShare(c *gin.Context) {
	pass := c.GetHeader("X-Share-Passphrase")
	if c.Request.Method == http.MethodPost && pass == "" {
		var in struct {
			Passphrase string `json:"passphrase"`
		}
		_ = c.ShouldBindJSON(&in)
		pass = in.Passphrase
	}
	v, err := a.svc.OpenShareLink(c.Request.Context(), c.Param("token"), pass)
	if err != nil {
		a.fail(c, err)
		return
	}
	if f := c.Query("format"); f != "" {
		a.render(c, v.Secrets, f)
		return
	}
	c.JSON(http.StatusOK, v)
}

// Package httpapi is the driving HTTP adapter (REST API, Gin).
package httpapi

import (
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"

	"github.com/linustorvaldss/vaulty/internal/domain"
	"github.com/linustorvaldss/vaulty/internal/service"
)

type Options struct {
	CORSOrigins []string
	Logger      *slog.Logger
	// SecureCookies sets the Secure flag on cookies (HTTPS deployments).
	SecureCookies bool
}

type API struct {
	svc  *service.Service
	opts Options
}

const (
	ctxPrincipal = "vaulty.principal"
	ctxScope     = "vaulty.scope"
	headerTenant = "X-Tenant-ID"
	maxBodyBytes = 1 << 20 // 1 MiB
)

func NewRouter(svc *service.Service, opts Options) *gin.Engine {
	if opts.Logger == nil {
		opts.Logger = slog.Default()
	}
	a := &API{svc: svc, opts: opts}

	r := gin.New()
	r.Use(gin.Recovery(), requestLogger(opts.Logger), securityHeaders())
	corsCfg := cors.Config{
		AllowMethods:     []string{"GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"},
		AllowHeaders:     []string{"Authorization", "Content-Type", headerTenant, "X-Share-Passphrase"},
		AllowCredentials: true,
		MaxAge:           12 * time.Hour,
	}
	if len(opts.CORSOrigins) == 0 {
		corsCfg.AllowAllOrigins, corsCfg.AllowCredentials = true, false
	} else {
		corsCfg.AllowOrigins = opts.CORSOrigins
	}
	r.Use(cors.New(corsCfg))

	r.GET("/health", func(c *gin.Context) { c.JSON(http.StatusOK, gin.H{"status": "ok"}) })

	v1 := r.Group("/api/v1")
	limited := v1.Group("", rateLimit(20, time.Minute))

	// Public
	limited.POST("/auth/register", a.register)
	limited.POST("/auth/login", a.login)
	v1.GET("/auth/providers", a.providers)
	v1.GET("/auth/oauth/:provider/start", a.oauthStart)
	v1.GET("/auth/oauth/:provider/callback", a.oauthCallback)
	limited.GET("/shared/:token", a.openShare)
	limited.POST("/shared/:token", a.openShare)

	// Authenticated (session JWT or access token)
	auth := v1.Group("", a.authenticate)
	auth.GET("/me", a.me)
	auth.GET("/tenants", a.listTenants)
	auth.POST("/tenants", a.createTenant)
	auth.GET("/tokens", a.listTokens)
	auth.DELETE("/tokens/:id", a.deleteToken)

	// Tenant-scoped: X-Tenant-ID header (id or slug), defaults to the personal
	// workspace; access tokens are bound to their workspace.
	t := auth.Group("", a.scope)
	t.POST("/tokens", a.createToken)
	t.GET("/tenant/members", a.listMembers)
	t.POST("/tenant/members", a.addMember)
	t.DELETE("/tenant/members/:userID", a.removeMember)

	t.GET("/cloud/aws", a.getAWS)
	t.PUT("/cloud/aws", a.setAWS)
	t.POST("/cloud/aws/verify", a.verifyAWS)
	t.DELETE("/cloud/aws", a.deleteAWS)

	t.GET("/projects", a.listProjects)
	t.POST("/projects", a.createProject)
	t.GET("/projects/:project", a.getProject)
	t.PATCH("/projects/:project", a.updateProject)
	t.DELETE("/projects/:project", a.deleteProject)

	t.GET("/projects/:project/environments", a.listEnvironments)
	t.POST("/projects/:project/environments", a.createEnvironment)
	t.DELETE("/projects/:project/environments/:env", a.deleteEnvironment)

	s := t.Group("/projects/:project/environments/:env")
	s.GET("/secrets", a.listSecrets)
	s.POST("/secrets", a.createSecret)
	s.POST("/secrets/import", a.importSecrets)
	s.GET("/secrets/export", a.exportSecrets)
	s.GET("/secrets/:key", a.getSecret)
	s.PUT("/secrets/:key", a.putSecret)
	s.DELETE("/secrets/:key", a.deleteSecret)

	s.GET("/shares", a.listShares)
	s.POST("/shares", a.createShare)
	t.DELETE("/shares/:id", a.revokeShare)

	return r
}

// ---------- middleware ----------

func (a *API) authenticate(c *gin.Context) {
	h := c.GetHeader("Authorization")
	token, ok := strings.CutPrefix(h, "Bearer ")
	if !ok {
		a.fail(c, domain.Unauthorized("missing bearer token"))
		return
	}
	p, err := a.svc.Authenticate(c.Request.Context(), strings.TrimSpace(token))
	if err != nil {
		a.fail(c, err)
		return
	}
	c.Set(ctxPrincipal, p)
	c.Next()
}

func (a *API) scope(c *gin.Context) {
	sc, err := a.svc.ResolveScope(c.Request.Context(), principal(c), c.GetHeader(headerTenant))
	if err != nil {
		a.fail(c, err)
		return
	}
	c.Set(ctxScope, sc)
	c.Next()
}

func principal(c *gin.Context) *service.Principal {
	p, _ := c.Get(ctxPrincipal)
	pp, _ := p.(*service.Principal)
	return pp
}

func scope(c *gin.Context) *service.Scope {
	s, _ := c.Get(ctxScope)
	sc, _ := s.(*service.Scope)
	return sc
}

func securityHeaders() gin.HandlerFunc {
	return func(c *gin.Context) {
		h := c.Writer.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		if strings.HasPrefix(c.Request.URL.Path, "/api/") {
			h.Set("Cache-Control", "no-store")
		}
		c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, maxBodyBytes)
		c.Next()
	}
}

func requestLogger(l *slog.Logger) gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()
		c.Next()
		// Never log query strings: share tokens and OAuth codes travel there.
		l.Info("http", "method", c.Request.Method, "route", c.FullPath(), "status", c.Writer.Status(),
			"duration_ms", time.Since(start).Milliseconds(), "ip", c.ClientIP())
	}
}

// rateLimit is a small fixed-window limiter per client IP and route. It is
// per-process; put a shared limiter (API Gateway/WAF/Redis) in front in prod.
func rateLimit(limit int, window time.Duration) gin.HandlerFunc {
	type bucket struct {
		start time.Time
		n     int
	}
	var (
		mu      sync.Mutex
		buckets = map[string]*bucket{}
	)
	return func(c *gin.Context) {
		key := c.ClientIP() + "|" + c.FullPath()
		now := time.Now()
		mu.Lock()
		if len(buckets) > 10000 {
			for k, b := range buckets {
				if now.Sub(b.start) > window {
					delete(buckets, k)
				}
			}
		}
		b, ok := buckets[key]
		if !ok || now.Sub(b.start) > window {
			b = &bucket{start: now}
			buckets[key] = b
		}
		b.n++
		over := b.n > limit
		mu.Unlock()
		if over {
			c.AbortWithStatusJSON(http.StatusTooManyRequests, gin.H{"error": gin.H{"code": "rate_limited", "message": "too many requests"}})
			return
		}
		c.Next()
	}
}

// ---------- errors ----------

var statusByKind = map[domain.Kind]int{
	domain.KindNotFound:     http.StatusNotFound,
	domain.KindConflict:     http.StatusConflict,
	domain.KindValidation:   http.StatusBadRequest,
	domain.KindUnauthorized: http.StatusUnauthorized,
	domain.KindForbidden:    http.StatusForbidden,
	domain.KindGone:         http.StatusGone,
	domain.KindUnavailable:  http.StatusServiceUnavailable,
}

func (a *API) fail(c *gin.Context, err error) {
	kind := domain.KindOf(err)
	status, ok := statusByKind[kind]
	msg := err.Error()
	var de *domain.Error
	if errors.As(err, &de) && kind == domain.KindUnavailable {
		msg = de.Message // don't leak cloud error details
		a.opts.Logger.Error("upstream error", "err", err)
	}
	var maxErr *http.MaxBytesError
	switch {
	case errors.As(err, &maxErr):
		status, kind, msg, ok = http.StatusRequestEntityTooLarge, "too_large", "request body too large", true
	case !ok:
		a.opts.Logger.Error("internal error", "err", err, "route", c.FullPath())
		status, kind, msg = http.StatusInternalServerError, "internal", "internal error"
	}
	c.AbortWithStatusJSON(status, gin.H{"error": gin.H{"code": kind, "message": msg}})
}

func (a *API) bind(c *gin.Context, dst any) bool {
	if err := c.ShouldBindJSON(dst); err != nil {
		var maxErr *http.MaxBytesError
		if errors.As(err, &maxErr) {
			a.fail(c, err)
		} else {
			a.fail(c, domain.Invalid("invalid JSON body: %v", err))
		}
		return false
	}
	return true
}

func items[T any](v []T) gin.H {
	if v == nil {
		v = []T{}
	}
	return gin.H{"items": v}
}

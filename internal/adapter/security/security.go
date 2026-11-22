// Package security implements password hashing (bcrypt) and session tokens
// (HS256 JWT).
package security

import (
	"errors"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"

	"github.com/linustorvaldss/vaulty/internal/port"
)

// ---------- bcrypt ----------

type Bcrypt struct{ Cost int }

var _ port.PasswordHasher = Bcrypt{}

func (b Bcrypt) Hash(password string) (string, error) {
	cost := b.Cost
	if cost == 0 {
		cost = bcrypt.DefaultCost
	}
	h, err := bcrypt.GenerateFromPassword([]byte(password), cost)
	return string(h), err
}

func (Bcrypt) Compare(hash, password string) bool {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)) == nil
}

// ---------- JWT ----------

const (
	audSession = "vaulty:session"
	audState   = "vaulty:oauth-state"
)

type JWT struct {
	secret []byte
	ttl    time.Duration
	issuer string
}

var _ port.SessionIssuer = (*JWT)(nil)

func NewJWT(secret string, ttl time.Duration) (*JWT, error) {
	if len(secret) < 32 {
		return nil, errors.New("JWT_SECRET must be at least 32 characters")
	}
	return &JWT{secret: []byte(secret), ttl: ttl, issuer: "vaulty"}, nil
}

type sessionClaims struct {
	Email string `json:"email"`
	jwt.RegisteredClaims
}

func (j *JWT) Issue(c port.Claims) (string, time.Time, error) {
	now := time.Now()
	exp := now.Add(j.ttl)
	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, sessionClaims{
		Email: c.Email,
		RegisteredClaims: jwt.RegisteredClaims{
			Subject: c.UserID, Issuer: j.issuer, Audience: jwt.ClaimStrings{audSession},
			IssuedAt: jwt.NewNumericDate(now), ExpiresAt: jwt.NewNumericDate(exp),
		},
	})
	s, err := tok.SignedString(j.secret)
	return s, exp, err
}

func (j *JWT) keyFunc(*jwt.Token) (any, error) { return j.secret, nil }

func (j *JWT) Parse(token string) (*port.Claims, error) {
	var c sessionClaims
	_, err := jwt.ParseWithClaims(token, &c, j.keyFunc,
		jwt.WithValidMethods([]string{"HS256"}), jwt.WithAudience(audSession), jwt.WithIssuer(j.issuer), jwt.WithExpirationRequired())
	if err != nil {
		return nil, err
	}
	return &port.Claims{UserID: c.Subject, Email: c.Email}, nil
}

type stateClaims struct {
	Data map[string]string `json:"d"`
	jwt.RegisteredClaims
}

func (j *JWT) SignState(payload map[string]string, ttl time.Duration) (string, error) {
	now := time.Now()
	return jwt.NewWithClaims(jwt.SigningMethodHS256, stateClaims{
		Data: payload,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer: j.issuer, Audience: jwt.ClaimStrings{audState},
			IssuedAt: jwt.NewNumericDate(now), ExpiresAt: jwt.NewNumericDate(now.Add(ttl)),
		},
	}).SignedString(j.secret)
}

func (j *JWT) ParseState(state string) (map[string]string, error) {
	var c stateClaims
	_, err := jwt.ParseWithClaims(state, &c, j.keyFunc,
		jwt.WithValidMethods([]string{"HS256"}), jwt.WithAudience(audState), jwt.WithIssuer(j.issuer), jwt.WithExpirationRequired())
	if err != nil {
		return nil, err
	}
	return c.Data, nil
}

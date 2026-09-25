package iamproxy

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"time"
)

const googleSQLScope = "https://www.googleapis.com/auth/sqlservice.login"
const azureAudience = "https://ossrdbms-aad.database.windows.net"

type googleToken struct {
	Principal string
	Scope     string
	Expiry    time.Time
}

type service struct {
	Config       *Config
	Now          func() time.Time
	mu           sync.Mutex
	googleTokens map[string]googleToken
	azureKey     *rsa.PrivateKey
}

func newService(c *Config) (*service, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	return &service{Config: c, Now: time.Now, googleTokens: map[string]googleToken{}, azureKey: key}, nil
}

func (s *service) principal(id string) *Principal {
	for i := range s.Config.Principals {
		if s.Config.Principals[i].ID == id {
			return &s.Config.Principals[i]
		}
	}
	return nil
}

func (s *service) googleIssue(p *Principal, scope string) (string, int) {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(err)
	}
	token := "ya29.mock." + base64.RawURLEncoding.EncodeToString(b[:])
	s.mu.Lock()
	s.googleTokens[token] = googleToken{p.ID, scope, s.Now().Add(time.Hour)}
	s.mu.Unlock()
	return token, 3600
}

func (s *service) Validate(l Listener, username, password string) (*Principal, error) {
	var p *Principal
	var err error
	switch l.Provider {
	case "aws":
		p, err = s.validateAWS(l, username, password)
	case "google":
		p, err = s.validateGoogle(l, username, password)
	case "azure":
		p, err = s.validateAzure(l, username, password)
	default:
		err = errors.New("unknown provider")
	}
	if err != nil || p == nil {
		return nil, errors.New("authentication failed")
	}
	if !p.Granted(l.Name) {
		return nil, errors.New("authentication failed")
	}
	return p, nil
}

func googleUsername(email, engine string) string {
	email = strings.ToLower(email)
	if engine == "mysql" {
		return strings.SplitN(email, "@", 2)[0]
	}
	return strings.TrimSuffix(email, ".gserviceaccount.com")
}

func (s *service) validateGoogle(l Listener, username, password string) (*Principal, error) {
	s.mu.Lock()
	t, ok := s.googleTokens[password]
	s.mu.Unlock()
	if !ok || !s.Now().Before(t.Expiry) {
		return nil, errors.New("invalid token")
	}
	if !strings.Contains(" "+t.Scope+" ", " "+googleSQLScope+" ") && !strings.Contains(" "+t.Scope+" ", " https://www.googleapis.com/auth/cloud-platform ") {
		return nil, errors.New("invalid scope")
	}
	p := s.principal(t.Principal)
	if p == nil || p.Email == "" || username != googleUsername(p.Email, l.Engine) {
		return nil, errors.New("wrong username")
	}
	return p, nil
}

func (s *service) azureIssue(p *Principal, tenant string, life time.Duration) (string, error) {
	return s.azureIssueForAudience(p, tenant, azureAudience, life)
}

func (s *service) azureIssueForAudience(p *Principal, tenant, audience string, life time.Duration) (string, error) {
	if life <= 0 {
		life = time.Hour
	}
	now := s.Now()
	issuer := strings.TrimRight(s.Config.PublicURL, "/") + "/" + tenant + "/v2.0"
	head := map[string]any{"alg": "RS256", "typ": "JWT", "kid": "mock-1"}
	claims := map[string]any{"iss": issuer, "aud": audience, "tid": tenant, "oid": p.ID, "upn": p.Email, "iat": now.Unix(), "nbf": now.Unix(), "exp": now.Add(life).Unix(), "groups": p.Groups}
	hb, _ := json.Marshal(head)
	cb, _ := json.Marshal(claims)
	part := base64.RawURLEncoding.EncodeToString(hb) + "." + base64.RawURLEncoding.EncodeToString(cb)
	h := sha256.Sum256([]byte(part))
	sig, err := rsa.SignPKCS1v15(rand.Reader, s.azureKey, crypto.SHA256, h[:])
	if err != nil {
		return "", err
	}
	return part + "." + base64.RawURLEncoding.EncodeToString(sig), nil
}

func (s *service) validateAzure(l Listener, username, token string) (*Principal, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, errors.New("invalid jwt")
	}
	hb, e1 := base64.RawURLEncoding.DecodeString(parts[0])
	cb, e2 := base64.RawURLEncoding.DecodeString(parts[1])
	sig, e3 := base64.RawURLEncoding.DecodeString(parts[2])
	if e1 != nil || e2 != nil || e3 != nil {
		return nil, errors.New("invalid jwt encoding")
	}
	var header struct {
		Alg string `json:"alg"`
		Kid string `json:"kid"`
	}
	var claims struct {
		Iss    string   `json:"iss"`
		Aud    string   `json:"aud"`
		Tenant string   `json:"tid"`
		ID     string   `json:"oid"`
		UPN    string   `json:"upn"`
		Nbf    int64    `json:"nbf"`
		Exp    int64    `json:"exp"`
		Groups []string `json:"groups"`
	}
	if json.Unmarshal(hb, &header) != nil || json.Unmarshal(cb, &claims) != nil || header.Alg != "RS256" || header.Kid != "mock-1" {
		return nil, errors.New("invalid jwt claims")
	}
	h := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if rsa.VerifyPKCS1v15(&s.azureKey.PublicKey, crypto.SHA256, h[:], sig) != nil {
		return nil, errors.New("invalid signature")
	}
	issuer := strings.TrimRight(s.Config.PublicURL, "/") + "/" + l.Tenant + "/v2.0"
	if claims.Iss != issuer || claims.Aud != azureAudience || claims.Tenant != l.Tenant || s.Now().Unix() < claims.Nbf || s.Now().Unix() >= claims.Exp {
		return nil, errors.New("invalid jwt claims")
	}
	p := s.principal(claims.ID)
	if p == nil || claims.UPN != p.Email {
		return nil, errors.New("invalid principal")
	}
	if username == p.Email {
		return p, nil
	}
	for _, g := range p.Groups {
		if g == username {
			for _, cg := range claims.Groups {
				if cg == g {
					return p, nil
				}
			}
		}
	}
	return nil, errors.New("wrong username")
}

func (s *service) AzureJWK() map[string]any {
	n := s.azureKey.PublicKey.N.Bytes()
	e := []byte{1, 0, 1}
	return map[string]any{"kty": "RSA", "kid": "mock-1", "use": "sig", "alg": "RS256", "n": base64.RawURLEncoding.EncodeToString(n), "e": base64.RawURLEncoding.EncodeToString(e)}
}

func checkSecret(a, b string) bool { return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1 }

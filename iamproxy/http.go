package iamproxy

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

type mockHTTP struct {
	s    *service
	mu   sync.Mutex
	imds map[string]time.Time
}

func (s *service) HTTPHandler() http.Handler {
	h := &mockHTTP{s: s, imds: map[string]time.Time{}}
	return http.HandlerFunc(h.serve)
}

func jsonReply(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func (h *mockHTTP) serve(w http.ResponseWriter, r *http.Request) {
	p := r.URL.Path
	switch {
	case p == "/healthz":
		jsonReply(w, 200, map[string]string{"status": "ok"})
	case p == "/arm/subscriptions":
		jsonReply(w, 200, map[string]any{"value": []any{}})
	case p == "/arm/tenants":
		jsonReply(w, 200, map[string]any{"value": []any{map[string]string{"tenantId": "tenant-1", "id": "/tenants/tenant-1"}}})
	case p == "/latest/api/token":
		h.awsIMDSToken(w, r)
	case strings.HasPrefix(p, "/latest/meta-data/iam/security-credentials/"):
		h.awsIMDSCredentials(w, r)
	case strings.HasPrefix(p, "/v2/credentials/"):
		h.awsECSCredentials(w, r)
	case strings.HasPrefix(p, "/ecs/v4/"):
		h.awsECSMetadata(w, r)
	case p == "/computeMetadata/v1/instance/service-accounts/default/token" || strings.HasPrefix(p, "/computeMetadata/v1/instance/service-accounts/") && strings.HasSuffix(p, "/token"):
		h.googleMetadata(w, r)
	case p == "/computeMetadata/v1/instance/service-accounts/default/email":
		h.googleMetadata(w, r)
	case p == "/oauth2.googleapis.com/token" || p == "/token":
		h.googleOAuth(w, r)
	case p == "/metadata/identity/oauth2/token":
		h.azureIMDS(w, r)
	case strings.HasSuffix(p, "/.well-known/openid-configuration"):
		h.azureDiscovery(w, r)
	case strings.HasSuffix(p, "/discovery/v2.0/keys"):
		jsonReply(w, 200, map[string]any{"keys": []any{h.s.AzureJWK()}})
	case strings.HasSuffix(p, "/oauth2/v2.0/token"):
		h.azureOAuth(w, r)
	default:
		http.NotFound(w, r)
	}
}

func (h *mockHTTP) awsIMDSToken(w http.ResponseWriter, r *http.Request) {
	if r.Method != "PUT" {
		http.Error(w, "method", 405)
		return
	}
	ttl, err := strconv.Atoi(r.Header.Get("X-Aws-Ec2-Metadata-Token-Ttl-Seconds"))
	if err != nil || ttl < 1 || ttl > 21600 {
		http.Error(w, "invalid IMDSv2 token TTL", 400)
		return
	}
	var b [24]byte
	if _, err := rand.Read(b[:]); err != nil {
		http.Error(w, "rng", 500)
		return
	}
	t := base64.RawURLEncoding.EncodeToString(b[:])
	h.mu.Lock()
	for token, expiry := range h.imds {
		if !h.s.Now().Before(expiry) {
			delete(h.imds, token)
		}
	}
	h.imds[t] = h.s.Now().Add(time.Duration(ttl) * time.Second)
	h.mu.Unlock()
	w.Header().Set("Content-Type", "text/plain")
	_, _ = w.Write([]byte(t))
}

func (h *mockHTTP) awsIMDSCredentials(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		http.Error(w, "method", 405)
		return
	}
	t := r.Header.Get("X-Aws-Ec2-Metadata-Token")
	h.mu.Lock()
	expiry, ok := h.imds[t]
	h.mu.Unlock()
	if !ok || !h.s.Now().Before(expiry) {
		http.Error(w, "IMDS token required", 401)
		return
	}
	role := strings.TrimPrefix(r.URL.Path, "/latest/meta-data/iam/security-credentials/")
	if role == "" {
		for _, p := range h.s.Config.Principals {
			if p.AWSAccessKey != "" {
				_, _ = w.Write([]byte(p.ID + "\n"))
			}
		}
		return
	}
	p := h.s.principal(role)
	if p == nil || p.AWSAccessKey == "" {
		http.NotFound(w, r)
		return
	}
	jsonReply(w, 200, map[string]any{"Code": "Success", "Type": "AWS-HMAC", "AccessKeyId": p.AWSAccessKey, "SecretAccessKey": p.AWSSecretKey, "Token": p.AWSSessionToken, "Expiration": h.s.Now().Add(time.Hour).UTC().Format(time.RFC3339)})
}

func (h *mockHTTP) awsECSCredentials(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method", http.StatusMethodNotAllowed)
		return
	}
	id := strings.TrimPrefix(r.URL.Path, "/v2/credentials/")
	if id == "" || strings.Contains(id, "/") {
		http.NotFound(w, r)
		return
	}
	p := h.s.principal(id)
	if p == nil || p.AWSAccessKey == "" {
		http.NotFound(w, r)
		return
	}
	if p.ECSAuthorizationToken != "" && !checkSecret(p.ECSAuthorizationToken, r.Header.Get("Authorization")) {
		http.Error(w, "authorization token required", http.StatusUnauthorized)
		return
	}
	jsonReply(w, http.StatusOK, map[string]any{
		"RoleArn":         "arn:aws:iam::123456789012:role/" + p.ID,
		"AccessKeyId":     p.AWSAccessKey,
		"SecretAccessKey": p.AWSSecretKey,
		"Token":           p.AWSSessionToken,
		"Expiration":      h.s.Now().Add(time.Hour).UTC().Format(time.RFC3339),
	})
}

func (h *mockHTTP) awsECSMetadata(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method", http.StatusMethodNotAllowed)
		return
	}
	parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/ecs/v4/"), "/")
	if len(parts) < 1 || len(parts) > 3 || parts[0] == "" {
		http.NotFound(w, r)
		return
	}
	p := h.s.principal(parts[0])
	if p == nil || p.AWSAccessKey == "" {
		http.NotFound(w, r)
		return
	}
	arn := "arn:aws:ecs:us-east-1:123456789012:task/iam-proxy-fixtures/" + p.ID
	container := map[string]any{
		"DockerId":      "iam-proxy-" + p.ID,
		"Name":          p.ID,
		"DockerName":    "iam-proxy-" + p.ID,
		"Image":         "db-iam-auth-emulator-proxy-e2e:local",
		"ImageID":       "sha256:fixture",
		"DesiredStatus": "RUNNING",
		"KnownStatus":   "RUNNING",
	}
	stats := map[string]any{
		"read":         h.s.Now().UTC().Format(time.RFC3339Nano),
		"cpu_stats":    map[string]any{"cpu_usage": map[string]any{"total_usage": 0}, "system_cpu_usage": 0},
		"memory_stats": map[string]any{"usage": 0, "limit": 0},
		"networks":     map[string]any{},
	}
	if len(parts) == 1 {
		jsonReply(w, http.StatusOK, container)
		return
	}
	if len(parts) == 2 && parts[1] == "stats" {
		jsonReply(w, http.StatusOK, stats)
		return
	}
	if len(parts) == 3 && parts[1] == "task" && parts[2] == "stats" {
		jsonReply(w, http.StatusOK, map[string]any{"iam-proxy-" + p.ID: stats})
		return
	}
	if len(parts) != 2 {
		http.NotFound(w, r)
		return
	}
	if parts[1] != "task" && parts[1] != "taskWithTags" {
		http.NotFound(w, r)
		return
	}
	task := map[string]any{
		"Cluster": "iam-proxy-fixtures", "TaskARN": arn,
		"Family": "iam-proxy-fixture", "Revision": "1",
		"DesiredStatus": "RUNNING", "KnownStatus": "RUNNING",
		"LaunchType": "FARGATE", "Containers": []any{container},
	}
	if parts[1] == "taskWithTags" {
		task["TaskTags"] = []any{}
		task["ContainerInstanceTags"] = []any{}
	}
	jsonReply(w, http.StatusOK, task)
}

func (h *mockHTTP) googleMetadata(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Metadata-Flavor") != "Google" {
		http.Error(w, "metadata header required", 403)
		return
	}
	id := r.URL.Query().Get("principal")
	if id == "" {
		for _, p := range h.s.Config.Principals {
			if p.Email != "" {
				id = p.ID
				break
			}
		}
	}
	p := h.s.principal(id)
	if p == nil || p.Email == "" {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Metadata-Flavor", "Google")
	if strings.HasSuffix(r.URL.Path, "/email") {
		_, _ = w.Write([]byte(p.Email))
		return
	}
	scope := r.URL.Query().Get("scopes")
	if scope == "" {
		scope = googleSQLScope
	}
	if scope != googleSQLScope && scope != "https://www.googleapis.com/auth/cloud-platform" {
		http.Error(w, "scope not allowed", 400)
		return
	}
	token, expires := h.s.googleIssue(p, scope)
	jsonReply(w, 200, map[string]any{"access_token": token, "expires_in": expires, "token_type": "Bearer"})
}

func (h *mockHTTP) googleOAuth(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "method", 405)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "form", 400)
		return
	}
	var p *Principal
	switch r.Form.Get("grant_type") {
	case "refresh_token":
		for i := range h.s.Config.Principals {
			candidate := &h.s.Config.Principals[i]
			if candidate.GoogleRefreshToken != "" && checkSecret(candidate.GoogleRefreshToken, r.Form.Get("refresh_token")) {
				p = candidate
				break
			}
		}
	default:
		http.Error(w, "unsupported grant", 400)
		return
	}
	if p == nil {
		http.Error(w, "invalid grant", 401)
		return
	}
	scope := r.Form.Get("scope")
	if scope == "" {
		scope = googleSQLScope
	}
	if scope != googleSQLScope && scope != "https://www.googleapis.com/auth/cloud-platform" {
		http.Error(w, "invalid scope", 400)
		return
	}
	token, expires := h.s.googleIssue(p, scope)
	jsonReply(w, 200, map[string]any{"access_token": token, "expires_in": expires, "token_type": "Bearer", "scope": scope})
}

func (h *mockHTTP) azureIMDS(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Metadata") != "true" {
		http.Error(w, "Metadata header required", 400)
		return
	}
	resource := r.URL.Query().Get("resource")
	if resource != azureAudience && resource != "https://management.azure.com/" && resource != "https://management.core.windows.net/" {
		http.Error(w, "invalid resource", 400)
		return
	}
	id := r.URL.Query().Get("client_id")
	var p *Principal
	for i := range h.s.Config.Principals {
		candidate := &h.s.Config.Principals[i]
		if candidate.AzureClientID != "" && (id == "" || id == candidate.AzureClientID) {
			if p != nil && id == "" {
				http.Error(w, "ambiguous identity", 400)
				return
			}
			p = candidate
		}
	}
	if p == nil {
		http.Error(w, "identity not found", 404)
		return
	}
	tenant := h.azureTenantFor(p)
	if tenant == "" {
		http.Error(w, "tenant not found", 400)
		return
	}
	token, err := h.s.azureIssueForAudience(p, tenant, resource, time.Hour)
	if err != nil {
		http.Error(w, "signing failed", 500)
		return
	}
	jsonReply(w, 200, map[string]any{"access_token": token, "client_id": p.AzureClientID, "expires_in": "3600", "expires_on": fmt.Sprint(h.s.Now().Add(time.Hour).Unix()), "not_before": fmt.Sprint(h.s.Now().Unix()), "resource": resource, "token_type": "Bearer"})
}

func (h *mockHTTP) azureTenantFor(p *Principal) string {
	for _, l := range h.s.Config.Listeners {
		if l.Provider == "azure" && p.Granted(l.Name) {
			return l.Tenant
		}
	}
	return ""
}

func (h *mockHTTP) azureOAuth(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "method", 405)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "form", 400)
		return
	}
	parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	if len(parts) < 4 || parts[len(parts)-3] != "oauth2" {
		http.NotFound(w, r)
		return
	}
	tenant := parts[0]
	if r.Form.Get("grant_type") != "client_credentials" || !azureClientCredentialScope(r.Form.Get("scope")) {
		http.Error(w, "unsupported grant or scope", 400)
		return
	}
	var p *Principal
	for i := range h.s.Config.Principals {
		candidate := &h.s.Config.Principals[i]
		if candidate.AzureClientID == r.Form.Get("client_id") && candidate.AzureClientSecret != "" && checkSecret(candidate.AzureClientSecret, r.Form.Get("client_secret")) && h.azureTenantFor(candidate) == tenant {
			p = candidate
			break
		}
	}
	if p == nil {
		http.Error(w, "invalid client", 401)
		return
	}
	token, err := h.s.azureIssue(p, tenant, time.Hour)
	if err != nil {
		http.Error(w, "signing failed", 500)
		return
	}
	jsonReply(w, 200, map[string]any{"access_token": token, "expires_in": 3600, "ext_expires_in": 3600, "token_type": "Bearer"})
}

// azureClientCredentialScope accepts the OSS RDBMS ".default" scope, alone or
// with the OIDC scopes MSAL appends to every token request. Tokens are only
// ever issued for azureAudience.
func azureClientCredentialScope(scope string) bool {
	resource := 0
	for _, s := range strings.Fields(scope) {
		switch s {
		case azureAudience + "/.default":
			resource++
		case "openid", "offline_access", "profile":
		default:
			return false
		}
	}
	return resource == 1
}

func (h *mockHTTP) azureDiscovery(w http.ResponseWriter, r *http.Request) {
	parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	if len(parts) < 3 {
		http.NotFound(w, r)
		return
	}
	tenant := parts[0]
	// MSAL requires the issuer to share the authority's scheme and host, and
	// only accepts an https authority, so answer TLS requests with the origin
	// the client used.
	origin := strings.TrimRight(h.s.Config.PublicURL, "/")
	if r.TLS != nil {
		origin = "https://" + r.Host
	}
	base := origin + "/" + tenant
	jsonReply(w, 200, map[string]any{
		"issuer":                                base + "/v2.0",
		"authorization_endpoint":                base + "/oauth2/v2.0/authorize",
		"token_endpoint":                        base + "/oauth2/v2.0/token",
		"jwks_uri":                              base + "/discovery/v2.0/keys",
		"response_types_supported":              []string{"token"},
		"scopes_supported":                      []string{"openid", "profile", "offline_access"},
		"token_endpoint_auth_methods_supported": []string{"client_secret_post"},
		"id_token_signing_alg_values_supported": []string{"RS256"},
	})
}

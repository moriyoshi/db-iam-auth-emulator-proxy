package iamproxy

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
)

// TestAzureDefaultCredentialOffline drives DefaultAzureCredential's
// environment (client secret) credential, which uses MSAL tenant discovery and
// appends OIDC scopes, against the TLS credential endpoints.
func TestAzureDefaultCredentialOffline(t *testing.T) {
	c := &Config{
		HTTPSListen: "127.0.0.1:0",
		Listeners:   []Listener{{Name: "azure-postgres", Listen: "127.0.0.1:0", Provider: "azure", Engine: "postgres", Instance: "testdb", Tenant: "tenant-1", Upstream: "upstream.internal:5432"}},
		Principals:  []Principal{{ID: "alice", Email: "alice@example.com", Grants: []string{"azure-postgres"}, BackendUser: "backend", BackendPassword: "backpass", AzureClientID: "client-1", AzureClientSecret: "secret"}},
	}
	e := startEmbedded(t, c, Options{})
	var paths []string
	client := &http.Client{Transport: recordingTransport{&http.Transport{TLSClientConfig: &tls.Config{RootCAs: e.CertPool()}}, &paths}, Timeout: 5 * time.Second}
	credential := func(secret string) azcore.TokenCredential {
		t.Helper()
		t.Setenv("AZURE_TOKEN_CREDENTIALS", "EnvironmentCredential")
		t.Setenv("AZURE_TENANT_ID", "tenant-1")
		t.Setenv("AZURE_CLIENT_ID", "client-1")
		t.Setenv("AZURE_CLIENT_SECRET", secret)
		t.Setenv("AZURE_AUTHORITY_HOST", e.HTTPSURL()+"/")
		cred, err := azidentity.NewDefaultAzureCredential(&azidentity.DefaultAzureCredentialOptions{
			ClientOptions:            policy.ClientOptions{Transport: client, Retry: policy.RetryOptions{MaxRetries: -1}},
			DisableInstanceDiscovery: true,
		})
		if err != nil {
			t.Fatal(err)
		}
		return cred
	}
	ctx := context.Background()
	token, err := credential("secret").GetToken(ctx, policy.TokenRequestOptions{Scopes: []string{azureAudience + "/.default"}})
	if err != nil {
		t.Fatalf("GetToken: %v (requests %q)", err, paths)
	}
	l := e.Config().Listeners[0]
	if _, err = e.svc.Validate(l, "alice@example.com", token.Token); err != nil {
		t.Fatalf("SDK token rejected: %v", err)
	}
	if aud := jwtAudience(t, token.Token); aud != azureAudience {
		t.Fatalf("token audience = %q", aud)
	}
	for _, p := range paths {
		if !strings.HasPrefix(p, "/tenant-1/") {
			t.Fatalf("SDK request left the tenant authority: %q", p)
		}
	}
	for name, scope := range map[string]string{"management scope": "https://management.azure.com/.default", "bare audience": azureAudience} {
		if _, err := credential("secret").GetToken(ctx, policy.TokenRequestOptions{Scopes: []string{scope}}); err == nil {
			t.Errorf("%s issued a token", name)
		}
	}
	if _, err := credential("wrong").GetToken(ctx, policy.TokenRequestOptions{Scopes: []string{azureAudience + "/.default"}}); err == nil {
		t.Error("wrong client secret issued a token")
	}
}

func TestAzureClientCredentialScope(t *testing.T) {
	for scope, want := range map[string]bool{
		azureAudience + "/.default":                                       true,
		azureAudience + "/.default openid offline_access profile":         true,
		"openid offline_access profile":                                   false,
		azureAudience + "/.default https://management.azure.com/.default": false,
		azureAudience + "/.default " + azureAudience + "/.default":        false,
		azureAudience + "/.default email":                                 false,
		"":                                                                false,
	} {
		if got := azureClientCredentialScope(scope); got != want {
			t.Errorf("azureClientCredentialScope(%q) = %v", scope, got)
		}
	}
}

type recordingTransport struct {
	next  http.RoundTripper
	paths *[]string
}

func (r recordingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	*r.paths = append(*r.paths, req.URL.Path)
	return r.next.RoundTrip(req)
}

func jwtAudience(t *testing.T, token string) string {
	t.Helper()
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("not a JWT")
	}
	b, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatal(err)
	}
	var claims struct {
		Aud string `json:"aud"`
	}
	if err = json.Unmarshal(b, &claims); err != nil {
		t.Fatal(err)
	}
	return claims.Aud
}

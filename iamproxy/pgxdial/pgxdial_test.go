package pgxdial_test

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/moriyoshi/db-iam-auth-emulator-proxy/iamproxy"
	"github.com/moriyoshi/db-iam-auth-emulator-proxy/iamproxy/pgxdial"
	"github.com/moriyoshi/db-iam-auth-emulator-proxy/internal/fakedb"
)

func googleToken(t *testing.T, e *iamproxy.Emulator) string {
	t.Helper()
	req, _ := http.NewRequest("GET", e.HTTPURL()+"/computeMetadata/v1/instance/service-accounts/default/token", nil)
	req.Header.Set("Metadata-Flavor", "Google")
	r, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Body.Close()
	var v struct {
		AccessToken string `json:"access_token"`
	}
	if err = json.NewDecoder(r.Body).Decode(&v); err != nil || v.AccessToken == "" {
		t.Fatalf("token: %v", err)
	}
	return v.AccessToken
}

func TestConfigureRoutesByHostname(t *testing.T) {
	upstream := &fakedb.Server{User: "backend", Password: "backpass"}
	c := &iamproxy.Config{
		Listeners:  []iamproxy.Listener{{Name: "pg", Listen: "127.0.0.1:15432", Provider: "google", Engine: "postgres", Instance: "testdb", Hostname: "pg.example.internal", Upstream: "db:5432"}},
		Principals: []iamproxy.Principal{{ID: "alice", Email: "alice@example.com", Grants: []string{"pg"}, BackendUser: "backend", BackendPassword: "backpass"}},
	}
	e, err := iamproxy.Start(context.Background(), c, iamproxy.Options{InMemory: true, UpstreamDialer: upstream.PostgresDialer})
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	cfg, err := pgconn.ParseConfig("postgres://alice%40example.com@pg.example.internal:15432/appdb?sslmode=verify-full")
	if err != nil {
		t.Fatal(err)
	}
	cfg.Password = googleToken(t, e)
	pgxdial.Configure(cfg, e)
	conn, err := pgconn.ConnectConfig(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close(context.Background())
	results, err := conn.Exec(context.Background(), "select current_user").ReadAll()
	if err != nil || len(results) != 1 || string(results[0].Rows[0][0]) != "backend" {
		t.Fatalf("query: %v %+v", err, results)
	}
	if dials := upstream.Dials(); len(dials) != 1 || dials[0] != "db:5432" {
		t.Fatalf("upstream dials = %q", dials)
	}
}

func TestConfigureKeepsExplicitRoots(t *testing.T) {
	cfg, err := pgconn.ParseConfig("host=pg.example.internal,pg2.example.internal sslmode=verify-full")
	if err != nil {
		t.Fatal(err)
	}
	e, err := iamproxy.Start(context.Background(), &iamproxy.Config{
		Listeners: []iamproxy.Listener{{Name: "pg", Listen: "127.0.0.1:15432", Provider: "google", Engine: "postgres", Instance: "testdb", Upstream: "db:5432"}},
	}, iamproxy.Options{InMemory: true})
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	custom := e.CertPool()
	cfg.TLSConfig.RootCAs = custom
	original := cfg.Fallbacks[0].TLSConfig
	pgxdial.Configure(cfg, e)
	if cfg.TLSConfig.RootCAs != custom {
		t.Fatal("explicit RootCAs replaced")
	}
	if cfg.Fallbacks[0].TLSConfig == original || original.RootCAs != nil {
		t.Fatal("fallback TLS config was modified in place instead of cloned")
	}
}

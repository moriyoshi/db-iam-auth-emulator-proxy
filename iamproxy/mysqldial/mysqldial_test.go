package mysqldial_test

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/moriyoshi/db-iam-auth-emulator-proxy/iamproxy"
	"github.com/moriyoshi/db-iam-auth-emulator-proxy/iamproxy/mysqldial"
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

func TestRegisterRoutesDSNByHostname(t *testing.T) {
	upstream := &fakedb.Server{User: "backend", Password: "backpass"}
	c := &iamproxy.Config{
		Listeners:  []iamproxy.Listener{{Name: "my", Listen: "127.0.0.1:13306", Provider: "google", Engine: "mysql", Instance: "testdb", Hostname: "my.example.internal", Upstream: "db:3306"}},
		Principals: []iamproxy.Principal{{ID: "alice", Email: "alice@example.com", Grants: []string{"my"}, BackendUser: "backend", BackendPassword: "backpass"}},
	}
	e, err := iamproxy.Start(context.Background(), c, iamproxy.Options{InMemory: true, UpstreamDialer: upstream.MySQLDialer})
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	if err = mysqldial.Register("iamproxy-test", e); err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("mysql", "alice:"+googleToken(t, e)+"@iamproxy-test(my.example.internal:13306)/appdb?tls=iamproxy-test&allowCleartextPasswords=true")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var user string
	if err = db.QueryRow("select current_user()").Scan(&user); err != nil {
		t.Fatal(err)
	}
	if user != "backend@%" {
		t.Fatalf("current_user() = %q", user)
	}
	if dials := upstream.Dials(); len(dials) != 1 || dials[0] != "db:3306" {
		t.Fatalf("upstream dials = %q", dials)
	}
}

func TestRegisterRejectsReservedName(t *testing.T) {
	e, err := iamproxy.Start(context.Background(), &iamproxy.Config{
		Listeners: []iamproxy.Listener{{Name: "my", Listen: "127.0.0.1:13306", Provider: "google", Engine: "mysql", Instance: "testdb", Upstream: "db:3306"}},
	}, iamproxy.Options{InMemory: true})
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	if err = mysqldial.Register("skip-verify", e); err == nil {
		t.Fatal("reserved TLS name accepted")
	}
}

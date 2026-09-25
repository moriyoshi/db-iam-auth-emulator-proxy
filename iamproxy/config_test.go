package iamproxy

import (
	"reflect"
	"testing"

	"github.com/goccy/go-yaml"
)

func TestConfigRejectsAmbiguousGoogleUsername(t *testing.T) {
	c := &Config{TLSCert: "cert", TLSKey: "key", Listeners: []Listener{{Name: "g", Listen: "127.0.0.1:13306", Provider: "google", Engine: "mysql", Instance: "testdb", Upstream: "127.0.0.1:3306"}}, Principals: []Principal{
		{ID: "one", Email: "alice@example.com", BackendUser: "one", BackendPassword: "secret", Grants: []string{"g"}},
		{ID: "two", Email: "alice@other.com", BackendUser: "two", BackendPassword: "secret", Grants: []string{"g"}},
	}}
	if err := c.Validate(); err == nil {
		t.Fatal("colliding MySQL usernames accepted")
	}
}

func TestConfigRejectsRemoteCredentialEndpoint(t *testing.T) {
	c := &Config{HTTPListen: "0.0.0.0:8090"}
	if err := c.Validate(); err == nil {
		t.Fatal("remote credential endpoint accepted")
	}
}

func TestConfigRejectsRemoteTLSCredentialEndpoint(t *testing.T) {
	c := &Config{HTTPSListen: "0.0.0.0:8443"}
	if err := c.Validate(); err == nil {
		t.Fatal("remote TLS credential endpoint accepted")
	}
}

func TestParseConfigReadsYAML(t *testing.T) {
	c, err := ParseConfig([]byte(`
tls_cert: cert
tls_key: key
listeners:
  - name: pg
    listen: 127.0.0.1:15432
    provider: azure
    engine: postgres
    instance: testdb
    tenant: tenant-1
    upstream: 127.0.0.1:5432
principals:
  - id: alice
    email: alice@example.com
    grants: [pg]
    backend_user: backend
    backend_password: secret
`))
	if err != nil {
		t.Fatal(err)
	}
	if c.HTTPListen != "127.0.0.1:8090" || c.Listeners[0].Tenant != "tenant-1" || !c.Principals[0].Granted("pg") {
		t.Fatalf("unexpected configuration: %+v", c)
	}
}

func TestParseConfigRejectsInvalidDocuments(t *testing.T) {
	for name, input := range map[string]string{
		"empty":             "# nothing\n",
		"unknown field":     "tls_cert: cert\ntls_key: key\nlistner: []\n",
		"nested unknown":    "listeners:\n  - name: pg\n    upstram: 127.0.0.1:5432\n",
		"second document":   "tls_cert: cert\n---\ntls_key: key\n",
		"failed validation": "tls_cert: cert\n",
	} {
		if _, err := ParseConfig([]byte(input)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestExampleConfigIsValid(t *testing.T) {
	if _, err := LoadConfig("../config.example.yaml"); err != nil {
		t.Fatal(err)
	}
}

func TestConfigYAMLRoundTrip(t *testing.T) {
	want, err := LoadConfig("../config.example.yaml")
	if err != nil {
		t.Fatal(err)
	}
	b, err := yaml.Marshal(want)
	if err != nil {
		t.Fatal(err)
	}
	got, err := ParseConfig(b)
	if err != nil {
		t.Fatalf("%v\n%s", err, b)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("round trip changed configuration:\n%s", b)
	}
}

package iamproxy

import (
	"context"
	"database/sql"
	"errors"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	mysqlDriver "github.com/go-sql-driver/mysql"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/moriyoshi/db-iam-auth-emulator-proxy/internal/fakedb"
)

func embeddedConfig(engine, listen string) *Config {
	return &Config{
		Listeners:  []Listener{{Name: "db", Listen: listen, Provider: "aws", Engine: engine, Instance: "testdb", Hostname: "db.cluster.us-east-1.rds.amazonaws.com", Region: "us-east-1", ResourceID: "db-test", Upstream: "upstream.internal:5432"}},
		Principals: []Principal{{ID: "alice", Grants: []string{"db"}, BackendUser: "backend", BackendPassword: "backpass", AWSAccessKey: "AKIATEST", AWSSecretKey: "test-secret"}},
	}
}

func startEmbedded(t *testing.T, c *Config, o Options) *Emulator {
	t.Helper()
	e, err := Start(context.Background(), c, o)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = e.Close() })
	return e
}

// memoryPostgres connects by the listener's cloud hostname, which DNS cannot
// resolve, and verifies the emulator's certificate for that name.
func memoryPostgres(t *testing.T, e *Emulator, password string) (*pgconn.PgConn, error) {
	t.Helper()
	return memoryPostgresParams(t, e, password, nil)
}

func memoryPostgresParams(t *testing.T, e *Emulator, password string, params map[string]string) (*pgconn.PgConn, error) {
	t.Helper()
	l := e.Config().Listeners[0]
	_, port, _ := net.SplitHostPort(l.Listen)
	cfg, err := pgconn.ParseConfig("sslmode=verify-full dbname=appdb host=" + l.Hostname + " port=" + port)
	if err != nil {
		t.Fatal(err)
	}
	cfg.User = "alice"
	cfg.Password = password
	cfg.TLSConfig.RootCAs = e.CertPool()
	cfg.DialFunc = e.DialContext
	cfg.LookupFunc = func(_ context.Context, host string) ([]string, error) { return []string{host}, nil }
	for k, v := range params {
		cfg.RuntimeParams[k] = v
	}
	return pgconn.ConnectConfig(context.Background(), cfg)
}

func TestEmbeddedPostgresInMemory(t *testing.T) {
	upstream := &fakedb.Server{User: "backend", Password: "backpass"}
	e := startEmbedded(t, embeddedConfig("postgres", "127.0.0.1:15432"), Options{InMemory: true, UpstreamDialer: upstream.PostgresDialer})
	l := e.Config().Listeners[0]
	conn, err := memoryPostgres(t, e, signIntegrationRDS(l, time.Now()))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close(context.Background())
	results, err := conn.Exec(context.Background(), "select current_user").ReadAll()
	if err != nil || len(results) != 1 || len(results[0].Rows) != 1 || string(results[0].Rows[0][0]) != "backend" {
		t.Fatalf("query through emulator: %v %+v", err, results)
	}
	if dials := upstream.Dials(); len(dials) != 1 || dials[0] != "upstream.internal:5432" {
		t.Fatalf("upstream dials = %q", dials)
	}
	if s := upstream.Startups(); len(s) != 1 || s[0]["user"] != "backend" || s[0]["database"] != "appdb" {
		t.Fatalf("upstream startup = %v", s)
	}
	if err = conn.CancelRequest(context.Background()); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for len(upstream.Cancels()) == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if c := upstream.Cancels(); len(c) != 1 {
		t.Fatalf("cancel requests reaching upstream = %v", c)
	}
	if dials := upstream.Dials(); len(dials) != 2 || dials[1] != "upstream.internal:5432" {
		t.Fatalf("cancel dialed %q", dials)
	}
}

func TestEmbeddedPostgresReplicationStartup(t *testing.T) {
	upstream := &fakedb.Server{User: "backend", Password: "backpass"}
	e := startEmbedded(t, embeddedConfig("postgres", "127.0.0.1:15432"), Options{InMemory: true, UpstreamDialer: upstream.PostgresDialer})
	l := e.Config().Listeners[0]
	for _, tc := range []struct{ client, upstream string }{{"database", "database"}, {"true", "true"}, {"on", "true"}, {"off", ""}, {"", ""}} {
		var params map[string]string
		if tc.client != "" {
			params = map[string]string{"replication": tc.client}
		}
		conn, err := memoryPostgresParams(t, e, signIntegrationRDS(l, time.Now()), params)
		if err != nil {
			t.Fatalf("replication=%q: %v", tc.client, err)
		}
		conn.Close(context.Background())
		s := upstream.Startups()
		got, ok := s[len(s)-1]["replication"]
		if tc.upstream == "" && ok || tc.upstream != "" && got != tc.upstream {
			t.Errorf("replication=%q reached upstream as %q (present %v), want %q", tc.client, got, ok, tc.upstream)
		}
	}
	dials := len(upstream.Dials())
	_, err := memoryPostgresParams(t, e, signIntegrationRDS(l, time.Now()), map[string]string{"replication": "bogus"})
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) || pgErr.Code != "22023" {
		t.Fatalf("invalid replication error = %v", err)
	}
	if len(upstream.Dials()) != dials {
		t.Fatal("invalid replication parameter dialed upstream")
	}
}

func TestEmbeddedRejectsBadTokenBeforeUpstream(t *testing.T) {
	upstream := &fakedb.Server{User: "backend", Password: "backpass"}
	e := startEmbedded(t, embeddedConfig("postgres", "127.0.0.1:15432"), Options{InMemory: true, UpstreamDialer: upstream.PostgresDialer})
	_, err := memoryPostgres(t, e, "not-a-token")
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) || pgErr.Code != "28P01" {
		t.Fatalf("bad token error = %v", err)
	}
	if dials := upstream.Dials(); len(dials) != 0 {
		t.Fatalf("upstream dialed before authentication: %q", dials)
	}
}

// mysqlInMemory opens a go-sql-driver connection to the listener's cloud
// hostname through e's in-memory dialer.
func mysqlInMemory(t *testing.T, upstream *fakedb.Server) (*Emulator, *sql.DB) {
	t.Helper()
	c := embeddedConfig("mysql", "127.0.0.1:13306")
	c.Listeners[0].Upstream = "upstream.internal:3306"
	e := startEmbedded(t, c, Options{InMemory: true, UpstreamDialer: upstream.MySQLDialer})
	l := e.Config().Listeners[0]
	network := "iamproxy-" + t.Name()
	mysqlDriver.RegisterDialContext(network, func(ctx context.Context, addr string) (net.Conn, error) {
		return e.DialContext(ctx, "tcp", addr)
	})
	config := mysqlDriver.NewConfig()
	config.User = "alice"
	config.Passwd = signIntegrationRDS(l, time.Now())
	config.Net = network
	config.Addr = l.Hostname + ":13306"
	config.DBName = "appdb"
	config.TLS = e.ClientTLSConfig()
	config.AllowCleartextPasswords = true
	connector, err := mysqlDriver.NewConnector(config)
	if err != nil {
		t.Fatal(err)
	}
	db := sql.OpenDB(connector)
	t.Cleanup(func() { _ = db.Close() })
	return e, db
}

func TestEmbeddedMySQLInMemory(t *testing.T) {
	upstream := &fakedb.Server{User: "backend", Password: "backpass"}
	_, db := mysqlInMemory(t, upstream)
	var user string
	if err := db.QueryRow("select current_user()").Scan(&user); err != nil {
		t.Fatal(err)
	}
	if user != "backend@%" {
		t.Fatalf("current_user() = %q", user)
	}
	if dials := upstream.Dials(); len(dials) != 1 || dials[0] != "upstream.internal:3306" {
		t.Fatalf("upstream dials = %q", dials)
	}
	if s := upstream.Startups(); len(s) != 1 || s[0]["user"] != "backend" || s[0]["database"] != "appdb" {
		t.Fatalf("upstream login = %v", s)
	}
}

func TestEmbeddedMySQLRefusesCapabilityMismatch(t *testing.T) {
	// go-sql-driver always negotiates CLIENT_DEPRECATE_EOF; relaying from an
	// upstream without it would misframe every result set.
	_, db := mysqlInMemory(t, &fakedb.Server{User: "backend", Password: "backpass", NoDeprecateEOF: true})
	err := db.Ping()
	var myErr *mysqlDriver.MySQLError
	if !errors.As(err, &myErr) || myErr.Number != 1235 {
		t.Fatalf("capability mismatch error = %v", err)
	}
}

func TestEmbeddedEphemeralTCP(t *testing.T) {
	e := startEmbedded(t, embeddedConfig("postgres", "127.0.0.1:0"), Options{})
	addr, ok := e.ListenerAddr("db")
	if _, port, _ := net.SplitHostPort(addr); !ok || port == "0" {
		t.Fatalf("listener address = %q", addr)
	}
	c := e.Config()
	if c.PublicURL != e.HTTPURL() || strings.HasSuffix(e.HTTPURL(), ":0") {
		t.Fatalf("public URL %q, HTTP URL %q", c.PublicURL, e.HTTPURL())
	}
	r, err := http.Get(e.HTTPURL() + "/healthz")
	if err != nil {
		t.Fatal(err)
	}
	r.Body.Close()
	if r.StatusCode != 200 {
		t.Fatalf("healthz = %d", r.StatusCode)
	}
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	conn.Close()
}

func TestEmbeddedDialRouting(t *testing.T) {
	c := embeddedConfig("postgres", "127.0.0.1:15432")
	e := startEmbedded(t, c, Options{InMemory: true})
	ctx := context.Background()
	for _, addr := range []string{"127.0.0.1:15432", "db.cluster.us-east-1.rds.amazonaws.com:15432"} {
		conn, err := e.DialContext(ctx, "tcp", addr)
		if err != nil {
			t.Fatalf("%s: %v", addr, err)
		}
		conn.Close()
	}
	for _, addr := range []string{"127.0.0.1:5432", "upstream.internal:5432", "db.cluster.us-east-1.rds.amazonaws.com:5432"} {
		if _, err := e.DialContext(ctx, "tcp", addr); err == nil {
			t.Errorf("%s: dial accepted", addr)
		}
	}
	if _, err := e.DialContext(ctx, "unix", "127.0.0.1:15432"); err == nil {
		t.Error("unix network accepted")
	}
	c.Listeners[0].Hostname = "changed.example"
	if got := e.Config().Listeners[0].Hostname; got != "db.cluster.us-east-1.rds.amazonaws.com" {
		t.Fatalf("caller mutation reached emulator: %q", got)
	}
	if err := e.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-e.Done():
	default:
		t.Fatal("Done not closed after Close")
	}
	if _, err := e.DialContext(ctx, "tcp", "127.0.0.1:15432"); err == nil {
		t.Fatal("dial accepted after Close")
	}
}

func TestEmbeddedInMemoryNeedsFixedPort(t *testing.T) {
	if _, err := Start(context.Background(), embeddedConfig("postgres", "127.0.0.1:0"), Options{InMemory: true}); err == nil {
		t.Fatal("ephemeral in-memory listener accepted")
	}
}

package iamproxy

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	mysqlDriver "github.com/go-sql-driver/mysql"
	"github.com/jackc/pglogrepl"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgproto3"
)

func TestIntegrationSixProfiles(t *testing.T) {
	if os.Getenv("IAM_PROXY_E2E") != "1" {
		t.Skip("set IAM_PROXY_E2E=1 and provide local databases")
	}
	pgAddr := os.Getenv("IAM_PROXY_PG_ADDR")
	if pgAddr == "" {
		pgAddr = "127.0.0.1:25432"
	}
	myAddr := os.Getenv("IAM_PROXY_MYSQL_ADDR")
	if myAddr == "" {
		myAddr = "127.0.0.1:23306"
	}
	c := &Config{}
	for _, provider := range []string{"aws", "google", "azure"} {
		for _, engine := range []string{"postgres", "mysql"} {
			name := provider + "-" + engine
			l := Listener{Name: name, Listen: "127.0.0.1:0", Provider: provider, Engine: engine, Instance: "testdb", Hostname: name + ".db.test", Region: "us-east-1", ResourceID: "db-test", Tenant: "tenant-1", UpstreamTLS: "disable"}
			if engine == "postgres" {
				l.Upstream = pgAddr
			} else {
				l.Upstream = myAddr
			}
			c.Listeners = append(c.Listeners, l)
		}
	}
	c.Principals = []Principal{{ID: "alice", Email: "alice@example.com", Grants: []string{"aws-postgres", "aws-mysql", "google-postgres", "google-mysql", "azure-postgres", "azure-mysql"}, BackendUser: "backend", BackendPassword: "backpass", AWSAccessKey: "AKIATEST", AWSSecretKey: "test-secret", GoogleRefreshToken: "refresh", AzureClientID: "client-1", AzureClientSecret: "secret"}}
	emu, err := Start(context.Background(), c, Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer emu.Close()
	c = emu.Config()
	mysqlDriver.RegisterDialContext("iamproxy-integration", func(ctx context.Context, addr string) (net.Conn, error) {
		return emu.DialContext(ctx, "tcp", addr)
	})
	if err = mysqlDriver.RegisterTLSConfig("iamproxy-integration", &tls.Config{RootCAs: emu.CertPool()}); err != nil {
		t.Fatal(err)
	}
	clientHTTP := &http.Client{Timeout: time.Second}
	issueGoogle := func() string {
		req, _ := http.NewRequest("GET", c.PublicURL+"/computeMetadata/v1/instance/service-accounts/default/token?principal=alice", nil)
		req.Header.Set("Metadata-Flavor", "Google")
		r, e := clientHTTP.Do(req)
		if e != nil {
			t.Fatal(e)
		}
		defer r.Body.Close()
		var v struct {
			AccessToken string `json:"access_token"`
		}
		if e = json.NewDecoder(r.Body).Decode(&v); e != nil {
			t.Fatal(e)
		}
		return v.AccessToken
	}
	issueAzure := func() string {
		u := c.PublicURL + "/metadata/identity/oauth2/token?api-version=2018-02-01&resource=" + url.QueryEscape(azureAudience) + "&client_id=client-1"
		req, _ := http.NewRequest("GET", u, nil)
		req.Header.Set("Metadata", "true")
		r, e := clientHTTP.Do(req)
		if e != nil {
			t.Fatal(e)
		}
		defer r.Body.Close()
		var v struct {
			AccessToken string `json:"access_token"`
		}
		if e = json.NewDecoder(r.Body).Decode(&v); e != nil {
			t.Fatal(e)
		}
		return v.AccessToken
	}
	googleToken := issueGoogle()
	azureToken := issueAzure()
	for _, l := range c.Listeners {
		for _, transport := range []string{"tcp", "memory"} {
			t.Run(l.Name+"/"+transport, func(t *testing.T) {
				username := "alice"
				token := ""
				switch l.Provider {
				case "aws":
					token = signIntegrationRDS(l, time.Now())
				case "google":
					token = googleToken
					if l.Engine == "postgres" {
						username = "alice@example.com"
					}
				case "azure":
					token = azureToken
					username = "alice@example.com"
				}
				_, port, _ := net.SplitHostPort(l.Listen)
				// TCP reaches the bound loopback address; memory reaches the
				// listener by its cloud hostname, which DNS cannot resolve.
				host := "127.0.0.1"
				if transport == "memory" {
					host = l.Hostname
				}
				if l.Engine == "postgres" {
					cfg, e := pgconn.ParseConfig("sslmode=verify-full host=" + host + " port=" + port)
					if e != nil {
						t.Fatal(e)
					}
					cfg.Database = "testdb"
					cfg.User = username
					cfg.Password = token
					cfg.TLSConfig.RootCAs = emu.CertPool()
					cfg.Fallbacks = nil
					if transport == "memory" {
						cfg.DialFunc = emu.DialContext
						cfg.LookupFunc = func(_ context.Context, host string) ([]string, error) { return []string{host}, nil }
					}
					conn, e := pgconn.ConnectConfig(context.Background(), cfg)
					if e != nil {
						t.Fatal(e)
					}
					defer conn.Close(context.Background())
					result := conn.ExecParams(context.Background(), "select current_user", nil, nil, nil, nil).Read()
					if result.Err != nil || len(result.Rows) != 1 || string(result.Rows[0][0]) != "backend" {
						t.Fatalf("current_user: %v %q", result.Err, result.Rows)
					}
					// pgx sends CancelRequest over TLS, like libpq 17+.
					go func() {
						time.Sleep(200 * time.Millisecond)
						_ = conn.CancelRequest(context.Background())
					}()
					_, e = conn.Exec(context.Background(), "select pg_sleep(30)").ReadAll()
					var pgErr *pgconn.PgError
					if !errors.As(e, &pgErr) || pgErr.Code != "57014" {
						t.Fatalf("cancelled query error = %v", e)
					}
				} else {
					config := mysqlDriver.NewConfig()
					config.User = username
					config.Passwd = token
					config.Net = "tcp"
					if transport == "memory" {
						config.Net = "iamproxy-integration"
					}
					config.Addr = net.JoinHostPort(host, port)
					config.DBName = "testdb"
					config.TLSConfig = "iamproxy-integration"
					config.AllowCleartextPasswords = true
					conn, e := sql.Open("mysql", config.FormatDSN())
					if e != nil {
						t.Fatal(e)
					}
					defer conn.Close()
					var user string
					if e = conn.QueryRow("select current_user()").Scan(&user); e != nil {
						t.Fatal(e)
					}
					if !strings.HasPrefix(user, "backend@") {
						t.Fatalf("current_user() = %q", user)
					}
				}
			})
		}
	}
	if err := emu.Close(); err != nil {
		t.Fatal(err)
	}
}

// TestIntegrationPostgresLogicalReplication streams logical decoding through
// the proxy with pglogrepl. The upstream needs wal_level=logical and a backend
// user with REPLICATION.
func TestIntegrationPostgresLogicalReplication(t *testing.T) {
	if os.Getenv("IAM_PROXY_E2E") != "1" {
		t.Skip("set IAM_PROXY_E2E=1 and provide a local PostgreSQL with wal_level=logical")
	}
	pgAddr := os.Getenv("IAM_PROXY_PG_ADDR")
	if pgAddr == "" {
		pgAddr = "127.0.0.1:25432"
	}
	c := &Config{
		Listeners:  []Listener{{Name: "aws-postgres", Listen: "127.0.0.1:0", Provider: "aws", Engine: "postgres", Instance: "testdb", Hostname: "aws-postgres.db.test", Region: "us-east-1", ResourceID: "db-test", Upstream: pgAddr, UpstreamTLS: "disable"}},
		Principals: []Principal{{ID: "alice", Grants: []string{"aws-postgres"}, BackendUser: "backend", BackendPassword: "backpass", AWSAccessKey: "AKIATEST", AWSSecretKey: "test-secret"}},
	}
	emu, err := Start(context.Background(), c, Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer emu.Close()
	l := emu.Config().Listeners[0]
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	connect := func(params map[string]string) *pgconn.PgConn {
		t.Helper()
		_, port, _ := net.SplitHostPort(l.Listen)
		cfg, e := pgconn.ParseConfig("sslmode=verify-full dbname=testdb host=" + l.Hostname + " port=" + port)
		if e != nil {
			t.Fatal(e)
		}
		cfg.User = "alice"
		cfg.Password = signIntegrationRDS(l, time.Now())
		cfg.TLSConfig.RootCAs = emu.CertPool()
		cfg.Fallbacks = nil
		cfg.DialFunc = emu.DialContext
		cfg.LookupFunc = func(_ context.Context, host string) ([]string, error) { return []string{host}, nil }
		for k, v := range params {
			cfg.RuntimeParams[k] = v
		}
		conn, e := pgconn.ConnectConfig(ctx, cfg)
		if e != nil {
			t.Fatal(e)
		}
		t.Cleanup(func() { _ = conn.Close(context.Background()) })
		return conn
	}
	normal := connect(nil)
	if _, err = normal.Exec(ctx, "create table if not exists iamproxy_repl_probe (id serial primary key, marker text not null)").ReadAll(); err != nil {
		t.Fatal(err)
	}
	repl := connect(map[string]string{"replication": "database"})
	sys, err := pglogrepl.IdentifySystem(ctx, repl)
	if err != nil {
		t.Fatalf("IDENTIFY_SYSTEM through proxy: %v", err)
	}
	if sys.DBName != "testdb" {
		t.Fatalf("IDENTIFY_SYSTEM dbname = %q", sys.DBName)
	}
	slot := fmt.Sprintf("iamproxy_probe_%d", time.Now().UnixNano())
	created, err := pglogrepl.CreateReplicationSlot(ctx, repl, slot, "test_decoding", pglogrepl.CreateReplicationSlotOptions{Temporary: true, Mode: pglogrepl.LogicalReplication})
	if err != nil {
		t.Fatalf("CREATE_REPLICATION_SLOT through proxy: %v", err)
	}
	start, err := pglogrepl.ParseLSN(created.ConsistentPoint)
	if err != nil {
		t.Fatal(err)
	}
	if err = pglogrepl.StartReplication(ctx, repl, slot, start, pglogrepl.StartReplicationOptions{Mode: pglogrepl.LogicalReplication}); err != nil {
		t.Fatalf("START_REPLICATION through proxy: %v", err)
	}
	marker := "marker-" + slot
	if _, err = normal.Exec(ctx, "insert into iamproxy_repl_probe (marker) values ('"+marker+"')").ReadAll(); err != nil {
		t.Fatal(err)
	}
	for {
		msg, e := repl.ReceiveMessage(ctx)
		if e != nil {
			t.Fatalf("replication stream: %v", e)
		}
		cd, ok := msg.(*pgproto3.CopyData)
		if !ok {
			t.Fatalf("unexpected replication message %T", msg)
		}
		if len(cd.Data) == 0 || cd.Data[0] != pglogrepl.XLogDataByteID {
			continue
		}
		x, e := pglogrepl.ParseXLogData(cd.Data[1:])
		if e != nil {
			t.Fatal(e)
		}
		if strings.Contains(string(x.WALData), "INSERT") && strings.Contains(string(x.WALData), marker) {
			end := x.WALStart + pglogrepl.LSN(len(x.WALData))
			if e = pglogrepl.SendStandbyStatusUpdate(ctx, repl, pglogrepl.StandbyStatusUpdate{WALWritePosition: end}); e != nil {
				t.Fatal(e)
			}
			break
		}
	}
	result := normal.ExecParams(ctx, "select count(*) from iamproxy_repl_probe where marker = $1", [][]byte{[]byte(marker)}, nil, nil, nil).Read()
	if result.Err != nil || len(result.Rows) != 1 || string(result.Rows[0][0]) != "1" {
		t.Fatalf("normal query alongside replication: %v %q", result.Err, result.Rows)
	}
}

func signIntegrationRDS(l Listener, now time.Time) string {
	_, port, _ := net.SplitHostPort(l.Listen)
	host := net.JoinHostPort(l.Hostname, port)
	date := now.UTC().Format("20060102T150405Z")
	cred := "AKIATEST/" + now.UTC().Format("20060102") + "/" + l.Region + "/rds-db/aws4_request"
	v := url.Values{"Action": {"connect"}, "DBUser": {"alice"}, "X-Amz-Algorithm": {"AWS4-HMAC-SHA256"}, "X-Amz-Credential": {cred}, "X-Amz-Date": {date}, "X-Amz-Expires": {"900"}, "X-Amz-SignedHeaders": {"host"}}
	canonical := "GET\n/\n" + awsQuery(v) + "\nhost:" + host + "\n\nhost\ne3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	h := sha256.Sum256([]byte(canonical))
	sts := "AWS4-HMAC-SHA256\n" + date + "\n" + strings.TrimPrefix(cred, "AKIATEST/") + "\n" + hex.EncodeToString(h[:])
	k := awsHMAC([]byte("AWS4test-secret"), now.UTC().Format("20060102"))
	k = awsHMAC(k, l.Region)
	k = awsHMAC(k, "rds-db")
	k = awsHMAC(k, "aws4_request")
	v.Set("X-Amz-Signature", hex.EncodeToString(awsHMAC(k, sts)))
	return host + "/?" + awsQuery(v)
}

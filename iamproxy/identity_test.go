package iamproxy

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	rdsauth "github.com/aws/aws-sdk-go-v2/feature/rds/auth"
)

func fixtureService(t *testing.T) (*service, []Listener) {
	t.Helper()
	l := []Listener{
		{Name: "aws-pg", Listen: "127.0.0.1:15432", Provider: "aws", Engine: "postgres", Instance: "db", Hostname: "db.test", Region: "us-east-1", ResourceID: "db-123"},
		{Name: "google-my", Listen: "127.0.0.1:13306", Provider: "google", Engine: "mysql", Instance: "db"},
		{Name: "azure-pg", Listen: "127.0.0.1:15433", Provider: "azure", Engine: "postgres", Instance: "db", Tenant: "tenant-1"},
	}
	c := &Config{PublicURL: "http://127.0.0.1:8090", Listeners: l, Principals: []Principal{{ID: "alice", Email: "alice@example.com", Groups: []string{"readers"}, Grants: []string{"aws-pg", "google-my", "azure-pg"}, AWSAccessKey: "AKIATEST", AWSSecretKey: "test-secret", GoogleRefreshToken: "refresh", AzureClientID: "client-1", AzureClientSecret: "secret"}}}
	s, err := newService(c)
	if err != nil {
		t.Fatal(err)
	}
	s.Now = func() time.Time { return time.Date(2026, 9, 25, 0, 0, 0, 0, time.UTC) }
	return s, l
}

func signTestRDS(l Listener, now time.Time) string {
	date := now.Format("20060102T150405Z")
	cred := "AKIATEST/" + now.Format("20060102") + "/us-east-1/rds-db/aws4_request"
	v := url.Values{"Action": {"connect"}, "DBUser": {"alice"}, "X-Amz-Algorithm": {"AWS4-HMAC-SHA256"}, "X-Amz-Credential": {cred}, "X-Amz-Date": {date}, "X-Amz-Expires": {"900"}, "X-Amz-SignedHeaders": {"host"}}
	host := "db.test:15432"
	canonical := "GET\n/\n" + awsQuery(v) + "\nhost:" + host + "\n\nhost\ne3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	h := sha256.Sum256([]byte(canonical))
	sts := "AWS4-HMAC-SHA256\n" + date + "\n" + strings.TrimPrefix(cred, "AKIATEST/") + "\n" + hex.EncodeToString(h[:])
	k := awsHMAC([]byte("AWS4test-secret"), now.Format("20060102"))
	k = awsHMAC(k, "us-east-1")
	k = awsHMAC(k, "rds-db")
	k = awsHMAC(k, "aws4_request")
	v.Set("X-Amz-Signature", hex.EncodeToString(awsHMAC(k, sts)))
	return host + "/?" + awsQuery(v)
}

func TestRDSValidation(t *testing.T) {
	s, l := fixtureService(t)
	token := signTestRDS(l[0], s.Now())
	if _, err := s.Validate(l[0], "alice", token); err != nil {
		t.Fatalf("valid token: %v", err)
	}
	for name, bad := range map[string]string{"wrong user": strings.Replace(token, "DBUser=alice", "DBUser=bob", 1), "bad signature": token + "x", "wrong host": strings.Replace(token, "db.test", "wrong.test", 1)} {
		if _, err := s.Validate(l[0], "alice", bad); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	s.Now = func() time.Time { return time.Date(2026, 9, 25, 0, 16, 0, 0, time.UTC) }
	if _, err := s.Validate(l[0], "alice", token); err == nil {
		t.Fatal("expired token accepted")
	}
}

func TestRDSValidationAWSSDK(t *testing.T) {
	s, l := fixtureService(t)
	s.Now = time.Now
	build := func(region, secret string) string {
		t.Helper()
		creds := aws.CredentialsProviderFunc(func(context.Context) (aws.Credentials, error) {
			return aws.Credentials{AccessKeyID: "AKIATEST", SecretAccessKey: secret}, nil
		})
		token, err := rdsauth.BuildAuthToken(context.Background(), "db.test:15432", region, "alice", creds)
		if err != nil {
			t.Fatal(err)
		}
		return token
	}
	token := build("us-east-1", "test-secret")
	if !strings.HasPrefix(token, "db.test:15432?") {
		t.Fatalf("SDK token shape changed: %q", token)
	}
	if _, err := s.Validate(l[0], "alice", token); err != nil {
		t.Fatalf("SDK token: %v", err)
	}
	// An explicit "/" path signs identically.
	if _, err := s.Validate(l[0], "alice", strings.Replace(token, "?", "/?", 1)); err != nil {
		t.Fatalf("SDK token with slash path: %v", err)
	}
	for name, bad := range map[string]string{
		"wrong secret":   build("us-east-1", "other-secret"),
		"wrong region":   build("us-west-2", "test-secret"),
		"wrong user":     strings.Replace(token, "DBUser=alice", "DBUser=bob", 1),
		"other path":     strings.Replace(token, "?", "/x?", 1),
		"encoded path":   strings.Replace(token, "?", "/%2F?", 1),
		"tampered query": strings.Replace(token, "X-Amz-Expires=900", "X-Amz-Expires=899", 1),
	} {
		if _, err := s.Validate(l[0], "alice", bad); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}

func TestGoogleAndAzureValidation(t *testing.T) {
	s, l := fixtureService(t)
	token, _ := s.googleIssue(&s.Config.Principals[0], googleSQLScope)
	if _, err := s.Validate(l[1], "alice", token); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Validate(l[1], "bob", token); err == nil {
		t.Fatal("wrong Google username accepted")
	}
	azure, err := s.azureIssue(&s.Config.Principals[0], "tenant-1", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Validate(l[2], "alice@example.com", azure); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Validate(l[2], "readers", azure); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Validate(l[2], "other", azure); err == nil {
		t.Fatal("wrong Azure user accepted")
	}
	s.Now = func() time.Time { return time.Date(2026, 9, 25, 1, 0, 0, 0, time.UTC) }
	if _, err := s.Validate(l[1], "alice", token); err == nil {
		t.Fatal("expired Google token accepted")
	}
	if _, err := s.Validate(l[2], "alice@example.com", azure); err == nil {
		t.Fatal("expired Azure token accepted")
	}
}

func TestGoogleUsername(t *testing.T) {
	if got := googleUsername("sa@project.iam.gserviceaccount.com", "postgres"); got != "sa@project.iam" {
		t.Fatal(got)
	}
	if got := googleUsername("Alice@Example.Com", "mysql"); got != "alice" {
		t.Fatal(got)
	}
}

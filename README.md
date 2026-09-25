# db-iam-auth-emulator-proxy

A Go forward proxy for testing database clients that authenticate with Amazon
RDS IAM, Google Cloud SQL IAM, or Azure Database Microsoft Entra credentials.
It accepts MySQL and PostgreSQL wire protocols, verifies fixture credentials,
then connects to a stock database as the configured per-principal backend user.

The first release covers manual token login for all six provider/engine pairs.
The mock credential HTTP service provides AWS IMDSv2 and ECS task credentials, Google
metadata and refresh-token endpoints, and Azure managed-identity and OAuth
endpoints. RDS login tokens are generated locally by the AWS SDK or CLI; there
is no RDS token-minting HTTP API. Cloud SQL Auth Proxy and language-connector
automatic login are not implemented.

## Build and run

```sh
make build
cp config.example.yaml config.yaml
./.agents-workspace/tmp/db-iam-auth-emulator-proxy -validate -config config.yaml
./.agents-workspace/tmp/db-iam-auth-emulator-proxy -config config.yaml
```

Generate a test certificate and key before validation:

```sh
openssl req -x509 -newkey rsa:2048 -nodes -days 1 \
  -subj '/CN=localhost' -addext 'subjectAltName=DNS:localhost,IP:127.0.0.1' \
  -keyout server.key -out server.crt
```

Edit the example's upstream addresses, backend accounts, and grants to match
your local databases. The example credentials are public fixtures and must be
replaced for any shared environment. Listeners and mock endpoints currently
bind only to loopback. Client connections require TLS; MySQL clients must
enable `mysql_clear_password` and PostgreSQL clients must pass the token as the
password. Backend TLS mode can be `disable`, `require` (encrypted without
certificate verification), or `verify-full`.

Each listener fixes one provider, engine, instance, and upstream address.
Each principal has an explicit grant for the listener and a matching backend
database account. The proxy does not create SQL users or grant SQL privileges.
Provision those accounts in MySQL/PostgreSQL before connecting.

## Credential endpoints

| Provider | Fixture source | Example use |
| --- | --- | --- |
| AWS | IMDSv2 `PUT /latest/api/token` and `/latest/meta-data/iam/security-credentials/<principal-id>`, or ECS `/v2/credentials/<principal-id>` and `/ecs/v4/<principal-id>/task` | Point `AWS_EC2_METADATA_SERVICE_ENDPOINT` or `AWS_CONTAINER_CREDENTIALS_FULL_URI` at the mock, then run `aws rds generate-db-auth-token` |
| Google | `GET /computeMetadata/v1/instance/service-accounts/default/token?principal=<id>` with `Metadata-Flavor: Google`, or `POST /token` with `grant_type=refresh_token` | Use returned `access_token` with the Cloud SQL login scope as the password |
| Azure | `GET /metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://ossrdbms-aad.database.windows.net&client_id=<id>` with `Metadata: true`, or `POST /<tenant>/oauth2/v2.0/token` with client credentials | Use returned `access_token` as the password |

The Azure service also exposes `/<tenant>/v2.0/.well-known/openid-configuration`
and `/<tenant>/discovery/v2.0/keys`. Point SDK credential source URLs to the
mock base URL explicitly; SDK support for endpoint overrides varies. The mock
does not intercept cloud hostnames or support all SDK credential chains.

`DefaultAzureCredential` and other MSAL-based client secret credentials work
offline against the TLS routes: set `AZURE_AUTHORITY_HOST` to the
`https_listen` base URL with a trailing slash, `AZURE_TENANT_ID`,
`AZURE_CLIENT_ID`, and `AZURE_CLIENT_SECRET`, trust the proxy certificate in
the credential's HTTP transport, and set `DisableInstanceDiscovery` (MSAL
otherwise asks `login.microsoftonline.com` to validate the authority). Request
the `https://ossrdbms-aad.database.windows.net/.default` scope; other
audiences are refused.

AWS SDK for Go v2 `rds/auth.BuildAuthToken` tokens (`host:port?...`, without a
`/` path) are accepted like AWS CLI tokens.

PostgreSQL listeners forward the `replication` startup parameter, so logical
replication clients (`replication=database`) and physical ones
(`replication=true`) work when the backend account has `REPLICATION` and the
upstream allows it (for logical decoding, `wal_level=logical`).

Set `https_listen` to expose the same credential routes over TLS with
`tls_cert` and `tls_key`. The E2E Azure CLI scenario uses this for a local
mock resource manager and trusts the fixture certificate.

The IMDSv2 endpoint requires a TTL from 1 to 21600 seconds and a valid
`X-aws-ec2-metadata-token` header on role metadata reads. Set
`AWS_EC2_METADATA_V1_DISABLED=true` to make CLI fallback failures visible.
The `aws-imdsv2-cli.star` scenario clears inherited AWS credentials and
profiles before calling the real AWS CLI, proving that it uses the mock IMDSv2
service.

For an ECS credential chain, set
`AWS_CONTAINER_CREDENTIALS_FULL_URI=http://127.0.0.1:8090/v2/credentials/<principal-id>`.
If the principal config has `ecs_authorization_token`, set
`AWS_CONTAINER_AUTHORIZATION_TOKEN` to the same value. The optional
`ECS_CONTAINER_METADATA_URI_V4=http://127.0.0.1:8090/ecs/v4/<principal-id>`
exposes container and `/task` metadata. The `aws-ecs-cli.star` scenario clears
other AWS credentials and uses the real AWS CLI to fetch ECS credentials and
sign an RDS token.

The metadata mock also serves `/taskWithTags`, `/stats`, and `/task/stats`.

## Embedding in Go

Package `iamproxy` runs the same listeners and credential endpoints inside
another Go process. `Start` validates a copy of the configuration, binds it,
and returns immediately; `Close` shuts it down.

```go
e, err := iamproxy.Start(ctx, &iamproxy.Config{
	Listeners: []iamproxy.Listener{{
		Name: "orders", Listen: "127.0.0.1:0", Provider: "aws", Engine: "postgres",
		Instance: "orders", Hostname: "orders.cluster.us-east-1.rds.amazonaws.com",
		Region: "us-east-1", ResourceID: "db-orders", Upstream: "127.0.0.1:5432",
	}},
	Principals: []iamproxy.Principal{{ID: "app", Grants: []string{"orders"},
		BackendUser: "app", BackendPassword: "secret",
		AWSAccessKey: "AKIATEST", AWSSecretKey: "test-secret"}},
}, iamproxy.Options{})
defer e.Close()
addr, _ := e.ListenerAddr("orders") // bound loopback address
imds := e.HTTPURL() + "/"           // AWS_EC2_METADATA_SERVICE_ENDPOINT
```

An empty `http_listen` and listener ports of `0` bind ephemeral loopback
ports; `Config()` reports the bound addresses and derived `public_url`.
Without `tls_cert`, `tls_key`, or `Options.Certificate`, the emulator
generates a self-signed certificate for localhost, loopback addresses, and
every listener hostname. Trust it with `CertPool()`, `ClientTLSConfig()`, or
`CertificatePEM()`. `Options.Logger` takes an `*slog.Logger`; the default
discards logs.

### In-memory connections

`Emulator.DialContext` opens a connection to a listener without a socket.
It matches the dialed address against each listener's `listen` address and
its `hostname` with the same port, and never falls back to the network. With
`Options.InMemory`, database listeners bind no TCP port at all, so parallel
tests cannot collide. Their `listen` ports must then be fixed, because AWS
tokens sign the endpoint host and port. Credential HTTP endpoints always use
TCP, since cloud SDKs locate them by URL.

Drivers need a dial hook:

| Driver | Hook |
| --- | --- |
| `jackc/pgx` and `pgconn` | `pgxdial.Configure(cfg, e)` sets `DialFunc`, skips DNS lookup so cloud hostnames reach the emulator, and trusts the emulator certificate |
| `go-sql-driver/mysql` | `mysqldial.Register("iam", e)`, then a DSN like `app:TOKEN@iam(orders.example:3306)/orders?tls=iam&allowCleartextPasswords=true` |
| Any driver with a dial function | Pass `e.DialContext`; its signature matches `net.Dialer.DialContext` |

The go-mysql client cannot connect as a frontend client, because it does not
send `mysql_clear_password`.

`Options.UpstreamDialer` replaces how the emulator reaches backend databases,
for example to use a container network or an in-process fake. It is only
ever called with a listener's configured `upstream`.

## Tests

```sh
go test ./...      # hermetic tests
make e2e-check    # parse/resolve checked-in Starlark scenarios, no Docker
make e2e          # shared image, disposable PostgreSQL 17, MySQL 8.4, MariaDB 10.11
```

The E2E image contains the AWS, Google Cloud, and Azure CLIs, Docker client,
and server files from the official PostgreSQL, MySQL, and MariaDB images.
`make e2e` needs Docker on the host, but uses no host cloud CLI. The runner owns its
containers, process, temporary configuration, and TLS certificate and cleans
them on success or failure. The opt-in Go integration
test can target already running local databases with `IAM_PROXY_E2E=1`;
`IAM_PROXY_PG_ADDR` and `IAM_PROXY_MYSQL_ADDR` override its default addresses.
It embeds the emulator and runs every profile over TCP and in memory. It
expects a `backend` account with password `backpass` and a `testdb` database.
The Starlark suite is the standard live gate.

Scenarios show each cloud CLI command explicitly. `start_proxy()` returns the
mock URLs and fixture paths; shared helpers in `e2e/scenarios/common.star`
prepare environment values with `set_env()`, and `spawn(argv)` inherits that
scenario environment.

See [ARCHITECTURE.md](ARCHITECTURE.md) for protocol boundaries and [PLAN.md](PLAN.md)
for the original roadmap and deferred Cloud SQL connector work.

## License

Copyright 2026 Moriyoshi Koizumi

Licensed under the [Apache License, Version 2.0](LICENSE).

This project is not affiliated with or endorsed by Amazon Web Services, Google,
or Microsoft. Product names are used only to identify the services it emulates.

# IAM database authentication emulation proxies

## Goal and boundary

Build a Go service that accepts ordinary MySQL and PostgreSQL clients, checks
cloud-style login credentials locally, and forwards authenticated sessions to
ordinary MySQL or PostgreSQL servers. A companion HTTP service issues test
credentials through selected cloud-compatible endpoints. The target is local
integration testing, not deployment as a cloud identity provider.

The first release supports **manual token login** for Amazon RDS IAM, Google
Cloud SQL IAM, and Azure Database for MySQL/PostgreSQL Microsoft Entra ID. It
does not claim to be a complete RDS, Cloud SQL, or Azure control plane. Cloud
SQL automatic IAM login through Cloud SQL Auth Proxy or language connectors is
a later compatibility project: those connectors also depend on Cloud SQL Admin
API metadata, ephemeral certificates, and a separate transport.

Go follows the choice in the adjacent `yesno-cdc` project: one distributable
service, mature network/database libraries, and straightforward concurrent
connection handling. Keep protocol and validation logic in small packages so
Go library limitations do not dictate the externally visible behavior.

## External contract

Each listener has a fixed `{provider, engine, instance}` binding and a fixed
upstream database address. The listener address, port, TLS certificate, and
cloud-facing hostname are configured explicitly. A client connects to that
listener using its normal database driver and supplies a token as its password.
The proxy never selects an arbitrary upstream from client-supplied input.

| Profile | Client password | Identity and authorization checks | Credential source to emulate |
| --- | --- | --- | --- |
| RDS MySQL/PostgreSQL | SigV4 presigned `rds-db` URL | Verify signature, access key/session token, region, endpoint and port, `DBUser`, time window, and local `rds-db:connect` grant for the configured DB resource/user | AWS SDK/CLI signs locally; provide fixture AWS credentials or a mock credential-provider endpoint, not a fictional RDS token API |
| Cloud SQL MySQL/PostgreSQL | OAuth 2.0 access token | Resolve token to principal; check expiry, Cloud SQL scope, configured instance login grant, and engine-specific database username | Mock Google metadata token endpoint and OAuth token exchange |
| Azure MySQL/PostgreSQL | Entra access token | Verify issuer, signature, tenant, database audience, expiry, principal and configured instance/user grant | Mock managed-identity endpoint and Entra OAuth token endpoint |

RDS tokens are valid for 15 minutes; Google access tokens are normally valid
for one hour; Azure token lifetime is derived from the token's `exp` claim.
Validate at **connection establishment**, and do not terminate a working
database session merely because its initial login token subsequently expires.
Use an injectable clock and configurable test lifetimes for expiry cases.

For MySQL, use TLS and the `mysql_clear_password` client plugin so the token
reaches the proxy unchanged. For PostgreSQL, request a cleartext `PasswordMessage`
inside TLS. A TLS refusal or plaintext login must fail before a credential is
read. Support long tokens without silent truncation and limit packet/message
size explicitly.

Cloud SQL username normalization is engine-specific: MySQL uses the part of a
user email before `@`, and a service account's name before its service-account
domain; PostgreSQL uses the full user email, while service accounts omit the
`.gserviceaccount.com` suffix. Detect collisions after normalization and reject
ambiguous fixture accounts. Azure usernames can be a user principal name or a
configured group name; group login uses an individual member's token. Do not
infer a group relationship solely from a claimed username.

## Architecture

```text
client credential helper ──HTTP──> mock credential endpoints
         │                             │
         └──MySQL/PostgreSQL + TLS──────┤ fixture identity/permissions
                                       ▼
                              protocol listener
                               ├─ credential validation
                               ├─ principal → backend account mapping
                               └─ upstream login + session forwarding
                                                    │
                                                    ▼
                                         stock MySQL/PostgreSQL
```

Separate `internal/identity` (fixture principals, grants, token registry and
signing keys), `internal/provider/{aws,gcp,azure}` (issue/validate rules),
`internal/wire/{mysql,postgres}` (frontend login and session handling), and
`internal/upstream` (backend login and account mapping). The HTTP issuance
service and database listeners share the same fixture state in one process for
the initial version. Use bounded connection counts, timeouts, and context
cancellation on both sides.

The proxy authenticates the client first, then opens a fresh upstream
connection as a configured **per-principal backend account**. Fixture setup
provides that account and its secret; the database grants its actual SQL
privileges. No SQL parsing or query rewriting is needed. Reject an identity
without an exact mapping. Do not implement a shared administrator account with
query-time `SET ROLE`: it would make identity and privilege behavior misleading,
especially on MySQL. Document that backend roles are provisioned separately
and that the emulation does not reproduce cloud-side role creation.

The proxy must finish each database handshake on both sides before forwarding
the live session. It cannot blindly relay initial auth bytes because the client
and backend use different credentials. After login, preserve database packet
boundaries and state; forward errors and notices accurately. For PostgreSQL,
implement startup/SSL negotiation, password exchange, backend startup metadata,
and CancelRequest routing to the correct upstream connection. For MySQL,
implement handshake, TLS upgrade, auth-plugin negotiation, and sequence numbers;
account for commands that reauthenticate or change session identity, such as
`COM_CHANGE_USER`, by rejecting them until implemented safely. Keep prepared
statements, transactions, and streaming results opaque after login.

## Mock credential endpoints

Endpoints are opt-in and bound to loopback by default. Their exact advertised
base URLs and issuer names are configuration values, allowing test clients to
override SDK endpoints or use a fixture credential file. Supply a test CA when
HTTPS is required. Never depend on redirecting real public cloud hostnames.

| Provider | Initial endpoint surface | Notes |
| --- | --- | --- |
| AWS | Static fixture key/session credentials; optionally IMDSv2-style role credential endpoint | `aws rds generate-db-auth-token` and SDK equivalents sign locally. Mocking `GenerateDBAuthToken` over HTTP would model a nonexistent service call. Add STS `AssumeRole` only for a demonstrated client use case. |
| Google | Compute metadata service-account identity/token endpoints; OAuth token exchange for a fixture refresh token or service-account assertion | Return OAuth-shaped `access_token`, `token_type`, and `expires_in`; opaque server-registered tokens are sufficient for local validation. Pin requested scopes to Cloud SQL login-compatible values. |
| Azure | IMDS managed identity token endpoint; tenant-scoped OAuth token endpoint and OIDC discovery/JWKS for JWT verification | Require the database resource/audience (`https://ossrdbms-aad.database.windows.net` in public Azure), check tenant/client identity, and return provider-shaped expiry fields. |

Publish tiny client examples for each profile using a normal driver and an
explicit mock credential source. Include a matrix showing which AWS credential
providers, Google ADC sources, Azure credential-chain sources, CLI commands,
and Cloud SQL connectors have actually been exercised. Unsupported credential
chains should fail clearly; SDK endpoint override behavior varies by SDK.

## Implementation sequence and exit criteria

1. **Fixture and configuration contract.** Define instance bindings,
   principals, backend accounts, cloud grants, token lifetimes, signing keys,
   TLS, and provider endpoint URLs. Validate duplicate listeners, ambiguous
   usernames, missing backend mappings, and unsafe remote binds. Provide a
   minimal example for all six profiles.
2. **PostgreSQL vertical slice.** Implement TLS, cleartext token startup,
   upstream login, streaming, error propagation, and cancellation. Use a
   simple fixture token to prove transaction and prepared-statement forwarding
   before adding provider-specific checks.
3. **Provider validators and issuers.** Add AWS SigV4 with canonicalization and
   temporary-session credentials; Google opaque OAuth tokens and scope/grant
   checks; Azure signed JWT, tenant/audience/JWKS checks, and group membership.
   Test wrong host, user, resource, scope, tenant, signature, clock window,
   expired token, and revoked or absent grant.
4. **MySQL vertical slice.** Add TLS, `mysql_clear_password`, backend login,
   streaming and explicit handling of reauthentication commands. Repeat all
   provider checks through real MySQL clients.
5. **Credential HTTP compatibility.** Add the endpoint surfaces in the table,
   then exercise selected real SDK/CLI credential paths against them. Document
   each required endpoint override and certificate setting.
6. **Integration and release gate.** In disposable local MySQL and PostgreSQL,
   test success and denial for every provider/engine pair, long-lived sessions
   beyond token expiry, concurrent connections, cancellation, backend failures,
   TLS rejection, username normalization/collisions, and no credential leakage
   in logs. Run hermetic Go unit tests by default; make database-backed tests
   opt-in. Ship an example configuration and a support matrix based on observed
   client versions.

## Deliberate limits and later work

The first release emulates connection authentication and forwards SQL traffic.
It does not implement IAM, GCP IAM, or Entra policy administration APIs; cloud
database provisioning; real cloud endpoint discovery; Cloud SQL connector
transport; transparent DNS interception; or all SDK credential chains. Add
Cloud SQL automatic IAM authentication only after identifying a specific
connector/version and documenting its Admin API and transport exchanges.

Keep fixture signing keys and backend passwords test-scoped. Avoid token values
in logs, traces, diagnostics, and SQL error text. Reject malformed protocol
messages and unknown auth methods, and close both connections on half-open
session failure.

## Primary references

- [AWS RDS IAM connection tokens](https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/UsingWithRDS.IAMDBAuth.Connecting.html) and [CLI token format](https://docs.aws.amazon.com/cli/latest/reference/rds/generate-db-auth-token.html)
- [Cloud SQL MySQL IAM login](https://docs.cloud.google.com/sql/docs/mysql/iam-logins), [Cloud SQL PostgreSQL IAM login](https://docs.cloud.google.com/sql/docs/postgres/iam-logins), and [Google metadata tokens](https://docs.cloud.google.com/compute/docs/access/authenticate-workloads)
- [Azure MySQL Entra login](https://learn.microsoft.com/en-us/azure/mysql/security/security-how-to-entra), [Azure PostgreSQL Entra login](https://learn.microsoft.com/en-us/azure/postgresql/security/security-entra-configure), and [Azure managed identity tokens](https://learn.microsoft.com/en-us/entra/identity/managed-identities-azure-resources/how-to-use-vm-token)

# Architecture and invariants

The service has one HTTP credential issuer and one listener per configured
provider/engine/instance tuple. Fixture principals carry cloud credentials,
explicit listener grants, and one backend account. The database listener
authenticates first, then opens the upstream connection. SQL runs under the
backend account's real database privileges.

## Packages

`iamproxy` is the public, embeddable package; `cmd/db-iam-auth-emulator-proxy`
is a thin CLI over `iamproxy.Start`. `iamproxy/pgxdial` and
`iamproxy/mysqldial` adapt drivers to in-memory dialing. `internal/fakedb`
holds minimal PostgreSQL and MySQL upstreams for hermetic tests.

## Trust boundaries

- All listeners, including credential HTTP endpoints, bind to loopback.
- Every database listener also accepts in-memory connections from
  `Emulator.DialContext`, which routes only to configured listener addresses
  or hostnames and never dials the network. `Options.InMemory` leaves database
  listeners unbound.
- `Options.UpstreamDialer` receives only a listener's configured upstream
  address, for both logins and PostgreSQL cancellation.
- The optional HTTPS credential endpoint serves the same handler using the
  configured TLS certificate and key.
- A listener's upstream is static configuration. Client-supplied database,
  username, or token data cannot choose another upstream address.
- Frontend MySQL and PostgreSQL login requires TLS. A PostgreSQL cleartext
  `PasswordMessage` and MySQL `mysql_clear_password` response are accepted only
  after TLS negotiation.
- Tokens are checked at login. A session is not disconnected when its token
  later expires. Secrets and token values must never be logged.
- Fixture grants authorize a cloud principal to enter a listener; backend SQL
  grants authorize statements. A principal cannot share a backend account with
  another principal on the same listener.

## Protocol handoff

PostgreSQL handles SSLRequest, startup, cleartext password challenge, backend
login through `pgconn`, startup metadata, and CancelRequest. A CancelRequest
may arrive before or after TLS negotiation; pgx and libpq 17+ encrypt it
when the session used TLS. `pgconn.SyncConn`
and `Hijack` hand off the idle upstream socket, then bytes are relayed without
SQL rewriting. Backend PID/secret pairs are exposed to the client only while
that session remains active and are mapped to its configured upstream for
cancellation.

The backend startup carries only `database`, `application_name`, and
`replication`. `replication` is normalized as PostgreSQL parses it
(`database` for logical walsender mode, a boolean for physical mode) and
invalid values are refused before authentication, so replication clients such
as pglogrepl and `pg_recvlogical` can run `IDENTIFY_SYSTEM` and
`START_REPLICATION` through the proxy. The backend account still needs the
`REPLICATION` attribute.

MySQL sends a TLS-capable handshake advertising `mysql_clear_password`, parses
the TLS client response, validates the token, and logs into the upstream using
`go-mysql`. The frontend handshake finishes before the upstream is known, so
after upstream login the negotiated framing capabilities (`DEPRECATE_EOF`,
`QUERY_ATTRIBUTES`, `SESSION_TRACK`, and multi-result flags) must match the
client's; otherwise the session fails with MySQL error 1235 instead of
relaying misframed packets. Post-login bytes are forwarded. `COM_CHANGE_USER` is rejected,
because it would bypass the initial identity mapping. Compression and local
file upload are not advertised.

## Credential checks

- AWS: SigV4 presigned `rds-db` URL, endpoint/port, DBUser, scope, timestamp,
  session token, and fixture grant. Signing uses the hash of the empty request
  body, matching `aws rds generate-db-auth-token`. An empty URL path, as
  emitted by aws-sdk-go-v2 `rds/auth.BuildAuthToken`, is the SigV4 canonical
  `/`; any other path is rejected. Fixture credentials are
  available from IMDSv2 and ECS container credential endpoints.
- Google: opaque mock OAuth token registry, scope, expiry, fixture principal,
  grant, and Cloud SQL engine-specific username normalization.
- Azure: RS256 JWT signature, mock issuer, tenant, database audience, validity
  window, principal, group membership, and listener grant. The client
  credentials endpoint accepts only `https://ossrdbms-aad.database.windows.net/.default`,
  optionally with the `openid offline_access profile` scopes MSAL appends, and
  always issues that audience. Over TLS, tenant discovery reports the request
  origin as its issuer because MSAL requires it to match the https authority;
  issued tokens keep the `public_url` issuer the validator checks.

The mock endpoint surface is intentionally bounded. Cloud SQL connector
transport, real cloud IAM policy APIs, database provisioning, and transparent
cloud hostname replacement are outside the current implementation.

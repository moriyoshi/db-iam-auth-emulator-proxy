# Testing

`go test ./...` covers fixture validation, token issuance and validation, HTTP endpoints, and protocol behavior without Docker. Real SDK clients run hermetically: aws-sdk-go-v2 `rds/auth.BuildAuthToken` tokens and azidentity `DefaultAzureCredential` (environment client secret, MSAL tenant discovery) against the TLS credential routes. The optional integration test uses `IAM_PROXY_E2E=1` with existing local PostgreSQL and MySQL servers; `TestIntegrationPostgresLogicalReplication` also needs PostgreSQL with `wal_level=logical` and streams test_decoding output through the proxy with pglogrepl.

The standard live suite is `make e2e`. `make e2e-check` compiles the runner and parses/resolves every checked-in Starlark scenario without Docker. `make e2e-one SCENARIO=e2e/scenarios/<name>.star` runs one scenario.

The shared `db-iam-auth-emulator-proxy-e2e:local` image contains the Go proxy and runner, Docker CLI, AWS CLI, Google Cloud CLI, Azure CLI, PostgreSQL 17, MySQL 8.4, and MariaDB 10.11 server files from their official images. Only a Docker daemon is required on the host. The runner creates one isolated harness per scenario, starts requested fixture modes with `--database` (PostgreSQL runs with `wal_level=logical`), validates and starts the real proxy, calls real cloud CLIs, executes SQL through the proxy, and tears down its containers and files.

Scenarios are listed in `Makefile`. Starlark scenarios call `spawn(argv)` to run CLIs explicitly. `set_env(values, unset_prefixes=...)` changes the environment inherited by later commands within one scenario; `common.star` shares cloud environment builders across scenarios. The harness owns credential files and isolates CLI configuration so inherited cloud credentials cannot bypass mock endpoints.

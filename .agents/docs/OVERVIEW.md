# Overview

This Go service accepts TLS protected MySQL and PostgreSQL logins with AWS RDS IAM, Google Cloud SQL IAM, or Azure Database Entra style credentials. It verifies fixture identity and grants, then forwards the established session to a configured stock database account. `internal/emulator` contains the proxy and mock HTTP credential service. `internal/e2e` runs Starlark scenarios using a shared container image containing the runner, cloud CLIs, and all three database fixtures.

Start with `README.md` for usage, `ARCHITECTURE.md` for protocol and trust boundaries, and `QUALITY_GATE.md` before declaring work complete.

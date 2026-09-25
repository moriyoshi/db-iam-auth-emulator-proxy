# E2E harness

`internal/e2e` registers Starlark builtins and manages the proxy, fixtures, cloud CLI subprocesses, and cleanup. The Makefile builds one shared image. That image acts as the runner and as each PostgreSQL, MySQL, or MariaDB fixture selected by `--database`. It contains all three cloud CLIs, so the host needs only Docker.

Every scenario has a temporary config and TLS certificate. The runner exposes a loopback credential issuer, starts only requested database fixtures, and checks SQL over the authenticated proxy. `start_proxy()` returns endpoint and fixture paths; `set_env()` configures the scenario environment; `spawn(argv)` executes each visible CLI command. Keep CLI environment and credentials private to the scenario so a developer's own cloud session cannot affect results.

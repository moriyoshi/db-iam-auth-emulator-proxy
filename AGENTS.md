# Repository guide for coding agents

Read [README.md](README.md) for operation, [ARCHITECTURE.md](ARCHITECTURE.md) for invariants, and [PLAN.md](PLAN.md) for the original roadmap. The plan may be older than the implementation.

Agent memory and gates live in [.agents/docs/OVERVIEW.md](.agents/docs/OVERVIEW.md), [.agents/docs/QUALITY_GATE.md](.agents/docs/QUALITY_GATE.md), [.agents/docs/TESTING.md](.agents/docs/TESTING.md), [.agents/docs/TODO.md](.agents/docs/TODO.md), [.agents/docs/JOURNAL.md](.agents/docs/JOURNAL.md), and [.agents/docs/LTM/INDEX.md](.agents/docs/LTM/INDEX.md).

Repository skills under `.agents/skills` provide the sibling project's `good-sleep`, `deep-sleep`, `distill-memories`, `reconcile-journal-ltm`, and `tackle-todos` memory workflows, adapted to this proxy.

## Engineering rules

- Keep every database listener bound to one configured provider, engine, instance, and upstream. Client input must never select the upstream.
- Authenticate before opening an upstream connection. Require TLS before reading database passwords. Do not log secrets or tokens.
- Preserve the authenticated backend session after handoff. Reject MySQL `COM_CHANGE_USER`; route PostgreSQL cancellation only to its active upstream session.
- Keep `go test ./...` independent of Docker, network, and external databases. Put live protocol and CLI checks in the opt-in Starlark E2E harness.
- Add each checked-in scenario to `E2E_SCENARIOS` in `Makefile`. Keep scenario global names and registered builtins in sync.
- Keep cloud credential minting commands explicit in Starlark scenarios. Use `set_env()` once for a provider, then `spawn(argv)`; shared environment builders live in `e2e/scenarios/common.star`.
- Build binaries, logs, and scratch probes under `.agents-workspace/tmp`. Preserve unrelated files and changes. Do not commit, push, or open a PR unless asked.
- Run the relevant checks in `.agents/docs/QUALITY_GATE.md` before reporting completion.
- Append durable findings to `.agents/docs/JOURNAL.md`; verify TODO items against current code before changing their status.

Use `rg` for discovery. Read the implementation before testing it, and make assertions against observable behavior rather than merely reproducing implementation steps.

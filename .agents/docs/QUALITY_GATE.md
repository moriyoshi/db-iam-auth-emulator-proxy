# Quality gate

For Go changes, run `gofmt` on changed files, then:

```sh
go build ./...
go vet ./...
go test ./...
```

Run `go test -race ./...` for shared state, connection lifecycle, and process supervision changes. Keep default Go tests hermetic.

For harness, Dockerfile, entrypoint, or scenario changes, run `make e2e-check` and the affected `make e2e-one SCENARIO=e2e/scenarios/<name>.star`. Run `make e2e` for cross provider or shared image changes. Confirm the harness removed its `iam-proxy-e2e-*` containers. Report any gate that could not run.

Re-read changed documentation for accuracy. Append durable findings to `JOURNAL.md`, and update `LTM/INDEX.md` when adding a memory topic.

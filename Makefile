GO ?= go
E2E_TMP ?= .agents-workspace/tmp
PROXY_BIN := $(E2E_TMP)/db-iam-auth-emulator-proxy
E2E_BIN := $(E2E_TMP)/db-iam-auth-emulator-proxy-e2e
E2E_IMAGE ?= db-iam-auth-emulator-proxy-e2e:local
E2E_SCENARIOS := \
	e2e/scenarios/six-profiles.star \
	e2e/scenarios/aws-imdsv2-cli.star \
	e2e/scenarios/aws-ecs-cli.star \
	e2e/scenarios/mariadb-fixture.star \
	e2e/scenarios/postgres-logical-replication.star
E2E_FLAGS ?=

.PHONY: build test e2e-check e2e-image e2e e2e-one
build:
	mkdir -p $(E2E_TMP)
	$(GO) build -o $(PROXY_BIN) ./cmd/db-iam-auth-emulator-proxy
	$(GO) build -o $(E2E_BIN) ./cmd/db-iam-auth-emulator-proxy-e2e

test:
	$(GO) test ./...

e2e-check: build
	$(E2E_BIN) --check $(E2E_SCENARIOS)

e2e-image: build
	docker build -f e2e/Dockerfile -t $(E2E_IMAGE) .

e2e: e2e-image
	docker run --rm --network host -v /var/run/docker.sock:/var/run/docker.sock $(E2E_IMAGE) --proxy /usr/local/bin/db-iam-auth-emulator-proxy --fixture-image $(E2E_IMAGE) $(E2E_FLAGS) $(E2E_SCENARIOS)

e2e-one: e2e-image
	@test -n "$(SCENARIO)" || (echo "SCENARIO is required" >&2; exit 2)
	docker run --rm --network host -v /var/run/docker.sock:/var/run/docker.sock $(E2E_IMAGE) --proxy /usr/local/bin/db-iam-auth-emulator-proxy --fixture-image $(E2E_IMAGE) $(E2E_FLAGS) $(SCENARIO)

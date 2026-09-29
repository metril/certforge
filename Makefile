SHELL := /bin/bash
GO ?= go
export GOTOOLCHAIN := local
SQLC_VERSION := v1.27.0
OAPI_CODEGEN_VERSION := v2.4.1
GOLANGCI_LINT_VERSION := v1.61.0
SWAGGER_UI_VERSION := 5.17.14
COMPOSE_TEST := docker compose -p certforge-e2e -f deploy/compose.yaml -f deploy/compose.test.yaml
COMPOSE_TEST_ABS := docker compose -p certforge-e2e -f $(CURDIR)/deploy/compose.yaml -f $(CURDIR)/deploy/compose.test.yaml

.PHONY: generate build build-embed test test-integration lint e2e e2e-web vendor-swagger image-agent

generate:
	@if [ -f sqlc.yaml ]; then $(GO) run github.com/sqlc-dev/sqlc/cmd/sqlc@$(SQLC_VERSION) generate; fi
	@if [ -f api/openapi.yaml ]; then mkdir -p internal/api/gen && $(GO) run github.com/oapi-codegen/oapi-codegen/v2/cmd/oapi-codegen@$(OAPI_CODEGEN_VERSION) -config api/oapi-codegen.yaml api/openapi.yaml; fi
	@if [ -f api/oapi-codegen.client.yaml ]; then mkdir -p internal/api/client && $(GO) run github.com/oapi-codegen/oapi-codegen/v2/cmd/oapi-codegen@$(OAPI_CODEGEN_VERSION) -config api/oapi-codegen.client.yaml api/openapi.yaml; fi
	$(GO) generate ./internal/challenge/...
	@if [ -d web ]; then npm --prefix web run gen; fi

VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)

build:
	CGO_ENABLED=0 $(GO) build -trimpath -ldflags "-X main.version=$(VERSION)" -o bin/certforge ./cmd/certforge
	CGO_ENABLED=0 $(GO) build -trimpath -ldflags "-X main.version=$(VERSION)" -o bin/certforge-agent ./cmd/certforge-agent

image-agent:
	docker build -f deploy/Dockerfile.agent --build-arg VERSION=$(VERSION) -t ghcr.io/metril/certforge-agent:dev .

build-embed:
	rm -rf internal/webui/dist
	cp -r web/dist internal/webui/dist
	CGO_ENABLED=0 $(GO) build -trimpath -tags embedweb -ldflags "-X main.version=$(VERSION)" -o bin/certforge ./cmd/certforge

test:
	$(GO) test -race ./...

test-integration:
	$(GO) test -race -tags integration ./...

lint:
	$(GO) run github.com/golangci/golangci-lint/cmd/golangci-lint@$(GOLANGCI_LINT_VERSION) run ./...

# Dev/test KEK. World-readable because the container runs as uid 65532; see docs/configuration.md for production.
deploy/secrets/kek:
	mkdir -p deploy/secrets
	head -c 32 /dev/urandom | base64 > $@
	chmod 0644 $@

e2e: deploy/secrets/kek
	rm -rf .e2e && mkdir -p .e2e/agent-data .e2e/traefik .e2e/ssl .e2e/vault && chmod 0777 .e2e/vault
	export CF_E2E_UID=$$(id -u) CF_E2E_GID=$$(id -g) CF_VAULT_PORT=$${CF_VAULT_PORT:-8200} CF_E2E_VAULT_TOKEN=$${CF_E2E_VAULT_TOKEN:-certforge-e2e-root}; \
	$(COMPOSE_TEST) --profile e2e up -d --build --wait; up_status=$$?; \
	if [ $$up_status -ne 0 ]; then \
		$(COMPOSE_TEST) --profile e2e down -v; exit $$up_status; \
	fi; \
	export CF_E2E_BASE_URL=http://localhost:$${CF_HTTP_PORT:-8080} \
		CF_E2E_PEBBLE_MGMT=https://localhost:$${CF_PEBBLE_MGMT_PORT:-15000} \
		CF_E2E_DEX_ADDR=127.0.0.1:$${CF_DEX_PORT:-5556} \
		CF_E2E_CHALLTESTSRV=http://localhost:$${CF_CHALLTESTSRV_PORT:-18055} \
		CF_E2E_AGENT_DIR=$(CURDIR)/.e2e \
		CF_E2E_COMPOSE="$(COMPOSE_TEST_ABS)" \
		CF_E2E_COMPOSE_VAULT_FILE=$(CURDIR)/deploy/compose.vault.yaml \
		CF_E2E_VAULT=http://localhost:$${CF_VAULT_PORT} \
		CF_E2E_VAULT_ADDR=$${CF_E2E_VAULT_ADDR:-http://vault:8200}; \
	$(GO) test -tags e2e -count=1 -timeout 20m -skip TestVaultAgainstCompose ./test/e2e/...; status=$$?; \
	if [ $$status -eq 0 ]; then \
		$(GO) test -tags e2e -count=1 -timeout 15m -run TestVaultAgainstCompose ./test/e2e/...; status=$$?; \
	fi; \
	$(COMPOSE_TEST) --profile e2e down -v; exit $$status

# Playwright against a fresh compose stack with the agent service (plan 3B).
# --profile e2e brings up the agent service (compose.test.yaml keeps it out
# of the plain dev stack; see its own comment on why it must not start
# without CF_E2E_UID/GID, which this target exports below) and Vault (5B's
# Playwright suite needs it too; CF_E2E_VAULT_ADDR/CF_E2E_VAULT_TOKEN are
# exported here for that reason even though nothing in this target's own
# npm run e2e reads them yet).
e2e-web: deploy/secrets/kek
	rm -rf .e2e && mkdir -p .e2e/agent-data .e2e/traefik .e2e/ssl .e2e/vault && chmod 0777 .e2e/vault
	export CF_E2E_UID=$$(id -u) CF_E2E_GID=$$(id -g) CF_VAULT_PORT=$${CF_VAULT_PORT:-8200} CF_E2E_VAULT_TOKEN=$${CF_E2E_VAULT_TOKEN:-certforge-e2e-root}; \
	$(COMPOSE_TEST) --profile e2e up -d --build --wait; up_status=$$?; \
	if [ $$up_status -ne 0 ]; then \
		$(COMPOSE_TEST) --profile e2e down -v; exit $$up_status; \
	fi; \
	CF_E2E_BASE_URL=http://localhost:$${CF_HTTP_PORT:-8080} \
	CF_E2E_AGENT_DIR=$(CURDIR)/.e2e \
	CF_E2E_VAULT_ADDR=$${CF_E2E_VAULT_ADDR:-http://vault:8200} \
	CF_E2E_VAULT_TOKEN=$${CF_E2E_VAULT_TOKEN} \
	npm --prefix web run e2e; status=$$?; $(COMPOSE_TEST) --profile e2e down -v; exit $$status

vendor-swagger:
	curl -fsSL -o internal/api/docs/swagger-ui-bundle.js https://cdn.jsdelivr.net/npm/swagger-ui-dist@$(SWAGGER_UI_VERSION)/swagger-ui-bundle.js
	curl -fsSL -o internal/api/docs/swagger-ui.css https://cdn.jsdelivr.net/npm/swagger-ui-dist@$(SWAGGER_UI_VERSION)/swagger-ui.css

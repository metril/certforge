SHELL := /bin/bash
GO ?= go
SQLC_VERSION := v1.27.0
OAPI_CODEGEN_VERSION := v2.4.1
GOLANGCI_LINT_VERSION := v1.61.0
SWAGGER_UI_VERSION := 5.17.14
COMPOSE_TEST := docker compose -f deploy/compose.yaml -f deploy/compose.test.yaml

.PHONY: generate build build-embed test test-integration lint e2e vendor-swagger

generate:
	@if [ -f sqlc.yaml ]; then $(GO) run github.com/sqlc-dev/sqlc/cmd/sqlc@$(SQLC_VERSION) generate; fi
	@if [ -f api/openapi.yaml ]; then mkdir -p internal/api/gen && $(GO) run github.com/oapi-codegen/oapi-codegen/v2/cmd/oapi-codegen@$(OAPI_CODEGEN_VERSION) -config api/oapi-codegen.yaml api/openapi.yaml; fi

build:
	CGO_ENABLED=0 $(GO) build -trimpath -o bin/certforge ./cmd/certforge

build-embed:
	rm -rf internal/webui/dist
	cp -r web/dist internal/webui/dist
	CGO_ENABLED=0 $(GO) build -trimpath -tags embedweb -o bin/certforge ./cmd/certforge

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
	$(COMPOSE_TEST) up -d --build --wait
	CF_E2E_BASE_URL=http://localhost:8080 $(GO) test -tags e2e -count=1 ./test/e2e/...; status=$$?; $(COMPOSE_TEST) down -v; exit $$status

vendor-swagger:
	curl -fsSL -o internal/api/docs/swagger-ui-bundle.js https://cdn.jsdelivr.net/npm/swagger-ui-dist@$(SWAGGER_UI_VERSION)/swagger-ui-bundle.js
	curl -fsSL -o internal/api/docs/swagger-ui.css https://cdn.jsdelivr.net/npm/swagger-ui-dist@$(SWAGGER_UI_VERSION)/swagger-ui.css

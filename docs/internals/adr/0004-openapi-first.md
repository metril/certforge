# 0004. OpenAPI-first API with generated strict server

Date: 2026-09-24. Status: accepted.

## Context
The UI, `cfctl`, and third parties all consume the API. Hand-written handlers and clients drift.

## Decision
`api/openapi.yaml` is the source of truth. oapi-codegen v2 generates a chi strict server (typed request and response objects) into `internal/api/gen`. The web client types come from the same file via openapi-typescript. The spec is served at `/api/v1/openapi.json`, with Swagger UI (vendored, no CDN) at `/api/docs`. Errors are RFC 9457 problem+json.

## Consequences
Adding an endpoint means editing YAML first. Generated code is committed and CI fails on drift. Cookies and client IPs are reached through a strict middleware that puts the raw `http.ResponseWriter` and request in the context.

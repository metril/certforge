# ADR 0005: Routing challenge provider

Status: accepted (Phase 1B)

## Context

A certificate can cover names in several DNS zones hosted by different providers (for example `*.example.com` at Cloudflare and `other.net` at Route 53), and some names may need manual TXT records. lego v4 accepts exactly one DNS-01 provider per client, and calls it with the bare authorization domain (`example.com` for both `example.com` and `*.example.com`). lego providers read their credentials from environment variables, and `dns01.AddRecursiveNameservers` sets a package-global resolver list.

## Decision

- `challenge.Router` is the single provider lego sees. It holds an ordered list of rules (`Matcher` + `ChallengeProvider`), built per attempt from the certificate's own rules followed by the inherited catch-all rules. The first matching rule wins.
- Match syntax, mirrored by the web UI's coverage check: `*` (any name), `*.zone` (names exactly one label below zone, and the wildcard name `*.zone` itself: what a `*.zone` certificate covers), `zone` (the zone, every name below it, and wildcards below it).
- lego's bare domain is mapped back to the certificate name: the exact name if listed, else `*.` + domain. Apex and wildcard share `_acme-challenge.<zone>`, so the apex rule serves both when both names are present.
- `Router.Validate` runs before an order is placed; an uncovered name or an IP address fails the attempt without contacting the CA.
- Propagation checks are installed per client with `dns01.WrapPreCheck`. When a rule, the defaults or the CA name resolvers, CertForge queries them itself (`challenge.CheckTXT`) instead of calling the global `AddRecursiveNameservers`.
- lego providers are constructed under a process-wide mutex that unsets every schema key (and its `_FILE` variant), sets the credential's values, calls `dns.NewDNSChallengeProviderByName`, and restores the environment. Providers copy their config at construction, so later calls do not read the environment.
- manual-dns is a provider that records TXT records in `manual_dns_pending` and blocks the first propagation check until the operator confirms or the wait budget (1 h) runs out.

## Consequences

- One certificate can span any number of DNS providers; ordering is explicit and visible in the UI.
- Mixing DNS-01 with HTTP-01 or TLS-ALPN-01 in one certificate needs a per-authorization solver wrapper (Phase 4).
- Provider construction is serialised; construction is fast, so contention is negligible at Phase 1 scale. A subprocess fallback stays possible if a provider ever reads the environment lazily.
- lego's `exec` and `manual` providers are not offered: one runs arbitrary programs on the server, the other reads stdin.

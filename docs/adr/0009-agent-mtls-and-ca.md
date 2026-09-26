# 0009: Agent identity by mutual TLS with an internal CA

Status: accepted (Phase 3)

## Context
Agents must authenticate to the server, and the server to agents, without a public CA and without trust on first use. A sibling project frames agent traffic with a NaCl handshake on top of the socket.

## Decision
- CertForge runs its own ECDSA P-256 agent CA (`agent_cas`, key envelope-encrypted like certificate keys), created on first start under an advisory lock. Agent certificates carry only the URI SAN `urn:certforge:client:<uuid>` and `clientAuth`; the listener's certificate is `serverAuth` for the names in Settings → Agents.
- Agents authenticate with mutual TLS on a separate listener (CF_LISTEN_AGENT). The server maps the verified certificate to its client and also requires the stored serial, so revoking, re-enrolling or renewing invalidates the previous certificate at once without a CRL.
- An enrolment token pins, by SHA-256, the CA that signs the listener's own certificate at issuance time — the oldest non-retired CA, not necessarily the active one (rotate only changes which CA signs new *agent* certificates; the listener's own signing CA changes only on retire, so the listener stays reachable under the CA a token was minted against until that CA is actually retired). The agent accepts the server only if the presented chain contains that CA and the leaf verifies under it; afterwards it trusts the returned bundle.
- Several CAs are trusted at once. Rotation creates a new active CA (which signs new *agent* certificates from then on) and marks the old one retiring; agents move over as they renew. Retire switches the listener's own signing chain to the new CA, and is blocked while any active agent certificate still depends on the CA being retired.
- The NaCl layer is not used: mTLS already gives an authenticated, encrypted, forward-secret channel, and a second handshake would add key management without adding protection. Only the idea of one read or write per message survives, in `internal/agentproto.Conn`.

## Consequences
The agent port needs TLS passthrough; a TLS-terminating proxy in front of it breaks client authentication (forwarded client-cert headers are never trusted). Server compromise still means the attacker can issue agent certificates and push files; hooks stay off unless each agent allowlists them (docs/security.md).

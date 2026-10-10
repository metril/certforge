# 0020: Agent protocol that survives a hostile TLS-terminating proxy

Status: accepted. Supersedes in part [0009](0009-agent-mtls-and-ca.md) (transport authentication) and [0010](0010-agent-websocket-hub.md) (socket framing).

## Context
Operators put CertForge behind a reverse proxy that terminates TLS (nginx, Caddy, Traefik, a cloud load balancer). ADR 0009 made mutual TLS the agent's identity, so the agent port had to bypass any such proxy: a proxy that terminates TLS drops the client certificate. Many sites cannot do that, and a proxy that terminates TLS also sees every byte of the agent channel: enrolment tokens, private keys inside bundles, and the server's answers.

The goal: agents work through any proxy, and a proxy that is hostile (or compromised) learns nothing and can change nothing. It may still refuse service.

## Threat model
The proxy holds the TLS keys on both legs and sees plaintext HTTP and WebSocket frames. It can drop, delay, duplicate, reorder, truncate or replay messages, and it can answer the agent itself. Under this protocol it cannot:
- **Read** a request body, a response body, a bundle or a WebSocket message after the handshake. Every body is sealed.
- **Forge** a request (each is signed by the agent's key) or a response (each is signed by the server's responder key).
- **Replay** a request (a signed nonce and a per-session sequence number are checked) or a response (it is bound to the request nonce).
- **Enrol** an agent: it never sees the enrolment token, and approval needs an administrator.

It can deny service by dropping or delaying traffic. The agent treats anything unsigned as a transport error, never as an instruction (in particular, never as revocation).

Out of scope: a compromised server, a compromised agent host, and traffic analysis (sizes and timing are visible).

## Decision
**Signed requests and responses.** Every request carries an HTTP message signature, a profile of RFC 9421: the covered components are `@method`, `@authority`, `@request-target`, `content-digest` and `cf-ephemeral`; the parameters are `created`, `nonce`, `keyid` and `alg`. The signature is ECDSA P-256 as raw 64-byte `r||s` (not ASN.1 DER). The verifier rebuilds the whole `Signature-Input` and requires an exact match, so no extra parameter can be smuggled in. `@authority` is the server's configured host, never the request's `Host`, so a request signed for one host fails on another. Responses cover `@status` and `content-digest` and carry `created`, the `req-nonce` of the request they answer and `keyid`; `cf-error` is covered when present. Clock skew is limited to 60 s (the server) and 120 s (the shared maximum).

**Sessions with ephemeral ECDH.** `POST /agent/v1/session` carries the agent's certificate and an ephemeral P-256 key in the signed `Cf-Ephemeral` header. The server answers with its own ephemeral key, signed by the responder. Both sides derive per-direction AES-256-GCM keys with HKDF-SHA256 (salt = session nonce, info = `certforge-agent-session-v1` plus the direction). The GCM nonce is a fixed prefix plus the message sequence number; the additional data binds direction, sequence and request context. Because the keys come from ephemeral keys, recording the traffic and later stealing the agent key or the responder key reveals nothing: forward secrecy. A session lasts at most 10 minutes, 1000 messages per direction and 16 per client.

**HPKE enrolment with proof of possession and admin approval.** The agent cannot trust a session yet, so enrolment uses HPKE (RFC 9180: DHKEM P-256, HKDF-SHA256, AES-256-GCM) to a one-use server key from `GET /enroll/hello`. The token is never sent. The agent proves it holds the token with an HMAC keyed by the token hash over the CSR digest, host, time, nonce and reply key; a swapped CSR or reply key fails the check. The token is consumed only after the proof verifies. By default the server then holds the request until an administrator approves it. The agent and the administrator compare a verification code derived from the CSR public key and the CA fingerprint in the token, so a man in the middle who substitutes either shows a different code. The agent polls with requests signed by the CSR key and receives the certificate sealed to a fresh key.

**The sealed WebSocket.** The upgrade request is signed like any request. The server's first frame, `hello_ack`, carries the responder's signature over both ephemeral keys, the session id and the upgrade nonce. Later frames are binary `seq || AES-GCM`, accepted strictly in order. Close codes are never trusted: `revoked` and `trust_bundle_update` count only after they open. A session protects 1000 messages per direction, so near the cap the sender stops queuing, the server closes with `4003` and the agent reconnects: a fresh handshake and fresh keys, with no in-band rekey. The agent backs off if that happens within a minute.

**The responder certificate.** The agent must know that a response came from the server and not from the proxy, but the proxy owns the TLS certificate. The server signs responses with a separate key whose certificate is issued by the agent CA, valid 24 hours and renewed at two thirds of its life. Its extended key usage is `OCSPSigning` and its subject carries the organizational unit `2.25.284011506363329835389774668932300182646`. `OCSPSigning` is accepted by no TLS stack for server or client authentication, so the certificate is useless as a TLS identity, and no listener or agent certificate can pass as a responder. The agent requires exactly that usage and unit, and checks the chain against its trust bundle. A custom extended-key-usage OID was the first choice; Go's `crypto/x509` cannot parse an OID with such a large arc, hence the marker in the subject.

**Signed and unsigned refusals.** A refusal the agent acts on must be unforgeable. After the request signature verifies, the server refuses with a signed bodyless response whose `Cf-Error` (`auth`, `session`, `stale`, `replay`) is covered by the signature. Before that, the server cannot tell a real agent from a probe, so failures (bad certificate, bad signature, stale time, unknown session, oversize body) are unsigned. The agent treats an unsigned answer as a transport error and retries; it concludes "revoked" only from a signed `auth` refusal or a sealed `revoked` message. The one unsigned code the agent acts on is `session`, and only to open a new session once.

**Nonces in memory.** Request nonces (120 s) and sessions are kept in the server process. That is correct for the single replica CertForge runs (ADR 0010). More than one replica needs a shared `NonceStore`, shared sessions and a shared hub; until then, run one.

**No client certificate.** The agent still holds a certificate from the agent CA, but it is an identity inside the protocol, not a TLS credential. The listener asks for no client certificate, and a certificate alone admits nothing. The server still checks that the client is active and that the certificate serial is the newest one issued, on every request and every WebSocket message.

## Consequences
- **Breaking change.** Old agents cannot talk to a new server, and new agents cannot talk to an old one. Upgrade the server first, then the agents. Existing agent certificates stay valid and agents do not re-enrol. See [upgrades](../../operations/upgrades.md).
- The agent port is optional: the same protocol is served on the HTTP port, so one proxy and one port can carry everything. The proxy must forward `Host` unchanged and pass the signature headers and WebSocket upgrades.
- The agent trusts the server's TLS certificate for hygiene only (CA pin, system roots or both, `CF_AGENT_TRANSPORT`); authenticity comes from the signatures.
- Poll secrets travel signed but not sealed. A proxy that reads one still cannot poll without the CSR key.
- Bundles still carry the private key for agent-side deploy targets, inside the sealed channel.
- A new enrolment step (approval) and a new setting, `requireApproval`.
- A proxy can still stop agents from syncing. Monitor agent liveness, not only server health.

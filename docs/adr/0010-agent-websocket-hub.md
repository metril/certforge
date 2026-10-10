# 0010: One WebSocket per agent, level-triggered sync

Status: accepted. **Superseded in part by [0020](0020-agent-protocol-through-proxy.md):** the upgrade is signed and the frames are sealed, so messages are no longer plain JSON text, and a socket reconnects with close code `4003` before its session message cap. The hub, sync, ping and eviction rules below are unchanged.

## Context
Agents sit behind NAT and CGNAT, so the server cannot call them. Changes (new versions, grant edits, revocation, CA rotation) should reach them within seconds, but a lost message must never leave an agent wrong.

## Decision
- Each agent keeps one WebSocket to `/agent/v1/ws` (coder/websocket, JSON messages with a `type` field; *superseded in part by 0020: after the first frame each message is a sealed binary frame carrying that JSON*). The server sends `hello_ack`, `sync{revision}`, `trust_bundle_update` and `revoked`; the agent sends `hello`, `heartbeat` and `deploy_result`. There is no request/response on the socket.
- Sync is level-triggered: every change bumps `clients.desired_revision` in the change's own transaction and `sync` is sent after commit. The agent always fetches the full assignments and reconciles, on connect, on `sync`, and on its own pull schedule; a missed nudge only delays it.
- Heartbeats and reports go over the socket when it is up and over REST otherwise (`certforge-agent pull` never opens one); both reach the same service methods.
- The server pings every 25 s and closes a socket after 75 s without a message or pong. A new connection for a client evicts the old one (close code 4000); revocation and re-enrolment close with 4001. Added by 0020: 4003 asks the agent to reconnect for fresh keys.
- The registry is in memory. CertForge runs one replica in v1; `Client.connected` means connected to this process.

## Consequences
Running several replicas needs a fan-out (Postgres LISTEN/NOTIFY) and a shared presence view; until then extra replicas would leave agents unnudged on the others. Server-sent events were rejected: agents need to send as well, and a second REST path per direction would double the surface.

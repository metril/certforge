# 0022: Actions bound to the grant's target

Status: accepted.

## Context
Device actions (ssh, pfSense, PiKVM, GL.iNet, TrueNAS, RouterOS) carried a `targetId`. A grant could therefore run a step against a host other than its own deploy target, one restart action existed per target, and several grants on one device each restarted its services.

## Decision
Device actions have no `targetId`; they run on the grant's deploy target, server grants only. Each kind declares the grant target types it fits (`TargetTypes`), and the API returns 422 for an incompatible step, group edit or kind change. Migration 00040 strips `targetId` and removes steps whose action named a different host, recording `action.step_removed` audit events.

Migration 00041 adds `server_post_tails`, where a server grant parks its tail until the batch job runs.

Post-deploy steps whose execution does not depend on the certificate are batchable (`Kind.Batch`). A grant runs post steps inline until its first batchable step; that step and the rest form its tail. Tails of grants on one host are merged in grant-id order, sharing a batchable step by action id and keeping each grant's order. The server runs the merged tails in a `certforge_server_post_batch` job per target, unique per target and 15-second window and scheduled at the window start plus 30 s, so it runs 15–30 s after the deploys it collects; the agent merges within one reconcile run. A merged failure fails every contributor where the step is not optional. Exec is per certificate unless the action sets `oncePerHost`.

## Consequences
- Breaking: clients must stop sending `targetId` for device actions; one action serves every grant of a target type.
- A restart happens once per host per window, but a grant is marked deployed only after its tail runs, up to about 30 s later.
- A grant deployed after the window closes waits for the next one, so the same service can restart more than once.
- Pre-deploy steps never merge.

-- Phase 6A Task 8: the database-backed series Collector queries once per
-- scrape (cached CacheTTL). river_job is river's own table, outside this
-- schema, so its stats are queried directly in collector.go instead of
-- here; backup.status and crypto.rewrap (Deviations R6/Task 5) are plain
-- settings.Store reads, not sqlc queries.

-- name: MetricsCertificatesByStatus :many
SELECT o.slug AS org, c.status AS status, count(*) AS count
FROM certificates c
JOIN orgs o ON o.id = c.org_id
GROUP BY o.slug, c.status;

-- Cardinality note (binding requirement): one row per certificate that has
-- an issued version, labelled by the certificate's own id — bounded by the
-- number of certificates, not by name (free text) or version history.
-- name: MetricsCertificateNotAfter :many
SELECT o.slug AS org, c.id AS certificate, v.not_after AS not_after
FROM certificates c
JOIN orgs o ON o.id = c.org_id
JOIN certificate_versions v ON v.id = c.current_version_id
WHERE c.current_version_id IS NOT NULL;

-- name: MetricsCertificatesDueRenewal :many
SELECT o.slug AS org, count(*) AS count
FROM certificates c
JOIN orgs o ON o.id = c.org_id
WHERE c.managed AND c.next_renew_at IS NOT NULL AND c.next_renew_at <= now()
GROUP BY o.slug;

-- online = active and seen within the "agents" section's offlineAfterSeconds
-- (collector.go's own onlineCutoff, mirroring agents.Service.OnlineCutoff);
-- pending/revoked pass through unchanged.
-- name: MetricsClientsByStatus :many
SELECT o.slug AS org,
       (CASE
           WHEN c.status = 'active' AND c.last_seen >= sqlc.arg(online_cutoff)::timestamptz THEN 'online'
           WHEN c.status = 'active' THEN 'offline'
           ELSE c.status
       END)::text AS status,
       count(*) AS count
FROM clients c
JOIN orgs o ON o.id = c.org_id
GROUP BY 1, 2;

-- Agent-run grants (deployments.state is already pending/ok/failed/drift)
-- unioned with server-run grants (server_deployments.status has no drift
-- state; deployed maps to ok, matching the agent side's own terminal
-- success state). Two rows for the same (org, status) pair are summed in
-- Go, not here, since the two SELECTs group independently.
-- name: MetricsDeploymentsByStatus :many
SELECT o.slug AS org, d.state AS status, count(*) AS count
FROM deployments d
JOIN client_cert_grants g ON g.id = d.grant_id
JOIN clients c ON c.id = g.client_id
JOIN orgs o ON o.id = c.org_id
WHERE g.removed_at IS NULL
GROUP BY o.slug, d.state
UNION ALL
SELECT o.slug AS org,
       (CASE sd.status WHEN 'deployed' THEN 'ok' ELSE sd.status END)::text AS status,
       count(*) AS count
FROM server_deployments sd
JOIN client_cert_grants g ON g.id = sd.grant_id
JOIN deploy_targets t ON t.id = g.deploy_target_id
JOIN orgs o ON o.id = t.org_id
WHERE g.removed_at IS NULL
GROUP BY o.slug, sd.status;

-- name: MetricsMonitorsByState :many
SELECT o.slug AS org, m.state AS state, count(*) AS count
FROM external_monitors m
JOIN orgs o ON o.id = m.org_id
GROUP BY o.slug, m.state;

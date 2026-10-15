-- +goose Up
ALTER TABLE notification_events DROP CONSTRAINT notification_events_kind_check;
ALTER TABLE notification_events ADD CONSTRAINT notification_events_kind_check CHECK (kind IN (
    'cert.issued', 'cert.renewal_failed', 'cert.issuance_failed', 'cert.expiring', 'cert.expired',
    'deploy.failed', 'action.failed', 'deploy.drift', 'client.offline', 'client.online', 'agent.cert_expiring', 'client.pending_approval',
    'monitor.mismatch', 'monitor.unreachable', 'monitor.expiring', 'monitor.recovered',
    'backup.completed', 'backup.failed', 'test'
));

-- +goose Down
ALTER TABLE notification_events DROP CONSTRAINT notification_events_kind_check;
DELETE FROM notification_events WHERE kind IN ('cert.issuance_failed', 'action.failed', 'client.online');
ALTER TABLE notification_events ADD CONSTRAINT notification_events_kind_check CHECK (kind IN (
    'cert.issued', 'cert.renewal_failed', 'cert.expiring', 'cert.expired',
    'deploy.failed', 'deploy.drift', 'client.offline', 'agent.cert_expiring', 'client.pending_approval',
    'monitor.mismatch', 'monitor.unreachable', 'monitor.expiring', 'monitor.recovered',
    'backup.completed', 'backup.failed', 'test'
));

import { expect, it } from 'vitest';
import { iso, makeCert, makeClient, NOW } from '@/test/fixtures';
import { attentionItems } from './attention';
import { attentionQueue, clientAttentionItems } from './clientAttention';

it('raises failed, drift, offline-with-grants and agent-certificate items; skips revoked', () => {
  const items = clientAttentionItems(
    [
      makeClient({ id: 'a', failedCount: 1, driftCount: 2 }),
      makeClient({ id: 'b', connected: false, online: false, lastSeen: iso(-1) }),
      makeClient({ id: 'c', connected: false, online: false, lastSeen: iso(-1), grantCount: 0 }),
      makeClient({ id: 'd', agentCertNotAfter: iso(3) }),
      makeClient({ id: 'e', status: 'revoked', failedCount: 4 }),
      makeClient({ id: 'f', connected: false, online: false, lastSeen: null }),
      // Pull-only, seen 30 s ago: online per the server, so not queued.
      makeClient({ id: 'g', connected: false, online: true, lastSeen: new Date(NOW - 30_000).toISOString() }),
    ],
    NOW,
  );
  expect(items.map((i) => [i.client.id, i.kind, i.cause])).toEqual([
    ['a', 'deploy-failed', '1 deployment failed'],
    ['a', 'drift', '2 grants drifted'],
    ['b', 'offline', 'Last seen 1 d ago'],
    ['d', 'agent-cert', 'Agent certificate expires in 3 d'],
    ['f', 'offline', 'Never connected'],
  ]);
});

it('merges certificate and client items by severity', () => {
  const certItems = attentionItems(
    [makeCert({ id: 'x', status: 'failed', failureCount: 1, lastError: 'boom' }), makeCert({ id: 'y', nextRenewAt: iso(-2) })],
    NOW,
  );
  const clientItems = clientAttentionItems([makeClient({ id: 'a', driftCount: 1 }), makeClient({ id: 'b', connected: false, online: false, lastSeen: iso(-1) })], NOW);
  expect(attentionQueue(certItems, clientItems).map((q) => q.item.kind)).toEqual(['failed', 'drift', 'overdue', 'offline']);
});

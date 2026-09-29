import { http, HttpResponse } from 'msw';
import { expect, it } from 'vitest';
import { server } from '@/test/server';
import { makeChannel, url } from '@/test/fixtures';
import { createChannel, deleteChannel, testChannel, updateChannel } from './channels';

const channel = makeChannel({ id: 'ch-9', orgId: 'org-other', name: 'ops' });

it("channel calls use the channel's org", async () => {
  const seen: string[] = [];
  server.use(
    http.patch(url('/orgs/:orgId/channels/:id'), ({ params }) => {
      seen.push(`patch:${params.orgId as string}`);
      return HttpResponse.json(channel);
    }),
    http.delete(url('/orgs/:orgId/channels/:id'), ({ params }) => {
      seen.push(`delete:${params.orgId as string}`);
      return new HttpResponse(null, { status: 204 });
    }),
    http.post(url('/orgs/:orgId/channels/:id/test'), ({ params }) => {
      seen.push(`test:${params.orgId as string}`);
      return HttpResponse.json({ status: 'delivered', durationMs: 12 });
    }),
    http.post(url('/orgs/:orgId/channels'), ({ params }) => {
      seen.push(`create:${params.orgId as string}`);
      return HttpResponse.json(channel, { status: 201 });
    }),
  );
  await updateChannel(channel, { name: 'ops', type: 'webhook', config: {}, events: [], minSeverity: 'info', allOrgs: false, enabled: true });
  await deleteChannel(channel);
  await testChannel(channel);
  await createChannel('org-1', { name: 'x', type: 'webhook', config: {}, events: [], minSeverity: 'info', allOrgs: false, enabled: true });
  expect(seen).toEqual(['patch:org-other', 'delete:org-other', 'test:org-other', 'create:org-1']);
});

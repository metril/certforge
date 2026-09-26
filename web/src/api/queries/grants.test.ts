import { http, HttpResponse } from 'msw';
import { expect, it } from 'vitest';
import { server } from '@/test/server';
import { makeGrant, problem, url } from '@/test/fixtures';
import { createGrants } from './grants';

it('posts one grant per certificate and keeps going after a failure', async () => {
  const seen: string[] = [];
  server.use(
    http.post(url('/orgs/org-1/clients/cl-1/grants'), async ({ request }) => {
      const body = (await request.json()) as { certificateId: string; delivery: string };
      seen.push(body.certificateId);
      if (body.certificateId === 'c-2') return problem(409, 'www is already granted to web-1.');
      return HttpResponse.json(makeGrant({ id: `g-${body.certificateId}`, certificateId: body.certificateId }), { status: 201 });
    }),
  );
  const r = await createGrants('org-1', 'cl-1', ['c-1', 'c-2', 'c-3'], { delivery: 'push', layoutId: 'l-1', hookIds: [], autoRemediate: false });
  expect(seen).toEqual(['c-1', 'c-2', 'c-3']);
  expect(r.created.map((g) => g.certificateId)).toEqual(['c-1', 'c-3']);
  expect(r.failed).toEqual([{ certificateId: 'c-2', message: 'www is already granted to web-1.' }]);
});

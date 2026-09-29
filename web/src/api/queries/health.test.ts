import { http, HttpResponse } from 'msw';
import { expect, it } from 'vitest';
import { server } from '@/test/server';
import { fetchReadiness } from './health';

it('status set for string and object checks', async () => {
  server.use(
    http.get('*/readyz', () =>
      HttpResponse.json(
        {
          checks: {
            database: 'ok',
            vault: 'degraded',
            kek: { status: 'failed', error: 'boom' },
            queue: { ok: true },
            other: { ok: false },
          },
        },
        { status: 503 },
      ),
    ),
  );
  const r = await fetchReadiness();
  const byName = Object.fromEntries(r.checks.map((c) => [c.name, c]));
  expect(byName.database).toEqual({ name: 'database', ok: true, status: 'ok', message: undefined });
  expect(byName.vault).toEqual({ name: 'vault', ok: false, status: 'degraded', message: 'degraded' });
  expect(byName.kek).toEqual({ name: 'kek', ok: false, status: 'failed', message: 'boom' });
  expect(byName.queue).toEqual({ name: 'queue', ok: true, status: 'ok', message: undefined });
  expect(byName.other).toEqual({ name: 'other', ok: false, status: 'failed', message: undefined });
});

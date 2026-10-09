import { http, HttpResponse } from 'msw';
import { screen } from '@testing-library/react';
import { expect, it } from 'vitest';
import { server } from '@/test/server';
import { authHandlers, makeApiKey, url } from '@/test/fixtures';
import { renderRoute } from '@/test/render';

it('applying a saved view on API keys clears filters the view does not set', async () => {
  localStorage.setItem('cf-views-apikeys', JSON.stringify([{ name: 'only-q', search: { q: 'deploy' } }]));
  server.use(...authHandlers({ authed: true }), http.get(url('/api-keys'), () => HttpResponse.json({ items: [makeApiKey()] })));
  const { user, router } = renderRoute('/settings/access?tab=keys&state=revoked');
  await user.click(await screen.findByRole('button', { name: 'only-q' }));
  const s = router.state.location.search as Record<string, unknown>;
  expect(s.q).toBe('deploy');
  expect(s.state).toBeUndefined();
  expect(s.tab).toBe('keys');
});

it('applying a saved view on bindings clears filters the view does not set', async () => {
  localStorage.setItem('cf-views-bindings', JSON.stringify([{ name: 'only-q', search: { q: 'ann' } }]));
  server.use(...authHandlers({ authed: true }), http.get(url('/role-bindings'), () => HttpResponse.json({ items: [] })), http.get(url('/users'), () => HttpResponse.json({ items: [] })), http.get(url('/api-keys'), () => HttpResponse.json({ items: [] })));
  const { user, router } = renderRoute('/settings/access?tab=bindings&type=user');
  await user.click(await screen.findByRole('button', { name: 'only-q' }));
  const s = router.state.location.search as Record<string, unknown>;
  expect(s.q).toBe('ann');
  expect(s.type).toBeUndefined();
  expect(s.tab).toBe('bindings');
});

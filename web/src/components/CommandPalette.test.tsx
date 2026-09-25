import { http, HttpResponse } from 'msw';
import { screen, waitFor } from '@testing-library/react';
import { expect, it } from 'vitest';
import { server } from '@/test/server';
import { authHandlers, makeCert, url } from '@/test/fixtures';
import { renderRoute } from '@/test/render';

it('opens with Ctrl-K and jumps to a certificate by any of its names', async () => {
  server.use(
    ...authHandlers({ authed: true }),
    http.get(url('/orgs/org-1/certificates'), () =>
      HttpResponse.json({ items: [makeCert({ id: 'c-7', name: 'edge', commonName: 'edge.example.com', sans: ['edge.example.com', 'cdn.example.net'] })], nextCursor: null }),
    ),
    http.get(url('/orgs/org-1/certificates/c-7'), () => HttpResponse.json(makeCert({ id: 'c-7', name: 'edge' }))),
    http.get(url('/orgs/org-1/cas'), () => HttpResponse.json([])),
    http.get(url('/orgs/org-1/acme-accounts'), () => HttpResponse.json([])),
    http.get(url('/orgs/org-1/dns-credentials'), () => HttpResponse.json([])),
    http.get(url('/orgs/org-1/issuance-defaults/effective'), () => HttpResponse.json({})),
  );
  const { router, user } = renderRoute('/o/acme/overview');
  await screen.findByRole('heading', { name: 'Overview' });
  await user.keyboard('{Control>}k{/Control}');
  await user.type(await screen.findByPlaceholderText('www.example.com'), 'cdn.example');
  await user.click(await screen.findByRole('option', { name: /^edge/ }));
  await waitFor(() => expect(router.state.location.pathname).toBe('/o/acme/certificates/c-7/overview'));
});

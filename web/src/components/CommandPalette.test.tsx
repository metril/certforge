import { http, HttpResponse } from 'msw';
import { screen, waitFor } from '@testing-library/react';
import { expect, it } from 'vitest';
import { server } from '@/test/server';
import { authHandlers, makeCert, url } from '@/test/fixtures';
import { renderRoute } from '@/test/render';

function certificateHandlers(cert: ReturnType<typeof makeCert>) {
  return [
    ...authHandlers({ authed: true }),
    http.get(url('/orgs/org-1/certificates'), () => HttpResponse.json({ items: [cert], nextCursor: null })),
    http.get(url(`/orgs/org-1/certificates/${cert.id}`), () => HttpResponse.json(cert)),
    http.get(url('/orgs/org-1/cas'), () => HttpResponse.json([])),
    http.get(url('/orgs/org-1/acme-accounts'), () => HttpResponse.json([])),
    http.get(url('/orgs/org-1/dns-credentials'), () => HttpResponse.json([])),
    http.get(url('/orgs/org-1/issuance-defaults/effective'), () => HttpResponse.json({})),
  ];
}

it('opens with Ctrl-K and jumps to a certificate by any of its names', async () => {
  server.use(...certificateHandlers(makeCert({ id: 'c-7', name: 'edge', commonName: 'edge.example.com', sans: ['edge.example.com', 'cdn.example.net'] })));
  const { router, user } = renderRoute('/o/acme/overview');
  await screen.findByRole('heading', { name: 'Overview' });
  await user.keyboard('{Control>}k{/Control}');
  await user.type(await screen.findByPlaceholderText('www.example.com'), 'cdn.example');
  await user.click(await screen.findByRole('option', { name: /^edge/ }));
  await waitFor(() => expect(router.state.location.pathname).toBe('/o/acme/certificates/c-7/overview'));
});

// Review fix: Certificates now render before Actions (a "Renew <name>" item
// used to come first in the DOM, so Enter on a matching name renewed
// instead of navigating). cmdk auto-highlights the first matching item.
it('selects the matching certificate on Enter instead of the Renew action below it', async () => {
  const renewed: string[] = [];
  server.use(
    ...certificateHandlers(makeCert({ id: 'c-9', name: 'edge', commonName: 'edge.example.com', sans: ['edge.example.com'] })),
    http.post(url('/orgs/org-1/certificates/:id/renew'), ({ params }) => (renewed.push(params.id as string), new HttpResponse(null, { status: 202 }))),
  );
  const { router, user } = renderRoute('/o/acme/overview');
  await screen.findByRole('heading', { name: 'Overview' });
  await user.keyboard('{Control>}k{/Control}');
  await user.type(await screen.findByPlaceholderText('www.example.com'), 'edge');
  await screen.findByRole('option', { name: /^edge/ });
  await user.keyboard('{Enter}');
  await waitFor(() => expect(router.state.location.pathname).toBe('/o/acme/certificates/c-9/overview'));
  expect(renewed).toEqual([]);
});

// Review fix: the palette's own dialog is exempt from the global suppress
// selector for Ctrl/Cmd-K specifically, so a second press — even with the
// search input focused — closes it instead of being swallowed the same way
// a generic dialog/sheet/popover swallows it (lib/shortcuts.test.ts).
it('closes on a second Ctrl-K pressed while its own search input has focus', async () => {
  server.use(...certificateHandlers(makeCert({ id: 'c-8', name: 'edge' })));
  const { user } = renderRoute('/o/acme/overview');
  await screen.findByRole('heading', { name: 'Overview' });
  await user.keyboard('{Control>}k{/Control}');
  const input = await screen.findByPlaceholderText('www.example.com');
  await user.click(input);
  expect(input).toHaveFocus();
  await user.keyboard('{Control>}k{/Control}');
  await waitFor(() => expect(screen.queryByPlaceholderText('www.example.com')).toBeNull());
});

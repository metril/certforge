import { http, HttpResponse } from 'msw';
import { screen, waitFor } from '@testing-library/react';
import { expect, it } from 'vitest';
import { server } from '@/test/server';
import { url } from '@/test/fixtures';
import { renderUI } from '@/test/render';
import { ManualDnsCard } from './ManualDnsCard';

it('lists TXT records with copy buttons, copies zone lines, and confirms', async () => {
  let confirmed = false;
  server.use(
    http.get(url('/orgs/org-1/certificates/c-1/manual-dns'), () =>
      HttpResponse.json([
        { name: '_acme-challenge.lab.local', type: 'TXT', value: 'abc123', ttl: 60 },
        { name: '_acme-challenge.lab.local.', type: 'TXT', value: 'def456', ttl: 60 },
      ]),
    ),
    http.post(url('/orgs/org-1/certificates/c-1/manual-dns/confirm'), () => {
      confirmed = true;
      return new HttpResponse(null, { status: 202 });
    }),
  );
  const { user } = renderUI(<ManualDnsCard orgId="org-1" cert={{ id: 'c-1', name: 'lab' }} />);
  expect(await screen.findByRole('region', { name: 'Manual DNS for lab' })).toBeInTheDocument();
  expect(screen.getAllByRole('button', { name: /^Copy value for / })).toHaveLength(2);
  await user.click(screen.getByRole('button', { name: 'Copy all as zone lines' }));
  expect(await navigator.clipboard.readText()).toBe(
    '_acme-challenge.lab.local. 60 IN TXT "abc123"\n_acme-challenge.lab.local. 60 IN TXT "def456"',
  );
  await user.click(screen.getByRole('button', { name: "I've added them" }));
  await waitFor(() => expect(confirmed).toBe(true));
});

it('renders nothing when there are no records', async () => {
  let asked = false;
  server.use(http.get(url('/orgs/org-1/certificates/c-1/manual-dns'), () => ((asked = true), HttpResponse.json([]))));
  renderUI(<ManualDnsCard orgId="org-1" cert={{ id: 'c-1', name: 'lab' }} />);
  await waitFor(() => expect(asked).toBe(true));
  expect(screen.queryByRole('region', { name: /Manual DNS/ })).toBeNull();
});

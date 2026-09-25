import { http, HttpResponse } from 'msw';
import { screen, waitFor } from '@testing-library/react';
import { expect, it } from 'vitest';
import { server } from '@/test/server';
import { iso, problem, url } from '@/test/fixtures';
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
  const { user } = renderUI(<ManualDnsCard orgId="org-1" cert={{ id: 'c-1', name: 'lab' }} canConfirm />);
  expect(await screen.findByRole('region', { name: 'Manual DNS for lab' })).toBeInTheDocument();
  expect(screen.getAllByRole('button', { name: /^Copy value for / })).toHaveLength(2);
  await user.click(screen.getByRole('button', { name: 'Copy all as zone lines' }));
  expect(await navigator.clipboard.readText()).toBe(
    '_acme-challenge.lab.local. 60 IN TXT "abc123"\n_acme-challenge.lab.local. 60 IN TXT "def456"',
  );
  await user.click(screen.getByRole('button', { name: "I've added them" }));
  await waitFor(() => expect(confirmed).toBe(true));
});

// Fix round 2 (Important #1): certs:issue is gated by the caller
// (OverviewPage/CertificateDetail pass `canConfirm`, mirroring
// CertificateHeader's own canRenew/canDelete props) — with it false the
// confirm button stays visible but disabled, with a tooltip.
it('disables the confirm button when canConfirm is false', async () => {
  server.use(
    http.get(url('/orgs/org-1/certificates/c-1/manual-dns'), () =>
      HttpResponse.json([{ name: '_acme-challenge.lab.local', type: 'TXT', value: 'abc123', ttl: 60 }]),
    ),
  );
  renderUI(<ManualDnsCard orgId="org-1" cert={{ id: 'c-1', name: 'lab' }} canConfirm={false} />);
  expect(await screen.findByRole('button', { name: "I've added them" })).toBeDisabled();
});

it('renders nothing when there are no records', async () => {
  let asked = false;
  server.use(http.get(url('/orgs/org-1/certificates/c-1/manual-dns'), () => ((asked = true), HttpResponse.json([]))));
  renderUI(<ManualDnsCard orgId="org-1" cert={{ id: 'c-1', name: 'lab' }} canConfirm />);
  await waitFor(() => expect(asked).toBe(true));
  expect(screen.queryByRole('region', { name: /Manual DNS/ })).toBeNull();
});

// Fix round 1 (review, Take now #4): "Add these before <a time already
// gone by>" reads as broken once the deadline has passed; a fixed line that
// switches state (computed at render, no timer) replaces it.
it('shows an expired message once the deadline has passed, not a stale "add before"', async () => {
  server.use(
    http.get(url('/orgs/org-1/certificates/c-1/manual-dns'), () =>
      HttpResponse.json([{ name: '_acme-challenge.lab.local', type: 'TXT', value: 'abc123', ttl: 60, expiresAt: iso(-0.001) }]),
    ),
  );
  renderUI(<ManualDnsCard orgId="org-1" cert={{ id: 'c-1', name: 'lab' }} canConfirm />);
  expect(await screen.findByText(/expired without confirmation/)).toBeInTheDocument();
  expect(screen.queryByText(/^Add these before/)).toBeNull();
});

// Fix round 1 (review, Take now #5): a 409 ("nothing waiting, or the
// records expired") must not sit above a fresh set of records once one
// arrives — confirm's own onSettled already refetches this query; the card
// must clear the stale message when that refetch lands new data.
it('clears a 409 error once a fresh set of records arrives', async () => {
  // The second GET (triggered by confirm's own onSettled invalidation) is
  // delayed a beat so the intermediate state — error shown, old records
  // still on screen — is actually observable, instead of the refetch
  // racing ahead of the assertion within the same tick.
  let getCalls = 0;
  server.use(
    http.get(url('/orgs/org-1/certificates/c-1/manual-dns'), async () => {
      getCalls++;
      if (getCalls > 1) await new Promise((r) => setTimeout(r, 30));
      const value = getCalls === 1 ? 'abc123' : 'freshvalue';
      return HttpResponse.json([{ name: '_acme-challenge.lab.local', type: 'TXT', value, ttl: 60 }]);
    }),
    http.post(url('/orgs/org-1/certificates/c-1/manual-dns/confirm'), () => problem(409, 'no manual-dns records are waiting, or they expired', {}, 'Nothing to confirm')),
  );
  const { user } = renderUI(<ManualDnsCard orgId="org-1" cert={{ id: 'c-1', name: 'lab' }} canConfirm />);
  await screen.findByText('abc123');
  await user.click(screen.getByRole('button', { name: "I've added them" }));
  expect(await screen.findByRole('alert')).toHaveTextContent(/no manual-dns records are waiting/i);
  await screen.findByText('freshvalue');
  expect(screen.queryByRole('alert')).toBeNull();
});

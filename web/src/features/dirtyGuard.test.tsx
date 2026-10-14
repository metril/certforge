import { useState, type ReactElement } from 'react';
import { http, HttpResponse } from 'msw';
import { screen, waitFor } from '@testing-library/react';
import { beforeEach, it, expect, vi } from 'vitest';
import type { DnsCredential } from '@/api/types';
import { server } from '@/test/server';
import { authHandlers, me, presets, caLocalImported, cloudflare, makeChannel, makeLayout, makeMonitor, makeTarget, metaNotifiers, org, targetTestSecret, testSecretSchema, traefikSchema, url } from '@/test/fixtures';
import { renderRoute, renderUI } from '@/test/render';
import { LayoutSheet } from '@/features/delivery/LayoutSheet';
import { CaSheet } from '@/features/issuers/CaSheet';
import { CredentialSheet } from '@/features/issuers/CredentialSheet';
import { MonitorSheet } from '@/features/alerts/MonitorSheet';
import { ChannelSheet } from '@/features/alerts/ChannelSheet';

vi.mock('@/lib/org', async (orig) => ({ ...(await orig<typeof import('@/lib/org')>()), useMe: () => me }));

// Regression: opening an existing item and pressing Escape without touching
// anything must close at once, never raise "Discard changes?".
beforeEach(() => {
  server.use(
    ...authHandlers({ authed: true }),
    http.get(url('/meta/schemas'), () => HttpResponse.json({ dnsProviders: [cloudflare], deployTargets: [traefikSchema, testSecretSchema], notifiers: metaNotifiers, signers: [] })),
    http.get(url('/orgs/org-1/certificates'), () => HttpResponse.json({ items: [] })),
    http.get(url('/meta/ca-presets'), () => HttpResponse.json(presets)),
  );
});

function Host({ children }: { children: (open: boolean, set: (o: boolean) => void) => ReactElement }) {
  const [open, setOpen] = useState(true);
  return <>{open ? children(open, setOpen) : <p>closed</p>}</>;
}

async function expectCleanEscape(ui: ReactElement, ready: RegExp | string) {
  const { user } = renderUI(ui);
  await screen.findByText(ready);
  // Let mount effects (SecretInput sentinels, RJSF defaults) settle first.
  await new Promise((r) => setTimeout(r, 100));
  // Autofocus can land on a HelpTip, whose tooltip would eat the first Escape.
  (document.activeElement as HTMLElement | null)?.blur();
  await user.keyboard('{Escape}');
  await new Promise((r) => setTimeout(r, 200));
  expect(screen.queryByText('Discard changes?')).not.toBeInTheDocument();
  await waitFor(() => expect(screen.getByText('closed')).toBeInTheDocument());
}

// The target edit page opens clean: leaving it raises no discard prompt.
async function expectCleanLeave(id: string, heading: string) {
  server.use(http.get(url('/orgs/org-1/deploy-targets'), () => HttpResponse.json({ items: [targetTestSecret, makeTarget()] })));
  const { router } = renderRoute(`/o/acme/delivery/targets/${id}/edit`);
  await screen.findByRole('heading', { name: heading });
  await new Promise((r) => setTimeout(r, 100));
  await router.navigate({ to: '/o/$org/delivery/targets', params: { org: 'acme' } });
  expect(screen.queryByText('Discard changes?')).not.toBeInTheDocument();
  await waitFor(() => expect(router.state.location.pathname).toBe('/o/acme/delivery/targets'));
}

it('target edit page with stored secrets leaves clean', () => expectCleanLeave(targetTestSecret.id, 'Edit test sink'));

it('target edit page plain leaves clean', () => expectCleanLeave('t-1', 'Edit edge traefik'));

it('LayoutSheet with stored password closes clean', async () => {
  const files = [{ path: '/a.p12', format: 'p12', parts: ['fullchain', 'key'], owner: 'root', group: 'root', mode: '0640' }] as never;
  await expectCleanEscape(
    <Host>{(_o, set) => <LayoutSheet orgId={org.id} layout={makeLayout({ passwordSet: true, files })} readOnly={false} onOpenChange={set} />}</Host>,
    'Edit nginx',
  );
});

it('CaSheet (imported private CA) closes clean', async () => {
  await expectCleanEscape(<Host>{(o, set) => <CaSheet orgId={org.id} open={o} ca={caLocalImported} onOpenChange={set} />}</Host>, /Edit Imported CA/);
});

it('CredentialSheet with stored secret closes clean', async () => {
  const credential = { id: 'cr-1', orgId: org.id, name: 'cf', provider: 'cloudflare', config: {}, storedSecrets: ['CF_DNS_API_TOKEN'], createdAt: '', updatedAt: '' } as unknown as DnsCredential;
  await expectCleanEscape(<Host>{(o, set) => <CredentialSheet orgId={org.id} open={o} provider={cloudflare} credential={credential} onOpenChange={set} />}</Host>, 'Edit cf');
});

it('MonitorSheet closes clean', async () => {
  await expectCleanEscape(<Host>{(o, set) => <MonitorSheet orgId={org.id} open={o} monitor={makeMonitor()} onOpenChange={set} />}</Host>, 'edge');
});

it('ChannelSheet with stored secret closes clean', async () => {
  await expectCleanEscape(<Host>{(o, set) => <ChannelSheet orgId={org.id} open={o} channel={makeChannel()} onOpenChange={set} />}</Host>, 'ops-webhook');
});

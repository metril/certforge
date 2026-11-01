import { http, HttpResponse } from 'msw';
import { screen } from '@testing-library/react';
import { beforeEach, expect, it } from 'vitest';
import { server } from '@/test/server';
import { authHandlers, ca, caLocal, makeCert, providers, url } from '@/test/fixtures';
import { renderRoute } from '@/test/render';

function setup(caId: string, rules = [] as ReturnType<typeof makeCert>['verificationRules']) {
  const cert = makeCert({ verificationRules: rules, effective: { caId: { value: caId, source: 'cert' } } });
  server.use(
    ...authHandlers({ authed: true }),
    http.get(url('/orgs/org-1/certificates/c-1'), () => HttpResponse.json(cert)),
    http.get(url('/orgs/org-1/certificates/c-1/versions'), () => HttpResponse.json([])),
    http.get(url('/orgs/org-1/certificates'), () => HttpResponse.json({ items: [cert], nextCursor: null })),
    http.get(url('/orgs/org-1/cas'), () => HttpResponse.json([ca, caLocal])),
    http.get(url('/orgs/org-1/acme-accounts'), () => HttpResponse.json([])),
    http.get(url('/orgs/org-1/dns-credentials'), () => HttpResponse.json([])),
    http.get(url('/orgs/org-1/clients'), () => HttpResponse.json({ items: [], nextCursor: null })),
    http.get(url('/meta/schemas'), () => HttpResponse.json({ dnsProviders: providers, deployTargets: [], notifiers: [], signers: [] })),
    http.get(url('/orgs/org-1/issuance-defaults/effective'), () => HttpResponse.json({ builtin: {} })),
    http.get(url('/orgs/org-1/issuance-defaults'), () => HttpResponse.json({})),
    http.get(url('/settings/issuance_defaults'), () => HttpResponse.json({ schema: {}, value: {} })),
  );
}

beforeEach(() => localStorage.clear());

for (const tab of ['overview', 'settings']) {
  it(`${tab}: a private CA shows verification as not needed, no coverage warnings`, async () => {
    setup(caLocal.id);
    renderRoute(`/o/acme/certificates/c-1/${tab}`);
    expect(await screen.findByText(/Internal CA issues without domain verification/)).toBeInTheDocument();
    expect(screen.queryByRole('region', { name: 'Coverage' })).not.toBeInTheDocument();
    expect(screen.queryByText(/No matching rule/)).not.toBeInTheDocument();
  });

  it(`${tab}: an ACME CA still shows coverage`, async () => {
    setup(ca.id);
    renderRoute(`/o/acme/certificates/c-1/${tab}`);
    expect(await screen.findByRole('region', { name: 'Coverage' })).toBeInTheDocument();
    expect(screen.queryByText(/issues without domain verification/)).not.toBeInTheDocument();
  });
}

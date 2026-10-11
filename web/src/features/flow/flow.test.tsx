import { http, HttpResponse } from 'msw';
import { fireEvent, screen, waitFor, within } from '@testing-library/react';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import { server } from '@/test/server';
import { authHandlers, makeGrant, meWith, problem, url } from '@/test/fixtures';
import { renderRoute } from '@/test/render';
import type { Flow, FlowNodeData } from './flowGraph';

const node = (kind: FlowNodeData['kind'], id: string, extra: Partial<FlowNodeData> = {}): FlowNodeData => ({
  id: `${kind}:${id}`,
  kind,
  name: id,
  status: 'valid',
  href: `/o/acme/certificates/${id}`,
  ...extra,
});
const lane = (nodes: FlowNodeData[], hidden = false) => ({ hidden, omitted: 0, nodes });
const e = (from: string, to: string, certificateId?: string) => ({ from, to, status: 'valid' as const, certificateId });

const base: Flow = {
  truncated: false,
  generatedAt: '2026-01-01T00:00:00Z',
  lanes: {
    issuers: lane([node('ca', 'letsencrypt', { href: '/o/acme/issuers/cas?edit=ca1' })]),
    certificates: lane([node('certificate', 'www', { status: 'expiring', statusDetail: 'Expires in 5 days' }), node('certificate', 'api')]),
    delivery: lane([node('layout', 'nginx')]),
    clients: lane([node('client', 'web-1'), node('client', 'web-2')]),
    alerts: lane([node('channel', 'ops', { coversCertificates: true })]),
  },
  edges: [
    e('certificate:www', 'ca:letsencrypt'),
    e('certificate:api', 'ca:letsencrypt'),
    e('certificate:www', 'layout:nginx'),
    e('certificate:api', 'layout:nginx'),
    e('layout:nginx', 'client:web-1', 'www'),
    e('layout:nginx', 'client:web-2', 'api'),
  ],
};

function useFlow(f: () => Flow | Response) {
  server.use(http.get(url('/orgs/org-1/flow'), () => {
    const r = f();
    return r instanceof Response ? r : HttpResponse.json(r);
  }));
}

function setWidth(wide: boolean) {
  window.matchMedia = ((query: string) => ({
    matches: wide && (query.includes('1024px') || query.includes('768px')),
    media: query,
    onchange: null,
    addEventListener: () => {},
    removeEventListener: () => {},
    addListener: () => {},
    removeListener: () => {},
    dispatchEvent: () => false,
  })) as unknown as typeof window.matchMedia;
}

const original = window.matchMedia;
beforeEach(() =>
  server.use(
    ...authHandlers({ authed: true }),
    http.get(url('/orgs/org-1/clients/:id/grants'), () => HttpResponse.json({ items: [] })),
    http.get(url('/orgs/org-1/deploy-targets/:id/grants'), () => HttpResponse.json([])),
  ),
);
afterEach(() => {
  window.matchMedia = original;
});

const lanes = ['Issuers', 'Certificates', 'Delivery', 'Clients', 'Alerts'];

it('renders the five lanes with counts and connectors on a wide screen', async () => {
  setWidth(true);
  useFlow(() => base);
  const { container } = renderRoute('/o/acme/flow');
  for (const l of lanes) expect(await screen.findByRole('region', { name: l })).toBeInTheDocument();
  expect(within(screen.getByRole('region', { name: 'Certificates' })).getByText('2')).toBeInTheDocument();
  await waitFor(() => expect(container.querySelectorAll('[data-flow-connectors] path[data-edge]').length).toBe(6));
  expect(screen.getByRole('link', { name: 'Flow' })).toBeInTheDocument();
});

it('selecting a node dims the rest, shows the path panel with Open links, and clears with Escape', async () => {
  setWidth(true);
  useFlow(() => base);
  const { user, router, container } = renderRoute('/o/acme/flow');
  const www = await screen.findByRole('button', { name: /Certificate www/ });
  await user.click(www);
  await waitFor(() => expect(router.state.location.search).toMatchObject({ focus: 'certificate:www' }));
  const panel = await screen.findByRole('complementary', { name: 'Details' });
  expect(within(panel).getByRole('button', { name: 'letsencrypt' })).toBeInTheDocument();
  expect(within(panel).getByRole('button', { name: 'web-1' })).toBeInTheDocument();
  expect(within(panel).queryByRole('button', { name: 'web-2' })).toBeNull();
  expect(within(panel).getByRole('link', { name: 'Open letsencrypt' })).toHaveAttribute('href', '/o/acme/issuers/cas?edit=ca1');
  expect(screen.getByRole('button', { name: /Certificate api/ })).toHaveClass('opacity-40');
  expect(screen.getByRole('button', { name: /Client web-2/ })).toHaveClass('opacity-40');
  expect(screen.getByRole('button', { name: /Client web-1/ })).not.toHaveClass('opacity-40');
  expect(container.querySelectorAll('[data-dashed]').length).toBe(1);

  www.focus();
  await user.keyboard('{Escape}');
  await waitFor(() => expect(screen.queryByRole('complementary', { name: 'Details' })).toBeNull());
  expect(screen.getByRole('button', { name: /Certificate api/ })).not.toHaveClass('opacity-40');
});

it('Escape on a node clears the path even when an open tooltip already handled the key', async () => {
  setWidth(true);
  useFlow(() => base);
  renderRoute('/o/acme/flow?focus=certificate:www');
  await screen.findByRole('complementary', { name: 'Details' });
  const www = screen.getByRole('button', { name: /Certificate www/ });
  www.addEventListener('keydown', (ev) => ev.preventDefault());
  www.focus();
  const ev = new KeyboardEvent('keydown', { key: 'Escape', bubbles: true, cancelable: true });
  www.dispatchEvent(ev);
  expect(ev.defaultPrevented).toBe(true);
  await waitFor(() => expect(screen.queryByRole('complementary', { name: 'Details' })).toBeNull());
});

it('Escape inside the filter input does not clear the path selection', async () => {
  setWidth(true);
  useFlow(() => base);
  const { user } = renderRoute('/o/acme/flow?focus=certificate:www');
  await screen.findByRole('complementary', { name: 'Details' });
  await user.click(screen.getByRole('textbox', { name: 'Filter by name' }));
  await user.keyboard('{Escape}');
  expect(screen.getByRole('complementary', { name: 'Details' })).toBeInTheDocument();
});

it('moves focus within a lane with the arrow keys and clears by clicking the selected node', async () => {
  setWidth(true);
  useFlow(() => base);
  const { user } = renderRoute('/o/acme/flow?focus=certificate:www');
  const api = await screen.findByRole('button', { name: /Certificate api/ });
  const www = screen.getByRole('button', { name: /Certificate www/ });
  www.focus();
  await user.keyboard('{ArrowDown}');
  expect(api).toHaveFocus();
  await user.click(www);
  await waitFor(() => expect(screen.queryByRole('complementary', { name: 'Details' })).toBeNull());
});

it('shows empty, hidden and truncated states', async () => {
  setWidth(true);
  useFlow(() => ({
    ...base,
    truncated: true,
    lanes: { ...base.lanes, issuers: lane([]), alerts: lane([], true), clients: lane([]) },
    edges: [],
  }));
  renderRoute('/o/acme/flow');
  const issuers = await screen.findByRole('region', { name: 'Issuers' });
  expect(within(issuers).getByRole('link', { name: 'Add an issuer' })).toHaveAttribute('href', '/o/acme/issuers');
  expect(within(screen.getByRole('region', { name: 'Alerts' })).getByText('No access')).toBeInTheDocument();
  expect(screen.queryByText('Truncated')).toBeNull();
});

it('shows Retry when the flow fetch fails', async () => {
  useFlow(() => problem(500, 'boom'));
  renderRoute('/o/acme/flow');
  expect(await screen.findByRole('button', { name: 'Retry' })).toBeInTheDocument();
});

it('narrow screens open a bottom sheet and the close button clears the focus', async () => {
  setWidth(false);
  useFlow(() => base);
  const { user, router, container } = renderRoute('/o/acme/flow');
  const www = await screen.findByRole('button', { name: /Certificate www/ });
  expect(container.querySelector('[data-flow-connectors]')).toBeNull();
  await user.click(www);
  const dialog = await screen.findByRole('dialog');
  expect(within(dialog).getByRole('list', { name: 'Path' })).toBeInTheDocument();
  expect(screen.queryByRole('complementary', { name: 'Details' })).toBeNull();
  await user.click(within(dialog).getByRole('button', { name: 'Close' }));
  await waitFor(() => expect(router.state.location.search).not.toHaveProperty('focus'));
  await waitFor(() => expect(screen.queryByRole('dialog')).toBeNull());
});

it('the toolbar controls write the URL and the lanes follow', async () => {
  setWidth(true);
  useFlow(() => base);
  const { user, router, container } = renderRoute('/o/acme/flow');
  await screen.findByRole('button', { name: /Certificate www/ });
  await user.type(screen.getByRole('textbox', { name: 'Filter by name' }), 'web-1');
  await waitFor(() => expect(router.state.location.search).toMatchObject({ q: 'web-1' }));
  await waitFor(() => expect(screen.queryByRole('button', { name: /Client web-2/ })).toBeNull());
  expect(screen.getByRole('button', { name: /Certificate www/ })).toBeInTheDocument();
  expect(screen.queryByRole('button', { name: /Certificate api/ })).toBeNull();
  expect(within(screen.getByRole('region', { name: 'Clients' })).getByText('1/2')).toBeInTheDocument();
  await waitFor(() => expect(container.querySelectorAll('[data-flow-connectors] path[data-edge]').length).toBe(3));
  await user.click(screen.getByRole('button', { name: 'Clear filters' }));
  await waitFor(() => expect(router.state.location.search).not.toHaveProperty('q'));
  expect(await screen.findByRole('button', { name: /Client web-2/ })).toBeInTheDocument();
});

it('Problems keeps the unhealthy flow, and an empty result offers Clear filters', async () => {
  setWidth(true);
  useFlow(() => base);
  const { user, router } = renderRoute('/o/acme/flow');
  await screen.findByRole('button', { name: /Certificate www/ });
  await user.click(screen.getByRole('button', { name: 'Problems' }));
  await waitFor(() => expect(router.state.location.search).toMatchObject({ status: ['failed', 'expired', 'drift', 'expiring'] }));
  expect(screen.getByRole('button', { name: /Certificate www/ })).toBeInTheDocument();
  expect(screen.queryByRole('button', { name: /Certificate api/ })).toBeNull();
  await user.type(screen.getByRole('textbox', { name: 'Filter by name' }), 'nothing-like-this');
  expect(await screen.findByText('No flows match these filters.')).toBeInTheDocument();
  await user.click(screen.getAllByRole('button', { name: 'Clear filters' })[0]!);
  expect(await screen.findByRole('button', { name: /Certificate api/ })).toBeInTheDocument();
});

it('clears the focus when the filters hide the focused node', async () => {
  setWidth(true);
  useFlow(() => base);
  const { router } = renderRoute('/o/acme/flow?focus=certificate:api&q=www');
  await screen.findByRole('button', { name: /Certificate www/ });
  await waitFor(() => expect(router.state.location.search).not.toHaveProperty('focus'));
});

it('collapsing a lane shows one proxy row with the count and keeps the connectors', async () => {
  setWidth(true);
  useFlow(() => base);
  const { user, router, container } = renderRoute('/o/acme/flow');
  await screen.findByRole('button', { name: /Certificate www/ });
  const certs = screen.getByRole('region', { name: 'Certificates' });
  const head = within(certs).getByRole('button', { name: /^Certificates/ });
  expect(head).toHaveAttribute('aria-expanded', 'true');
  expect(certs.querySelector('h2')).toHaveTextContent('1 problem');
  await user.click(head);
  await waitFor(() => expect(router.state.location.search).toMatchObject({ collapsed: ['certificates'] }));
  expect(head).toHaveAttribute('aria-expanded', 'false');
  expect(screen.queryByRole('button', { name: /Certificate www/ })).toBeNull();
  const proxy = within(certs).getByRole('button', { name: 'Expand Certificates, 2 items, Expiring' });
  expect(proxy).toHaveTextContent('2');
  // Both certificates merge into the proxy: proxy-ca, proxy-layout and the two layout-client edges.
  await waitFor(() => expect(container.querySelectorAll('[data-flow-connectors] path[data-edge]').length).toBe(4));
  await user.click(proxy);
  await waitFor(() => expect(router.state.location.search).not.toHaveProperty('collapsed'));
  expect(await screen.findByRole('button', { name: /Certificate www/ })).toBeInTheDocument();
});

it('collapses a sub-group in place and Collapse all / Expand all toggle every lane', async () => {
  setWidth(true);
  useFlow(() => ({ ...base, lanes: { ...base.lanes, issuers: lane([node('ca', 'letsencrypt'), node('account', 'acct')]) } }));
  const { user, router } = renderRoute('/o/acme/flow');
  await screen.findByRole('button', { name: /Certificate www/ });
  await user.click(screen.getByRole('button', { name: /^ACME accounts/ }));
  await waitFor(() => expect(router.state.location.search).toMatchObject({ collapsed: ['issuers.accounts'] }));
  expect(screen.getByRole('button', { name: /CA letsencrypt/ })).toBeInTheDocument();
  expect(screen.getByRole('button', { name: 'Expand ACME accounts, 1 item, Healthy' })).toBeInTheDocument();
  await user.click(screen.getByRole('button', { name: 'Collapse all' }));
  await waitFor(() => expect(router.state.location.search.collapsed).toHaveLength(5));
  for (const l of lanes) expect(within(screen.getByRole('region', { name: l })).getAllByRole('button', { name: new RegExp(`^${l}`) })[0]).toHaveAttribute('aria-expanded', 'false');
  await user.click(screen.getByRole('button', { name: 'Expand all' }));
  await waitFor(() => expect(router.state.location.search).not.toHaveProperty('collapsed'));
  expect(await screen.findByRole('button', { name: /Certificate www/ })).toBeInTheDocument();
});

it('moves focus to the group heading after expanding a proxy, and arrows reach proxies', async () => {
  setWidth(true);
  useFlow(() => ({ ...base, lanes: { ...base.lanes, issuers: lane([node('ca', 'letsencrypt'), node('account', 'acct')]) } }));
  const { user } = renderRoute('/o/acme/flow?collapsed=%5B%22issuers.accounts%22%5D');
  const ca = await screen.findByRole('button', { name: /CA letsencrypt/ });
  ca.focus();
  await user.keyboard('{ArrowDown}');
  const proxy = screen.getByRole('button', { name: /^Expand ACME accounts/ });
  expect(proxy).toHaveFocus();
  await user.keyboard('{Enter}');
  const head = await screen.findByRole('button', { name: /^ACME accounts/ });
  await waitFor(() => expect(head).toHaveFocus());
});

it('opens the collapsed group of a focused node', async () => {
  setWidth(true);
  useFlow(() => base);
  const { router } = renderRoute('/o/acme/flow?focus=certificate:www&collapsed=%5B%22certificates%22,%22alerts%22%5D');
  expect(await screen.findByRole('button', { name: /Certificate www/ })).toBeInTheDocument();
  await waitFor(() => expect(router.state.location.search).toMatchObject({ collapsed: ['alerts'] }));
});

it('does not count a pending channel as a problem', async () => {
  setWidth(true);
  useFlow(() => ({ ...base, lanes: { ...base.lanes, alerts: lane([node('channel', 'ops', { status: 'pending' })]) } }));
  renderRoute('/o/acme/flow');
  const head = within(await screen.findByRole('region', { name: 'Alerts' })).getByRole('button', { name: /^Alerts/ });
  expect(head).not.toHaveTextContent('problem');
});

// Two issuers: cert www uses ca one, cert api uses ca two.
const twoIssuers: Flow = {
  ...base,
  lanes: {
    ...base.lanes,
    issuers: lane([node('ca', 'one'), node('ca', 'two')]),
  },
  edges: [
    e('certificate:www', 'ca:one'),
    e('certificate:api', 'ca:two'),
    e('certificate:www', 'layout:nginx'),
    e('certificate:api', 'layout:nginx'),
    e('layout:nginx', 'client:web-1', 'www'),
    e('layout:nginx', 'client:web-2', 'api'),
  ],
};

it('the Kind chips hide other kinds but keep the paths of the kept ones', async () => {
  setWidth(true);
  useFlow(() => base);
  const { user, router } = renderRoute('/o/acme/flow');
  await screen.findByRole('button', { name: /Certificate www/ });
  await user.click(screen.getByRole('button', { name: 'Client' }));
  await waitFor(() => expect(router.state.location.search).toMatchObject({ kind: ['client'] }));
  expect(screen.getByRole('button', { name: /Client web-1/ })).toBeInTheDocument();
  expect(screen.getByRole('button', { name: /Certificate www/ })).toBeInTheDocument();
  expect(screen.getByRole('button', { name: /CA letsencrypt/ })).toBeInTheDocument();
});

it('the Status chips keep nodes with that status and their paths', async () => {
  setWidth(true);
  useFlow(() => base);
  const { user, router } = renderRoute('/o/acme/flow');
  await screen.findByRole('button', { name: /Certificate www/ });
  await user.click(screen.getByRole('button', { name: 'Expiring' }));
  await waitFor(() => expect(router.state.location.search).toMatchObject({ status: ['expiring'] }));
  expect(screen.getByRole('button', { name: /Certificate www/ })).toBeInTheDocument();
  expect(screen.queryByRole('button', { name: /Certificate api/ })).toBeNull();
  expect(screen.getByRole('button', { name: 'Expiring' })).toHaveAttribute('aria-pressed', 'true');
});

it('the legacy ?status=problems still filters and lights the Problems chip', async () => {
  setWidth(true);
  useFlow(() => base);
  renderRoute('/o/acme/flow?status=problems');
  await screen.findByRole('button', { name: /Certificate www/ });
  expect(screen.queryByRole('button', { name: /Certificate api/ })).toBeNull();
  expect(screen.getByRole('button', { name: 'Problems' })).toHaveAttribute('aria-pressed', 'true');
});

it('the Issuer filter keeps only that issuer\'s certificates and their downstream', async () => {
  setWidth(true);
  useFlow(() => twoIssuers);
  const { user, router } = renderRoute('/o/acme/flow');
  await screen.findByRole('button', { name: /Certificate www/ });
  await user.click(screen.getByRole('combobox', { name: 'Issuer' }));
  await user.click(await screen.findByRole('option', { name: /two/ }));
  await waitFor(() => expect(router.state.location.search).toMatchObject({ issuer: ['ca:two'] }));
  expect(screen.getByRole('button', { name: /Certificate api/ })).toBeInTheDocument();
  expect(screen.queryByRole('button', { name: /Certificate www/ })).toBeNull();
  expect(screen.queryByRole('button', { name: /CA one/ })).toBeNull();
});

it('hovering a node marks its path with data-hover-path', async () => {
  setWidth(true);
  useFlow(() => base);
  const { user, container } = renderRoute('/o/acme/flow');
  const www = await screen.findByRole('button', { name: /Certificate www/ });
  expect(container.querySelector('[data-hover-path]')).toBeNull();
  await user.hover(www);
  await waitFor(() => expect(screen.getByRole('button', { name: /CA letsencrypt/ })).toHaveAttribute('data-hover-path'));
  expect(screen.getByRole('button', { name: /Client web-1/ })).toHaveAttribute('data-hover-path');
  expect(screen.getByRole('button', { name: /Client web-2/ })).not.toHaveAttribute('data-hover-path');
  await waitFor(() => expect(container.querySelector('[data-flow-connectors] path[data-hover-path]')).not.toBeNull());
  await user.unhover(www);
  await waitFor(() => expect(container.querySelector('[data-hover-path]')).toBeNull());
});

const detailed: Flow = {
  ...base,
  lanes: {
    ...base.lanes,
    certificates: lane([
      node('certificate', 'www', { status: 'expiring', summary: { expiresAt: '2030-01-01T00:00:00Z', versionSerial: 'ab12cd', counts: { grants: 1, deployments: 0, problems: 2 }, lastError: 'disk full' } }),
      node('certificate', 'api'),
    ]),
  },
};

function renewSpy() {
  const ids: string[] = [];
  server.use(http.post(url('/orgs/org-1/certificates/:id/renew'), ({ params }) => {
    ids.push(String(params.id));
    return HttpResponse.json({});
  }));
  return ids;
}

it('selecting a certificate shows the detail aside with its summary and the five path steps', async () => {
  setWidth(true);
  useFlow(() => detailed);
  const { user } = renderRoute('/o/acme/flow');
  await user.click(await screen.findByRole('button', { name: /Certificate www/ }));
  const aside = await screen.findByRole('complementary', { name: 'Details' });
  expect(within(aside).getByText('Expires')).toBeInTheDocument();
  expect(within(aside).getByText('ab12cd')).toBeInTheDocument();
  expect(within(aside).getByText('disk full')).toBeInTheDocument();
  const steps = within(within(aside).getByRole('list', { name: 'Path' })).getAllByRole('listitem');
  expect(steps.map((li) => li.getAttribute('aria-label'))).toEqual(['Issuer, 1 item', 'Certificate, 1 item', 'Delivery, 1 item', 'Client, 1 item', 'Alert, 1 item']);
  expect(within(steps[0]!).getByRole('link', { name: 'Open letsencrypt' })).toHaveAttribute('href', '/o/acme/issuers/cas?edit=ca1');
});

it('Renew posts the certificate renew call', async () => {
  setWidth(true);
  useFlow(() => detailed);
  const ids = renewSpy();
  const { user } = renderRoute('/o/acme/flow?focus=certificate:www');
  const aside = await screen.findByRole('complementary', { name: 'Details' });
  await user.click(within(aside).getByRole('button', { name: 'Renew' }));
  await waitFor(() => expect(ids).toEqual(['www']));
});

it('a viewer sees Renew disabled with the permission tooltip', async () => {
  setWidth(true);
  useFlow(() => detailed);
  server.use(http.get(url('/auth/me'), () => HttpResponse.json(meWith([{ role: 'viewer', orgId: null }]))));
  const { user } = renderRoute('/o/acme/flow?focus=certificate:www');
  const aside = await screen.findByRole('complementary', { name: 'Details' });
  const renew = within(aside).getByRole('button', { name: 'Renew' });
  expect(renew).toBeDisabled();
  await user.hover(renew.parentElement!);
  expect((await screen.findAllByText('Needs the certs:issue permission')).length).toBeGreaterThan(0);
});

it('Redeploy on a client confirms the count and redeploys only the path\'s grants', async () => {
  setWidth(true);
  useFlow(() => detailed);
  const posted: string[] = [];
  server.use(
    http.get(url('/orgs/org-1/clients/web-1/grants'), () =>
      HttpResponse.json({ items: [makeGrant({ id: 'g1', certificateId: 'www' }), makeGrant({ id: 'g2', certificateId: 'other' })] }),
    ),
    http.post(url('/orgs/org-1/grants/:id/redeploy'), ({ params }) => {
      posted.push(String(params.id));
      return HttpResponse.json({});
    }),
  );
  const { user } = renderRoute('/o/acme/flow?focus=client:web-1');
  const aside = await screen.findByRole('complementary', { name: 'Details' });
  const btn = within(aside).getByRole('button', { name: 'Redeploy' });
  await waitFor(() => expect(btn).not.toBeDisabled());
  await user.click(btn);
  const dlg = await screen.findByRole('dialog');
  expect(within(dlg).getByText(/Redeploy 1 grant\b/)).toBeInTheDocument();
  await user.click(within(dlg).getByRole('button', { name: 'Redeploy' }));
  await waitFor(() => expect(posted).toEqual(['g1']));
});

it('Redeploy is disabled when the client has no grants', async () => {
  setWidth(true);
  useFlow(() => detailed);
  server.use(http.get(url('/orgs/org-1/clients/web-1/grants'), () => HttpResponse.json({ items: [] })));
  renderRoute('/o/acme/flow?focus=client:web-1');
  const aside = await screen.findByRole('complementary', { name: 'Details' });
  await waitFor(() => expect(within(aside).getByRole('button', { name: 'Redeploy' })).toBeDisabled());
});

it('clicking a stepper row re-focuses that node', async () => {
  setWidth(true);
  useFlow(() => detailed);
  const { user, router } = renderRoute('/o/acme/flow?focus=certificate:www');
  const aside = await screen.findByRole('complementary', { name: 'Details' });
  await user.click(within(aside).getByRole('button', { name: 'letsencrypt' }));
  await waitFor(() => expect(router.state.location.search).toMatchObject({ focus: 'ca:letsencrypt' }));
});

it('?edge opens the Link panel; selecting a node clears it; Escape clears it', async () => {
  setWidth(true);
  useFlow(() => detailed);
  const { user, router } = renderRoute('/o/acme/flow?edge=layout:nginx>client:web-1');
  const aside = await screen.findByRole('complementary', { name: 'Details' });
  expect(within(aside).getByText('Link')).toBeInTheDocument();
  expect(within(aside).getByRole('button', { name: 'nginx' })).toBeInTheDocument();
  expect(within(aside).getByRole('button', { name: 'web-1' })).toBeInTheDocument();
  expect(within(aside).getByRole('link', { name: 'Open www' })).toBeInTheDocument();
  await user.click(screen.getByRole('button', { name: /Certificate api/ }));
  await waitFor(() => expect(router.state.location.search).toMatchObject({ focus: 'certificate:api' }));
  expect(router.state.location.search).not.toHaveProperty('edge');
});

it('Escape clears an edge selection', async () => {
  setWidth(true);
  useFlow(() => detailed);
  const { user, router } = renderRoute('/o/acme/flow?edge=layout:nginx>client:web-1');
  await screen.findByRole('complementary', { name: 'Details' });
  screen.getByRole('button', { name: /Certificate api/ }).focus();
  await user.keyboard('{Escape}');
  await waitFor(() => expect(router.state.location.search).not.toHaveProperty('edge'));
});

it('an edge with a hidden end is dropped', async () => {
  setWidth(true);
  useFlow(() => detailed);
  const { router } = renderRoute('/o/acme/flow?edge=layout:nginx>client:nope');
  await screen.findByRole('button', { name: /Certificate www/ });
  await waitFor(() => expect(router.state.location.search).not.toHaveProperty('edge'));
});

it('the Links buttons in node mode switch to edge mode', async () => {
  setWidth(true);
  useFlow(() => detailed);
  const { user, router } = renderRoute('/o/acme/flow?focus=client:web-1');
  const aside = await screen.findByRole('complementary', { name: 'Details' });
  await user.click(within(aside).getByRole('button', { name: /^→ nginx/ }));
  await waitFor(() => expect(router.state.location.search).toMatchObject({ edge: 'layout:nginx>client:web-1' }));
  expect(router.state.location.search).not.toHaveProperty('focus');
});

it('clicking an edge hit path selects the edge and hovering shows the labelled chip', async () => {
  setWidth(true);
  useFlow(() => detailed);
  const { router, container } = renderRoute('/o/acme/flow');
  await screen.findByRole('button', { name: /Certificate www/ });
  await waitFor(() => expect(container.querySelector('[data-edge-hit="client:web-1|layout:nginx"]')).not.toBeNull());
  const hit = container.querySelector('[data-edge-hit="client:web-1|layout:nginx"]')!;
  fireEvent.pointerEnter(hit);
  expect(await screen.findByText(/^grant · /)).toBeInTheDocument();
  fireEvent.click(hit);
  await waitFor(() => expect(router.state.location.search).toMatchObject({ edge: 'layout:nginx>client:web-1' }));
});

const many = (n: number, extra: (i: number) => Partial<FlowNodeData> = () => ({})): Flow => ({
  ...base,
  lanes: { ...base.lanes, certificates: lane(Array.from({ length: n }, (_, i) => node('certificate', `c${i + 1}`, extra(i + 1)))) },
  edges: [],
});
const certNodes = () => within(screen.getByRole('region', { name: 'Certificates' })).getAllByRole('button', { name: /^Certificate / });

it('caps a lane at 12 with problems first, Show more reveals the rest and writes ?more', async () => {
  setWidth(true);
  useFlow(() => many(15, (i) => (i === 14 ? { status: 'failed' } : {})));
  const { user, router } = renderRoute('/o/acme/flow');
  await screen.findByRole('button', { name: /Certificate c1,/ });
  expect(certNodes()).toHaveLength(12);
  expect(screen.getByRole('button', { name: /Certificate c14,/ })).toBeInTheDocument();
  expect(screen.queryByRole('button', { name: /Certificate c13,/ })).toBeNull();
  const more = screen.getByRole('button', { name: 'Show 3 more' });
  expect(more).toHaveAttribute('aria-expanded', 'false');
  await user.click(more);
  await waitFor(() => expect(router.state.location.search).toMatchObject({ more: ['certificates'] }));
  expect(certNodes()).toHaveLength(15);
  await user.click(screen.getByRole('button', { name: 'Show fewer' }));
  await waitFor(() => expect(router.state.location.search).not.toHaveProperty('more'));
  expect(certNodes()).toHaveLength(12);
});

it('?more loads expanded, and a focused node past the cap is drawn without expanding', async () => {
  setWidth(true);
  useFlow(() => many(15));
  renderRoute('/o/acme/flow?more=%5B%22certificates%22%5D');
  await screen.findByRole('button', { name: /Certificate c15,/ });
  expect(certNodes()).toHaveLength(15);
});

it('draws a focused 14th node without expanding the lane', async () => {
  setWidth(true);
  useFlow(() => many(15));
  renderRoute('/o/acme/flow?focus=certificate:c14');
  await screen.findByRole('button', { name: /Certificate c14,/ });
  expect(certNodes()).toHaveLength(13);
  expect(screen.getByRole('button', { name: 'Show 2 more' })).toBeInTheDocument();
});

it('a lane with omitted nodes shows a per-lane notice linking to the list', async () => {
  setWidth(true);
  useFlow(() => ({ ...base, truncated: true, lanes: { ...base.lanes, issuers: { ...base.lanes.issuers, omitted: 5 } } }));
  renderRoute('/o/acme/flow');
  const issuers = await screen.findByRole('region', { name: 'Issuers' });
  expect(within(issuers).getByText(/\+5 not shown/)).toBeInTheDocument();
  expect(within(issuers).getByRole('link', { name: 'Open Issuers' })).toHaveAttribute('href', '/o/acme/issuers');
  expect(within(screen.getByRole('region', { name: 'Clients' })).queryByText(/not shown/)).toBeNull();
  expect(screen.queryByText('Truncated')).toBeNull();
});

it('narrow nodes show upstream and downstream link counts and no connectors', async () => {
  setWidth(false);
  useFlow(() => ({ ...base, lanes: { ...base.lanes, delivery: lane([node('layout', 'nginx'), node('layout', 'apache')]) }, edges: [...base.edges, e('certificate:www', 'layout:apache')] }));
  const { container } = renderRoute('/o/acme/flow');
  const www = await screen.findByRole('button', { name: /Certificate www/ });
  expect(within(www).getByLabelText('1 upstream, 2 downstream')).toHaveTextContent('↑1 ↓2');
  expect(container.querySelector('[data-flow-connectors]')).toBeNull();
});

it('lane headers are sticky', async () => {
  setWidth(true);
  useFlow(() => base);
  renderRoute('/o/acme/flow');
  const h = (await screen.findByRole('region', { name: 'Certificates' })).querySelector('h2')!;
  expect(h).toHaveClass('sticky', 'top-0');
});

it('a healthy node shows no status chip but names its status; a failed node shows the chip and a failed rail', async () => {
  setWidth(true);
  useFlow(() => ({ ...base, lanes: { ...base.lanes, certificates: lane([node('certificate', 'api'), node('certificate', 'bad', { status: 'failed' })]) } }));
  renderRoute('/o/acme/flow');
  const ok = await screen.findByRole('button', { name: 'Certificate api, Healthy' });
  expect(within(ok).queryByText('Healthy')).toBeNull();
  expect(ok.querySelector('.bg-valid')).not.toBeNull();
  const bad = screen.getByRole('button', { name: /Certificate bad, Failed/ });
  expect(within(bad).getByText('Failed')).toBeInTheDocument();
  expect(bad.querySelector('.bg-failed')).not.toBeNull();
});

it('a certificate card reads its expiry in the meta line', async () => {
  vi.useFakeTimers({ toFake: ['Date'] });
  vi.setSystemTime(new Date('2026-01-01T00:00:00Z'));
  try {
    setWidth(true);
    useFlow(() => ({ ...base, lanes: { ...base.lanes, certificates: lane([node('certificate', 'api', { summary: { expiresAt: '2026-01-13T00:00:00Z' } })]) } }));
    renderRoute('/o/acme/flow');
    const api = await screen.findByRole('button', { name: /Certificate api/ });
    expect(within(api).getByText('in 12 d')).toBeInTheDocument();
  } finally {
    vi.useRealTimers();
  }
});

it('the selected node is filled, and a lane header shows its count pill and problems in red', async () => {
  setWidth(true);
  useFlow(() => base);
  renderRoute('/o/acme/flow?focus=certificate:www');
  expect(await screen.findByRole('button', { name: /Certificate www/ })).toHaveClass('bg-selected', 'shadow-ctl');
  const certs = screen.getByRole('region', { name: 'Certificates' });
  expect(within(certs).getByText('2')).toHaveClass('bg-subtle');
  expect(within(certs).getByText('1 problem')).toHaveClass('text-failed');
});

it('a selected connection is drawn thick with an arrowhead', async () => {
  setWidth(true);
  useFlow(() => detailed);
  const { container } = renderRoute('/o/acme/flow?edge=layout:nginx>client:web-1');
  await screen.findByRole('complementary', { name: 'Details' });
  await waitFor(() => expect(container.querySelector('path[data-selected]')).not.toBeNull());
  const p = container.querySelector('path[data-selected]')!;
  expect(p).toHaveAttribute('stroke-width', '3');
  expect(p.getAttribute('marker-end')).toMatch(/^url\(#.*flow-arrow-/);
});

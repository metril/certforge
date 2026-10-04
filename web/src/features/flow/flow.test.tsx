import { http, HttpResponse } from 'msw';
import { screen, waitFor, within } from '@testing-library/react';
import { afterEach, beforeEach, expect, it } from 'vitest';
import { server } from '@/test/server';
import { authHandlers, problem, url } from '@/test/fixtures';
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
const lane = (nodes: FlowNodeData[], hidden = false) => ({ hidden, nodes });
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
beforeEach(() => server.use(...authHandlers({ authed: true })));
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
  await waitFor(() => expect(container.querySelectorAll('[data-flow-connectors] path').length).toBe(6));
  expect(screen.getByRole('link', { name: 'Flow' })).toBeInTheDocument();
});

it('selecting a node dims the rest, shows the path panel with Open links, and clears with Escape', async () => {
  setWidth(true);
  useFlow(() => base);
  const { user, router, container } = renderRoute('/o/acme/flow');
  const www = await screen.findByRole('button', { name: /Certificate www/ });
  await user.click(www);
  await waitFor(() => expect(router.state.location.search).toMatchObject({ focus: 'certificate:www' }));
  const panel = await screen.findByRole('region', { name: 'Path' });
  expect(within(panel).getByText('letsencrypt')).toBeInTheDocument();
  expect(within(panel).getByText('web-1')).toBeInTheDocument();
  expect(within(panel).queryByText('web-2')).toBeNull();
  expect(within(panel).getByRole('link', { name: 'Open letsencrypt' })).toHaveAttribute('href', '/o/acme/issuers/cas?edit=ca1');
  expect(screen.getByRole('button', { name: /Certificate api/ })).toHaveClass('opacity-40');
  expect(screen.getByRole('button', { name: /Client web-2/ })).toHaveClass('opacity-40');
  expect(screen.getByRole('button', { name: /Client web-1/ })).not.toHaveClass('opacity-40');
  expect(container.querySelectorAll('[data-dashed]').length).toBe(1);

  www.focus();
  await user.keyboard('{Escape}');
  await waitFor(() => expect(screen.queryByRole('region', { name: 'Path' })).toBeNull());
  expect(screen.getByRole('button', { name: /Certificate api/ })).not.toHaveClass('opacity-40');
});

it('Escape on a node clears the path even when an open tooltip already handled the key', async () => {
  setWidth(true);
  useFlow(() => base);
  renderRoute('/o/acme/flow?focus=certificate:www');
  await screen.findByRole('region', { name: 'Path' });
  const www = screen.getByRole('button', { name: /Certificate www/ });
  www.addEventListener('keydown', (ev) => ev.preventDefault());
  www.focus();
  const ev = new KeyboardEvent('keydown', { key: 'Escape', bubbles: true, cancelable: true });
  www.dispatchEvent(ev);
  expect(ev.defaultPrevented).toBe(true);
  await waitFor(() => expect(screen.queryByRole('region', { name: 'Path' })).toBeNull());
});

it('Escape inside the filter input does not clear the path selection', async () => {
  setWidth(true);
  useFlow(() => base);
  const { user } = renderRoute('/o/acme/flow?focus=certificate:www');
  await screen.findByRole('region', { name: 'Path' });
  await user.click(screen.getByRole('textbox', { name: 'Filter by name' }));
  await user.keyboard('{Escape}');
  expect(screen.getByRole('region', { name: 'Path' })).toBeInTheDocument();
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
  await waitFor(() => expect(screen.queryByRole('region', { name: 'Path' })).toBeNull());
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
  expect(screen.getByText('Truncated')).toBeInTheDocument();
});

it('shows Retry when the flow fetch fails', async () => {
  useFlow(() => problem(500, 'boom'));
  renderRoute('/o/acme/flow');
  expect(await screen.findByRole('button', { name: 'Retry' })).toBeInTheDocument();
});

it('narrow screens filter every lane to the selected path and offer a Clear button', async () => {
  setWidth(false);
  useFlow(() => base);
  const { user, container } = renderRoute('/o/acme/flow');
  const www = await screen.findByRole('button', { name: /Certificate www/ });
  expect(container.querySelector('[data-flow-connectors]')).toBeNull();
  expect(screen.getByRole('button', { name: /Certificate api/ })).toBeInTheDocument();
  await user.click(www);
  const panel = await screen.findByRole('region', { name: 'Path' });
  await waitFor(() => expect(screen.queryByRole('button', { name: /Certificate api/ })).toBeNull());
  expect(screen.queryByRole('button', { name: /Client web-2/ })).toBeNull();
  expect(screen.getByRole('button', { name: /Client web-1/ })).toBeInTheDocument();
  await user.click(within(panel).getByRole('button', { name: 'Clear' }));
  expect(await screen.findByRole('button', { name: /Certificate api/ })).toBeInTheDocument();
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
  await waitFor(() => expect(container.querySelectorAll('[data-flow-connectors] path').length).toBe(3));
  await user.click(screen.getByRole('button', { name: 'Clear filters' }));
  await waitFor(() => expect(router.state.location.search).not.toHaveProperty('q'));
  expect(await screen.findByRole('button', { name: /Client web-2/ })).toBeInTheDocument();
});

it('Problems keeps the unhealthy flow, and an empty result offers Clear filters', async () => {
  setWidth(true);
  useFlow(() => base);
  const { user, router } = renderRoute('/o/acme/flow');
  await screen.findByRole('button', { name: /Certificate www/ });
  await user.click(screen.getByRole('radio', { name: 'Problems' }));
  await waitFor(() => expect(router.state.location.search).toMatchObject({ status: 'problems' }));
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
  const head = within(certs).getByRole('button', { name: /Certificates/ });
  expect(head).toHaveAttribute('aria-expanded', 'true');
  expect(head).toHaveTextContent('1 problem');
  await user.click(head);
  await waitFor(() => expect(router.state.location.search).toMatchObject({ collapsed: ['certificates'] }));
  expect(head).toHaveAttribute('aria-expanded', 'false');
  expect(screen.queryByRole('button', { name: /Certificate www/ })).toBeNull();
  const proxy = within(certs).getByRole('button', { name: 'Expand Certificates, 2 items, Expiring' });
  expect(proxy).toHaveTextContent('2');
  // Both certificates merge into the proxy: proxy-ca, proxy-layout and the two layout-client edges.
  await waitFor(() => expect(container.querySelectorAll('[data-flow-connectors] path').length).toBe(4));
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
  const head = within(await screen.findByRole('region', { name: 'Alerts' })).getByRole('button', { name: /Alerts/ });
  expect(head).not.toHaveTextContent('problem');
});

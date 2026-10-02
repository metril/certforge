import { http, HttpResponse } from 'msw';
import { render, screen, waitFor, within } from '@testing-library/react';
import { toast } from 'sonner';
import { beforeEach, expect, it, vi } from 'vitest';
import type { Monitor, MonitorInput } from '@/api/types';
import { TooltipProvider } from '@/components/ui/tooltip';
import { server } from '@/test/server';
import { authHandlers, iso, makeCert, makeMonitor, meWith, NOW, org, problem, url } from '@/test/fixtures';
import { renderRoute } from '@/test/render';
import { ExpiryChip } from './ExpiryChip';

let monitors: Monitor[];
let posted: MonitorInput | undefined;
let patched: MonitorInput | undefined;
let checked: string | undefined;
let checkResult: Monitor | undefined;

// The desktop DataTable path (mirrors channels.test.tsx's own stub); without
// it jsdom's default matchMedia stub (matches: false) would render the
// below-`md` card list instead in every test here.
function stubViewport(isMdUp: boolean) {
  vi.stubGlobal('matchMedia', (query: string) => ({
    matches: query === '(min-width: 768px)' ? isMdUp : false,
    media: query,
    addEventListener: () => {},
    removeEventListener: () => {},
  }));
}

beforeEach(() => {
  stubViewport(true);
  monitors = [];
  posted = patched = undefined;
  checked = undefined;
  server.use(
    ...authHandlers({ authed: true }),
    http.get(url('/orgs/:orgId/monitors'), () => HttpResponse.json(monitors)),
    http.post(url('/orgs/:orgId/monitors'), async ({ request }) => {
      posted = (await request.json()) as MonitorInput;
      return HttpResponse.json(makeMonitor({ id: 'mon-new', ...posted }), { status: 201 });
    }),
    http.patch(url('/orgs/:orgId/monitors/:id'), async ({ request, params }) => {
      patched = (await request.json()) as MonitorInput;
      const existing = monitors.find((m) => m.id === params.id)!;
      const updated = { ...existing, ...patched };
      monitors = monitors.map((m) => (m.id === existing.id ? updated : m));
      return HttpResponse.json(updated);
    }),
    http.post(url('/orgs/:orgId/monitors/:id/check'), ({ params }) => {
      checked = params.id as string;
      const result = checkResult ?? monitors.find((m) => m.id === params.id)!;
      monitors = monitors.map((m) => (m.id === result.id ? result : m));
      return HttpResponse.json(result);
    }),
  );
});

it('lists monitors with state and fingerprint', async () => {
  monitors = [makeMonitor({ state: 'ok', lastFingerprint: 'ab'.repeat(32), nextCheckAt: iso(1) })];
  renderRoute('/o/acme/alerts/monitors');
  const table = await screen.findByRole('table', { name: 'Monitors' });
  expect(within(table).getByText('edge')).toBeInTheDocument();
  expect(within(table).getByText('edge.example.com:443')).toBeInTheDocument();
  expect(within(table).getByText('1 h')).toBeInTheDocument();
  expect(within(table).getByText('OK')).toBeInTheDocument();
  expect(within(table).getByText(`${'ab'.repeat(8)}…`)).toBeInTheDocument();
});

it('paused chip when disabled', async () => {
  monitors = [makeMonitor({ enabled: false, state: 'ok' })];
  renderRoute('/o/acme/alerts/monitors');
  const table = await screen.findByRole('table', { name: 'Monitors' });
  expect(within(table).getByText('Paused')).toBeInTheDocument();
  expect(within(table).queryByText('OK')).not.toBeInTheDocument();
});

it('interval segmented posts seconds', async () => {
  const { user } = renderRoute('/o/acme/alerts/monitors?edit=new');
  const sheet = await screen.findByRole('dialog', { name: 'New monitor' });
  await user.type(within(sheet).getByLabelText('Name'), 'edge');
  await user.type(within(sheet).getByLabelText('Host'), 'edge.example.com');
  await user.click(within(sheet).getByRole('radio', { name: '15 m' }));
  await user.click(within(sheet).getByRole('button', { name: 'Save' }));
  await waitFor(() => expect(posted).toBeDefined());
  expect(posted!.intervalSeconds).toBe(900);
});

it('non-preset interval kept', async () => {
  monitors = [makeMonitor({ intervalSeconds: 5400 })];
  const { user } = renderRoute('/o/acme/alerts/monitors?edit=mon-1');
  const sheet = await screen.findByRole('dialog', { name: 'edge' });
  expect(within(sheet).getByText('Currently 90 m')).toBeInTheDocument();
  await user.click(within(sheet).getByRole('button', { name: 'Save' }));
  await waitFor(() => expect(patched).toBeDefined());
  expect(patched!.intervalSeconds).toBe(5400);
});

it('expected certificate sends id or null', async () => {
  monitors = [makeMonitor({ expectedCertificateId: null, expectedCertificateName: null })];
  server.use(http.get(url('/orgs/:orgId/certificates'), () => HttpResponse.json({ items: [makeCert({ id: 'c-1', name: 'www' })], nextCursor: null })));
  const { user, router } = renderRoute('/o/acme/alerts/monitors?edit=mon-1');
  const sheet = await screen.findByRole('dialog', { name: 'edge' });
  await user.click(within(sheet).getByRole('button', { name: /^Advanced/ }));
  const combo = await within(sheet).findByRole('combobox', { name: 'Expected certificate' });
  await user.click(combo);
  await user.click(await screen.findByText('www'));
  await user.click(within(sheet).getByRole('button', { name: 'Save' }));
  await waitFor(() => expect(patched?.expectedCertificateId).toBe('c-1'));
  monitors = [{ ...monitors[0]!, expectedCertificateId: 'c-1', expectedCertificateName: 'www' }];

  await router.navigate({ to: '/o/$org/alerts/monitors', params: { org: 'acme' }, search: { edit: 'mon-1' } });
  const sheet2 = await screen.findByRole('dialog', { name: 'edge' });
  await user.click(within(sheet2).getByRole('button', { name: /^Advanced/ }));
  await user.click(within(sheet2).getByRole('combobox', { name: 'Expected certificate' }));
  await user.click(await screen.findByText('Any CertForge certificate'));
  await user.click(within(sheet2).getByRole('button', { name: 'Save' }));
  await waitFor(() => expect(patched?.expectedCertificateId).toBeNull());
});

it('check now updates row', async () => {
  monitors = [makeMonitor({ state: 'unknown' })];
  checkResult = makeMonitor({ state: 'ok', lastCheckedAt: iso(0) });
  const { user } = renderRoute('/o/acme/alerts/monitors');
  const table = await screen.findByRole('table', { name: 'Monitors' });
  expect(within(table).getByText('Unknown')).toBeInTheDocument();
  await user.click(within(table).getByRole('button', { name: 'Check edge now' }));
  await waitFor(() => expect(checked).toBe('mon-1'));
  expect(await within(table).findByText('OK')).toBeInTheDocument();
});

it('check now needs alerts:write', async () => {
  monitors = [makeMonitor()];
  server.use(http.get(url('/auth/me'), () => HttpResponse.json(meWith([{ role: 'viewer', orgId: org.id }]))));
  const { user } = renderRoute('/o/acme/alerts/monitors');
  const table = await screen.findByRole('table', { name: 'Monitors' });
  const btn = within(table).getByRole('button', { name: 'Check edge now' });
  expect(btn).toBeDisabled();
  await user.hover(btn);
  expect(await screen.findByRole('tooltip')).toHaveTextContent('Needs the alerts:write permission');
});

it('last check rows show issuer, expiry and error', async () => {
  monitors = [
    makeMonitor({
      state: 'unreachable',
      lastCheckedAt: iso(-1),
      lastFingerprint: 'ab'.repeat(32),
      lastIssuer: 'Let\'s Encrypt',
      lastNotAfter: iso(10),
      lastError: 'connection refused',
    }),
  ];
  renderRoute('/o/acme/alerts/monitors?edit=mon-1');
  const sheet = await screen.findByRole('dialog', { name: 'edge' });
  expect(within(sheet).getByText(/Let's Encrypt/)).toBeInTheDocument();
  expect(within(sheet).getByText('connection refused')).toBeInTheDocument();
  expect(within(sheet).getAllByText('Any CertForge certificate').length).toBeGreaterThan(0);
});

it('no last check block before first check', async () => {
  monitors = [makeMonitor({ lastCheckedAt: null })];
  renderRoute('/o/acme/alerts/monitors?edit=mon-1');
  const sheet = await screen.findByRole('dialog', { name: 'edge' });
  expect(within(sheet).queryByText('Last check')).not.toBeInTheDocument();
});

it('reset toast when target changes', async () => {
  // Asserts on the toast.success call directly (not the rendered DOM): sonner
  // keeps its toast list in a module-level singleton untouched by RTL's
  // cleanup(), so an identical message from an earlier test in this file can
  // still be on screen when this one renders its own Toaster, making a DOM
  // text query unreliable across tests.
  const success = vi.spyOn(toast, 'success');
  monitors = [makeMonitor({ host: 'edge.example.com' })];
  const { user } = renderRoute('/o/acme/alerts/monitors?edit=mon-1');
  const sheet = await screen.findByRole('dialog', { name: 'edge' });
  const host = within(sheet).getByLabelText('Host');
  await user.clear(host);
  await user.type(host, 'other.example.com');
  await user.click(within(sheet).getByRole('button', { name: 'Save' }));
  await waitFor(() => expect(patched).toBeDefined());
  await waitFor(() => expect(success).toHaveBeenCalledWith('Monitor saved; state resets to Unknown'));
  success.mockRestore();
});

it('limit 422 toasts', async () => {
  server.use(http.post(url('/orgs/:orgId/monitors'), () => problem(422, 'An organization can have at most 500 monitors.')));
  const { user } = renderRoute('/o/acme/alerts/monitors?edit=new');
  const sheet = await screen.findByRole('dialog', { name: 'New monitor' });
  await user.type(within(sheet).getByLabelText('Name'), 'edge');
  await user.type(within(sheet).getByLabelText('Host'), 'edge.example.com');
  await user.click(within(sheet).getByRole('button', { name: 'Save' }));
  expect(await screen.findByText('An organization can have at most 500 monitors.')).toBeInTheDocument();
});

// Batch 2 review: the original test asserted only the label — expiryTone's
// three branches (valid, expiring under EXPIRING_DAYS, expired at/past
// notAfter) went untested.
it.each([
  ['valid', iso(20), 'in 20 d', 'border-valid/40'],
  ['expiring', iso(9), 'in 9 d', 'border-expiring/60'],
  ['expired', iso(-1), '1 d ago', 'border-expired'],
] as const)('ExpiryChip: %s tone and relative days', (_tone, notAfter, label, toneClass) => {
  render(
    <TooltipProvider>
      <ExpiryChip notAfter={notAfter} now={NOW} />
    </TooltipProvider>,
  );
  const chip = screen.getByText(label);
  expect(chip).toBeInTheDocument();
  expect(chip).toHaveClass(toneClass);
});

// Batch 2 review: same class as ChannelCard's own batch 1 fix — the mobile
// monitor card's onKeyDown caught Enter/Space bubbling up from the nested
// Check now button (and the fingerprint CopyField), preventDefault'd, and
// opened the sheet instead — the button/field couldn't be used by keyboard
// below `md`.
it('card: check now works by keyboard without opening the sheet', async () => {
  stubViewport(false);
  monitors = [makeMonitor({ state: 'unknown' })];
  checkResult = makeMonitor({ state: 'ok', lastCheckedAt: iso(0) });
  const { user, router } = renderRoute('/o/acme/alerts/monitors');
  const btn = await screen.findByRole('button', { name: 'Check edge now' });
  btn.focus();
  await user.keyboard(' ');
  await waitFor(() => expect(checked).toBe('mon-1'));
  expect(router.state.location.search).toEqual({});
});

it('card: copy fingerprint works by keyboard without opening the sheet', async () => {
  stubViewport(false);
  monitors = [makeMonitor({ lastFingerprint: 'ab'.repeat(32) })];
  const { user, router } = renderRoute('/o/acme/alerts/monitors');
  const copyBtn = await screen.findByRole('button', { name: 'Copy fingerprint' });
  copyBtn.focus();
  await user.keyboard(' ');
  expect(await screen.findByText('Copied')).toBeInTheDocument();
  expect(router.state.location.search).toEqual({});
});

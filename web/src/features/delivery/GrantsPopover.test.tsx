import { http, HttpResponse } from 'msw';
import { screen, within } from '@testing-library/react';
import { expect, it, vi } from 'vitest';
import { server } from '@/test/server';
import { authHandlers, makeGrant, makeTarget, traefikSchema, url } from '@/test/fixtures';
import { renderRoute } from '@/test/render';

it('opens a click popover of the target grants, each linking to its grant', async () => {
  vi.stubGlobal('matchMedia', (query: string) => ({ matches: query === '(min-width: 768px)', media: query, addEventListener: () => {}, removeEventListener: () => {} }));
  let query = '';
  server.use(
    ...authHandlers({ authed: true }),
    http.get(url('/meta/schemas'), () => HttpResponse.json({ dnsProviders: [], deployTargets: [traefikSchema], notifiers: [], signers: [] })),
    http.get(url('/orgs/org-1/deploy-targets'), () => HttpResponse.json({ items: [makeTarget({ grantCount: 2 })] })),
    http.get(url('/orgs/org-1/grants'), ({ request }) => {
      query = new URL(request.url).search;
      return HttpResponse.json({
        items: [
          makeGrant({ id: 'g-a', certificateName: 'www', clientName: 'web-1', layoutName: 'nginx' }),
          makeGrant({ id: 'g-s', certificateName: 'api', clientId: null, clientName: null, runsOn: 'server', deployTargetId: 't-9', deployTargetName: 'vault', layoutId: null }),
        ],
      });
    }),
  );
  const { user } = renderRoute('/o/acme/delivery/targets');
  await user.click(await screen.findByRole('button', { name: '2 grants' }));
  const agent = (await screen.findByText('agent · web-1 · nginx')).closest('a')!;
  expect(agent).toHaveAttribute('href', '/o/acme/clients/cl-1/certificates?open=g-a');
  expect(within(screen.getByText('server · vault').closest('a')!).getByText('api')).toBeInTheDocument();
  expect(screen.getByText('server · vault').closest('a')).toHaveAttribute('href', '/o/acme/delivery/targets/t-9/grants?open=g-s');
  expect(new URLSearchParams(query).get('deployTargetId')).toBe('t-1');
});

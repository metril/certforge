import { http, HttpResponse } from 'msw';
import { screen, waitFor } from '@testing-library/react';
import { expect, it } from 'vitest';
import { server } from '@/test/server';
import { authHandlers, metaSigners, presets, url } from '@/test/fixtures';
import { renderRoute } from '@/test/render';

// W10: rjsf fills defaults through onChange on mount; a pristine create sheet
// for a form-driven CA kind must not report dirty (Escape closes at once).
it.each(['localca', 'vaultpki'] as const)('a pristine %s create sheet closes without a discard prompt', async (kind) => {
  server.use(
    ...authHandlers({ authed: true }),
    http.get(url('/meta/schemas'), () => HttpResponse.json({ dnsProviders: [], deployTargets: [], notifiers: [], signers: metaSigners })),
    http.get(url('/meta/ca-presets'), () => HttpResponse.json(presets)),
    http.get(url('/orgs/org-1/cas'), () => HttpResponse.json([])),
  );
  const { user, router } = renderRoute(`/o/acme/issuers/cas?edit=new&kind=${kind}`);
  await screen.findByText('Add certificate authority');
  await new Promise((r) => setTimeout(r, 300));
  (document.activeElement as HTMLElement | null)?.blur();
  await user.keyboard('{Escape}');
  await waitFor(() => expect(router.state.location.search).not.toHaveProperty('edit'));
  expect(screen.queryByText('Discard changes?')).not.toBeInTheDocument();
});

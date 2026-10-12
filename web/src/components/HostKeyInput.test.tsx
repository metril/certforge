import { useState } from 'react';
import { http, HttpResponse } from 'msw';
import { screen, waitFor, within } from '@testing-library/react';
import type { RJSFSchema } from '@rjsf/utils';
import { expect, it } from 'vitest';
import type { SshPeekRequest } from '@/api/types';
import { SchemaForm } from '@/forms/SchemaForm';
import type { HostKeyScope } from './HostKeyInput';
import { url } from '@/test/fixtures';
import { renderUI } from '@/test/render';
import { server } from '@/test/server';

const schema = {
  type: 'object',
  properties: {
    host: { type: 'string', title: 'Host' },
    port: { type: 'integer', title: 'Port' },
    hostKey: { type: 'string', format: 'ssh-host-key', title: 'Host key' },
  },
} as RJSFSchema;

const full: HostKeyScope = { orgId: 'org-1', canPeek: true };
const ED = 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIED';
const RSA = 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABRSA';

function Harness({ scope, initial = {} }: { scope?: HostKeyScope | null; initial?: Record<string, unknown> }) {
  const [v, setV] = useState<Record<string, unknown>>(initial);
  return (
    <>
      <SchemaForm schema={schema} value={v} onChange={setV} formContext={scope === null ? {} : { sshHostKey: scope ?? full }} />
      <output data-testid="value">{String(v.hostKey ?? '')}</output>
    </>
  );
}

const value = () => screen.getByTestId('value').textContent;

it('accepts a pasted key', async () => {
  const { user } = renderUI(<Harness />);
  await user.click(screen.getByRole('textbox', { name: /Host key/ }));
  await user.paste(ED);
  expect(value()).toBe(ED);
});

it('prefills host and port, fetches, and fills the input with the chosen key', async () => {
  let sent: SshPeekRequest | undefined;
  server.use(
    http.post(url('/orgs/org-1/ssh/peek'), async ({ request }) => {
      sent = (await request.json()) as SshPeekRequest;
      return HttpResponse.json({ ok: true, keys: [{ type: 'ssh-rsa', key: RSA, sha256: 'SHA256:rsafp' }, { type: 'ssh-ed25519', key: ED, sha256: 'SHA256:edfp' }] });
    }),
  );
  const { user } = renderUI(<Harness initial={{ host: 'router.lan', port: 2222 }} />);
  await user.click(screen.getByRole('button', { name: 'Fetch from server' }));
  const dialog = await screen.findByRole('dialog', { name: /Fetch from server/ });
  expect(within(dialog).getByRole('textbox', { name: 'Host' })).toHaveValue('router.lan');
  expect(within(dialog).getByRole('textbox', { name: 'Port' })).toHaveValue('2222');
  await user.click(within(dialog).getByRole('button', { name: 'Fetch' }));
  const ed = await within(dialog).findByRole('radio', { name: /ssh-ed25519/ });
  expect(sent).toEqual({ host: 'router.lan', port: 2222 });
  expect(within(dialog).getByText('SHA256:edfp')).toBeInTheDocument();
  expect(ed).toHaveAttribute('aria-checked', 'true');
  await user.click(within(dialog).getByRole('radio', { name: /ssh-rsa/ }));
  await user.click(within(dialog).getByRole('button', { name: 'Use key' }));
  await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument());
  expect(value()).toBe(RSA);
});

it('shows a failed peek inline', async () => {
  server.use(http.post(url('/orgs/org-1/ssh/peek'), () => HttpResponse.json({ ok: false, error: 'connection refused', keys: [] })));
  const { user } = renderUI(<Harness initial={{ host: 'router.lan' }} />);
  await user.click(screen.getByRole('button', { name: 'Fetch from server' }));
  const dialog = await screen.findByRole('dialog');
  await user.click(within(dialog).getByRole('button', { name: 'Fetch' }));
  expect(await within(dialog).findByRole('alert')).toHaveTextContent('connection refused');
  expect(within(dialog).getByRole('button', { name: 'Use key' })).toBeDisabled();
});

it('offers no Fetch without a scope', () => {
  renderUI(<Harness scope={null} />);
  expect(screen.queryByRole('button', { name: 'Fetch from server' })).not.toBeInTheDocument();
});

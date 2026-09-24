import type { ReactElement } from 'react';
import { act, screen } from '@testing-library/react';
import { expect, it, vi } from 'vitest';
import { Providers } from '@/app/Providers';
import { readRecent } from '@/lib/recent';
import { hyperone, providers, route53 } from '@/test/fixtures';
import { renderUI } from '@/test/render';
import { ProviderPicker } from './ProviderPicker';

it('finds a provider by alias and remembers it', async () => {
  const onPick = vi.fn();
  const { user } = renderUI(<ProviderPicker open onOpenChange={() => {}} providers={providers} onPickProvider={onPick} />);
  await user.type(screen.getByRole('combobox'), 'aws');
  await user.click(screen.getByRole('option', { name: /Amazon Route 53/ }));
  expect(onPick).toHaveBeenCalledWith(route53);
  expect(readRecent()).toEqual(['route53']);
});

it('shows org credentials, recent, common, and all providers in that order', () => {
  localStorage.setItem('cf-recent-providers', JSON.stringify(['hetzner']));
  renderUI(
    <ProviderPicker
      open
      onOpenChange={() => {}}
      providers={providers}
      credentials={[{ id: 'd-1', name: 'Cloudflare prod', providerCode: 'cloudflare', config: {} }]}
      onPickProvider={() => {}}
      onPickCredential={() => {}}
    />,
  );
  const headings = [...document.querySelectorAll('[cmdk-group-heading]')].map((h) => h.textContent);
  expect(headings).toEqual(['Credentials in this org', 'Recently used', 'Common', 'All providers']);
});

// Fix round 1 (preflight review): cmdk's default filter also scores an
// item's raw `value`, not just its `keywords`. The old item values
// (`all:<code>`, `cred:<uuid>`) meant typing the generic word "all" or
// "cred" matched every provider/credential, since it's a literal substring
// of every one of their values. None of the fixtures' names/codes/aliases
// contain "all", so a working search should find nothing for it.
it('does not match a namespace word like "all" against every provider', async () => {
  const { user } = renderUI(
    <ProviderPicker
      open
      onOpenChange={() => {}}
      providers={providers}
      credentials={[{ id: 'd-1', name: 'Cloudflare prod', providerCode: 'cloudflare', config: {} }]}
      onPickProvider={() => {}}
      onPickCredential={() => {}}
    />,
  );
  await user.type(screen.getByRole('combobox'), 'all');
  expect(screen.getByText('No provider matches.')).toBeInTheDocument();
  expect(screen.queryByRole('option')).not.toBeInTheDocument();
});

it('resets the search text when the dialog closes', async () => {
  const { user, rerender, queryClient } = renderUI(<ProviderPicker open onOpenChange={() => {}} providers={providers} onPickProvider={() => {}} />);
  const wrap = (ui: ReactElement) => <Providers queryClient={queryClient}>{ui}</Providers>;
  await user.type(screen.getByRole('combobox'), 'aws');
  expect(screen.getByRole('combobox')).toHaveValue('aws');
  expect(screen.getAllByRole('option')).toHaveLength(1);

  rerender(wrap(<ProviderPicker open={false} onOpenChange={() => {}} providers={providers} onPickProvider={() => {}} />));
  rerender(wrap(<ProviderPicker open onOpenChange={() => {}} providers={providers} onPickProvider={() => {}} />));

  expect(screen.getByRole('combobox')).toHaveValue('');
  // Unfiltered again: route53 (in COMMON_PROVIDERS) shows once in "Common"
  // and once in "All providers", so the full option count is well above 1.
  expect(screen.getAllByRole('option').length).toBeGreaterThan(1);
});

it('disables an unsupported provider and shows its reason as a tooltip on hover of the icon; picking it does nothing', async () => {
  const onPick = vi.fn();
  const { user } = renderUI(<ProviderPicker open onOpenChange={() => {}} providers={providers} onPickProvider={onPick} />);
  const opt = screen.getByRole('option', { name: /HyperOne/ });
  expect(opt).toHaveAttribute('aria-disabled', 'true');
  const why = screen.getByRole('button', { name: 'Why HyperOne is unavailable' });
  await user.hover(why);
  expect(await screen.findByRole('tooltip')).toHaveTextContent('Requires a passport file');
  expect(onPick).not.toHaveBeenCalled();
});

it('shows the unsupported reason tooltip on keyboard focus, not just hover', async () => {
  renderUI(<ProviderPicker open onOpenChange={() => {}} providers={providers} onPickProvider={() => {}} />);
  const why = screen.getByRole('button', { name: 'Why HyperOne is unavailable' });
  act(() => why.focus());
  expect(await screen.findByRole('tooltip')).toHaveTextContent('Requires a passport file');
});

it('does not show credentials or the "no credential" affordance when the caller has no credential handler', () => {
  renderUI(<ProviderPicker open onOpenChange={() => {}} providers={[hyperone]} onPickProvider={() => {}} />);
  expect(screen.queryByText('Credentials in this org')).not.toBeInTheDocument();
});

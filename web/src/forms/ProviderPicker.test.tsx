import { screen } from '@testing-library/react';
import { expect, it, vi } from 'vitest';
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

it('disables an unsupported provider and shows its reason as a tooltip; picking it does nothing', async () => {
  const onPick = vi.fn();
  const { user } = renderUI(<ProviderPicker open onOpenChange={() => {}} providers={providers} onPickProvider={onPick} />);
  const opt = screen.getByRole('option', { name: /HyperOne/ });
  expect(opt).toHaveAttribute('aria-disabled', 'true');
  await user.hover(opt);
  expect(await screen.findByRole('tooltip')).toHaveTextContent('Requires a passport file');
  expect(onPick).not.toHaveBeenCalled();
});

it('does not show credentials or the "no credential" affordance when the caller has no credential handler', () => {
  renderUI(<ProviderPicker open onOpenChange={() => {}} providers={[hyperone]} onPickProvider={() => {}} />);
  expect(screen.queryByText('Credentials in this org')).not.toBeInTheDocument();
});

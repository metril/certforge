import { screen, within } from '@testing-library/react';
import { expect, it, vi } from 'vitest';
import { renderUI } from '@/test/render';
import { Card } from './Card';
import { FormSection } from './FormSection';
import { PageHeader } from './PageHeader';
import { PrimaryCell } from './PrimaryCell';

it('PageHeader renders title, help, actions, tabs nav and filters', () => {
  renderUI(
    <PageHeader title="Hooks" help="hook.phase" actions={<button>New</button>} tabs={<a href="#a">A</a>} tabsLabel="Delivery" filters={<input aria-label="Search" />} />,
  );
  expect(screen.getByRole('heading', { name: /Hooks/ })).toBeInTheDocument();
  expect(screen.getByRole('button', { name: 'Help' })).toBeInTheDocument();
  expect(within(screen.getByRole('navigation', { name: 'Delivery' })).getByRole('link', { name: 'A' })).toBeInTheDocument();
});

it('PageHeader collapses filters into a Filters popover with a count below md', async () => {
  const { user } = renderUI(<PageHeader title="X" filters={<input aria-label="Search" />} activeFilters={2} />);
  expect(screen.queryByLabelText('Search')).not.toBeInTheDocument();
  await user.click(screen.getByRole('button', { name: /Filters/ }));
  expect(screen.getByText('2')).toBeInTheDocument();
  expect(await screen.findByLabelText('Search')).toBeInTheDocument();
});

it('PrimaryCell joins meta parts, dropping empty ones', () => {
  renderUI(<PrimaryCell primary="reload" meta={['Post-deploy', null, '60 s', false]} />);
  expect(screen.getByText('reload')).toBeInTheDocument();
  expect(screen.getByText('Post-deploy · 60 s')).toBeInTheDocument();
});

it('FormSection collapsible is closed by default, opens by keyboard and shows a count', async () => {
  const { user } = renderUI(
    <FormSection title="Advanced" collapsible count={2}>
      <input aria-label="Inner" />
    </FormSection>,
  );
  const trigger = screen.getByRole('button', { name: /Advanced/ });
  expect(trigger).toHaveAttribute('aria-expanded', 'false');
  expect(screen.getByLabelText('2 changed')).toBeInTheDocument();
  expect(screen.queryByLabelText('Inner')).not.toBeInTheDocument();
  trigger.focus();
  await user.keyboard('{Enter}');
  expect(screen.getByLabelText('Inner')).toBeInTheDocument();
});

it('FormSection supports defaultOpen, summary and the static variant', () => {
  renderUI(
    <>
      <FormSection title="Open" collapsible defaultOpen summary="1 overridden">
        <input aria-label="A" />
      </FormSection>
      <FormSection title="Plain">
        <input aria-label="B" />
      </FormSection>
    </>,
  );
  expect(screen.getByLabelText('A')).toBeInTheDocument();
  expect(screen.getByText('1 overridden')).toBeInTheDocument();
  expect(within(screen.getByRole('region', { name: 'Plain' })).getByLabelText('B')).toBeInTheDocument();
});

it('FormSection is a Card at top level and keeps the hairline look nested in a Card', () => {
  renderUI(
    <>
      <FormSection title="Top">
        <p>a</p>
      </FormSection>
      <Card>
        <FormSection title="Nested">
          <p>b</p>
        </FormSection>
      </Card>
    </>,
  );
  const top = screen.getByRole('region', { name: 'Top' });
  expect(top.className).toContain('bg-panel');
  expect(top.querySelector('[data-slot="card-header"]')).toHaveTextContent('Top');
  const nested = screen.getByRole('region', { name: 'Nested' });
  expect(nested.className).toContain('border-t');
  expect(nested.className).not.toContain('bg-panel');
});

it('PageHeader shows a labelled filter toolbar at md and up, with Clear filters and no chips', async () => {
  vi.stubGlobal('matchMedia', (query: string) => ({ matches: query === '(min-width: 768px)', media: query, addEventListener: () => {}, removeEventListener: () => {} }));
  const onClear = vi.fn();
  const { user } = renderUI(
    <PageHeader title="X" tabs={<a href="#a">A</a>} filters={<input aria-label="Search" />} activeFilters={1} onClearFilters={onClear} filterChips={<span>CHIP</span>} />,
  );
  expect(within(screen.getByRole('search', { name: 'Filters' })).getByLabelText('Search')).toBeInTheDocument();
  expect(screen.queryByText('CHIP')).not.toBeInTheDocument();
  await user.click(screen.getByRole('button', { name: 'Clear filters' }));
  expect(onClear).toHaveBeenCalled();
  vi.unstubAllGlobals();
});

it('PageHeader keeps chips inside the mobile Filters popover', async () => {
  const { user } = renderUI(<PageHeader title="X" filters={<input aria-label="Search" />} filterChips={<span>CHIP</span>} />);
  await user.click(screen.getByRole('button', { name: /Filters/ }));
  expect(await screen.findByText('CHIP')).toBeInTheDocument();
});

it('PageHeader lets the mobile Filters popover clear active filters', async () => {
  const onClear = vi.fn();
  const { user } = renderUI(<PageHeader title="X" filters={<input aria-label="Search" />} activeFilters={2} onClearFilters={onClear} />);
  await user.click(screen.getByRole('button', { name: /Filters/ }));
  await user.click(await screen.findByRole('button', { name: 'Clear filters' }));
  expect(onClear).toHaveBeenCalledTimes(1);
});

it('PageHeader omits the popover Clear filters button when chips already offer Clear all', async () => {
  const { user } = renderUI(<PageHeader title="X" filters={<input aria-label="Search" />} activeFilters={1} onClearFilters={vi.fn()} filterChips={<span>CHIP</span>} />);
  await user.click(screen.getByRole('button', { name: /Filters/ }));
  await screen.findByText('CHIP');
  expect(screen.queryByRole('button', { name: 'Clear filters' })).not.toBeInTheDocument();
});

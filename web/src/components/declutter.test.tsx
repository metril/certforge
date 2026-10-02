import { screen, within } from '@testing-library/react';
import { expect, it } from 'vitest';
import { renderUI } from '@/test/render';
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

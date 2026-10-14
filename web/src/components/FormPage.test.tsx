import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { createMemoryHistory, createRootRoute, createRoute, createRouter, Link, RouterProvider } from '@tanstack/react-router';
import { expect, it } from 'vitest';
import { FormPage } from './FormPage';
import { TooltipProvider } from '@/components/ui/tooltip';

function setup(dirty: boolean) {
  const bypass = { current: false };
  const root = createRootRoute();
  const form = createRoute({
    getParentRoute: () => root,
    path: '/form',
    component: () => (
      <FormPage title="Edit thing" backTo={{ label: 'Things', link: { to: '/list' as never } }} actions={<button>Save</button>} rail={<p>Rail text</p>} dirty={dirty} bypass={bypass}>
        <p>Body</p>
        <Link to={'/list' as never}>Leave</Link>
      </FormPage>
    ),
  });
  const list = createRoute({ getParentRoute: () => root, path: '/list', component: () => <p>List page</p> });
  const router = createRouter({ routeTree: root.addChildren([form, list]), history: createMemoryHistory({ initialEntries: ['/form'] }) });
  render(
    <TooltipProvider>
      <RouterProvider router={router} />
    </TooltipProvider>,
  );
  return { router, user: userEvent.setup(), bypass };
}

it('renders title, breadcrumb, actions, body and rail', async () => {
  setup(false);
  expect(await screen.findByRole('heading', { name: 'Edit thing' })).toBeInTheDocument();
  expect(screen.getByRole('link', { name: 'Things' })).toHaveAttribute('href', '/list');
  expect(screen.getByRole('button', { name: 'Save' })).toBeInTheDocument();
  expect(screen.getByText('Body')).toBeInTheDocument();
  expect(screen.getByText('Rail text')).toBeInTheDocument();
});

it('lets a clean page navigate away', async () => {
  const { user } = setup(false);
  await user.click(await screen.findByRole('link', { name: 'Leave' }));
  expect(await screen.findByText('List page')).toBeInTheDocument();
});

it('asks before leaving a dirty page; Cancel stays, Discard leaves', async () => {
  const { user } = setup(true);
  await user.click(await screen.findByRole('link', { name: 'Leave' }));
  expect(await screen.findByText('Discard changes?')).toBeInTheDocument();
  await user.click(screen.getByRole('button', { name: 'Cancel' }));
  expect(screen.getByText('Body')).toBeInTheDocument();
  await user.click(screen.getByRole('link', { name: 'Leave' }));
  await user.click(await screen.findByRole('button', { name: 'Discard' }));
  expect(await screen.findByText('List page')).toBeInTheDocument();
});

it('skips the guard when bypass is set', async () => {
  const { user, bypass } = setup(true);
  bypass.current = true;
  await user.click(await screen.findByRole('link', { name: 'Leave' }));
  expect(await screen.findByText('List page')).toBeInTheDocument();
});

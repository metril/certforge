import { useState } from 'react';
import { act, render, screen } from '@testing-library/react';
import { QueryClientProvider } from '@tanstack/react-query';
import {
  createBrowserHistory,
  createRootRoute,
  createRoute,
  createRouter,
  Link,
  RouterProvider,
  useNavigate,
  useSearch,
} from '@tanstack/react-router';
import { makeQueryClient } from '@/lib/queryClient';
import userEvent from '@testing-library/user-event';
import { describe, expect, it, vi } from 'vitest';
import { TooltipProvider } from './tooltip';
import { Sheet, SheetBody, SheetContent, SheetDescription, SheetFooter, SheetHeader, SheetTitle, useSheetGuard } from './sheet';

function Harness({ form, dirty }: { form?: boolean; dirty?: boolean }) {
  const [open, setOpen] = useState(true);
  return (
    <div>
      <button>outside</button>
      <Sheet open={open} form={form} dirty={dirty} onOpenChange={setOpen}>
        <SheetContent>
          <SheetHeader>
            <SheetTitle>Panel</SheetTitle>
            <SheetDescription>desc</SheetDescription>
          </SheetHeader>
        </SheetContent>
      </Sheet>
    </div>
  );
}

describe('Sheet guard', () => {
  it('form sheet ignores outside clicks', async () => {
    const user = userEvent.setup({ pointerEventsCheck: 0 });
    render(<TooltipProvider><Harness form /></TooltipProvider>);
    await user.click(document.body);
    expect(screen.getByText('Panel')).toBeInTheDocument();
  });

  it('read-only sheet still closes on outside click', async () => {
    const user = userEvent.setup({ pointerEventsCheck: 0 });
    render(<TooltipProvider><Harness /></TooltipProvider>);
    await user.click(document.body);
    expect(screen.queryByText('Panel')).not.toBeInTheDocument();
  });

  it('clean form closes on Escape', async () => {
    const user = userEvent.setup();
    render(<TooltipProvider><Harness form dirty={false} /></TooltipProvider>);
    await user.keyboard('{Escape}');
    expect(screen.queryByText('Panel')).not.toBeInTheDocument();
  });

  it('dirty form prompts; Cancel keeps it open', async () => {
    const user = userEvent.setup();
    render(<TooltipProvider><Harness form dirty /></TooltipProvider>);
    await user.keyboard('{Escape}');
    expect(screen.getByText('Discard changes?')).toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: 'Cancel' }));
    expect(screen.queryByText('Discard changes?')).not.toBeInTheDocument();
    expect(screen.getByText('Panel')).toBeInTheDocument();
  });

  it('dirty form closes on Discard', async () => {
    const user = userEvent.setup();
    render(<TooltipProvider><Harness form dirty /></TooltipProvider>);
    await user.click(screen.getByRole('button', { name: 'Close' }));
    await user.click(screen.getByRole('button', { name: 'Discard' }));
    expect(screen.queryByText('Panel')).not.toBeInTheDocument();
  });
});

function NavHarness({ form, dirty }: { form: boolean; dirty: boolean }) {
  const navigate = useNavigate() as unknown as (o: { to: string; search: object }) => void;
  const search = useSearch({ strict: false }) as { edit?: string };
  const close = () => navigate({ to: '/list', search: {} });
  const guard = useSheetGuard((o) => !o && close());
  return (
    <div>
      <Link to={'/other' as string}>other</Link>
      <button onClick={() => navigate({ to: '/list', search: { edit: 'a', tab: 'x' } })}>same-sheet</button>
      <Sheet guard={guard} open={search.edit !== undefined} form={form} dirty={dirty} onOpenChange={(o) => !o && close()}>
        <SheetContent>
          <SheetHeader>
            <SheetTitle>Panel</SheetTitle>
            <SheetDescription>desc</SheetDescription>
          </SheetHeader>
          <button onClick={async () => { await Promise.resolve(); guard.close(); }}>Save</button>
        </SheetContent>
      </Sheet>
    </div>
  );
}

async function mountNav(form: boolean, dirty: boolean) {
  const root = createRootRoute();
  const list = createRoute({
    getParentRoute: () => root,
    path: '/list',
    validateSearch: (s: Record<string, unknown>) => ({
      edit: typeof s.edit === 'string' ? s.edit : undefined,
      tab: typeof s.tab === 'string' ? s.tab : undefined,
    }),
    component: () => <NavHarness form={form} dirty={dirty} />,
  });
  const other = createRoute({ getParentRoute: () => root, path: '/other', component: () => <div>other page</div> });
  // Memory history only blocks push/replace; Back/Forward need the popstate path.
  window.history.pushState({ __TSR_index: 0, key: 'k0' }, '', '/list');
  window.history.pushState({ __TSR_index: 1, key: 'k1' }, '', '/list?edit=a');
  const history = createBrowserHistory();
  const router = createRouter({ routeTree: root.addChildren([list, other]), history });
  const queryClient = makeQueryClient({ test: true });
  render(
    <QueryClientProvider client={queryClient}>
      <TooltipProvider>
      <RouterProvider router={router} />
      </TooltipProvider>
    </QueryClientProvider>,
  );
  await screen.findByText('Panel');
  return { router, user: userEvent.setup({ pointerEventsCheck: 0 }) };
}

describe('Sheet navigation guard', () => {
  it('dirty form: Back prompts; Cancel keeps sheet and URL; Discard navigates', async () => {
    const { router, user } = await mountNav(true, true);
    act(() => window.history.back());
    expect(await screen.findByText('Discard changes?')).toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: 'Cancel' }));
    expect(screen.queryByText('Discard changes?')).not.toBeInTheDocument();
    expect(screen.getByText('Panel')).toBeInTheDocument();
    expect(router.history.location.search).toContain('edit=a');
    await vi.waitFor(() => expect(window.location.search).toContain('edit=a'));
    act(() => window.history.back());
    await user.click(await screen.findByRole('button', { name: 'Discard' }));
    await vi.waitFor(() => expect(screen.queryByText('Panel')).not.toBeInTheDocument());
    expect(router.history.location.search).not.toContain('edit');
  });

  it('dirty form: link click prompts; Escape while prompting never stacks a second dialog', async () => {
    const { user } = await mountNav(true, true);
    await user.click(screen.getByText('other'));
    expect(await screen.findByText('Discard changes?')).toBeInTheDocument();
    await user.keyboard('{Escape}');
    expect(screen.queryAllByText('Discard changes?')).toHaveLength(0);
    expect(screen.getByText('Panel')).toBeInTheDocument();
  });

  it('dirty form: a save closes without a prompt', async () => {
    const { user } = await mountNav(true, true);
    await user.click(screen.getByRole('button', { name: 'Save' }));
    await vi.waitFor(() => expect(screen.queryByText('Panel')).not.toBeInTheDocument());
    expect(screen.queryByText('Discard changes?')).not.toBeInTheDocument();
  });

  it('dirty form: changing search while keeping the sheet open is not blocked', async () => {
    const { router, user } = await mountNav(true, true);
    await user.click(screen.getByText('same-sheet'));
    await vi.waitFor(() => expect(router.history.location.search).toContain('tab=x'));
    expect(screen.queryByText('Discard changes?')).not.toBeInTheDocument();
  });

  it('clean form: Back is not prompted', async () => {
    await mountNav(true, false);
    act(() => window.history.back());
    await vi.waitFor(() => expect(screen.queryByText('Panel')).not.toBeInTheDocument());
    expect(screen.queryByText('Discard changes?')).not.toBeInTheDocument();
  });

  it('read-only sheet: Back is not prompted', async () => {
    await mountNav(false, true);
    act(() => window.history.back());
    await vi.waitFor(() => expect(screen.queryByText('Panel')).not.toBeInTheDocument());
    expect(screen.queryByText('Discard changes?')).not.toBeInTheDocument();
  });
});

describe('Sheet layout', () => {
  function Layout({ size }: { size?: 'sm' | 'md' | 'lg' | 'xl' }) {
    return (
      <Sheet open>
        <SheetContent size={size}>
          <SheetHeader>
            <SheetTitle>Panel</SheetTitle>
            <SheetDescription>desc</SheetDescription>
          </SheetHeader>
          <SheetBody>body</SheetBody>
          <SheetFooter>foot</SheetFooter>
        </SheetContent>
      </Sheet>
    );
  }
  const q = (slot: string) => document.querySelector(`[data-slot="${slot}"]`) as HTMLElement;

  it('only the body scrolls and the footer is its sibling', () => {
    render(
      <TooltipProvider>
        <Layout />
      </TooltipProvider>,
    );
    expect(q('sheet-body').className).toContain('overflow-y-auto');
    expect(q('sheet-content').className).not.toContain('overflow-y-auto');
    expect(q('sheet-footer').parentElement).toBe(q('sheet-content'));
    expect(q('sheet-body').contains(q('sheet-footer'))).toBe(false);
  });

  it.each([
    [undefined, 'sm:max-w-lg'],
    ['sm', 'sm:max-w-md'],
    ['md', 'sm:max-w-lg'],
    ['lg', 'sm:max-w-2xl'],
    ['xl', 'sm:max-w-3xl'],
  ] as const)('size %s maps to %s', (size, cls) => {
    render(
      <TooltipProvider>
        <Layout size={size} />
      </TooltipProvider>,
    );
    expect(q('sheet-content').className).toContain(cls);
  });
});

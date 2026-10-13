import { http, HttpResponse } from 'msw';
import { screen, waitFor, within } from '@testing-library/react';
import { expect, it, vi } from 'vitest';
import { server } from '@/test/server';
import { authHandlers, makeAction, makeActionGroup, url } from '@/test/fixtures';
import { renderUI } from '@/test/render';
import { useState } from 'react';
import type { GrantStep } from '@/api/types';
import { StepsPicker } from './StepsPicker';

function Harness({ runsOn, initial = [], spy }: { runsOn: 'agent' | 'server'; initial?: GrantStep[]; spy?: (v: GrantStep[]) => void }) {
  const [v, setV] = useState(initial);
  return (
    <StepsPicker
      orgId="org-1"
      runsOn={runsOn}
      value={v}
      newActionHref="/o/acme/delivery/actions?edit=new"
      onChange={(n) => {
        spy?.(n);
        setV(n);
      }}
    />
  );
}

function setup() {
  server.use(
    ...authHandlers({ authed: true }),
    http.get(url('/orgs/org-1/actions'), () =>
      HttpResponse.json({
        items: [
          makeAction(),
          makeAction({ id: 'a-2', name: 'notify', phase: 'pre_deploy' }),
          makeAction({ id: 'a-3', name: 'ssh reload', kind: 'ssh', runsOn: 'server' }),
        ],
      }),
    ),
    http.get(url('/orgs/org-1/action-groups'), () => HttpResponse.json({ items: [makeActionGroup()] })),
  );
}

it('filters the library by runsOn and lists groups', async () => {
  setup();
  const { user } = renderUI(<Harness runsOn="agent" />);
  await user.click(await screen.findByRole('combobox', { name: 'Add from library' }));
  const names = (await screen.findAllByRole('option')).map((o) => o.textContent);
  expect(names).toEqual([expect.stringContaining('reload nginx'), expect.stringContaining('notify'), expect.stringContaining('web reload')]);
  expect(screen.getByRole('option', { name: /web reload/ })).toHaveTextContent('Group · 2 actions');
});

it('server grants offer server actions only', async () => {
  setup();
  const { user } = renderUI(<Harness runsOn="server" />);
  await user.click(await screen.findByRole('combobox', { name: 'Add from library' }));
  expect(await screen.findByRole('option', { name: /ssh reload/ })).toBeInTheDocument();
  expect(screen.queryByRole('option', { name: /reload nginx/ })).not.toBeInTheDocument();
});

it('adds, orders and removes steps with badges', async () => {
  setup();
  const spy = vi.fn();
  const { user } = renderUI(<Harness runsOn="agent" initial={[{ action: 'a-1' }, { action: 'a-2' }, { group: 'ag-1' }]} spy={spy} />);
  const list = await screen.findByRole('list', { name: 'Step run order' });
  await within(list).findByText('notify');
  const items = () => within(list).getAllByRole('listitem');
  expect(items()[0]).toHaveTextContent('1.reload nginxCommandPost');
  expect(items()[1]).toHaveTextContent('Pre');
  expect(items()[2]).toHaveTextContent('Group · 2 actions');
  expect(screen.getByRole('button', { name: 'Move reload nginx up' })).toHaveAttribute('aria-disabled', 'true');
  await user.click(screen.getByRole('button', { name: 'Move notify up' }));
  expect(spy).toHaveBeenLastCalledWith([{ action: 'a-2' }, { action: 'a-1' }, { group: 'ag-1' }]);
  await user.click(screen.getByRole('button', { name: 'Remove web reload' }));
  expect(spy).toHaveBeenLastCalledWith([{ action: 'a-2' }, { action: 'a-1' }]);
  expect(screen.getByRole('link', { name: 'New action' })).toHaveAttribute('href', '/o/acme/delivery/actions?edit=new');
});

it('offers a group only when every member fits the side', async () => {
  server.use(
    ...authHandlers({ authed: true }),
    http.get(url('/orgs/org-1/actions'), () => HttpResponse.json({ items: [makeAction(), makeAction({ id: 'a-3', name: 'ssh reload', kind: 'ssh', runsOn: 'server' })] })),
    http.get(url('/orgs/org-1/action-groups'), () =>
      HttpResponse.json({ items: [makeActionGroup({ id: 'g-mixed', name: 'mixed', actionIds: ['a-1', 'a-3'] }), makeActionGroup({ id: 'g-ok', name: 'agent only', actionIds: ['a-1'] }), makeActionGroup({ id: 'g-empty', name: 'empty', actionIds: [] })] }),
    ),
  );
  const { user } = renderUI(<Harness runsOn="agent" />);
  await user.click(await screen.findByRole('combobox', { name: 'Add from library' }));
  expect(await screen.findByRole('option', { name: /agent only/ })).toBeInTheDocument();
  expect(screen.getByRole('option', { name: /empty/ })).toBeInTheDocument();
  expect(screen.queryByRole('option', { name: /mixed/ })).not.toBeInTheDocument();
});

it('warns on restart steps outside the allowed targets, directly or via a group', async () => {
  server.use(
    ...authHandlers({ authed: true }),
    http.get(url('/orgs/org-1/actions'), () =>
      HttpResponse.json({ items: [makeAction({ id: 'r-1', name: 'bad restart', kind: 'restart', config: { target: 'docker:x' } }), makeAction({ id: 'r-2', name: 'good restart', kind: 'restart', config: { target: 'docker:y' } })] }),
    ),
    http.get(url('/orgs/org-1/action-groups'), () => HttpResponse.json({ items: [makeActionGroup({ actionIds: ['r-1'] })] })),
  );
  renderUI(<StepsPicker orgId="org-1" runsOn="agent" value={[{ action: 'r-1' }, { action: 'r-2' }, { group: 'ag-1' }]} onChange={() => {}} restartTargets={[{ target: 'docker:y', allowed: true }]} />);
  await screen.findByText('bad restart');
  const rows = within(screen.getByRole('list', { name: 'Step run order' })).getAllByRole('listitem');
  await waitFor(() => expect(within(rows[0]!).getByText('Not allowed on this agent')).toBeInTheDocument());
  expect(within(rows[1]!).queryByText('Not allowed on this agent')).not.toBeInTheDocument();
  expect(within(rows[2]!).getByText('Not allowed on this agent')).toBeInTheDocument();
});
